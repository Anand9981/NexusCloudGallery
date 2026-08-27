import os
import re
import uuid
import boto3
import smtplib
import random
import certifi
import json
import traceback
import zipfile
import urllib.request
from flask import send_file
from PIL import Image
from io import BytesIO
from bson import ObjectId
from bson import json_util
from flask import session
from functools import wraps
from user_agents import parse 
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime, timedelta
from flask import make_response, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import abort
from itsdangerous import URLSafeTimedSerializer
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from apscheduler.schedulers.background import BackgroundScheduler

# ---------------------------------------------------
# CONFIGURATION & CLOUD SETUP
# ---------------------------------------------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'nexus_premium_key_999')

# ---------------------------------------------------
# CYBERSECURITY: NATIVE INTRUSION DETECTION SYSTEM (IDS)
# ---------------------------------------------------
# Yeh hamara custom RAM-based security tracker hai
SECURITY_CACHE = {}

def check_security_limit(ip, action, max_attempts=3, window_minutes=1):
    """Check karega ki user block hua hai ya nahi (With Terminal Logs)"""
    now = datetime.utcnow()
    cache_key = f"{ip}_{action}"
    
    if cache_key in SECURITY_CACHE:
        # Purane attempts ko strict seconds logic se hatao
        valid_attempts = [t for t in SECURITY_CACHE[cache_key] if (now - t).total_seconds() < (window_minutes * 60)]
        SECURITY_CACHE[cache_key] = valid_attempts
        
        # 🟢 TERMINAL PAR LIVE DEKHEIN: Kitne attempts hue
        print(f"🔒 [SECURITY LOG] Action: {action} | Failed Attempts: {len(valid_attempts)}/{max_attempts}")
        
        if len(valid_attempts) >= max_attempts:
            # 🔴 TERMINAL PAR LIVE DEKHEIN: Shield Triggered
            print(f"🚨 [ALERT] INTRUSION DETECTED! IP {ip} BLOCKED FOR 60 SECONDS!")
            return True
            
    return False

def log_failed_attempt(ip, action):
    """Har galat attempt ko memory mein save karega"""
    cache_key = f"{ip}_{action}"
    SECURITY_CACHE.setdefault(cache_key, []).append(datetime.utcnow())

def clear_security_cache(ip, action):
    """Sahi Login hone par pichle saare errors maaf kar dega (Clear)"""
    cache_key = f"{ip}_{action}"
    if cache_key in SECURITY_CACHE:
        del SECURITY_CACHE[cache_key]

# AWS Configuration
ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')
SECRET_KEY_AWS = os.getenv('AWS_SECRET_ACCESS_KEY')
BUCKET_NAME = os.getenv('AWS_BUCKET_NAME')
REGION = os.getenv('AWS_REGION', 'us-east-1')

s3_client = boto3.client('s3', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY_AWS, region_name=REGION)
rek_client = boto3.client('rekognition', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY_AWS, region_name=REGION)

# Database Setup
MONGO_URI = os.getenv('MONGO_URI')
client = MongoClient(
    MONGO_URI,
    tlsCAFile=certifi.where(),
)
db = client['NexusCloud_V2']
images_collection = db['assets']
users_collection = db['accounts']
folders_collection = db['directories']
moderation_rules_collection = db['moderation_rules']

people_collection = db['people']

# AWS Rekognition Human Face Collection Initialization
REK_COLLECTION_ID = "nexus_human_faces"
try:
    rek_client.create_collection(CollectionId=REK_COLLECTION_ID)
    print(f"✅ AWS Rekognition Face Collection '{REK_COLLECTION_ID}' Ready.")
except rek_client.exceptions.ResourceAlreadyExistsException:
    pass
except Exception as e:
    print(f"Face Collection Warning: {e}")

RECOVERY_OTP_CACHE = {} 

# ---------------------------------------------------
# OTP CLEANUP TASK (Background mein chalega)
# ---------------------------------------------------
def cleanup_otp_cache():
    """15 minute se purane OTPs ko remove karega"""
    print(f"[{datetime.utcnow()}] 🧹 Cleaning up expired OTPs...")
    now = datetime.utcnow()
    # List comprehension ka use karke sirf expired entries delete karein
    expired_keys = [user for user, data in RECOVERY_OTP_CACHE.items() 
                    if (now - data['timestamp']).total_seconds() > 900]
    for user in expired_keys:
        RECOVERY_OTP_CACHE.pop(user, None)


# ---------------------------------------------------
# BACKGROUND CLEANUP SCHEDULER
# ---------------------------------------------------
def background_cleanup():
    """Daily automated task to process expired deletion requests."""
    print(f"[{datetime.utcnow()}] Running daily account cleanup task...")
    now = datetime.utcnow()
    
    # Un sabhi accounts ko dhundo jinhe 30 din ho chuke hain
    expired_accounts = list(users_collection.find({"is_scheduled_for_deletion": True, "deletion_scheduled_at": {"$lte": now}}))
    
    for user in expired_accounts:
        if user.get("delete_assets_option", False):
            # Asset cleanup logic (S3 + MongoDB)
            user_assets = list(images_collection.find({"uploader": user['username']}))
            for asset in user_assets:
                try:
                    # Original image delete karo
                    s3_client.delete_object(Bucket=BUCKET_NAME, Key=asset['s3_key'])
                    
                    # 🧹 THUMBNAIL BHI DELETE KARO
                    s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"thumb_{asset['s3_key']}")
                except Exception as e:
                    print(f"Error purging S3 asset: {e}")
            
            # MongoDB se user ki saari images delete karo
            images_collection.delete_many({"uploader": user['username']})
        
        # User account delete karo
        users_collection.delete_one({"_id": user['_id']})
        print(f"Purged account: {user['username']}")

scheduler = BackgroundScheduler()
scheduler.add_job(func=background_cleanup, trigger="interval", days=1)
scheduler.add_job(func=cleanup_otp_cache, trigger="interval", minutes=15) # 15 min mein cache check
scheduler.start()

# ---------------------------------------------------
# AUTHENTICATION SETUP
# ---------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DEFAULT_ADMINS = ["parmanandsahu2005@gmail.com", "nexuscloud.admin@gmail.com"]

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data.get('email')
        self.profile_pic = user_data.get('profile_pic', 'https://ui-avatars.com/api/?name=' + user_data['username'])
        self.is_scheduled_for_deletion = user_data.get('is_scheduled_for_deletion', False)
        self.deletion_scheduled_at = user_data.get('deletion_scheduled_at')
        user_email_lower = user_data.get('email', '').strip().lower() if user_data.get('email') else ""
        self.is_admin = user_data.get('is_admin', False) or (user_email_lower in DEFAULT_ADMINS)

# 🛡️ ADMINISTRATIVE SECURITY SHIELD OVERRIDE
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not getattr(current_user, 'is_admin', False) or not session.get('is_admin_session'):
            return render_template('404.html', text_override="Security Shield: Active administrative clearance token required for this session."), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/test')
def test():
    return "Server is working perfectly!"


@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = users_collection.find_one({"_id": ObjectId(user_id)})
        return User(user_data) if user_data else None
    except:
        return None

# Smart Analytics Global Context Processor
@app.context_processor
def inject_usage_stats():
    if current_user.is_authenticated:
        total_assets = images_collection.count_documents({"uploader": current_user.username, "in_trash": False})
        trash_count = images_collection.count_documents({"uploader": current_user.username, "in_trash": True})
        return dict(total_assets=total_assets, trash_count=trash_count)
    return dict(total_assets=0, trash_count=0)

from flask import send_from_directory

# ---------------------------------------------------
# PWA (PROGRESSIVE WEB APP) ROUTES
# ---------------------------------------------------
@app.route('/manifest.json')
def serve_manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/service-worker.js')
def serve_sw():
    return send_from_directory('static', 'service-worker.js', mimetype='application/javascript')

# ---------------------------------------------------
# CORE ROUTES (EXPLORE & SEARCH)
# ---------------------------------------------------

@app.route('/')
def index():
    try:
        search_query = request.args.get('q', '').strip()
        per_page = 15 
        
        # 🌟 DYNAMIC PUBLIC FOLDERS LOOKUP: Sabhi public folders ke naam fetch karo
        public_folder_docs = list(folders_collection.find({"is_public": True}))
        public_folder_names = [f['folder_name'] for f in public_folder_docs]
        
        # Base Security Query (Trash hidden + Public Images + Public Folders + General)
        query = {
            "in_trash": {"$ne": True}, 
            "$or": [
                {"is_public": True},
                {"folder_name": {"$in": public_folder_names}},
                {
                    "folder_name": {"$regex": "^General$", "$options": "i"}, 
                    "is_public": {"$ne": False}
                }
            ]
        }
        
        # AI Search Filter
        if search_query:
            safe_query = re.escape(search_query)
            query["$and"] = [{
                "$or": [
                    {"tags": {"$regex": safe_query, "$options": "i"}},
                    {"filename": {"$regex": safe_query, "$options": "i"}}
                ]
            }]
            
        # Private Mode (Blocked Tags Filter)
        if current_user.is_authenticated:
            user_profile = users_collection.find_one({"username": current_user.username})
            if user_profile and user_profile.get('blocked_tags'):
                blocked_tags = user_profile['blocked_tags']
                escaped = [re.escape(str(t).strip().lower()) for t in blocked_tags if str(t).strip()]
                if escaped:
                    block_condition = {"tags": {"$not": {"$elemMatch": {"$regex": "|".join(escaped), "$options": "i"}}}}
                    if "$and" in query:
                        query["$and"].append(block_condition)
                    else:
                        query["$and"] = [block_condition]

        # Dropdown Folders Logic (Personal Folders + Joined Collab Folders)
        user_folders = []
        if current_user.is_authenticated:
            user_folders = list(folders_collection.find({
                "$or": [
                    {"owner": current_user.username},
                    {"contributors": current_user.username}
                ]
            }))
            user_folders.sort(key=lambda x: str(x.get('_id')), reverse=True)
            for folder in user_folders:
                folder['asset_count'] = images_collection.count_documents({
                    "folder_name": {"$regex": f"^{re.escape(folder['folder_name'])}$", "$options": "i"},
                    "in_trash": {"$ne": True}
                })

        # Trending AI Tags Logic
        trending = []
        try:
            trending = list(images_collection.aggregate([
                {"$match": query}, 
                {"$unwind": "$tags"},
                {"$sort": {"uploaded_at": -1}}, 
                {"$limit": 50},
                {"$group": {"_id": "$tags", "count": {"$sum": 1}}}, 
                {"$sort": {"count": -1}}, 
                {"$limit": 10}
            ]))
            trending = [t for t in trending if t.get('_id')]
        except Exception:
            pass

        # Initial 15 Images Fetch
        pipeline = [
            {"$match": query},
            {"$sort": {"uploaded_at": -1}}, 
            {"$limit": per_page},
            {"$lookup": {"from": "accounts", "localField": "uploader", "foreignField": "username", "as": "uploader_meta"}},
            {"$addFields": {"profile_pic": {"$arrayElemAt": ["$uploader_meta.profile_pic", 0]}}}
        ]
        
        all_images = list(images_collection.aggregate(pipeline))
        return render_template('index.html', images=all_images, folders=user_folders, trending_tags=trending, search_query=search_query)

    except Exception as e:
        print("CRITICAL INDEX ERROR:", e)
        return render_template('index.html', images=[], folders=[], trending_tags=[], search_query='')


@app.route('/load-more')
def load_more():
    try:
        scroll_page = request.args.get('page', 1, type=int)
        search_query = request.args.get('q', '').strip()
        
        per_page = 15  
        skip_count = (scroll_page - 1) * per_page
        
        # 🌟 DYNAMIC PUBLIC FOLDERS LOOKUP
        public_folder_docs = list(folders_collection.find({"is_public": True}))
        public_folder_names = [f['folder_name'] for f in public_folder_docs]
        
        query = {
            "in_trash": {"$ne": True}, 
            "$or": [
                {"is_public": True},
                {"folder_name": {"$in": public_folder_names}},
                {
                    "folder_name": {"$regex": "^General$", "$options": "i"}, 
                    "is_public": {"$ne": False}
                }
            ]
        }
        
        if search_query:
            safe_query = re.escape(search_query)
            query["$and"] = [{
                "$or": [
                    {"tags": {"$regex": safe_query, "$options": "i"}},
                    {"filename": {"$regex": safe_query, "$options": "i"}}
                ]
            }]
            
        if current_user.is_authenticated:
            user_profile = users_collection.find_one({"username": current_user.username})
            if user_profile and user_profile.get('blocked_tags'):
                blocked_tags = user_profile['blocked_tags']
                escaped = [re.escape(str(t).strip().lower()) for t in blocked_tags if str(t).strip()]
                if escaped:
                    block_condition = {"tags": {"$not": {"$elemMatch": {"$regex": "|".join(escaped), "$options": "i"}}}}
                    if "$and" in query:
                        query["$and"].append(block_condition)
                    else:
                        query["$and"] = [block_condition]

        pipeline = [
            {"$match": query},
            {"$sort": {"uploaded_at": -1}}, 
            {"$skip": skip_count},          
            {"$limit": per_page},           
            {"$lookup": {"from": "accounts", "localField": "uploader", "foreignField": "username", "as": "uploader_meta"}},
            {"$addFields": {"profile_pic": {"$arrayElemAt": ["$uploader_meta.profile_pic", 0]}}}
        ]
        
        new_images = list(images_collection.aggregate(pipeline))
        return jsonify(json.loads(json_util.dumps(new_images)))
        
    except Exception as e:
        print("Infinite Scroll Backend Error:", e)
        return jsonify([])

# @app.route('/')
# def index():
#     try:
#         search_query = request.args.get('q', '').strip()
#         per_page = 15 
        
#         # Base Security Query (Trash items hidden)
#         query = {
#             "in_trash": {"$ne": True}, 
#             "$or": [
#                 {"is_public": True},
#                 {
#                     "folder_name": {"$regex": "^General$", "$options": "i"}, 
#                     "is_public": {"$ne": False}  # Missing ya true chalega, bas explicitly False nahi hona chahiye
#                 }
#             ]
#         }
        
#         # AI Search Filter
#         if search_query:
#             safe_query = re.escape(search_query)
#             query["$and"] = [{
#                 "$or": [
#                     {"tags": {"$regex": safe_query, "$options": "i"}},
#                     {"filename": {"$regex": safe_query, "$options": "i"}}
#                 ]
#             }]
            
#         # Private Mode (Blocked Tags Filter)
#         if current_user.is_authenticated:
#             user_profile = users_collection.find_one({"username": current_user.username})
#             if user_profile and user_profile.get('blocked_tags'):
#                 blocked_tags = user_profile['blocked_tags']
#                 escaped = [re.escape(str(t).strip().lower()) for t in blocked_tags if str(t).strip()]
#                 if escaped:
#                     block_condition = {"tags": {"$not": {"$elemMatch": {"$regex": "|".join(escaped), "$options": "i"}}}}
#                     if "$and" in query:
#                         query["$and"].append(block_condition)
#                     else:
#                         query["$and"] = [block_condition]

#         # Dropdown Folders Logic
#         user_folders = []
#         if current_user.is_authenticated:
#             user_folders = list(folders_collection.find({"owner": current_user.username}))
#             user_folders.sort(key=lambda x: str(x.get('_id')), reverse=True)
#             for folder in user_folders:
#                 folder['asset_count'] = images_collection.count_documents({
#                     "uploader": current_user.username, 
#                     "folder_name": folder['folder_name'],
#                     "in_trash": {"$ne": True}
#                 })

#         # Trending AI Tags Logic
#         trending = []
#         try:
#             trending = list(images_collection.aggregate([
#                 {"$match": query}, 
#                 {"$unwind": "$tags"},
#                 {"$sort": {"uploaded_at": -1}}, 
#                 {"$limit": 50},
#                 {"$group": {"_id": "$tags", "count": {"$sum": 1}}}, 
#                 {"$sort": {"count": -1}}, 
#                 {"$limit": 10}
#             ]))
#             trending = [t for t in trending if t.get('_id')]
#         except Exception:
#             pass

#         # Initial 15 Images Fetch
#         pipeline = [
#             {"$match": query},
#             {"$sort": {"uploaded_at": -1}}, 
#             {"$limit": per_page},
#             {"$lookup": {"from": "accounts", "localField": "uploader", "foreignField": "username", "as": "uploader_meta"}},
#             {"$addFields": {"profile_pic": {"$arrayElemAt": ["$uploader_meta.profile_pic", 0]}}}
#         ]
        
#         all_images = list(images_collection.aggregate(pipeline))
#         return render_template('index.html', images=all_images, folders=user_folders, trending_tags=trending, search_query=search_query)

#     except Exception as e:
#         print("CRITICAL INDEX ERROR:", e)
#         return render_template('index.html', images=[], folders=[], trending_tags=[], search_query='')

# @app.route('/load-more')
# def load_more():
#     try:
#         scroll_page = request.args.get('page', 1, type=int)
#         search_query = request.args.get('q', '').strip()
        
#         per_page = 15  
#         skip_count = (scroll_page - 1) * per_page
        
#         query = {
#             "in_trash": {"$ne": True}, 
#             "$or": [
#                 {"is_public": True},
#                 {
#                     "folder_name": {"$regex": "^General$", "$options": "i"}, 
#                     "is_public": {"$ne": False}
#                 }
#             ]
#         }
        
#         if search_query:
#             safe_query = re.escape(search_query)
#             query["$and"] = [{
#                 "$or": [
#                     {"tags": {"$regex": safe_query, "$options": "i"}},
#                     {"filename": {"$regex": safe_query, "$options": "i"}}
#                 ]
#             }]
            
#         if current_user.is_authenticated:
#             user_profile = users_collection.find_one({"username": current_user.username})
#             if user_profile and user_profile.get('blocked_tags'):
#                 blocked_tags = user_profile['blocked_tags']
#                 escaped = [re.escape(str(t).strip().lower()) for t in blocked_tags if str(t).strip()]
#                 if escaped:
#                     block_condition = {"tags": {"$not": {"$elemMatch": {"$regex": "|".join(escaped), "$options": "i"}}}}
#                     if "$and" in query:
#                         query["$and"].append(block_condition)
#                     else:
#                         query["$and"] = [block_condition]

#         pipeline = [
#             {"$match": query},
#             {"$sort": {"uploaded_at": -1}}, 
#             {"$skip": skip_count},          
#             {"$limit": per_page},           
#             {"$lookup": {"from": "accounts", "localField": "uploader", "foreignField": "username", "as": "uploader_meta"}},
#             {"$addFields": {"profile_pic": {"$arrayElemAt": ["$uploader_meta.profile_pic", 0]}}}
#         ]
        
#         new_images = list(images_collection.aggregate(pipeline))
        
#         # 100% JSON Safe Response Format
#         return jsonify(json.loads(json_util.dumps(new_images)))
        
#     except Exception as e:
#         print("Infinite Scroll Backend Error:", e)
#         return jsonify([])

@app.route('/search')
def search():
    query = request.args.get('q')
    if not query: return redirect(url_for('index'))

    # 1. Search Filters Logic
    search_filter = {
        "in_trash": False,
        "$or": [
            {"is_public": True},
            {
                "folder_name": {"$regex": "^General$", "$options": "i"}, 
                "is_public": {"$ne": False}
            }
        ],
        "$and": [
            {
                "$or": [
                    {"tags": {"$regex": query, "$options": "i"}},
                    {"filename": {"$regex": query, "$options": "i"}}
                ]
            }
        ]
    }
    
    if current_user.is_authenticated:
        user_profile = users_collection.find_one({"_id": ObjectId(current_user.id)})
        blocked_tags = user_profile.get('blocked_tags', []) if user_profile else []
        
        if blocked_tags:
            strict_filters = []
            for t in blocked_tags:
                clean_t = str(t).strip().lower()
                strict_filters.append(clean_t)
                strict_filters.append(f"#{clean_t}")
            regex_patterns = [f"^{re.escape(tag)}$" for tag in strict_filters]
            
            # Blocked tags को सर्च रिजल्ट्स से हटाना
            search_filter["tags"] = {
                "$not": {
                    "$elemMatch": {
                        "$regex": "|".join(regex_patterns), 
                        "$options": "i"
                    }
                }
            }

    # 2. Fetching Images
    results = list(images_collection.find(search_filter).sort("uploaded_at", -1))
    
    # 3. Fetching Folders for the Upload UI
    user_folders = []
    if current_user.is_authenticated:
        user_folders = list(folders_collection.find({"owner": current_user.username}).sort("_id", -1))
        
    # 4. Rendering Template
    return render_template('index.html', images=results, search_query=query, folders=user_folders)

@app.route('/increment-view/<img_id>', methods=['POST'])
@login_required
def increment_view(img_id):
    try:
        result = images_collection.find_one_and_update(
            {'_id': ObjectId(img_id)},
            {'$inc': {'views': 1}},
            return_document=True
        )
        if result:
            return jsonify({'status': 'success', 'new_views': result.get('views', 0)})
        return jsonify({'status': 'error', 'message': 'Asset missing'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/user/<username>')
def uploader_profile_view(username):
    try:
        uploader_record = users_collection.find_one({"username": username})
        if not uploader_record:
            return render_template('404.html', text_override="The requested cloud identity profile perimeter does not exist within our database tracking cluster."), 404
            
        public_folders = list(folders_collection.find({
            "owner": username,
            "is_public": True
        }))
        
        for folder in public_folders:
            folder['asset_count'] = images_collection.count_documents({
                "uploader": username,
                "folder_name": folder['folder_name'],
                "in_trash": False,
                "is_public": True
            })
            
        public_images = list(images_collection.find({
            "uploader": username,
            "is_public": True,
            "in_trash": False
        }).sort("uploaded_at", -1))
        
        return render_template(
            'uploader_profile.html', 
            uploader=uploader_record, 
            folders=public_folders, 
            images=public_images
        )
        
    except Exception as e:
        print(f"Uploader Profile Context Processing Dropout: {str(e)}")
        return redirect(url_for('index'))

# ---------------------------------------------------
# ASSET MANAGEMENT (UPLOAD, FOLDERS & PRIVACY)
# ---------------------------------------------------

@app.route('/upload', methods=['POST'])
def upload():
    if 'image' not in request.files:
        return jsonify({"status": "error", "message": "Selection Required"}), 400

    files = request.files.getlist('image')
    
    # ✅ FIX 1: Blank submit interception check (Empty selections handling)
    valid_files_to_process = [f for f in files if f.filename != '']
    if not valid_files_to_process:
        return jsonify({"status": "error", "message": "No valid files selected for upload."}), 400

    selected_folder = request.form.get('folder_name', 'General')
    manual_tags = request.form.get('manual_tags', '').split(',')
    uploader = current_user.username if current_user.is_authenticated else "Guest"
    
    # 🛡️ DYNAMIC AWS REKOGNITION SHIELD ENGINE: Pulling rules straight from Database Core
    active_rules_docs = list(moderation_rules_collection.find({}))
    BLOCKED_SAFETY_LABELS = set(rule['label'].lower().strip() for rule in active_rules_docs)

    uploaded_files = []
    blocked_files = []

    try:
        # --- FOLDER PRIVACY CHECK (Multi-User Collab & Case-Insensitive) ---
        is_public_flag = False
        if selected_folder.lower() == 'general':
            is_public_flag = True  
        else:
            folder_doc = folders_collection.find_one({
                "folder_name": {"$regex": f"^{re.escape(selected_folder)}$", "$options": "i"}
            })
            is_public_flag = folder_doc.get('is_public', False) if folder_doc else False

        # --- PROCESS & UPLOAD FILES (With Dynamic Content Moderation Filter) ---
        for file in valid_files_to_process:
            orig_name = secure_filename(file.filename)
            filename = f"{datetime.now().timestamp()}_{orig_name}"
            thumb_filename = f"thumb_{filename}"
            
            # 1. File ko memory mein read karein
            file_bytes = file.read()
            
            # 2. Temporary Upload Original to S3 (Taki AI scan complete kar sake)
            s3_client.put_object(
                Bucket=BUCKET_NAME,
                Key=filename,
                Body=file_bytes,
                ContentType=file.content_type
            )
            
            # 3. AWS Rekognition AI Tags Analysis Core Protocol
            rek_response = rek_client.detect_labels(
                Image={'S3Object': {'Bucket': BUCKET_NAME, 'Name': filename}}, 
                MaxLabels=15
            )
            
            ai_tags = [label['Name'].lower() for label in rek_response['Labels']]
            
            # 🚨 DYNAMIC SHIELD EVALUATOR: Checking parameters inside active rules data matrix
            is_unsafe = False
            detected_threats = []
            
            for label in rek_response['Labels']:
                label_name = label['Name'].lower()
                parents = [p['Name'].lower() for p in label.get('Parents', [])]
                
                # Check validation over dynamically declared keys array
                if label_name in BLOCKED_SAFETY_LABELS or any(p in BLOCKED_SAFETY_LABELS for p in parents):
                    is_unsafe = True
                    detected_threats.append(label['Name'])
            
            # 🚫 PURGE INTERCEPT ACTION: Target threat verified, trigger instantaneous cloud destruction
            if is_unsafe:
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=filename)
                blocked_files.append(f"{orig_name} (Detected: {', '.join(set(detected_threats))})")
                continue 
            
            # 4. Create & Upload Thumbnail (~50KB for Grid layout)
            try:
                img = Image.open(BytesIO(file_bytes))
                if img.mode in ("RGBA", "P"): 
                    img = img.convert("RGB")
                
                img.thumbnail((600, 600)) 
                
                thumb_io = BytesIO()
                img.save(thumb_io, format='JPEG', quality=60)
                thumb_io.seek(0)
                
                s3_client.put_object(
                    Bucket=BUCKET_NAME,
                    Key=thumb_filename,
                    Body=thumb_io.getvalue(),
                    ContentType='image/jpeg'
                )
            except Exception as e:
                print(f"Thumbnail processing error: {e}")
                thumb_filename = filename
            
            final_tags = list(set(ai_tags + [t.strip().lower() for t in manual_tags if t.strip()]))
            original_url = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{filename}"
            thumb_url = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{thumb_filename}"
            
            # ---------------------------------------------------
            # 🧑‍🤝‍🧑 LOGGED-IN ONLY, HUMAN FACE RECOGNITION
            # ---------------------------------------------------
            detected_people_ids = []
            if current_user.is_authenticated:
                try:
                    face_index_resp = rek_client.index_faces(
                        CollectionId=REK_COLLECTION_ID,
                        Image={'S3Object': {'Bucket': BUCKET_NAME, 'Name': filename}},
                        MaxFaces=6,
                        QualityFilter="AUTO",
                        DetectionAttributes=['DEFAULT']
                    )

                    for face_record in face_index_resp.get('FaceRecords', []):
                        face_id = face_record['Face']['FaceId']

                        search_matches = rek_client.search_faces(
                            CollectionId=REK_COLLECTION_ID,
                            FaceId=face_id,
                            FaceMatchThreshold=80,
                            MaxFaces=5
                        )

                        matched_person = None
                        face_matches = search_matches.get('FaceMatches', [])
                        if face_matches:
                            matched_face_ids = [m['Face']['FaceId'] for m in face_matches]
                            # Strict User Filter: Sirf current user ke faces match honge
                            matched_person = people_collection.find_one({
                                "user": current_user.username,
                                "face_ids": {"$in": matched_face_ids}
                            })

                        if matched_person:
                            people_collection.update_one(
                                {"_id": matched_person['_id']},
                                {"$addToSet": {"face_ids": face_id}}
                            )
                            detected_people_ids.append(str(matched_person['_id']))
                        else:
                            total_people = people_collection.count_documents({"user": current_user.username}) + 1
                            person_default_name = f"Person {total_people:02d}"

                            new_person_doc = {
                                "user": current_user.username,
                                "name": person_default_name,
                                "face_ids": [face_id],
                                "cover_image": thumb_url,
                                "created_at": datetime.utcnow()
                            }
                            p_res = people_collection.insert_one(new_person_doc)
                            detected_people_ids.append(str(p_res.inserted_id))

                except Exception as face_err:
                    print(f"Face Indexing Skipped: {face_err}")
            
            # 5. Save to Database Node
            images_collection.insert_one({
                "filename": orig_name, 
                "s3_key": filename, 
                "url": original_url,          
                "thumb_url": thumb_url,       
                "tags": final_tags,
                "people": list(set(detected_people_ids)),
                "uploader": uploader, 
                "folder_name": selected_folder,
                "views": 0, "likes": 0, "shares": 0, "downloads": 0, 
                "is_favorite": False, "in_trash": False, 
                "uploaded_at": datetime.utcnow(), 
                "is_public": is_public_flag
            })
            uploaded_files.append(orig_name)

        # --- DYNAMIC RESPONSE GATEWAY EVALUATION ---
        if len(blocked_files) == len(valid_files_to_process) and len(valid_files_to_process) > 0:
            return jsonify({
                "status": "safety_error",
                "message": f"🚨 Upload restricted: Selected files violate our platform safety guidelines. {', '.join(blocked_files)}."
            }), 400
            
        elif len(blocked_files) > 0:
            return jsonify({
                "status": "partial_success",
                "message": f"⚠️ Partial Sync: {len(uploaded_files)} files uploaded successfully. While, {len(blocked_files)} files violating content policy were restricted. {', '.join(blocked_files)}."
            })
            
        else:
            return jsonify({"status": "success", "message": "Assets Compressed & Synchronized"})
    
    except Exception as e:
        print(f"Upload Matrix Error: {e}")
        return jsonify({"status": "error", "message": f"Operational pipeline fallout: {str(e)}"}), 500

@app.route('/create-folder', methods=['POST'])
@login_required
def create_folder():
    folder_name = request.form.get('folder_name')
    if folder_name:
        folders_collection.insert_one({
            "folder_name": folder_name.strip(),
            "owner": current_user.username,
            "is_public": False,
            "created_at": datetime.utcnow()
        })
        return jsonify({"status": "success", "message": "Folder Created"})
    return jsonify({"status": "error", "message": "Invalid Name"})

@app.route('/folder/<name>')
@login_required
def folder_view(name):
    # Check folder ownership ya contributor access
    folder = folders_collection.find_one({
        "folder_name": {"$regex": f"^{re.escape(name)}$", "$options": "i"},
        "$or": [{"owner": current_user.username}, {"contributors": current_user.username}]
    })
    
    all_user_folders = list(folders_collection.find({"owner": current_user.username}))
    
    # Is folder ki saari photos fetch karo (Kisi bhi user/guest ki ho)
    folder_images = list(images_collection.find({
        "folder_name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}, 
        "in_trash": False
    }).sort("uploaded_at", -1))
    
    return render_template('folder_view.html', folder_name=name, folder=folder, images=folder_images, all_user_folders=all_user_folders)

@app.route('/move-assets', methods=['POST'])
@login_required
def move_assets():
    try:
        data = request.get_json()
        asset_ids = data.get('asset_ids', [])
        target_folder = data.get('target_folder')
        
        if not asset_ids or not target_folder:
            return jsonify({'status': 'error', 'message': 'Invalid selection'})
            
        bson_ids = [ObjectId(id_str) for id_str in asset_ids]
        images_collection.update_many(
            {'_id': {'$in': bson_ids}, 'uploader': current_user.username},
            {'$set': {'folder_name': target_folder}}
        )
        return jsonify({'status': 'success', 'message': 'Assets moved successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
# ---------------------------------------------------
# ✨ AI SMART ALBUMS: EXPANDED AUTO-GROUPING ENGINE
# ---------------------------------------------------

THEME_KEYWORD_TAXONOMY = {
    "Animals & Pets": [
        "animal", "bird", "dog", "cat", "rabbit", "bear", "finch", "wren", "pet", 
        "wildlife", "mammal", "fauna", "rodent", "rat", "fish", "puppy", "kitten", "canine", "beast"
    ],
    "Nature & Landscapes": [
        "nature", "tree", "plant", "mountain", "landscape", "sky", "water", "flower", 
        "forest", "sea", "ocean", "outdoors", "conifer", "scenery", "sunset", "grass", 
        "desert", "sand", "terrain", "shoreline", "land", "earth", "aerial view", "soil"
    ],
    "Vehicles & Transport": [
        "car", "vehicle", "automobile", "motorcycle", "scooter", "bike", "airplane", 
        "train", "truck", "wheel", "transportation", "coupe", "sedan", "spaceship", 
        "spacecraft", "rocket", "vessel", "machine", "aviation"
    ],
    "Food & Dining": [
        "food", "meal", "dish", "drink", "beverage", "dessert", "fruit", "vegetable", 
        "snack", "restaurant", "coffee", "lunch", "dinner", "breakfast", "cuisine"
    ],
    "People & Portraits": [
        "person", "human", "people", "portrait", "face", "crowd", "smile", "woman", 
        "man", "child", "girl", "boy", "selfie", "astronaut", "costume", "suit", "fashion"
    ],
    "Architecture & Urban": [
        "building", "architecture", "city", "urban", "house", "bridge", "tower", 
        "interior", "room", "skyscraper", "monument", "wall", "structure"
    ],
    "Documents & Notes": [
        "text", "document", "receipt", "invoice", "paper", "page", "screenshot", 
        "book", "label", "flyer", "poster", "notes", "diagram"
    ]
}

# ---------------------------------------------------
# ✨ AI SMART ALBUMS: EXPANDED AUTO-GROUPING ENGINE (MULTI-USER FIXED)
# ---------------------------------------------------

@app.route('/smart-organize-preview/<folder_name>', methods=['GET'])
@login_required
def smart_organize_preview(folder_name):
    try:
        # 1. Folder verify karo (Owner ho ya Contributor)
        folder = folders_collection.find_one({
            "folder_name": folder_name,
            "$or": [{"owner": current_user.username}, {"contributors": current_user.username}]
        })

        # 2. FIX: Is folder ke saare assets scan karo (Chahe owner ne dale hon ya contributor/guest ne)
        current_images = list(images_collection.find({
            "folder_name": folder_name,
            "in_trash": {"$ne": True}
        }))
        
        if not current_images:
            return jsonify({"status": "error", "message": "No assets found in this folder."}), 400

        user_existing_folders = list(folders_collection.find({"owner": current_user.username}))
        existing_folder_names = [f['folder_name'] for f in user_existing_folders]

        categorized_moves = {}
        uncategorized_ids = []

        for img in current_images:
            img_tags = [t.lower().strip() for t in img.get('tags', [])]
            matched_target_folder = None
            is_existing = False

            # Priority 1: Check existing folders by direct tag similarity
            for exist_name in existing_folder_names:
                clean_exist = exist_name.lower().strip()
                if clean_exist == folder_name.lower().strip():
                    continue
                if any(clean_exist in tag or tag in clean_exist for tag in img_tags):
                    matched_target_folder = exist_name
                    is_existing = True
                    break

            # Priority 2: Keyword taxonomy evaluation
            if not matched_target_folder and img_tags:
                for theme_title, keywords in THEME_KEYWORD_TAXONOMY.items():
                    if any(kw in img_tags for kw in keywords):
                        for exist_name in existing_folder_names:
                            clean_exist = exist_name.lower().strip()
                            if clean_exist == folder_name.lower().strip():
                                continue
                            if any(kw in clean_exist for kw in keywords):
                                matched_target_folder = exist_name
                                is_existing = True
                                break
                        
                        if not matched_target_folder:
                            matched_target_folder = theme_title
                            is_existing = False
                        break

            # Priority 3: Fallback bucket
            if not matched_target_folder and categorized_moves:
                matched_target_folder = list(categorized_moves.keys())[0]
                is_existing = categorized_moves[matched_target_folder]["exists"]

            if matched_target_folder and matched_target_folder.lower().strip() != folder_name.lower().strip():
                if matched_target_folder not in categorized_moves:
                    categorized_moves[matched_target_folder] = {
                        "target_folder": matched_target_folder,
                        "exists": is_existing,
                        "asset_ids": [],
                        "count": 0
                    }
                categorized_moves[matched_target_folder]["asset_ids"].append(str(img['_id']))
                categorized_moves[matched_target_folder]["count"] += 1
            else:
                uncategorized_ids.append(str(img['_id']))

        return jsonify({
            "status": "success",
            "current_folder": folder_name,
            "total_scanned": len(current_images),
            "suggestions": list(categorized_moves.values()),
            "uncategorized_count": len(uncategorized_ids)
        })

    except Exception as e:
        print(f"Smart preview error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/execute-smart-organize', methods=['POST'])
@login_required
def execute_smart_organize():
    try:
        data = request.get_json() or {}
        moves = data.get('moves', [])
        
        if not moves:
            return jsonify({"status": "error", "message": "No categories selected to move."}), 400

        total_moved = 0
        for item in moves:
            target = item.get('target_folder', '').strip()
            asset_ids = item.get('asset_ids', [])
            
            if not target or not asset_ids:
                continue

            folder_exists = folders_collection.find_one({
                "owner": current_user.username,
                "folder_name": {"$regex": f"^{re.escape(target)}$", "$options": "i"}
            })
            if not folder_exists:
                folders_collection.insert_one({
                    "folder_name": target,
                    "owner": current_user.username,
                    "is_public": False,
                    "created_at": datetime.utcnow()
                })

            bson_ids = [ObjectId(aid) for aid in asset_ids]
            
            # FIX: Uploader filter hata diya gaya hai taaki shared photos bhi move ho sakein
            res = images_collection.update_many(
                {"_id": {"$in": bson_ids}},
                {"$set": {"folder_name": target}}
            )
            total_moved += res.modified_count

        return jsonify({
            "status": "success", 
            "message": f"Successfully moved {total_moved} assets!"
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/rename-folder/<folder_id>', methods=['POST'])
@login_required
def rename_folder(folder_id):
    try:
        data = request.get_json() or {}
        new_name = data.get('new_name', '').strip()
        
        if not new_name:
            return jsonify({'status': 'error', 'message': 'Room name cannot be empty.'}), 400
            
        # 1. Pehle purana folder dhoondo taaki uska original naam mil sake
        folder = folders_collection.find_one({'_id': ObjectId(folder_id), 'owner': current_user.username})
        
        if not folder:
            return jsonify({'status': 'error', 'message': 'Folder not found.'}), 404
            
        old_name = folder.get('folder_name')

        # 2. Images collection mein purane naam wali sabhi photos ko naye naam se replace karo
        images_collection.update_many(
            {'uploader': current_user.username, 'folder_name': old_name},
            {'$set': {'folder_name': new_name}}
        )
        
        # 3. Aakhiri mein Folder collection mein folder ka naam update karo
        folders_collection.update_one(
            {'_id': ObjectId(folder_id), 'owner': current_user.username},
            {'$set': {'folder_name': new_name}}
        )
        
        return jsonify({'status': 'success', 'message': 'Folder renamed successfully.'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Internal re-indexing failure context: {str(e)}'}), 500

@app.route('/update-folder-privacy/<folder_id>', methods=['POST'])
@login_required
def update_folder_privacy(folder_id):
    data = request.get_json() or {}
    is_public = bool(data.get('is_public', False))
    
    folders_collection.update_one(
        {'_id': ObjectId(folder_id), 'owner': current_user.username},
        {'$set': {'is_public': is_public}}
    )
    
    folder = folders_collection.find_one({'_id': ObjectId(folder_id)})
    if folder:
        # FIX: 'uploader' filter hata diya taaki sabhi contributors ki photos public/private synchronize hon
        images_collection.update_many(
            {'folder_name': folder['folder_name']},
            {'$set': {'is_public': is_public}}
        )
    
    return jsonify({'status': 'success'})

@app.route('/delete-folder/<folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    folder = folders_collection.find_one({'_id': ObjectId(folder_id), 'owner': current_user.username})
    if folder:
        images_collection.update_many(
            {'folder_name': folder['folder_name'], 'uploader': current_user.username},
            {'$set': {'in_trash': True, 'original_folder': folder['folder_name'], 'deleted_at': datetime.utcnow()}}
        )
        folders_collection.delete_one({'_id': ObjectId(folder_id)})
        return jsonify({'status': 'success'})
        
    return jsonify({'status': 'error', 'message': 'Folder not found'}), 404

@app.route('/toggle-folder-privacy/<folder_id>', methods=['POST'])
@login_required
def toggle_folder_privacy(folder_id):
    folder = folders_collection.find_one({"_id": ObjectId(folder_id), "owner": current_user.username})
    if folder:
        new_status = not folder.get('is_public', False)
        folders_collection.update_one({"_id": ObjectId(folder_id)}, {"$set": {"is_public": new_status}})
        
        # FIX: Saari shared photos ek sath update hongi
        images_collection.update_many(
            {"folder_name": folder['folder_name']},
            {"$set": {"is_public": new_status}}
        )
        return jsonify({"status": "success", "new_status": "Public" if new_status else "Private"})
    return jsonify({"status": "error"}), 403

@app.route('/share-folder/<folder_name>')
def share_folder(folder_name):
    images = list(images_collection.find({"folder_name": folder_name, "is_public": True, "in_trash": False}))
    return render_template('index.html', images=images, folder_name=folder_name, is_shared_view=True)

@app.route('/download-folder/<folder_name>')
@login_required
def download_folder_zip(folder_name):
    images = list(images_collection.find({
        "folder_name": folder_name, 
        "uploader": current_user.username, 
        "in_trash": False
    }))
    
    if not images:
        flash("Folder is empty or not found.", "error")
        return redirect(url_for('folder_view', name=folder_name))

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for img in images:
            try:
                s3_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=img['s3_key'])
                file_bytes = s3_obj['Body'].read()
                zf.writestr(img['filename'], file_bytes)
            except Exception as e:
                print(f"Error zipping {img['filename']}: {e}")
    
    memory_file.seek(0)
    clean_folder_name = folder_name.replace(" ", "_")
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"{clean_folder_name}_Nexus_Backup.zip"
    )

# ---------------------------------------------------
# USER VAULT & PERSONAL FILES
# ---------------------------------------------------

@app.route('/my-vault')
@login_required
def my_vault():
    # 1. User ke personal folders
    user_folders = list(folders_collection.find({'owner': current_user.username}))
    for folder in user_folders:
        folder['asset_count'] = images_collection.count_documents({
            'folder_name': {"$regex": f"^{re.escape(folder['folder_name'])}$", "$options": "i"},
            'in_trash': {'$ne': True}
        })
        
        # 🤝 STRICT COLLAB CHECK: Sirf tab True hoga jab Owner ke alawa kisi aur ki active photo upload hogi
        external_uploads = images_collection.count_documents({
            'folder_name': {"$regex": f"^{re.escape(folder['folder_name'])}$", "$options": "i"},
            'uploader': {"$ne": folder['owner']},
            'in_trash': {'$ne': True}
        })
        folder['has_collab_uploads'] = (external_uploads > 0)
        
    # 2. 🤝 Dusre users ke rooms jo is user ne join kiye hain
    joined_collab_folders = list(folders_collection.find({
        'contributors': current_user.username,
        'owner': {'$ne': current_user.username}
    }))
    for folder in joined_collab_folders:
        folder['asset_count'] = images_collection.count_documents({
            'folder_name': {"$regex": f"^{re.escape(folder['folder_name'])}$", "$options": "i"},
            'in_trash': {'$ne': True}
        })
        
    user_images = list(images_collection.find({"uploader": current_user.username, "in_trash": False}).sort("uploaded_at", -1))
    return render_template('vault.html', images=user_images, folders=user_folders, collab_folders=joined_collab_folders)

# ---------------------------------------------------
# ENGAGEMENT & FAVORITES SYSTEM
# ---------------------------------------------------

@app.route('/favorites')
@login_required
def favorites():
    try:
        query = {
            "liked_by": current_user.username, 
            "in_trash": {"$ne": True}
        }

        pipeline = [
            {"$match": query},
            {"$sort": {"uploaded_at": -1}}, 
            {
                "$lookup": {
                    "from": "accounts", 
                    "localField": "uploader", 
                    "foreignField": "username", 
                    "as": "uploader_meta"
                }
            },
            {
                "$addFields": {
                    "profile_pic": {"$arrayElemAt": ["$uploader_meta.profile_pic", 0]}
                }
            }
        ]

        favorite_images = list(images_collection.aggregate(pipeline))
        
        return render_template('favorites.html', images=favorite_images)

    except Exception as e:
        print("FAVORITES FETCH ERROR:", str(e))
        return render_template('favorites.html', images=[])

@app.route('/like-image/<image_id>', methods=['POST'])
def like_image(image_id):
    try:
        image = images_collection.find_one({"_id": ObjectId(image_id)})
        if not image:
            return jsonify({"status": "error", "message": "Asset not found."}), 404

        if current_user.is_authenticated:
            user_identifier = current_user.username
        else:
            user_identifier = f"guest_{request.remote_addr}"

        liked_by_list = image.get('liked_by', [])

        if user_identifier in liked_by_list:
            img = images_collection.find_one_and_update(
                {"_id": ObjectId(image_id)},
                {
                    "$inc": {"likes": -1},
                    "$pull": {"liked_by": user_identifier} 
                },
                return_document=True
            )
        else:
            img = images_collection.find_one_and_update(
                {"_id": ObjectId(image_id)},
                {
                    "$inc": {"likes": 1},
                    "$addToSet": {"liked_by": user_identifier} 
                },
                return_document=True
            )

        return jsonify({"status": "success", "new_likes": img.get('likes', 0)})

    except Exception as e:
        print("LIKE SYSTEM ERROR:", str(e))
        return jsonify({"status": "error", "message": "Server error while processing like."}), 500

@app.route('/share-image/<image_id>', methods=['POST'])
def share_image(image_id):
    images_collection.update_one({"_id": ObjectId(image_id)}, {"$inc": {"shares": 1}})
    return jsonify({"status": "success"})

@app.route('/download-image/<image_id>')
def download_asset(image_id):
    asset = images_collection.find_one({"_id": ObjectId(image_id)})
    if asset:
        images_collection.update_one({"_id": ObjectId(image_id)}, {"$inc": {"views": 1, "downloads": 1}})
        return redirect(asset['url'])
    return "Asset not found", 404

# ---------------------------------------------------
# TRASH & BATCH BULK ROUTER STORAGE SYSTEM
# ---------------------------------------------------

@app.route('/bulk-trash-assets', methods=['POST'])
@login_required
def bulk_trash_assets():
    try:
        data = request.get_json() or {}
        asset_ids = data.get('asset_ids', [])
        if not asset_ids:
            return jsonify({'status': 'error', 'message': 'Payload structure contains no valid entities.'}), 400
            
        bson_ids_array = [ObjectId(id_str) for id_str in asset_ids]
        images_collection.update_many(
            {'_id': {'$in': bson_ids_array}, 'uploader': current_user.username},
            {'$set': {'in_trash': True, 'deleted_at': datetime.utcnow()}}
        )
        return jsonify({'status': 'success', 'message': 'Batch collection entity status rewritten successfully.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Internal collection stack anomaly context: {str(e)}'}), 500

@app.route('/move-to-trash/<image_id>', methods=['POST'])
@login_required
def move_to_trash(image_id):
    images_collection.update_one({"_id": ObjectId(image_id), "uploader": current_user.username}, {"$set": {"in_trash": True, "deleted_at": datetime.utcnow()}})
    return jsonify({"status": "success"})

@app.route('/restore-asset/<image_id>', methods=['POST'])
@login_required
def restore_asset(image_id):
    images_collection.update_one({"_id": ObjectId(image_id), "uploader": current_user.username}, {"$set": {"in_trash": False}, "$unset": {"deleted_at": ""}})
    return jsonify({"status": "success", "message": "Asset restored to vault"})

@app.route('/permanent-delete/<image_id>', methods=['POST'])
@login_required
def permanent_delete(image_id):
    asset = images_collection.find_one({"_id": ObjectId(image_id), "uploader": current_user.username})
    if asset:
        try:
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=asset['s3_key'])
            try:
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"thumb_{asset['s3_key']}")
            except:
                pass 
                
            images_collection.delete_one({"_id": ObjectId(image_id)})
            return jsonify({"status": "success", "message": "Asset purged permanently"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})
    return jsonify({"status": "error", "message": "Unauthorized"}), 403

@app.route('/empty-trash', methods=['POST'])
@login_required
def empty_trash():
    user_trash = list(images_collection.find({"uploader": current_user.username, "in_trash": True}))
    try:
        for asset in user_trash:
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=asset['s3_key'])
            try:
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"thumb_{asset['s3_key']}")
            except:
                pass
                
        images_collection.delete_many({"uploader": current_user.username, "in_trash": True})
        return jsonify({"status": "success", "message": "Trash purged successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/trash-bin')
@login_required
def trash_bin():
    expiry_limit = datetime.utcnow() - timedelta(days=30)
    images_collection.delete_many({"in_trash": True, "deleted_at": {"$lt": expiry_limit}})
    items = list(images_collection.find({"uploader": current_user.username, "in_trash": True}))
    return render_template('trash.html', items=items)

#---------------------------------------------------------------
# SECURITY CORE: ACCOUNT DELETION & RECOVERY
#---------------------------------------------------------------
@app.route('/request-account-deletion', methods=['POST'])
@login_required
def request_account_deletion():
    data = request.get_json() or {}
    delete_assets = data.get('delete_assets', False)
    
    if not delete_assets:
        images_collection.update_many(
            {"uploader": current_user.username}, 
            {"$set": {"status": "archived", "is_public": False}}
        )
    
    deletion_date = datetime.utcnow() + timedelta(days=30)
    
    users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$set": {
            "is_scheduled_for_deletion": True,
            "delete_assets_option": delete_assets,
            "deletion_scheduled_at": deletion_date
        }}
    )
    
    session['is_scheduled_for_deletion'] = True
    session['deletion_scheduled_at'] = deletion_date.isoformat()
    
    return jsonify({
        'status': 'success', 
        'message': 'Account marked for deletion. Data lifecycle initiated.'
    })

#----------------------------------------------------------------------------------------------
# ACCOUNT DELETION & RECOVERY ENDPOINTS
#----------------------------------------------------------------------------------------------
# ---------------------------------------------------
# SMTP EMAIL PIPELINE (Nexus Cloud Core Mail Engine)
# ---------------------------------------------------

def send_sync_email_optimized(target_email, subject, body_content):
    """Core synchronous email dispatcher with absolute security headers to bypass filters."""
    try:
        sender_identity = os.getenv('SMTP_SENDER')
        smtp_app_secret = os.getenv('SMTP_PASSWORD')
        
        if not sender_identity or not smtp_app_secret:
            print("❌ [SMTP SHIELD] Aborted: Environmental credentials missing.", flush=True)
            return False

        msg = MIMEMultipart()
        msg['From'] = f"Nexus Cloud Support <{sender_identity}>"
        msg['To'] = target_email
        msg['Subject'] = subject
        
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = make_msgid()
        
        if "</div>" in body_content or "<div" in body_content:
            msg.attach(MIMEText(body_content, 'html'))
        else:
            msg.attach(MIMEText(body_content, 'plain'))
        
        print(f"📡 [SMTP SHIELD] Initializing connection for: {target_email}...", flush=True)
        
        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=7)
            server.login(sender_identity, smtp_app_secret)
            server.sendmail(sender_identity, target_email, msg.as_string())
            server.quit()
            print(f"✅ [SMTP SHIELD] Success: Email delivered via Port 465 SSL", flush=True)
            return True
        except Exception as e465:
            print(f"⚠️ Port 465 SSL skipped, trying Port 587 TLS: {str(e465)}", flush=True)
            
            server = smtplib.SMTP('smtp.gmail.com', 587, timeout=7)
            server.starttls()
            server.login(sender_identity, smtp_app_secret)
            server.sendmail(sender_identity, target_email, msg.as_string())
            server.quit()
            print(f"✅ [SMTP SHIELD] Success: Email delivered via Port 587 TLS", flush=True)
            return True
            
    except Exception as final_err:
        print(f"❌ [SMTP CRITICAL ERROR] Transmission failure: {str(final_err)}", flush=True)
        return False

def dispatch_smtp_secure_email(target_email, username, subject, body_content):
    return send_sync_email_optimized(target_email, subject, body_content)

def send_email(target_email, subject, body_content):
    return send_sync_email_optimized(target_email, subject, body_content)

@app.route('/send-recovery-otp', methods=['POST'])
def send_recovery_otp():
    client_ip = request.remote_addr or "127.0.0.1"

    if check_security_limit(client_ip, "otp", max_attempts=6, window_minutes=60):
        return jsonify({
            "status": "error", 
            "message": "Security Shield Activated: Maximum OTP limit reached. Please try again after 1 hour."
        }), 429

    data = request.get_json() or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    
    user = users_collection.find_one({'username': username, 'email': email})
    if not user:
        log_failed_attempt(client_ip, "otp")
        return jsonify({'status': 'error', 'message': 'Account validation failed: This identity profile is not registered.'}), 401
        
    generated_token = str(random.randint(100000, 999999))
    
    subject = "NEXUS Cloud Service - Request for Secure Password Reset"
    body_content = f"""
    Hello {username},
    
    Thank you for choosing Nexus Cloud. We are committed to keeping your account secure.
    We have received a request to reset your password. To complete this process, please use the verification code provided below:
    
    🔑 AUTHENTICATION OTP: {generated_token}
    
    For your security, this code will expire in 10 minutes. If you did not initiate this request, please ignore this email, and no changes will be made to your account.
    
    Best regards,
    Nexus Security Architecture Team
    """

    try:
        dispatch_smtp_secure_email(email, username, subject, body_content)
        
        RECOVERY_OTP_CACHE[username] = {
            "otp": generated_token,
            "timestamp": datetime.utcnow()
        }
        
        return jsonify({'status': 'success', 'message': 'Payload routed successfully.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@app.route('/execute-secure-reset', methods=['POST'])
def execute_secure_reset():
    try:
        data = request.get_json() or {}
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        new_password = data.get('new_password', '')
        mode = data.get('mode') 
        
        user = users_collection.find_one({'username': username, 'email': email})
        if not user:
            return jsonify({'status': 'error', 'message': 'Identity verification failed. Registered parameters do not match.'}), 401

        if mode == 'OTP':
            otp_token = data.get('otp_token', '').strip()
            otp_data = RECOVERY_OTP_CACHE.get(username)
            
            if not otp_data:
                return jsonify({'status': 'error', 'message': 'OTP missing.'}), 401

            if (datetime.utcnow() - otp_data['timestamp']).total_seconds() > 900:
                RECOVERY_OTP_CACHE.pop(username, None)
                return jsonify({'status': 'error', 'message': 'OTP expired.'}), 401

            if otp_token != otp_data['otp']:
                return jsonify({'status': 'error', 'message': 'Invalid OTP.'}), 401
            
            RECOVERY_OTP_CACHE.pop(username, None)

        elif mode == 'SECRET':
            input_question = data.get('security_question', '')
            input_answer = data.get('security_answer', '').strip().lower()
            
            db_saved_question = user.get('security_question', '')
            db_saved_answer = str(user.get('security_answer', '')).strip().lower()
            
            if input_question != db_saved_question or input_answer != db_saved_answer:
                return jsonify({'status': 'error', 'message': 'Security secret answer verification rejected.'}), 401
        
        else:
            return jsonify({'status': 'error', 'message': 'Invalid verification mode selected.'}), 400
            
        new_hashed_signature = generate_password_hash(new_password)
        users_collection.update_one({'_id': user['_id']}, {'$set': {'password': new_hashed_signature}})
        if email:
            send_password_change_notification(email)
            
        return jsonify({'status': 'success', 'message': 'Password updated successfully.'})
        
    except Exception as e:
        print(f"CRITICAL RESET ERROR: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal reset pipeline error.'}), 500

@app.route('/internal-change-password', methods=['POST'])
@login_required
def internal_change_password():
    try:
        current_pw = request.form.get('current_password')
        new_pw = request.form.get('new_password')
        
        user_record = users_collection.find_one({'_id': ObjectId(current_user.id)})
        
        if user_record and check_password_hash(user_record['password'], current_pw):
            new_hashed_format = generate_password_hash(new_pw)
            
            users_collection.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': {'password': new_hashed_format}}
            )
            if user_record.get('email'):
                send_password_change_notification(user_record['email'])
                
            return jsonify({'status': 'success', 'message': 'Master security credentials updated successfully.'})
        else:
            return jsonify({'status': 'error', 'message': 'The current password signature provided does not match.'}), 401
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Internal cluster operational dropout: {str(e)}'}), 500

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = session.get('reset_email') or request.form.get('email')
        new_password = request.form.get('password')
        
        if email and new_password:
            hashed_password = generate_password_hash(new_password)
            
            users_collection.update_one(
                {"email": email},
                {"$set": {"password": hashed_password}}
            )
            
            notify_subject = "Nexus Cloud: Security Password Reset Confirmed"
            notify_html = f"""
            <div style="font-family: 'Inter', Arial, sans-serif; max-width: 500px; margin: auto; padding: 30px; border: 1px solid #e2e8f0; border-radius: 20px; background-color: #ffffff; box-shadow: 0 4px 12px rgba(0,0,0,0.03);">
                <div style="text-align: center; margin-bottom: 20px;">
                    <span style="font-size: 40px;">🛡️</span>
                </div>
                <h2 style="color: #2563eb; text-align: center; margin-top: 0; font-weight: 800; text-transform: uppercase; letter-spacing: -0.5px;">Reset Successful</h2>
                <p style="color: #334155; font-size: 14px; line-height: 1.6; margin-top: 20px;">Hello Explorer,</p>
                <p style="color: #475569; font-size: 14px; line-height: 1.6;">The data account recovery pipeline for <strong>{email}</strong> has finalized successfully. Your temporary configuration hashes have been overwritten with your new secure access password.</p>
                <p style="color: #64748b; font-size: 13px; line-height: 1.6; background: #fff7ed; padding: 12px; border-radius: 10px; border-left: 4px solid #f97316;">
                    <strong>Verification Method:</strong> Identity Token Validation Pipeline<br>
                    <strong>System Action:</strong> Old Credentials Revoked Automatically
                </p>
                <p style="color: #475569; font-size: 14px; line-height: 1.6;">You can now securely access your primary master directory parameters utilizing your freshly configured identity password.</p>
                <hr style="border: none; border-top: 1px solid #f1f5f9; margin: 25px 0;">
                <p style="color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; text-align: center; margin-bottom: 0;">Monitored securely by,<br><strong>Nexus Cloud Core Matrix</strong></p>
            </div>
            """
            send_email(email, notify_subject, notify_html)
            
            session.pop('reset_email', None)
            
            flash("Account access credentials restored successfully. Please sign in.", "success")
            return redirect(url_for('login'))
            
        flash("System processing fault: Identity reference validation failed.", "error")
        return redirect(url_for('reset_password'))

    return render_template('reset_password.html')

@app.route('/update-settings', methods=['POST'])
@login_required
def update_settings():
    avatar_choice = request.form.get('avatar_choice')
    
    if 'custom_profile_pic' in request.files:
        file = request.files['custom_profile_pic']
        if file and file.filename != '':
            try:
                orig_name = secure_filename(file.filename)
                unique_filename = f"profile_{current_user.username}_{int(datetime.now().timestamp())}_{orig_name}"
                
                s3_client.upload_fileobj(file, BUCKET_NAME, unique_filename, ExtraArgs={'ContentType': file.content_type})
                final_pic = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{unique_filename}"
                
                users_collection.update_one(
                    {"_id": ObjectId(current_user.id)}, 
                    {"$set": {"profile_pic": final_pic}}
                )
                
                flash("Profile system avatar synchronized from local system successfully!", "success")
                return redirect(url_for('settings'))
            except Exception as e:
                flash(f"Cloud synchronizer dropout: {str(e)}", "error")
                return redirect(url_for('settings'))

    if avatar_choice:
        users_collection.update_one(
            {"_id": ObjectId(current_user.id)}, 
            {"$set": {"profile_pic": avatar_choice}}
        )
        flash("AI system identity avatar registered successfully!", "success")
        
    return redirect(url_for('settings'))

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    try:
        selected_avatar = request.form.get('selected_avatar')
        update_fields = {}
        
        if selected_avatar:
            update_fields['profile_pic'] = selected_avatar
            
        if 'custom_photo' in request.files:
            file = request.files['custom_photo']
            if file and file.filename != '':
                orig_name = secure_filename(file.filename)
                unique_filename = f"profile_{current_user.username}_{int(datetime.now().timestamp())}_{orig_name}"
                
                s3_client.upload_fileobj(file, BUCKET_NAME, unique_filename, ExtraArgs={'ContentType': file.content_type})
                
                final_pic = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{unique_filename}"
                update_fields['profile_pic'] = final_pic

        if update_fields:
            users_collection.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': update_fields}
            )
            flash("Profile Identity parameters synchronized successfully!", "success")
            
        return redirect(url_for('settings'))
    except Exception as e:
        print(f"Profile Sync Exception: {str(e)}")
        return redirect(url_for('settings'))

@app.route('/synchronize-identity', methods=['POST'])
@login_required
def synchronize_identity():
    try:
        data = request.get_json()
        selected_avatar = data.get('selected_avatar')
        
        if not selected_avatar:
            return jsonify({'status': 'error', 'message': 'No avatar selected.'}), 400

        users_collection.update_one(
            {'_id': ObjectId(current_user.id)},
            {'$set': {'profile_pic': selected_avatar}}
        )
        
        current_user.profile_pic = selected_avatar
        session['profile_pic'] = selected_avatar
        session.modified = True
        
        return jsonify({'status': 'success', 'message': 'Profile Updated'})
    except Exception as e:
        print(f"DEBUG ERROR: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get-available-avatars', methods=['GET'])
@login_required
def get_available_avatars():
    avatar_dir = os.path.join(app.static_folder, 'images', 'avatars')
    
    if not os.path.exists(avatar_dir):
        return jsonify([])
        
    file_list = []
    for filename in os.listdir(avatar_dir):
        if filename.lower().endswith(('.png', '.jpg', '.jpeg')) and 'default' not in filename:
            file_list.append(filename)
            
    return jsonify(sorted(file_list))

@app.route('/block-tag', methods=['POST'])
@login_required
def block_tag():
    tag_to_block = request.form.get('tag_name', '').strip().lower()
    if tag_to_block:
        users_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$addToSet": {"blocked_tags": tag_to_block}}
        )
        flash(f"#{tag_to_block} successfully restricted from your content stream.", "success")
    return redirect(url_for('settings'))

@app.route('/unblock-tag/<tag_name>', methods=['POST'])
@login_required
def unblock_tag(tag_name):
    users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$pull": {"blocked_tags": tag_name.lower()}}
    )
    flash(f"#{tag_name} restriction revoked successfully.", "success")
    return redirect(url_for('settings'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        sec_question = request.form.get('security_question')
        sec_answer = request.form.get('security_answer', '').strip().lower()
        
        if not username or not email or not password:
            return jsonify({'status': 'error', 'message': 'All authorization parameters are required.'})
        
        try:
            if users_collection.find_one({"$or": [{"email": email}, {"username": username}]}):
                return jsonify({'status': 'error', 'message': 'Username or Email already exists.'})
                
            hashed_password = generate_password_hash(password)
            
            users_collection.insert_one({
                "username": username, 
                "email": email, 
                "password": hashed_password,
                "profile_pic": f"https://ui-avatars.com/api/?name={username}&background=2563eb&color=fff",
                "created_at": datetime.utcnow(),
                "blocked_tags": [],
                "security_question": sec_question,
                "security_answer": sec_answer
            })
            
            return jsonify({'status': 'success'})
            
        except Exception as database_error:
            print(f"MongoDB write transaction fallout registry error: {str(database_error)}")
            return jsonify({'status': 'error', 'message': 'Internal Cluster Registry Failure.'}), 500
            
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            client_ip = request.remote_addr or "127.0.0.1"
            
            if check_security_limit(client_ip, "login", max_attempts=3, window_minutes=1):
                return jsonify({
                    "status": "error", 
                    "message": "Security Shield Activated: Maximum attempt limit reached. Try again in 60 seconds."
                }), 429

            input_username = request.form.get('username', '').strip()
            input_password = request.form.get('password', '')
            
            user_data = users_collection.find_one({"username": input_username})
            
            if not user_data:
                log_failed_attempt(client_ip, "login")
                return render_template('401.html', text_override="Requested profile ID is invalid..."), 401
                
            if not check_password_hash(user_data['password'], input_password):
                log_failed_attempt(client_ip, "login")
                return jsonify({
                    'status': 'password_error', 
                    'message': 'Incorrect password signature. Please try again.'
                })
                
            clear_security_cache(client_ip, "login")
            
            login_as_admin = request.form.get('login_as_admin') == 'true'

            user_email_lower = user_data.get('email', '').strip().lower() if user_data.get('email') else ""
            is_user_admin = user_data.get('is_admin', False) or (user_email_lower in DEFAULT_ADMINS)

            if login_as_admin and not is_user_admin:
                return jsonify({
                    'status': 'error',
                    'message': 'Access Denied: Your identity registry does not hold administrative clearance.'
                }), 403
            
            if login_as_admin and is_user_admin:
                session['is_admin_session'] = True
            else:
                session.pop('is_admin_session', None)
            
            login_user(User(user_data))
            session_token = str(uuid.uuid4())
            
            ua = parse(request.user_agent.string)
            raw_ua = request.user_agent.string 

            if ua.is_pc:
                clean_device = f"{ua.browser.family} on {ua.os.family}"
            elif ua.is_mobile or ua.is_tablet:
                brand = str(ua.device.brand) if ua.device.brand else ""
                model = str(ua.device.model) if ua.device.model else ""
                family = str(ua.device.family) if ua.device.family else ""
                
                device_name = ""
                
                if brand and model and brand.lower() not in ["none", "generic"]:
                    device_name = f"{brand} {model}"
                elif family and family.lower() not in ["none", "generic smartphone", "generic", "other"]:
                    device_name = family
                    
                if len(device_name.strip()) <= 2:
                    match = re.search(r'Android \d+[a-zA-Z0-9._]*; (?:[a-zA-Z]{2}-[a-zA-Z]{2}; )?([^;)]+)', raw_ua)
                    if match:
                        extracted = match.group(1).split('Build')[0].strip()
                        if len(extracted) > 2:
                            device_name = extracted
                    
                if len(device_name.strip()) <= 2:
                    device_name = f"{ua.os.family} Smartphone"
                    
                clean_device = f"{ua.browser.family} on {device_name}"
                if ua.os.family and ua.os.family not in device_name:
                    clean_device += f" ({ua.os.family})"
            else:
                clean_device = f"{ua.browser.family} on {ua.os.family}"
            
            session_data = {
                "user_id": user_data['_id'],
                "session_token": session_token,
                "device_info": clean_device, 
                "ip_address": request.remote_addr,
                "last_active": datetime.utcnow()
            }
            db.sessions.insert_one(session_data)
            
            # 🚀 DYNAMIC REDIRECT WITH COLLAB & NEXT ROUTING
            next_target = request.args.get('next') or request.form.get('next')
            
            if login_as_admin and is_user_admin:
                redirect_url = url_for('admin_dashboard')
            elif next_target and next_target.startswith('/'):
                redirect_url = next_target
            else:
                redirect_url = url_for('index')
            
            response = jsonify({
                'status': 'success', 
                'redirect_url': redirect_url,
                'message': 'Master security authorization data metrics synchronized successfully.'
            })
            response.set_cookie('nexus_session_token', session_token, httponly=True, secure=False)
            return response
            
        except Exception as e:
            print("LOGIN DATABASE TIMEOUT ERROR:", e)
            return jsonify({'status': 'error', 'message': 'Database connection failed.'}), 500
            
    return render_template('login.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_data = users_collection.find_one({"_id": ObjectId(current_user.id)})
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        if new_password:
            hashed_password = generate_password_hash(new_password)
            
            users_collection.update_one(
                {"_id": ObjectId(current_user.id)},
                {"$set": {"password": hashed_password}}
            )
            
            user_email = user_data.get('email') or current_user.email
            notify_subject = "Nexus Cloud: Password Changed Successfully"
            notify_html = f"""
            <div style="font-family: 'Inter', Arial, sans-serif; max-width: 500px; margin: auto; padding: 30px; border: 1px solid #e2e8f0; border-radius: 20px; background-color: #ffffff; box-shadow: 0 4px 12px rgba(0,0,0,0.03);">
                <div style="text-align: center; margin-bottom: 20px;">
                    <span style="font-size: 40px;">🔒</span>
                </div>
                <h2 style="color: #0f172a; text-align: center; margin-top: 0; font-weight: 800; text-transform: uppercase; letter-spacing: -0.5px;">Password Updated</h2>
                <p style="color: #334155; font-size: 14px; line-height: 1.6; margin-top: 20px;">Hello <strong>{user_data.get('username', 'User')}</strong>,</p>
                <p style="color: #475569; font-size: 14px; line-height: 1.6;">This is an automated security notification to confirm that the security access credentials for your Nexus Cloud account were successfully changed via the Profile Settings panel.</p>
                <p style="color: #64748b; font-size: 13px; line-height: 1.6; background: #f8fafc; padding: 12px; border-radius: 10px; border-left: 4px solid #2563eb;">
                    <strong>Status:</strong> Verification Complete<br>
                    <strong>Location/Source:</strong> Account Security Panel
                </p>
                <p style="color: #475569; font-size: 14px; line-height: 1.6;">If you authorized this configuration change, your setup is complete and no further validation actions are required.</p>
                <hr style="border: none; border-top: 1px solid #f1f5f9; margin: 25px 0;">
                <p style="color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; text-align: center; margin-bottom: 0;">Securely deployed by,<br><strong>Nexus Cloud Core Matrix</strong></p>
            </div>
            """
            send_email(user_email, notify_subject, notify_html)
            
            flash("Your profile security settings and password have been successfully compiled.", "success")
            return redirect(url_for('settings'))
            
        flash("Password field cannot be empty.", "error")
        return redirect(url_for('settings'))

    user_sessions = list(db.sessions.find({"user_id": ObjectId(current_user.id)}))
    
    return render_template('settings.html', 
                            blocked_tags=user_data.get('blocked_tags', []),
                            user_sessions=user_sessions,
                            current_token=request.cookies.get('nexus_session_token'))

@app.before_request
def update_last_active():
    if request.endpoint and 'static' in request.endpoint:
        return

    if current_user.is_authenticated:
        token = request.cookies.get('nexus_session_token')
        
        if token:
            now = datetime.utcnow()
            last_checked_str = session.get('last_session_check')
            
            if last_checked_str:
                try:
                    last_checked_time = datetime.fromisoformat(last_checked_str)
                    if (now - last_checked_time).total_seconds() < 240:
                        return 
                except ValueError:
                    pass 

            session_record = db.sessions.find_one({"session_token": token})
            
            if not session_record:
                logout_user()
                session.clear()
            else:
                db.sessions.update_one(
                    {"session_token": token},
                    {"$set": {"last_active": now}}
                )
                session['last_session_check'] = now.isoformat()
        else:
            logout_user()
            
@app.after_request
def add_header(response):
    if 'text/html' in response.headers.get('Content-Type', ''):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

@app.route('/logout')
def logout():
    # 1. Database sessions collection se token delete karo
    token = request.cookies.get('nexus_session_token')
    if token and current_user.is_authenticated:
        db.sessions.delete_one({"session_token": token, "user_id": ObjectId(current_user.id)})

    # 2. Flask-Login aur Session data wipe karo
    logout_user()
    session.clear()

    # 3. Response banakar cookie udaao aur browser caching band karo
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('nexus_session_token')
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    
    flash("Signed out successfully.", "success")
    return resp

@app.route('/update-username', methods=['POST'])
@login_required
def update_username():
    try:
        data = request.get_json()
        new_username = data.get('new_username', '').strip()
        old_username = current_user.username

        if not new_username or len(new_username) < 3:
            return jsonify({"status": "error", "message": "Identity name must be at least 3 characters long."})
        
        if not re.match(r"^[a-zA-Z0-9_]+$", new_username):
            return jsonify({"status": "error", "message": "Only letters, numbers, and underscores are allowed."})

        existing_user = users_collection.find_one({"username": {"$regex": f"^{new_username}$", "$options": "i"}})
        if existing_user and str(existing_user['_id']) != current_user.id:
            return jsonify({"status": "error", "message": "This Identity is already taken by another user."})

        users_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {"username": new_username}}
        )

        images_collection.update_many(
            {"uploader": old_username},
            {"$set": {"uploader": new_username}}
        )

        folders_collection.update_many(
            {"owner": old_username},
            {"$set": {"owner": new_username}}
        )

        return jsonify({"status": "success", "message": "Global identity synchronized successfully."})

    except Exception as e:
        print("USERNAME UPDATE ERROR:", str(e))
        return jsonify({"status": "error", "message": "Critical database sync failure."})
    
@app.route('/cancel-account-deletion', methods=['POST'])
@login_required
def cancel_account_deletion():
    try:
        users_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {
                "is_scheduled_for_deletion": False,
                "delete_assets_option": False,
                "deletion_scheduled_at": None
            }}
        )
        
        session['is_scheduled_for_deletion'] = False
        session.pop('deletion_scheduled_at', None)
        
        return jsonify({'status': 'success', 'message': 'Account recovered successfully.'})
    except Exception as e:
        print(f"RECOVERY ERROR: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal recovery failure.'}), 500
    
@app.route('/revoke-session/<token>', methods=['POST'])
@login_required
def revoke_session(token):
    try:
        db.sessions.delete_one({
            "session_token": token, 
            "user_id": ObjectId(current_user.id)
        })
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    
@app.route('/revoke-all-sessions', methods=['POST'])
@login_required
def revoke_all_sessions():
    try:
        current_token = request.cookies.get('nexus_session_token')
        
        if not current_token:
            return jsonify({"status": "error", "message": "Current session context missing."}), 400
            
        result = db.sessions.delete_many({
            "user_id": ObjectId(current_user.id),
            "session_token": {"$ne": current_token}
        })
        
        return jsonify({
            "status": "success", 
            "message": f"Successfully remove {result.deleted_count} remote devices."
        })
    except Exception as e:
        print("REMOVE ALL ERROR:", str(e))
        return jsonify({"status": "error", "message": "Database sync failed."}), 500
    
@app.route('/get-images')
@login_required
def get_images():
    page = int(request.args.get('page', 1))
    per_page = 20  
    skip = (page - 1) * per_page
    
    images = list(images_collection.find({"owner": current_user.username})
                .sort("timestamp", -1)
                .skip(skip)
                .limit(per_page))
    
    return jsonify(json.loads(json_util.dumps(images)))

s = URLSafeTimedSerializer(app.secret_key)

@app.route('/generate-share-link/<folder_id>', methods=['POST'])
@login_required
def generate_share_link(folder_id):
    data = request.get_json()
    password = data.get('password')
    
    folder = folders_collection.find_one({"_id": ObjectId(folder_id), "owner": current_user.username})
    if not folder:
        return jsonify({"status": "error", "message": "Folder not found"}), 404

    if not folder.get('is_public', False):
        try:
            ua = parse(request.user_agent.string)
            raw_ua = request.user_agent.string

            if ua.is_pc:
                device_info = f"{ua.browser.family} on {ua.os.family}"
            elif ua.is_mobile or ua.is_tablet:
                brand = str(ua.device.brand) if ua.device.brand else ""
                model = str(ua.device.model) if ua.device.model else ""
                family = str(ua.device.family) if ua.device.family else ""
                
                device_name = ""
                
                if brand and model and brand.lower() not in ["none", "generic"]:
                    device_name = f"{brand} {model}"
                elif family and family.lower() not in ["none", "generic smartphone", "generic", "other"]:
                    device_name = family
                    
                if len(device_name.strip()) <= 2:
                    match = re.search(r'Android \d+[a-zA-Z0-9._]*; (?:[a-zA-Z]{2}-[a-zA-Z]{2}; )?([^;)]+)', raw_ua)
                    if match:
                        extracted = match.group(1).split('Build')[0].strip()
                        if len(extracted) > 2:
                            device_name = extracted
                    
                if len(device_name.strip()) <= 2:
                    device_name = f"{ua.os.family} Smartphone"
                    
                device_info = f"{ua.browser.family} on {device_name}"
                if ua.os.family and ua.os.family not in device_name:
                    device_info += f" ({ua.os.family})"
            else:
                device_info = f"{ua.browser.family} on {ua.os.family}"
            
            ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
            current_time = ist_time.strftime("%B %d, %Y at %I:%M %p IST")
            
            subject = "⚠️ Security Alert: Private Folder Shared"
            body = f"""
Hello {current_user.username},

A sharing link was generated for your PRIVATE folder '{folder['folder_name']}'.

Time: {current_time}
Device: {device_info}

If this was not you, please immediately secure your account.

Regards,
Nexus Security Team
"""
            
            dispatch_smtp_secure_email(current_user.email, current_user.username, subject, body)
        except Exception as e:
            print(f"Non-fatal Email Error: {e}") 

    hashed_pw = generate_password_hash(password) if password else None
    expiry_time = 172800 if password else None 
    
    token = s.dumps(str(folder_id), salt='folder-share-salt')
    
    folders_collection.update_one(
        {"_id": ObjectId(folder_id)},
        {"$set": {
            "share_token": token,
            "share_password": hashed_pw,
            "expiry_in_seconds": expiry_time
        }}
    )
    
    share_url = url_for('access_shared_folder', token=token, _external=True)
    return jsonify({"status": "success", "share_url": share_url})

@app.route('/share/access/<token>', methods=['GET', 'POST'])
def access_shared_folder(token):
    folder = folders_collection.find_one({"share_token": token})
    if not folder:
        return "Folder not found or link invalid.", 404
        
    expiry = folder.get('expiry_in_seconds') 
    
    try:
        folder_id = s.loads(token, salt='folder-share-salt', max_age=expiry)
    except:
        return "This link has expired or is invalid.", 403

    if str(folder['_id']) != str(folder_id):
        return "Invalid link.", 403

    if folder.get('share_password'):
        is_owner = current_user.is_authenticated and folder['owner'] == current_user.username
        
        if not is_owner:
            if request.method == 'POST':
                user_pw = request.form.get('password')
                if check_password_hash(folder['share_password'], user_pw):
                    session[f'access_{folder_id}'] = True
                else:
                    return render_template('password_prompt.html', token=token, error="Wrong Password!")
            
            if not session.get(f'access_{folder_id}'):
                return render_template('password_prompt.html', token=token)

    images = list(images_collection.find({"folder_name": folder['folder_name'], "in_trash": False}))
    return render_template('shared_view.html', images=images, folder=folder)

@app.route('/share/download-all/<token>')
def download_all_shared(token):
    folder = folders_collection.find_one({"share_token": token})
    if not folder:
        return "Folder not found.", 404
        
    expiry = folder.get('expiry_in_seconds')
    try:
        folder_id = s.loads(token, salt='folder-share-salt', max_age=expiry)
    except:
        return "Link has expired.", 403

    if folder.get('share_password') and not session.get(f'access_{folder_id}'):
        return "Unauthorized access.", 401
        
    images = list(images_collection.find({"folder_name": folder['folder_name'], "in_trash": False}))
    if not images:
        return "Folder is empty.", 404

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for img in images:
            try:
                s3_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=img['s3_key'])
                file_bytes = s3_obj['Body'].read()
                zf.writestr(img['filename'], file_bytes)
            except Exception as e:
                print(f"Error zipping {img['filename']}: {e}")
    
    memory_file.seek(0)
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"{folder['folder_name']}_Nexus_Assets.zip"
    )

def send_password_change_notification(user_email):
    user_record = users_collection.find_one({"email": user_email})
    username = user_record.get("username", "User") if user_record else "User"
    
    ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
    
    current_date = ist_time.strftime("%B %d, %Y")
    current_time = ist_time.strftime("%I:%M %p IST") 
    
    subject = "Security Notice: Your Nexus Cloud password was changed"
    
    body = f"""Hello {username},

This is a confirmation that your password for Nexus Cloud was updated on {current_date} at {current_time}.

If you made this change: No action is needed.

If you did not authorize this change: Secure your account immediately by resetting your password on the login portal or contact our support team.

For your security, always ensure you are accessing your account through official channels.

Best regards,
The Nexus Cloud Security Team
"""
    
    try:
        dispatch_smtp_secure_email(user_email, username, subject, body)
    except Exception as e:
        print(f"Notification Email Skipped: {e}")
        
# ---------------------------------------------------
# 👥 PEOPLE HUB & FACE MANAGEMENT ROUTES
# ---------------------------------------------------

@app.route('/people')
@login_required
def people_hub():
    people_list = list(people_collection.find({"user": current_user.username}).sort("created_at", -1))
    
    # Har person ki total photos count calculate karo
    for person in people_list:
        person_id_str = str(person['_id'])
        count = images_collection.count_documents({
            "uploader": current_user.username,
            "people": person_id_str,
            "in_trash": {"$ne": True}
        })
        person['photo_count'] = count

    return render_template('people.html', people=people_list)


@app.route('/person/<person_id>')
@login_required
def person_gallery(person_id):
    person = people_collection.find_one({"_id": ObjectId(person_id), "user": current_user.username})
    if not person:
        return render_template('404.html', text_override="Person record not found."), 404

    # Is person ki saari photos fetch karo
    person_photos = list(images_collection.find({
        "uploader": current_user.username,
        "people": person_id,
        "in_trash": {"$ne": True}
    }).sort("uploaded_at", -1))

    return render_template('person_view.html', person=person, images=person_photos)


@app.route('/rename-person/<person_id>', methods=['POST'])
@login_required
def rename_person(person_id):
    try:
        data = request.get_json() or {}
        new_name = data.get('new_name', '').strip()
        
        if not new_name:
            return jsonify({"status": "error", "message": "Name cannot be empty."}), 400

        people_collection.update_one(
            {"_id": ObjectId(person_id), "user": current_user.username},
            {"$set": {"name": new_name}}
        )
        return jsonify({"status": "success", "message": f"Updated name to '{new_name}'."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
# ---------------------------------------------------
# 🔗 PERSON LINK GENERATION, SHARING & ZIP DOWNLOAD
# ---------------------------------------------------

@app.route('/generate-person-share-link/<person_id>', methods=['POST'])
@login_required
def generate_person_share_link(person_id):
    try:
        data = request.get_json() or {}
        password = data.get('password')
        
        person = people_collection.find_one({"_id": ObjectId(person_id), "user": current_user.username})
        if not person:
            return jsonify({"status": "error", "message": "Person profile not found."}), 404

        hashed_pw = generate_password_hash(password) if password else None
        expiry_time = 172800 if password else None # Password hai to 48 hrs, warna permanent
        
        token = s.dumps(str(person_id), salt='person-share-salt')
        
        people_collection.update_one(
            {"_id": ObjectId(person_id)},
            {"$set": {
                "share_token": token,
                "share_password": hashed_pw,
                "expiry_in_seconds": expiry_time
            }}
        )
        
        share_url = url_for('access_shared_person', token=token, _external=True)
        return jsonify({"status": "success", "share_url": share_url})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/share/person/access/<token>', methods=['GET', 'POST'])
def access_shared_person(token):
    person = people_collection.find_one({"share_token": token})
    if not person:
        return "Shared person album not found or link is invalid.", 404
        
    expiry = person.get('expiry_in_seconds')
    try:
        person_id = s.loads(token, salt='person-share-salt', max_age=expiry)
    except:
        return "This shared person link has expired or is invalid.", 403

    if str(person['_id']) != str(person_id):
        return "Invalid token parameter signature.", 403

    # Password Protection Check
    if person.get('share_password'):
        is_owner = current_user.is_authenticated and person['user'] == current_user.username
        if not is_owner:
            if request.method == 'POST':
                user_pw = request.form.get('password')
                if check_password_hash(person['share_password'], user_pw):
                    session[f'access_person_{person_id}'] = True
                else:
                    return render_template('password_prompt.html', token=token, error="Wrong Password!")
            
            if not session.get(f'access_person_{person_id}'):
                return render_template('password_prompt.html', token=token)

    # Fetch all photos containing this person across all folders
    images = list(images_collection.find({
        "uploader": person['user'],
        "people": str(person['_id']),
        "in_trash": {"$ne": True}
    }).sort("uploaded_at", -1))
    
    return render_template('shared_person_view.html', images=images, person=person)


@app.route('/share/person/download-all/<token>')
def download_all_person_shared(token):
    person = people_collection.find_one({"share_token": token})
    if not person:
        return "Person album not found.", 404
        
    expiry = person.get('expiry_in_seconds')
    try:
        person_id = s.loads(token, salt='person-share-salt', max_age=expiry)
    except:
        return "Link has expired.", 403

    if person.get('share_password') and not session.get(f'access_person_{person_id}'):
        return "Unauthorized access.", 401
        
    images = list(images_collection.find({
        "uploader": person['user'],
        "people": str(person['_id']),
        "in_trash": {"$ne": True}
    }))
    if not images:
        return "No assets found to download.", 404

    # In-Memory ZIP generation
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for img in images:
            try:
                s3_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=img['s3_key'])
                file_bytes = s3_obj['Body'].read()
                zf.writestr(img['filename'], file_bytes)
            except Exception as e:
                print(f"Error zipping {img['filename']}: {e}")
    
    memory_file.seek(0)
    clean_name = person['name'].replace(" ", "_")
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"{clean_name}_Nexus_Photos.zip"
    )
        
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    general_assets = list(images_collection.find({"folder_name": {"$regex": "^General$", "$options": "i"}, "in_trash": False}).sort("uploaded_at", -1))
    all_users = list(users_collection.find({}))
    active_rules = list(moderation_rules_collection.find({}).sort("created_at", -1))
    return render_template('admin_dashboard.html', assets=general_assets, users=all_users, default_admins=DEFAULT_ADMINS, rules=active_rules)

@app.route('/admin/promote', methods=['POST'])
@admin_required
def admin_promote():
    data = request.get_json() or {}
    target_username = data.get('username', '').strip()
    
    user = users_collection.find_one({"username": target_username})
    if not user:
        return jsonify({"status": "error", "message": "User node not found."}), 404
        
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"is_admin": True}})
    
    ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
    current_time = ist_time.strftime("%B %d, %Y at %I:%M %p IST")
    
    subject_master = "🚨 Security Notice: New Administrator Appointed"
    body_master = f"""Hello Administrator,

This is an automated security report from the Nexus Control Shield. A new identity profile has been granted administrative access parameters.

[PROMOTED USER DETAILS]
Account Username: {user['username']}
Registered Email: {user.get('email', 'N/A')}

[AUTHORIZER DETAILS]
Authorized By: {current_user.username}
Authorizer Email: {getattr(current_user, 'email', 'N/A')}

Timestamp: {current_time}

If you did not authorize this deployment, please log into your default root account and revoke permissions immediately.

Best regards,
The Nexus Cloud Security Team"""
    
    for master_email in DEFAULT_ADMINS:
        try: dispatch_smtp_secure_email(master_email, "Master Admin", subject_master, body_master)
        except Exception as e: print(f"Master Email error: {e}")

    if user.get('email'):
        subject_new_admin = "🎉 Access Granted: Welcome to the Nexus Admin Cluster"
        body_new_admin = f"""Hello {user['username']},

Congratulations! You have been officially appointed as an Administrator on the Nexus Cloud Platform.

Your identity profile has been successfully integrated into the Core Administrative Matrix. This clearance grants you high-level system parameters to regulate public ingest content schemas, handle directory clusters, and manage global repository security.

With great power comes great responsibility. As a member of the admin cluster, you hold master keys to data structures. We trust you to handle these privileges ethically, securely, and professionally to protect our global user network. Please ensure all system updates and asset management conform strictly to our compliance protocols.

Welcome aboard the core node team.

Best regards,
The Nexus Global Governance Board"""
        try:
            dispatch_smtp_secure_email(user['email'], user['username'], subject_new_admin, body_new_admin)
        except Exception as e:
            print(f"New Admin Notification Email Skipped: {e}")

    return jsonify({"status": "success", "message": f"{target_username} promoted to Admin and notified successfully."})

@app.route('/admin/demote', methods=['POST'])
@admin_required
def admin_demote():
    data = request.get_json() or {}
    target_username = data.get('username', '').strip()
    
    user = users_collection.find_one({"username": target_username})
    if not user: 
        return jsonify({"status": "error", "message": "User not found."}), 404
        
    if user.get('email') in DEFAULT_ADMINS:
        return jsonify({"status": "error", "message": "Critical Denial: Master Core root profiles cannot be demoted."}), 403
        
    if user['username'] == current_user.username:
        return jsonify({"status": "error", "message": "Critical Denial: You cannot revoke your own administrative clearance."}), 400
        
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"is_admin": False}})
    return jsonify({"status": "success", "message": f"{target_username} removed from admin privileges."})

@app.route('/admin/manage-asset/<action>/<image_id>', methods=['POST'])
@admin_required
def admin_manage_asset(action, image_id):
    asset = images_collection.find_one({"_id": ObjectId(image_id)})
    if not asset: return jsonify({"status": "error", "message": "Asset not found"}), 404
        
    if action == 'delete':
        try:
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=asset['s3_key'])
            try: s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"thumb_{asset['s3_key']}")
            except: pass
            images_collection.delete_one({"_id": ObjectId(image_id)})
            return jsonify({"status": "success", "message": "Asset purged completely."})
        except Exception as e: return jsonify({"status": "error", "message": str(e)})
            
    elif action in ['public', 'private']:
        is_public_flag = (action == 'public')
        images_collection.update_one({"_id": ObjectId(image_id)}, {"$set": {"is_public": is_public_flag}})
        return jsonify({"status": "success", "message": "Asset privacy status updated."})
        
    return jsonify({"status": "error", "message": "Invalid action."}), 400

# ---------------------------------------------------
# ERROR OVERRIDE HANDLERS
# ---------------------------------------------------
@app.errorhandler(401)
def unauthorized_error(e):
    return render_template('401.html', text_override="Access Unauthorized: The requested identity profile is invalid or requires authentication."), 401

@app.errorhandler(403)
def forbidden_error(e):
    return render_template('401.html', text_override="Security Shield: Administrative clearance level required to access this matrix node."), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/admin/moderation/add', methods=['POST'])
@admin_required
def admin_add_moderation_rule():
    data = request.get_json() or {}
    new_label = data.get('label', '').strip().lower()
    
    if not new_label:
        return jsonify({"status": "error", "message": "Security tracking node value cannot be null."}), 400
        
    exists = moderation_rules_collection.find_one({"label": new_label})
    if exists:
        return jsonify({"status": "error", "message": "This label target registry parameter already exists inside the active shield shield system."}), 400
        
    moderation_rules_collection.insert_one({
        "label": new_label,
        "created_at": datetime.utcnow()
    })
    return jsonify({"status": "success", "message": f"AI Moderation shield updated successfully: Tracking parameter '{new_label}' is now active."})

@app.route('/admin/moderation/delete/<rule_id>', methods=['POST'])
@admin_required
def admin_delete_moderation_rule(rule_id):
    try:
        moderation_rules_collection.delete_one({"_id": ObjectId(rule_id)})
        return jsonify({"status": "success", "message": "Dynamic shield tracking parameter removed safely."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
# ---------------------------------------------------
# 🤝 COLLABORATIVE WORKSPACE & MULTI-USER ROOMS
# ---------------------------------------------------

@app.route('/generate-collab-link/<folder_id>', methods=['POST'])
@login_required
def generate_collab_link(folder_id):
    try:
        data = request.get_json(silent=True) or {}
        password = data.get('password')
        
        folder = folders_collection.find_one({"_id": ObjectId(folder_id), "owner": current_user.username})
        if not folder:
            return jsonify({"status": "error", "message": "Folder not found."}), 404

        hashed_pw = generate_password_hash(password) if password else None
        
        # Dedicated Token Serializer
        serializer = URLSafeTimedSerializer(app.secret_key)
        token = serializer.dumps(str(folder_id), salt='collab-room-salt')
        
        folders_collection.update_one(
            {"_id": ObjectId(folder_id)},
            {"$set": {
                "is_collab": True,
                "collab_token": token,
                "collab_password": hashed_pw
            }}
        )
        
        collab_url = url_for('access_collab_room', token=token, _external=True)
        return jsonify({"status": "success", "collab_url": collab_url})
    except Exception as e:
        print(f"Collab Generation Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/collab/room/<token>', methods=['GET', 'POST'])
def access_collab_room(token):
    folder = folders_collection.find_one({"collab_token": token})
    if not folder:
        return "Collaborative workspace not found or invalid link.", 404

    folder_id = str(folder['_id'])
    try:
        s.loads(token, salt='collab-room-salt')
    except:
        return "Workspace link has expired or is invalid.", 403

    # Password Check
    if folder.get('collab_password'):
        is_owner = current_user.is_authenticated and folder['owner'] == current_user.username
        if not is_owner:
            if request.method == 'POST':
                user_pw = request.form.get('password')
                if check_password_hash(folder['collab_password'], user_pw):
                    session[f'collab_access_{folder_id}'] = True
                else:
                    return render_template('password_prompt.html', token=token, error="Incorrect Workspace Password!")
            
            if not session.get(f'collab_access_{folder_id}'):
                return render_template('password_prompt.html', token=token)

    # 🚀 AUTO-JOIN & PERMANENT CONTRIBUTORS SYNC
    if current_user.is_authenticated and current_user.username != folder['owner']:
        folders_collection.update_one(
            {"_id": folder['_id']},
            {
                "$addToSet": {"contributors": current_user.username},
                "$set": {"is_collab": True}
            }
        )

    # Case-insensitive photos fetch
    images = list(images_collection.find({
        "folder_name": {"$regex": f"^{re.escape(folder['folder_name'])}$", "$options": "i"},
        "in_trash": False
    }).sort("uploaded_at", -1))
    
    return render_template('collab_room.html', folder=folder, images=images)

@app.route('/collab/upload/<token>', methods=['POST'])
def collab_upload(token):
    folder = folders_collection.find_one({"collab_token": token})
    if not folder:
        return jsonify({"status": "error", "message": "Room not found."}), 404

    # Security check for password protected room
    folder_id = str(folder['_id'])
    if folder.get('collab_password'):
        is_owner = current_user.is_authenticated and folder['owner'] == current_user.username
        if not is_owner and not session.get(f'collab_access_{folder_id}'):
            return jsonify({"status": "error", "message": "Unauthorized room access."}), 403

    if 'image' not in request.files:
        return jsonify({"status": "error", "message": "No files selected."}), 400

    files = request.files.getlist('image')
    guest_name = request.form.get('guest_name', '').strip()
    
    # Uploader Name decide karo
    if current_user.is_authenticated:
        uploader_identity = current_user.username
    elif guest_name:
        uploader_identity = f"{guest_name} (Guest)"
    else:
        uploader_identity = "Guest Explorer"

    uploaded_count = 0
    for file in files:
        if file.filename == '':
            continue
        try:
            orig_name = secure_filename(file.filename)
            filename = f"collab_{int(datetime.utcnow().timestamp())}_{orig_name}"
            thumb_filename = f"thumb_{filename}"
            file_bytes = file.read()

            s3_client.put_object(Bucket=BUCKET_NAME, Key=filename, Body=file_bytes, ContentType=file.content_type)

            # Thumbnail generation
            try:
                img = Image.open(BytesIO(file_bytes))
                if img.mode in ("RGBA", "P"): img = img.convert("RGB")
                img.thumbnail((600, 600))
                thumb_io = BytesIO()
                img.save(thumb_io, format='JPEG', quality=60)
                thumb_io.seek(0)
                s3_client.put_object(Bucket=BUCKET_NAME, Key=thumb_filename, Body=thumb_io.getvalue(), ContentType='image/jpeg')
            except:
                thumb_filename = filename

            # AI Tags
            ai_tags = []
            try:
                rek_resp = rek_client.detect_labels(Image={'S3Object': {'Bucket': BUCKET_NAME, 'Name': filename}}, MaxLabels=10)
                ai_tags = [label['Name'].lower() for label in rek_resp['Labels']]
            except:
                pass

            images_collection.insert_one({
                "filename": orig_name,
                "s3_key": filename,
                "url": f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{filename}",
                "thumb_url": f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{thumb_filename}",
                "tags": ai_tags,
                "uploader": uploader_identity,
                "folder_name": folder['folder_name'],
                "views": 0, "likes": 0, "shares": 0, "downloads": 0,
                "is_favorite": False, "in_trash": False,
                "uploaded_at": datetime.utcnow(),
                "is_public": folder.get('is_public', False)
            })
            uploaded_count += 1
        except Exception as e:
            print(f"Collab upload error: {e}")

    return jsonify({"status": "success", "message": f"Successfully added {uploaded_count} photos to {folder['folder_name']}!"})

# 🚀 APP.RUN KO HAMESHA FILE KE EK DUM LAST MEIN HONA CHAHIYE
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
    
    
    















































# import os
# import re
# import uuid
# import boto3
# import smtplib
# import random
# import certifi
# import json
# import traceback
# import zipfile
# import urllib.request
# from flask import send_file
# from PIL import Image
# from io import BytesIO
# from bson import ObjectId
# from bson import json_util
# from flask import session
# from functools import wraps
# from user_agents import parse 
# from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
# from dotenv import load_dotenv
# from pymongo import MongoClient
# from datetime import datetime, timedelta
# from flask import make_response, redirect, url_for
# from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# from werkzeug.security import generate_password_hash, check_password_hash
# from werkzeug.utils import secure_filename
# from flask import abort
# from itsdangerous import URLSafeTimedSerializer
# from bson.objectid import ObjectId
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# from email.utils import formatdate, make_msgid
# from apscheduler.schedulers.background import BackgroundScheduler

# # ---------------------------------------------------
# # CONFIGURATION & CLOUD SETUP
# # ---------------------------------------------------
# load_dotenv()
# app = Flask(__name__)
# app.secret_key = os.getenv('SECRET_KEY', 'nexus_premium_key_999')

# # ---------------------------------------------------
# # CYBERSECURITY: NATIVE INTRUSION DETECTION SYSTEM (IDS)
# # ---------------------------------------------------
# # Yeh hamara custom RAM-based security tracker hai
# SECURITY_CACHE = {}

# def check_security_limit(ip, action, max_attempts=3, window_minutes=1):
#     """Check karega ki user block hua hai ya nahi (With Terminal Logs)"""
#     now = datetime.utcnow()
#     cache_key = f"{ip}_{action}"
    
#     if cache_key in SECURITY_CACHE:
#         # Purane attempts ko strict seconds logic se hatao
#         valid_attempts = [t for t in SECURITY_CACHE[cache_key] if (now - t).total_seconds() < (window_minutes * 60)]
#         SECURITY_CACHE[cache_key] = valid_attempts
        
#         # 🟢 TERMINAL PAR LIVE DEKHEIN: Kitne attempts hue
#         print(f"🔒 [SECURITY LOG] Action: {action} | Failed Attempts: {len(valid_attempts)}/{max_attempts}")
        
#         if len(valid_attempts) >= max_attempts:
#             # 🔴 TERMINAL PAR LIVE DEKHEIN: Shield Triggered
#             print(f"🚨 [ALERT] INTRUSION DETECTED! IP {ip} BLOCKED FOR 60 SECONDS!")
#             return True
            
#     return False

# def log_failed_attempt(ip, action):
#     """Har galat attempt ko memory mein save karega"""
#     cache_key = f"{ip}_{action}"
#     SECURITY_CACHE.setdefault(cache_key, []).append(datetime.utcnow())

# def clear_security_cache(ip, action):
#     """Sahi Login hone par pichle saare errors maaf kar dega (Clear)"""
#     cache_key = f"{ip}_{action}"
#     if cache_key in SECURITY_CACHE:
#         del SECURITY_CACHE[cache_key]

# # AWS Configuration
# ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')
# SECRET_KEY_AWS = os.getenv('AWS_SECRET_ACCESS_KEY')
# BUCKET_NAME = os.getenv('AWS_BUCKET_NAME')
# REGION = os.getenv('AWS_REGION', 'us-east-1')

# s3_client = boto3.client('s3', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY_AWS, region_name=REGION)
# rek_client = boto3.client('rekognition', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY_AWS, region_name=REGION)

# # Database Setup
# MONGO_URI = os.getenv('MONGO_URI')
# import certifi
# client = MongoClient(
#     MONGO_URI,
#     tlsCAFile=certifi.where(),
# )
# # client = MongoClient(MONGO_URI, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
# db = client['NexusCloud_V2']
# images_collection = db['assets']
# users_collection = db['accounts']
# folders_collection = db['directories']
# moderation_rules_collection = db['moderation_rules']

# # --- Yahan add karo ---
# RECOVERY_OTP_CACHE = {} 
# # ----------------------
# # ---------------------------------------------------
# # OTP CLEANUP TASK (Background mein chalega)
# # ---------------------------------------------------
# def cleanup_otp_cache():
#     """15 minute se purane OTPs ko remove karega"""
#     print(f"[{datetime.utcnow()}] 🧹 Cleaning up expired OTPs...")
#     now = datetime.utcnow()
#     # List comprehension ka use karke sirf expired entries delete karein
#     expired_keys = [user for user, data in RECOVERY_OTP_CACHE.items() 
#                     if (now - data['timestamp']).total_seconds() > 900]
#     for user in expired_keys:
#         RECOVERY_OTP_CACHE.pop(user, None)


# # ---------------------------------------------------
# # BACKGROUND CLEANUP SCHEDULER
# # ---------------------------------------------------
# def background_cleanup():
#     """Daily automated task to process expired deletion requests."""
#     print(f"[{datetime.utcnow()}] Running daily account cleanup task...")
#     now = datetime.utcnow()
    
#     # Un sabhi accounts ko dhundo jinhe 30 din ho chuke hain
#     expired_accounts = list(users_collection.find({"is_scheduled_for_deletion": True, "deletion_scheduled_at": {"$lte": now}}))
    
#     for user in expired_accounts:
#         if user.get("delete_assets_option", False):
#             # Asset cleanup logic (S3 + MongoDB)
#             user_assets = list(images_collection.find({"uploader": user['username']}))
#             for asset in user_assets:
#                 try:
#                     # Original image delete karo
#                     s3_client.delete_object(Bucket=BUCKET_NAME, Key=asset['s3_key'])
                    
#                     # 🧹 THUMBNAIL BHI DELETE KARO
#                     s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"thumb_{asset['s3_key']}")
#                 except Exception as e:
#                     print(f"Error purging S3 asset: {e}")
            
#             # MongoDB se user ki saari images delete karo
#             images_collection.delete_many({"uploader": user['username']})
        
#         # User account delete karo
#         users_collection.delete_one({"_id": user['_id']})
#         print(f"Purged account: {user['username']}")

# scheduler = BackgroundScheduler()
# scheduler.add_job(func=background_cleanup, trigger="interval", days=1)
# scheduler.add_job(func=cleanup_otp_cache, trigger="interval", minutes=15) # 15 min mein cache check
# scheduler.start()

# # ---------------------------------------------------
# # AUTHENTICATION SETUP
# # ---------------------------------------------------
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'

# DEFAULT_ADMINS = ["parmanandsahu2005@gmail.com", "nexuscloud.admin@gmail.com"]

# class User(UserMixin):
#     def __init__(self, user_data):
#         self.id = str(user_data['_id'])
#         self.username = user_data['username']
#         self.email = user_data.get('email')
#         self.profile_pic = user_data.get('profile_pic', 'https://ui-avatars.com/api/?name=' + user_data['username'])
#         self.is_scheduled_for_deletion = user_data.get('is_scheduled_for_deletion', False)
#         self.deletion_scheduled_at = user_data.get('deletion_scheduled_at')
#         user_email_lower = user_data.get('email', '').strip().lower() if user_data.get('email') else ""
#         self.is_admin = user_data.get('is_admin', False) or (user_email_lower in DEFAULT_ADMINS)

# # 🛡️ ADMINISTRATIVE SECURITY SHIELD OVERRIDE
# def admin_required(f):
#     @wraps(f)
#     @login_required
#     def decorated_function(*args, **kwargs):
#         if not getattr(current_user, 'is_admin', False) or not session.get('is_admin_session'):
#             return render_template('404.html', text_override="Security Shield: Active administrative clearance token required for this session."), 403
#         return f(*args, **kwargs)
#     return decorated_function

# # class User(UserMixin):
# #     def __init__(self, user_data):
# #         self.id = str(user_data['_id'])
# #         self.username = user_data['username']
# #         self.email = user_data.get('email')
# #         self.profile_pic = user_data.get('profile_pic', 'https://ui-avatars.com/api/?name=' + user_data['username'])
# #         self.is_scheduled_for_deletion = user_data.get('is_scheduled_for_deletion', False)
# #         self.deletion_scheduled_at = user_data.get('deletion_scheduled_at')


# @app.route('/test')
# def test():
#     return "Server is working perfectly!"


# @login_manager.user_loader
# def load_user(user_id):
#     # Agar user_id invalid hua toh ObjectId error dega, isliye check zaroori hai
#     try:
#         user_data = users_collection.find_one({"_id": ObjectId(user_id)})
#         return User(user_data) if user_data else None
#     except:
#         return None

# # Smart Analytics Global Context Processor
# @app.context_processor
# def inject_usage_stats():
#     if current_user.is_authenticated:
#         total_assets = images_collection.count_documents({"uploader": current_user.username, "in_trash": False})
#         trash_count = images_collection.count_documents({"uploader": current_user.username, "in_trash": True})
#         return dict(total_assets=total_assets, trash_count=trash_count)
#     return dict(total_assets=0, trash_count=0)

# # ---------------------------------------------------
# # CORE ROUTES (EXPLORE & SEARCH)
# # ---------------------------------------------------

# # @app.route('/')
# # def index():
# #     return render_template('index.html', images=[], folders=[], trending_tags=[], search_query='')

# # ------------------------------------------------------------------
# # 🔥 EXPLORE PAGE & INFINITE SCROLL (SYNCHRONIZED CORE)
# # ------------------------------------------------------------------
# @app.route('/')
# def index():
#     try:
#         search_query = request.args.get('q', '').strip()
#         per_page = 15 
        
#         # Base Security Query (Trash items hidden)
#         query = {
#             "in_trash": {"$ne": True}, 
#             "$or": [
#                 {"is_public": True},
#                 {
#                     "folder_name": {"$regex": "^General$", "$options": "i"}, 
#                     "is_public": {"$ne": False}  # Missing ya true chalega, bas explicitly False nahi hona chahiye
#                 }
#             ]
#         }
#         # query = {
#         #     "in_trash": {"$ne": True}, 
#         #     "is_public": True
#         # }
#         # query = {
#         #     "in_trash": {"$ne": True}, 
#         #     "$or": [
#         #         {"is_public": True},
#         #         {"folder_name": {"$regex": "^General$", "$options": "i"}}
#         #     ]
#         # }
        
#         # AI Search Filter
#         if search_query:
#             safe_query = re.escape(search_query)
#             query["$and"] = [{
#                 "$or": [
#                     {"tags": {"$regex": safe_query, "$options": "i"}},
#                     {"filename": {"$regex": safe_query, "$options": "i"}}
#                 ]
#             }]
            
#         # Private Mode (Blocked Tags Filter)
#         if current_user.is_authenticated:
#             user_profile = users_collection.find_one({"username": current_user.username})
#             if user_profile and user_profile.get('blocked_tags'):
#                 blocked_tags = user_profile['blocked_tags']
#                 escaped = [re.escape(str(t).strip().lower()) for t in blocked_tags if str(t).strip()]
#                 if escaped:
#                     block_condition = {"tags": {"$not": {"$elemMatch": {"$regex": "|".join(escaped), "$options": "i"}}}}
#                     if "$and" in query:
#                         query["$and"].append(block_condition)
#                     else:
#                         query["$and"] = [block_condition]

#         # Dropdown Folders Logic
#         user_folders = []
#         if current_user.is_authenticated:
#             user_folders = list(folders_collection.find({"owner": current_user.username}))
#             user_folders.sort(key=lambda x: str(x.get('_id')), reverse=True)
#             for folder in user_folders:
#                 folder['asset_count'] = images_collection.count_documents({
#                     "uploader": current_user.username, 
#                     "folder_name": folder['folder_name'],
#                     "in_trash": {"$ne": True}
#                 })

#         # Trending AI Tags Logic
#         trending = []
#         try:
#             trending = list(images_collection.aggregate([
#                 {"$match": query}, 
#                 {"$unwind": "$tags"},
#                 {"$sort": {"uploaded_at": -1}}, 
#                 {"$limit": 50},
#                 {"$group": {"_id": "$tags", "count": {"$sum": 1}}}, 
#                 {"$sort": {"count": -1}}, 
#                 {"$limit": 10}
#             ]))
#             trending = [t for t in trending if t.get('_id')]
#         except Exception:
#             pass

#         # Initial 15 Images Fetch
#         pipeline = [
#             {"$match": query},
#             {"$sort": {"uploaded_at": -1}}, 
#             {"$limit": per_page},
#             {"$lookup": {"from": "accounts", "localField": "uploader", "foreignField": "username", "as": "uploader_meta"}},
#             {"$addFields": {"profile_pic": {"$arrayElemAt": ["$uploader_meta.profile_pic", 0]}}}
#         ]
        
#         all_images = list(images_collection.aggregate(pipeline))
#         return render_template('index.html', images=all_images, folders=user_folders, trending_tags=trending, search_query=search_query)

#     except Exception as e:
#         print("CRITICAL INDEX ERROR:", e)
#         return render_template('index.html', images=[], folders=[], trending_tags=[], search_query='')

# @app.route('/load-more')
# def load_more():
#     try:
#         scroll_page = request.args.get('page', 1, type=int)
#         search_query = request.args.get('q', '').strip()
        
#         per_page = 15  
#         skip_count = (scroll_page - 1) * per_page
        
#         query = {
#             "in_trash": {"$ne": True}, 
#             "$or": [
#                 {"is_public": True},
#                 {
#                     "folder_name": {"$regex": "^General$", "$options": "i"}, 
#                     "is_public": {"$ne": False}
#                 }
#             ]
#         }
#         # query = {
#         #     "in_trash": {"$ne": True}, 
#         #     "is_public": True
#         # }
#         # query = {
#         #     "in_trash": {"$ne": True}, 
#         #     "$or": [
#         #         {"is_public": True},
#         #         {"folder_name": {"$regex": "^General$", "$options": "i"}}
#         #     ]
#         # }
        
#         if search_query:
#             safe_query = re.escape(search_query)
#             query["$and"] = [{
#                 "$or": [
#                     {"tags": {"$regex": safe_query, "$options": "i"}},
#                     {"filename": {"$regex": safe_query, "$options": "i"}}
#                 ]
#             }]
            
#         if current_user.is_authenticated:
#             user_profile = users_collection.find_one({"username": current_user.username})
#             if user_profile and user_profile.get('blocked_tags'):
#                 blocked_tags = user_profile['blocked_tags']
#                 escaped = [re.escape(str(t).strip().lower()) for t in blocked_tags if str(t).strip()]
#                 if escaped:
#                     block_condition = {"tags": {"$not": {"$elemMatch": {"$regex": "|".join(escaped), "$options": "i"}}}}
#                     if "$and" in query:
#                         query["$and"].append(block_condition)
#                     else:
#                         query["$and"] = [block_condition]

#         pipeline = [
#             {"$match": query},
#             {"$sort": {"uploaded_at": -1}}, 
#             {"$skip": skip_count},          
#             {"$limit": per_page},           
#             {"$lookup": {"from": "accounts", "localField": "uploader", "foreignField": "username", "as": "uploader_meta"}},
#             {"$addFields": {"profile_pic": {"$arrayElemAt": ["$uploader_meta.profile_pic", 0]}}}
#         ]
        
#         new_images = list(images_collection.aggregate(pipeline))
        
#         # 100% JSON Safe Response Format
#         return jsonify(json.loads(json_util.dumps(new_images)))
        
#     except Exception as e:
#         print("Infinite Scroll Backend Error:", e)
#         return jsonify([])

# @app.route('/search')
# def search():
#     query = request.args.get('q')
#     if not query: return redirect(url_for('index'))

#     # 1. Search Filters Logic (अब Public OR General फोल्डर दोनों की इमेजेज सर्च होंगी)
#     # Search filter legacy override control matrix
#     search_filter = {
#         "in_trash": False,
#         "$or": [
#             {"is_public": True},
#             {
#                 "folder_name": {"$regex": "^General$", "$options": "i"}, 
#                 "is_public": {"$ne": False}
#             }
#         ],
#         "$and": [
#             {
#                 "$or": [
#                     {"tags": {"$regex": query, "$options": "i"}},
#                     {"filename": {"$regex": query, "$options": "i"}}
#                 ]
#             }
#         ]
#     }
#     # search_filter = {
#     #     "in_trash": False,
#     #     "is_public": True,
#     #     "$and": [
#     #         {
#     #             "$or": [
#     #                 {"tags": {"$regex": query, "$options": "i"}},
#     #                 {"filename": {"$regex": query, "$options": "i"}}
#     #             ]
#     #         }
#     #     ]
#     # }
#     # search_filter = {
#     #     "in_trash": False,
#     #     "$or": [
#     #         {"is_public": True},          # कंडीशन 1: इमेज पब्लिक हो
#     #         {"folder_name": "General"}   # कंडीशन 2: या फिर General फोल्डर की हो
#     #     ],
#     #     "$and": [
#     #         {
#     #             "$or": [
#     #                 {"tags": {"$regex": query, "$options": "i"}},
#     #                 {"filename": {"$regex": query, "$options": "i"}}
#     #             ]
#     #         }
#     #     ]
#     # }
    
#     if current_user.is_authenticated:
#         user_profile = users_collection.find_one({"_id": ObjectId(current_user.id)})
#         blocked_tags = user_profile.get('blocked_tags', []) if user_profile else []
        
#         if blocked_tags:
#             strict_filters = []
#             for t in blocked_tags:
#                 clean_t = str(t).strip().lower()
#                 strict_filters.append(clean_t)
#                 strict_filters.append(f"#{clean_t}")
#             regex_patterns = [f"^{re.escape(tag)}$" for tag in strict_filters]
            
#             # Blocked tags को सर्च रिजल्ट्स से हटाना
#             search_filter["tags"] = {
#                 "$not": {
#                     "$elemMatch": {
#                         "$regex": "|".join(regex_patterns), 
#                         "$options": "i"
#                     }
#                 }
#             }

#     # 2. Fetching Images
#     results = list(images_collection.find(search_filter).sort("uploaded_at", -1))
    
#     # 3. Fetching Folders for the Upload UI
#     user_folders = []
#     if current_user.is_authenticated:
#         user_folders = list(folders_collection.find({"owner": current_user.username}).sort("_id", -1))
        
#     # 4. Rendering Template
#     return render_template('index.html', images=results, search_query=query, folders=user_folders)

# @app.route('/increment-view/<img_id>', methods=['POST'])
# @login_required
# def increment_view(img_id):
#     try:
#         result = images_collection.find_one_and_update(
#             {'_id': ObjectId(img_id)},
#             {'$inc': {'views': 1}},
#             return_document=True
#         )
#         if result:
#             return jsonify({'status': 'success', 'new_views': result.get('views', 0)})
#         return jsonify({'status': 'error', 'message': 'Asset missing'}), 404
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': str(e)}), 500

# @app.route('/user/<username>')
# def uploader_profile_view(username):
#     try:
#         uploader_record = users_collection.find_one({"username": username})
#         if not uploader_record:
#             return render_template('404.html', text_override="The requested cloud identity profile perimeter does not exist within our database tracking cluster."), 404
            
#         public_folders = list(folders_collection.find({
#             "owner": username,
#             "is_public": True
#         }))
        
#         for folder in public_folders:
#             folder['asset_count'] = images_collection.count_documents({
#                 "uploader": username,
#                 "folder_name": folder['folder_name'],
#                 "in_trash": False,
#                 "is_public": True
#             })
            
#         public_images = list(images_collection.find({
#             "uploader": username,
#             "is_public": True,
#             "in_trash": False
#         }).sort("uploaded_at", -1))
        
#         return render_template(
#             'uploader_profile.html', 
#             uploader=uploader_record, 
#             folders=public_folders, 
#             images=public_images
#         )
        
#     except Exception as e:
#         print(f"Uploader Profile Context Processing Dropout: {str(e)}")
#         return redirect(url_for('index'))

# # ---------------------------------------------------
# # ASSET MANAGEMENT (UPLOAD, FOLDERS & PRIVACY)
# # ---------------------------------------------------

# @app.route('/upload', methods=['POST'])
# def upload():
#     if 'image' not in request.files:
#         return jsonify({"status": "error", "message": "Selection Required"}), 400

#     files = request.files.getlist('image')
    
#     # ✅ FIX 1: Blank submit interception check (Empty selections handling)
#     valid_files_to_process = [f for f in files if f.filename != '']
#     if not valid_files_to_process:
#         return jsonify({"status": "error", "message": "No valid files selected for upload."}), 400

#     selected_folder = request.form.get('folder_name', 'General')
#     manual_tags = request.form.get('manual_tags', '').split(',')
#     uploader = current_user.username if current_user.is_authenticated else "Guest"
    
#     # 🛡️ DYNAMIC AWS REKOGNITION SHIELD ENGINE: Pulling rules straight from Database Core
#     active_rules_docs = list(moderation_rules_collection.find({}))
#     BLOCKED_SAFETY_LABELS = set(rule['label'].lower().strip() for rule in active_rules_docs)

#     # Fallback auto-seeding agar database rules index completely empty ho (For first boot runtime safety)
#     # if not BLOCKED_SAFETY_LABELS:
#     #     default_seeding_labels = ['gun', 'weapon', 'weaponry', 'firearm', 'pistol', 'rifle', 'hand grenade', 'grenade', 'explosive', 'bomb', 'knife', 'dagger', 'ammunition', 'violence', 'gore']
#     #     for lbl in default_seeding_labels:
#     #         moderation_rules_collection.insert_one({"label": lbl, "created_at": datetime.utcnow()})
#     #     BLOCKED_SAFETY_LABELS = set(default_seeding_labels)

#     uploaded_files = []
#     blocked_files = []

#     try:
#         # --- FOLDER PRIVACY CHECK ---
#         is_public_flag = False
#         if selected_folder.lower() == 'general':
#             is_public_flag = True  
#         elif current_user.is_authenticated:
#             folder_doc = folders_collection.find_one({
#                 "folder_name": selected_folder, 
#                 "owner": current_user.username
#             })
#             is_public_flag = folder_doc.get('is_public', False) if folder_doc else False

#         # --- PROCESS & UPLOAD FILES (With Dynamic Content Moderation Filter) ---
#         for file in valid_files_to_process:
#             orig_name = secure_filename(file.filename)
#             filename = f"{datetime.now().timestamp()}_{orig_name}"
#             thumb_filename = f"thumb_{filename}"
            
#             # 1. File ko memory mein read karein
#             file_bytes = file.read()
            
#             # 2. Temporary Upload Original to S3 (Taki AI scan complete kar sake)
#             s3_client.put_object(
#                 Bucket=BUCKET_NAME,
#                 Key=filename,
#                 Body=file_bytes,
#                 ContentType=file.content_type
#             )
            
#             # 3. AWS Rekognition AI Tags Analysis Core Protocol
#             rek_response = rek_client.detect_labels(
#                 Image={'S3Object': {'Bucket': BUCKET_NAME, 'Name': filename}}, 
#                 MaxLabels=15
#             )
            
#             ai_tags = [label['Name'].lower() for label in rek_response['Labels']]
            
#             # 🚨 DYNAMIC SHIELD EVALUATOR: Checking parameters inside active rules data matrix
#             is_unsafe = False
#             detected_threats = []
            
#             for label in rek_response['Labels']:
#                 label_name = label['Name'].lower()
#                 parents = [p['Name'].lower() for p in label.get('Parents', [])]
                
#                 # Check validation over dynamically declared keys array
#                 if label_name in BLOCKED_SAFETY_LABELS or any(p in BLOCKED_SAFETY_LABELS for p in parents):
#                     is_unsafe = True
#                     detected_threats.append(label['Name'])
            
#             # 🚫 PURGE INTERCEPT ACTION: Target threat verified, trigger instantaneous cloud destruction
#             if is_unsafe:
#                 s3_client.delete_object(Bucket=BUCKET_NAME, Key=filename)
#                 blocked_files.append(f"{orig_name} (Detected: {', '.join(set(detected_threats))})")
#                 continue # Skip process array loop segment moving safely forward
            
#             # 4. Create & Upload Thumbnail (~50KB for Grid layout)
#             try:
#                 img = Image.open(BytesIO(file_bytes))
#                 if img.mode in ("RGBA", "P"): 
#                     img = img.convert("RGB")
                
#                 img.thumbnail((600, 600)) 
                
#                 thumb_io = BytesIO()
#                 img.save(thumb_io, format='JPEG', quality=60)
#                 thumb_io.seek(0)
                
#                 s3_client.put_object(
#                     Bucket=BUCKET_NAME,
#                     Key=thumb_filename,
#                     Body=thumb_io.getvalue(),
#                     ContentType='image/jpeg'
#                 )
#             except Exception as e:
#                 print(f"Thumbnail processing error: {e}")
#                 thumb_filename = filename
            
#             final_tags = list(set(ai_tags + [t.strip().lower() for t in manual_tags if t.strip()]))
#             original_url = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{filename}"
#             thumb_url = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{thumb_filename}"
            
#             # 5. Save to Database Node
#             images_collection.insert_one({
#                 "filename": orig_name, 
#                 "s3_key": filename, 
#                 "url": original_url,          
#                 "thumb_url": thumb_url,       
#                 "tags": final_tags,
#                 "uploader": uploader, 
#                 "folder_name": selected_folder,
#                 "views": 0, "likes": 0, "shares": 0, "downloads": 0, 
#                 "is_favorite": False, "in_trash": False, 
#                 "uploaded_at": datetime.utcnow(), 
#                 "is_public": is_public_flag
#             })
#             uploaded_files.append(orig_name)

#         # --- DYNAMIC RESPONSE GATEWAY EVALUATION ---
#         if len(blocked_files) == len(valid_files_to_process) and len(valid_files_to_process) > 0:
#             return jsonify({
#                 "status": "safety_error",
#                 "message": f"🚨 Upload restricted: Selected files violate our platform safety guidelines. {', '.join(blocked_files)}."
#             }), 400
            
#         elif len(blocked_files) > 0:
#             return jsonify({
#                 "status": "partial_success",
#                 "message": f"⚠️ Partial Sync: {len(uploaded_files)} files uploaded successfully. While, {len(blocked_files)} files violating content policy were restricted. {', '.join(blocked_files)}."
#             })
            
#         else:
#             return jsonify({"status": "success", "message": "Assets Compressed & Synchronized"})
    
#     except Exception as e:
#         print(f"Upload Matrix Error: {e}")
#         return jsonify({"status": "error", "message": f"Operational pipeline fallout: {str(e)}"}), 500

# # @app.route('/upload', methods=['POST'])
# # def upload():
# #     if 'image' not in request.files:
# #         return jsonify({"status": "error", "message": "Selection Required"}), 400

# #     files = request.files.getlist('image')
    
# #     # ✅ FIX 1: Blank submit interception check (Empty selections handling)
# #     valid_files_to_process = [f for f in files if f.filename != '']
# #     if not valid_files_to_process:
# #         return jsonify({"status": "error", "message": "No valid files selected for upload."}), 400

# #     selected_folder = request.form.get('folder_name', 'General')
# #     manual_tags = request.form.get('manual_tags', '').split(',')
# #     uploader = current_user.username if current_user.is_authenticated else "Guest"
    
# #     # 🛡️ AWS REKOGNITION RESTRICTED SAFETY LABELS MATRIX (Stealth Content Blocker)
# #     BLOCKED_SAFETY_LABELS = {
# #         'gun', 'weapon', 'weaponry', 'firearm', 'pistol', 'rifle', 'hand grenade', 
# #         'grenade', 'explosive', 'bomb', 'knife', 'dagger', 'ammunition', 'violence', 'gore'
# #     }

# #     uploaded_files = []
# #     blocked_files = []

# #     try:
# #         # --- FOLDER PRIVACY CHECK ---
# #         is_public_flag = False
# #         if selected_folder.lower() == 'general':
# #             is_public_flag = True  
# #         elif current_user.is_authenticated:
# #             folder_doc = folders_collection.find_one({
# #                 "folder_name": selected_folder, 
# #                 "owner": current_user.username
# #             })
# #             is_public_flag = folder_doc.get('is_public', False) if folder_doc else False

# #         # --- PROCESS & UPLOAD FILES (With Live Content Moderation Filter) ---
# #         for file in valid_files_to_process:
# #             orig_name = secure_filename(file.filename)
# #             filename = f"{datetime.now().timestamp()}_{orig_name}"
# #             thumb_filename = f"thumb_{filename}"
            
# #             # 1. File ko memory mein read karein
# #             file_bytes = file.read()
            
# #             # 2. Temporary Upload Original to S3 (Taki AI ise scan kar sake)
# #             s3_client.put_object(
# #                 Bucket=BUCKET_NAME,
# #                 Key=filename,
# #                 Body=file_bytes,
# #                 ContentType=file.content_type
# #             )
            
# #             # 3. AWS Rekognition AI Tags (Original file se AI check karega)
# #             rek_response = rek_client.detect_labels(
# #                 Image={'S3Object': {'Bucket': BUCKET_NAME, 'Name': filename}}, 
# #                 MaxLabels=15
# #             )
            
# #             ai_tags = [label['Name'].lower() for label in rek_response['Labels']]
            
# #             # 🚨 SECURITY SHIELD: Check violations inside labels or parent categories hierarchy
# #             is_unsafe = False
# #             detected_threats = []
            
# #             for label in rek_response['Labels']:
# #                 label_name = label['Name'].lower()
# #                 parents = [p['Name'].lower() for p in label.get('Parents', [])]
                
# #                 # Agar label ya uska koi parent blocked list mein hai, toh block trigger hoga
# #                 if label_name in BLOCKED_SAFETY_LABELS or any(p in BLOCKED_SAFETY_LABELS for p in parents):
# #                     is_unsafe = True
# #                     detected_threats.append(label['Name'])
            
# #             # 🚫 ACTION: Agar photo unsafe hai, to turant S3 cloud se purge (delete) kardo
# #             if is_unsafe:
# #                 s3_client.delete_object(Bucket=BUCKET_NAME, Key=filename)
# #                 blocked_files.append(f"{orig_name} (Detected: {', '.join(set(detected_threats))})")
# #                 continue # Loop ko yahin se skip karke agli safe photo par jao
            
# #             # 4. Create & Upload Thumbnail (~50KB for Grid)
# #             try:
# #                 img = Image.open(BytesIO(file_bytes))
# #                 if img.mode in ("RGBA", "P"): 
# #                     img = img.convert("RGB")
                
# #                 img.thumbnail((600, 600)) 
                
# #                 thumb_io = BytesIO()
# #                 img.save(thumb_io, format='JPEG', quality=60)
# #                 thumb_io.seek(0)
                
# #                 s3_client.put_object(
# #                     Bucket=BUCKET_NAME,
# #                     Key=thumb_filename,
# #                     Body=thumb_io.getvalue(),
# #                     ContentType='image/jpeg'
# #                 )
# #             except Exception as e:
# #                 print(f"Thumbnail processing error: {e}")
# #                 thumb_filename = filename # Fallback to original if compression fails
            
# #             # Merge AI tags with manual input tags smoothly
# #             final_tags = list(set(ai_tags + [t.strip().lower() for t in manual_tags if t.strip()]))
            
# #             original_url = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{filename}"
# #             thumb_url = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{thumb_filename}"
            
# #             # 5. Database mein exact original schema parameters save karein
# #             images_collection.insert_one({
# #                 "filename": orig_name, 
# #                 "s3_key": filename, 
# #                 "url": original_url,          
# #                 "thumb_url": thumb_url,       
# #                 "tags": final_tags,
# #                 "uploader": uploader, 
# #                 "folder_name": selected_folder,
# #                 "views": 0, "likes": 0, "shares": 0, "downloads": 0, 
# #                 "is_favorite": False, "in_trash": False, 
# #                 "uploaded_at": datetime.utcnow(), 
# #                 "is_public": is_public_flag
# #             })
# #             uploaded_files.append(orig_name)

# #         # --- DYNAMIC MULTI-CASE RESPONSE EVALUATION ---
# #         # Case A: Agar saari ki saari images policy violate kar gayi hon
# #         if len(blocked_files) == len(valid_files_to_process) and len(valid_files_to_process) > 0:
# #             return jsonify({
# #                 "status": "safety_error",
# #                 "message": f"🚨 Upload Denied: Content moderation shield blocked all assets due to security policy violations. Restricted weapons or violence data layout elements detected: {', '.join(blocked_files)}."
# #             }), 400
            
# #         # Case B: Partial Success (Kuch upload hui, kuch block hui)
# #         elif len(blocked_files) > 0:
# #             return jsonify({
# #                 "status": "partial_success",
# #                 "message": f"⚠️ Partial Sync Complete: {len(uploaded_files)} assets synchronized successfully. However, {len(blocked_files)} assets were filtered and purged by security shield due to safety violations: {', '.join(blocked_files)}."
# #             })
            
# #         # Case C: 100% Normal Full Success (Saari photos clean hain)
# #         else:
# #             return jsonify({"status": "success", "message": "Assets Compressed & Synchronized"})
    
# #     except Exception as e:
# #         print(f"Upload Matrix Error: {e}")
# #         return jsonify({"status": "error", "message": f"Operational pipeline fallout: {str(e)}"}), 500

# @app.route('/create-folder', methods=['POST'])
# @login_required
# def create_folder():
#     folder_name = request.form.get('folder_name')
#     if folder_name:
#         folders_collection.insert_one({
#             "folder_name": folder_name.strip(),
#             "owner": current_user.username,
#             "is_public": False,
#             "created_at": datetime.utcnow()
#         })
#         return jsonify({"status": "success", "message": "Folder Created"})
#     return jsonify({"status": "error", "message": "Invalid Name"})

# @app.route('/folder/<name>')
# @login_required
# def folder_view(name):
#     all_user_folders = list(folders_collection.find({"owner": current_user.username}))
#     folder_images = list(images_collection.find({"uploader": current_user.username, "folder_name": name, "in_trash": False}).sort("uploaded_at", -1))
#     return render_template('folder_view.html', folder_name=name, images=folder_images, all_user_folders=all_user_folders)

# @app.route('/move-assets', methods=['POST'])
# @login_required
# def move_assets():
#     try:
#         data = request.get_json()
#         asset_ids = data.get('asset_ids', [])
#         target_folder = data.get('target_folder')
        
#         if not asset_ids or not target_folder:
#             return jsonify({'status': 'error', 'message': 'Invalid selection'})
            
#         bson_ids = [ObjectId(id_str) for id_str in asset_ids]
#         images_collection.update_many(
#             {'_id': {'$in': bson_ids}, 'uploader': current_user.username},
#             {'$set': {'folder_name': target_folder}}
#         )
#         return jsonify({'status': 'success', 'message': 'Assets moved successfully'})
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': str(e)}), 500

# @app.route('/rename-folder/<folder_id>', methods=['POST'])
# @login_required
# def rename_folder(folder_id):
#     try:
#         data = request.get_json() or {}
#         new_name = data.get('new_name', '').strip()
        
#         if not new_name:
#             return jsonify({'status': 'error', 'message': 'Room name cannot be empty.'}), 400
            
#         # 1. Pehle purana folder dhoondo taaki uska original naam mil sake
#         folder = folders_collection.find_one({'_id': ObjectId(folder_id), 'owner': current_user.username})
        
#         if not folder:
#             return jsonify({'status': 'error', 'message': 'Folder not found.'}), 404
            
#         old_name = folder.get('folder_name')

#         # 2. Images collection mein purane naam wali sabhi photos ko naye naam se replace karo
#         images_collection.update_many(
#             {'uploader': current_user.username, 'folder_name': old_name},
#             {'$set': {'folder_name': new_name}}
#         )
        
#         # 3. Aakhiri mein Folder collection mein folder ka naam update karo
#         folders_collection.update_one(
#             {'_id': ObjectId(folder_id), 'owner': current_user.username},
#             {'$set': {'folder_name': new_name}}
#         )
        
#         return jsonify({'status': 'success', 'message': 'Folder renamed successfully.'})
        
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Internal re-indexing failure context: {str(e)}'}), 500

# @app.route('/update-folder-privacy/<folder_id>', methods=['POST'])
# @login_required
# def update_folder_privacy(folder_id):
#     data = request.get_json()
#     is_public = data.get('is_public', False)
    
#     folders_collection.update_one(
#         {'_id': ObjectId(folder_id), 'owner': current_user.username},
#         {'$set': {'is_public': is_public}}
#     )
    
#     folder = folders_collection.find_one({'_id': ObjectId(folder_id)})
#     if folder:
#         images_collection.update_many(
#             {'folder_name': folder['folder_name'], 'uploader': current_user.username},
#             {'$set': {'is_public': is_public}}
#         )
    
#     return jsonify({'status': 'success'})

# @app.route('/delete-folder/<folder_id>', methods=['POST'])
# @login_required
# def delete_folder(folder_id):
#     folder = folders_collection.find_one({'_id': ObjectId(folder_id), 'owner': current_user.username})
#     if folder:
#         images_collection.update_many(
#             {'folder_name': folder['folder_name'], 'uploader': current_user.username},
#             {'$set': {'in_trash': True, 'original_folder': folder['folder_name'], 'deleted_at': datetime.utcnow()}}
#         )
#         folders_collection.delete_one({'_id': ObjectId(folder_id)})
#         return jsonify({'status': 'success'})
        
#     return jsonify({'status': 'error', 'message': 'Folder not found'}), 404

# @app.route('/toggle-folder-privacy/<folder_id>', methods=['POST'])
# @login_required
# def toggle_folder_privacy(folder_id):
#     folder = folders_collection.find_one({"_id": ObjectId(folder_id), "owner": current_user.username})
#     if folder:
#         new_status = not folder.get('is_public', False)
#         folders_collection.update_one({"_id": ObjectId(folder_id)}, {"$set": {"is_public": new_status}})
#         images_collection.update_many(
#             {"folder_name": folder['folder_name'], "uploader": current_user.username},
#             {"$set": {"is_public": new_status}}
#         )
#         return jsonify({"status": "success", "new_status": "Public" if new_status else "Private"})
#     return jsonify({"status": "error"}), 403

# @app.route('/share-folder/<folder_name>')
# def share_folder(folder_name):
#     images = list(images_collection.find({"folder_name": folder_name, "is_public": True, "in_trash": False}))
#     return render_template('index.html', images=images, folder_name=folder_name, is_shared_view=True)

# @app.route('/download-folder/<folder_name>')
# @login_required
# def download_folder_zip(folder_name):
#     # 1. Ensure karein ki user ke paas is folder ka access hai aur usme images hain
#     images = list(images_collection.find({
#         "folder_name": folder_name, 
#         "uploader": current_user.username, 
#         "in_trash": False
#     }))
    
#     if not images:
#         flash("Folder is empty or not found.", "error")
#         return redirect(url_for('folder_view', name=folder_name))

#     # 2. GeeksforGeeks Standard: In-Memory ZIP Generation (Super Fast & Secure)
#     memory_file = BytesIO()
#     with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
#         for img in images:
#             try:
#                 # S3 se image read karke seedha ZIP mein stream karein
#                 s3_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=img['s3_key'])
#                 file_bytes = s3_obj['Body'].read()
#                 zf.writestr(img['filename'], file_bytes)
#             except Exception as e:
#                 print(f"Error zipping {img['filename']}: {e}")
    
#     memory_file.seek(0)
    
#     # 3. User ko ZIP file as attachment bhejein
#     clean_folder_name = folder_name.replace(" ", "_")
#     return send_file(
#         memory_file,
#         mimetype='application/zip',
#         as_attachment=True,
#         download_name=f"{clean_folder_name}_Nexus_Backup.zip"
#     )

# # ---------------------------------------------------
# # USER VAULT & PERSONAL FILES
# # ---------------------------------------------------

# @app.route('/my-vault')
# @login_required
# def my_vault():
#     user_folders = list(folders_collection.find({'owner': current_user.username}))
#     for folder in user_folders:
#         count = images_collection.count_documents({
#             'uploader': current_user.username, 
#             'folder_name': folder['folder_name'],
#             'in_trash': {'$ne': True}
#         })
#         folder['asset_count'] = count
        
#     user_images = list(images_collection.find({"uploader": current_user.username, "in_trash": False}).sort("uploaded_at", -1))
#     return render_template('vault.html', images=user_images, folders=user_folders)

# # ---------------------------------------------------
# # ENGAGEMENT & FAVORITES SYSTEM
# # ---------------------------------------------------

# @app.route('/favorites')
# @login_required
# def favorites():
#     try:
#         # 'likes' hai, toh "liked_by" ki jagah "likes" likhein.
#         query = {
#             "liked_by": current_user.username, 
#             "in_trash": {"$ne": True}
#         }

#         # Aggregation pipeline taaki dusre users ki profile pic bhi favorites 
#         # page par theek se load ho sake.
#         pipeline = [
#             {"$match": query},
#             {"$sort": {"uploaded_at": -1}}, 
#             {
#                 "$lookup": {
#                     "from": "accounts", 
#                     "localField": "uploader", 
#                     "foreignField": "username", 
#                     "as": "uploader_meta"
#                 }
#             },
#             {
#                 "$addFields": {
#                     "profile_pic": {"$arrayElemAt": ["$uploader_meta.profile_pic", 0]}
#                 }
#             }
#         ]

#         favorite_images = list(images_collection.aggregate(pipeline))
        
#         return render_template('favorites.html', images=favorite_images)

#     except Exception as e:
#         print("FAVORITES FETCH ERROR:", str(e))
#         # Agar koi error aaye toh page crash na ho
#         return render_template('favorites.html', images=[])

# @app.route('/like-image/<image_id>', methods=['POST'])
# def like_image(image_id):
#     try:
#         # 1. Image find karo
#         image = images_collection.find_one({"_id": ObjectId(image_id)})
#         if not image:
#             return jsonify({"status": "error", "message": "Asset not found."}), 404

#         # 2. Identity Check: Login hai ya Guest?
#         if current_user.is_authenticated:
#             # Login user ke liye uska Username use karenge
#             user_identifier = current_user.username
#         else:
#             # Guest user ke liye uska IP Address use karenge taaki spam na ho
#             # Example identifier: "guest_192.168.1.5"
#             user_identifier = f"guest_{request.remote_addr}"

#         # 3. Check karo ki is identifier ne pehle like kiya hai ya nahi
#         liked_by_list = image.get('liked_by', [])

#         if user_identifier in liked_by_list:
#             # ❌ UNLIKE LOGIC (Agar pehle se like kiya hai)
#             img = images_collection.find_one_and_update(
#                 {"_id": ObjectId(image_id)},
#                 {
#                     "$inc": {"likes": -1},
#                     "$pull": {"liked_by": user_identifier} # Database se naam/IP hatao
#                 },
#                 return_document=True
#             )
#         else:
#             # ✅ LIKE LOGIC (Agar naya like hai)
#             img = images_collection.find_one_and_update(
#                 {"_id": ObjectId(image_id)},
#                 {
#                     "$inc": {"likes": 1},
#                     "$addToSet": {"liked_by": user_identifier} # Database mein naam/IP jodo
#                 },
#                 return_document=True
#             )

#         return jsonify({"status": "success", "new_likes": img.get('likes', 0)})

#     except Exception as e:
#         print("LIKE SYSTEM ERROR:", str(e))
#         return jsonify({"status": "error", "message": "Server error while processing like."}), 500

# @app.route('/share-image/<image_id>', methods=['POST'])
# def share_image(image_id):
#     images_collection.update_one({"_id": ObjectId(image_id)}, {"$inc": {"shares": 1}})
#     return jsonify({"status": "success"})

# @app.route('/download-image/<image_id>')
# def download_asset(image_id):
#     asset = images_collection.find_one({"_id": ObjectId(image_id)})
#     if asset:
#         images_collection.update_one({"_id": ObjectId(image_id)}, {"$inc": {"views": 1, "downloads": 1}})
#         return redirect(asset['url'])
#     return "Asset not found", 404

# # ---------------------------------------------------
# # TRASH & BATCH BULK ROUTER STORAGE SYSTEM
# # ---------------------------------------------------

# @app.route('/bulk-trash-assets', methods=['POST'])
# @login_required
# def bulk_trash_assets():
#     try:
#         data = request.get_json() or {}
#         asset_ids = data.get('asset_ids', [])
#         if not asset_ids:
#             return jsonify({'status': 'error', 'message': 'Payload structure contains no valid entities.'}), 400
            
#         bson_ids_array = [ObjectId(id_str) for id_str in asset_ids]
#         images_collection.update_many(
#             {'_id': {'$in': bson_ids_array}, 'uploader': current_user.username},
#             {'$set': {'in_trash': True, 'deleted_at': datetime.utcnow()}}
#         )
#         return jsonify({'status': 'success', 'message': 'Batch collection entity status rewritten successfully.'})
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Internal collection stack anomaly context: {str(e)}'}), 500

# @app.route('/move-to-trash/<image_id>', methods=['POST'])
# @login_required
# def move_to_trash(image_id):
#     images_collection.update_one({"_id": ObjectId(image_id), "uploader": current_user.username}, {"$set": {"in_trash": True, "deleted_at": datetime.utcnow()}})
#     return jsonify({"status": "success"})

# @app.route('/restore-asset/<image_id>', methods=['POST'])
# @login_required
# def restore_asset(image_id):
#     images_collection.update_one({"_id": ObjectId(image_id), "uploader": current_user.username}, {"$set": {"in_trash": False}, "$unset": {"deleted_at": ""}})
#     return jsonify({"status": "success", "message": "Asset restored to vault"})

# @app.route('/permanent-delete/<image_id>', methods=['POST'])
# @login_required
# def permanent_delete(image_id):
#     asset = images_collection.find_one({"_id": ObjectId(image_id), "uploader": current_user.username})
#     if asset:
#         try:
#             # Original delete karo
#             s3_client.delete_object(Bucket=BUCKET_NAME, Key=asset['s3_key'])
#             # 🧹 THUMBNAIL BHI DELETE KARO (Naya Logic)
#             try:
#                 s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"thumb_{asset['s3_key']}")
#             except:
#                 pass 
                
#             images_collection.delete_one({"_id": ObjectId(image_id)})
#             return jsonify({"status": "success", "message": "Asset purged permanently"})
#         except Exception as e:
#             return jsonify({"status": "error", "message": str(e)})
#     return jsonify({"status": "error", "message": "Unauthorized"}), 403

# @app.route('/empty-trash', methods=['POST'])
# @login_required
# def empty_trash():
#     user_trash = list(images_collection.find({"uploader": current_user.username, "in_trash": True}))
#     try:
#         for asset in user_trash:
#             # Original delete karo
#             s3_client.delete_object(Bucket=BUCKET_NAME, Key=asset['s3_key'])
#             # 🧹 THUMBNAIL BHI DELETE KARO
#             try:
#                 s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"thumb_{asset['s3_key']}")
#             except:
#                 pass
                
#         images_collection.delete_many({"uploader": current_user.username, "in_trash": True})
#         return jsonify({"status": "success", "message": "Trash purged successfully"})
#     except Exception as e:
#         return jsonify({"status": "error", "message": str(e)})

# @app.route('/trash-bin')
# @login_required
# def trash_bin():
#     expiry_limit = datetime.utcnow() - timedelta(days=30)
#     images_collection.delete_many({"in_trash": True, "deleted_at": {"$lt": expiry_limit}})
#     items = list(images_collection.find({"uploader": current_user.username, "in_trash": True}))
#     return render_template('trash.html', items=items)

# #---------------------------------------------------------------
# # SECURITY CORE: ACCOUNT DELETION & RECOVERY
# #---------------------------------------------------------------
# @app.route('/request-account-deletion', methods=['POST'])
# @login_required
# def request_account_deletion():
#     data = request.get_json() or {}
#     delete_assets = data.get('delete_assets', False)
    
#     # 1. ARCHIVE LOGIC: Agar assets preserve karne hain (User ne tick nahi kiya)
#     if not delete_assets:
#         images_collection.update_many(
#             {"uploader": current_user.username}, 
#             {"$set": {"status": "archived", "is_public": False}}
#         )
#     # Note: Agar delete_assets=True hai, toh background_cleanup 
#     # 30 din baad script ke through S3 se delete kar dega.
    
#     # 2. ACCOUNT LIFECYCLE: Deletion scheduling
#     deletion_date = datetime.utcnow() + timedelta(days=30)
    
#     users_collection.update_one(
#         {"_id": ObjectId(current_user.id)},
#         {"$set": {
#             "is_scheduled_for_deletion": True,
#             "delete_assets_option": delete_assets,
#             "deletion_scheduled_at": deletion_date
#         }}
#     )
    
#     # 3. SESSION SYNC: UI turant update karne ke liye
#     session['is_scheduled_for_deletion'] = True
#     session['deletion_scheduled_at'] = deletion_date.isoformat()
    
#     return jsonify({
#         'status': 'success', 
#         'message': 'Account marked for deletion. Data lifecycle initiated.'
#     })

# #----------------------------------------------------------------------------------------------
# # ACCOUNT DELETION & RECOVERY ENDPOINTS
# #----------------------------------------------------------------------------------------------
# # ---------------------------------------------------
# # SMTP EMAIL PIPELINE (Nexus Cloud Core Mail Engine)
# # ---------------------------------------------------
# from email.utils import formatdate, make_msgid

# def send_sync_email_optimized(target_email, subject, body_content):
#     """Core synchronous email dispatcher with absolute security headers to bypass filters."""
#     try:
#         sender_identity = os.getenv('SMTP_SENDER')
#         smtp_app_secret = os.getenv('SMTP_PASSWORD')
        
#         if not sender_identity or not smtp_app_secret:
#             print("❌ [SMTP SHIELD] Aborted: Environmental credentials missing.", flush=True)
#             return False

#         msg = MIMEMultipart()
#         msg['From'] = f"Nexus Cloud Support <{sender_identity}>"
#         msg['To'] = target_email
#         msg['Subject'] = subject
        
#         # Security validation headers configuration
#         msg['Date'] = formatdate(localtime=True)
#         msg['Message-ID'] = make_msgid()
        
#         # HTML template parsing validation checkpoint
#         if "</div>" in body_content or "<div" in body_content:
#             msg.attach(MIMEText(body_content, 'html'))
#         else:
#             msg.attach(MIMEText(body_content, 'plain'))
        
#         print(f"📡 [SMTP SHIELD] Initializing connection for: {target_email}...", flush=True)
        
#         # Primary Pipeline: Port 465 SSL Direct Connect
#         try:
#             server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=7)
#             server.login(sender_identity, smtp_app_secret)
#             server.sendmail(sender_identity, target_email, msg.as_string())
#             server.quit()
#             print(f"✅ [SMTP SHIELD] Success: Email delivered via Port 465 SSL", flush=True)
#             return True
#         except Exception as e465:
#             print(f"⚠️ Port 465 SSL skipped, trying Port 587 TLS: {str(e465)}", flush=True)
            
#             # Secondary Pipeline: Fallback Port 587 TLS Connect
#             server = smtplib.SMTP('smtp.gmail.com', 587, timeout=7)
#             server.starttls()
#             server.login(sender_identity, smtp_app_secret)
#             server.sendmail(sender_identity, target_email, msg.as_string())
#             server.quit()
#             print(f"✅ [SMTP SHIELD] Success: Email delivered via Port 587 TLS", flush=True)
#             return True
            
#     except Exception as final_err:
#         print(f"❌ [SMTP CRITICAL ERROR] Transmission failure: {str(final_err)}", flush=True)
#         return False

# def dispatch_smtp_secure_email(target_email, username, subject, body_content):
#     """Universal wrapper for OTP and Admin routes preserving signature compatibility."""
#     return send_sync_email_optimized(target_email, subject, body_content)

# def send_email(target_email, subject, body_content):
#     """Backward compatibility alias mapping for template system recovery paths."""
#     return send_sync_email_optimized(target_email, subject, body_content)

# # # ---------------------------------------------------
# # # SMTP EMAIL PIPELINE (Async Threading Engine)
# # # ---------------------------------------------------
# # def send_async_email_worker(flask_app, target_email, subject, body_content):
# #     """Background worker thread to execute secure cloud SMTP operations without blocking requests."""
# #     with flask_app.app_context():
# #         try:
# #             sender_identity = os.getenv('SMTP_SENDER')
# #             smtp_app_secret = os.getenv('SMTP_PASSWORD')
            
# #             if not sender_identity or not smtp_app_secret:
# #                 print("❌ [SMTP SHIELD] Aborted: Environmental credentials missing on Render.")
# #                 return

# #             msg = MIMEMultipart()
# #             msg['From'] = sender_identity
# #             msg['To'] = target_email
# #             msg['Subject'] = subject
            
# #             # Check if body contains HTML tags for reset password view formatting layout
# #             if "</div>" in body_content or "<div" in body_content:
# #                 msg.attach(MIMEText(body_content, 'html'))
# #             else:
# #                 msg.attach(MIMEText(body_content, 'plain'))
            
# #             # Cloud hosting best practice: Try Port 465 SSL first as Port 587 TLS is heavily firewalled on Render
# #             try:
# #                 server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10)
# #                 server.login(sender_identity, smtp_app_secret)
# #                 server.sendmail(sender_identity, target_email, msg.as_string())
# #                 server.quit()
# #                 print(f"✅ [ASYNC MAIL] Email successfully dispatched to {target_email} via Port 465 SSL")
# #                 return
# #             except Exception as e465:
# #                 print(f"⚠️ Port 465 SSL initialization failed, trying backup Port 587: {e465}")
                
# #             # Secondary backup pipeline layout utilizing port 587 with strict short connection timeout
# #             server = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
# #             server.starttls()
# #             server.login(sender_identity, smtp_app_secret)
# #             server.sendmail(sender_identity, target_email, msg.as_string())
# #             server.quit()
# #             print(f"✅ [ASYNC MAIL] Email successfully dispatched to {target_email} via Port 587 TLS")
            
# #         except Exception as final_err:
# #             print(f"❌ [ASYNC MAIL CRITICAL] Dropouts encountered during Render transport network lifecycle: {str(final_err)}")

# # def dispatch_smtp_secure_email(target_email, username, subject, body_content):
# #     """Universal Async SMTP utility to instantly release Flask threads and prevent Render client frontend timeouts."""
# #     import threading
# #     threading.Thread(
# #         target=send_async_email_worker, 
# #         args=(app, target_email, subject, body_content)
# #     ).start()
# #     return True

# # def send_email(target_email, subject, body_content):
# #     """🚨 CRITICAL NAME-ERROR ALIAS: Maps the missing function calls in reset_password route back to core engine safely."""
# #     return dispatch_smtp_secure_email(target_email, "Explorer", subject, body_content)

# # def dispatch_smtp_secure_email(target_email, username, subject, body_content):
# #     """Universal SMTP utility for all email types (OTP or Alerts)."""
# #     try:
# #         sender_identity = os.getenv('SMTP_SENDER')
# #         smtp_app_secret = os.getenv('SMTP_PASSWORD')
        
# #         if not sender_identity or not smtp_app_secret:
# #             raise Exception("SMTP credentials missing.")

# #         msg = MIMEMultipart()
# #         msg['From'] = sender_identity
# #         msg['To'] = target_email
# #         msg['Subject'] = subject # Yahan dynamic subject aayega
        
# #         msg.attach(MIMEText(body_content, 'plain'))
        
# #         server = smtplib.SMTP('smtp.gmail.com', 587)
# #         server.starttls()
# #         server.login(sender_identity, smtp_app_secret)
# #         server.sendmail(sender_identity, target_email, msg.as_string())
# #         server.quit()
# #         print(f"✅ Email successfully dispatched to {target_email}")
        
# #     except Exception as e:
# #         print(f"❌ SMTP Error: {str(e)}")
# #         raise Exception(f"SMTP Transmission Failed: {str(e)}")

# # ---------------------------------------------------
# # OTP RECOVERY ROUTE With Universal Email Dispatcher
# # ---------------------------------------------------
# @app.route('/send-recovery-otp', methods=['POST'])
# def send_recovery_otp():
#     client_ip = request.remote_addr or "127.0.0.1"

#     # Rate Limiting Shield
#     if check_security_limit(client_ip, "otp", max_attempts=6, window_minutes=60):
#         return jsonify({
#             "status": "error", 
#             "message": "Security Shield Activated: Maximum OTP limit reached. Please try again after 1 hour."
#         }), 429

#     data = request.get_json() or {}
#     username = data.get('username', '').strip()
#     email = data.get('email', '').strip()
    
#     # 1. User Validation
#     user = users_collection.find_one({'username': username, 'email': email})
#     if not user:
#         log_failed_attempt(client_ip, "otp")
#         return jsonify({'status': 'error', 'message': 'Account validation failed: This identity profile is not registered.'}), 401
        
#     generated_token = str(random.randint(100000, 999999))
    
#     # 2. Email Content
#     subject = "NEXUS Cloud Service - Request for Secure Password Reset"
#     body_content = f"""
#     Hello {username},
    
#     Thank you for choosing Nexus Cloud. We are committed to keeping your account secure.
#     We have received a request to reset your password. To complete this process, please use the verification code provided below:
    
#     🔑 AUTHENTICATION OTP: {generated_token}
    
#     For your security, this code will expire in 10 minutes. If you did not initiate this request, please ignore this email, and no changes will be made to your account.
    
#     Best regards,
#     Nexus Security Architecture Team
#     """

#     # 3. Dispatch & Cache
#     try:
#         # Universal function call
#         dispatch_smtp_secure_email(email, username, subject, body_content)
        
#         # Cache update
#         RECOVERY_OTP_CACHE[username] = {
#             "otp": generated_token,
#             "timestamp": datetime.utcnow()
#         }
        
#         return jsonify({'status': 'success', 'message': 'Payload routed successfully.'})
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': str(e)}), 500
    
# @app.route('/execute-secure-reset', methods=['POST'])
# def execute_secure_reset():
#     try:
#         data = request.get_json() or {}
        
#         username = data.get('username', '').strip()
#         email = data.get('email', '').strip()
#         new_password = data.get('new_password', '')
#         mode = data.get('mode') 
        
#         user = users_collection.find_one({'username': username, 'email': email})
#         if not user:
#             return jsonify({'status': 'error', 'message': 'Identity verification failed. Registered parameters do not match.'}), 401

#         # 2. MODE-BASED VALIDATION LOGIC
#         if mode == 'OTP':
#             otp_token = data.get('otp_token', '').strip()
#             otp_data = RECOVERY_OTP_CACHE.get(username)
            
#             # A. OTP Check: Existence
#             if not otp_data:
#                 return jsonify({'status': 'error', 'message': 'OTP missing.'}), 401

#             # B. OTP Check: 15 Minute Expiry (900 seconds)
#             if (datetime.utcnow() - otp_data['timestamp']).total_seconds() > 900:
#                 RECOVERY_OTP_CACHE.pop(username, None)
#                 return jsonify({'status': 'error', 'message': 'OTP expired.'}), 401

#             # C. OTP Check: Validity
#             if otp_token != otp_data['otp']:
#                 return jsonify({'status': 'error', 'message': 'Invalid OTP.'}), 401
            
#             # Success: OTP clear karo
#             RECOVERY_OTP_CACHE.pop(username, None)

#         elif mode == 'SECRET':
#             # Security Question Verify karo
#             input_question = data.get('security_question', '')
#             input_answer = data.get('security_answer', '').strip().lower()
            
#             db_saved_question = user.get('security_question', '')
#             db_saved_answer = str(user.get('security_answer', '')).strip().lower()
            
#             if input_question != db_saved_question or input_answer != db_saved_answer:
#                 return jsonify({'status': 'error', 'message': 'Security secret answer verification rejected.'}), 401
        
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid verification mode selected.'}), 400
            
#         # 3. Password Update karo
#         new_hashed_signature = generate_password_hash(new_password)
#         users_collection.update_one({'_id': user['_id']}, {'$set': {'password': new_hashed_signature}})
#         if email:
#             send_password_change_notification(email)
            
#         return jsonify({'status': 'success', 'message': 'Password updated successfully.'})
        
#     except Exception as e:
#         print(f"CRITICAL RESET ERROR: {str(e)}")
#         return jsonify({'status': 'error', 'message': 'Internal reset pipeline error.'}), 500

# @app.route('/internal-change-password', methods=['POST'])
# @login_required
# def internal_change_password():
#     try:
#         current_pw = request.form.get('current_password')
#         new_pw = request.form.get('new_password')
        
#         user_record = users_collection.find_one({'_id': ObjectId(current_user.id)})
        
#         if user_record and check_password_hash(user_record['password'], current_pw):
#             new_hashed_format = generate_password_hash(new_pw)
            
#             users_collection.update_one(
#                 {'_id': ObjectId(current_user.id)},
#                 {'$set': {'password': new_hashed_format}}
#             )
#             if user_record.get('email'):
#                 send_password_change_notification(user_record['email'])
                
#             return jsonify({'status': 'success', 'message': 'Master security credentials updated successfully.'})
#         else:
#             return jsonify({'status': 'error', 'message': 'The current password signature provided does not match.'}), 401
            
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Internal cluster operational dropout: {str(e)}'}), 500

# # ---------------------------------------------------
# # ACCREDITATION RECOVERY TERMINAL (RESET PASSWORD UI LINK)
# # ---------------------------------------------------

# # @app.route('/reset-password', methods=['GET'])
# # def reset_password():
# #     """Renders the fresh dynamic account recovery interface template cleanly"""
# #     return render_template('reset_password.html')

# # @app.route('/secure-reset', methods=['POST'])
# # def secure_reset():
# #     return redirect(url_for('index'))

# @app.route('/reset-password', methods=['GET', 'POST'])
# def reset_password():
#     """Renders and processes the fresh dynamic account recovery interface template cleanly"""
#     if request.method == 'POST':
#         # Recovery phase data identification pipelines
#         email = session.get('reset_email') or request.form.get('email')
#         new_password = request.form.get('password')
        
#         if email and new_password:
#             # 1. Generate standard security cryptographic hash
#             hashed_password = generate_password_hash(new_password)
            
#             # 2. Complete DB modification update query safely
#             users_collection.update_one(
#                 {"email": email},
#                 {"$set": {"password": hashed_password}}
#             )
            
#             # 3. Complete and rich customized professional template string
#             notify_subject = "Nexus Cloud: Security Password Reset Confirmed"
#             notify_html = f"""
#             <div style="font-family: 'Inter', Arial, sans-serif; max-width: 500px; margin: auto; padding: 30px; border: 1px solid #e2e8f0; border-radius: 20px; background-color: #ffffff; box-shadow: 0 4px 12px rgba(0,0,0,0.03);">
#                 <div style="text-align: center; margin-bottom: 20px;">
#                     <span style="font-size: 40px;">🛡️</span>
#                 </div>
#                 <h2 style="color: #2563eb; text-align: center; margin-top: 0; font-weight: 800; text-transform: uppercase; letter-spacing: -0.5px;">Reset Successful</h2>
#                 <p style="color: #334155; font-size: 14px; line-height: 1.6; margin-top: 20px;">Hello Explorer,</p>
#                 <p style="color: #475569; font-size: 14px; line-height: 1.6;">The data account recovery pipeline for <strong>{email}</strong> has finalized successfully. Your temporary configuration hashes have been overwritten with your new secure access password.</p>
#                 <p style="color: #64748b; font-size: 13px; line-height: 1.6; background: #fff7ed; padding: 12px; border-radius: 10px; border-left: 4px solid #f97316;">
#                     <strong>Verification Method:</strong> Identity Token Validation Pipeline<br>
#                     <strong>System Action:</strong> Old Credentials Revoked Automatically
#                 </p>
#                 <p style="color: #475569; font-size: 14px; line-height: 1.6;">You can now securely access your primary master directory parameters utilizing your freshly configured identity password.</p>
#                 <hr style="border: none; border-top: 1px solid #f1f5f9; margin: 25px 0;">
#                 <p style="color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; text-align: center; margin-bottom: 0;">Monitored securely by,<br><strong>Nexus Cloud Core Matrix</strong></p>
#             </div>
#             """
#             # Deploy notification message package transmission
#             send_email(email, notify_subject, notify_html)
            
#             # Clean backup recovery session blocks to keep layout safe
#             session.pop('reset_email', None)
            
#             flash("Account access credentials restored successfully. Please sign in.", "success")
#             return redirect(url_for('login'))
            
#         flash("System processing fault: Identity reference validation failed.", "error")
#         return redirect(url_for('reset_password'))

#     return render_template('reset_password.html')

# # ---------------------------------------------------
# # COMPREHENSIVE USER CONFIGURATION (SETTINGS SYSTEM)
# # ---------------------------------------------------

# @app.route('/update-settings', methods=['POST'])
# @login_required
# def update_settings():
#     avatar_choice = request.form.get('avatar_choice')
    
#     if 'custom_profile_pic' in request.files:
#         file = request.files['custom_profile_pic']
#         if file and file.filename != '':
#             try:
#                 orig_name = secure_filename(file.filename)
#                 unique_filename = f"profile_{current_user.username}_{int(datetime.now().timestamp())}_{orig_name}"
                
#                 s3_client.upload_fileobj(file, BUCKET_NAME, unique_filename, ExtraArgs={'ContentType': file.content_type})
#                 final_pic = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{unique_filename}"
                
#                 users_collection.update_one(
#                     {"_id": ObjectId(current_user.id)}, 
#                     {"$set": {"profile_pic": final_pic}}
#                 )
                
#                 flash("Profile system avatar synchronized from local system successfully!", "success")
#                 return redirect(url_for('settings'))
#             except Exception as e:
#                 flash(f"Cloud synchronizer dropout: {str(e)}", "error")
#                 return redirect(url_for('settings'))

#     if avatar_choice:
#         users_collection.update_one(
#             {"_id": ObjectId(current_user.id)}, 
#             {"$set": {"profile_pic": avatar_choice}}
#         )
#         flash("AI system identity avatar registered successfully!", "success")
        
#     return redirect(url_for('settings'))

# @app.route('/update-profile', methods=['POST'])
# @login_required
# def update_profile():
#     try:
#         selected_avatar = request.form.get('selected_avatar')
#         update_fields = {}
        
#         if selected_avatar:
#             update_fields['profile_pic'] = selected_avatar
            
#         if 'custom_photo' in request.files:
#             file = request.files['custom_photo']
#             if file and file.filename != '':
#                 orig_name = secure_filename(file.filename)
#                 unique_filename = f"profile_{current_user.username}_{int(datetime.now().timestamp())}_{orig_name}"
                
#                 s3_client.upload_fileobj(file, BUCKET_NAME, unique_filename, ExtraArgs={'ContentType': file.content_type})
                
#                 final_pic = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{unique_filename}"
#                 update_fields['profile_pic'] = final_pic

#         if update_fields:
#             users_collection.update_one(
#                 {'_id': ObjectId(current_user.id)},
#                 {'$set': update_fields}
#             )
#             flash("Profile Identity parameters synchronized successfully!", "success")
            
#         return redirect(url_for('settings'))
#     except Exception as e:
#         print(f"Profile Sync Exception: {str(e)}")
#         return redirect(url_for('settings'))

# @app.route('/synchronize-identity', methods=['POST'])
# @login_required
# def synchronize_identity():
#     try:
#         data = request.get_json()
#         selected_avatar = data.get('selected_avatar')
        
#         if not selected_avatar:
#             return jsonify({'status': 'error', 'message': 'No avatar selected.'}), 400

#         users_collection.update_one(
#             {'_id': ObjectId(current_user.id)},
#             {'$set': {'profile_pic': selected_avatar}}
#         )
        
#         # Session aur current_user ko update karna zaroori hai taki UI turant refresh ho
#         current_user.profile_pic = selected_avatar
#         session['profile_pic'] = selected_avatar
#         session.modified = True
        
#         return jsonify({'status': 'success', 'message': 'Profile Updated'})
#     except Exception as e:
#         print(f"DEBUG ERROR: {str(e)}") # Critical for finding the break
#         return jsonify({'status': 'error', 'message': str(e)}), 500

# @app.route('/get-available-avatars', methods=['GET'])
# @login_required
# def get_available_avatars():
#     """Core directory scanning mapping to locate verified asset strings layout grid"""
#     avatar_dir = os.path.join(app.static_folder, 'images', 'avatars')
    
#     if not os.path.exists(avatar_dir):
#         return jsonify([])
        
#     file_list = []
#     for filename in os.listdir(avatar_dir):
#         if filename.lower().endswith(('.png', '.jpg', '.jpeg')) and 'default' not in filename:
#             file_list.append(filename)
            
#     return jsonify(sorted(file_list))

# @app.route('/block-tag', methods=['POST'])
# @login_required
# def block_tag():
#     tag_to_block = request.form.get('tag_name', '').strip().lower()
#     if tag_to_block:
#         users_collection.update_one(
#             {"_id": ObjectId(current_user.id)},
#             {"$addToSet": {"blocked_tags": tag_to_block}}
#         )
#         flash(f"#{tag_to_block} successfully restricted from your content stream.", "success")
#     return redirect(url_for('settings'))

# @app.route('/unblock-tag/<tag_name>', methods=['POST'])
# @login_required
# def unblock_tag(tag_name):
#     users_collection.update_one(
#         {"_id": ObjectId(current_user.id)},
#         {"$pull": {"blocked_tags": tag_name.lower()}}
#     )
#     flash(f"#{tag_name} restriction revoked successfully.", "success")
#     return redirect(url_for('settings'))

# # ---------------------------------------------------
# # AUTHENTICATION
# # ---------------------------------------------------

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form.get('username', '').strip()
#         email = request.form.get('email', '').strip()
#         password = request.form.get('password', '')
        
#         sec_question = request.form.get('security_question')
#         sec_answer = request.form.get('security_answer', '').strip().lower()
        
#         if not username or not email or not password:
#             return jsonify({'status': 'error', 'message': 'All authorization parameters are required.'})
        
#         try:
#             if users_collection.find_one({"$or": [{"email": email}, {"username": username}]}):
#                 return jsonify({'status': 'error', 'message': 'Username or Email already exists.'})
                
#             hashed_password = generate_password_hash(password)
            
#             users_collection.insert_one({
#                 "username": username, 
#                 "email": email, 
#                 "password": hashed_password,
#                 "profile_pic": f"https://ui-avatars.com/api/?name={username}&background=2563eb&color=fff",
#                 "created_at": datetime.utcnow(),
#                 "blocked_tags": [],
#                 "security_question": sec_question,
#                 "security_answer": sec_answer
#             })
            
#             return jsonify({'status': 'success'})
            
#         except Exception as database_error:
#             print(f"MongoDB write transaction fallout registry error: {str(database_error)}")
#             return jsonify({'status': 'error', 'message': 'Internal Cluster Registry Failure.'}), 500
            
#     return render_template('signup.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         try:
#             client_ip = request.remote_addr or "127.0.0.1"
            
#             # 🛡️ 1. SHIELD CHECK (Sabse pehle check hoga)
#             if check_security_limit(client_ip, "login", max_attempts=3, window_minutes=1):
#                 return jsonify({
#                     "status": "error", 
#                     "message": "Security Shield Activated: Maximum attempt limit reached. Try again in 60 seconds."
#                 }), 429

#             input_username = request.form.get('username', '').strip()
#             input_password = request.form.get('password', '')
            
#             user_data = users_collection.find_one({"username": input_username})
            
#             if not user_data:
#                 log_failed_attempt(client_ip, "login")  # ❌ Galat Username par attempt log karo
#                 return render_template('401.html', text_override="Requested profile ID is invalid..."), 401
                
#             if not check_password_hash(user_data['password'], input_password):
#                 log_failed_attempt(client_ip, "login")  # ❌ Galat Password par attempt log karo
#                 return jsonify({
#                     'status': 'password_error', 
#                     'message': 'Incorrect password signature. Please try again.'
#                 })
                
#             # ✅ SUCCESS: Purane errors clear kardo
#             clear_security_cache(client_ip, "login")
            
#             # 🛡️ Check karein ki kya admin login requested hai
#             login_as_admin = request.form.get('login_as_admin') == 'true'

#             user_email_lower = user_data.get('email', '').strip().lower() if user_data.get('email') else ""
#             is_user_admin = user_data.get('is_admin', False) or (user_email_lower in DEFAULT_ADMINS)

#             if login_as_admin and not is_user_admin:
#                 return jsonify({
#                     'status': 'error',
#                     'message': 'Access Denied: Your identity registry does not hold administrative clearance.'
#                 }), 403
            
#             if login_as_admin and is_user_admin:
#                 session['is_admin_session'] = True
#             else:
#                 session.pop('is_admin_session', None)
            
#             login_user(User(user_data))
#             session_token = str(uuid.uuid4())
            
#             # 📱 NAYA DEVICE PARSING LOGIC START
#             ua = parse(request.user_agent.string)
#             raw_ua = request.user_agent.string  # Browser ki raw string lenge

#             if ua.is_pc:
#                 clean_device = f"{ua.browser.family} on {ua.os.family}"
#             elif ua.is_mobile or ua.is_tablet:
#                 brand = str(ua.device.brand) if ua.device.brand else ""
#                 model = str(ua.device.model) if ua.device.model else ""
#                 family = str(ua.device.family) if ua.device.family else ""
                
#                 device_name = ""
                
#                 # Step 1: Agar Brand aur Model clear hai (e.g., Apple iPhone, Samsung SM-S928B)
#                 if brand and model and brand.lower() not in ["none", "generic"]:
#                     device_name = f"{brand} {model}"
#                 # Step 2: Agar Family name theek hai (e.g., Redmi Note 12)
#                 elif family and family.lower() not in ["none", "generic smartphone", "generic", "other"]:
#                     device_name = family
                    
#                 # 🚀 Step 3: THE FIX - Agar system galti se sirf "K" ya chota naam pakad le
#                 if len(device_name.strip()) <= 2:
#                     # Regex se raw data me se exact Android model chura lenge
#                     match = re.search(r'Android \d+[a-zA-Z0-9._]*; (?:[a-zA-Z]{2}-[a-zA-Z]{2}; )?([^;)]+)', raw_ua)
#                     if match:
#                         extracted = match.group(1).split('Build')[0].strip()
#                         if len(extracted) > 2:
#                             device_name = extracted
                    
#                 # Final Fallback agar browser ne bilkul hi model hide kar diya ho
#                 if len(device_name.strip()) <= 2:
#                     device_name = f"{ua.os.family} Smartphone"
                    
#                 # Final Formatting (e.g., Chrome on Samsung SM-G998B (Android))
#                 clean_device = f"{ua.browser.family} on {device_name}"
#                 if ua.os.family and ua.os.family not in device_name:
#                     clean_device += f" ({ua.os.family})"
#             else:
#                 clean_device = f"{ua.browser.family} on {ua.os.family}"
#             # 📱 NAYA DEVICE PARSING LOGIC END
            
#             session_data = {
#                 "user_id": user_data['_id'],
#                 "session_token": session_token,
#                 "device_info": clean_device,  # Ye ab clean hoke aayega
#                 "ip_address": request.remote_addr,
#                 "last_active": datetime.utcnow()
#             }
#             db.sessions.insert_one(session_data)
            
#             redirect_url = url_for('admin_dashboard') if (login_as_admin and is_user_admin) else url_for('index')
            
#             response = jsonify({
#                 'status': 'success', 
#                 'redirect_url': redirect_url,
#                 'message': 'Master security authorization data metrics synchronized successfully.'
#             })
#             response.set_cookie('nexus_session_token', session_token, httponly=True, secure=False)
#             return response
            
#         except Exception as e:
#             print("LOGIN DATABASE TIMEOUT ERROR:", e)
#             return jsonify({'status': 'error', 'message': 'Database connection failed.'}), 500
            
#     return render_template('login.html')

# # @app.route('/login', methods=['GET', 'POST'])
# # def login():
# #     if request.method == 'POST':
# #         try:
# #             client_ip = request.remote_addr or "127.0.0.1"
            
# #             # 🛡️ 1. SHIELD CHECK (Sabse pehle check hoga)
# #             if check_security_limit(client_ip, "login", max_attempts=3, window_minutes=1):
# #                 return jsonify({
# #                     "status": "error", 
# #                     "message": "Security Shield Activated: Maximum attempt limit reached. Try again in 60 seconds."
# #                 }), 429

# #             input_username = request.form.get('username', '').strip()
# #             input_password = request.form.get('password', '')
            
# #             user_data = users_collection.find_one({"username": input_username})
            
# #             if not user_data:
# #                 log_failed_attempt(client_ip, "login")  # ❌ Galat Username par attempt log karo
# #                 return render_template('401.html', text_override="Requested profile ID is invalid..."), 401
                
# #             if not check_password_hash(user_data['password'], input_password):
# #                 log_failed_attempt(client_ip, "login")  # ❌ Galat Password par attempt log karo
# #                 return jsonify({
# #                     'status': 'password_error', 
# #                     'message': 'Incorrect password signature. Please try again.'
# #                 })
                
# #             # ✅ SUCCESS: Purane errors clear kardo
# #             clear_security_cache(client_ip, "login")
            
# #             login_user(User(user_data))
# #             session_token = str(uuid.uuid4())
            
# #             # 📱 NAYA DEVICE PARSING LOGIC START
# #             ua = parse(request.user_agent.string)

# #             if ua.is_pc:
# #                 clean_device = f"{ua.browser.family} on {ua.os.family}"
# #             elif ua.is_mobile or ua.is_tablet:
# #                 # Mobile/Tablet ke case mein device brand nikalne ki koshish karein
# #                 device_brand = ua.device.brand if ua.device.brand else ua.device.family
                
# #                 # Agar abhi bhi "Generic" hai, toh direct OS ka naam use karein (e.g., Android, iOS)
# #                 if "generic" in device_brand.lower() or "spider" in device_brand.lower():
# #                     clean_device = f"{ua.browser.family} on {ua.os.family} Mobile"
# #                 else:
# #                     clean_device = f"{ua.browser.family} on {device_brand} ({ua.os.family})"
# #             else:
# #                 # Fallback agar kuch samajh na aaye
# #                 clean_device = f"{ua.browser.family} on {ua.os.family}"
# #             # 📱 NAYA DEVICE PARSING LOGIC END
            
# #             session_data = {
# #                 "user_id": user_data['_id'],
# #                 "session_token": session_token,
# #                 "device_info": clean_device,  # Ye ab clean hoke aayega
# #                 "ip_address": request.remote_addr,
# #                 "last_active": datetime.utcnow()
# #             }
# #             db.sessions.insert_one(session_data)
            
# #             response = jsonify({
# #                 'status': 'success', 
# #                 'redirect_url': url_for('index'),
# #                 'message': 'Master security authorization data metrics synchronized successfully.'
# #             })
# #             response.set_cookie('nexus_session_token', session_token, httponly=True, secure=False)
# #             return response
            
# #         except Exception as e:
# #             print("LOGIN DATABASE TIMEOUT ERROR:", e)
# #             return jsonify({'status': 'error', 'message': 'Database connection failed.'}), 500
            
# #     return render_template('login.html')

# @app.route('/settings', methods=['GET', 'POST'])
# @login_required
# def settings():
#     user_data = users_collection.find_one({"_id": ObjectId(current_user.id)})
    
#     if request.method == 'POST':
#         new_password = request.form.get('new_password')
        
#         if new_password:
#             # 1. New password ko securely hash karein
#             hashed_password = generate_password_hash(new_password)
            
#             # 2. Database node par naya hash update karein
#             users_collection.update_one(
#                 {"_id": ObjectId(current_user.id)},
#                 {"$set": {"password": hashed_password}}
#             )
            
#             # 3. Professional Professional Notification HTML Engine
#             user_email = user_data.get('email') or current_user.email
#             notify_subject = "Nexus Cloud: Password Changed Successfully"
#             notify_html = f"""
#             <div style="font-family: 'Inter', Arial, sans-serif; max-width: 500px; margin: auto; padding: 30px; border: 1px solid #e2e8f0; border-radius: 20px; background-color: #ffffff; box-shadow: 0 4px 12px rgba(0,0,0,0.03);">
#                 <div style="text-align: center; margin-bottom: 20px;">
#                     <span style="font-size: 40px;">🔒</span>
#                 </div>
#                 <h2 style="color: #0f172a; text-align: center; margin-top: 0; font-weight: 800; text-transform: uppercase; letter-spacing: -0.5px;">Password Updated</h2>
#                 <p style="color: #334155; font-size: 14px; line-height: 1.6; margin-top: 20px;">Hello <strong>{user_data.get('username', 'User')}</strong>,</p>
#                 <p style="color: #475569; font-size: 14px; line-height: 1.6;">This is an automated security notification to confirm that the security access credentials for your Nexus Cloud account were successfully changed via the Profile Settings panel.</p>
#                 <p style="color: #64748b; font-size: 13px; line-height: 1.6; background: #f8fafc; padding: 12px; border-radius: 10px; border-left: 4px solid #2563eb;">
#                     <strong>Status:</strong> Verification Complete<br>
#                     <strong>Location/Source:</strong> Account Security Panel
#                 </p>
#                 <p style="color: #475569; font-size: 14px; line-height: 1.6;">If you authorized this configuration change, your setup is complete and no further validation actions are required.</p>
#                 <hr style="border: none; border-top: 1px solid #f1f5f9; margin: 25px 0;">
#                 <p style="color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; text-align: center; margin-bottom: 0;">Securely deployed by,<br><strong>Nexus Cloud Core Matrix</strong></p>
#             </div>
#             """
#             # Universal function deployment
#             send_email(user_email, notify_subject, notify_html)
            
#             flash("Your profile security settings and password have been successfully compiled.", "success")
#             return redirect(url_for('settings'))
            
#         flash("Password field cannot be empty.", "error")
#         return redirect(url_for('settings'))

#     # Fetch all active sessions for GET request layout
#     user_sessions = list(db.sessions.find({"user_id": ObjectId(current_user.id)}))
    
#     return render_template('settings.html', 
#                             blocked_tags=user_data.get('blocked_tags', []),
#                             user_sessions=user_sessions,
#                             current_token=request.cookies.get('nexus_session_token'))

# @app.before_request
# def update_last_active():
#     if request.endpoint and 'static' in request.endpoint:
#         return

#     if current_user.is_authenticated:
#         token = request.cookies.get('nexus_session_token')
        
#         if token:
#             now = datetime.utcnow()
#             last_checked_str = session.get('last_session_check')
            
#             if last_checked_str:
#                 try:
#                     last_checked_time = datetime.fromisoformat(last_checked_str)
#                     if (now - last_checked_time).total_seconds() < 240:
#                         return 
#                 except ValueError:
#                     pass 

#             session_record = db.sessions.find_one({"session_token": token})
            
#             if not session_record:
#                 logout_user()
#                 session.clear()
#             else:
#                 db.sessions.update_one(
#                     {"session_token": token},
#                     {"$set": {"last_active": now}}
#                 )
#                 session['last_session_check'] = now.isoformat()
#         else:
#             logout_user()

# # @app.before_request
# # def update_last_active():
# #     if current_user.is_authenticated:
# #         token = request.cookies.get('nexus_session_token')
# #         if token:
# #             db.sessions.update_one(
# #                 {"session_token": token},
# #                 {"$set": {"last_active": datetime.utcnow()}}
# #             )

# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     session.pop('is_admin_session', None)
#     flash("Signed out.", "success")
#     return redirect(url_for('index'))

# @app.route('/update-username', methods=['POST'])
# @login_required
# def update_username():
#     try:
#         data = request.get_json()
#         new_username = data.get('new_username', '').strip()
#         old_username = current_user.username

#         # Security Checks
#         if not new_username or len(new_username) < 3:
#             return jsonify({"status": "error", "message": "Identity name must be at least 3 characters long."})
        
#         if not re.match(r"^[a-zA-Z0-9_]+$", new_username):
#             return jsonify({"status": "error", "message": "Only letters, numbers, and underscores are allowed."})

#         # Check if new username is already taken by someone else
#         existing_user = users_collection.find_one({"username": {"$regex": f"^{new_username}$", "$options": "i"}})
#         if existing_user and str(existing_user['_id']) != current_user.id:
#             return jsonify({"status": "error", "message": "This Identity is already taken by another user."})

#         # 1. Update Master Identity (Users Collection)
#         users_collection.update_one(
#             {"_id": ObjectId(current_user.id)},
#             {"$set": {"username": new_username}}
#         )

#         # 2. Update Image Ownerships (Images Collection)
#         images_collection.update_many(
#             {"uploader": old_username},
#             {"$set": {"uploader": new_username}}
#         )

#         # 3. Update Folder Ownerships (Folders Collection)
#         folders_collection.update_many(
#             {"owner": old_username},
#             {"$set": {"owner": new_username}}
#         )

#         return jsonify({"status": "success", "message": "Global identity synchronized successfully."})

#     except Exception as e:
#         print("USERNAME UPDATE ERROR:", str(e))
#         return jsonify({"status": "error", "message": "Critical database sync failure."})
    
# # ---------------------------------------------------
# # ACCOUNT RECOVERY (Deletion schedule cancel karne ke liye)
# # ---------------------------------------------------
# @app.route('/cancel-account-deletion', methods=['POST'])
# @login_required
# def cancel_account_deletion():
#     try:
#         # User ko 'is_scheduled_for_deletion' false kardo
#         users_collection.update_one(
#             {"_id": ObjectId(current_user.id)},
#             {"$set": {
#                 "is_scheduled_for_deletion": False,
#                 "delete_assets_option": False,
#                 "deletion_scheduled_at": None
#             }}
#         )
        
#         # Session update karo taaki UI turant refresh ho
#         session['is_scheduled_for_deletion'] = False
#         session.pop('deletion_scheduled_at', None)
        
#         return jsonify({'status': 'success', 'message': 'Account recovered successfully.'})
#     except Exception as e:
#         print(f"RECOVERY ERROR: {str(e)}")
#         return jsonify({'status': 'error', 'message': 'Internal recovery failure.'}), 500
    
# @app.route('/revoke-session/<token>', methods=['POST'])
# @login_required
# def revoke_session(token):
#     try:
#         # Sirf current user ke hi sessions delete ho sakein (Security)
#         db.sessions.delete_one({
#             "session_token": token, 
#             "user_id": ObjectId(current_user.id)
#         })
#         return jsonify({"status": "success"})
#     except Exception as e:
#         return jsonify({"status": "error", "message": str(e)})
    
# @app.route('/revoke-all-sessions', methods=['POST'])
# @login_required
# def revoke_all_sessions():
#     try:
#         # Current device ka token fetch karo
#         current_token = request.cookies.get('nexus_session_token')
        
#         if not current_token:
#             return jsonify({"status": "error", "message": "Current session context missing."}), 400
            
#         # 🚨 MAGIC QUERY: Is user ke wo saare session uda do, jinka token current_token ke barabar ($ne) NAHI hai
#         result = db.sessions.delete_many({
#             "user_id": ObjectId(current_user.id),
#             "session_token": {"$ne": current_token}
#         })
        
#         return jsonify({
#             "status": "success", 
#             "message": f"Successfully remove {result.deleted_count} remote devices."
#         })
#     except Exception as e:
#         print("REMOVE ALL ERROR:", str(e))
#         return jsonify({"status": "error", "message": "Database sync failed."}), 500
    
# @app.route('/get-images')
# @login_required
# def get_images():
#     page = int(request.args.get('page', 1))
#     per_page = 20  # Ek baar mein sirf 20 images
#     skip = (page - 1) * per_page
    
#     # Database se sirf 20 images nikalenge
#     images = list(images_collection.find({"owner": current_user.username})
#                 .sort("timestamp", -1)
#                 .skip(skip)
#                 .limit(per_page))
    
#     # Images ko JSON format mein bhejenge
#     return jsonify(json.loads(json_util.dumps(images)))

# #-------------------------------------------------------------------------------------------------
# # Folder Sharing Logic (Token Generation, Access Control, Password Protection)
# #-------------------------------------------------------------------------------------------------
# s = URLSafeTimedSerializer(app.secret_key)

# @app.route('/generate-share-link/<folder_id>', methods=['POST'])
# @login_required
# def generate_share_link(folder_id):
#     data = request.get_json()
#     password = data.get('password')
    
#     # 1. Folder check karo
#     folder = folders_collection.find_one({"_id": ObjectId(folder_id), "owner": current_user.username})
#     if not folder:
#         return jsonify({"status": "error", "message": "Folder not found"}), 404

#     # 2. Privacy Check: Agar folder private hai, toh Email warning bhejo
#     if not folder.get('is_public', False):
#         try:
#             # 📱 NAYA DEVICE PARSING LOGIC START
#             ua = parse(request.user_agent.string)
#             raw_ua = request.user_agent.string

#             if ua.is_pc:
#                 device_info = f"{ua.browser.family} on {ua.os.family}"
#             elif ua.is_mobile or ua.is_tablet:
#                 brand = str(ua.device.brand) if ua.device.brand else ""
#                 model = str(ua.device.model) if ua.device.model else ""
#                 family = str(ua.device.family) if ua.device.family else ""
                
#                 device_name = ""
                
#                 # Step 1: Agar Brand aur Model clear hai
#                 if brand and model and brand.lower() not in ["none", "generic"]:
#                     device_name = f"{brand} {model}"
#                 # Step 2: Agar Family name theek hai
#                 elif family and family.lower() not in ["none", "generic smartphone", "generic", "other"]:
#                     device_name = family
                    
#                 # 🚀 Step 3: THE FIX - Regex for Android hidden models
#                 if len(device_name.strip()) <= 2:
#                     match = re.search(r'Android \d+[a-zA-Z0-9._]*; (?:[a-zA-Z]{2}-[a-zA-Z]{2}; )?([^;)]+)', raw_ua)
#                     if match:
#                         extracted = match.group(1).split('Build')[0].strip()
#                         if len(extracted) > 2:
#                             device_name = extracted
                    
#                 # Final Fallback
#                 if len(device_name.strip()) <= 2:
#                     device_name = f"{ua.os.family} Smartphone"
                    
#                 device_info = f"{ua.browser.family} on {device_name}"
#                 if ua.os.family and ua.os.family not in device_name:
#                     device_info += f" ({ua.os.family})"
#             else:
#                 device_info = f"{ua.browser.family} on {ua.os.family}"
#             # 📱 NAYA DEVICE PARSING LOGIC END
            
#             # IST (Indian Standard Time) calculate karna: UTC + 5:30 hours
#             ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
#             current_time = ist_time.strftime("%B %d, %Y at %I:%M %p IST")
            
#             subject = "⚠️ Security Alert: Private Folder Shared"
#             body = f"""
# Hello {current_user.username},

# A sharing link was generated for your PRIVATE folder '{folder['folder_name']}'.

# Time: {current_time}
# Device: {device_info}

# If this was not you, please immediately secure your account.

# Regards,
# Nexus Security Team
# """
            
#             dispatch_smtp_secure_email(current_user.email, current_user.username, subject, body)
#         except Exception as e:
#             print(f"Non-fatal Email Error: {e}") # Yeh code ko crash nahi hone dega

#     # 3. Password hash karo agar set kiya hai
#     hashed_pw = generate_password_hash(password) if password else None
    
#     # 4. Logic: Agar password hai toh 48hr expiry (172800 sec), warna None (Permanent)
#     expiry_time = 172800 if password else None 
    
#     # 5. Secure Token (Salted)
#     token = s.dumps(str(folder_id), salt='folder-share-salt')
    
#     # 6. DB mein save karo (Token, Password aur Expiry)
#     folders_collection.update_one(
#         {"_id": ObjectId(folder_id)},
#         {"$set": {
#             "share_token": token,
#             "share_password": hashed_pw,
#             "expiry_in_seconds": expiry_time
#         }}
#     )
    
#     # 7. Public link return karo
#     share_url = url_for('access_shared_folder', token=token, _external=True)
#     return jsonify({"status": "success", "share_url": share_url})

# @app.route('/share/access/<token>', methods=['GET', 'POST'])
# def access_shared_folder(token):
#     # 1. Folder fetch karo (Token verify karne se pehle zaroori hai expiry nikalne ke liye)
#     folder = folders_collection.find_one({"share_token": token})
#     if not folder:
#         return "Folder not found or link invalid.", 404
        
#     # 🌟 Dynamic Expiry Check (Agar database mein expiry_in_seconds None hai, toh default 48hrs/172800 le lo)
#     expiry = folder.get('expiry_in_seconds') 
    
#     # 2. Token verify karo (Dynamic expiry ke sath)
#     try:
#         # Note: s.loads mein 'max_age' agar None hoga, toh link permanent rahega
#         folder_id = s.loads(token, salt='folder-share-salt', max_age=expiry)
#     except:
#         return "This link has expired or is invalid.", 403

#     # Ensure ki jo ID token se decode hui, woh wahi folder hai
#     if str(folder['_id']) != str(folder_id):
#         return "Invalid link.", 403

#     # 3. Access control logic (Owner bypass + Password check)
#     if folder.get('share_password'):
#         is_owner = current_user.is_authenticated and folder['owner'] == current_user.username
        
#         if not is_owner:
#             if request.method == 'POST':
#                 user_pw = request.form.get('password')
#                 if check_password_hash(folder['share_password'], user_pw):
#                     session[f'access_{folder_id}'] = True
#                 else:
#                     return render_template('password_prompt.html', token=token, error="Wrong Password!")
            
#             # Agar password verify nahi hua hai, toh prompt dikhao
#             if not session.get(f'access_{folder_id}'):
#                 return render_template('password_prompt.html', token=token)

#     # 4. Access granted: Photos dikhao
#     images = list(images_collection.find({"folder_name": folder['folder_name'], "in_trash": False}))
#     return render_template('shared_view.html', images=images, folder=folder)

# @app.route('/share/download-all/<token>')
# def download_all_shared(token):
#     # 1. Folder Token Fetch Karein
#     folder = folders_collection.find_one({"share_token": token})
#     if not folder:
#         return "Folder not found.", 404
        
#     # 2. Expiry Verify Karein
#     expiry = folder.get('expiry_in_seconds')
#     try:
#         folder_id = s.loads(token, salt='folder-share-salt', max_age=expiry)
#     except:
#         return "Link has expired.", 403

#     # 3. Session Security Check (Taki bina password wala download na kar sake)
#     if folder.get('share_password') and not session.get(f'access_{folder_id}'):
#         return "Unauthorized access.", 401
        
#     # 4. Saari photos nikalen
#     images = list(images_collection.find({"folder_name": folder['folder_name'], "in_trash": False}))
#     if not images:
#         return "Folder is empty.", 404

#     # 5. GeeksforGeeks Standard: In-Memory ZIP file generation (Fast & Efficient)
#     memory_file = BytesIO()
#     with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
#         for img in images:
#             try:
#                 # S3 se padhein aur seedha Zip mein daalein
#                 s3_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=img['s3_key'])
#                 file_bytes = s3_obj['Body'].read()
#                 zf.writestr(img['filename'], file_bytes)
#             except Exception as e:
#                 print(f"Error zipping {img['filename']}: {e}")
    
#     memory_file.seek(0)
    
#     # 6. ZIP Client ko return karein
#     return send_file(
#         memory_file,
#         mimetype='application/zip',
#         as_attachment=True,
#         download_name=f"{folder['folder_name']}_Nexus_Assets.zip"
#     )

# def send_password_change_notification(user_email):
#     user_record = users_collection.find_one({"email": user_email})
#     username = user_record.get("username", "User") if user_record else "User"
    
#     # IST (Indian Standard Time) calculate karna: UTC + 5:30 hours
#     ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
    
#     # Live date aur time format karna (IST mein)
#     current_date = ist_time.strftime("%B %d, %Y")
#     current_time = ist_time.strftime("%I:%M %p IST") 
    
#     subject = "Security Notice: Your Nexus Cloud password was changed"
    
#     body = f"""Hello {username},

# This is a confirmation that your password for Nexus Cloud was updated on {current_date} at {current_time}.

# If you made this change: No action is needed.

# If you did not authorize this change: Secure your account immediately by resetting your password on the login portal or contact our support team.

# For your security, always ensure you are accessing your account through official channels.

# Best regards,
# The Nexus Cloud Security Team
# """
    
#     try:
#         dispatch_smtp_secure_email(user_email, username, subject, body)
#     except Exception as e:
#         print(f"Notification Email Skipped: {e}")
        
# @app.route('/admin/dashboard')
# @admin_required
# def admin_dashboard():
#     general_assets = list(images_collection.find({"folder_name": {"$regex": "^General$", "$options": "i"}, "in_trash": False}).sort("uploaded_at", -1))
#     all_users = list(users_collection.find({}))
#     active_rules = list(moderation_rules_collection.find({}).sort("created_at", -1))
#     return render_template('admin_dashboard.html', assets=general_assets, users=all_users, default_admins=DEFAULT_ADMINS, rules=active_rules)

# @app.route('/admin/promote', methods=['POST'])
# @admin_required
# def admin_promote():
#     data = request.get_json() or {}
#     target_username = data.get('username', '').strip()
    
#     user = users_collection.find_one({"username": target_username})
#     if not user:
#         return jsonify({"status": "error", "message": "User node not found."}), 404
        
#     users_collection.update_one({"_id": user["_id"]}, {"$set": {"is_admin": True}})
    
#     # IST (Indian Standard Time) Formatting
#     ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
#     current_time = ist_time.strftime("%B %d, %Y at %I:%M %p IST")
    
#     # 📧 MAIL 1: ALERT TO DEFAULT MASTER ADMINS (With Authorizer Email)
#     subject_master = "🚨 Security Notice: New Administrator Appointed"
#     body_master = f"""Hello Administrator,

# This is an automated security report from the Nexus Control Shield. A new identity profile has been granted administrative access parameters.

# [PROMOTED USER DETAILS]
# Account Username: {user['username']}
# Registered Email: {user.get('email', 'N/A')}

# [AUTHORIZER DETAILS]
# Authorized By: {current_user.username}
# Authorizer Email: {getattr(current_user, 'email', 'N/A')}

# Timestamp: {current_time}

# If you did not authorize this deployment, please log into your default root account and revoke permissions immediately.

# Best regards,
# The Nexus Cloud Security Team"""
    
#     for master_email in DEFAULT_ADMINS:
#         try: dispatch_smtp_secure_email(master_email, "Master Admin", subject_master, body_master)
#         except Exception as e: print(f"Master Email error: {e}")

#     # 📧 MAIL 2: CONGRATULATIONS TO THE NEW ADMIN (Polite & Formal Warning)
#     if user.get('email'):
#         subject_new_admin = "🎉 Access Granted: Welcome to the Nexus Admin Cluster"
#         body_new_admin = f"""Hello {user['username']},

# Congratulations! You have been officially appointed as an Administrator on the Nexus Cloud Platform.

# Your identity profile has been successfully integrated into the Core Administrative Matrix. This clearance grants you high-level system parameters to regulate public ingest content schemas, handle directory clusters, and manage global repository security.

# With great power comes great responsibility. As a member of the admin cluster, you hold master keys to data structures. We trust you to handle these privileges ethically, securely, and professionally to protect our global user network. Please ensure all system updates and asset management conform strictly to our compliance protocols.

# Welcome aboard the core node team.

# Best regards,
# The Nexus Global Governance Board"""
#         try:
#             dispatch_smtp_secure_email(user['email'], user['username'], subject_new_admin, body_new_admin)
#         except Exception as e:
#             print(f"New Admin Notification Email Skipped: {e}")

#     return jsonify({"status": "success", "message": f"{target_username} promoted to Admin and notified successfully."})

# @app.route('/admin/demote', methods=['POST'])
# @admin_required
# def admin_demote():
#     data = request.get_json() or {}
#     target_username = data.get('username', '').strip()
    
#     user = users_collection.find_one({"username": target_username})
#     if not user: 
#         return jsonify({"status": "error", "message": "User not found."}), 404
        
#     # 🛡️ BRAHMASTRA LOGIC: Default core 2 admins ko koi touch bhi nahi kar sakta
#     if user.get('email') in DEFAULT_ADMINS:
#         return jsonify({"status": "error", "message": "Critical Denial: Master Core root profiles cannot be demoted."}), 403
        
#     # 🚫 SELF-DEMOTION SHIELD: Admin khud ko demote nahi kar sakta
#     if user['username'] == current_user.username:
#         return jsonify({"status": "error", "message": "Critical Denial: You cannot revoke your own administrative clearance."}), 400
        
#     users_collection.update_one({"_id": user["_id"]}, {"$set": {"is_admin": False}})
#     return jsonify({"status": "success", "message": f"{target_username} removed from admin privileges."})

# @app.route('/admin/manage-asset/<action>/<image_id>', methods=['POST'])
# @admin_required
# def admin_manage_asset(action, image_id):
#     asset = images_collection.find_one({"_id": ObjectId(image_id)})
#     if not asset: return jsonify({"status": "error", "message": "Asset not found"}), 404
        
#     if action == 'delete':
#         try:
#             s3_client.delete_object(Bucket=BUCKET_NAME, Key=asset['s3_key'])
#             try: s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"thumb_{asset['s3_key']}")
#             except: pass
#             images_collection.delete_one({"_id": ObjectId(image_id)})
#             return jsonify({"status": "success", "message": "Asset purged completely."})
#         except Exception as e: return jsonify({"status": "error", "message": str(e)})
            
#     elif action in ['public', 'private']:
#         is_public_flag = (action == 'public')
#         images_collection.update_one({"_id": ObjectId(image_id)}, {"$set": {"is_public": is_public_flag}})
#         return jsonify({"status": "success", "message": "Asset privacy status updated."})
        
#     return jsonify({"status": "error", "message": "Invalid action."}), 400

# # ---------------------------------------------------
# # ERROR OVERRIDE HANDLERS
# # ---------------------------------------------------
# @app.errorhandler(401)
# def unauthorized_error(e):
#     return render_template('401.html', text_override="Access Unauthorized: The requested identity profile is invalid or requires authentication."), 401

# @app.errorhandler(403)
# def forbidden_error(e):
#     return render_template('401.html', text_override="Security Shield: Administrative clearance level required to access this matrix node."), 403

# @app.errorhandler(404)
# def page_not_found(e):
#     return render_template('404.html'), 404

# @app.route('/admin/moderation/add', methods=['POST'])
# @admin_required
# def admin_add_moderation_rule():
#     data = request.get_json() or {}
#     new_label = data.get('label', '').strip().lower()
    
#     if not new_label:
#         return jsonify({"status": "error", "message": "Security tracking node value cannot be null."}), 400
        
#     exists = moderation_rules_collection.find_one({"label": new_label})
#     if exists:
#         return jsonify({"status": "error", "message": "This label target registry parameter already exists inside the active shield shield system."}), 400
        
#     moderation_rules_collection.insert_one({
#         "label": new_label,
#         "created_at": datetime.utcnow()
#     })
#     return jsonify({"status": "success", "message": f"AI Moderation shield updated successfully: Tracking parameter '{new_label}' is now active."})

# @app.route('/admin/moderation/delete/<rule_id>', methods=['POST'])
# @admin_required
# def admin_delete_moderation_rule(rule_id):
#     try:
#         moderation_rules_collection.delete_one({"_id": ObjectId(rule_id)})
#         return jsonify({"status": "success", "message": "Dynamic shield tracking parameter removed safely."})
#     except Exception as e:
#         return jsonify({"status": "error", "message": str(e)}), 500

# # @app.route('/debug-check')
# # def debug_check():
# #     try:
# #         # Total images in DB
# #         total = images_collection.count_documents({})
# #         public = images_collection.count_documents({"is_public": True})
# #         general = images_collection.count_documents({"folder_name": {"$regex": "^General$", "$options": "i"}})
# #         with_tags = images_collection.count_documents({"tags": {"$exists": True, "$ne": []}})
        
# #         # Sample image to see its structure
# #         sample = images_collection.find_one({})
# #         sample_info = {
# #             "folder": sample.get("folder_name") if sample else None,
# #             "is_public": sample.get("is_public") if sample else None,
# #             "tags": sample.get("tags", [])[:5] if sample else None,
# #             "uploader": sample.get("uploader") if sample else None
# #         }
        
# #         # Folders in DB
# #         folders = []
# #         if current_user.is_authenticated:
# #             folders = list(folders_collection.find(
# #                 {"owner": current_user.username}, 
# #                 {"folder_name": 1, "_id": 0}
# #             ))

# #         return jsonify({
# #             "total_images": total,
# #             "public_images": public,
# #             "general_folder_images": general,
# #             "images_with_tags": with_tags,
# #             "sample_image": sample_info,
# #             "your_folders_in_db": folders,
# #             "logged_in_as": current_user.username if current_user.is_authenticated else "NOT LOGGED IN"
# #         })
# #     except Exception as e:
# #         return jsonify({"error": str(e)})

# # @app.route('/run-thumbnail-migration', methods=['GET'])
# # @login_required
# # def run_thumbnail_migration():
# #     if current_user.username != "Parm055": # Sirf admin (aap) ke liye lock
# #         return "Unauthorized", 403
        
# #     assets = list(images_collection.find({"thumb_url": {"$exists": False}}))
# #     count = 0
    
# #     for asset in assets:
# #         try:
# #             # 1. S3 se original image download karo
# #             s3_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=asset['s3_key'])
# #             file_bytes = s3_obj['Body'].read()
            
# #             # 2. Thumbnail banao
# #             img = Image.open(BytesIO(file_bytes))
# #             if img.mode in ("RGBA", "P"): img = img.convert("RGB")
# #             img.thumbnail((600, 600))
            
# #             thumb_io = BytesIO()
# #             img.save(thumb_io, format='JPEG', quality=60)
# #             thumb_io.seek(0)
            
# #             # 3. S3 par naya thumbnail upload karo
# #             thumb_filename = f"thumb_{asset['s3_key']}"
# #             s3_client.put_object(
# #                 Bucket=BUCKET_NAME,
# #                 Key=thumb_filename,
# #                 Body=thumb_io.getvalue(),
# #                 ContentType='image/jpeg'
# #             )
            
# #             # 4. DB update karo
# #             thumb_url = f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com/{thumb_filename}"
# #             images_collection.update_one(
# #                 {"_id": asset['_id']},
# #                 {"$set": {"thumb_url": thumb_url}}
# #             )
# #             count += 1
# #             print(f"✅ Migration successful for: {asset['filename']}")
            
# #         except Exception as e:
# #             print(f"❌ Error migrating {asset.get('filename')}: {e}")
            
# #     return f"Migration Completed! {count} thumbnails generated."
# #    ## http://127.0.0.1:5000/run-thumbnail-migration
    
# if __name__ == '__main__':
#     # Render ke dynamic port ko fetch karna (GeeksforGeeks standard practice)
#     port = int(os.environ.get('PORT', 5000))
#     app.run(host='0.0.0.0', port=port, debug=False)