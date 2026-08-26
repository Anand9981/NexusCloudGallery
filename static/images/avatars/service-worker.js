const CACHE_NAME = 'nexus-cloud-v1';
const urlsToCache = [
    '/',
    '/login',
    '/static/images/avatars/ai-avatar-1.png'
];

// App Install Hote Waqt
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            console.log('Opened cache');
            return cache.addAll(urlsToCache);
        })
    );
});

// Network Requests Handle Karna (Fast Loading)
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request).then(response => {
            return response || fetch(event.request);
        })
    );
});