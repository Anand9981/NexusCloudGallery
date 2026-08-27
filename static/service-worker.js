const CACHE_NAME = 'nexus-cloud-v3';
const staticAssets = [
    '/static/logo/logo.png',
    '/manifest.json'
];

// Install Event (Purani cache ko immediately replace karega)
self.addEventListener('install', event => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(staticAssets);
        })
    );
});

// Activate Event (Purana v1/v2 cache memory se uda dega)
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys.map(key => {
                    if (key !== CACHE_NAME) {
                        console.log('Purging Old Cache:', key);
                        return caches.delete(key);
                    }
                })
            );
        }).then(() => self.clients.claim())
    );
});

// Fetch Event (HTML pages hamesha live network se aayenge)
self.addEventListener('fetch', event => {
    if (event.request.mode === 'navigate') {
        event.respondWith(
            fetch(event.request).catch(() => caches.match(event.request))
        );
        return;
    }

    event.respondWith(
        caches.match(event.request).then(cachedResponse => {
            return cachedResponse || fetch(event.request);
        })
    );
});