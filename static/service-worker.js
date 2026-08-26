const CACHE_NAME = 'nexus-cloud-v2';
const urlsToCache = [
    '/',
    '/login',
    '/static/logo/logo.png'
];

self.addEventListener('install', event => {
    self.skipWaiting(); // Naye service worker ko turant activate karega
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            console.log('Opened cache');
            return cache.addAll(urlsToCache);
        })
    );
});

self.addEventListener('activate', event => {
    // Purani cache (v1) ko delete karega
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cache => {
                    if (cache !== CACHE_NAME) {
                        return caches.delete(cache);
                    }
                })
            );
        })
    );
});

self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request).then(response => {
            return response || fetch(event.request);
        })
    );
});