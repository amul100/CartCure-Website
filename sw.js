/**
 * CartCure Service Worker
 * Provides offline caching and faster repeat visits
 */

const CACHE_NAME = 'cartcure-v4';
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/styles.css',
    '/script.js',
    '/security-config.js',
    '/CartCure_fullLogo.webp',
    '/CartCure_fullLogo_compressed.jpg',
    '/CartCure_Favicon_compressed.png'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                // Cache static assets, but don't fail if some are missing
                return Promise.allSettled(
                    STATIC_ASSETS.map((url) =>
                        cache.add(url).catch((err) => {
                            console.warn('Failed to cache:', url, err);
                        })
                    )
                );
            })
            .then(() => self.skipWaiting())
    );
});

// Activate event - cleanup old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) =>
                Promise.all(
                    keys
                        .filter((key) => key !== CACHE_NAME)
                        .map((key) => caches.delete(key))
                )
            )
            .then(() => self.clients.claim())
    );
});

// Fetch event - different strategies for different resource types
self.addEventListener('fetch', (event) => {
    // Skip non-GET requests
    if (event.request.method !== 'GET') return;

    // Skip cross-origin requests (except CDN resources we trust)
    const url = new URL(event.request.url);
    const isSameOrigin = url.origin === self.location.origin;
    const isTrustedCDN = url.hostname === 'cdn.jsdelivr.net';

    if (!isSameOrigin && !isTrustedCDN) return;

    // Skip Google Apps Script API calls (always need fresh data)
    if (url.hostname === 'script.google.com') return;

    // Determine if this is a critical resource that should use network-first
    // CSS and HTML need fresh content to avoid layout issues
    const isCriticalResource = url.pathname.endsWith('.css') ||
                               url.pathname.endsWith('.html') ||
                               url.pathname === '/' ||
                               url.pathname === '';

    if (isCriticalResource) {
        // Network-first strategy for CSS/HTML: always try network, fallback to cache
        event.respondWith(
            fetch(event.request)
                .then((networkResponse) => {
                    // Cache the fresh response for offline use
                    if (networkResponse.ok) {
                        const responseClone = networkResponse.clone();
                        caches.open(CACHE_NAME)
                            .then((cache) => cache.put(event.request, responseClone));
                    }
                    return networkResponse;
                })
                .catch(() => {
                    // Network failed, try cache as fallback
                    return caches.match(event.request);
                })
        );
    } else {
        // Stale-while-revalidate for images, scripts, and other assets
        event.respondWith(
            caches.match(event.request)
                .then((cachedResponse) => {
                    // Create fetch promise for background update
                    const fetchPromise = fetch(event.request)
                        .then((networkResponse) => {
                            // Only cache successful responses
                            if (networkResponse.ok) {
                                const responseClone = networkResponse.clone();
                                caches.open(CACHE_NAME)
                                    .then((cache) => cache.put(event.request, responseClone));
                            }
                            return networkResponse;
                        })
                        .catch(() => {
                            // Network failed, return cached version or nothing
                            return cachedResponse;
                        });

                    // Return cached version immediately, update in background
                    return cachedResponse || fetchPromise;
                })
        );
    }
});
