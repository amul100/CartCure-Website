/**
 * CartCure Service Worker
 * Provides offline caching and faster repeat visits
 */

const CACHE_NAME = 'cartcure-v7';
const STATIC_ASSETS = [
    // Core pages
    '/',
    '/index.html',
    '/offline.html',
    '/testimonials.html',
    '/how-to.html',
    '/feedback.html',
    '/demo.html',
    '/quote-acceptance.html',
    '/payment-received.html',
    '/privacy-policy.html',
    '/terms-of-service.html',
    // Service pages
    '/shopify-bug-fixes.html',
    '/shopify-checkout-optimization.html',
    '/shopify-seo-fixes.html',
    '/shopify-speed-optimization.html',
    '/shopify-theme-customization.html',
    // Stylesheets
    '/styles.css',
    // Scripts
    '/script.js',
    '/testimonials.js',
    '/security-config.js',
    // Images
    '/CartCure_fullLogo.webp',
    '/CartCure_fullLogo_compressed.jpg',
    '/CartCure_Favicon_compressed.webp',
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
    // CSS, HTML, and JS need fresh content to avoid layout/functionality issues
    const isCriticalResource = url.pathname.endsWith('.css') ||
                               url.pathname.endsWith('.html') ||
                               url.pathname.endsWith('.js') ||
                               url.pathname === '/' ||
                               url.pathname === '';

    if (isCriticalResource) {
        // Network-first strategy for CSS/HTML/JS: always try network, fallback to cache
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
                .catch(async () => {
                    // Network failed, try cache as fallback
                    const cachedResponse = await caches.match(event.request);
                    if (cachedResponse) {
                        return cachedResponse;
                    }
                    // For HTML pages with no cache, show offline page
                    if (url.pathname.endsWith('.html') || url.pathname === '/' || url.pathname === '') {
                        return caches.match('/offline.html');
                    }
                    return cachedResponse;
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
