(function() {
    'use strict';

    const SCRIPT_URL = 'https://script.google.com/macros/s/AKfycbyBjf9TKEogrSWp5cLxs4tZWuGbIdWUYGn5oDGIBVWvVQWggNDjxZzgugrgo0s8LZ4stg/exec';

    // Check for demo mode
    const urlParams = new URLSearchParams(window.location.search);
    const isDemo = urlParams.get('demo') === 'true';

    // Demo testimonials for layout testing
    const demoTestimonials = [
        {
            name: 'Sarah Mitchell',
            business: 'Kiwi Crafts Co',
            location: 'Auckland',
            rating: 5,
            testimonial: 'CartCure fixed our checkout issue within hours! Our conversion rate improved immediately. Highly recommend for any Shopify store owner in NZ.'
        },
        {
            name: 'James Thompson',
            business: 'Thompson Outdoors',
            location: 'Wellington',
            rating: 5,
            testimonial: 'Professional, quick, and affordable. They sorted out our mobile menu and product filtering. Will definitely use again for future Shopify work.'
        },
        {
            name: 'Emma Wilson',
            business: 'Coastal Beauty NZ',
            location: 'Christchurch',
            rating: 4,
            testimonial: 'Great communication throughout the process. Fixed several bugs on our site and even suggested improvements we hadn\'t thought of.'
        },
        {
            name: 'Mike Chen',
            business: 'Tech Gadgets Store',
            location: 'Hamilton',
            rating: 5,
            testimonial: 'Fast turnaround and excellent quality work. Our site speed improved dramatically after their optimizations. A+ service!'
        },
        {
            name: 'Lisa Brown',
            business: 'Organic Foods NZ',
            location: 'Tauranga',
            rating: 5,
            testimonial: 'Helped us integrate a complex shipping calculator. The support was outstanding and they explained everything clearly.'
        },
        {
            name: 'David Patel',
            business: 'Fashion Forward',
            location: 'Dunedin',
            rating: 4,
            testimonial: 'Very responsive team. They customized our product pages exactly how we wanted. Fair pricing for quality work.'
        }
    ];

    // Show demo banner
    function showDemoBanner() {
        const container = document.querySelector('.testimonials-page .container');
        if (!container) return;

        // Check if banner already exists
        if (document.getElementById('demoBanner')) return;

        const banner = document.createElement('div');
        banner.id = 'demoBanner';
        banner.style.cssText = `
            background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
            color: white;
            text-align: center;
            padding: 0.75rem 1rem;
            font-weight: 700;
            font-size: 0.9rem;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            letter-spacing: 1px;
            margin-bottom: 1.5rem;
            border: 2px solid #cc5500;
            box-shadow: 3px 3px 0px rgba(0, 0, 0, 0.15);
        `;
        banner.textContent = 'DEMO MODE - Layout Preview Only';

        // Insert after the back link
        const backLink = container.querySelector('.back-link');
        if (backLink) {
            backLink.insertAdjacentElement('afterend', banner);
        } else {
            container.insertBefore(banner, container.firstChild);
        }
    }

    // Mobile menu toggle
    const menuToggle = document.getElementById('menuToggle');
    const navLinks = document.getElementById('navLinks');

    if (menuToggle && navLinks) {
        menuToggle.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            menuToggle.classList.toggle('active');
        });

        document.querySelectorAll('.nav-links a').forEach(link => {
            link.addEventListener('click', () => {
                navLinks.classList.remove('active');
                menuToggle.classList.remove('active');
            });
        });
    }

    // Header scroll effect (throttled for performance)
    const header = document.getElementById('header');
    let scrollTicking = false;
    window.addEventListener('scroll', () => {
        if (!scrollTicking) {
            window.requestAnimationFrame(() => {
                if (window.scrollY > 50) {
                    header.classList.add('scrolled');
                } else {
                    header.classList.remove('scrolled');
                }
                scrollTicking = false;
            });
            scrollTicking = true;
        }
    }, { passive: true });

    // Load all testimonials (no 5-star filter, no limit)
    function loadAllTestimonials() {
        const testimonialGrid = document.getElementById('testimonialGrid');
        if (!testimonialGrid) return;

        // Demo mode - show sample testimonials and banner
        if (isDemo) {
            showDemoBanner();
            renderTestimonials(demoTestimonials);
            return;
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);

        // Fetch ALL approved testimonials (no fiveStarOnly, no limit)
        fetch(SCRIPT_URL + '?action=getTestimonials', { signal: controller.signal })
            .then(response => response.text())
            .then(text => {
                try {
                    return JSON.parse(text);
                } catch (e) {
                    throw new Error('Invalid JSON response');
                }
            })
            .then(data => {
                clearTimeout(timeoutId);
                if (data.success && data.testimonials && data.testimonials.length > 0) {
                    renderTestimonials(data.testimonials);
                } else {
                    renderComingSoon();
                }
            })
            .catch(() => {
                clearTimeout(timeoutId);
                renderComingSoon();
            });
    }

    function renderTestimonials(testimonials) {
        const testimonialGrid = document.getElementById('testimonialGrid');
        if (!testimonialGrid) return;

        testimonialGrid.innerHTML = '';

        testimonials.forEach(testimonial => {
            const initials = getInitials(testimonial.name);
            const subtitle = [testimonial.business, testimonial.location]
                .filter(x => x)
                .join(', ');
            const stars = '\u2605'.repeat(testimonial.rating) + '\u2606'.repeat(5 - testimonial.rating);

            const card = document.createElement('div');
            card.className = 'testimonial-card';
            card.innerHTML = `
                <div class="testimonial-header">
                    <div class="testimonial-avatar">${escapeHtml(initials)}</div>
                    <div class="testimonial-info">
                        <h4>${escapeHtml(testimonial.name)}</h4>
                        <p>${escapeHtml(subtitle)}</p>
                    </div>
                </div>
                <div class="testimonial-content">
                    "${escapeHtml(testimonial.testimonial)}"
                </div>
                <div class="testimonial-rating">${stars}</div>
            `;
            testimonialGrid.appendChild(card);
        });

        // Animate cards in using CSS classes (no inline styles)
        testimonialGrid.querySelectorAll('.testimonial-card').forEach((card) => {
            card.classList.add('fade-in-up');
            // Use double RAF for batched style updates
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    card.classList.add('animate');
                });
            });
        });
    }

    function renderComingSoon() {
        const testimonialGrid = document.getElementById('testimonialGrid');
        if (!testimonialGrid) return;

        testimonialGrid.innerHTML = `
            <div class="testimonials-coming-soon">
                <div class="coming-soon-icon">💬</div>
                <h3>Testimonials Coming Soon</h3>
                <p>We're just getting started! Check back soon to see what our clients have to say about their experience with CartCure.</p>
            </div>
        `;
    }

    function getInitials(name) {
        if (!name) return '?';
        const parts = name.trim().split(' ');
        if (parts.length === 1) {
            return parts[0].charAt(0).toUpperCase();
        }
        return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Register service worker for offline caching
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js').catch(() => {});
    }

    // Initialize
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadAllTestimonials);
    } else {
        loadAllTestimonials();
    }
})();
