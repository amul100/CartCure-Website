(function() {
    'use strict';

    const SCRIPT_URL = 'https://script.google.com/macros/s/AKfycbyBjf9TKEogrSWp5cLxs4tZWuGbIdWUYGn5oDGIBVWvVQWggNDjxZzgugrgo0s8LZ4stg/exec';

    // Mobile menu toggle
    const menuToggle = document.getElementById('menuToggle');
    const navLinks = document.getElementById('navLinks');

    if (menuToggle && navLinks) {
        menuToggle.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            const spans = menuToggle.querySelectorAll('span');

            if (navLinks.classList.contains('active')) {
                spans[0].style.transform = 'rotate(45deg) translateY(8px)';
                spans[1].style.opacity = '0';
                spans[2].style.transform = 'rotate(-45deg) translateY(-8px)';
            } else {
                spans[0].style.transform = '';
                spans[1].style.opacity = '1';
                spans[2].style.transform = '';
            }
        });

        document.querySelectorAll('.nav-links a').forEach(link => {
            link.addEventListener('click', () => {
                navLinks.classList.remove('active');
                const spans = menuToggle.querySelectorAll('span');
                spans[0].style.transform = '';
                spans[1].style.opacity = '1';
                spans[2].style.transform = '';
            });
        });
    }

    // Header scroll effect
    const header = document.getElementById('header');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }
    });

    // Load all testimonials (no 5-star filter, no limit)
    function loadAllTestimonials() {
        console.log('[DEBUG] loadAllTestimonials() called');
        const testimonialGrid = document.getElementById('testimonialGrid');
        if (!testimonialGrid) {
            console.error('[DEBUG] testimonialGrid element not found!');
            return;
        }
        console.log('[DEBUG] testimonialGrid found');

        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            console.error('[DEBUG] Request timed out after 8 seconds');
            controller.abort();
        }, 8000);

        const fetchUrl = SCRIPT_URL + '?action=getTestimonials';
        console.log('[DEBUG] Fetching from:', fetchUrl);

        // Fetch ALL approved testimonials (no fiveStarOnly, no limit)
        fetch(fetchUrl, { signal: controller.signal })
            .then(response => {
                console.log('[DEBUG] Response received');
                console.log('[DEBUG] Response status:', response.status);
                console.log('[DEBUG] Response ok:', response.ok);
                console.log('[DEBUG] Response headers:', [...response.headers.entries()]);
                return response.text();
            })
            .then(text => {
                console.log('[DEBUG] Raw response text:', text.substring(0, 500));
                try {
                    return JSON.parse(text);
                } catch (e) {
                    console.error('[DEBUG] JSON parse error:', e);
                    console.error('[DEBUG] Full response text:', text);
                    throw new Error('Invalid JSON response');
                }
            })
            .then(data => {
                clearTimeout(timeoutId);
                console.log('[DEBUG] Parsed data:', data);
                console.log('[DEBUG] data.success:', data.success);
                console.log('[DEBUG] data.testimonials:', data.testimonials);
                console.log('[DEBUG] testimonials count:', data.testimonials ? data.testimonials.length : 0);

                if (data.success && data.testimonials && data.testimonials.length > 0) {
                    console.log('[DEBUG] Rendering', data.testimonials.length, 'testimonials');
                    renderTestimonials(data.testimonials);
                } else {
                    console.log('[DEBUG] No testimonials found, showing coming soon');
                    console.log('[DEBUG] data.error:', data.error);
                    renderComingSoon();
                }
            })
            .catch(error => {
                clearTimeout(timeoutId);
                console.error('[DEBUG] Fetch error:', error);
                console.error('[DEBUG] Error name:', error.name);
                console.error('[DEBUG] Error message:', error.message);
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

        // Animate cards in
        testimonialGrid.querySelectorAll('.testimonial-card').forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            card.style.transition = `all 0.4s ease ${index * 0.1}s`;
            setTimeout(() => {
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, 50);
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

    // Initialize
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadAllTestimonials);
    } else {
        loadAllTestimonials();
    }
})();
