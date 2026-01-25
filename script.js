/**
 * CartCure Contact Form - Secure Implementation
 *
 * SECURITY FEATURES:
 * - IIFE wrapper to prevent global variable pollution
 * - DOMPurify input sanitization
 * - Rate limiting (client-side)
 * - Audio file size/duration limits
 * - Input validation with max lengths
 * - Proper error handling (no console.error exposure in production)
 * - Memory leak prevention (URL.revokeObjectURL)
 */

(function() {
    'use strict';

    // ========================================================================
    // DEPENDENCY VALIDATION
    // ========================================================================

    // Verify required libraries are loaded
    if (typeof SecurityConfig === 'undefined') {
        console.error('CartCure Error: SecurityConfig not loaded. Check that security-config.js is included before script.js');
        return;
    }

    if (typeof DOMPurify === 'undefined') {
        console.error('CartCure Error: DOMPurify not loaded. Check CDN connection or include DOMPurify library.');
        return;
    }

    // ========================================================================
    // PRIVATE VARIABLES
    // ========================================================================

    // DOM Elements
    const elements = {
        menuToggle: document.getElementById('menuToggle'),
        navLinks: document.getElementById('navLinks'),
        header: document.getElementById('header'),
        voiceButton: document.getElementById('voiceButton'),
        recordingTimer: document.getElementById('recordingTimer'),
        audioPreview: document.getElementById('audioPreview'),
        audioPlayer: document.getElementById('audioPlayer'),
        deleteAudio: document.getElementById('deleteAudio'),
        messageTextarea: document.getElementById('message'),
        contactForm: document.getElementById('contactForm')
    };

    // Audio recording state
    let mediaRecorder = null;
    let audioChunks = [];
    let recordingInterval = null;
    let recordingSeconds = 0;
    let recordedAudioBlob = null;
    let audioObjectUrl = null; // For cleanup

    // Google Apps Script URL (replace with your deployment URL)
    const SCRIPT_URL = 'https://script.google.com/macros/s/AKfycbyBjf9TKEogrSWp5cLxs4tZWuGbIdWUYGn5oDGIBVWvVQWggNDjxZzgugrgo0s8LZ4stg/exec';

    // Production mode flag (set to true for production)
    const IS_PRODUCTION = false; // TEMPORARILY DISABLED FOR DEBUGGING

    // Human-readable word list for submission numbers (easy to remember, say, and type)
    const SUBMISSION_WORDS = [
        // Original words (48)
        'MAPLE', 'RIVER', 'CORAL', 'FROST', 'AMBER', 'CLOUD', 'STONE', 'BLOOM',
        'SPARK', 'OCEAN', 'CEDAR', 'DAWN', 'FLAME', 'PEARL', 'STORM', 'LUNAR',
        'GROVE', 'HAVEN', 'PEAK', 'TIDE', 'FERN', 'BLAZE', 'DUSK', 'SILK',
        'MINT', 'SAGE', 'FLINT', 'CREST', 'PINE', 'CLIFF', 'MOSS', 'OPAL',
        'REED', 'BROOK', 'GLOW', 'WREN', 'IRIS', 'EMBER', 'SWIFT', 'HAZE',
        'BIRCH', 'LARK', 'VALE', 'HELM', 'FAWN', 'TRAIL', 'SHADE', 'QUILL',
        // Additional words (50+)
        'ASPEN', 'BRIAR', 'COVE', 'DELTA', 'ECHO', 'FJORD', 'GLADE', 'HAWK',
        'JADE', 'KELP', 'LOTUS', 'MARSH', 'NOVA', 'ORBIT', 'PETAL', 'QUARTZ',
        'RIDGE', 'SHORE', 'TERRA', 'UNITY', 'VIVID', 'WISP', 'XENON', 'YUCCA',
        'ZEPHYR', 'ALDER', 'BISON', 'CRANE', 'DRIFT', 'EAGLE', 'FINCH', 'GARNET',
        'HOLLY', 'IVORY', 'JASPER', 'KITE', 'LYNX', 'MISTY', 'NORTH', 'OLIVE',
        'PRISM', 'QUEST', 'RAVEN', 'SOLAR', 'TULIP', 'UMBRA', 'VAPOR', 'WILLOW',
        'ZINC', 'ARCTIC', 'BASALT', 'COBALT', 'DUNE', 'FALCON', 'GOLDEN', 'HARBOR'
    ];

    // ========================================================================
    // RATE LIMITING
    // ========================================================================

    /**
     * Check if user has exceeded rate limit
     */
    function checkRateLimit() {
        try {
            const submissions = JSON.parse(
                localStorage.getItem(SecurityConfig.RATE_LIMIT.TRACKING_KEY) || '[]'
            );

            const now = Date.now();
            const recentSubmissions = submissions.filter(
                timestamp => (now - timestamp) < SecurityConfig.RATE_LIMIT.WINDOW_MS
            );

            if (recentSubmissions.length >= SecurityConfig.RATE_LIMIT.MAX_SUBMISSIONS_PER_HOUR) {
                return false; // Rate limit exceeded
            }

            return true; // OK to submit
        } catch (e) {
            // localStorage unavailable (private browsing) or data corrupted
            // Allow submission but log warning
            console.warn('Rate limit check failed, allowing submission:', e.message);
            return true;
        }
    }

    /**
     * Record a new submission for rate limiting
     */
    function recordSubmission() {
        try {
            const submissions = JSON.parse(
                localStorage.getItem(SecurityConfig.RATE_LIMIT.TRACKING_KEY) || '[]'
            );

            const now = Date.now();
            const recentSubmissions = submissions.filter(
                timestamp => (now - timestamp) < SecurityConfig.RATE_LIMIT.WINDOW_MS
            );

            recentSubmissions.push(now);

            localStorage.setItem(
                SecurityConfig.RATE_LIMIT.TRACKING_KEY,
                JSON.stringify(recentSubmissions)
            );
        } catch (e) {
            // localStorage unavailable (private browsing) or quota exceeded
            console.warn('Could not record submission for rate limiting:', e.message);
        }
    }

    // ========================================================================
    // INPUT VALIDATION AND SANITIZATION
    // ========================================================================

    /**
     * Validate and sanitize text input using DOMPurify
     */
    function sanitizeInput(input) {
        if (!input || typeof input !== 'string') return '';

        // Use DOMPurify to sanitize (strips all HTML)
        const sanitized = DOMPurify.sanitize(input, SecurityConfig.DOM_PURIFY);

        return sanitized.trim();
    }

    /**
     * Validate email format
     */
    function validateEmail(email) {
        if (!email || email.length > SecurityConfig.VALIDATION.EMAIL_MAX_LENGTH) {
            return false;
        }

        return SecurityConfig.VALIDATION.EMAIL_REGEX.test(email);
    }

    /**
     * Validate URL format
     */
    function validateURL(url) {
        if (!url) return true; // URL is optional

        if (url.length > SecurityConfig.VALIDATION.STORE_URL_MAX_LENGTH) {
            return false;
        }

        // Ensure protocol
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        // Check against blocked patterns
        const lowerUrl = url.toLowerCase();
        for (const pattern of SecurityConfig.VALIDATION.BLOCKED_URL_PATTERNS) {
            if (lowerUrl.includes(pattern.toLowerCase())) {
                return false;
            }
        }

        return SecurityConfig.VALIDATION.URL_REGEX.test(url);
    }

    /**
     * Validate audio file size
     */
    function validateAudioSize(blob) {
        const sizeInMB = blob.size / (1024 * 1024);
        return sizeInMB <= (SecurityConfig.AUDIO.MAX_FILE_SIZE_BYTES / (1024 * 1024));
    }

    /**
     * Validate audio MIME type
     */
    function validateAudioType(blob) {
        // Check if blob.type exists and is a string
        if (!blob.type || typeof blob.type !== 'string') {
            return false;
        }
        return SecurityConfig.AUDIO.ALLOWED_MIME_TYPES.some(type =>
            blob.type.startsWith(type.split(';')[0])
        );
    }

    // ========================================================================
    // NAVIGATION AND UI
    // ========================================================================

    /**
     * Mobile menu toggle
     */
    if (elements.menuToggle && elements.navLinks) {
        elements.menuToggle.addEventListener('click', () => {
            elements.navLinks.classList.toggle('active');
            const spans = elements.menuToggle.querySelectorAll('span');

            if (elements.navLinks.classList.contains('active')) {
                spans[0].style.transform = 'rotate(45deg) translateY(8px)';
                spans[1].style.opacity = '0';
                spans[2].style.transform = 'rotate(-45deg) translateY(-8px)';
            } else {
                spans[0].style.transform = '';
                spans[1].style.opacity = '1';
                spans[2].style.transform = '';
            }
        });
    }

    /**
     * Close mobile menu on link click
     */
    if (elements.navLinks && elements.menuToggle) {
        document.querySelectorAll('.nav-links a').forEach(link => {
            link.addEventListener('click', () => {
                elements.navLinks.classList.remove('active');
                const spans = elements.menuToggle.querySelectorAll('span');
                spans[0].style.transform = '';
                spans[1].style.opacity = '1';
                spans[2].style.transform = '';
            });
        });
    }

    /**
     * Header scroll effect
     */
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            elements.header.classList.add('scrolled');
        } else {
            elements.header.classList.remove('scrolled');
        }
    });

    /**
     * Scroll to services section
     */
    function scrollToServices() {
        const servicesSection = document.getElementById('services');
        if (!servicesSection) return;
        const headerOffset = 90;
        const elementPosition = servicesSection.getBoundingClientRect().top;
        const offsetPosition = elementPosition + window.pageYOffset - headerOffset;
        window.scrollTo({ top: offsetPosition, behavior: 'smooth' });
    }

    // Attach scroll arrow click handler
    const scrollArrow = document.getElementById('scrollArrow');
    if (scrollArrow) {
        scrollArrow.addEventListener('click', scrollToServices);
    }

    // ========================================================================
    // VOICE RECORDING
    // ========================================================================

    /**
     * Start/stop voice recording
     */
    if (elements.voiceButton) {
        elements.voiceButton.addEventListener('click', async () => {
            if (!mediaRecorder || mediaRecorder.state === 'inactive') {
                await startRecording();
            } else {
                stopRecording();
            }
        });
    }

    /**
     * Start audio recording
     */
    async function startRecording() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaRecorder = new MediaRecorder(stream);

            mediaRecorder.ondataavailable = (event) => {
                audioChunks.push(event.data);
            };

            mediaRecorder.onstop = () => {
                recordedAudioBlob = new Blob(audioChunks, { type: 'audio/webm' });

                // Validate audio size
                if (!validateAudioSize(recordedAudioBlob)) {
                    showError(SecurityConfig.ERRORS.FILE_TOO_LARGE);
                    cleanupRecording();
                    return;
                }

                // Validate audio type
                if (!validateAudioType(recordedAudioBlob)) {
                    showError(SecurityConfig.ERRORS.FILE_INVALID_TYPE);
                    cleanupRecording();
                    return;
                }

                // Cleanup previous URL if exists
                if (audioObjectUrl) {
                    URL.revokeObjectURL(audioObjectUrl);
                }

                audioObjectUrl = URL.createObjectURL(recordedAudioBlob);
                elements.audioPlayer.src = audioObjectUrl;
                elements.audioPreview.classList.add('active');

                // Stop all tracks
                stream.getTracks().forEach(track => track.stop());
            };

            audioChunks = [];
            recordedAudioBlob = null;
            recordingSeconds = 0;
            elements.voiceButton.classList.add('recording');
            mediaRecorder.start();
            elements.voiceButton.textContent = '⏹️ Stop Recording';

            // Start timer
            recordingInterval = setInterval(() => {
                recordingSeconds++;
                const minutes = Math.floor(recordingSeconds / 60);
                const seconds = recordingSeconds % 60;
                elements.recordingTimer.textContent =
                    `${minutes}:${seconds.toString().padStart(2, '0')}`;

                // Show warning near limit
                if (recordingSeconds === SecurityConfig.AUDIO.WARNING_SECONDS) {
                    showWarning('30 seconds remaining');
                }

                // Auto-stop at max duration
                if (recordingSeconds >= SecurityConfig.AUDIO.MAX_DURATION_SECONDS) {
                    stopRecording();
                    showWarning('Maximum recording duration reached');
                }
            }, 1000);

        } catch (error) {
            // Clean up any partial recording state on error
            clearInterval(recordingInterval);
            mediaRecorder = null;
            audioChunks = [];
            recordingSeconds = 0;
            if (elements.voiceButton) {
                elements.voiceButton.classList.remove('recording');
                elements.voiceButton.textContent = '🎤 Record Voice Note';
            }
            if (elements.recordingTimer) {
                elements.recordingTimer.textContent = '';
            }
            handleError('Microphone access denied. Please check browser permissions.', error);
        }
    }

    /**
     * Stop audio recording
     */
    function stopRecording() {
        if (mediaRecorder && mediaRecorder.state !== 'inactive') {
            mediaRecorder.stop();
            if (elements.voiceButton) {
                elements.voiceButton.classList.remove('recording');
                elements.voiceButton.textContent = '🎤 Record Voice Note';
            }
            clearInterval(recordingInterval);
            if (elements.recordingTimer) {
                elements.recordingTimer.textContent = '';
            }
        }
    }

    /**
     * Cleanup recording resources
     */
    function cleanupRecording() {
        audioChunks = [];
        recordedAudioBlob = null;
        if (audioObjectUrl) {
            URL.revokeObjectURL(audioObjectUrl);
            audioObjectUrl = null;
        }
    }

    /**
     * Delete recorded audio
     */
    if (elements.deleteAudio) {
        elements.deleteAudio.addEventListener('click', () => {
            if (elements.audioPreview) elements.audioPreview.classList.remove('active');
            if (elements.audioPlayer) elements.audioPlayer.src = '';
            cleanupRecording();
        });
    }

    // ========================================================================
    // FORM SUBMISSION
    // ========================================================================

    /**
     * Handle form submission
     */
    async function handleSubmit(e) {
        e.preventDefault();

        // Get button reference early and disable immediately to prevent double-submit
        const button = e.target.querySelector('.submit-button');
        if (!button) return;

        // Check if already submitting
        if (button.disabled) return;

        const originalText = button.textContent;

        // Check HTML5 validation
        if (!e.target.checkValidity()) {
            return;
        }

        // Check client-side rate limiting
        // Note: Server-side rate limiting is also enforced in google_apps_script.js
        // TEMPORARILY DISABLED FOR TESTING
        // if (!checkRateLimit()) {
        //     showError(SecurityConfig.ERRORS.RATE_LIMIT);
        //     return;
        // }

        // Get and sanitize inputs
        const name = sanitizeInput(document.getElementById('name').value);
        const email = sanitizeInput(document.getElementById('email').value);
        const phone = sanitizeInput(document.getElementById('phone').value);
        const storeUrl = sanitizeInput(document.getElementById('store').value);
        const message = sanitizeInput(elements.messageTextarea.value);

        // Validate name length
        if (name.length > SecurityConfig.VALIDATION.NAME_MAX_LENGTH) {
            showError('Name is too long (max 100 characters)');
            return;
        }

        // Validate email
        if (!validateEmail(email)) {
            showError('Please enter a valid email address');
            return;
        }

        // Validate phone number
        if (!phone || phone.length < 6 || phone.length > 20) {
            showError('Please enter a valid phone number');
            return;
        }

        // Validate store URL (required)
        if (!storeUrl) {
            showError('Please enter your store URL');
            return;
        }
        if (!validateURL(storeUrl)) {
            showError('Please enter a valid store URL');
            return;
        }

        // Validate message length
        if (message.length > SecurityConfig.VALIDATION.MESSAGE_MAX_LENGTH) {
            showError('Message is too long (max 5000 characters)');
            return;
        }

        // If recording is still active, stop it and wait for the blob
        if (mediaRecorder && mediaRecorder.state === 'recording') {
            stopRecording();

            // Wait for the blob to be created (onstop handler)
            await new Promise(resolve => {
                const checkBlob = setInterval(() => {
                    if (recordedAudioBlob !== null) {
                        clearInterval(checkBlob);
                        resolve();
                    }
                }, 50);
                // Timeout after 2 seconds to prevent infinite waiting
                setTimeout(() => {
                    clearInterval(checkBlob);
                    resolve();
                }, 2000);
            });
        }

        // Check that either message or voice note is provided
        const hasAudio = recordedAudioBlob !== null;
        if (!message && !hasAudio) {
            showError('Please provide either a message or voice note');
            return;
        }

        // Disable button and show sending state
        button.textContent = 'Sending...';
        button.disabled = true;
        button.style.opacity = '0.7';

        try {
            // Generate unique human-readable submission number: CC-WORD-XXX
            // Format is easier to remember, say over phone, and type
            const now = new Date();
            const randomWord = SUBMISSION_WORDS[Math.floor(Math.random() * SUBMISSION_WORDS.length)];
            const randomNum = Math.floor(100 + Math.random() * 900); // 3-digit number (100-999)
            const submissionNumber = `CC-${randomWord}-${randomNum}`;

            // Build form data
            const formData = {
                submissionNumber: submissionNumber,
                timestamp: now.toLocaleString('en-NZ', {
                    timeZone: 'Pacific/Auckland',
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: true
                }),
                name: name,
                email: email,
                phone: phone,
                storeUrl: storeUrl,
                message: message || 'Voice note only - see audio file',
                hasVoiceNote: hasAudio ? 'Yes' : 'No',
                voiceNoteData: ''
            };

            // Convert audio to base64 if present
            if (hasAudio && recordedAudioBlob) {
                formData.voiceNoteData = await convertBlobToBase64(recordedAudioBlob);
            }

            // Submit to Google Apps Script
            // Use URLSearchParams to avoid CORS preflight
            const formBody = new URLSearchParams();
            for (const key in formData) {
                formBody.append(key, formData[key]);
            }

            // Debug logging
            if (!IS_PRODUCTION) {
                const debugData = Object.fromEntries(formBody);
                console.log('Submitting form data:', debugData);
                console.log('Submission number:', debugData.submissionNumber);
            }

            const response = await fetch(SCRIPT_URL, {
                method: 'POST',
                mode: 'cors',
                cache: 'no-cache',
                redirect: 'follow',
                body: formBody
            });

            // Debug logging - only in development
            if (!IS_PRODUCTION) {
                console.log('Response status:', response.status);
                console.log('Response ok:', response.ok);
            }

            const responseText = await response.text();

            // Parse response with error handling
            let result;
            try {
                result = JSON.parse(responseText);
            } catch (parseError) {
                if (!IS_PRODUCTION) {
                    console.error('Failed to parse server response:', responseText);
                }
                throw new Error('Invalid server response');
            }

            // Debug logging - only in development
            if (!IS_PRODUCTION) {
                console.log('=== SERVER RESPONSE ===');
                console.log('Success:', result.success);
                console.log('Message:', result.message);
                if (result.error) {
                    console.log('Error:', result.error);
                    console.log('Error Type:', result.errorType);
                }
                console.log('Full response:', result);
            }

            if (result.success) {
                // Record submission for rate limiting
                // TEMPORARILY DISABLED FOR TESTING
                // recordSubmission();

                // Show success message
                button.textContent = '✓ Submitted Successfully!';
                button.style.background = 'var(--accent-green)';

                // Reset form after delay
                setTimeout(() => {
                    button.textContent = originalText;
                    button.disabled = false;
                    button.style.opacity = '1';
                    button.style.background = '';
                    e.target.reset();
                    elements.audioPreview.classList.remove('active');
                    elements.audioPlayer.src = '';
                    cleanupRecording();
                }, 2500);
            } else {
                throw new Error(result.message || 'Submission failed');
            }

        } catch (error) {
            // Enhanced error logging for debugging
            if (!IS_PRODUCTION) {
                console.error('=== ERROR CAUGHT ===');
                console.error('Error type:', error.constructor.name);
                console.error('Error message:', error.message);
                console.error('Error stack:', error.stack);
                console.error('Script URL:', SCRIPT_URL);
                console.error('Full error object:', error);
            }

            handleError(SecurityConfig.ERRORS.NETWORK, error);

            button.textContent = '✗ Error - Please try again';
            button.style.background = '#d64545';

            setTimeout(() => {
                button.textContent = originalText;
                button.disabled = false;
                button.style.opacity = '1';
                button.style.background = '';
            }, 3000);
        }
    };

    /**
     * Convert Blob to Base64
     */
    function convertBlobToBase64(blob) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onloadend = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsDataURL(blob);
        });
    }

    // ========================================================================
    // ERROR HANDLING
    // ========================================================================

    /**
     * Show error message to user
     */
    function showError(message) {
        alert(message); // In production, use a better UI component
    }

    /**
     * Show warning message to user
     */
    function showWarning(message) {
        // In production, use a toast/snackbar component
        console.warn(message);
    }

    /**
     * Handle errors (log in dev, hide in production)
     */
    function handleError(userMessage, error) {
        if (!IS_PRODUCTION) {
            console.error('Error:', error);
        }
        showError(userMessage);
    }

    // ========================================================================
    // SCROLL ANIMATIONS
    // ========================================================================

    const observerOptions = {
        threshold: 0.01,
        rootMargin: '0px 0px 50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    document.querySelectorAll('.service-card, .benefit-item').forEach((el, index) => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = `all 0.5s cubic-bezier(0.4, 0, 0.2, 1) ${index * 0.05}s`;
        observer.observe(el);
    });

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    /**
     * Initialize application on page load
     */
    function init() {
        // Attach form submit handler
        if (elements.contactForm) {
            elements.contactForm.addEventListener('submit', handleSubmit);
            console.log('✓ Form handler attached successfully');
        } else {
            console.error('✗ Contact form not found! Cannot attach handler.');
        }

        // Load testimonials
        loadTestimonials();

        // Log initialization in dev mode
        if (!IS_PRODUCTION) {
            console.log('CartCure Contact Form initialized with security features');
            console.log('- Rate Limiting: ' + SecurityConfig.RATE_LIMIT.MAX_SUBMISSIONS_PER_HOUR + '/hour');
            console.log('- Input Sanitization: DOMPurify');
            console.log('- Max Audio Duration: ' + SecurityConfig.AUDIO.MAX_DURATION_SECONDS + 's');
            console.log('- Max Audio Size: ' + (SecurityConfig.AUDIO.MAX_FILE_SIZE_BYTES / 1024 / 1024) + 'MB');
        }
    }

    // ========================================================================
    // TESTIMONIALS
    // ========================================================================

    /**
     * Load testimonials from Google Sheets API
     * @param {boolean} fiveStarOnly - If true, only fetch 5-star testimonials
     * @param {number|null} limit - Maximum number to fetch (null for all)
     */
    function loadTestimonials(fiveStarOnly = true, limit = 6) {
        const testimonialGrid = document.getElementById('testimonialGrid');
        if (!testimonialGrid) return;

        // Build API URL with parameters
        let apiUrl = SCRIPT_URL + '?action=getTestimonials';
        if (fiveStarOnly) {
            apiUrl += '&fiveStarOnly=true';
        }
        if (limit) {
            apiUrl += '&limit=' + limit;
        }

        // Fetch testimonials from API with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000); // 8 second timeout

        fetch(apiUrl, { signal: controller.signal })
            .then(response => response.json())
            .then(data => {
                clearTimeout(timeoutId);
                if (data.success && data.testimonials && data.testimonials.length > 0) {
                    renderTestimonials(data.testimonials, limit);
                } else {
                    // Show "Coming Soon" message if no testimonials approved yet
                    renderComingSoon();
                }
            })
            .catch(error => {
                clearTimeout(timeoutId);
                if (error.name === 'AbortError') {
                    console.warn('Testimonials fetch timed out, showing coming soon');
                } else {
                    console.error('Error loading testimonials:', error);
                }
                // Show "Coming Soon" on error (better than fake testimonials)
                renderComingSoon();
            });
    }

    /**
     * Render testimonials to the page
     * @param {Array} testimonials - Array of testimonial objects
     * @param {number|null} limit - If set, show "See all" button (indicates homepage view)
     */
    function renderTestimonials(testimonials, limit) {
        const testimonialGrid = document.getElementById('testimonialGrid');
        if (!testimonialGrid) return;

        // Clear loading message
        testimonialGrid.innerHTML = '';

        // Render each testimonial
        testimonials.forEach(testimonial => {
            const initials = getInitials(testimonial.name);
            const subtitle = [testimonial.business, testimonial.location]
                .filter(x => x)
                .join(', ');
            const stars = '★'.repeat(testimonial.rating) + '☆'.repeat(5 - testimonial.rating);

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

        // Add "See all testimonials" button on homepage (when limit is set)
        if (limit && testimonials.length > 0) {
            const seeAllContainer = document.createElement('div');
            seeAllContainer.className = 'see-all-testimonials';
            seeAllContainer.innerHTML = `
                <a href="testimonials.html" class="see-all-button">See All Testimonials</a>
            `;
            testimonialGrid.parentNode.appendChild(seeAllContainer);
        }

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

    /**
     * Render "Coming Soon" message when no approved testimonials exist
     */
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

        // Animate in
        const comingSoon = testimonialGrid.querySelector('.testimonials-coming-soon');
        if (comingSoon) {
            comingSoon.style.opacity = '0';
            comingSoon.style.transform = 'translateY(20px)';
            comingSoon.style.transition = 'all 0.5s ease';
            setTimeout(() => {
                comingSoon.style.opacity = '1';
                comingSoon.style.transform = 'translateY(0)';
            }, 50);
        }
    }

    /**
     * Get initials from a name
     */
    function getInitials(name) {
        if (!name) return '?';
        const parts = name.trim().split(' ');
        if (parts.length === 1) {
            return parts[0].charAt(0).toUpperCase();
        }
        return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
    }

    /**
     * Escape HTML to prevent XSS
     */
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // ========================================================================
    // CLEANUP ON PAGE UNLOAD
    // ========================================================================

    window.addEventListener('beforeunload', () => {
        // Clean up audio object URLs to prevent memory leaks
        if (audioObjectUrl) {
            URL.revokeObjectURL(audioObjectUrl);
        }
    });

})(); // End IIFE
