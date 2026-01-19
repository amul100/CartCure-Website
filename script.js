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
    const IS_PRODUCTION = true;

    // ========================================================================
    // RATE LIMITING
    // ========================================================================

    /**
     * Check if user has exceeded rate limit
     */
    function checkRateLimit() {
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
    }

    /**
     * Record a new submission for rate limiting
     */
    function recordSubmission() {
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

    /**
     * Close mobile menu on link click
     */
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', () => {
            elements.navLinks.classList.remove('active');
            const spans = elements.menuToggle.querySelectorAll('span');
            spans[0].style.transform = '';
            spans[1].style.opacity = '1';
            spans[2].style.transform = '';
        });
    });

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
    elements.voiceButton.addEventListener('click', async () => {
        if (!mediaRecorder || mediaRecorder.state === 'inactive') {
            await startRecording();
        } else {
            stopRecording();
        }
    });

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
            handleError('Microphone access denied. Please check browser permissions.', error);
        }
    }

    /**
     * Stop audio recording
     */
    function stopRecording() {
        if (mediaRecorder && mediaRecorder.state !== 'inactive') {
            mediaRecorder.stop();
            elements.voiceButton.classList.remove('recording');
            elements.voiceButton.textContent = '🎤 Record Voice Note';
            clearInterval(recordingInterval);
            elements.recordingTimer.textContent = '';
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
    elements.deleteAudio.addEventListener('click', () => {
        elements.audioPreview.classList.remove('active');
        elements.audioPlayer.src = '';
        cleanupRecording();
    });

    // ========================================================================
    // FORM SUBMISSION
    // ========================================================================

    /**
     * Handle form submission
     */
    async function handleSubmit(e) {
        e.preventDefault();

        // Check HTML5 validation
        if (!e.target.checkValidity()) {
            return;
        }

        // Check rate limiting (bypass for admin emails)
        const emailValue = document.getElementById('email').value.trim().toLowerCase();
        const adminEmails = ['andrew.lee.muller@gmail.com', 'amanda.balsillie@gmail.com'];
        const isAdmin = adminEmails.includes(emailValue);

        console.log('Rate limit check - Email:', emailValue, 'Is Admin:', isAdmin);

        if (!isAdmin && !checkRateLimit()) {
            showError(SecurityConfig.ERRORS.RATE_LIMIT);
            return;
        }

        // Clear rate limit history for admins (allows unlimited testing)
        if (isAdmin) {
            localStorage.removeItem(SecurityConfig.RATE_LIMIT.TRACKING_KEY);
            console.log('Admin detected - rate limit cleared');
        }

        // Get and sanitize inputs
        const name = sanitizeInput(document.getElementById('name').value);
        const email = sanitizeInput(document.getElementById('email').value);
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

        // Validate store URL if provided
        if (storeUrl && !validateURL(storeUrl)) {
            showError('Please enter a valid store URL');
            return;
        }

        // Validate message length
        if (message.length > SecurityConfig.VALIDATION.MESSAGE_MAX_LENGTH) {
            showError('Message is too long (max 5000 characters)');
            return;
        }

        // Check that either message or voice note is provided
        const hasAudio = recordedAudioBlob !== null;
        if (!message && !hasAudio) {
            showError('Please provide either a message or voice note');
            return;
        }

        const button = e.target.querySelector('.submit-button');
        const originalText = button.textContent;

        button.textContent = 'Sending...';
        button.disabled = true;
        button.style.opacity = '0.7';

        try {
            // Generate unique submission number: CC-YYYYMMDD-XXXXX
            const now = new Date();
            const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '');
            const randomNum = Math.floor(10000 + Math.random() * 90000); // 5-digit random number
            const submissionNumber = `CC-${dateStr}-${randomNum}`;

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
                storeUrl: storeUrl || '',
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
                console.log('Submitting form data:', Object.fromEntries(formBody));
            }

            const response = await fetch(SCRIPT_URL, {
                method: 'POST',
                mode: 'cors',
                cache: 'no-cache',
                redirect: 'follow',
                body: formBody
            });

            console.log('Response status:', response.status);
            console.log('Response ok:', response.ok);
            console.log('Response headers:', response.headers);

            const responseText = await response.text();
            console.log('Response text:', responseText);

            const result = JSON.parse(responseText);

            // Debug logging - ALWAYS log the response
            console.log('=== SERVER RESPONSE ===');
            console.log('Success:', result.success);
            console.log('Message:', result.message);
            if (result.error) {
                console.log('Error:', result.error);
                console.log('Error Type:', result.errorType);
            }
            console.log('Full response:', result);

            if (result.success) {
                // Record submission for rate limiting
                recordSubmission();

                // Show success message with submission number
                button.textContent = '✓ Sent! Ref: ' + formData.submissionNumber;
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

        // Log initialization in dev mode
        if (!IS_PRODUCTION) {
            console.log('CartCure Contact Form initialized with security features');
            console.log('- Rate Limiting: ' + SecurityConfig.RATE_LIMIT.MAX_SUBMISSIONS_PER_HOUR + '/hour');
            console.log('- Input Sanitization: DOMPurify');
            console.log('- Max Audio Duration: ' + SecurityConfig.AUDIO.MAX_DURATION_SECONDS + 's');
            console.log('- Max Audio Size: ' + (SecurityConfig.AUDIO.MAX_FILE_SIZE_BYTES / 1024 / 1024) + 'MB');
        }
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
