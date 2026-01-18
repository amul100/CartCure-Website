/**
 * Security Configuration for CartCure Website
 *
 * This file contains all security-related constants and configurations.
 * DO NOT modify these values unless you understand the security implications.
 */

const SecurityConfig = {
    // Rate Limiting Configuration
    RATE_LIMIT: {
        MAX_SUBMISSIONS_PER_HOUR: 5,
        TRACKING_KEY: 'cartcure_submissions',
        WINDOW_MS: 3600000, // 1 hour in milliseconds
        LOCKOUT_MESSAGE: 'Too many submissions. Please try again in 1 hour.'
    },

    // Audio File Configuration
    AUDIO: {
        MAX_DURATION_SECONDS: 180,      // 3 minutes maximum
        MAX_FILE_SIZE_BYTES: 10485760,  // 10 MB in bytes
        ALLOWED_MIME_TYPES: [
            'audio/webm',
            'audio/webm;codecs=opus',
            'audio/ogg',
            'audio/ogg;codecs=opus',
            'audio/mp4',
            'audio/mpeg'
        ],
        WARNING_SECONDS: 150 // Show warning at 2:30
    },

    // Input Validation Configuration
    VALIDATION: {
        NAME_MAX_LENGTH: 100,
        EMAIL_MAX_LENGTH: 254,
        STORE_URL_MAX_LENGTH: 2048,
        MESSAGE_MAX_LENGTH: 5000,

        // Email regex (RFC 5322 simplified)
        EMAIL_REGEX: /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,

        // Strict URL validation (HTTP/HTTPS only, no javascript:, data:, file: protocols)
        URL_REGEX: /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$/,

        // Allowed URL protocols
        ALLOWED_PROTOCOLS: ['http:', 'https:'],

        // Blocked URL patterns
        BLOCKED_URL_PATTERNS: [
            'javascript:',
            'data:',
            'file:',
            'vbscript:',
            'about:',
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '::1',
            '192.168.',
            '10.0.',
            '172.16.'
        ],

        // Whitelist of allowed TLDs
        ALLOWED_TLDS: [
            'com', 'co.nz', 'nz', 'org', 'net', 'io', 'co', 'uk',
            'au', 'ca', 'us', 'de', 'fr', 'jp', 'cn', 'in', 'br'
        ]
    },

    // DOMPurify Configuration
    DOM_PURIFY: {
        ALLOWED_TAGS: [],  // No HTML tags allowed - strip all
        ALLOWED_ATTR: [],  // No attributes allowed
        KEEP_CONTENT: true,
        RETURN_DOM: false,
        RETURN_DOM_FRAGMENT: false,
        RETURN_DOM_IMPORT: false,
        SANITIZE_DOM: true,
        IN_PLACE: false
    },

    // Content Security Policy
    CSP: {
        DIRECTIVES: {
            'default-src': ["'self'"],
            'script-src': [
                "'self'",
                'https://cdn.jsdelivr.net',           // DOMPurify CDN
                'https://www.google.com',             // reCAPTCHA (future)
                'https://www.gstatic.com'             // reCAPTCHA (future)
            ],
            'style-src': ["'self'", "'unsafe-inline'"], // Allow inline styles for paperlike theme
            'img-src': ["'self'", 'data:'],
            'font-src': ["'self'"],
            'connect-src': [
                "'self'",
                'https://script.google.com',          // Google Apps Script endpoint
                'https://script.googleusercontent.com' // Google Apps Script redirect target
            ],
            'media-src': ["'self'", 'blob:'],         // Allow blob URLs for audio recording
            'object-src': ["'none'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"],
            'frame-ancestors': ["'none'"],
            'upgrade-insecure-requests': []
        }
    },

    // Error Messages (user-friendly, no technical details)
    ERRORS: {
        GENERIC: 'An error occurred. Please try again.',
        NETWORK: 'Network error. Please check your connection and try again.',
        VALIDATION: 'Please check your input and try again.',
        FILE_TOO_LARGE: 'Audio file is too large. Maximum size is 10MB.',
        FILE_INVALID_TYPE: 'Invalid audio format. Please try recording again.',
        RECORDING_TOO_LONG: 'Recording is too long. Maximum duration is 3 minutes.',
        RATE_LIMIT: 'Too many submissions. Please try again later.',
        CSRF_INVALID: 'Security validation failed. Please refresh the page and try again.',
        CONSENT_REQUIRED: 'Please accept the privacy policy to record voice notes.'
    },

    // Success Messages
    SUCCESS: {
        FORM_SUBMITTED: 'Thank you! We\'ll get back to you ASAP.',
        AUDIO_RECORDED: 'Voice note recorded successfully'
    }
};

// Freeze the configuration to prevent modifications
Object.freeze(SecurityConfig);
Object.freeze(SecurityConfig.RATE_LIMIT);
Object.freeze(SecurityConfig.AUDIO);
Object.freeze(SecurityConfig.VALIDATION);
Object.freeze(SecurityConfig.DOM_PURIFY);
Object.freeze(SecurityConfig.CSP);
Object.freeze(SecurityConfig.ERRORS);
Object.freeze(SecurityConfig.SUCCESS);

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityConfig;
}
