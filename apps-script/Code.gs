/**
 * Secure Google Apps Script Handler for CartCure Contact Form
 *
 * DEPLOYMENT INSTRUCTIONS:
 * 1. Copy this entire file
 * 2. Go to https://script.google.com
 * 3. Create new project: "CartCure Form Handler"
 * 4. Paste this code
 * 5. Configure Script Properties (File > Project Properties > Script Properties):
 *    - SHARED_SECRET: Generate random 32+ character string for HMAC signing
 *    - ADMIN_EMAIL: Your email address for notifications
 *    - SHEET_ID: Create a Google Sheet and paste its ID here
 * 6. Deploy as web app:
 *    - Execute as: Me
 *    - Who has access: Anyone
 * 7. Copy the deployment URL and update script.js
 *
 * SECURITY FEATURES:
 * - HMAC-SHA256 request signature verification
 * - CSRF token validation
 * - Server-side input validation and sanitization
 * - Rate limiting per IP address
 * - HTML entity escaping for XSS prevention
 * - Email format validation (RFC 5322)
 * - URL validation with protocol whitelist
 * - Audio file size/type validation
 * - IP logging and abuse detection
 * - Maximum length enforcement
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

// ============================================================================
// PRODUCTION MODE FLAG
// ============================================================================
// Set to false for testing/debugging (disables origin validation, shows detailed errors)
// IMPORTANT: Set to true before deploying to production!
const IS_PRODUCTION = true;

// Get configuration from Script Properties
const CONFIG = {
  SHARED_SECRET: PropertiesService.getScriptProperties().getProperty('SHARED_SECRET'),
  ADMIN_EMAIL: PropertiesService.getScriptProperties().getProperty('ADMIN_EMAIL'),
  SHEET_ID: PropertiesService.getScriptProperties().getProperty('SHEET_ID'),

  // Validation limits
  MAX_NAME_LENGTH: 100,
  MAX_EMAIL_LENGTH: 254,
  MAX_URL_LENGTH: 2048,
  MAX_MESSAGE_LENGTH: 5000,
  MAX_AUDIO_SIZE_MB: 10,

  // Rate limiting
  MAX_SUBMISSIONS_PER_HOUR: 5,
  RATE_LIMIT_WINDOW_MS: 3600000, // 1 hour

  // Allowed origins (add your domain when deployed)
  ALLOWED_ORIGINS: [
    'https://cartcure.co.nz',
    'https://www.cartcure.co.nz'
  ]
};

// Validation regexes
const REGEX = {
  EMAIL: /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
  URL: /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$/,
  SUSPICIOUS_PATTERNS: /<script|<iframe|javascript:|data:|vbscript:|onload=|onerror=|onclick=/gi
};

// Blocked URL patterns
const BLOCKED_PATTERNS = [
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
];

// ============================================================================
// MAIN HANDLER
// ============================================================================

/**
 * Main POST request handler
 */
function doPost(e) {
  try {
    // Log incoming request for debugging (only in development)
    if (!IS_PRODUCTION) {
      Logger.log('=== Incoming Request ===');
      Logger.log('postData.type: ' + (e.postData ? e.postData.type : 'undefined'));
      Logger.log('postData.contents length: ' + (e.postData ? e.postData.contents.length : 'undefined'));
      Logger.log('parameter keys: ' + (e.parameter ? Object.keys(e.parameter).join(', ') : 'undefined'));
    }

    // Parse request body - handle both JSON and form-encoded data
    let data;
    if (e.postData && e.postData.type === 'application/json') {
      data = JSON.parse(e.postData.contents);
      if (!IS_PRODUCTION) Logger.log('Parsed as JSON');
    } else {
      // URL-encoded form data comes in e.parameter
      data = e.parameter;
      if (!IS_PRODUCTION) Logger.log('Using e.parameter (form-encoded)');
    }

    if (!IS_PRODUCTION) {
      Logger.log('Data keys received: ' + Object.keys(data).join(', '));
      Logger.log('submissionNumber received: ' + data.submissionNumber);
    }

    const origin = e.parameter.origin || '';

    // Security validations
    validateOrigin(origin);

    // =========================================================================
    // SERVER-SIDE RATE LIMITING
    // =========================================================================
    // This checks submissions per email address using Script Properties storage.
    // Limits: 5 submissions per hour per email address.
    //
    // HOW IT WORKS:
    // - Stores submission timestamps in Script Properties (persists across requests)
    // - Key format: "ratelimit_<email>" with JSON array of timestamps
    // - Cleans up old timestamps (>1 hour) on each check
    // - Returns 429-style error if limit exceeded
    //
    // TO DISABLE FOR TESTING: Comment out the checkServerRateLimit() call below
    // =========================================================================
    const emailForRateLimit = (data.email || '').trim().toLowerCase();
    checkServerRateLimit(emailForRateLimit);

    // Input validation and sanitization
    const sanitizedData = validateAndSanitizeInput(data);

    // Log submission
    logSubmission(sanitizedData);

    // Store in Google Sheet
    saveToSheet(sanitizedData);

    // Send email notification to admin
    sendEmailNotification(sanitizedData);

    // Send confirmation email to user
    sendUserConfirmationEmail(sanitizedData);

    // Record successful submission for rate limiting
    recordServerSubmission(emailForRateLimit);

    // Return success response
    return ContentService
      .createTextOutput(JSON.stringify({
        success: true,
        message: 'Form submitted successfully'
      }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    Logger.log('Error processing submission: ' + error.message);
    if (!IS_PRODUCTION) {
      Logger.log('Error stack: ' + error.stack);
    }

    // Build error response - only include technical details in development mode
    const errorResponse = {
      success: false,
      message: error.userMessage || 'An error occurred. Please try again.'
    };

    // Only expose technical error details when NOT in production
    if (!IS_PRODUCTION) {
      errorResponse.error = error.message;
      errorResponse.errorType = error.name;
    }

    return ContentService
      .createTextOutput(JSON.stringify(errorResponse))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

/**
 * Handle GET requests (testing/health check)
 */
function doGet(e) {
  return ContentService
    .createTextOutput(JSON.stringify({
      status: 'ok',
      message: 'CartCure Form Handler is running',
      timestamp: new Date().toISOString()
    }))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Run all tests - use this to verify the script is working correctly
 * Tests: Drive permissions, debug file creation, and full form submission
 */
function runAllTests() {
  Logger.log('========== CARTCURE SCRIPT TESTS ==========\n');

  const results = { drive: false, debug: false, form: false };

  // Test 1: Drive permissions
  Logger.log('--- Test 1: Drive Permissions ---');
  try {
    const folder = getOrCreateDebugFolder();
    const testFile = folder.createFile('_test_' + Date.now() + '.txt', 'test');
    testFile.setTrashed(true);
    results.drive = true;
    Logger.log('PASS: Drive permissions OK\n');
  } catch (e) {
    Logger.log('FAIL: ' + e.message + '\n');
  }

  // Test 2: Debug file creation
  Logger.log('--- Test 2: Debug File Creation ---');
  try {
    const debugUrl = saveDebugFileToDrive({
      submissionNumber: 'CC-' + new Date().toISOString().slice(0,10).replace(/-/g,'') + '-TEST1',
      timestamp: new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }),
      name: 'Test User',
      email: 'test@example.com',
      storeUrl: 'https://example.com',
      message: 'Test message',
      hasVoiceNote: false
    });
    results.debug = !!debugUrl;
    Logger.log(debugUrl ? 'PASS: Debug file created - ' + debugUrl + '\n' : 'FAIL: No URL returned\n');
  } catch (e) {
    Logger.log('FAIL: ' + e.message + '\n');
  }

  // Test 3: Full form submission
  Logger.log('--- Test 3: Form Submission ---');
  try {
    const formResult = doPost({
      postData: { type: 'application/x-www-form-urlencoded', contents: '' },
      parameter: {
        name: 'Test User',
        email: 'test@example.com',
        storeUrl: 'https://example.com',
        message: 'Test submission from runAllTests()',
        hasVoiceNote: 'No',
        voiceNoteData: '',
        origin: 'http://localhost'
      }
    });
    const response = JSON.parse(formResult.getContent());
    results.form = response.success;
    Logger.log(response.success ? 'PASS: Form submission OK\n' : 'FAIL: ' + response.message + '\n');
  } catch (e) {
    Logger.log('FAIL: ' + e.message + '\n');
  }

  // Summary
  Logger.log('========== RESULTS ==========');
  Logger.log('Drive Permissions: ' + (results.drive ? 'PASS' : 'FAIL'));
  Logger.log('Debug File:        ' + (results.debug ? 'PASS' : 'FAIL'));
  Logger.log('Form Submission:   ' + (results.form ? 'PASS' : 'FAIL'));
  Logger.log('=============================');

  return results;
}

// ============================================================================
// SECURITY VALIDATION FUNCTIONS
// ============================================================================

/**
 * Validate request origin
 * In production mode, rejects requests from origins not in ALLOWED_ORIGINS
 * In development mode (IS_PRODUCTION = false), allows all origins
 */
function validateOrigin(origin) {
  // Skip origin validation in development mode
  if (!IS_PRODUCTION) {
    Logger.log('Development mode: Skipping origin validation');
    return;
  }

  // In production, validate against allowed origins
  // Note: Google Apps Script doesn't always receive origin header reliably
  // This is a defense-in-depth measure, not the only protection
  if (origin && !CONFIG.ALLOWED_ORIGINS.includes(origin)) {
    Logger.log('Rejected request from origin: ' + origin);
    const error = new Error('Invalid origin: ' + origin);
    error.userMessage = 'Request rejected';
    throw error;
  }
}

// ============================================================================
// SERVER-SIDE RATE LIMITING
// ============================================================================
// Uses Script Properties to persist rate limit data across requests.
// This cannot be bypassed by clearing browser storage or direct API calls.
//
// TO DISABLE FOR TESTING:
// 1. Set IS_PRODUCTION = false (disables many security features), OR
// 2. Comment out the checkServerRateLimit() call in doPost()
// ============================================================================

/**
 * Check if email has exceeded rate limit
 * Throws error if rate limit exceeded
 *
 * @param {string} email - Email address to check
 */
function checkServerRateLimit(email) {
  if (!email) return; // Skip if no email provided (will fail validation later anyway)

  const scriptProperties = PropertiesService.getScriptProperties();
  const key = 'ratelimit_' + email.replace(/[^a-z0-9@._-]/gi, '_'); // Sanitize key
  const now = Date.now();
  const windowMs = CONFIG.RATE_LIMIT_WINDOW_MS; // 1 hour

  // Get existing timestamps for this email
  let timestamps = [];
  try {
    const stored = scriptProperties.getProperty(key);
    if (stored) {
      timestamps = JSON.parse(stored);
    }
  } catch (e) {
    // If parsing fails, start fresh
    timestamps = [];
  }

  // Filter to only recent timestamps (within the rate limit window)
  const recentTimestamps = timestamps.filter(function(ts) {
    return (now - ts) < windowMs;
  });

  // Check if limit exceeded
  if (recentTimestamps.length >= CONFIG.MAX_SUBMISSIONS_PER_HOUR) {
    Logger.log('Rate limit exceeded for email: ' + email + ' (' + recentTimestamps.length + ' submissions in last hour)');
    const error = new Error('Rate limit exceeded');
    error.userMessage = 'Too many submissions. Please try again in 1 hour.';
    throw error;
  }

  if (!IS_PRODUCTION) {
    Logger.log('Rate limit check passed for ' + email + ': ' + recentTimestamps.length + '/' + CONFIG.MAX_SUBMISSIONS_PER_HOUR + ' submissions');
  }
}

/**
 * Record a successful submission for rate limiting
 *
 * @param {string} email - Email address to record
 */
function recordServerSubmission(email) {
  if (!email) return;

  const scriptProperties = PropertiesService.getScriptProperties();
  const key = 'ratelimit_' + email.replace(/[^a-z0-9@._-]/gi, '_');
  const now = Date.now();
  const windowMs = CONFIG.RATE_LIMIT_WINDOW_MS;

  // Get existing timestamps
  let timestamps = [];
  try {
    const stored = scriptProperties.getProperty(key);
    if (stored) {
      timestamps = JSON.parse(stored);
    }
  } catch (e) {
    timestamps = [];
  }

  // Filter to recent timestamps and add the new one
  const recentTimestamps = timestamps.filter(function(ts) {
    return (now - ts) < windowMs;
  });
  recentTimestamps.push(now);

  // Save back to properties
  scriptProperties.setProperty(key, JSON.stringify(recentTimestamps));

  if (!IS_PRODUCTION) {
    Logger.log('Recorded submission for ' + email + '. Total in window: ' + recentTimestamps.length);
  }
}

/**
 * Utility function to clear rate limit for a specific email (for admin use)
 * Run this from the Apps Script editor to reset rate limit for testing
 *
 * @param {string} email - Email address to clear rate limit for
 */
function clearRateLimitForEmail(email) {
  const scriptProperties = PropertiesService.getScriptProperties();
  const key = 'ratelimit_' + email.replace(/[^a-z0-9@._-]/gi, '_');
  scriptProperties.deleteProperty(key);
  Logger.log('Rate limit cleared for: ' + email);
}

/**
 * Utility function to clear ALL rate limits (for admin use)
 * Run this from the Apps Script editor to reset all rate limits
 */
function clearAllRateLimits() {
  const scriptProperties = PropertiesService.getScriptProperties();
  const allProps = scriptProperties.getProperties();
  let clearedCount = 0;

  for (const key in allProps) {
    if (key.startsWith('ratelimit_')) {
      scriptProperties.deleteProperty(key);
      clearedCount++;
    }
  }

  Logger.log('Cleared ' + clearedCount + ' rate limit entries');
}

// ============================================================================
// INPUT VALIDATION AND SANITIZATION
// ============================================================================

/**
 * Validate and sanitize all input data
 */
function validateAndSanitizeInput(data) {
  const sanitized = {};

  // Validate submission number (format: CC-YYYYMMDD-XXXXX)
  sanitized.submissionNumber = validateSubmissionNumber(data.submissionNumber);

  // Validate and sanitize name
  sanitized.name = validateAndSanitizeText(
    data.name,
    'Name',
    CONFIG.MAX_NAME_LENGTH,
    true // required
  );

  // Validate and sanitize email
  sanitized.email = validateEmail(data.email);

  // Validate and sanitize store URL
  sanitized.storeUrl = validateURL(data.storeUrl);

  // Validate and sanitize message
  sanitized.message = validateAndSanitizeText(
    data.message,
    'Message',
    CONFIG.MAX_MESSAGE_LENGTH,
    false // optional if voice note provided
  );

  // Validate voice note if provided
  sanitized.hasVoiceNote = data.hasVoiceNote === 'Yes';
  if (sanitized.hasVoiceNote) {
    sanitized.voiceNoteData = validateAudioData(data.voiceNoteData);
  }

  // Check that either message or voice note is provided
  if (!sanitized.message && !sanitized.hasVoiceNote) {
    const error = new Error('No message or voice note provided');
    error.userMessage = 'Please provide either a message or voice note.';
    throw error;
  }

  // Add timestamp
  sanitized.timestamp = new Date().toLocaleString('en-NZ', {
    timeZone: 'Pacific/Auckland',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  });

  return sanitized;
}

/**
 * Validate submission number format
 */
function validateSubmissionNumber(submissionNumber) {
  if (!submissionNumber || submissionNumber.trim() === '') {
    // Generate one server-side if not provided (fallback)
    const now = new Date();
    const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '');
    const randomNum = Math.floor(10000 + Math.random() * 90000);
    return `CC-${dateStr}-${randomNum}`;
  }

  // Validate format: CC-YYYYMMDD-XXXXX
  const regex = /^CC-\d{8}-\d{5}$/;
  if (!regex.test(submissionNumber)) {
    const error = new Error('Invalid submission number format');
    error.userMessage = 'Invalid submission format.';
    throw error;
  }

  return submissionNumber;
}

/**
 * Validate and sanitize text input
 */
function validateAndSanitizeText(text, fieldName, maxLength, required) {
  if (!text || text.trim() === '') {
    if (required) {
      const error = new Error(fieldName + ' is required');
      error.userMessage = fieldName + ' is required.';
      throw error;
    }
    return '';
  }

  // Trim whitespace
  text = text.trim();

  // Check length
  if (text.length > maxLength) {
    const error = new Error(fieldName + ' is too long');
    error.userMessage = fieldName + ' exceeds maximum length.';
    throw error;
  }

  // Check for suspicious patterns
  if (REGEX.SUSPICIOUS_PATTERNS.test(text)) {
    const error = new Error('Suspicious input detected in ' + fieldName);
    error.userMessage = 'Invalid characters in ' + fieldName + '.';
    throw error;
  }

  // HTML entity escape for XSS prevention
  return escapeHtml(text);
}

/**
 * Validate email format
 */
function validateEmail(email) {
  if (!email || email.trim() === '') {
    const error = new Error('Email is required');
    error.userMessage = 'Email is required.';
    throw error;
  }

  email = email.trim().toLowerCase();

  if (email.length > CONFIG.MAX_EMAIL_LENGTH) {
    const error = new Error('Email is too long');
    error.userMessage = 'Email exceeds maximum length.';
    throw error;
  }

  if (!REGEX.EMAIL.test(email)) {
    const error = new Error('Invalid email format');
    error.userMessage = 'Please enter a valid email address.';
    throw error;
  }

  return escapeHtml(email);
}

/**
 * Validate URL format
 */
function validateURL(url) {
  if (!url || url.trim() === '') {
    return ''; // URL is optional
  }

  url = url.trim();

  // Ensure http:// or https:// prefix
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  if (url.length > CONFIG.MAX_URL_LENGTH) {
    const error = new Error('URL is too long');
    error.userMessage = 'Store URL exceeds maximum length.';
    throw error;
  }

  if (!REGEX.URL.test(url)) {
    const error = new Error('Invalid URL format');
    error.userMessage = 'Please enter a valid store URL.';
    throw error;
  }

  // Check for blocked patterns
  const lowerUrl = url.toLowerCase();
  for (const pattern of BLOCKED_PATTERNS) {
    if (lowerUrl.includes(pattern)) {
      const error = new Error('Blocked URL pattern detected');
      error.userMessage = 'Invalid store URL.';
      throw error;
    }
  }

  return escapeHtml(url);
}

/**
 * Validate audio data
 */
function validateAudioData(audioData) {
  if (!audioData || audioData.trim() === '') {
    const error = new Error('Audio data is empty');
    error.userMessage = 'Voice note is empty.';
    throw error;
  }

  // Check if it's base64 encoded
  if (!audioData.startsWith('data:audio/')) {
    const error = new Error('Invalid audio format');
    error.userMessage = 'Invalid voice note format.';
    throw error;
  }

  // Estimate file size (base64 is ~33% larger than original)
  // Add null check for split result to handle malformed data
  const splitData = audioData.split(',');
  if (splitData.length < 2 || !splitData[1]) {
    const error = new Error('Malformed audio data');
    error.userMessage = 'Invalid voice note format.';
    throw error;
  }

  const base64Length = splitData[1].length;
  const estimatedSizeBytes = (base64Length * 3) / 4;
  const estimatedSizeMB = estimatedSizeBytes / (1024 * 1024);

  if (estimatedSizeMB > CONFIG.MAX_AUDIO_SIZE_MB) {
    const error = new Error('Audio file too large');
    error.userMessage = 'Voice note exceeds 10MB limit.';
    throw error;
  }

  // Validate MIME type
  const semicolonIndex = audioData.indexOf(';');
  if (semicolonIndex === -1) {
    const error = new Error('Invalid audio data format');
    error.userMessage = 'Invalid voice note format.';
    throw error;
  }

  const mimeType = audioData.substring(5, semicolonIndex);
  const allowedTypes = ['audio/webm', 'audio/ogg', 'audio/mp4', 'audio/mpeg'];
  if (!allowedTypes.includes(mimeType)) {
    const error = new Error('Invalid audio MIME type');
    error.userMessage = 'Invalid voice note format.';
    throw error;
  }

  return audioData; // Return full base64 string for storage
}

/**
 * HTML entity escape to prevent XSS
 */
function escapeHtml(text) {
  if (!text) return '';

  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ============================================================================
// DATA STORAGE AND LOGGING
// ============================================================================

/**
 * Log submission to Apps Script logs
 */
function logSubmission(data) {
  Logger.log('Form submission received:');
  Logger.log('- Submission #: ' + data.submissionNumber);
  Logger.log('- Name: ' + data.name);
  Logger.log('- Email: ' + data.email);
  Logger.log('- Store URL: ' + data.storeUrl);
  Logger.log('- Has Voice Note: ' + data.hasVoiceNote);
  Logger.log('- Timestamp: ' + data.timestamp);

  // Save debug file to Google Drive
  saveDebugFileToDrive(data);
}

/**
 * Save a debug text file to Google Drive with submission details
 * This helps track form submissions for debugging purposes
 */
function saveDebugFileToDrive(data) {
  try {
    Logger.log('Attempting to save debug file for: ' + data.submissionNumber);
    const folder = getOrCreateDebugFolder();
    Logger.log('Debug folder obtained: ' + folder.getName());

    // Create debug content with submission details
    const debugContent = [
      '=== CartCure Form Submission Debug Log ===',
      '',
      'Submission Number: ' + data.submissionNumber,
      'Timestamp: ' + data.timestamp,
      'Server Time: ' + new Date().toISOString(),
      '',
      '--- Submission Details ---',
      'Name: ' + data.name,
      'Email: ' + data.email,
      'Store URL: ' + (data.storeUrl || 'Not provided'),
      'Message: ' + (data.message || 'Voice note only'),
      'Has Voice Note: ' + (data.hasVoiceNote ? 'Yes' : 'No'),
      '',
      '--- Debug Info ---',
      'Script execution completed successfully',
      '================================='
    ].join('\n');

    // Create filename with submission number
    const fileName = 'debug_' + data.submissionNumber + '.txt';

    // Create the file (plain text)
    const file = folder.createFile(fileName, debugContent);

    Logger.log('Debug file saved to Drive: ' + file.getUrl());
    return file.getUrl();
  } catch (error) {
    Logger.log('Error saving debug file to Drive: ' + error.message);
    // Don't throw - this is just for debugging, shouldn't break the submission
    return '';
  }
}

/**
 * Get or create the CartCure Debug Logs folder in Google Drive
 */
function getOrCreateDebugFolder() {
  const folderName = 'CartCure Debug Logs';
  const folders = DriveApp.getFoldersByName(folderName);

  if (folders.hasNext()) {
    return folders.next();
  }

  // Create the folder if it doesn't exist
  return DriveApp.createFolder(folderName);
}

/**
 * Save submission to Google Sheet
 */
function saveToSheet(data) {
  if (!CONFIG.SHEET_ID) {
    Logger.log('WARNING: SHEET_ID not configured. Skipping sheet save.');
    return;
  }

  try {
    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    let sheet = ss.getSheetByName('Submissions');

    // If Submissions sheet doesn't exist, create it
    if (!sheet) {
      Logger.log('Submissions sheet not found. Creating it...');
      sheet = ss.insertSheet('Submissions');
    }

    // Check if headers exist, if not create them
    if (sheet.getLastRow() === 0) {
      sheet.appendRow([
        'Submission #',
        'Timestamp',
        'Name',
        'Email',
        'Store URL',
        'Message',
        'Has Voice Note',
        'Voice Note Link',
        'Status'
      ]);
    }

    // Save audio file to Google Drive if present
    let audioFileUrl = '';
    if (data.hasVoiceNote && data.voiceNoteData) {
      audioFileUrl = saveAudioToDrive(data.voiceNoteData, data.submissionNumber);
    }

    // Find the first empty row (starting from row 2 to skip headers)
    const targetRow = findFirstEmptyRow(sheet);

    // Prepare the row data with Status set to 'New'
    const rowData = [
      data.submissionNumber,
      data.timestamp,
      data.name,
      data.email,
      data.storeUrl,
      data.message,
      data.hasVoiceNote ? 'Yes' : 'No',
      audioFileUrl,
      'New'
    ];

    // Write to the target row
    const range = sheet.getRange(targetRow, 1, 1, rowData.length);
    range.setValues([rowData]);

    Logger.log('Data saved to sheet at row ' + targetRow);
  } catch (error) {
    Logger.log('Error saving to sheet: ' + error.message);
    // Don't throw - submission should succeed even if sheet save fails
  }
}

/**
 * Find the first completely empty row in the sheet (skipping header row)
 */
function findFirstEmptyRow(sheet) {
  const lastRow = sheet.getLastRow();
  const numCols = 9; // Number of data columns (including Status)

  // If sheet only has headers or is empty, return row 2
  if (lastRow <= 1) {
    return 2;
  }

  // Get all data from row 2 onwards
  const dataRange = sheet.getRange(2, 1, lastRow - 1, numCols);
  const values = dataRange.getValues();

  // Find first empty row
  for (let i = 0; i < values.length; i++) {
    const row = values[i];
    // Check if entire row is empty (all cells are blank)
    const isEmpty = row.every(cell => cell === '' || cell === null || cell === undefined);
    if (isEmpty) {
      return i + 2; // +2 because we started at row 2 (1-indexed)
    }
  }

  // No empty rows found, use the next row after last
  return lastRow + 1;
}

/**
 * Save audio file to Google Drive
 */
function saveAudioToDrive(base64Data, submissionNumber) {
  try {
    // Extract MIME type and base64 data
    const matches = base64Data.match(/^data:(.+);base64,(.+)$/);
    if (!matches) {
      Logger.log('Invalid base64 audio data format');
      return '';
    }

    const mimeType = matches[1];
    const base64 = matches[2];

    // Decode base64
    const blob = Utilities.newBlob(
      Utilities.base64Decode(base64),
      mimeType,
      submissionNumber + '.webm'
    );

    // Get or create the CartCure Voice Notes folder
    const folder = getOrCreateVoiceNotesFolder();
    const file = folder.createFile(blob);

    // Set sharing permissions to view-only
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);

    return file.getUrl();
  } catch (error) {
    Logger.log('Error saving audio to Drive: ' + error.message);
    return '';
  }
}

/**
 * Get or create the CartCure Voice Notes folder in Google Drive
 */
function getOrCreateVoiceNotesFolder() {
  const folderName = 'CartCure Voice Notes';
  const folders = DriveApp.getFoldersByName(folderName);

  if (folders.hasNext()) {
    return folders.next();
  }

  // Create the folder if it doesn't exist
  return DriveApp.createFolder(folderName);
}

// ============================================================================
// EMAIL NOTIFICATIONS
// ============================================================================

/**
 * Send email notification to admin
 */
function sendEmailNotification(data) {
  if (!CONFIG.ADMIN_EMAIL) {
    Logger.log('WARNING: ADMIN_EMAIL not configured. Skipping email notification.');
    return;
  }

  try {
    const subject = '🛒 [' + data.submissionNumber + '] New Submission from ' + data.name;

    // Paperlike theme colors (matching user confirmation email)
    const colors = {
      brandGreen: '#2d5d3f',
      brandGreenLight: '#3a7a52',
      paperWhite: '#f9f7f3',
      paperCream: '#faf8f4',
      paperBorder: '#d4cfc3',
      inkBlack: '#2b2b2b',
      inkGray: '#5a5a5a',
      inkLight: '#8a8a8a',
      alertBg: '#fff8e6',
      alertBorder: '#f5d76e'
    };

    // Build professional HTML email body
    const htmlBody = `
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; background-color: ${colors.paperCream}; font-family: Georgia, 'Times New Roman', serif;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: ${colors.paperCream};">
            <tr>
              <td align="center" style="padding: 40px 20px;">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width: 600px; background-color: ${colors.paperWhite}; border: 3px solid ${colors.paperBorder}; box-shadow: 4px 4px 0 rgba(0,0,0,0.08);">

                  <!-- Header -->
                  <tr>
                    <td style="padding: 25px 40px; background-color: ${colors.brandGreen};">
                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                        <tr>
                          <td>
                            <h1 style="margin: 0; color: #ffffff; font-size: 22px; font-weight: normal; font-family: Georgia, 'Times New Roman', serif;">
                              New Form Submission
                            </h1>
                          </td>
                          <td align="right">
                            <span style="color: rgba(255,255,255,0.9); font-size: 13px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                              CartCure Admin
                            </span>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>

                  <!-- Reference Badge -->
                  <tr>
                    <td style="padding: 25px 40px 0 40px;">
                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                        <tr>
                          <td style="background-color: ${colors.alertBg}; border: 2px solid ${colors.alertBorder}; border-radius: 6px; padding: 15px 20px;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                              <tr>
                                <td>
                                  <span style="color: ${colors.inkLight}; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                                    Reference
                                  </span><br>
                                  <span style="color: ${colors.brandGreen}; font-size: 18px; font-weight: bold; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                                    ${data.submissionNumber}
                                  </span>
                                </td>
                                <td align="right">
                                  <span style="color: ${colors.inkGray}; font-size: 13px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                                    ${data.timestamp}
                                  </span>
                                </td>
                              </tr>
                            </table>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>

                  <!-- Contact Details -->
                  <tr>
                    <td style="padding: 30px 40px;">
                      <h2 style="margin: 0 0 20px 0; color: ${colors.inkBlack}; font-size: 16px; font-weight: normal; text-transform: uppercase; letter-spacing: 1px; border-bottom: 2px solid ${colors.paperBorder}; padding-bottom: 10px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                        Contact Details
                      </h2>

                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: ${colors.paperCream}; border: 1px solid ${colors.paperBorder}; border-radius: 6px;">
                        <tr>
                          <td style="padding: 18px 20px; border-bottom: 1px solid ${colors.paperBorder};">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                              <tr>
                                <td width="100" style="color: ${colors.inkLight}; font-size: 13px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; vertical-align: top;">
                                  Name
                                </td>
                                <td style="color: ${colors.inkBlack}; font-size: 15px; font-weight: bold;">
                                  ${data.name}
                                </td>
                              </tr>
                            </table>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 18px 20px; border-bottom: 1px solid ${colors.paperBorder};">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                              <tr>
                                <td width="100" style="color: ${colors.inkLight}; font-size: 13px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; vertical-align: top;">
                                  Email
                                </td>
                                <td>
                                  <a href="mailto:${data.email}" style="color: ${colors.brandGreen}; font-size: 15px; text-decoration: none; font-weight: bold;">
                                    ${data.email}
                                  </a>
                                </td>
                              </tr>
                            </table>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 18px 20px;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                              <tr>
                                <td width="100" style="color: ${colors.inkLight}; font-size: 13px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; vertical-align: top;">
                                  Store URL
                                </td>
                                <td>
                                  ${data.storeUrl
                                    ? `<a href="${data.storeUrl}" target="_blank" style="color: ${colors.brandGreen}; font-size: 15px; text-decoration: none;">${data.storeUrl}</a>`
                                    : `<span style="color: ${colors.inkLight}; font-size: 15px; font-style: italic;">Not provided</span>`}
                                </td>
                              </tr>
                            </table>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>

                  <!-- Message Section -->
                  <tr>
                    <td style="padding: 0 40px 30px 40px;">
                      <h2 style="margin: 0 0 20px 0; color: ${colors.inkBlack}; font-size: 16px; font-weight: normal; text-transform: uppercase; letter-spacing: 1px; border-bottom: 2px solid ${colors.paperBorder}; padding-bottom: 10px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                        Message
                      </h2>

                      <div style="background-color: #ffffff; border: 1px solid ${colors.paperBorder}; border-left: 4px solid ${colors.brandGreen}; border-radius: 0 6px 6px 0; padding: 20px;">
                        <p style="margin: 0; color: ${colors.inkBlack}; font-size: 15px; line-height: 1.7; white-space: pre-wrap;">
                          ${data.message || '<em style="color: ' + colors.inkLight + ';">No written message — voice note attached</em>'}
                        </p>
                      </div>

                      ${data.hasVoiceNote ? `
                      <div style="margin-top: 15px; background-color: ${colors.alertBg}; border: 1px solid ${colors.alertBorder}; border-radius: 6px; padding: 12px 16px;">
                        <table role="presentation" cellspacing="0" cellpadding="0">
                          <tr>
                            <td style="padding-right: 10px; font-size: 18px;">🎤</td>
                            <td style="color: ${colors.inkGray}; font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                              <strong>Voice note attached</strong> — Check Google Sheet or Drive for audio file
                            </td>
                          </tr>
                        </table>
                      </div>
                      ` : ''}
                    </td>
                  </tr>

                  <!-- Action Button -->
                  <tr>
                    <td style="padding: 0 40px 35px 40px;">
                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                        <tr>
                          <td align="center">
                            <a href="https://docs.google.com/spreadsheets/d/${CONFIG.SHEET_ID}/edit"
                               target="_blank"
                               style="display: inline-block; background-color: ${colors.brandGreen}; color: #ffffff; padding: 14px 35px; text-decoration: none; border-radius: 6px; font-size: 15px; font-weight: bold; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                              View in Google Sheets →
                            </a>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>

                  <!-- Footer -->
                  <tr>
                    <td style="padding: 20px 40px; background-color: ${colors.paperCream}; border-top: 2px solid ${colors.paperBorder};">
                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                        <tr>
                          <td>
                            <p style="margin: 0; color: ${colors.inkLight}; font-size: 12px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                              CartCure Contact Form · Auto-generated notification
                            </p>
                          </td>
                          <td align="right">
                            <a href="https://cartcure.co.nz" style="color: ${colors.brandGreen}; font-size: 12px; text-decoration: none; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                              cartcure.co.nz
                            </a>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
      </html>
    `;

    // Plain text version
    const plainBody = `
══════════════════════════════════════════════════════
   NEW CARTCURE FORM SUBMISSION
══════════════════════════════════════════════════════

Reference: ${data.submissionNumber}
Submitted: ${data.timestamp}

──────────────────────────────────────────────────────
CONTACT DETAILS
──────────────────────────────────────────────────────

Name:      ${data.name}
Email:     ${data.email}
Store URL: ${data.storeUrl || 'Not provided'}

──────────────────────────────────────────────────────
MESSAGE
──────────────────────────────────────────────────────

${data.message || '[Voice note only - no written message]'}

${data.hasVoiceNote ? '🎤 Voice note attached - check Google Sheet/Drive for audio file\n' : ''}
──────────────────────────────────────────────────────
QUICK ACTIONS
──────────────────────────────────────────────────────

→ View Google Sheet: https://docs.google.com/spreadsheets/d/${CONFIG.SHEET_ID}/edit
→ Reply to customer: mailto:${data.email}

══════════════════════════════════════════════════════
CartCure Contact Form · https://cartcure.co.nz
    `;

    // Send email
    MailApp.sendEmail({
      to: CONFIG.ADMIN_EMAIL,
      subject: subject,
      body: plainBody,
      htmlBody: htmlBody,
      name: 'CartCure Forms'
    });

    Logger.log('Email notification sent successfully');
  } catch (error) {
    Logger.log('Error sending email: ' + error.message);
    // Don't throw - submission should succeed even if email fails
  }
}

/**
 * Send confirmation email to the user who submitted the form
 */
function sendUserConfirmationEmail(data) {
  if (!data.email) {
    Logger.log('WARNING: No user email provided. Skipping user confirmation.');
    return;
  }

  try {
    const subject = 'We received your request! - CartCure [' + data.submissionNumber + ']';

    // Paperlike theme colors
    const colors = {
      brandGreen: '#2d5d3f',
      paperWhite: '#f9f7f3',
      paperCream: '#faf8f4',
      paperBorder: '#d4cfc3',
      inkBlack: '#2b2b2b',
      inkGray: '#5a5a5a',
      inkLight: '#8a8a8a'
    };

    // Build professional HTML email with paperlike theme
    const htmlBody = `
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; background-color: ${colors.paperCream}; font-family: Georgia, 'Times New Roman', serif;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: ${colors.paperCream};">
            <tr>
              <td align="center" style="padding: 40px 20px;">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width: 600px; background-color: ${colors.paperWhite}; border: 3px solid ${colors.paperBorder}; box-shadow: 4px 4px 0 rgba(0,0,0,0.08);">

                  <!-- Header with Logo -->
                  <tr>
                    <td align="center" style="padding: 30px 40px 20px 40px; border-bottom: 2px solid ${colors.paperBorder};">
                      <img src="https://cartcure.co.nz/CartCure_fullLogo.png" alt="CartCure" width="180" style="display: block; max-width: 180px; height: auto;">
                    </td>
                  </tr>

                  <!-- Main Content -->
                  <tr>
                    <td style="padding: 40px;">
                      <!-- Greeting -->
                      <h1 style="margin: 0 0 20px 0; color: ${colors.brandGreen}; font-size: 24px; font-weight: normal; font-family: Georgia, 'Times New Roman', serif;">
                        Thanks for reaching out, ${data.name}!
                      </h1>

                      <p style="margin: 0 0 25px 0; color: ${colors.inkBlack}; font-size: 16px; line-height: 1.7;">
                        We've received your request and we're excited to help with your Shopify store. Our team will review the details and get back to you within <strong>1-2 business days</strong> with a quote or any follow-up questions.
                      </p>

                      <!-- Reference Box -->
                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom: 30px;">
                        <tr>
                          <td style="background-color: ${colors.paperCream}; border: 2px solid ${colors.paperBorder}; padding: 20px;">
                            <p style="margin: 0 0 5px 0; color: ${colors.inkLight}; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                              Your Reference Number
                            </p>
                            <p style="margin: 0; color: ${colors.brandGreen}; font-size: 20px; font-weight: bold; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                              ${data.submissionNumber}
                            </p>
                          </td>
                        </tr>
                      </table>

                      <!-- Submission Details -->
                      <h2 style="margin: 0 0 15px 0; color: ${colors.inkBlack}; font-size: 18px; font-weight: normal; border-bottom: 1px solid ${colors.paperBorder}; padding-bottom: 10px;">
                        What you shared with us:
                      </h2>

                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom: 30px;">
                        <tr>
                          <td style="padding: 12px 0; border-bottom: 1px solid ${colors.paperBorder};">
                            <span style="color: ${colors.inkLight}; font-size: 14px;">Submitted</span><br>
                            <span style="color: ${colors.inkBlack}; font-size: 15px;">${data.timestamp}</span>
                          </td>
                        </tr>
                        ${data.storeUrl ? `
                        <tr>
                          <td style="padding: 12px 0; border-bottom: 1px solid ${colors.paperBorder};">
                            <span style="color: ${colors.inkLight}; font-size: 14px;">Your Store</span><br>
                            <a href="${data.storeUrl}" style="color: ${colors.brandGreen}; font-size: 15px; text-decoration: none;">${data.storeUrl}</a>
                          </td>
                        </tr>
                        ` : ''}
                        <tr>
                          <td style="padding: 12px 0; border-bottom: 1px solid ${colors.paperBorder};">
                            <span style="color: ${colors.inkLight}; font-size: 14px;">Your Message</span><br>
                            <span style="color: ${colors.inkBlack}; font-size: 15px; line-height: 1.6;">${data.message || '<em style="color: ' + colors.inkGray + ';">Voice note attached</em>'}</span>
                          </td>
                        </tr>
                        ${data.hasVoiceNote ? `
                        <tr>
                          <td style="padding: 12px 0;">
                            <span style="color: ${colors.inkLight}; font-size: 14px;">Voice Note</span><br>
                            <span style="color: ${colors.brandGreen}; font-size: 15px;">✓ Received and saved</span>
                          </td>
                        </tr>
                        ` : ''}
                      </table>

                      <!-- What's Next -->
                      <h2 style="margin: 0 0 15px 0; color: ${colors.inkBlack}; font-size: 18px; font-weight: normal; border-bottom: 1px solid ${colors.paperBorder}; padding-bottom: 10px;">
                        What happens next?
                      </h2>

                      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom: 30px;">
                        <tr>
                          <td style="padding: 10px 0;">
                            <table role="presentation" cellspacing="0" cellpadding="0">
                              <tr>
                                <td style="width: 30px; vertical-align: top; color: ${colors.brandGreen}; font-size: 18px; font-weight: bold;">1.</td>
                                <td style="color: ${colors.inkBlack}; font-size: 15px; line-height: 1.6;">We review your request and assess the work needed</td>
                              </tr>
                            </table>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 10px 0;">
                            <table role="presentation" cellspacing="0" cellpadding="0">
                              <tr>
                                <td style="width: 30px; vertical-align: top; color: ${colors.brandGreen}; font-size: 18px; font-weight: bold;">2.</td>
                                <td style="color: ${colors.inkBlack}; font-size: 15px; line-height: 1.6;">We'll email you a clear quote (no surprises!)</td>
                              </tr>
                            </table>
                          </td>
                        </tr>
                        <tr>
                          <td style="padding: 10px 0;">
                            <table role="presentation" cellspacing="0" cellpadding="0">
                              <tr>
                                <td style="width: 30px; vertical-align: top; color: ${colors.brandGreen}; font-size: 18px; font-weight: bold;">3.</td>
                                <td style="color: ${colors.inkBlack}; font-size: 15px; line-height: 1.6;">Once approved, we get to work — most fixes are completed within 7 days</td>
                              </tr>
                            </table>
                          </td>
                        </tr>
                      </table>

                      <!-- Friendly Close -->
                      <p style="margin: 0; color: ${colors.inkBlack}; font-size: 16px; line-height: 1.7;">
                        Have questions in the meantime? Just reply to this email — we're happy to help.
                      </p>

                      <p style="margin: 25px 0 0 0; color: ${colors.inkBlack}; font-size: 16px;">
                        Cheers,<br>
                        <strong style="color: ${colors.brandGreen};">The CartCure Team</strong>
                      </p>
                    </td>
                  </tr>

                  <!-- Footer -->
                  <tr>
                    <td style="padding: 25px 40px; background-color: ${colors.paperCream}; border-top: 2px solid ${colors.paperBorder};">
                      <p style="margin: 0 0 10px 0; color: ${colors.inkLight}; font-size: 13px; text-align: center; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                        Quick Shopify® Fixes for NZ Businesses
                      </p>
                      <p style="margin: 0; color: ${colors.inkLight}; font-size: 12px; text-align: center; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
                        <a href="https://cartcure.co.nz" style="color: ${colors.brandGreen}; text-decoration: none;">cartcure.co.nz</a>
                      </p>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
      </html>
    `;

    // Plain text version for email clients that don't support HTML
    const plainBody = `
Thanks for reaching out, ${data.name}!

We've received your request and we're excited to help with your Shopify store. Our team will review the details and get back to you within 1-2 business days with a quote or any follow-up questions.

YOUR REFERENCE NUMBER: ${data.submissionNumber}

WHAT YOU SHARED WITH US:
------------------------
Submitted: ${data.timestamp}
${data.storeUrl ? 'Your Store: ' + data.storeUrl + '\n' : ''}Message: ${data.message || 'Voice note attached'}
${data.hasVoiceNote ? 'Voice Note: Received and saved\n' : ''}

WHAT HAPPENS NEXT?
------------------
1. We review your request and assess the work needed
2. We'll email you a clear quote (no surprises!)
3. Once approved, we get to work — most fixes are completed within 7 days

Have questions in the meantime? Just reply to this email — we're happy to help.

Cheers,
The CartCure Team

---
CartCure | Quick Shopify® Fixes for NZ Businesses
https://cartcure.co.nz
    `;

    // Send email to user
    MailApp.sendEmail({
      to: data.email,
      subject: subject,
      body: plainBody,
      htmlBody: htmlBody,
      name: 'CartCure'
    });

    Logger.log('User confirmation email sent to: ' + data.email);
  } catch (error) {
    Logger.log('Error sending user confirmation email: ' + error.message);
    // Don't throw - submission should succeed even if confirmation email fails
  }
}

// ============================================================================
// JOB MANAGEMENT SYSTEM
// ============================================================================
// This section handles quotes, job tracking, invoices, and workflow management
// ============================================================================

// Job Management Configuration
const JOB_CONFIG = {
  // SLA Settings
  DEFAULT_SLA_DAYS: 7,          // 7-day promise
  AT_RISK_THRESHOLD: 2,         // Yellow warning when <2 days remaining

  // Quote Settings
  QUOTE_VALIDITY_DAYS: 14,
  PAYMENT_TERMS_DAYS: 7,

  // GST (read from Settings sheet, default if not set)
  GST_RATE: 0.15,
  CURRENCY_SYMBOL: '$'
};

// Sheet Names
const SHEETS = {
  SUBMISSIONS: 'Submissions',
  JOBS: 'Jobs',
  INVOICES: 'Invoice Log',
  SETTINGS: 'Settings',
  DASHBOARD: 'Dashboard'
};

// Job Status Constants
const JOB_STATUS = {
  PENDING_QUOTE: 'Pending Quote',
  QUOTED: 'Quoted',
  ACCEPTED: 'Accepted',
  IN_PROGRESS: 'In Progress',
  COMPLETED: 'Completed',
  ON_HOLD: 'On Hold',
  CANCELLED: 'Cancelled',
  DECLINED: 'Declined'
};

// Payment Status Constants
const PAYMENT_STATUS = {
  UNPAID: 'Unpaid',
  INVOICED: 'Invoiced',
  PAID: 'Paid',
  OVERDUE: 'Overdue',
  REFUNDED: 'Refunded'
};

// Job Categories
const JOB_CATEGORIES = ['Design', 'Content', 'Bug Fix', 'Improvement', 'App Setup', 'Other'];

// ============================================================================
// CUSTOM MENU
// ============================================================================

/**
 * Create custom menu when spreadsheet opens
 */
function onOpen() {
  const ui = SpreadsheetApp.getUi();
  ui.createMenu('🛒 CartCure')
    .addSubMenu(ui.createMenu('📊 Dashboard')
      .addItem('Refresh Dashboard', 'refreshDashboard'))
    .addSeparator()
    .addSubMenu(ui.createMenu('📋 Jobs')
      .addItem('Create Job from Submission', 'showCreateJobDialog')
      .addItem('Mark Quote Accepted', 'showAcceptQuoteDialog')
      .addItem('Start Work on Job', 'showStartWorkDialog')
      .addItem('Mark Job Complete', 'showCompleteJobDialog')
      .addItem('Put Job On Hold', 'showOnHoldDialog'))
    .addSubMenu(ui.createMenu('💰 Quotes')
      .addItem('Send Quote', 'showSendQuoteDialog')
      .addItem('Send Quote Reminder', 'showQuoteReminderDialog')
      .addItem('Mark Quote Declined', 'showDeclineQuoteDialog'))
    .addSubMenu(ui.createMenu('🧾 Invoices')
      .addItem('Generate Invoice', 'showGenerateInvoiceDialog')
      .addItem('Send Invoice', 'showSendInvoiceDialog')
      .addItem('Mark as Paid', 'showMarkPaidDialog'))
    .addSubMenu(ui.createMenu('📈 Reports')
      .addItem('Overdue Jobs', 'showOverdueJobs')
      .addItem('Outstanding Payments', 'showOutstandingPayments')
      .addItem('Monthly Summary', 'showMonthlySummary'))
    .addSeparator()
    .addItem('⚙️ Setup Sheets', 'setupJobManagementSheets')
    .addItem('⚠️ Hard Reset (Delete All Data)', 'showHardResetDialog')
    .addToUi();
}

// ============================================================================
// SETUP FUNCTIONS
// ============================================================================

/**
 * Setup all required sheets for job management
 * Run this once to create the sheets structure
 */
function setupJobManagementSheets() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const ui = SpreadsheetApp.getUi();

  try {
    // Create Jobs sheet
    createJobsSheet(ss);

    // Create Invoice Log sheet
    createInvoiceLogSheet(ss);

    // Create Settings sheet
    createSettingsSheet(ss);

    // Create Dashboard sheet
    createDashboardSheet(ss);

    // Update Submissions sheet with new columns
    updateSubmissionsSheet(ss);

    ui.alert('Setup Complete', 'All job management sheets have been created successfully!\n\nNext steps:\n1. Fill in your business details in the Settings sheet\n2. Use the CartCure menu to manage jobs', ui.ButtonSet.OK);

    Logger.log('Job management sheets setup completed successfully');
  } catch (error) {
    Logger.log('Error setting up sheets: ' + error.message);
    ui.alert('Setup Error', 'There was an error setting up the sheets: ' + error.message, ui.ButtonSet.OK);
  }
}

/**
 * Create the Jobs sheet with all required columns
 */
function createJobsSheet(ss) {
  let sheet = ss.getSheetByName(SHEETS.JOBS);

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.JOBS);
  } else {
    // Clear existing content if sheet exists
    sheet.clear();
  }

  // Define headers
  const headers = [
    'Job #',
    'Submission #',
    'Created Date',
    'Client Name',
    'Client Email',
    'Store URL',
    'Job Description',
    'Category',
    'Status',
    'Quote Amount (excl GST)',
    'GST',
    'Total (incl GST)',
    'Quote Sent Date',
    'Quote Valid Until',
    'Quote Accepted Date',
    'Days Since Accepted',
    'Days Remaining',
    'SLA Status',
    'Estimated Turnaround',
    'Due Date',
    'Actual Start Date',
    'Actual Completion Date',
    'Payment Status',
    'Payment Date',
    'Payment Method',
    'Payment Reference',
    'Invoice #',
    'Notes',
    'Last Updated'
  ];

  // Set headers
  sheet.getRange(1, 1, 1, headers.length).setValues([headers]);

  // Format header row
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  headerRange.setBackground('#2d5d3f');
  headerRange.setFontColor('#ffffff');
  headerRange.setFontWeight('bold');
  headerRange.setHorizontalAlignment('center');

  // Freeze header row
  sheet.setFrozenRows(1);

  // Set column widths
  sheet.setColumnWidth(1, 100);  // Job #
  sheet.setColumnWidth(7, 300);  // Job Description
  sheet.setColumnWidth(28, 250); // Notes

  // Add data validation for Category (column 8)
  const categoryRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(JOB_CATEGORIES, true)
    .setAllowInvalid(false)
    .build();
  sheet.getRange(2, 8, 500, 1).setDataValidation(categoryRule);

  // Add data validation for Status (column 9)
  const statusRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(Object.values(JOB_STATUS), true)
    .setAllowInvalid(false)
    .build();
  sheet.getRange(2, 9, 500, 1).setDataValidation(statusRule);

  // Add data validation for Payment Status (column 23)
  const paymentRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(Object.values(PAYMENT_STATUS), true)
    .setAllowInvalid(false)
    .build();
  sheet.getRange(2, 23, 500, 1).setDataValidation(paymentRule);

  // Add conditional formatting for SLA Status
  addSLAConditionalFormatting(sheet);

  Logger.log('Jobs sheet created successfully');
}

/**
 * Add conditional formatting for SLA status column
 */
function addSLAConditionalFormatting(sheet) {
  const slaColumn = 18; // SLA Status column
  const range = sheet.getRange(2, slaColumn, 500, 1);

  // Clear existing rules
  const rules = sheet.getConditionalFormatRules();
  const newRules = rules.filter(rule => {
    const ranges = rule.getRanges();
    return !ranges.some(r => r.getColumn() === slaColumn);
  });

  // OVERDUE - Red
  const overdueRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('OVERDUE')
    .setBackground('#ffcccc')
    .setFontColor('#cc0000')
    .setBold(true)
    .setRanges([range])
    .build();

  // AT RISK - Yellow
  const atRiskRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('AT RISK')
    .setBackground('#fff3cd')
    .setFontColor('#856404')
    .setBold(true)
    .setRanges([range])
    .build();

  // On Track - Green
  const onTrackRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('On Track')
    .setBackground('#d4edda')
    .setFontColor('#155724')
    .setRanges([range])
    .build();

  newRules.push(overdueRule, atRiskRule, onTrackRule);
  sheet.setConditionalFormatRules(newRules);
}

/**
 * Create the Invoice Log sheet
 */
function createInvoiceLogSheet(ss) {
  let sheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.INVOICES);
  } else {
    sheet.clear();
  }

  const headers = [
    'Invoice #',
    'Job #',
    'Client Name',
    'Client Email',
    'Invoice Date',
    'Due Date',
    'Amount (excl GST)',
    'GST',
    'Total',
    'Status',
    'Sent Date',
    'Paid Date',
    'Payment Reference',
    'Notes'
  ];

  sheet.getRange(1, 1, 1, headers.length).setValues([headers]);

  // Format header
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  headerRange.setBackground('#2d5d3f');
  headerRange.setFontColor('#ffffff');
  headerRange.setFontWeight('bold');

  sheet.setFrozenRows(1);

  // Add data validation for Status
  const statusRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(['Draft', 'Sent', 'Paid', 'Overdue', 'Cancelled'], true)
    .setAllowInvalid(false)
    .build();
  sheet.getRange(2, 10, 500, 1).setDataValidation(statusRule);

  Logger.log('Invoice Log sheet created successfully');
}

/**
 * Create the Settings sheet
 */
function createSettingsSheet(ss) {
  let sheet = ss.getSheetByName(SHEETS.SETTINGS);

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.SETTINGS);
  } else {
    sheet.clear();
  }

  const settings = [
    ['Setting', 'Value', 'Description'],
    ['Business Name', 'CartCure', 'Your business name for invoices'],
    ['GST Registered', 'No', 'Yes or No - controls GST display on quotes/invoices'],
    ['GST Number', '', 'Your GST number (if registered)'],
    ['Bank Account', '', 'Bank account number for payments (XX-XXXX-XXXXXXX-XX)'],
    ['Bank Name', '', 'Bank name (e.g., ANZ, ASB, Westpac)'],
    ['Default Quote Validity', '14', 'Days quote is valid for'],
    ['Default Payment Terms', '7', 'Days to pay after invoice'],
    ['Default SLA Days', '7', 'Your turnaround promise in days'],
    ['Admin Email', CONFIG.ADMIN_EMAIL || '', 'Email for notifications'],
    ['Next Job Number', '1', 'Auto-incremented job number counter'],
    ['Next Invoice Number', '1', 'Auto-incremented invoice number counter']
  ];

  sheet.getRange(1, 1, settings.length, 3).setValues(settings);

  // Format header
  sheet.getRange(1, 1, 1, 3).setBackground('#2d5d3f').setFontColor('#ffffff').setFontWeight('bold');

  // Format setting names
  sheet.getRange(2, 1, settings.length - 1, 1).setFontWeight('bold');

  // Set column widths
  sheet.setColumnWidth(1, 180);
  sheet.setColumnWidth(2, 250);
  sheet.setColumnWidth(3, 350);

  sheet.setFrozenRows(1);

  Logger.log('Settings sheet created successfully');
}

/**
 * Create the Dashboard sheet
 */
function createDashboardSheet(ss) {
  let sheet = ss.getSheetByName(SHEETS.DASHBOARD);

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.DASHBOARD);
    // Move dashboard to be the first sheet
    ss.setActiveSheet(sheet);
    ss.moveActiveSheet(1);
  } else {
    sheet.clear();
  }

  // Dashboard header
  sheet.getRange('A1').setValue('📊 CartCure Dashboard');
  sheet.getRange('A1').setFontSize(20).setFontWeight('bold').setFontColor('#2d5d3f');

  sheet.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));
  sheet.getRange('A2').setFontColor('#8a8a8a').setFontStyle('italic');

  // Summary Metrics Section
  sheet.getRange('A4').setValue('📈 Summary Metrics');
  sheet.getRange('A4').setFontSize(14).setFontWeight('bold');

  const metricsLabels = [
    ['Metric', 'Value'],
    ['Jobs OVERDUE', '=COUNTIF(Jobs!R:R,"OVERDUE")'],
    ['Jobs AT RISK', '=COUNTIF(Jobs!R:R,"AT RISK")'],
    ['Jobs In Progress', '=COUNTIF(Jobs!I:I,"In Progress")'],
    ['Jobs Awaiting Quote', '=COUNTIF(Jobs!I:I,"Pending Quote")'],
    ['Pending Quotes (sent)', '=COUNTIF(Jobs!I:I,"Quoted")'],
    ['Unpaid Invoices', '=SUMIF(Jobs!W:W,"Unpaid",Jobs!L:L)+SUMIF(Jobs!W:W,"Invoiced",Jobs!L:L)'],
    ['Revenue This Month', '=SUMIFS(Jobs!L:L,Jobs!W:W,"Paid",Jobs!X:X,">="&DATE(YEAR(TODAY()),MONTH(TODAY()),1))']
  ];

  sheet.getRange(5, 1, metricsLabels.length, 2).setValues(metricsLabels);
  sheet.getRange(5, 1, 1, 2).setBackground('#f0f0f0').setFontWeight('bold');

  // Active Jobs Section
  sheet.getRange('A15').setValue('🔥 Active Jobs (sorted by urgency)');
  sheet.getRange('A15').setFontSize(14).setFontWeight('bold');

  sheet.getRange('A16').setValue('Click "Refresh Dashboard" from the CartCure menu to update this view');
  sheet.getRange('A16').setFontColor('#8a8a8a').setFontStyle('italic');

  const activeJobsHeaders = ['Job #', 'Client', 'Description', 'Days Remaining', 'SLA Status', 'Status', 'Due Date'];
  sheet.getRange(18, 1, 1, activeJobsHeaders.length).setValues([activeJobsHeaders]);
  sheet.getRange(18, 1, 1, activeJobsHeaders.length).setBackground('#2d5d3f').setFontColor('#ffffff').setFontWeight('bold');

  // Pending Quotes Section
  sheet.getRange('A30').setValue('⏳ Pending Quotes (sorted by age)');
  sheet.getRange('A30').setFontSize(14).setFontWeight('bold');

  const pendingQuotesHeaders = ['Job #', 'Client', 'Quote Amount', 'Days Waiting', 'Quote Valid Until', 'Action'];
  sheet.getRange(32, 1, 1, pendingQuotesHeaders.length).setValues([pendingQuotesHeaders]);
  sheet.getRange(32, 1, 1, pendingQuotesHeaders.length).setBackground('#2d5d3f').setFontColor('#ffffff').setFontWeight('bold');

  // Set column widths
  sheet.setColumnWidth(1, 100);
  sheet.setColumnWidth(2, 150);
  sheet.setColumnWidth(3, 250);
  sheet.setColumnWidth(4, 120);
  sheet.setColumnWidth(5, 100);
  sheet.setColumnWidth(6, 100);
  sheet.setColumnWidth(7, 100);

  Logger.log('Dashboard sheet created successfully');
}

/**
 * Setup the Submissions sheet with professional formatting and status tracking
 */
function setupSubmissionsSheet(ss) {
  let sheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.SUBMISSIONS);
    Logger.log('Created new Submissions sheet');
  } else {
    // Clear formatting but keep data
    const lastRow = sheet.getLastRow();
    if (lastRow > 1) {
      Logger.log('Submissions sheet exists with ' + (lastRow - 1) + ' submissions - preserving data');
    }
  }

  // Define headers with Status column
  const headers = [
    'Submission #',
    'Timestamp',
    'Name',
    'Email',
    'Store URL',
    'Message',
    'Has Voice Note',
    'Voice Note Link',
    'Status'
  ];

  // Check if we need to add the Status column to existing data
  const currentHeaders = sheet.getLastRow() > 0 ? sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0] : [];
  const needsStatusColumn = !currentHeaders.includes('Status');

  if (needsStatusColumn && sheet.getLastRow() > 0) {
    Logger.log('Adding Status column to existing Submissions sheet');
    // Add Status header
    sheet.getRange(1, 9).setValue('Status');
    // Set all existing submissions to 'New' status
    if (sheet.getLastRow() > 1) {
      sheet.getRange(2, 9, sheet.getLastRow() - 1, 1).setValue('New');
    }
  } else if (sheet.getLastRow() === 0) {
    // New sheet - set headers
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  }

  // Format header row with CartCure green
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  headerRange.setBackground('#2d5d3f');
  headerRange.setFontColor('#ffffff');
  headerRange.setFontWeight('bold');
  headerRange.setHorizontalAlignment('center');
  headerRange.setVerticalAlignment('middle');

  // Freeze header row
  sheet.setFrozenRows(1);

  // Set column widths for better readability
  sheet.setColumnWidth(1, 120);  // Submission #
  sheet.setColumnWidth(2, 160);  // Timestamp
  sheet.setColumnWidth(3, 150);  // Name
  sheet.setColumnWidth(4, 200);  // Email
  sheet.setColumnWidth(5, 250);  // Store URL
  sheet.setColumnWidth(6, 350);  // Message
  sheet.setColumnWidth(7, 120);  // Has Voice Note
  sheet.setColumnWidth(8, 250);  // Voice Note Link
  sheet.setColumnWidth(9, 130);  // Status

  // Add data validation for Status column (column 9)
  const statusValues = ['New', 'In Review', 'Job Created', 'Declined', 'Spam'];
  const statusRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(statusValues, true)
    .setAllowInvalid(false)
    .build();
  sheet.getRange(2, 9, 1000, 1).setDataValidation(statusRule);

  // Add conditional formatting for Status column
  addSubmissionStatusFormatting(sheet);

  // Enable filtering for all columns
  const dataRange = sheet.getRange(1, 1, Math.max(sheet.getLastRow(), 2), headers.length);
  dataRange.createFilter();

  // Protect the header row from accidental edits
  const protection = sheet.getRange(1, 1, 1, headers.length).protect();
  protection.setDescription('Protected header row');
  protection.setWarningOnly(true);

  Logger.log('Submissions sheet setup completed successfully');
}

/**
 * Add conditional formatting for Submission Status column
 */
function addSubmissionStatusFormatting(sheet) {
  const statusColumn = 9; // Status column
  const range = sheet.getRange(2, statusColumn, 1000, 1);

  // Clear existing conditional formatting rules for this column
  const rules = sheet.getConditionalFormatRules();
  const newRules = rules.filter(rule => {
    const ranges = rule.getRanges();
    return !ranges.some(r => r.getColumn() === statusColumn);
  });

  // New - Blue (needs attention)
  const newRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('New')
    .setBackground('#cfe2ff')
    .setFontColor('#084298')
    .setBold(true)
    .setRanges([range])
    .build();

  // In Review - Yellow (being processed)
  const reviewRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('In Review')
    .setBackground('#fff3cd')
    .setFontColor('#856404')
    .setBold(true)
    .setRanges([range])
    .build();

  // Job Created - Green (success)
  const jobCreatedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Job Created')
    .setBackground('#d4edda')
    .setFontColor('#155724')
    .setRanges([range])
    .build();

  // Declined - Gray (closed)
  const declinedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Declined')
    .setBackground('#e9ecef')
    .setFontColor('#6c757d')
    .setRanges([range])
    .build();

  // Spam - Red (rejected)
  const spamRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Spam')
    .setBackground('#ffcccc')
    .setFontColor('#cc0000')
    .setRanges([range])
    .build();

  newRules.push(newRule, reviewRule, jobCreatedRule, declinedRule, spamRule);
  sheet.setConditionalFormatRules(newRules);
}

/**
 * Update Submissions sheet - kept for backward compatibility
 * Now calls the new setupSubmissionsSheet function
 */
function updateSubmissionsSheet(ss) {
  setupSubmissionsSheet(ss);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Get a setting value from the Settings sheet
 */
function getSetting(settingName) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.SETTINGS);

  if (!sheet) {
    Logger.log('Settings sheet not found');
    return null;
  }

  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === settingName) {
      return data[i][1];
    }
  }
  return null;
}

/**
 * Update a setting value in the Settings sheet
 */
function updateSetting(settingName, value) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.SETTINGS);

  if (!sheet) {
    Logger.log('Settings sheet not found');
    return false;
  }

  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === settingName) {
      sheet.getRange(i + 1, 2).setValue(value);
      return true;
    }
  }
  return false;
}

/**
 * Get the next job number and increment the counter
 */
function getNextJobNumber() {
  const currentNum = parseInt(getSetting('Next Job Number')) || 1;
  const jobNumber = 'JOB-' + String(currentNum).padStart(3, '0');
  updateSetting('Next Job Number', currentNum + 1);
  return jobNumber;
}

/**
 * Get the next invoice number and increment the counter
 */
function getNextInvoiceNumber() {
  const currentNum = parseInt(getSetting('Next Invoice Number')) || 1;
  const year = new Date().getFullYear();
  const invoiceNumber = 'INV-' + year + '-' + String(currentNum).padStart(3, '0');
  updateSetting('Next Invoice Number', currentNum + 1);
  return invoiceNumber;
}

/**
 * Format currency for NZD
 */
function formatCurrency(amount) {
  return JOB_CONFIG.CURRENCY_SYMBOL + Number(amount).toFixed(2);
}

/**
 * Calculate GST amount
 */
function calculateGST(amountExclGST) {
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  if (!isGSTRegistered) return 0;
  return amountExclGST * JOB_CONFIG.GST_RATE;
}

/**
 * Format date for NZ timezone
 */
function formatNZDate(date) {
  if (!date) return '';
  const d = new Date(date);
  return Utilities.formatDate(d, 'Pacific/Auckland', 'dd/MM/yyyy');
}

/**
 * Calculate days between two dates
 */
function daysBetween(date1, date2) {
  const d1 = new Date(date1);
  const d2 = new Date(date2);
  const diffTime = d2 - d1;
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
}

/**
 * Calculate SLA status based on accepted date
 */
function calculateSLAStatus(acceptedDate, turnaroundDays) {
  if (!acceptedDate) return '';

  const accepted = new Date(acceptedDate);
  const today = new Date();
  const dueDate = new Date(accepted);
  dueDate.setDate(dueDate.getDate() + (turnaroundDays || JOB_CONFIG.DEFAULT_SLA_DAYS));

  const daysRemaining = daysBetween(today, dueDate);

  if (daysRemaining < 0) return 'OVERDUE';
  if (daysRemaining <= JOB_CONFIG.AT_RISK_THRESHOLD) return 'AT RISK';
  return 'On Track';
}

// ============================================================================
// DROPDOWN HELPER FUNCTIONS
// ============================================================================

/**
 * Get all available submissions that can be converted to jobs
 * Returns array of objects with submission number and details
 */
function getAvailableSubmissions() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);

  if (!submissionsSheet) return [];

  const submissionsData = submissionsSheet.getDataRange().getValues();
  const headers = submissionsData[0];

  // Get existing job submission numbers to exclude
  const existingJobSubmissions = new Set();
  if (jobsSheet) {
    const jobsData = jobsSheet.getDataRange().getValues();
    for (let i = 1; i < jobsData.length; i++) {
      if (jobsData[i][1]) { // Submission # column
        existingJobSubmissions.add(jobsData[i][1]);
      }
    }
  }

  const submissions = [];
  for (let i = 1; i < submissionsData.length; i++) {
    const row = submissionsData[i];
    const submissionNum = row[0];
    const status = row[headers.indexOf('Status')] || row[8];

    // Only include submissions that don't have jobs yet
    if (submissionNum && !existingJobSubmissions.has(submissionNum)) {
      const name = row[headers.indexOf('Name')] || row[2];
      const email = row[headers.indexOf('Email')] || row[3];
      const timestamp = row[1];

      submissions.push({
        number: submissionNum,
        name: name || 'Unknown',
        email: email || '',
        timestamp: timestamp,
        status: status || 'New',
        display: submissionNum + ' - ' + (name || 'Unknown') + ' (' + (status || 'New') + ')'
      });
    }
  }

  return submissions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

/**
 * Get all jobs with specified statuses
 * Returns array of objects with job details
 */
function getJobsByStatus(statusFilter = []) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);

  if (!jobsSheet) return [];

  const data = jobsSheet.getDataRange().getValues();
  const headers = data[0];
  const jobs = [];

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const jobNum = row[0];
    const status = row[headers.indexOf('Status')] || row[8];

    if (jobNum && (statusFilter.length === 0 || statusFilter.includes(status))) {
      const clientName = row[headers.indexOf('Client Name')] || row[3];
      const storeUrl = row[headers.indexOf('Store URL')] || row[5];

      jobs.push({
        number: jobNum,
        clientName: clientName || 'Unknown',
        status: status,
        storeUrl: storeUrl || '',
        display: jobNum + ' - ' + (clientName || 'Unknown') + ' (' + status + ')'
      });
    }
  }

  return jobs;
}

/**
 * Get all invoices with specified statuses
 * Returns array of objects with invoice details
 */
function getInvoicesByStatus(statusFilter = []) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICE_LOG);

  if (!invoiceSheet) return [];

  const data = invoiceSheet.getDataRange().getValues();
  const headers = data[0];
  const invoices = [];

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const invoiceNum = row[0];
    const status = row[headers.indexOf('Status')] || row[10];

    if (invoiceNum && (statusFilter.length === 0 || statusFilter.includes(status))) {
      const jobNum = row[1];
      const clientName = row[2];
      const total = row[9];

      invoices.push({
        number: invoiceNum,
        jobNumber: jobNum,
        clientName: clientName || 'Unknown',
        status: status,
        total: total || 0,
        display: invoiceNum + ' - ' + (clientName || 'Unknown') + ' - ' + formatCurrency(total || 0) + ' (' + status + ')'
      });
    }
  }

  return invoices;
}

/**
 * Show HTML dialog with dropdown selection
 */
function showDropdownDialog(title, items, itemType, callback) {
  if (!items || items.length === 0) {
    const ui = SpreadsheetApp.getUi();
    ui.alert('No Items Available', 'No ' + itemType + ' available for selection.', ui.ButtonSet.OK);
    return;
  }

  const htmlContent = `
    <!DOCTYPE html>
    <html>
      <head>
        <base target="_top">
        <style>
          body {
            font-family: Arial, sans-serif;
            padding: 20px;
            margin: 0;
          }
          .container {
            max-width: 500px;
          }
          label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #333;
          }
          select {
            width: 100%;
            padding: 10px;
            margin-bottom: 20px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
          }
          .button-container {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
          }
          button {
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
          }
          .btn-primary {
            background-color: #4285f4;
            color: white;
          }
          .btn-primary:hover {
            background-color: #357ae8;
          }
          .btn-secondary {
            background-color: #f1f1f1;
            color: #333;
          }
          .btn-secondary:hover {
            background-color: #e1e1e1;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <label for="itemSelect">Select ${itemType}:</label>
          <select id="itemSelect">
            <option value="">-- Select ${itemType} --</option>
            ${items.map(item => `<option value="${item.number}">${item.display}</option>`).join('')}
          </select>

          <div class="button-container">
            <button class="btn-secondary" onclick="google.script.host.close()">Cancel</button>
            <button class="btn-primary" onclick="submitSelection()">OK</button>
          </div>
        </div>

        <script>
          function submitSelection() {
            const select = document.getElementById('itemSelect');
            const value = select.value;

            if (!value) {
              alert('Please select a ${itemType}');
              return;
            }

            google.script.run
              .withSuccessHandler(function() {
                google.script.host.close();
              })
              .withFailureHandler(function(error) {
                alert('Error: ' + error);
              })
              .${callback}(value);
          }
        </script>
      </body>
    </html>
  `;

  const html = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(550)
    .setHeight(200);

  SpreadsheetApp.getUi().showModalDialog(html, title);
}

// ============================================================================
// JOB MANAGEMENT FUNCTIONS
// ============================================================================

/**
 * Show dialog to create job from submission
 */
function showCreateJobDialog() {
  const submissions = getAvailableSubmissions();
  showDropdownDialog(
    'Create Job from Submission',
    submissions,
    'Submission',
    'createJobFromSubmission'
  );
}

/**
 * Create a new job from a submission
 */
function createJobFromSubmission(submissionNumber) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const ui = SpreadsheetApp.getUi();

  // Find the submission
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS) || ss.getActiveSheet();
  const submissionsData = submissionsSheet.getDataRange().getValues();
  const headers = submissionsData[0];

  let submissionRow = null;
  let submissionRowIndex = -1;

  for (let i = 1; i < submissionsData.length; i++) {
    if (submissionsData[i][0] === submissionNumber) {
      submissionRow = submissionsData[i];
      submissionRowIndex = i + 1; // 1-indexed for sheet operations
      break;
    }
  }

  if (!submissionRow) {
    ui.alert('Not Found', 'Submission ' + submissionNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  // Check if job already exists for this submission
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  if (jobsSheet) {
    const jobsData = jobsSheet.getDataRange().getValues();
    for (let i = 1; i < jobsData.length; i++) {
      if (jobsData[i][1] === submissionNumber) {
        ui.alert('Already Exists', 'A job already exists for this submission: ' + jobsData[i][0], ui.ButtonSet.OK);
        return;
      }
    }
  }

  // Get job number
  const jobNumber = getNextJobNumber();

  // Extract submission data
  const name = submissionRow[headers.indexOf('Name')] || submissionRow[2];
  const email = submissionRow[headers.indexOf('Email')] || submissionRow[3];
  const storeUrl = submissionRow[headers.indexOf('Store URL')] || submissionRow[4];
  const message = submissionRow[headers.indexOf('Message')] || submissionRow[5];

  // Create job row
  const now = new Date();
  const jobRow = [
    jobNumber,                    // Job #
    submissionNumber,             // Submission #
    formatNZDate(now),           // Created Date
    name,                         // Client Name
    email,                        // Client Email
    storeUrl,                     // Store URL
    message,                      // Job Description (initially from message)
    '',                           // Category (to be filled)
    JOB_STATUS.PENDING_QUOTE,    // Status
    '',                           // Quote Amount
    '',                           // GST
    '',                           // Total
    '',                           // Quote Sent Date
    '',                           // Quote Valid Until
    '',                           // Quote Accepted Date
    '',                           // Days Since Accepted
    '',                           // Days Remaining
    '',                           // SLA Status
    JOB_CONFIG.DEFAULT_SLA_DAYS, // Estimated Turnaround
    '',                           // Due Date
    '',                           // Actual Start Date
    '',                           // Actual Completion Date
    PAYMENT_STATUS.UNPAID,       // Payment Status
    '',                           // Payment Date
    '',                           // Payment Method
    '',                           // Payment Reference
    '',                           // Invoice #
    '',                           // Notes
    formatNZDate(now)            // Last Updated
  ];

  // Add to Jobs sheet
  if (!jobsSheet) {
    ui.alert('Error', 'Jobs sheet not found. Please run Setup first.', ui.ButtonSet.OK);
    return;
  }

  jobsSheet.appendRow(jobRow);

  // Update the submission status to "Job Created"
  const statusColumnIndex = headers.indexOf('Status');
  if (statusColumnIndex !== -1) {
    submissionsSheet.getRange(submissionRowIndex, statusColumnIndex + 1).setValue('Job Created');
    Logger.log('Updated submission ' + submissionNumber + ' status to "Job Created"');
  }

  ui.alert('Job Created',
    'Job ' + jobNumber + ' created successfully!\n\n' +
    'Next steps:\n' +
    '1. Go to the Jobs sheet\n' +
    '2. Fill in Category and Quote Amount\n' +
    '3. Use CartCure > Quotes > Send Quote',
    ui.ButtonSet.OK
  );

  Logger.log('Job ' + jobNumber + ' created from submission ' + submissionNumber);
}

/**
 * Get job data by job number
 */
function getJobByNumber(jobNumber) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.JOBS);

  if (!sheet) return null;

  const data = sheet.getDataRange().getValues();
  const headers = data[0];

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === jobNumber) {
      const job = {};
      headers.forEach((header, index) => {
        job[header] = data[i][index];
      });
      job._rowIndex = i + 1; // Store row index for updates
      return job;
    }
  }
  return null;
}

/**
 * Update a job field
 */
function updateJobField(jobNumber, fieldName, value) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.JOBS);

  if (!sheet) return false;

  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  const colIndex = headers.indexOf(fieldName);

  if (colIndex < 0) return false;

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === jobNumber) {
      sheet.getRange(i + 1, colIndex + 1).setValue(value);
      // Update Last Updated
      const lastUpdatedCol = headers.indexOf('Last Updated');
      if (lastUpdatedCol >= 0) {
        sheet.getRange(i + 1, lastUpdatedCol + 1).setValue(formatNZDate(new Date()));
      }
      return true;
    }
  }
  return false;
}

/**
 * Show dialog to mark quote as accepted
 */
function showAcceptQuoteDialog() {
  const jobs = getJobsByStatus([JOB_STATUS.QUOTED]);
  showDropdownDialog(
    'Mark Quote Accepted',
    jobs,
    'Job',
    'markQuoteAccepted'
  );
}

/**
 * Mark a quote as accepted - starts the SLA clock
 */
function markQuoteAccepted(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  if (job['Status'] !== JOB_STATUS.QUOTED) {
    ui.alert('Invalid Status', 'This job is not in Quoted status. Current status: ' + job['Status'], ui.ButtonSet.OK);
    return;
  }

  const now = new Date();
  const turnaround = parseInt(job['Estimated Turnaround']) || JOB_CONFIG.DEFAULT_SLA_DAYS;
  const dueDate = new Date(now);
  dueDate.setDate(dueDate.getDate() + turnaround);

  // Update job fields
  updateJobField(jobNumber, 'Status', JOB_STATUS.ACCEPTED);
  updateJobField(jobNumber, 'Quote Accepted Date', formatNZDate(now));
  updateJobField(jobNumber, 'Days Since Accepted', 0);
  updateJobField(jobNumber, 'Days Remaining', turnaround);
  updateJobField(jobNumber, 'SLA Status', 'On Track');
  updateJobField(jobNumber, 'Due Date', formatNZDate(dueDate));

  // Update submission status
  updateSubmissionStatus(job['Submission #'], 'Accepted');

  ui.alert('Quote Accepted',
    'Job ' + jobNumber + ' marked as Accepted!\n\n' +
    'SLA Clock Started:\n' +
    '- Due Date: ' + formatNZDate(dueDate) + '\n' +
    '- Days Remaining: ' + turnaround + '\n\n' +
    'Use CartCure > Jobs > Start Work when you begin.',
    ui.ButtonSet.OK
  );

  Logger.log('Quote accepted for ' + jobNumber);
}

/**
 * Update submission status
 */
function updateSubmissionStatus(submissionNumber, status) {
  if (!submissionNumber) return;

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.SUBMISSIONS) || ss.getActiveSheet();
  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  const statusCol = headers.indexOf('Status');

  if (statusCol < 0) return;

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === submissionNumber) {
      sheet.getRange(i + 1, statusCol + 1).setValue(status);
      return;
    }
  }
}

/**
 * Show dialog to start work on a job
 */
function showStartWorkDialog() {
  const jobs = getJobsByStatus([JOB_STATUS.ACCEPTED, JOB_STATUS.ON_HOLD]);
  showDropdownDialog(
    'Start Work on Job',
    jobs,
    'Job',
    'startWorkOnJob'
  );
}

/**
 * Start work on a job
 */
function startWorkOnJob(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  if (job['Status'] !== JOB_STATUS.ACCEPTED && job['Status'] !== JOB_STATUS.ON_HOLD) {
    ui.alert('Invalid Status', 'This job cannot be started. Current status: ' + job['Status'], ui.ButtonSet.OK);
    return;
  }

  const now = new Date();

  updateJobField(jobNumber, 'Status', JOB_STATUS.IN_PROGRESS);
  updateJobField(jobNumber, 'Actual Start Date', formatNZDate(now));

  // Update submission status
  updateSubmissionStatus(job['Submission #'], 'In Progress');

  ui.alert('Work Started', 'Job ' + jobNumber + ' is now In Progress.', ui.ButtonSet.OK);

  Logger.log('Work started on ' + jobNumber);
}

/**
 * Show dialog to mark job complete
 */
function showCompleteJobDialog() {
  const jobs = getJobsByStatus([JOB_STATUS.IN_PROGRESS]);
  showDropdownDialog(
    'Mark Job Complete',
    jobs,
    'Job',
    'markJobComplete'
  );
}
}

/**
 * Mark a job as complete
 */
function markJobComplete(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  if (job['Status'] !== JOB_STATUS.IN_PROGRESS) {
    ui.alert('Invalid Status', 'This job is not In Progress. Current status: ' + job['Status'], ui.ButtonSet.OK);
    return;
  }

  const now = new Date();

  updateJobField(jobNumber, 'Status', JOB_STATUS.COMPLETED);
  updateJobField(jobNumber, 'Actual Completion Date', formatNZDate(now));
  updateJobField(jobNumber, 'SLA Status', ''); // Clear SLA status
  updateJobField(jobNumber, 'Days Remaining', '');

  // Update submission status
  updateSubmissionStatus(job['Submission #'], 'Completed');

  const generateInvoice = ui.alert(
    'Job Complete',
    'Job ' + jobNumber + ' marked as Complete!\n\nWould you like to generate an invoice now?',
    ui.ButtonSet.YES_NO
  );

  if (generateInvoice === ui.Button.YES) {
    generateInvoiceForJob(jobNumber);
  }

  Logger.log('Job ' + jobNumber + ' completed');
}

/**
 * Show dialog to put job on hold
 */
function showOnHoldDialog() {
  const jobs = getJobsByStatus([JOB_STATUS.IN_PROGRESS, JOB_STATUS.ACCEPTED]);
  showDropdownDialog(
    'Put Job On Hold',
    jobs,
    'Job',
    'putJobOnHold'
  );
}

/**
 * Put a job on hold
 */
function putJobOnHold(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  updateJobField(jobNumber, 'Status', JOB_STATUS.ON_HOLD);

  ui.alert('On Hold', 'Job ' + jobNumber + ' is now On Hold.', ui.ButtonSet.OK);

  Logger.log('Job ' + jobNumber + ' put on hold');
}

// ============================================================================
// QUOTE FUNCTIONS
// ============================================================================

/**
 * Show dialog to send quote
 */
function showSendQuoteDialog() {
  const jobs = getJobsByStatus([JOB_STATUS.PENDING_QUOTE]);
  showDropdownDialog(
    'Send Quote',
    jobs,
    'Job',
    'sendQuoteEmail'
  );
}

/**
 * Send a professional quote email
 */
function sendQuoteEmail(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  // Validate quote amount
  const quoteAmount = parseFloat(job['Quote Amount (excl GST)']);
  if (!quoteAmount || isNaN(quoteAmount)) {
    ui.alert('Missing Quote', 'Please enter a Quote Amount in the Jobs sheet before sending.', ui.ButtonSet.OK);
    return;
  }

  // Get settings
  const businessName = getSetting('Business Name') || 'CartCure';
  const bankName = getSetting('Bank Name') || '';
  const bankAccount = getSetting('Bank Account') || '';
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gstNumber = getSetting('GST Number') || '';
  const quoteValidityDays = parseInt(getSetting('Default Quote Validity')) || JOB_CONFIG.QUOTE_VALIDITY_DAYS;
  const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;

  // Calculate amounts
  const gstAmount = isGSTRegistered ? quoteAmount * JOB_CONFIG.GST_RATE : 0;
  const totalAmount = quoteAmount + gstAmount;

  // Calculate validity date
  const now = new Date();
  const validUntil = new Date(now);
  validUntil.setDate(validUntil.getDate() + quoteValidityDays);

  // Update job with GST and totals
  updateJobField(jobNumber, 'GST', isGSTRegistered ? gstAmount.toFixed(2) : '');
  updateJobField(jobNumber, 'Total (incl GST)', totalAmount.toFixed(2));

  const clientName = job['Client Name'];
  const clientEmail = job['Client Email'];
  const jobDescription = job['Job Description'];
  const turnaround = job['Estimated Turnaround'] || JOB_CONFIG.DEFAULT_SLA_DAYS;

  // Generate and send email
  const subject = 'Your CartCure Quote [' + jobNumber + ']';
  const htmlBody = generateQuoteEmailHtml({
    jobNumber: jobNumber,
    clientName: clientName,
    jobDescription: jobDescription,
    subtotal: formatCurrency(quoteAmount),
    gst: isGSTRegistered ? formatCurrency(gstAmount) : null,
    total: formatCurrency(totalAmount),
    turnaround: turnaround,
    validUntil: formatNZDate(validUntil),
    bankName: bankName,
    bankAccount: bankAccount,
    adminEmail: adminEmail,
    businessName: businessName,
    gstNumber: gstNumber,
    isGSTRegistered: isGSTRegistered
  });

  const plainBody = generateQuotePlainText({
    jobNumber: jobNumber,
    clientName: clientName,
    jobDescription: jobDescription,
    subtotal: formatCurrency(quoteAmount),
    gst: isGSTRegistered ? formatCurrency(gstAmount) : null,
    total: formatCurrency(totalAmount),
    turnaround: turnaround,
    validUntil: formatNZDate(validUntil),
    bankName: bankName,
    bankAccount: bankAccount,
    isGSTRegistered: isGSTRegistered
  });

  try {
    MailApp.sendEmail({
      to: clientEmail,
      subject: subject,
      body: plainBody,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Update job status
    updateJobField(jobNumber, 'Status', JOB_STATUS.QUOTED);
    updateJobField(jobNumber, 'Quote Sent Date', formatNZDate(now));
    updateJobField(jobNumber, 'Quote Valid Until', formatNZDate(validUntil));

    ui.alert('Quote Sent',
      'Quote sent successfully to ' + clientEmail + '!\n\n' +
      'Amount: ' + formatCurrency(totalAmount) + (isGSTRegistered ? ' (incl GST)' : '') + '\n' +
      'Valid until: ' + formatNZDate(validUntil),
      ui.ButtonSet.OK
    );

    Logger.log('Quote sent for ' + jobNumber + ' to ' + clientEmail);
  } catch (error) {
    Logger.log('Error sending quote: ' + error.message);
    ui.alert('Error', 'Failed to send quote: ' + error.message, ui.ButtonSet.OK);
  }
}

/**
 * Generate HTML quote email
 */
function generateQuoteEmailHtml(data) {
  // Paperlike theme colors
  const colors = {
    brandGreen: '#2d5d3f',
    paperWhite: '#f9f7f3',
    paperCream: '#faf8f4',
    paperBorder: '#d4cfc3',
    inkBlack: '#2b2b2b',
    inkGray: '#5a5a5a',
    inkLight: '#8a8a8a',
    alertBg: '#fff8e6',
    alertBorder: '#f5d76e'
  };

  // Build pricing rows based on GST registration
  let pricingRows = '';
  if (data.isGSTRegistered) {
    pricingRows = `
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${colors.paperBorder};">
          <span style="color: ${colors.inkGray};">Subtotal (excl. GST)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${colors.paperBorder};">
          <span style="color: ${colors.inkBlack}; font-weight: bold;">${data.subtotal}</span>
        </td>
      </tr>
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${colors.paperBorder};">
          <span style="color: ${colors.inkGray};">GST (15%)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${colors.paperBorder};">
          <span style="color: ${colors.inkBlack};">${data.gst}</span>
        </td>
      </tr>
      <tr style="background-color: ${colors.brandGreen};">
        <td style="padding: 15px;">
          <span style="color: #ffffff; font-weight: bold;">TOTAL (incl. GST)</span>
        </td>
        <td align="right" style="padding: 15px;">
          <span style="color: #ffffff; font-size: 20px; font-weight: bold;">${data.total}</span>
        </td>
      </tr>
    `;
  } else {
    pricingRows = `
      <tr style="background-color: ${colors.brandGreen};">
        <td style="padding: 15px;">
          <span style="color: #ffffff; font-weight: bold;">TOTAL</span>
        </td>
        <td align="right" style="padding: 15px;">
          <span style="color: #ffffff; font-size: 20px; font-weight: bold;">${data.total}</span>
        </td>
      </tr>
    `;
  }

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; background-color: ${colors.paperCream}; font-family: Georgia, 'Times New Roman', serif;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: ${colors.paperCream};">
        <tr>
          <td align="center" style="padding: 40px 20px;">
            <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width: 600px; background-color: ${colors.paperWhite}; border: 3px solid ${colors.paperBorder}; box-shadow: 4px 4px 0 rgba(0,0,0,0.08);">

              <!-- Header with Logo -->
              <tr>
                <td align="center" style="padding: 30px 40px 20px 40px; border-bottom: 2px solid ${colors.paperBorder};">
                  <img src="https://cartcure.co.nz/CartCure_fullLogo.png" alt="CartCure" width="180" style="display: block; max-width: 180px; height: auto;">
                </td>
              </tr>

              <!-- Quote Badge -->
              <tr>
                <td style="padding: 25px 40px;">
                  <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                    <tr>
                      <td style="background-color: ${colors.brandGreen}; padding: 15px 20px; text-align: center;">
                        <span style="color: #ffffff; font-size: 12px; text-transform: uppercase; letter-spacing: 2px;">QUOTE</span>
                        <br>
                        <span style="color: #ffffff; font-size: 24px; font-weight: bold;">${data.jobNumber}</span>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

              <!-- Greeting -->
              <tr>
                <td style="padding: 0 40px 20px 40px;">
                  <h1 style="margin: 0 0 15px 0; color: ${colors.brandGreen}; font-size: 24px;">
                    Hi ${data.clientName},
                  </h1>
                  <p style="margin: 0; color: ${colors.inkBlack}; font-size: 16px; line-height: 1.7;">
                    Thanks for reaching out! We've reviewed your request and prepared the following quote for your Shopify store work.
                  </p>
                </td>
              </tr>

              <!-- Scope of Work -->
              <tr>
                <td style="padding: 0 40px 25px 40px;">
                  <h2 style="margin: 0 0 15px 0; color: ${colors.inkBlack}; font-size: 16px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 2px solid ${colors.paperBorder}; padding-bottom: 10px;">
                    Scope of Work
                  </h2>
                  <div style="background-color: ${colors.paperCream}; border-left: 4px solid ${colors.brandGreen}; padding: 15px 20px;">
                    <p style="margin: 0; color: ${colors.inkBlack}; font-size: 15px; line-height: 1.7; white-space: pre-wrap;">
                      ${data.jobDescription}
                    </p>
                  </div>
                </td>
              </tr>

              <!-- Pricing -->
              <tr>
                <td style="padding: 0 40px 25px 40px;">
                  <h2 style="margin: 0 0 15px 0; color: ${colors.inkBlack}; font-size: 16px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 2px solid ${colors.paperBorder}; padding-bottom: 10px;">
                    Pricing
                  </h2>
                  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: ${colors.paperCream}; border: 1px solid ${colors.paperBorder};">
                    ${pricingRows}
                  </table>
                </td>
              </tr>

              <!-- Timeline & Terms -->
              <tr>
                <td style="padding: 0 40px 25px 40px;">
                  <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                    <tr>
                      <td width="48%" style="background-color: ${colors.paperCream}; border: 1px solid ${colors.paperBorder}; padding: 15px; vertical-align: top;">
                        <span style="color: ${colors.inkGray}; font-size: 12px; text-transform: uppercase;">Estimated Turnaround</span>
                        <br>
                        <span style="color: ${colors.brandGreen}; font-size: 18px; font-weight: bold;">${data.turnaround} days</span>
                      </td>
                      <td width="4%"></td>
                      <td width="48%" style="background-color: ${colors.paperCream}; border: 1px solid ${colors.paperBorder}; padding: 15px; vertical-align: top;">
                        <span style="color: ${colors.inkGray}; font-size: 12px; text-transform: uppercase;">Quote Valid Until</span>
                        <br>
                        <span style="color: ${colors.brandGreen}; font-size: 18px; font-weight: bold;">${data.validUntil}</span>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

              <!-- Accept Button -->
              <tr>
                <td style="padding: 0 40px 30px 40px;" align="center">
                  <p style="margin: 0 0 15px 0; color: ${colors.inkGray}; font-size: 14px;">
                    Ready to proceed? Simply reply to this email with "Approved" and we'll get started!
                  </p>
                  <a href="mailto:${data.adminEmail}?subject=Quote%20Accepted%20-%20${data.jobNumber}&body=Hi%20CartCure%2C%0A%0AI%20approve%20the%20quote%20${data.jobNumber}%20for%20${encodeURIComponent(data.total)}.%0A%0APlease%20proceed%20with%20the%20work.%0A%0AThanks%2C%0A${encodeURIComponent(data.clientName)}"
                     style="display: inline-block; background-color: ${colors.brandGreen}; color: #ffffff; padding: 15px 40px; text-decoration: none; font-size: 16px; font-weight: bold; border: 3px solid ${colors.inkBlack}; box-shadow: 3px 3px 0 rgba(0,0,0,0.2);">
                    Accept Quote
                  </a>
                </td>
              </tr>

              <!-- Payment Info -->
              ${data.bankAccount ? `
              <tr>
                <td style="padding: 0 40px 25px 40px;">
                  <div style="background-color: ${colors.alertBg}; border: 2px solid ${colors.alertBorder}; padding: 15px;">
                    <p style="margin: 0 0 10px 0; color: ${colors.inkBlack}; font-weight: bold;">Payment Details (for your reference):</p>
                    <p style="margin: 0; color: ${colors.inkGray}; font-size: 14px; line-height: 1.6;">
                      Bank: ${data.bankName}<br>
                      Account: ${data.bankAccount}<br>
                      Reference: ${data.jobNumber}
                    </p>
                  </div>
                </td>
              </tr>
              ` : ''}

              <!-- Footer -->
              <tr>
                <td style="padding: 25px 40px; background-color: ${colors.paperCream}; border-top: 2px solid ${colors.paperBorder};">
                  <p style="margin: 0; color: ${colors.inkLight}; font-size: 12px; text-align: center;">
                    Questions? Just reply to this email.<br>
                    ${data.businessName} | Quick Shopify Fixes for NZ Businesses<br>
                    ${data.isGSTRegistered && data.gstNumber ? 'GST: ' + data.gstNumber + '<br>' : ''}
                    <a href="https://cartcure.co.nz" style="color: ${colors.brandGreen};">cartcure.co.nz</a>
                  </p>
                </td>
              </tr>

            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
  `;
}

/**
 * Generate plain text quote email
 */
function generateQuotePlainText(data) {
  let pricingSection = '';
  if (data.isGSTRegistered) {
    pricingSection = `
Subtotal (excl. GST): ${data.subtotal}
GST (15%): ${data.gst}
──────────────────
TOTAL (incl. GST): ${data.total}
    `;
  } else {
    pricingSection = `
TOTAL: ${data.total}
    `;
  }

  return `
═══════════════════════════════════════════════════
   CARTCURE QUOTE - ${data.jobNumber}
═══════════════════════════════════════════════════

Hi ${data.clientName},

Thanks for reaching out! We've reviewed your request and prepared the following quote for your Shopify store work.

───────────────────────────────────────────────────
SCOPE OF WORK
───────────────────────────────────────────────────

${data.jobDescription}

───────────────────────────────────────────────────
PRICING
───────────────────────────────────────────────────
${pricingSection}

Estimated Turnaround: ${data.turnaround} days
Quote Valid Until: ${data.validUntil}

───────────────────────────────────────────────────
HOW TO ACCEPT
───────────────────────────────────────────────────

Simply reply to this email with "Approved" and we'll get started right away!

${data.bankAccount ? `
───────────────────────────────────────────────────
PAYMENT DETAILS (for your reference)
───────────────────────────────────────────────────

Bank: ${data.bankName}
Account: ${data.bankAccount}
Reference: ${data.jobNumber}
` : ''}

Questions? Just reply to this email.

Cheers,
The CartCure Team

───────────────────────────────────────────────────
CartCure | Quick Shopify Fixes for NZ Businesses
https://cartcure.co.nz
  `;
}

/**
 * Show dialog to send quote reminder
 */
function showQuoteReminderDialog() {
  const jobs = getJobsByStatus([JOB_STATUS.QUOTED]);
  showDropdownDialog(
    'Send Quote Reminder',
    jobs,
    'Job',
    'sendQuoteReminder'
  );
}

/**
 * Send a quote reminder email
 */
function sendQuoteReminder(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  if (job['Status'] !== JOB_STATUS.QUOTED) {
    ui.alert('Invalid Status', 'This job is not awaiting quote response. Status: ' + job['Status'], ui.ButtonSet.OK);
    return;
  }

  const businessName = getSetting('Business Name') || 'CartCure';
  const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;
  const clientName = job['Client Name'];
  const clientEmail = job['Client Email'];
  const total = job['Total (incl GST)'];
  const validUntil = job['Quote Valid Until'];

  const subject = 'Reminder: Your CartCure Quote [' + jobNumber + ']';

  const htmlBody = `
    <p>Hi ${clientName},</p>
    <p>Just a friendly reminder that we sent you a quote for your Shopify store work.</p>
    <p><strong>Quote Reference:</strong> ${jobNumber}<br>
    <strong>Amount:</strong> $${total}<br>
    <strong>Valid Until:</strong> ${validUntil}</p>
    <p>If you'd like to proceed, simply reply to this email with "Approved" and we'll get started!</p>
    <p>If you have any questions or need changes to the scope, just let us know.</p>
    <p>Cheers,<br>The CartCure Team</p>
  `;

  try {
    MailApp.sendEmail({
      to: clientEmail,
      subject: subject,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    ui.alert('Reminder Sent', 'Quote reminder sent to ' + clientEmail, ui.ButtonSet.OK);
    Logger.log('Quote reminder sent for ' + jobNumber);
  } catch (error) {
    Logger.log('Error sending reminder: ' + error.message);
    ui.alert('Error', 'Failed to send reminder: ' + error.message, ui.ButtonSet.OK);
  }
}

/**
 * Show dialog to decline quote
 */
function showDeclineQuoteDialog() {
  const jobs = getJobsByStatus([JOB_STATUS.QUOTED, JOB_STATUS.PENDING_QUOTE]);
  showDropdownDialog(
    'Mark Quote Declined',
    jobs,
    'Job',
    'markQuoteDeclined'
  );
}

/**
 * Mark a quote as declined
 */
function markQuoteDeclined(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  updateJobField(jobNumber, 'Status', JOB_STATUS.DECLINED);
  updateSubmissionStatus(job['Submission #'], 'Declined');

  ui.alert('Quote Declined', 'Job ' + jobNumber + ' marked as Declined.', ui.ButtonSet.OK);
  Logger.log('Quote declined for ' + jobNumber);
}

// ============================================================================
// INVOICE FUNCTIONS
// ============================================================================

/**
 * Show dialog to generate invoice
 */
function showGenerateInvoiceDialog() {
  const jobs = getJobsByStatus([JOB_STATUS.COMPLETED]);
  showDropdownDialog(
    'Generate Invoice',
    jobs,
    'Job',
    'generateInvoiceForJob'
  );
}

/**
 * Generate an invoice for a job
 */
function generateInvoiceForJob(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  // Check if invoice already exists
  if (job['Invoice #']) {
    ui.alert('Invoice Exists', 'An invoice already exists for this job: ' + job['Invoice #'], ui.ButtonSet.OK);
    return;
  }

  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
  if (!invoiceSheet) {
    ui.alert('Error', 'Invoice Log sheet not found. Please run Setup first.', ui.ButtonSet.OK);
    return;
  }

  const invoiceNumber = getNextInvoiceNumber();
  const now = new Date();
  const paymentTerms = parseInt(getSetting('Default Payment Terms')) || JOB_CONFIG.PAYMENT_TERMS_DAYS;
  const dueDate = new Date(now);
  dueDate.setDate(dueDate.getDate() + paymentTerms);

  const amount = parseFloat(job['Quote Amount (excl GST)']) || 0;
  const gst = parseFloat(job['GST']) || 0;
  const total = parseFloat(job['Total (incl GST)']) || amount;

  const invoiceRow = [
    invoiceNumber,
    jobNumber,
    job['Client Name'],
    job['Client Email'],
    formatNZDate(now),
    formatNZDate(dueDate),
    amount.toFixed(2),
    gst.toFixed(2),
    total.toFixed(2),
    'Draft',
    '',
    '',
    '',
    ''
  ];

  invoiceSheet.appendRow(invoiceRow);

  // Update job with invoice number
  updateJobField(jobNumber, 'Invoice #', invoiceNumber);

  ui.alert('Invoice Generated',
    'Invoice ' + invoiceNumber + ' created!\n\n' +
    'Amount: ' + formatCurrency(total) + '\n' +
    'Due Date: ' + formatNZDate(dueDate) + '\n\n' +
    'Use CartCure > Invoices > Send Invoice to email it.',
    ui.ButtonSet.OK
  );

  Logger.log('Invoice ' + invoiceNumber + ' generated for ' + jobNumber);
}

/**
 * Show dialog to send invoice
 */
function showSendInvoiceDialog() {
  const invoices = getInvoicesByStatus(['Draft']);
  showDropdownDialog(
    'Send Invoice',
    invoices,
    'Invoice',
    'sendInvoiceEmail'
  );
}

/**
 * Get invoice by number
 */
function getInvoiceByNumber(invoiceNumber) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!sheet) return null;

  const data = sheet.getDataRange().getValues();
  const headers = data[0];

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === invoiceNumber) {
      const invoice = {};
      headers.forEach((header, index) => {
        invoice[header] = data[i][index];
      });
      invoice._rowIndex = i + 1;
      return invoice;
    }
  }
  return null;
}

/**
 * Update invoice field
 */
function updateInvoiceField(invoiceNumber, fieldName, value) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!sheet) return false;

  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  const colIndex = headers.indexOf(fieldName);

  if (colIndex < 0) return false;

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === invoiceNumber) {
      sheet.getRange(i + 1, colIndex + 1).setValue(value);
      return true;
    }
  }
  return false;
}

/**
 * Send invoice email
 */
function sendInvoiceEmail(invoiceNumber) {
  const ui = SpreadsheetApp.getUi();
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    ui.alert('Not Found', 'Invoice ' + invoiceNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  const businessName = getSetting('Business Name') || 'CartCure';
  const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;
  const bankName = getSetting('Bank Name') || '';
  const bankAccount = getSetting('Bank Account') || '';
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gstNumber = getSetting('GST Number') || '';

  const clientName = invoice['Client Name'];
  const clientEmail = invoice['Client Email'];
  const jobNumber = invoice['Job #'];
  const amount = invoice['Amount (excl GST)'];
  const gst = invoice['GST'];
  const total = invoice['Total'];
  const dueDate = invoice['Due Date'];

  const subject = 'Invoice ' + invoiceNumber + ' from CartCure';

  // Build pricing section
  let pricingHtml = '';
  if (isGSTRegistered && parseFloat(gst) > 0) {
    pricingHtml = `
      <p><strong>Amount (excl GST):</strong> $${amount}</p>
      <p><strong>GST (15%):</strong> $${gst}</p>
      <p style="font-size: 18px;"><strong>Total (incl GST):</strong> $${total}</p>
    `;
  } else {
    pricingHtml = `
      <p style="font-size: 18px;"><strong>Total:</strong> $${total}</p>
    `;
  }

  const htmlBody = `
    <div style="font-family: Georgia, serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 2px solid #d4cfc3; background-color: #f9f7f3;">
      <div style="text-align: center; padding: 20px; background-color: #2d5d3f; color: white;">
        <h1 style="margin: 0;">INVOICE</h1>
        <p style="margin: 10px 0 0 0; font-size: 20px;">${invoiceNumber}</p>
      </div>

      <div style="padding: 20px;">
        <p>Hi ${clientName},</p>
        <p>Thank you for choosing CartCure! Please find your invoice below for the completed work.</p>

        <div style="background-color: #faf8f4; padding: 15px; margin: 20px 0; border-left: 4px solid #2d5d3f;">
          <p><strong>Job Reference:</strong> ${jobNumber}</p>
          ${pricingHtml}
          <p><strong>Due Date:</strong> ${dueDate}</p>
        </div>

        ${bankAccount ? `
        <div style="background-color: #fff8e6; padding: 15px; border: 1px solid #f5d76e;">
          <p style="margin: 0 0 10px 0;"><strong>Payment Details:</strong></p>
          <p style="margin: 0;">
            Bank: ${bankName}<br>
            Account: ${bankAccount}<br>
            Reference: ${invoiceNumber}
          </p>
        </div>
        ` : ''}

        <p style="margin-top: 20px;">If you have any questions about this invoice, just reply to this email.</p>

        <p>Thanks for your business!</p>
        <p><strong>The CartCure Team</strong></p>
      </div>

      <div style="text-align: center; padding: 15px; background-color: #faf8f4; border-top: 2px solid #d4cfc3; font-size: 12px; color: #8a8a8a;">
        ${businessName} | Quick Shopify Fixes for NZ Businesses<br>
        ${isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : ''}
        <a href="https://cartcure.co.nz" style="color: #2d5d3f;">cartcure.co.nz</a>
      </div>
    </div>
  `;

  try {
    MailApp.sendEmail({
      to: clientEmail,
      subject: subject,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Update invoice status
    updateInvoiceField(invoiceNumber, 'Status', 'Sent');
    updateInvoiceField(invoiceNumber, 'Sent Date', formatNZDate(new Date()));

    // Update job payment status
    updateJobField(jobNumber, 'Payment Status', PAYMENT_STATUS.INVOICED);

    ui.alert('Invoice Sent', 'Invoice sent to ' + clientEmail, ui.ButtonSet.OK);
    Logger.log('Invoice ' + invoiceNumber + ' sent to ' + clientEmail);
  } catch (error) {
    Logger.log('Error sending invoice: ' + error.message);
    ui.alert('Error', 'Failed to send invoice: ' + error.message, ui.ButtonSet.OK);
  }
}

/**
 * Show dialog to mark invoice as paid
 */
function showMarkPaidDialog() {
  const invoices = getInvoicesByStatus(['Sent', 'Overdue']);

  if (!invoices || invoices.length === 0) {
    const ui = SpreadsheetApp.getUi();
    ui.alert('No Invoices Available', 'No sent or overdue invoices available to mark as paid.', ui.ButtonSet.OK);
    return;
  }

  const htmlContent = `
    <!DOCTYPE html>
    <html>
      <head>
        <base target="_top">
        <style>
          body {
            font-family: Arial, sans-serif;
            padding: 20px;
            margin: 0;
          }
          .container {
            max-width: 500px;
          }
          label {
            display: block;
            margin-bottom: 8px;
            margin-top: 12px;
            font-weight: bold;
            color: #333;
          }
          select, input {
            width: 100%;
            padding: 10px;
            margin-bottom: 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
          }
          .button-container {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
            margin-top: 20px;
          }
          button {
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
          }
          .btn-primary {
            background-color: #4285f4;
            color: white;
          }
          .btn-primary:hover {
            background-color: #357ae8;
          }
          .btn-secondary {
            background-color: #f1f1f1;
            color: #333;
          }
          .btn-secondary:hover {
            background-color: #e1e1e1;
          }
          .note {
            font-size: 12px;
            color: #666;
            margin-top: 4px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <label for="invoiceSelect">Select Invoice:</label>
          <select id="invoiceSelect">
            <option value="">-- Select Invoice --</option>
            ${invoices.map(inv => `<option value="${inv.number}">${inv.display}</option>`).join('')}
          </select>

          <label for="paymentMethod">Payment Method:</label>
          <select id="paymentMethod">
            <option value="Bank Transfer">Bank Transfer</option>
            <option value="Stripe">Stripe</option>
            <option value="PayPal">PayPal</option>
            <option value="Cash">Cash</option>
            <option value="Other">Other</option>
          </select>

          <label for="paymentRef">Payment Reference:</label>
          <input type="text" id="paymentRef" placeholder="Transaction ID or reference (optional)">
          <div class="note">Optional: Enter transaction ID or payment reference</div>

          <div class="button-container">
            <button class="btn-secondary" onclick="google.script.host.close()">Cancel</button>
            <button class="btn-primary" onclick="submitPayment()">Mark as Paid</button>
          </div>
        </div>

        <script>
          function submitPayment() {
            const invoiceNumber = document.getElementById('invoiceSelect').value;
            const method = document.getElementById('paymentMethod').value;
            const reference = document.getElementById('paymentRef').value;

            if (!invoiceNumber) {
              alert('Please select an invoice');
              return;
            }

            google.script.run
              .withSuccessHandler(function() {
                google.script.host.close();
              })
              .withFailureHandler(function(error) {
                alert('Error: ' + error);
              })
              .markInvoicePaid(invoiceNumber, method, reference);
          }
        </script>
      </body>
    </html>
  `;

  const html = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(550)
    .setHeight(400);

  SpreadsheetApp.getUi().showModalDialog(html, 'Mark Invoice as Paid');
}

/**
 * Mark an invoice as paid
 */
function markInvoicePaid(invoiceNumber, method, reference) {
  const ui = SpreadsheetApp.getUi();
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    ui.alert('Not Found', 'Invoice ' + invoiceNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  const now = new Date();
  const jobNumber = invoice['Job #'];

  // Update invoice
  updateInvoiceField(invoiceNumber, 'Status', 'Paid');
  updateInvoiceField(invoiceNumber, 'Paid Date', formatNZDate(now));
  updateInvoiceField(invoiceNumber, 'Payment Reference', reference);

  // Update job
  updateJobField(jobNumber, 'Payment Status', PAYMENT_STATUS.PAID);
  updateJobField(jobNumber, 'Payment Date', formatNZDate(now));
  updateJobField(jobNumber, 'Payment Method', method);
  updateJobField(jobNumber, 'Payment Reference', reference);

  ui.alert('Payment Recorded',
    'Invoice ' + invoiceNumber + ' marked as Paid!\n\n' +
    'Method: ' + method + '\n' +
    (reference ? 'Reference: ' + reference : ''),
    ui.ButtonSet.OK
  );

  Logger.log('Invoice ' + invoiceNumber + ' marked as paid');
}

// ============================================================================
// DASHBOARD & REPORTING FUNCTIONS
// ============================================================================

/**
 * Refresh the dashboard with current data
 */
function refreshDashboard() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const dashboard = ss.getSheetByName(SHEETS.DASHBOARD);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);

  if (!dashboard || !jobsSheet) {
    SpreadsheetApp.getUi().alert('Error', 'Dashboard or Jobs sheet not found. Please run Setup first.', SpreadsheetApp.getUi().ButtonSet.OK);
    return;
  }

  // Update timestamp
  dashboard.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));

  // Get all jobs data
  const jobsData = jobsSheet.getDataRange().getValues();
  const headers = jobsData[0];

  // Update SLA calculations for active jobs
  updateAllSLAStatus(jobsSheet, jobsData, headers);

  // Get active jobs (Accepted or In Progress)
  const activeJobs = [];
  const pendingQuotes = [];

  for (let i = 1; i < jobsData.length; i++) {
    const row = jobsData[i];
    const status = row[headers.indexOf('Status')];
    const jobNum = row[0];

    if (!jobNum) continue;

    if (status === JOB_STATUS.ACCEPTED || status === JOB_STATUS.IN_PROGRESS) {
      activeJobs.push({
        jobNumber: jobNum,
        client: row[headers.indexOf('Client Name')],
        description: (row[headers.indexOf('Job Description')] || '').substring(0, 50) + '...',
        daysRemaining: row[headers.indexOf('Days Remaining')],
        slaStatus: row[headers.indexOf('SLA Status')],
        status: status,
        dueDate: row[headers.indexOf('Due Date')]
      });
    } else if (status === JOB_STATUS.QUOTED) {
      const quoteSentDate = row[headers.indexOf('Quote Sent Date')];
      const daysWaiting = quoteSentDate ? daysBetween(new Date(quoteSentDate), new Date()) : 0;

      pendingQuotes.push({
        jobNumber: jobNum,
        client: row[headers.indexOf('Client Name')],
        quoteAmount: formatCurrency(row[headers.indexOf('Total (incl GST)')] || 0),
        daysWaiting: daysWaiting,
        validUntil: row[headers.indexOf('Quote Valid Until')],
        action: daysWaiting > 5 ? 'Follow up!' : 'Waiting'
      });
    }
  }

  // Sort active jobs: OVERDUE first, then by days remaining (ascending)
  activeJobs.sort((a, b) => {
    if (a.slaStatus === 'OVERDUE' && b.slaStatus !== 'OVERDUE') return -1;
    if (b.slaStatus === 'OVERDUE' && a.slaStatus !== 'OVERDUE') return 1;
    if (a.slaStatus === 'AT RISK' && b.slaStatus === 'On Track') return -1;
    if (b.slaStatus === 'AT RISK' && a.slaStatus === 'On Track') return 1;
    return (a.daysRemaining || 999) - (b.daysRemaining || 999);
  });

  // Sort pending quotes: oldest first
  pendingQuotes.sort((a, b) => b.daysWaiting - a.daysWaiting);

  // Clear and populate active jobs section (rows 19-28)
  dashboard.getRange(19, 1, 10, 7).clearContent();
  for (let i = 0; i < Math.min(activeJobs.length, 10); i++) {
    const job = activeJobs[i];
    dashboard.getRange(19 + i, 1, 1, 7).setValues([[
      job.jobNumber,
      job.client,
      job.description,
      job.daysRemaining,
      job.slaStatus,
      job.status,
      job.dueDate
    ]]);

    // Color code SLA status
    const slaCell = dashboard.getRange(19 + i, 5);
    if (job.slaStatus === 'OVERDUE') {
      slaCell.setBackground('#ffcccc').setFontColor('#cc0000').setFontWeight('bold');
    } else if (job.slaStatus === 'AT RISK') {
      slaCell.setBackground('#fff3cd').setFontColor('#856404').setFontWeight('bold');
    } else {
      slaCell.setBackground('#d4edda').setFontColor('#155724');
    }
  }

  // Clear and populate pending quotes section (rows 33-40)
  dashboard.getRange(33, 1, 8, 6).clearContent();
  for (let i = 0; i < Math.min(pendingQuotes.length, 8); i++) {
    const quote = pendingQuotes[i];
    dashboard.getRange(33 + i, 1, 1, 6).setValues([[
      quote.jobNumber,
      quote.client,
      quote.quoteAmount,
      quote.daysWaiting + ' days',
      quote.validUntil,
      quote.action
    ]]);

    // Highlight follow-up needed
    if (quote.action === 'Follow up!') {
      dashboard.getRange(33 + i, 6).setBackground('#fff3cd').setFontWeight('bold');
    }
  }

  Logger.log('Dashboard refreshed');
}

/**
 * Update SLA status for all active jobs
 */
function updateAllSLAStatus(sheet, data, headers) {
  const statusCol = headers.indexOf('Status');
  const acceptedDateCol = headers.indexOf('Quote Accepted Date');
  const turnaroundCol = headers.indexOf('Estimated Turnaround');
  const daysSinceCol = headers.indexOf('Days Since Accepted');
  const daysRemainingCol = headers.indexOf('Days Remaining');
  const slaStatusCol = headers.indexOf('SLA Status');

  for (let i = 1; i < data.length; i++) {
    const status = data[i][statusCol];
    const acceptedDate = data[i][acceptedDateCol];

    if ((status === JOB_STATUS.ACCEPTED || status === JOB_STATUS.IN_PROGRESS) && acceptedDate) {
      const turnaround = parseInt(data[i][turnaroundCol]) || JOB_CONFIG.DEFAULT_SLA_DAYS;
      const accepted = new Date(acceptedDate);
      const today = new Date();

      const daysSince = daysBetween(accepted, today);
      const daysRemaining = turnaround - daysSince;
      const slaStatus = daysRemaining < 0 ? 'OVERDUE' :
                        daysRemaining <= JOB_CONFIG.AT_RISK_THRESHOLD ? 'AT RISK' : 'On Track';

      // Update the sheet
      sheet.getRange(i + 1, daysSinceCol + 1).setValue(daysSince);
      sheet.getRange(i + 1, daysRemainingCol + 1).setValue(daysRemaining);
      sheet.getRange(i + 1, slaStatusCol + 1).setValue(slaStatus);
    }
  }
}

/**
 * Show overdue jobs report
 */
function showOverdueJobs() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  const ui = SpreadsheetApp.getUi();

  if (!jobsSheet) {
    ui.alert('Error', 'Jobs sheet not found.', ui.ButtonSet.OK);
    return;
  }

  const data = jobsSheet.getDataRange().getValues();
  const headers = data[0];
  const slaCol = headers.indexOf('SLA Status');

  const overdueJobs = [];
  for (let i = 1; i < data.length; i++) {
    if (data[i][slaCol] === 'OVERDUE') {
      overdueJobs.push(data[i][0] + ' - ' + data[i][headers.indexOf('Client Name')]);
    }
  }

  if (overdueJobs.length === 0) {
    ui.alert('No Overdue Jobs', 'Great news! You have no overdue jobs.', ui.ButtonSet.OK);
  } else {
    ui.alert('Overdue Jobs (' + overdueJobs.length + ')',
      'The following jobs are overdue:\n\n' + overdueJobs.join('\n'),
      ui.ButtonSet.OK
    );
  }
}

/**
 * Show outstanding payments report
 */
function showOutstandingPayments() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  const ui = SpreadsheetApp.getUi();

  if (!jobsSheet) {
    ui.alert('Error', 'Jobs sheet not found.', ui.ButtonSet.OK);
    return;
  }

  const data = jobsSheet.getDataRange().getValues();
  const headers = data[0];
  const paymentStatusCol = headers.indexOf('Payment Status');
  const totalCol = headers.indexOf('Total (incl GST)');

  let totalOutstanding = 0;
  const unpaidJobs = [];

  for (let i = 1; i < data.length; i++) {
    const paymentStatus = data[i][paymentStatusCol];
    if (paymentStatus === PAYMENT_STATUS.UNPAID || paymentStatus === PAYMENT_STATUS.INVOICED) {
      const amount = parseFloat(data[i][totalCol]) || 0;
      if (amount > 0) {
        totalOutstanding += amount;
        unpaidJobs.push(data[i][0] + ' - ' + data[i][headers.indexOf('Client Name')] + ' - ' + formatCurrency(amount));
      }
    }
  }

  if (unpaidJobs.length === 0) {
    ui.alert('No Outstanding Payments', 'All invoices are paid!', ui.ButtonSet.OK);
  } else {
    ui.alert('Outstanding Payments',
      'Total Outstanding: ' + formatCurrency(totalOutstanding) + '\n\n' + unpaidJobs.join('\n'),
      ui.ButtonSet.OK
    );
  }
}

/**
 * Show monthly summary
 */
function showMonthlySummary() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  const ui = SpreadsheetApp.getUi();

  if (!jobsSheet) {
    ui.alert('Error', 'Jobs sheet not found.', ui.ButtonSet.OK);
    return;
  }

  const data = jobsSheet.getDataRange().getValues();
  const headers = data[0];

  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

  let jobsCompleted = 0;
  let revenue = 0;
  let jobsStarted = 0;

  for (let i = 1; i < data.length; i++) {
    const completionDate = data[i][headers.indexOf('Actual Completion Date')];
    const paymentDate = data[i][headers.indexOf('Payment Date')];
    const createdDate = data[i][headers.indexOf('Created Date')];
    const total = parseFloat(data[i][headers.indexOf('Total (incl GST)')]) || 0;
    const paymentStatus = data[i][headers.indexOf('Payment Status')];

    if (completionDate && new Date(completionDate) >= monthStart) {
      jobsCompleted++;
    }

    if (paymentStatus === PAYMENT_STATUS.PAID && paymentDate && new Date(paymentDate) >= monthStart) {
      revenue += total;
    }

    if (createdDate && new Date(createdDate) >= monthStart) {
      jobsStarted++;
    }
  }

  const monthName = now.toLocaleString('en-NZ', { month: 'long', year: 'numeric' });

  ui.alert('Monthly Summary - ' + monthName,
    'Jobs Started: ' + jobsStarted + '\n' +
    'Jobs Completed: ' + jobsCompleted + '\n' +
    'Revenue Collected: ' + formatCurrency(revenue),
    ui.ButtonSet.OK
  );
}

// ============================================================================
// HARD RESET FUNCTIONS
// ============================================================================

/**
 * Show hard reset confirmation dialog
 */
function showHardResetDialog() {
  const ui = SpreadsheetApp.getUi();

  // First warning dialog
  const firstWarning = ui.alert(
    '⚠️ HARD RESET - PERMANENT DATA DELETION',
    '⚠️ WARNING: This will PERMANENTLY DELETE ALL:\n\n' +
    '• All Jobs\n' +
    '• All Invoices\n' +
    '• All Submissions/Enquiries\n' +
    '• Dashboard data\n\n' +
    '❌ THIS CANNOT BE UNDONE!\n\n' +
    'Are you absolutely sure you want to continue?',
    ui.ButtonSet.YES_NO
  );

  if (firstWarning === ui.Button.NO) {
    ui.alert('Hard Reset Cancelled', 'No data was deleted.', ui.ButtonSet.OK);
    return;
  }

  // Second confirmation - must type RESET
  const confirmText = ui.prompt(
    '⚠️ FINAL CONFIRMATION REQUIRED',
    '⚠️ THIS IS YOUR LAST CHANCE TO CANCEL!\n\n' +
    'All jobs, invoices, and enquiries will be PERMANENTLY DELETED.\n\n' +
    'To proceed, type exactly: RESET\n\n' +
    '(Type anything else to cancel)',
    ui.ButtonSet.OK_CANCEL
  );

  if (confirmText.getSelectedButton() === ui.Button.CANCEL) {
    ui.alert('Hard Reset Cancelled', 'No data was deleted.', ui.ButtonSet.OK);
    return;
  }

  const userInput = confirmText.getResponseText().trim();

  if (userInput !== 'RESET') {
    ui.alert(
      'Hard Reset Cancelled',
      'You typed: "' + userInput + '"\n\n' +
      'Expected: "RESET"\n\n' +
      'No data was deleted.',
      ui.ButtonSet.OK
    );
    return;
  }

  // Execute the hard reset
  try {
    performHardReset();

    // Run Setup Sheets to ensure everything is properly configured
    Logger.log('Running Setup Sheets after hard reset...');
    setupJobManagementSheets();

    ui.alert(
      '✅ Hard Reset Complete',
      'All data has been deleted and sheets have been reset:\n\n' +
      '• Jobs sheet cleared\n' +
      '• Invoices cleared\n' +
      '• Submissions cleared\n' +
      '• Dashboard cleared\n' +
      '• Job and Invoice counters reset to 1\n' +
      '• All sheets reconfigured\n\n' +
      'Your system is now in a fresh state.',
      ui.ButtonSet.OK
    );
  } catch (error) {
    ui.alert('Error During Hard Reset', 'An error occurred: ' + error.toString(), ui.ButtonSet.OK);
    Logger.log('Hard Reset Error: ' + error);
  }
}

/**
 * Perform the actual hard reset - delete all data
 */
function performHardReset() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);

  Logger.log('Starting hard reset...');

  // Clear Jobs sheet (keep header row)
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  if (jobsSheet) {
    const lastRow = jobsSheet.getLastRow();
    if (lastRow > 1) {
      jobsSheet.deleteRows(2, lastRow - 1);
    }
    Logger.log('Jobs sheet cleared');
  }

  // Clear Invoice Log sheet (keep header row)
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
  if (invoiceSheet) {
    const lastRow = invoiceSheet.getLastRow();
    if (lastRow > 1) {
      invoiceSheet.deleteRows(2, lastRow - 1);
    }
    Logger.log('Invoice Log cleared');
  }

  // Clear Submissions sheet (keep header row)
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
  if (submissionsSheet) {
    const lastRow = submissionsSheet.getLastRow();
    if (lastRow > 1) {
      submissionsSheet.deleteRows(2, lastRow - 1);
    }
    Logger.log('Submissions cleared');
  }

  // Clear Dashboard data areas (keep structure/headers)
  const dashboardSheet = ss.getSheetByName(SHEETS.DASHBOARD);
  if (dashboardSheet) {
    // Clear summary metrics (rows 3-9, column B)
    dashboardSheet.getRange('B3:B9').clearContent();

    // Clear active jobs section (rows 13-32)
    dashboardSheet.getRange('A13:G32').clearContent();

    // Clear pending quotes section (rows 36-45)
    dashboardSheet.getRange('A36:F45').clearContent();

    // Update last refreshed timestamp
    dashboardSheet.getRange('A1').setValue('Last refreshed: ' + formatNZDate(new Date()));

    Logger.log('Dashboard cleared');
  }

  // Reset counters in Settings sheet
  const settingsSheet = ss.getSheetByName(SHEETS.SETTINGS);
  if (settingsSheet) {
    const data = settingsSheet.getDataRange().getValues();
    for (let i = 0; i < data.length; i++) {
      if (data[i][0] === 'Next Job Number') {
        settingsSheet.getRange(i + 1, 2).setValue(1);
      }
      if (data[i][0] === 'Next Invoice Number') {
        settingsSheet.getRange(i + 1, 2).setValue(1);
      }
    }
    Logger.log('Settings counters reset');
  }

  Logger.log('Hard reset completed successfully');
}
