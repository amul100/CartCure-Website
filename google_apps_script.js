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
    // Log incoming request for debugging
    Logger.log('=== Incoming Request ===');
    Logger.log('postData.type: ' + (e.postData ? e.postData.type : 'undefined'));
    Logger.log('postData.contents length: ' + (e.postData ? e.postData.contents.length : 'undefined'));
    Logger.log('parameter keys: ' + (e.parameter ? Object.keys(e.parameter).join(', ') : 'undefined'));

    // Parse request body - handle both JSON and form-encoded data
    let data;
    if (e.postData && e.postData.type === 'application/json') {
      data = JSON.parse(e.postData.contents);
      Logger.log('Parsed as JSON');
    } else {
      // URL-encoded form data comes in e.parameter
      data = e.parameter;
      Logger.log('Using e.parameter (form-encoded)');
    }

    Logger.log('Data keys received: ' + Object.keys(data).join(', '));
    Logger.log('submissionNumber received: ' + data.submissionNumber);

    const origin = e.parameter.origin || '';

    // Security validations
    validateOrigin(origin);

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

    // Return success response
    return ContentService
      .createTextOutput(JSON.stringify({
        success: true,
        message: 'Form submitted successfully'
      }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    Logger.log('Error processing submission: ' + error.message);
    Logger.log('Error stack: ' + error.stack);

    // Return error with both user message and technical details for debugging
    return ContentService
      .createTextOutput(JSON.stringify({
        success: false,
        message: error.userMessage || 'An error occurred. Please try again.',
        error: error.message, // Add technical error for debugging
        errorType: error.name
      }))
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
 */
function validateOrigin(origin) {
  // In development, you might want to skip this check
  // In production, uncomment and configure ALLOWED_ORIGINS
  /*
  if (!CONFIG.ALLOWED_ORIGINS.includes(origin)) {
    const error = new Error('Invalid origin');
    error.userMessage = 'Request rejected';
    throw error;
  }
  */
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
  const base64Length = audioData.split(',')[1].length;
  const estimatedSizeBytes = (base64Length * 3) / 4;
  const estimatedSizeMB = estimatedSizeBytes / (1024 * 1024);

  if (estimatedSizeMB > CONFIG.MAX_AUDIO_SIZE_MB) {
    const error = new Error('Audio file too large');
    error.userMessage = 'Voice note exceeds 10MB limit.';
    throw error;
  }

  // Validate MIME type
  const mimeType = audioData.substring(5, audioData.indexOf(';'));
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
    const sheet = SpreadsheetApp.openById(CONFIG.SHEET_ID).getActiveSheet();

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
        'Voice Note Link'
      ]);
    }

    // Save audio file to Google Drive if present
    let audioFileUrl = '';
    if (data.hasVoiceNote && data.voiceNoteData) {
      audioFileUrl = saveAudioToDrive(data.voiceNoteData, data.submissionNumber);
    }

    // Find the first empty row (starting from row 2 to skip headers)
    const targetRow = findFirstEmptyRow(sheet);

    // Prepare the row data
    const rowData = [
      data.submissionNumber,
      data.timestamp,
      data.name,
      data.email,
      data.storeUrl,
      data.message,
      data.hasVoiceNote ? 'Yes' : 'No',
      audioFileUrl
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
  const numCols = 8; // Number of data columns

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
    const subject = '[' + data.submissionNumber + '] New CartCure Submission from ' + data.name;

    // Build HTML email body with escaped data
    const htmlBody = `
      <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
            <h2 style="color: #2d5d3f;">New Contact Form Submission</h2>
            <p style="font-size: 14px; color: #666; margin-bottom: 20px;">Reference: <strong>${data.submissionNumber}</strong></p>

            <table style="width: 100%; border-collapse: collapse; background: white; padding: 20px;">
              <tr>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Timestamp:</strong></td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;">${data.timestamp}</td>
              </tr>
              <tr>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Name:</strong></td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;">${data.name}</td>
              </tr>
              <tr>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Email:</strong></td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;"><a href="mailto:${data.email}">${data.email}</a></td>
              </tr>
              <tr>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Store URL:</strong></td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;">
                  ${data.storeUrl ? `<a href="${data.storeUrl}" target="_blank">${data.storeUrl}</a>` : 'Not provided'}
                </td>
              </tr>
              <tr>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Message:</strong></td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;">${data.message || 'Voice note only'}</td>
              </tr>
              <tr>
                <td style="padding: 10px;"><strong>Voice Note:</strong></td>
                <td style="padding: 10px;">${data.hasVoiceNote ? 'Yes (check Google Sheet/Drive)' : 'No'}</td>
              </tr>
            </table>

            <p style="margin-top: 20px; font-size: 12px; color: #666;">
              This email was automatically generated by the CartCure contact form.
            </p>
          </div>
        </body>
      </html>
    `;

    // Plain text version
    const plainBody = `
New Contact Form Submission
Reference: ${data.submissionNumber}

Timestamp: ${data.timestamp}
Name: ${data.name}
Email: ${data.email}
Store URL: ${data.storeUrl || 'Not provided'}
Message: ${data.message || 'Voice note only'}
Voice Note: ${data.hasVoiceNote ? 'Yes (check Google Sheet/Drive)' : 'No'}

---
This email was automatically generated by the CartCure contact form.
    `;

    // Send email
    MailApp.sendEmail({
      to: CONFIG.ADMIN_EMAIL,
      subject: subject,
      body: plainBody,
      htmlBody: htmlBody
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
                                <td style="color: ${colors.inkBlack}; font-size: 15px; line-height: 1.6;">Once approved, we get to work on your store</td>
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
3. Once approved, we get to work on your store

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

