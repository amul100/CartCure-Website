// ============================================================================
// SECURITY VALIDATION FUNCTIONS
// ============================================================================

/**
 * Throw a validation error with a user-friendly message.
 * @param {string} internalMsg - Technical error message for logging
 * @param {string} userMsg - User-friendly error message
 */
function throwValidationError(internalMsg, userMsg) {
  const error = new Error(internalMsg);
  error.userMessage = userMsg;
  throw error;
}

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
    throwValidationError('Rate limit exceeded', 'Too many submissions. Please try again in 1 hour.');
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

  // Validate and sanitize phone
  sanitized.phone = validatePhone(data.phone);

  // Validate and sanitize store URL (required)
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
    throwValidationError('No message or voice note provided', 'Please provide either a message or voice note.');
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
 * Supports both new format (CC-WORD-XXX) and legacy format (CC-YYYYMMDD-XXXXX)
 */
function validateSubmissionNumber(submissionNumber) {
  if (!submissionNumber || submissionNumber.trim() === '') {
    // Generate one server-side if not provided (fallback) - use new human-readable format
    const randomWord = SUBMISSION_WORDS[Math.floor(Math.random() * SUBMISSION_WORDS.length)];
    const randomNum = Math.floor(100 + Math.random() * 900); // 3-digit number
    return `CC-${randomWord}-${randomNum}`;
  }

  // Validate format: CC-WORD-XXX (new) or CC-YYYYMMDD-XXXXX (legacy)
  const newFormatRegex = /^CC-[A-Z]{3,6}-\d{3}$/;
  const legacyFormatRegex = /^CC-\d{8}-\d{5}$/;

  if (!newFormatRegex.test(submissionNumber) && !legacyFormatRegex.test(submissionNumber)) {
    throwValidationError('Invalid submission number format', 'Invalid submission format.');
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
    throwValidationError('Email is required', 'Email is required.');
  }

  email = email.trim().toLowerCase();

  if (email.length > CONFIG.MAX_EMAIL_LENGTH) {
    throwValidationError('Email is too long', 'Email exceeds maximum length.');
  }

  if (!REGEX.EMAIL.test(email)) {
    throwValidationError('Invalid email format', 'Please enter a valid email address.');
  }

  return escapeHtml(email);
}

/**
 * Validate phone number format
 */
function validatePhone(phone) {
  if (!phone || phone.trim() === '') {
    throwValidationError('Phone number is required', 'Please enter a phone number.');
  }

  phone = phone.trim();

  if (phone.length > 20) {
    throwValidationError('Invalid phone number length', 'Please enter a valid phone number.');
  }

  // Allow digits, spaces, dashes, parentheses, and plus sign
  if (!/^[\d\s\-\(\)\+]+$/.test(phone)) {
    throwValidationError('Invalid phone number format', 'Please enter a valid phone number.');
  }

  // Count actual digits (minimum 8 for valid NZ phone numbers)
  const digitCount = (phone.match(/\d/g) || []).length;
  if (digitCount < 8) {
    throwValidationError('Phone number too short', 'Please enter a valid phone number (minimum 8 digits).');
  }

  return escapeHtml(phone);
}

/**
 * Validate URL format (required)
 */
function validateURL(url) {
  if (!url || url.trim() === '') {
    throwValidationError('Store URL is required', 'Please enter your store URL.');
  }

  url = url.trim();

  // Ensure http:// or https:// prefix
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  if (url.length > CONFIG.MAX_URL_LENGTH) {
    throwValidationError('URL is too long', 'Store URL exceeds maximum length.');
  }

  if (!REGEX.URL.test(url)) {
    throwValidationError('Invalid URL format', 'Please enter a valid store URL.');
  }

  // Check for blocked patterns
  const lowerUrl = url.toLowerCase();
  for (const pattern of BLOCKED_PATTERNS) {
    if (lowerUrl.includes(pattern)) {
      throwValidationError('Blocked URL pattern detected', 'Invalid store URL.');
    }
  }

  return escapeHtml(url);
}

/**
 * Validate audio data
 */
function validateAudioData(audioData) {
  if (!audioData || audioData.trim() === '') {
    throwValidationError('Audio data is empty', 'Voice note is empty.');
  }

  // Check if it's base64 encoded
  if (!audioData.startsWith('data:audio/')) {
    throwValidationError('Invalid audio format', 'Invalid voice note format.');
  }

  // Estimate file size (base64 is ~33% larger than original)
  // Add null check for split result to handle malformed data
  const splitData = audioData.split(',');
  if (splitData.length < 2 || !splitData[1]) {
    throwValidationError('Malformed audio data', 'Invalid voice note format.');
  }

  const base64Length = splitData[1].length;
  const estimatedSizeBytes = (base64Length * 3) / 4;
  const estimatedSizeMB = estimatedSizeBytes / (1024 * 1024);

  if (estimatedSizeMB > CONFIG.MAX_AUDIO_SIZE_MB) {
    throwValidationError('Audio file too large', 'Voice note exceeds 10MB limit.');
  }

  // Validate MIME type
  const semicolonIndex = audioData.indexOf(';');
  if (semicolonIndex === -1) {
    throwValidationError('Invalid audio data format', 'Invalid voice note format.');
  }

  const mimeType = audioData.substring(5, semicolonIndex);
  const allowedTypes = ['audio/webm', 'audio/ogg', 'audio/mp4', 'audio/mpeg'];
  if (!allowedTypes.includes(mimeType)) {
    throwValidationError('Invalid audio MIME type', 'Invalid voice note format.');
  }

  return audioData; // Return full base64 string for storage
}

/**
 * HTML entity escape to prevent XSS
 */
function escapeHtml(text) {
  if (text === null || text === undefined) return '';

  // Convert to string (handles numbers, dates, etc.)
  const str = String(text);

  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Format activity details with clickable signature links
 * Escapes HTML but converts "Signature: [URL]" to clickable "click here to view" links
 */
function formatActivityDetails(text) {
  if (!text) return '';

  // First escape all HTML
  let escaped = escapeHtml(text);

  // Then replace "Signature: [Google Drive URL]" with clickable link
  // Match pattern: Signature: https://drive.google.com/...
  escaped = escaped.replace(
    /Signature:\s*(https:\/\/drive\.google\.com\/[^\s,]+)/g,
    'Signature: <a href="$1" target="_blank" style="color: #1a73e8; text-decoration: underline;">click here to view</a>'
  );

  return escaped;
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
  Logger.log('- Phone: ' + data.phone);
  Logger.log('- Store URL: ' + data.storeUrl);
  Logger.log('- Has Voice Note: ' + data.hasVoiceNote);
  Logger.log('- Timestamp: ' + data.timestamp);

  // Save debug file to Google Drive (only in development mode)
  if (!IS_PRODUCTION) {
    saveDebugFileToDrive(data);
  }
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
      'Phone: ' + data.phone,
      'Store URL: ' + data.storeUrl,
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
 * Save testimonial debug log to a file in Google Drive
 */
function saveTestimonialDebugFile(jobNumber, debugLog) {
  try {
    const folder = getOrCreateDebugFolder();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = 'TESTIMONIAL_DEBUG_' + (jobNumber || 'unknown') + '_' + timestamp + '.txt';
    const file = folder.createFile(fileName, debugLog.join('\n'));
    Logger.log('Testimonial debug file saved: ' + file.getUrl());
    return file.getUrl();
  } catch (error) {
    Logger.log('Error saving testimonial debug file: ' + error.message);
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
 * Save debug log to a file in the debug folder.
 * Automatically appends a timestamp to the filename.
 * @param {string} prefix - Filename prefix (e.g., 'DOPOST_DEBUG', 'TESTIMONIAL_JOB_CHECK')
 * @param {Array|string} content - Log content: array of lines (joined with \n) or a string
 */
function saveDebugLog(prefix, content) {
  if (IS_PRODUCTION) return;
  try {
    const folder = getOrCreateDebugFolder();
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const text = Array.isArray(content) ? content.join('\n') : String(content);
    folder.createFile(prefix + '_' + ts + '.txt', text);
  } catch (e) {
    try {
      const text = Array.isArray(content) ? content.join('\n') : String(content);
      DriveApp.createFile('DEBUG_FALLBACK_' + new Date().getTime() + '.txt', text + '\nError: ' + e.toString());
    } catch (e2) { /* ignore */ }
  }
}

/**
 * Log performance metrics to debug file for tracking optimization impact
 *
 * This function creates timestamped log entries to track how well the
 * performance optimizations are working in production
 *
 * @param {string} functionName - Name of the optimized function
 * @param {Object} metrics - Performance metrics (executionTime, fieldsUpdated, etc.)
 */
function logPerformanceToDebugFile(functionName, metrics) {
  try {
    const folder = getOrCreateDebugFolder();

    // Create or append to daily performance log
    const today = new Date();
    const dateStr = Utilities.formatDate(today, 'Pacific/Auckland', 'yyyy-MM-dd');
    const fileName = 'performance_log_' + dateStr + '.txt';

    // Build log entry
    const timestamp = Utilities.formatDate(today, 'Pacific/Auckland', 'yyyy-MM-dd HH:mm:ss');
    const logEntry = [
      timestamp + ' | ' + functionName + ' | ' + JSON.stringify(metrics)
    ].join('\n') + '\n';

    // Check if file exists
    const existingFiles = folder.getFilesByName(fileName);

    if (existingFiles.hasNext()) {
      // Append to existing file
      const file = existingFiles.next();
      const existingContent = file.getBlob().getDataAsString();
      file.setContent(existingContent + logEntry);
    } else {
      // Create new file with header
      const header = '=== CartCure Performance Log (' + dateStr + ') ===\n' +
                     'Format: Timestamp | Function | Metrics\n' +
                     '================================================\n';
      folder.createFile(fileName, header + logEntry);
    }
  } catch (error) {
    // Don't throw - performance logging should never break functionality
    Logger.log('[PERF] Error logging to debug file: ' + error.message);
  }
}

/**
 * Save submission to Google Sheet
 */
function saveToSheet(data) {
  const debugLog = []; // Capture all debug output

  if (!CONFIG.SHEET_ID) {
    const msg = 'WARNING: SHEET_ID not configured. Skipping sheet save.';
    Logger.log(msg);
    debugLog.push(msg);
    return;
  }

  try {
    const ss = getSpreadsheet();

    // Only do expensive debug operations in development mode
    if (!IS_PRODUCTION) {
      debugLog.push('=== SAVE TO SHEET DEBUG LOG ===');
      debugLog.push('Submission Number: ' + data.submissionNumber);
      debugLog.push('Timestamp: ' + new Date().toISOString());
      debugLog.push('');

      // DEBUG: Log all sheet names in the spreadsheet
      const allSheets = ss.getSheets();
      debugLog.push('=== ALL SHEETS IN SPREADSHEET ===');
      Logger.log('=== DEBUG: All sheets in spreadsheet ===');
      allSheets.forEach((s, index) => {
        const msg = 'Sheet ' + index + ': "' + s.getName() + '" (Index: ' + s.getIndex() + ')';
        Logger.log(msg);
        debugLog.push(msg);
      });
      debugLog.push('');

      debugLog.push('=== LOOKING FOR SUBMISSIONS SHEET ===');
      debugLog.push('Constant SHEETS.SUBMISSIONS = "' + SHEETS.SUBMISSIONS + '"');
    }

    let sheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

    if (!IS_PRODUCTION) {
      Logger.log('Looking for sheet: "' + SHEETS.SUBMISSIONS + '"');
      Logger.log('Sheet found: ' + (sheet ? sheet.getName() : 'NULL'));

      if (sheet) {
        debugLog.push('✓ Sheet FOUND: "' + sheet.getName() + '"');
        debugLog.push('  Sheet Index: ' + sheet.getIndex());
        debugLog.push('  Sheet ID: ' + sheet.getSheetId());
      } else {
        debugLog.push('✗ Sheet NOT FOUND - will create it');
      }
      debugLog.push('');
    }

    // If Submissions sheet doesn't exist, create it
    if (!sheet) {
      if (!IS_PRODUCTION) {
        debugLog.push('=== CREATING NEW SHEET ===');
        Logger.log('Submissions sheet not found. Creating it...');
      }
      sheet = ss.insertSheet(SHEETS.SUBMISSIONS);
      if (!IS_PRODUCTION) {
        const msg = 'Created sheet: "' + sheet.getName() + '" at index: ' + sheet.getIndex();
        Logger.log(msg);
        debugLog.push(msg);
        debugLog.push('');
      }
    }

    // Check if headers exist, if not create them
    const lastRow = sheet.getLastRow();

    if (lastRow === 0) {
      sheet.appendRow([
        'Status',
        'Submission #',
        'Timestamp',
        'Name',
        'Email',
        'Phone',
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

    // Prepare the row data with Status first (set to 'New')
    // Prefix phone with apostrophe if it starts with 0 to preserve leading zeros in Google Sheets
    const phoneForSheet = data.phone && String(data.phone).trim().startsWith('0')
      ? "'" + String(data.phone).trim()
      : data.phone;

    const rowData = [
      'New',
      data.submissionNumber,
      data.timestamp,
      data.name,
      data.email,
      phoneForSheet,
      data.storeUrl,
      data.message,
      data.hasVoiceNote ? 'Yes' : 'No',
      audioFileUrl
    ];

    // Insert at top (row 2) so newest submissions appear first
    insertAtTopSafe(sheet, rowData, false); // false = no toast (no UI context from doPost)

    if (!IS_PRODUCTION) {
      debugLog.push('=== SHEET STATUS ===');
      debugLog.push('Last row in sheet: ' + lastRow);
      debugLog.push('=== WRITING DATA ===');
      debugLog.push('Data written successfully to row 2');
      debugLog.push('rowData[5] (phone column): "' + rowData[5] + '"');
      debugLog.push('');
      debugLog.push('=== VERIFICATION ===');
      debugLog.push('Final sheet name: "' + sheet.getName() + '"');
      debugLog.push('Final sheet index: ' + sheet.getIndex());
      debugLog.push('Row written: 2 (top)');
      debugLog.push('');
      debugLog.push('✓ SUCCESS');
      saveDetailedDebugLog(data.submissionNumber, debugLog.join('\n'));
    }

    Logger.log('Data saved successfully to Submissions sheet');

  } catch (error) {
    Logger.log('Error saving to sheet: ' + error.message);

    // Save debug log even on error (only in development mode)
    if (!IS_PRODUCTION) {
      try {
        debugLog.push('');
        debugLog.push('✗ ERROR: ' + error.message);
        debugLog.push('Stack trace: ' + error.stack);
        saveDetailedDebugLog(data.submissionNumber, debugLog.join('\n'));
      } catch (e) {
        Logger.log('Failed to save debug log: ' + e.message);
      }
    }

    // Don't throw - submission should succeed even if sheet save fails
  }
}

/**
 * Save detailed debug log to a file
 */
function saveDetailedDebugLog(submissionNumber, logContent) {
  try {
    const folder = getOrCreateDebugFolder();
    const fileName = 'SHEET_DEBUG_' + submissionNumber + '.txt';
    const file = folder.createFile(fileName, logContent);
    Logger.log('Detailed debug log saved: ' + file.getUrl());
    return file.getUrl();
  } catch (error) {
    Logger.log('Error saving detailed debug log: ' + error.message);
    return '';
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

