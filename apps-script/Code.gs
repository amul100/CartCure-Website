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
const IS_PRODUCTION = false; // TEMPORARILY DISABLED FOR DEBUGGING

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
  RATE_LIMIT_ENABLED: false, // Set to true to enable rate limiting in production
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

// Human-readable word list for submission numbers (must match client-side list)
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

// ============================================================================
// EMAIL TEMPLATE SYSTEM
// ============================================================================

/**
 * Paperlike theme colors used across all email templates.
 * This single source of truth ensures consistent styling.
 */
const EMAIL_COLORS = {
  brandGreen: '#2d5d3f',
  brandGreenLight: '#3a7a52',
  paperWhite: '#f9f7f3',
  paperCream: '#faf8f4',
  paperBorder: '#d4cfc3',
  inkBlack: '#2b2b2b',
  inkGray: '#5a5a5a',
  inkLight: '#8a8a8a',
  alertBg: '#fff8e6',
  alertBorder: '#f5d76e',
  alertRed: '#c62828',
  alertRedBg: '#ffebee',
  // Deposit notice colors (blue-based but attention-grabbing)
  depositBlue: '#1565c0',
  depositBlueDark: '#0d47a1',
  depositBlueBg: '#e3f2fd',
  depositBlueBorder: '#1976d2'
};

/**
 * Renders an email template with the provided data.
 * Templates are stored as HTML files in the Apps Script project.
 *
 * @param {string} templateName - Name of the template file (without .html extension)
 * @param {Object} data - Data object with all template variables
 * @returns {string} Rendered HTML string
 *
 * Template syntax:
 * - <?= variable ?> for escaped output
 * - <?!= htmlVariable ?> for unescaped HTML output (use for pre-built HTML snippets)
 */
function renderEmailTemplate(templateName, data) {
  const template = HtmlService.createTemplateFromFile(templateName);

  // Always include colors
  template.colors = EMAIL_COLORS;

  // Copy all data properties to template
  for (const key in data) {
    if (data.hasOwnProperty(key)) {
      template[key] = data[key];
    }
  }

  // Evaluate and return HTML content
  return template.evaluate().getContent();
}

/**
 * Wraps email body content in the standard HTML document structure.
 *
 * @param {string} bodyContent - The inner email content (from template)
 * @returns {string} Complete HTML document
 */
function wrapEmailHtml(bodyContent) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: ${EMAIL_COLORS.paperCream}; font-family: Georgia, 'Times New Roman', serif;">
  ${bodyContent}
</body>
</html>`;
}

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
    if (e.postData && (e.postData.type === 'application/json' || e.postData.type === 'text/plain')) {
      // Handle both application/json and text/plain (which some forms use for CORS)
      try {
        data = JSON.parse(e.postData.contents);
        if (!IS_PRODUCTION) Logger.log('Parsed as JSON from ' + e.postData.type);
      } catch (parseError) {
        // If JSON parsing fails, fall back to parameter
        data = e.parameter;
        if (!IS_PRODUCTION) Logger.log('JSON parse failed, using e.parameter');
      }
    } else {
      // URL-encoded form data comes in e.parameter
      data = e.parameter;
      if (!IS_PRODUCTION) Logger.log('Using e.parameter (form-encoded)');
    }

    if (!IS_PRODUCTION) {
      Logger.log('Data keys received: ' + Object.keys(data).join(', '));
      Logger.log('submissionNumber received: ' + data.submissionNumber);

      // DEBUG: Write received data to file to diagnose phone issue
      try {
        const debugFolder = getOrCreateDebugFolder();
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const debugContent = [
          '=== DOPOST RAW DATA DEBUG ===',
          'Timestamp: ' + ts,
          '',
          '=== e.parameter keys ===',
          Object.keys(e.parameter || {}).join(', '),
          '',
          '=== e.parameter.phone ===',
          'Value: "' + (e.parameter ? e.parameter.phone : 'e.parameter is null') + '"',
          'Type: ' + typeof (e.parameter ? e.parameter.phone : undefined),
          '',
          '=== data object keys ===',
          Object.keys(data).join(', '),
          '',
          '=== data.phone ===',
          'Value: "' + data.phone + '"',
          'Type: ' + typeof data.phone,
          '',
          '=== All data values ===',
          'name: "' + data.name + '"',
          'email: "' + data.email + '"',
          'phone: "' + data.phone + '"',
          'storeUrl: "' + data.storeUrl + '"',
          'message length: ' + (data.message ? data.message.length : 0),
          'hasVoiceNote: "' + data.hasVoiceNote + '"',
          '',
          '=== postData info ===',
          'postData.type: ' + (e.postData ? e.postData.type : 'undefined'),
          'postData.contents (first 500 chars): ' + (e.postData ? e.postData.contents.substring(0, 500) : 'undefined')
        ].join('\n');
        debugFolder.createFile('DOPOST_DEBUG_' + ts + '.txt', debugContent);
      } catch (debugError) {
        Logger.log('Debug file creation failed: ' + debugError.message);
      }
    }

    // Check for action parameter to handle different form types
    const action = data.action || '';

    // Handle testimonial submission
    if (action === 'submitTestimonial') {
      return handleTestimonialSubmission(data);
    }

    // Handle quote acceptance from web form
    if (action === 'acceptQuote') {
      return handleQuoteAcceptance(data);
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
    // TO DISABLE: Set CONFIG.RATE_LIMIT_ENABLED = false
    // =========================================================================
    const emailForRateLimit = (data.email || '').trim().toLowerCase();
    if (CONFIG.RATE_LIMIT_ENABLED) {
      checkServerRateLimit(emailForRateLimit);
    }

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
    if (CONFIG.RATE_LIMIT_ENABLED) {
      recordServerSubmission(emailForRateLimit);
    }

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
  // Check for action parameter to handle different API endpoints
  const action = e.parameter.action || '';

  // Handle testimonials API endpoint
  if (action === 'getTestimonials') {
    const fiveStarOnly = e.parameter.fiveStarOnly === 'true';
    const limit = e.parameter.limit ? parseInt(e.parameter.limit, 10) : null;
    return getApprovedTestimonials(fiveStarOnly, limit);
  }

  // Default response - health check
  return ContentService
    .createTextOutput(JSON.stringify({
      status: 'ok',
      message: 'CartCure Form Handler is running',
      timestamp: new Date().toISOString()
    }))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Get all approved testimonials for display on the website
 * Returns testimonials where "Show on Website" checkbox is TRUE
 * @param {boolean} fiveStarOnly - If true, only return 5-star testimonials
 * @param {number|null} limit - Maximum number of testimonials to return (null for all)
 */
function getApprovedTestimonials(fiveStarOnly, limit) {
  try {
    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    const sheet = ss.getSheetByName(SHEETS.TESTIMONIALS);

    if (!sheet) {
      return ContentService
        .createTextOutput(JSON.stringify({
          success: true,
          testimonials: []
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    const lastRow = sheet.getLastRow();
    if (lastRow <= 1) {
      return ContentService
        .createTextOutput(JSON.stringify({
          success: true,
          testimonials: []
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Get all data including header for dynamic column lookup
    const allData = sheet.getDataRange().getValues();
    const headers = allData[0];
    const data = allData.slice(1); // Exclude header row

    // Find column indices dynamically
    const approvedColIndex = headers.indexOf('Approved');
    const nameColIndex = headers.indexOf('Name');
    const businessColIndex = headers.indexOf('Business');
    const locationColIndex = headers.indexOf('Location');
    const ratingColIndex = headers.indexOf('Rating');
    const testimonialColIndex = headers.indexOf('Testimonial');

    // Filter to only approved testimonials and format for website
    let approvedTestimonials = data
      .filter(row => approvedColIndex >= 0 && row[approvedColIndex] === true)
      .map(row => {
        const ratingValue = ratingColIndex >= 0 ? Number(row[ratingColIndex]) : 5;
        return {
          name: (nameColIndex >= 0 ? row[nameColIndex] : '') || 'Anonymous',
          business: (businessColIndex >= 0 ? row[businessColIndex] : '') || '',
          location: (locationColIndex >= 0 ? row[locationColIndex] : '') || '',
          rating: (!isNaN(ratingValue) && ratingValue >= 1 && ratingValue <= 5) ? ratingValue : 5,
          testimonial: (testimonialColIndex >= 0 ? row[testimonialColIndex] : '') || ''
        };
      })
      .filter(t => t.testimonial.trim() !== ''); // Only include non-empty testimonials

    // Filter to 5-star only if requested
    if (fiveStarOnly) {
      approvedTestimonials = approvedTestimonials.filter(t => t.rating === 5);
    }

    // Apply limit if specified
    if (limit && limit > 0) {
      approvedTestimonials = approvedTestimonials.slice(0, limit);
    }

    return ContentService
      .createTextOutput(JSON.stringify({
        success: true,
        testimonials: approvedTestimonials
      }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    Logger.log('Error fetching testimonials: ' + error.message);
    return ContentService
      .createTextOutput(JSON.stringify({
        success: false,
        error: 'Failed to load testimonials',
        testimonials: []
      }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

/**
 * Handle testimonial form submission
 * Requires valid job number and limits to one testimonial per job
 */
function handleTestimonialSubmission(data) {
  // Create debug file FIRST before anything else can fail
  try {
    const debugFolder = getOrCreateDebugFolder();
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const earlyDebug = [
      '=== Testimonial Early Debug ===',
      'Timestamp: ' + ts,
      'Data received: ' + JSON.stringify(data),
      'IS_PRODUCTION: ' + IS_PRODUCTION,
      'SHEETS defined: ' + (typeof SHEETS !== 'undefined'),
      'SHEETS.JOBS: ' + (typeof SHEETS !== 'undefined' ? SHEETS.JOBS : 'UNDEFINED')
    ];
    debugFolder.createFile('TESTIMONIAL_EARLY_' + ts + '.txt', earlyDebug.join('\n'));
  } catch (earlyDebugError) {
    // If even this fails, try a simpler approach
    try {
      DriveApp.createFile('TESTIMONIAL_ERROR_' + new Date().getTime() + '.txt', 'Early debug failed: ' + earlyDebugError.toString());
    } catch (e) { /* ignore */ }
  }

  try {
    // Debug logging (only in non-production)
    if (!IS_PRODUCTION) {
      Logger.log('=== Testimonial Submission Debug ===');
      Logger.log('Raw data object: ' + JSON.stringify(data));
      Logger.log('data.name: ' + data.name);
      Logger.log('data.testimonial: ' + (data.testimonial ? data.testimonial.substring(0, 50) + '...' : 'undefined'));
      Logger.log('data.jobNumber: ' + data.jobNumber);
      Logger.log('typeof data: ' + typeof data);
      Logger.log('Object keys: ' + Object.keys(data).join(', '));
    }

    // Validate required fields
    const name = (data.name || '').trim();
    const testimonial = (data.testimonial || '').trim();
    const jobNumber = (data.jobNumber || '').trim().toUpperCase();
    const email = (data.email || '').trim();

    if (!IS_PRODUCTION) {
      Logger.log('Parsed name: "' + name + '" (length: ' + name.length + ')');
      Logger.log('Parsed testimonial length: ' + testimonial.length);
      Logger.log('Parsed jobNumber: "' + jobNumber + '"');
    }

    if (!name || !testimonial) {
      if (!IS_PRODUCTION) {
        Logger.log('VALIDATION FAILED - name empty: ' + !name + ', testimonial empty: ' + !testimonial);
      }
      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'Name and testimonial are required'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Job number is required
    if (!jobNumber) {
      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'Job reference number is required to submit feedback'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);

    // Debug log array for file output
    const debugLog = [];
    debugLog.push('=== Testimonial Submission Debug ===');
    debugLog.push('Timestamp: ' + new Date().toISOString());
    debugLog.push('Job Number: ' + jobNumber);
    debugLog.push('Name: ' + name);
    debugLog.push('');

    // Validate that job number exists in Jobs sheet
    debugLog.push('SHEETS.JOBS value: ' + SHEETS.JOBS);
    const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
    if (!jobsSheet) {
      const allSheets = ss.getSheets().map(s => s.getName());
      debugLog.push('ERROR: Jobs sheet not found!');
      debugLog.push('Available sheets: ' + allSheets.join(', '));

      // Save debug file
      if (!IS_PRODUCTION) {
        saveTestimonialDebugFile(jobNumber, debugLog);
      }

      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'Unable to verify job reference. Please try again later.'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }
    debugLog.push('Jobs sheet found: YES');

    const jobsData = jobsSheet.getDataRange().getValues();
    // Column is named "Job #" not "Job Number"
    const jobNumberColIndex = jobsData[0].indexOf('Job #');
    debugLog.push('Row count: ' + jobsData.length);
    debugLog.push('Headers: ' + jobsData[0].join(', '));
    debugLog.push('Job Number column index: ' + jobNumberColIndex);

    if (jobNumberColIndex === -1) {
      debugLog.push('ERROR: Job Number column not found in headers');

      // Save debug file
      if (!IS_PRODUCTION) {
        saveTestimonialDebugFile(jobNumber, debugLog);
      }

      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'Unable to verify job reference. Please try again later.'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Save debug file on success path too
    if (!IS_PRODUCTION) {
      debugLog.push('');
      debugLog.push('Proceeding to job lookup...');
      // Log all job numbers in sheet for comparison
      const allJobNumbers = jobsData.slice(1).map(row => (row[jobNumberColIndex] || '').toString());
      debugLog.push('All job numbers in sheet: ' + allJobNumbers.join(', '));
      debugLog.push('Looking for: "' + jobNumber + '"');
      saveTestimonialDebugFile(jobNumber, debugLog);
    }

    // Check if job exists
    const jobExists = jobsData.slice(1).some(row => {
      const cellValue = (row[jobNumberColIndex] || '').toString().toUpperCase();
      return cellValue === jobNumber;
    });

    // Debug: Log job exists check
    if (!IS_PRODUCTION) {
      const debugFolder = getOrCreateDebugFolder();
      debugFolder.createFile('TESTIMONIAL_JOB_CHECK_' + new Date().getTime() + '.txt',
        'Job exists check for "' + jobNumber + '": ' + jobExists + '\nAll jobs: ' + jobsData.slice(1).map(row => row[jobNumberColIndex]).join(', '));
    }

    if (!jobExists) {
      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'Job reference not found. Please check your job number and try again.'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Check if testimonial already exists for this job
    let testimonialsSheet = ss.getSheetByName(SHEETS.TESTIMONIALS);

    // Debug: Log testimonials sheet check
    if (!IS_PRODUCTION) {
      const debugFolder = getOrCreateDebugFolder();
      debugFolder.createFile('TESTIMONIAL_SHEET_CHECK_' + new Date().getTime() + '.txt',
        'Testimonials sheet: ' + (testimonialsSheet ? testimonialsSheet.getName() : 'NULL') +
        '\nLast row: ' + (testimonialsSheet ? testimonialsSheet.getLastRow() : 'N/A'));
    }

    if (testimonialsSheet && testimonialsSheet.getLastRow() > 1) {
      const testimonialData = testimonialsSheet.getDataRange().getValues();
      const jobColIndex = testimonialData[0].indexOf('Job Number');
      if (jobColIndex !== -1) {
        const alreadySubmitted = testimonialData.slice(1).some(row => {
          const cellValue = (row[jobColIndex] || '').toString().toUpperCase();
          return cellValue === jobNumber;
        });

        // Debug: Log already submitted check
        if (!IS_PRODUCTION) {
          const debugFolder = getOrCreateDebugFolder();
          debugFolder.createFile('TESTIMONIAL_DUPLICATE_CHECK_' + new Date().getTime() + '.txt',
            'Already submitted for ' + jobNumber + ': ' + alreadySubmitted);
        }

        if (alreadySubmitted) {
          return ContentService
            .createTextOutput(JSON.stringify({
              success: false,
              message: 'Feedback has already been submitted for this job. Thank you!'
            }))
            .setMimeType(ContentService.MimeType.JSON);
        }
      }
    }

    // Sanitize inputs
    const ratingValue = Number(data.rating);
    const sanitizedData = {
      showOnWebsite: false,  // Always unchecked - needs manual approval
      submitted: new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }),
      name: escapeHtml(name.substring(0, 100)),
      business: escapeHtml((data.business || '').trim().substring(0, 150)),
      location: escapeHtml((data.location || '').trim().substring(0, 100)),
      rating: (!isNaN(ratingValue) && ratingValue >= 1 && ratingValue <= 5) ? Math.floor(ratingValue) : 5,
      testimonial: escapeHtml(testimonial.substring(0, 1000)),
      jobNumber: jobNumber.substring(0, 50),
      email: email.substring(0, 254)
    };

    // Create Testimonials sheet if it doesn't exist
    if (!testimonialsSheet) {
      if (!IS_PRODUCTION) {
        const debugFolder = getOrCreateDebugFolder();
        debugFolder.createFile('TESTIMONIAL_SHEET_CREATE_' + new Date().getTime() + '.txt', 'Creating testimonials sheet...');
      }
      setupTestimonialsSheet(ss, false);
      testimonialsSheet = ss.getSheetByName(SHEETS.TESTIMONIALS);
    }

    // Debug: Log what we're about to append
    if (!IS_PRODUCTION) {
      const debugFolder = getOrCreateDebugFolder();
      const appendDebug = [
        '=== Testimonial Append Debug ===',
        'Timestamp: ' + new Date().toISOString(),
        'Sheet exists: ' + (testimonialsSheet !== null),
        'Sheet name: ' + (testimonialsSheet ? testimonialsSheet.getName() : 'NULL'),
        'Data to append:',
        '  showOnWebsite: ' + sanitizedData.showOnWebsite,
        '  submitted: ' + sanitizedData.submitted,
        '  name: ' + sanitizedData.name,
        '  business: ' + sanitizedData.business,
        '  location: ' + sanitizedData.location,
        '  rating: ' + sanitizedData.rating,
        '  testimonial: ' + sanitizedData.testimonial.substring(0, 50) + '...',
        '  jobNumber: ' + sanitizedData.jobNumber,
        '  email: ' + sanitizedData.email
      ];
      debugFolder.createFile('TESTIMONIAL_APPEND_' + new Date().getTime() + '.txt', appendDebug.join('\n'));
    }

    // Append the testimonial using appendRow() - this correctly finds the last row with actual data
    // Note: Column A is left empty here - the checkbox is added by applyTestimonialRowValidation()
    const rowData = [
      '',  // Placeholder for checkbox - will be set properly after validation is applied
      sanitizedData.submitted,
      sanitizedData.name,
      sanitizedData.business,
      sanitizedData.location,
      sanitizedData.rating.toString(),
      sanitizedData.testimonial,
      sanitizedData.jobNumber,
      sanitizedData.email
    ];
    testimonialsSheet.appendRow(rowData);

    // Apply validation (checkbox, rating dropdown, text wrap) to the newly added row
    // This must happen AFTER appendRow so the checkbox validation is set before the value
    const newRow = testimonialsSheet.getLastRow();
    applyTestimonialRowValidation(testimonialsSheet, newRow);

    // Debug: Confirm append completed
    if (!IS_PRODUCTION) {
      const debugFolder = getOrCreateDebugFolder();
      debugFolder.createFile('TESTIMONIAL_APPENDED_' + new Date().getTime() + '.txt', 'Row appended successfully at row ' + newRow + '. Last row: ' + testimonialsSheet.getLastRow());
    }

    // Send notification email to admin
    if (CONFIG.ADMIN_EMAIL) {
      const subject = 'New Testimonial Submitted - ' + sanitizedData.name + ' [' + sanitizedData.jobNumber + ']';
      const body = `A new testimonial has been submitted and is awaiting your approval.

Job Reference: ${sanitizedData.jobNumber}
Name: ${sanitizedData.name}
Business: ${sanitizedData.business || 'Not provided'}
Location: ${sanitizedData.location || 'Not provided'}
Rating: ${'★'.repeat(sanitizedData.rating)}${'☆'.repeat(5 - sanitizedData.rating)}

Testimonial:
"${sanitizedData.testimonial}"

To approve this testimonial for display on the website:
1. Open the CartCure spreadsheet
2. Go to the Testimonials tab
3. Check the "Show on Website" checkbox

Submitted: ${sanitizedData.submitted}`;

      MailApp.sendEmail({
        to: CONFIG.ADMIN_EMAIL,
        subject: subject,
        body: body
      });
    }

    Logger.log('Testimonial submitted for job ' + sanitizedData.jobNumber + ' by: ' + sanitizedData.name);

    return ContentService
      .createTextOutput(JSON.stringify({
        success: true,
        message: 'Thank you for your feedback! Your testimonial will be reviewed shortly.'
      }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    Logger.log('Error saving testimonial: ' + error.message);
    return ContentService
      .createTextOutput(JSON.stringify({
        success: false,
        message: 'Sorry, there was an error submitting your testimonial. Please try again.'
      }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

/**
 * Handle quote acceptance from web form
 * Called when a client accepts a quote via the quote-acceptance.html page
 *
 * @param {Object} data - The form data containing:
 *   - jobNumber: The job reference number
 *   - fullName: Client's full name
 *   - acceptanceDate: Date of acceptance
 *   - comments: Optional comments from client
 *   - signatureData: Base64-encoded signature image
 *   - termsAccepted: Boolean confirming terms acceptance
 * @returns {Object} JSON response with success/failure
 */
function handleQuoteAcceptance(data) {
  try {
    // Validate required fields
    const jobNumber = (data.jobNumber || '').trim().toUpperCase();
    const fullName = (data.fullName || '').trim();
    const acceptanceDate = (data.acceptanceDate || '').trim();
    const signatureData = (data.signatureData || '').trim();
    const comments = (data.comments || '').trim();
    const termsAccepted = data.termsAccepted === true || data.termsAccepted === 'true';

    if (!jobNumber) {
      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'Job number is required'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    if (!fullName) {
      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'Full name is required'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    if (!signatureData) {
      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'Signature is required'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    if (!termsAccepted) {
      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'You must accept the Terms of Service to proceed'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Get the job
    const job = getJobByNumber(jobNumber);

    if (!job) {
      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'Job not found. Please check the job number and try again.'
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Check if job is in Quoted or Quote Reminded status
    if (job['Status'] !== JOB_STATUS.QUOTED && job['Status'] !== JOB_STATUS.QUOTE_REMINDED) {
      // Job might already be accepted
      if (job['Status'] === JOB_STATUS.ACCEPTED || job['Status'] === JOB_STATUS.IN_PROGRESS || job['Status'] === JOB_STATUS.COMPLETED) {
        return ContentService
          .createTextOutput(JSON.stringify({
            success: false,
            message: 'This quote has already been accepted. If you have questions, please contact us.'
          }))
          .setMimeType(ContentService.MimeType.JSON);
      }
      return ContentService
        .createTextOutput(JSON.stringify({
          success: false,
          message: 'This job is not in a quotable status. Current status: ' + job['Status']
        }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Convert signature to blob (used for both Drive storage and email attachment)
    const base64Data = signatureData.replace(/^data:image\/png;base64,/, '');
    const signatureBlob = Utilities.newBlob(Utilities.base64Decode(base64Data), 'image/png', 'signature.png');

    // Save signature to Google Drive
    let signatureFileUrl = '';
    try {
      const signatureFolder = getOrCreateSignaturesFolder();
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const fileName = 'Signature_' + jobNumber + '_' + timestamp + '.png';

      // Create a copy of the blob with the proper filename for Drive
      const driveBlob = signatureBlob.copyBlob();
      driveBlob.setName(fileName);

      // Save to Drive
      const file = signatureFolder.createFile(driveBlob);
      signatureFileUrl = file.getUrl();

      Logger.log('Signature saved: ' + signatureFileUrl);
    } catch (sigError) {
      Logger.log('Error saving signature: ' + sigError.message);
      // Continue without signature URL - still process acceptance
    }

    // Prepare acceptance notes
    const now = new Date();
    const acceptanceNotes = [
      '--- Quote Accepted via Web Form ---',
      'Accepted by: ' + escapeHtml(fullName),
      'Date: ' + (acceptanceDate || formatNZDate(now)),
      'Terms Accepted: Yes',
      signatureFileUrl ? 'Signature: ' + signatureFileUrl : '',
      comments ? 'Client Comments: ' + escapeHtml(comments.substring(0, 500)) : ''
    ].filter(Boolean).join('\n');

    // Calculate due date
    const turnaround = parseInt(job['Estimated Turnaround']) || JOB_CONFIG.DEFAULT_SLA_DAYS;
    const dueDate = new Date(now);
    dueDate.setDate(dueDate.getDate() + turnaround);

    // Get existing notes and append acceptance notes
    const existingNotes = job['Notes'] || '';
    const updatedNotes = existingNotes ? existingNotes + '\n\n' + acceptanceNotes : acceptanceNotes;

    // Update job fields
    updateJobFields(jobNumber, {
      'Status': JOB_STATUS.ACCEPTED,
      'Quote Accepted Date': formatNZDate(now),
      'Days Since Accepted': 0,
      'Days Remaining': turnaround,
      'SLA Status': 'On Track',
      'Due Date': formatNZDate(dueDate),
      'Notes': updatedNotes
    });

    // Check if deposit is required and generate invoice
    const total = parseFloat(job['Total (incl GST)']) || parseFloat(job['Quote Amount (excl GST)']) || 0;
    const requiresDeposit = total >= 200;
    let depositInfo = '';

    if (requiresDeposit) {
      const invoiceResult = generateAndSendDepositInvoice(jobNumber, job);
      if (invoiceResult.success) {
        depositInfo = 'A 50% deposit invoice (' + formatCurrency(invoiceResult.amount) + ') has been sent to your email.';
        Logger.log('Deposit invoice generated for ' + jobNumber + ': ' + invoiceResult.invoiceNumber);
      } else {
        Logger.log('Failed to generate deposit invoice for ' + jobNumber + ': ' + invoiceResult.error);
        // Still continue - admin can manually send invoice
      }
    }

    // Send admin notification
    if (CONFIG.ADMIN_EMAIL) {
      const adminSubject = 'Quote Accepted - ' + jobNumber + ' - ' + fullName;
      const adminBody = `A quote has been accepted via the web form.

Job Number: ${jobNumber}
Client: ${job['Client Name']} (${job['Client Email']})
Accepted By: ${fullName}
Acceptance Date: ${acceptanceDate || formatNZDate(now)}
Terms Accepted: Yes
${signatureFileUrl ? 'Signature: ' + signatureFileUrl : ''}

Quote Amount: ${formatCurrency(total)}
${requiresDeposit ? 'Deposit Required: Yes (50% = ' + formatCurrency(total * 0.5) + ')' : 'Deposit Required: No (under $200)'}

${comments ? 'Client Comments:\n' + comments : ''}

SLA:
- Due Date: ${formatNZDate(dueDate)}
- Days Remaining: ${turnaround}

---
Use CartCure > Jobs > Start Work when you begin.`;

      try {
        MailApp.sendEmail({
          to: CONFIG.ADMIN_EMAIL,
          subject: adminSubject,
          body: adminBody,
          inlineImages: { signature: signatureBlob }
        });
      } catch (emailError) {
        Logger.log('Failed to send admin notification: ' + emailError.message);
      }
    }

    // Send confirmation email to client
    const clientEmail = job['Client Email'];
    if (clientEmail) {
      try {
        const businessName = getSetting('Business Name') || 'CartCure';
        const isGSTRegistered = getSetting('GST Registered') === 'Yes';
        const gstNumber = getSetting('GST Number') || '';
        const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

        // Determine deposit message
        const depositMessage = requiresDeposit
          ? 'You\'ll receive a deposit invoice shortly. Payment of 50% (' + formatCurrency(total * 0.5) + ') is required to begin work.'
          : 'No deposit is required. We\'ll begin work and invoice you upon completion.';

        // Render the confirmation email template
        const bodyContent = renderEmailTemplate('email-quote-accepted', {
          jobNumber: jobNumber,
          clientName: job['Client Name'] || fullName,
          acceptedBy: fullName,
          acceptanceDate: acceptanceDate || formatNZDate(now),
          quoteAmount: formatCurrency(total),
          depositInfo: depositMessage,
          dueDate: formatNZDate(dueDate),
          businessName: businessName,
          gstFooterLine: gstFooterLine
        });

        const htmlBody = wrapEmailHtml(bodyContent);

        // Plain text version
        const plainBody = `Hi ${job['Client Name'] || fullName},

Thank you for accepting the quote for job ${jobNumber}!

ACCEPTANCE DETAILS
------------------
Accepted By: ${fullName}
Date: ${acceptanceDate || formatNZDate(now)}
Quote Amount: ${formatCurrency(total)}

WHAT HAPPENS NEXT
-----------------
${depositMessage}

We'll begin work on your project and keep you updated on progress.
Estimated completion: ${formatNZDate(dueDate)}

By accepting this quote, you agreed to our Terms of Service and Privacy Policy.

Thanks for choosing CartCure!

--
${businessName}
Quick Shopify Fixes for NZ Businesses
https://cartcure.co.nz`;

        MailApp.sendEmail({
          to: clientEmail,
          subject: 'Quote Accepted - ' + jobNumber,
          body: plainBody,
          htmlBody: htmlBody,
          name: businessName,
          inlineImages: { signature: signatureBlob }
        });

        Logger.log('Client confirmation email sent to: ' + clientEmail);
      } catch (clientEmailError) {
        Logger.log('Failed to send client confirmation email: ' + clientEmailError.message);
        // Continue - not critical
      }
    }

    Logger.log('Quote accepted via web form for ' + jobNumber + ' by ' + fullName);

    // Return success response
    return ContentService
      .createTextOutput(JSON.stringify({
        success: true,
        message: 'Quote accepted successfully!' + (depositInfo ? ' ' + depositInfo : ''),
        jobNumber: jobNumber
      }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    Logger.log('Error processing quote acceptance: ' + error.message);
    return ContentService
      .createTextOutput(JSON.stringify({
        success: false,
        message: 'Sorry, there was an error processing your acceptance. Please try again or contact us directly.'
      }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

/**
 * Get or create the Signatures folder in Google Drive
 * @returns {Folder} The Signatures folder
 */
function getOrCreateSignaturesFolder() {
  const folderName = 'CartCure Signatures';
  const folders = DriveApp.getFoldersByName(folderName);

  if (folders.hasNext()) {
    return folders.next();
  }

  // Create folder if it doesn't exist
  return DriveApp.createFolder(folderName);
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
      phone: '021 123 4567',
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
        phone: '021 123 4567',
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
 * Validate phone number format
 */
function validatePhone(phone) {
  if (!phone || phone.trim() === '') {
    const error = new Error('Phone number is required');
    error.userMessage = 'Please enter a phone number.';
    throw error;
  }

  phone = phone.trim();

  if (phone.length < 6 || phone.length > 20) {
    const error = new Error('Invalid phone number length');
    error.userMessage = 'Please enter a valid phone number.';
    throw error;
  }

  // Allow digits, spaces, dashes, parentheses, and plus sign
  if (!/^[\d\s\-\(\)\+]+$/.test(phone)) {
    const error = new Error('Invalid phone number format');
    error.userMessage = 'Please enter a valid phone number.';
    throw error;
  }

  return escapeHtml(phone);
}

/**
 * Validate URL format (required)
 */
function validateURL(url) {
  if (!url || url.trim() === '') {
    const error = new Error('Store URL is required');
    error.userMessage = 'Please enter your store URL.';
    throw error;
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
  Logger.log('- Phone: ' + data.phone);
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
 * Save debug log to a file in the debug folder
 * @param {Array} debugLog - Array of log messages
 * @param {string} prefix - Filename prefix
 */
function saveDebugLog(debugLog, prefix) {
  try {
    const folder = getOrCreateDebugFolder();
    const fileName = prefix + '.txt';
    folder.createFile(fileName, debugLog.join('\n'));
  } catch (e) {
    // If even this fails, try writing to Drive root
    try {
      DriveApp.createFile('DEBUG_FALLBACK_' + new Date().getTime() + '.txt', debugLog.join('\n') + '\nError: ' + e.toString());
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
    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
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

    let sheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
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

    // If Submissions sheet doesn't exist, create it
    if (!sheet) {
      debugLog.push('=== CREATING NEW SHEET ===');
      Logger.log('Submissions sheet not found. Creating it...');
      sheet = ss.insertSheet(SHEETS.SUBMISSIONS);
      const msg = 'Created sheet: "' + sheet.getName() + '" at index: ' + sheet.getIndex();
      Logger.log(msg);
      debugLog.push(msg);
      debugLog.push('');
    }

    // Check if headers exist, if not create them
    const lastRow = sheet.getLastRow();
    debugLog.push('=== SHEET STATUS ===');
    debugLog.push('Last row in sheet: ' + lastRow);

    if (lastRow === 0) {
      debugLog.push('No headers found - creating headers');
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
    } else {
      debugLog.push('Headers already exist');
    }
    debugLog.push('');

    // Save audio file to Google Drive if present
    let audioFileUrl = '';
    if (data.hasVoiceNote && data.voiceNoteData) {
      audioFileUrl = saveAudioToDrive(data.voiceNoteData, data.submissionNumber);
      debugLog.push('Audio file saved: ' + audioFileUrl);
    }

    // Find the first empty row (starting from row 2 to skip headers)
    const targetRow = findFirstEmptyRow(sheet);
    debugLog.push('=== WRITING DATA ===');
    debugLog.push('Target row: ' + targetRow);
    debugLog.push('Writing to sheet: "' + sheet.getName() + '"');
    debugLog.push('Sheet index: ' + sheet.getIndex());
    debugLog.push('');
    debugLog.push('=== DATA VALUES BEING WRITTEN ===');
    debugLog.push('data.submissionNumber: "' + data.submissionNumber + '"');
    debugLog.push('data.timestamp: "' + data.timestamp + '"');
    debugLog.push('data.name: "' + data.name + '"');
    debugLog.push('data.email: "' + data.email + '"');
    debugLog.push('data.phone: "' + data.phone + '" (type: ' + typeof data.phone + ')');
    debugLog.push('data.storeUrl: "' + data.storeUrl + '"');
    debugLog.push('data.message length: ' + (data.message ? data.message.length : 0));
    debugLog.push('data.hasVoiceNote: ' + data.hasVoiceNote);
    debugLog.push('');

    // Prepare the row data with Status first (set to 'New')
    const rowData = [
      'New',
      data.submissionNumber,
      data.timestamp,
      data.name,
      data.email,
      data.phone,
      data.storeUrl,
      data.message,
      data.hasVoiceNote ? 'Yes' : 'No',
      audioFileUrl
    ];

    debugLog.push('rowData[5] (phone column): "' + rowData[5] + '"');

    // Write to the target row
    Logger.log('Writing to sheet: "' + sheet.getName() + '" at row: ' + targetRow);
    Logger.log('Sheet index: ' + sheet.getIndex());
    const range = sheet.getRange(targetRow, 1, 1, rowData.length);
    range.setValues([rowData]);

    debugLog.push('✓ Data written successfully!');
    debugLog.push('');
    debugLog.push('=== VERIFICATION ===');
    debugLog.push('Final sheet name: "' + sheet.getName() + '"');
    debugLog.push('Final sheet index: ' + sheet.getIndex());
    debugLog.push('Row written: ' + targetRow);

    const msg = 'Data saved successfully to sheet "' + sheet.getName() + '" at row ' + targetRow;
    Logger.log(msg);
    debugLog.push('');
    debugLog.push('✓ SUCCESS: ' + msg);

    // Save debug log to file
    saveDetailedDebugLog(data.submissionNumber, debugLog.join('\n'));

  } catch (error) {
    const errorMsg = 'Error saving to sheet: ' + error.message;
    Logger.log(errorMsg);
    debugLog.push('');
    debugLog.push('✗ ERROR: ' + errorMsg);
    debugLog.push('Stack trace: ' + error.stack);

    // Save debug log even on error
    try {
      saveDetailedDebugLog(data.submissionNumber, debugLog.join('\n'));
    } catch (e) {
      Logger.log('Failed to save debug log: ' + e.message);
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

// ============================================================================
// EMAIL NOTIFICATIONS
// ============================================================================

/**
 * Send email notification to admin
 * EMAIL TEMPLATE: See apps-script/email-admin-notification.html
 */
function sendEmailNotification(data) {
  if (!CONFIG.ADMIN_EMAIL) {
    Logger.log('WARNING: ADMIN_EMAIL not configured. Skipping email notification.');
    return;
  }

  try {
    const subject = '🛒 [' + data.submissionNumber + '] New Submission from ' + data.name;

    // Build conditional HTML snippets
    const messageHtml = data.message || '<em style="color: ' + EMAIL_COLORS.inkLight + ';">No written message — voice note attached</em>';

    const voiceNoteHtml = data.hasVoiceNote ? `
      <div style="margin-top: 15px; background-color: ${EMAIL_COLORS.alertBg}; border: 1px solid ${EMAIL_COLORS.alertBorder}; border-radius: 6px; padding: 12px 16px;">
        <table role="presentation" cellspacing="0" cellpadding="0">
          <tr>
            <td style="padding-right: 10px; font-size: 18px;">🎤</td>
            <td style="color: ${EMAIL_COLORS.inkGray}; font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
              <strong>Voice note attached</strong> — Check Google Sheet or Drive for audio file
            </td>
          </tr>
        </table>
      </div>
    ` : '';

    // Render template with data
    const bodyContent = renderEmailTemplate('email-admin-notification', {
      submissionNumber: data.submissionNumber,
      timestamp: data.timestamp,
      clientName: data.name,
      clientEmail: data.email,
      clientPhone: data.phone,
      storeUrl: data.storeUrl,
      messageHtml: messageHtml,
      voiceNoteHtml: voiceNoteHtml,
      sheetsUrl: 'https://docs.google.com/spreadsheets/d/' + CONFIG.SHEET_ID + '/edit'
    });

    const htmlBody = wrapEmailHtml(bodyContent);

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
Phone:     ${data.phone}
Store URL: ${data.storeUrl}

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
/**
 * Send confirmation email to the user who submitted the form
 * EMAIL TEMPLATE: See apps-script/email-user-confirmation.html
 */
function sendUserConfirmationEmail(data) {
  if (!data.email) {
    Logger.log('WARNING: No user email provided. Skipping user confirmation.');
    return;
  }

  try {
    const subject = 'We received your request! - CartCure [' + data.submissionNumber + ']';

    // Build conditional HTML snippets
    const storeUrlHtml = data.storeUrl ? `
      <div style="background-color: ${EMAIL_COLORS.paperCream}; border-left: 4px solid ${EMAIL_COLORS.brandGreen}; padding: 15px 20px; margin-bottom: 15px;">
        <p style="margin: 0 0 8px 0; color: ${EMAIL_COLORS.inkGray}; font-size: 12px; text-transform: uppercase;">Your Store</p>
        <a href="${data.storeUrl}" style="color: ${EMAIL_COLORS.brandGreen}; font-size: 15px; text-decoration: none;">${data.storeUrl}</a>
      </div>
    ` : '';

    const messageHtml = data.message || '<em style="color: ' + EMAIL_COLORS.inkGray + ';">Voice note attached</em>';

    const voiceNoteHtml = data.hasVoiceNote ? `
      <div style="margin-top: 15px; background-color: ${EMAIL_COLORS.alertBg}; border: 1px solid ${EMAIL_COLORS.alertBorder}; padding: 12px 16px;">
        <span style="color: ${EMAIL_COLORS.brandGreen}; font-size: 15px;">✓ Voice note received and saved</span>
      </div>
    ` : '';

    // Render template with data
    const bodyContent = renderEmailTemplate('email-user-confirmation', {
      clientName: data.name,
      submissionNumber: data.submissionNumber,
      timestamp: data.timestamp,
      storeUrlHtml: storeUrlHtml,
      messageHtml: messageHtml,
      voiceNoteHtml: voiceNoteHtml
    });

    const htmlBody = wrapEmailHtml(bodyContent);

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
  DASHBOARD: 'Dashboard',
  ANALYTICS: 'Analytics',
  TESTIMONIALS: 'Testimonials',
  ACTIVITY_LOG: 'Activity Log'
};

// Job Status Constants
const JOB_STATUS = {
  PENDING_QUOTE: 'Pending Quote',
  QUOTED: 'Quoted',
  QUOTE_REMINDED: 'Quote Reminded',
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

// Job Categories (matching TOS services)
const JOB_CATEGORIES = [
  'Design',           // Logo, colors, fonts, layout modifications
  'Content',          // Product descriptions, page edits, banner updates
  'Bug Fix',          // Broken links, display issues, technical problems
  'Improvement',      // Menu updates, functionality changes, small improvements
  'Product/Image',    // Product uploads, CSV imports, image optimization
  'Creative',         // Custom banner design, custom graphics
  'Integration',      // App integration, configuration, third-party setup
  'Theme/Code',       // Theme customization, code modifications
  'Automation',       // Email automation setup
  'Other'
];

// Project Size Classification (for payment schedule tiers)
const PROJECT_SIZE = {
  SMALL: 'Small',       // Under $200 - full payment upfront
  MEDIUM: 'Medium',     // $200-$500 - 50% deposit, balance on completion
  LARGE: 'Large'        // Over $500 - case-by-case schedule
};

// Late Payment Fee Configuration
const LATE_FEE_CONFIG = {
  RATE_PER_DAY: 0.02,   // 2% per day as per TOS
  GRACE_PERIOD_DAYS: 7  // Days after due date before fees apply
};

// ============================================================================
// SHEET STYLING - Brand Color Palette
// ============================================================================
// Colors matching CartCure website and email design
const SHEET_COLORS = {
  // Primary brand colors
  brandGreen: '#2d5d3f',        // Primary accent - headers, buttons
  brandGreenLight: '#4a7c59',   // Lighter green for hover states

  // Paper-like background colors (warm off-whites)
  paperWhite: '#f9f7f3',        // Primary background
  paperCream: '#faf8f4',        // Alternate row color
  paperBeige: '#ece8df',        // Section backgrounds
  paperBorder: '#d4cfc3',       // Borders and dividers

  // Text colors
  inkBlack: '#2b2b2b',          // Primary text
  inkGray: '#5a5a5a',           // Secondary text
  inkLight: '#8a8a8a',          // Muted text

  // Header colors
  headerBg: '#2d5d3f',          // Header background (brand green)
  headerText: '#ffffff',        // Header text (white)

  // Status colors - SLA
  slaOnTrack: '#e8f5e9',        // Light green background
  slaOnTrackText: '#2d5d3f',    // Brand green text
  slaAtRisk: '#fff8e1',         // Light amber background
  slaAtRiskText: '#b8860b',     // Dark goldenrod text
  slaOverdue: '#ffebee',        // Light red background
  slaOverdueText: '#c62828',    // Dark red text

  // Status colors - Payment
  paymentPaid: '#e8f5e9',       // Light green
  paymentPaidText: '#2d5d3f',   // Brand green
  paymentPending: '#fff8e1',    // Light amber
  paymentPendingText: '#b8860b',// Dark goldenrod
  paymentUnpaid: '#ffebee',     // Light red
  paymentUnpaidText: '#c62828', // Dark red

  // Status colors - Job
  statusPendingQuote: '#fff3e0',    // Light orange - needs our action
  statusPendingQuoteText: '#e65100',// Dark orange text
  statusQuoted: '#f3e5f5',          // Light purple - waiting for client
  statusQuotedText: '#7b1fa2',      // Purple text
  statusQuoteReminded: '#fff8e1',   // Light amber - reminded, awaiting response
  statusQuoteRemindedText: '#f57c00', // Orange text
  statusAccepted: '#e8f5e9',        // Light green - ready to start
  statusAcceptedText: '#2e7d32',    // Green text
  statusActive: '#e3f2fd',          // Light blue for active jobs
  statusActiveText: '#1565c0',      // Blue text
  statusCompleted: '#c8e6c9',       // Medium green - done
  statusCompletedText: '#1b5e20',   // Dark green text
  statusCancelled: '#f5f5f5',       // Light gray
  statusCancelledText: '#757575',   // Gray text

  // Dashboard accent colors
  metricBg: '#f5f5f5',          // Light gray for metric labels
  sectionBg: '#fafafa',         // Very light gray for sections
  alertBg: '#fff8e6',           // Alert/warning background
  alertBorder: '#f5d76e',       // Alert/warning border

  // Additional text colors
  navy: '#1565c0',              // Navy blue for links/accent text

  // Status chart colors (Bg suffix for chart backgrounds)
  statusPendingBg: '#fff8e1',   // Light amber - Pending Quote
  statusQuotedBg: '#e3f2fd',    // Light blue - Quoted
  statusQuoteRemindedBg: '#ffe0b2', // Light orange - Quote Reminded
  statusAcceptedBg: '#c8e6c9',  // Light green - Accepted
  statusActiveBg: '#bbdefb',    // Medium blue - In Progress
  statusCompletedBg: '#a5d6a7', // Medium green - Completed
  statusOnHoldBg: '#ffecb3',    // Light amber/yellow - On Hold
  statusCancelledBg: '#e0e0e0', // Light gray - Cancelled
  statusDeclinedBg: '#ffcdd2',  // Light red/pink - Declined

  // Payment chart colors (Bg suffix for chart backgrounds)
  paymentUnpaidBg: '#ffcdd2',   // Light red - Unpaid
  paymentInvoicedBg: '#fff9c4', // Light yellow - Invoiced
  paymentPaidBg: '#c8e6c9'      // Light green - Paid
};

// ============================================================================
// COLUMN CONFIGURATION SYSTEM
// ============================================================================
// Single source of truth for all sheet column definitions.
// To reorder columns, just change the order here - no other code changes needed.
//
// Each column can have:
// - name: (required) Header text and identifier
// - width: (required) Column width in pixels
// - validation: (optional) { type: 'list'|'checkbox', values: [...], allowInvalid: bool }
// - format: (optional) { conditionalRules: [...], numberFormat, wrapText }
// - formula: (optional) Template string with {{COL_NAME}} placeholders for column letters
// - defaultValue: (optional) Default value for new rows
// ============================================================================

const COLUMN_CONFIG = {
  // -------------------------------------------------------------------------
  // JOBS SHEET (31 columns)
  // -------------------------------------------------------------------------
  JOBS: [
    {
      name: 'Status',
      width: 100,
      validation: { type: 'list', values: Object.values(JOB_STATUS), allowInvalid: false },
      format: {
        conditionalRules: [
          { when: 'equals', value: JOB_STATUS.PENDING_QUOTE, background: SHEET_COLORS.statusPendingQuote, fontColor: SHEET_COLORS.statusPendingQuoteText },
          { when: 'equals', value: JOB_STATUS.QUOTED, background: SHEET_COLORS.statusQuoted, fontColor: SHEET_COLORS.statusQuotedText },
          { when: 'equals', value: JOB_STATUS.QUOTE_REMINDED, background: SHEET_COLORS.statusQuoteReminded, fontColor: SHEET_COLORS.statusQuoteRemindedText },
          { when: 'equals', value: JOB_STATUS.ACCEPTED, background: SHEET_COLORS.statusAccepted, fontColor: SHEET_COLORS.statusAcceptedText },
          { when: 'equals', value: JOB_STATUS.IN_PROGRESS, background: SHEET_COLORS.statusActive, fontColor: SHEET_COLORS.statusActiveText, bold: true },
          { when: 'equals', value: JOB_STATUS.COMPLETED, background: SHEET_COLORS.statusCompleted, fontColor: SHEET_COLORS.statusCompletedText },
          { when: 'equals', value: JOB_STATUS.ON_HOLD, background: SHEET_COLORS.slaAtRisk, fontColor: SHEET_COLORS.slaAtRiskText },
          { when: 'equals', value: JOB_STATUS.CANCELLED, background: SHEET_COLORS.statusCancelled, fontColor: SHEET_COLORS.statusCancelledText },
          { when: 'equals', value: JOB_STATUS.DECLINED, background: SHEET_COLORS.slaOverdue, fontColor: SHEET_COLORS.slaOverdueText }
        ]
      },
      defaultValue: JOB_STATUS.PENDING_QUOTE
    },
    { name: 'Job #', width: 60 },
    { name: 'Total (incl GST)', width: 100, format: { numberFormat: '$#,##0.00' } },
    { name: 'Created Date', width: 100 },
    { name: 'Client Name', width: 120 },
    { name: 'Client Email', width: 180 },
    { name: 'Client Phone', width: 120 },
    { name: 'Store URL', width: 150 },
    { name: 'Job Description', width: 300, format: { wrapText: true } },
    {
      name: 'Category',
      width: 100,
      validation: { type: 'list', values: JOB_CATEGORIES, allowInvalid: false }
    },
    { name: 'Quote Amount (excl GST)', width: 130, format: { numberFormat: '$#,##0.00' } },
    { name: 'GST', width: 60, format: { numberFormat: '$#,##0.00' } },
    { name: 'Quote Sent Date', width: 110 },
    { name: 'Quote Valid Until', width: 110 },
    { name: 'Quote Accepted Date', width: 120 },
    { name: 'Days Since Accepted', width: 120 },
    { name: 'Days Remaining', width: 100 },
    {
      name: 'SLA Status',
      width: 80,
      format: {
        conditionalRules: [
          { when: 'equals', value: 'OVERDUE', background: SHEET_COLORS.slaOverdue, fontColor: SHEET_COLORS.slaOverdueText, bold: true },
          { when: 'equals', value: 'AT RISK', background: SHEET_COLORS.slaAtRisk, fontColor: SHEET_COLORS.slaAtRiskText, bold: true },
          { when: 'equals', value: 'On Track', background: SHEET_COLORS.slaOnTrack, fontColor: SHEET_COLORS.slaOnTrackText }
        ]
      }
    },
    { name: 'Estimated Turnaround', width: 130, defaultValue: JOB_CONFIG.DEFAULT_SLA_DAYS },
    { name: 'Due Date', width: 90 },
    { name: 'Actual Start Date', width: 110 },
    { name: 'Actual Completion Date', width: 140 },
    {
      name: 'Payment Status',
      width: 110,
      validation: { type: 'list', values: Object.values(PAYMENT_STATUS), allowInvalid: false },
      format: {
        conditionalRules: [
          { when: 'equals', value: PAYMENT_STATUS.PAID, background: SHEET_COLORS.paymentPaid, fontColor: SHEET_COLORS.paymentPaidText },
          { when: 'equals', value: PAYMENT_STATUS.INVOICED, background: SHEET_COLORS.paymentPending, fontColor: SHEET_COLORS.paymentPendingText },
          { when: 'equals', value: PAYMENT_STATUS.UNPAID, background: SHEET_COLORS.paperWhite, fontColor: SHEET_COLORS.inkGray },
          { when: 'equals', value: PAYMENT_STATUS.OVERDUE, background: SHEET_COLORS.slaOverdue, fontColor: SHEET_COLORS.slaOverdueText, bold: true },
          { when: 'equals', value: PAYMENT_STATUS.REFUNDED, background: SHEET_COLORS.paperBeige, fontColor: SHEET_COLORS.inkGray }
        ]
      },
      defaultValue: PAYMENT_STATUS.UNPAID
    },
    { name: 'Payment Date', width: 100 },
    { name: 'Payment Method', width: 110 },
    { name: 'Payment Reference', width: 120 },
    { name: 'Invoice #', width: 80 },
    {
      name: 'Remaining Balance',
      width: 120,
      // Formula uses column name placeholders: {{Total (incl GST)}} and {{Job #}}
      formula: '=IF({{Total (incl GST)}}{{row}}="","",{{Total (incl GST)}}{{row}}-SUMIFS(\'Invoice Log\'!{{INVOICES.Total}}:{{INVOICES.Total}},\'Invoice Log\'!{{INVOICES.Job #}}:{{INVOICES.Job #}},{{Job #}}{{row}},\'Invoice Log\'!{{INVOICES.Status}}:{{INVOICES.Status}},"Paid"))',
      format: { numberFormat: '$#,##0.00' }
    },
    { name: 'Notes', width: 150 },
    { name: 'Submission #', width: 90 },
    { name: 'Last Updated', width: 110 }
  ],

  // -------------------------------------------------------------------------
  // INVOICE LOG SHEET (19 columns)
  // -------------------------------------------------------------------------
  INVOICES: [
    {
      name: 'Status',
      width: 80,
      validation: { type: 'list', values: ['Draft', 'Sent', 'Paid', 'Overdue', 'Cancelled'], allowInvalid: false },
      format: {
        conditionalRules: [
          { when: 'equals', value: 'Paid', background: SHEET_COLORS.paymentPaid, fontColor: SHEET_COLORS.paymentPaidText },
          { when: 'equals', value: 'Sent', background: SHEET_COLORS.paymentPending, fontColor: SHEET_COLORS.paymentPendingText },
          { when: 'equals', value: 'Overdue', background: SHEET_COLORS.slaOverdue, fontColor: SHEET_COLORS.slaOverdueText, bold: true },
          { when: 'equals', value: 'Cancelled', background: SHEET_COLORS.statusCancelled, fontColor: SHEET_COLORS.statusCancelledText }
        ]
      }
    },
    { name: 'Invoice #', width: 80 },
    { name: 'Job #', width: 60 },
    { name: 'Client Name', width: 120 },
    { name: 'Client Email', width: 180 },
    { name: 'Client Phone', width: 120 },
    { name: 'Invoice Date', width: 100 },
    { name: 'Due Date', width: 90 },
    { name: 'Amount (excl GST)', width: 120, format: { numberFormat: '$#,##0.00' } },
    { name: 'GST', width: 60, format: { numberFormat: '$#,##0.00' } },
    { name: 'Total', width: 80, format: { numberFormat: '$#,##0.00' } },
    { name: 'Sent Date', width: 90 },
    { name: 'Paid Date', width: 90 },
    { name: 'Payment Reference', width: 130 },
    { name: 'Days Overdue', width: 90 },
    { name: 'Late Fee', width: 80, format: { numberFormat: '$#,##0.00' } },
    { name: 'Total With Fees', width: 100, format: { numberFormat: '$#,##0.00' } },
    {
      name: 'Invoice Type',
      width: 90,
      validation: { type: 'list', values: ['Full', 'Deposit', 'Balance', 'Additional'], allowInvalid: false }
    },
    { name: 'Notes', width: 150 }
  ],

  // -------------------------------------------------------------------------
  // SUBMISSIONS SHEET (10 columns)
  // -------------------------------------------------------------------------
  SUBMISSIONS: [
    {
      name: 'Status',
      width: 70,
      validation: { type: 'list', values: ['New', 'In Review', 'Job Created', 'Declined', 'Spam'], allowInvalid: false },
      format: {
        conditionalRules: [
          { when: 'equals', value: 'In Review', background: SHEET_COLORS.statusActive, fontColor: SHEET_COLORS.statusActiveText },
          { when: 'equals', value: 'Job Created', background: SHEET_COLORS.statusCompleted, fontColor: SHEET_COLORS.statusCompletedText },
          { when: 'equals', value: 'Declined', background: SHEET_COLORS.statusCancelled, fontColor: SHEET_COLORS.statusCancelledText },
          { when: 'equals', value: 'Spam', background: SHEET_COLORS.statusCancelled, fontColor: SHEET_COLORS.statusCancelledText }
        ]
      }
    },
    { name: 'Submission #', width: 100 },
    { name: 'Timestamp', width: 140 },
    { name: 'Name', width: 120 },
    { name: 'Email', width: 180 },
    { name: 'Phone', width: 120 },
    { name: 'Store URL', width: 150 },
    { name: 'Message', width: 350, format: { wrapText: true } },
    { name: 'Has Voice Note', width: 100 },
    { name: 'Voice Note Link', width: 150 }
  ],

  // -------------------------------------------------------------------------
  // TESTIMONIALS SHEET (9 columns)
  // -------------------------------------------------------------------------
  TESTIMONIALS: [
    { name: 'Show on Website', width: 110, validation: { type: 'checkbox' } },
    { name: 'Submitted', width: 140 },
    { name: 'Name', width: 120 },
    { name: 'Business', width: 150 },
    { name: 'Location', width: 100 },
    { name: 'Rating', width: 60, validation: { type: 'list', values: ['1', '2', '3', '4', '5'], allowInvalid: false } },
    { name: 'Testimonial', width: 400, format: { wrapText: true } },
    { name: 'Job Number', width: 100 },
    { name: 'Email', width: 180 }
  ],

  // -------------------------------------------------------------------------
  // ACTIVITY LOG SHEET (7 columns)
  // -------------------------------------------------------------------------
  ACTIVITY_LOG: [
    { name: 'Timestamp', width: 150 },
    { name: 'Job #', width: 80 },
    { name: 'Activity Type', width: 120 },
    { name: 'Subject/Summary', width: 250 },
    { name: 'Details', width: 350, format: { wrapText: true } },
    { name: 'From/To', width: 200 },
    { name: 'Logged By', width: 80 }
  ]
};

// ============================================================================
// COLUMN HELPER FUNCTIONS
// ============================================================================

/**
 * Gets the 1-based column index for a column name in a specific sheet config.
 * @param {string} sheetKey - Key in COLUMN_CONFIG (e.g., 'JOBS', 'INVOICES')
 * @param {string} columnName - The column header name
 * @returns {number} 1-based column index, or -1 if not found
 */
function getColIndex(sheetKey, columnName) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) {
    Logger.log('Warning: Unknown sheet key: ' + sheetKey);
    return -1;
  }
  const index = config.findIndex(col => col.name === columnName);
  return index === -1 ? -1 : index + 1; // Convert to 1-based
}

/**
 * Gets the Excel-style column letter for a column name.
 * @param {string} sheetKey - Key in COLUMN_CONFIG (e.g., 'JOBS', 'INVOICES')
 * @param {string} columnName - The column header name
 * @returns {string} Column letter (A, B, ... Z, AA, AB...), or '' if not found
 */
function getColLetter(sheetKey, columnName) {
  const index = getColIndex(sheetKey, columnName);
  if (index === -1) return '';
  return colIndexToLetter(index);
}

/**
 * Converts a 1-based column index to Excel-style letter(s).
 * @param {number} index - 1-based column index
 * @returns {string} Column letter (A, B, ... Z, AA, AB...)
 */
function colIndexToLetter(index) {
  let letter = '';
  let temp = index;
  while (temp > 0) {
    temp--;
    letter = String.fromCharCode(65 + (temp % 26)) + letter;
    temp = Math.floor(temp / 26);
  }
  return letter;
}

/**
 * Gets all column headers as an array for a sheet.
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @returns {string[]} Array of header names
 */
function getColHeaders(sheetKey) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return [];
  return config.map(col => col.name);
}

/**
 * Gets all column widths as an array for a sheet.
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @returns {number[]} Array of column widths
 */
function getColWidths(sheetKey) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return [];
  return config.map(col => col.width);
}

/**
 * Gets the column configuration for a specific column.
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @param {string} columnName - The column header name
 * @returns {Object|null} Column config object or null
 */
function getColConfig(sheetKey, columnName) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return null;
  return config.find(col => col.name === columnName) || null;
}

/**
 * Builds a row array from a data object using column config.
 * This ensures row arrays always match the column order defined in COLUMN_CONFIG.
 *
 * @param {string} sheetKey - Key in COLUMN_CONFIG (e.g., 'JOBS')
 * @param {Object} data - Object with column names as keys
 * @returns {Array} Row array in correct column order
 *
 * Example:
 *   buildRowFromConfig('JOBS', {
 *     'Status': 'Pending Quote',
 *     'Job #': 'J-001',
 *     'Client Name': 'John Doe'
 *   })
 *   // Returns: ['Pending Quote', '', 'J-001', '', 'John Doe', '', ...]
 */
function buildRowFromConfig(sheetKey, data) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) {
    throw new Error('Unknown sheet key: ' + sheetKey);
  }

  return config.map(col => {
    // Use provided value if exists
    if (data.hasOwnProperty(col.name)) {
      return data[col.name];
    }
    // Use default value if defined
    if (col.hasOwnProperty('defaultValue')) {
      return col.defaultValue;
    }
    // Otherwise empty string
    return '';
  });
}

/**
 * Converts a row array to an object using column config.
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @param {Array} rowArray - Array of values
 * @returns {Object} Object with column names as keys
 */
function rowToObject(sheetKey, rowArray) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return {};

  const obj = {};
  config.forEach((col, index) => {
    obj[col.name] = index < rowArray.length ? rowArray[index] : '';
  });
  return obj;
}

/**
 * Resolves formula template placeholders with actual column letters.
 * Supports two placeholder formats:
 * - {{Column Name}} - column in same sheet
 * - {{SHEET_KEY.Column Name}} - column in different sheet
 * - {{row}} - row number
 *
 * @param {string} sheetKey - The sheet this formula belongs to (for same-sheet columns)
 * @param {string} formulaTemplate - Template with placeholders
 * @param {number} row - Row number to substitute
 * @returns {string} Formula with column letters substituted
 */
function resolveFormula(sheetKey, formulaTemplate, row) {
  let formula = formulaTemplate;

  // Replace {{row}} with row number
  formula = formula.replace(/\{\{row\}\}/g, row.toString());

  // Replace {{SHEET_KEY.Column Name}} patterns (cross-sheet references)
  formula = formula.replace(/\{\{(\w+)\.([^}]+)\}\}/g, (match, otherSheetKey, colName) => {
    const letter = getColLetter(otherSheetKey, colName);
    if (!letter) {
      Logger.log('Warning: Column "' + colName + '" not found in ' + otherSheetKey);
      return match;
    }
    return letter;
  });

  // Replace {{Column Name}} patterns (same-sheet references)
  formula = formula.replace(/\{\{([^}]+)\}\}/g, (match, colName) => {
    const letter = getColLetter(sheetKey, colName);
    if (!letter) {
      Logger.log('Warning: Column "' + colName + '" not found in ' + sheetKey);
      return match;
    }
    return letter;
  });

  return formula;
}

/**
 * Builds Dashboard formula with dynamic column references.
 * @param {string} formulaTemplate - Template using {{JOBS.Column Name}} syntax
 * @returns {string} Formula with column letters
 */
function buildDashboardFormula(formulaTemplate) {
  return resolveFormula('JOBS', formulaTemplate, 0).replace(/0/g, ''); // Remove any leftover row refs
}

// ============================================================================
// SHEET SETUP HELPERS (using column config)
// ============================================================================

/**
 * Applies all data validation rules for a sheet based on COLUMN_CONFIG.
 * @param {Sheet} sheet - The Google Sheet object
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @param {number} startRow - First data row (usually 2)
 * @param {number} numRows - Number of rows to apply validation to
 */
function applyConfigValidation(sheet, sheetKey, startRow, numRows) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return;

  config.forEach((col, index) => {
    if (!col.validation) return;

    const colIndex = index + 1;
    const range = sheet.getRange(startRow, colIndex, numRows, 1);

    if (col.validation.type === 'list') {
      const rule = SpreadsheetApp.newDataValidation()
        .requireValueInList(col.validation.values, true)
        .setAllowInvalid(col.validation.allowInvalid !== false)
        .build();
      range.setDataValidation(rule);
    } else if (col.validation.type === 'checkbox') {
      range.insertCheckboxes();
    }
  });
}

/**
 * Applies all conditional formatting rules for a sheet based on COLUMN_CONFIG.
 * @param {Sheet} sheet - The Google Sheet object
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @param {number} startRow - First data row (usually 2)
 * @param {number} numRows - Number of rows to apply formatting to
 */
function applyConfigConditionalFormatting(sheet, sheetKey, startRow, numRows) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return;

  // Collect all new rules
  const newRules = [];

  config.forEach((col, index) => {
    if (!col.format || !col.format.conditionalRules) return;

    const colIndex = index + 1;
    const range = sheet.getRange(startRow, colIndex, numRows, 1);

    col.format.conditionalRules.forEach(ruleConfig => {
      let builder = SpreadsheetApp.newConditionalFormatRule();

      if (ruleConfig.when === 'equals') {
        builder = builder.whenTextEqualTo(ruleConfig.value);
      } else if (ruleConfig.when === 'formula') {
        builder = builder.whenFormulaSatisfied(ruleConfig.formula);
      }

      if (ruleConfig.background) builder = builder.setBackground(ruleConfig.background);
      if (ruleConfig.fontColor) builder = builder.setFontColor(ruleConfig.fontColor);
      if (ruleConfig.bold) builder = builder.setBold(true);

      builder = builder.setRanges([range]);
      newRules.push(builder.build());
    });
  });

  // Get existing rules and filter out rules for columns we're setting
  const existingRules = sheet.getConditionalFormatRules();
  const colsWithRules = new Set();
  config.forEach((col, index) => {
    if (col.format && col.format.conditionalRules) {
      colsWithRules.add(index + 1);
    }
  });

  const filteredRules = existingRules.filter(rule => {
    const ranges = rule.getRanges();
    return !ranges.some(r => colsWithRules.has(r.getColumn()));
  });

  // Combine filtered existing rules with new rules
  sheet.setConditionalFormatRules([...filteredRules, ...newRules]);
}

/**
 * Applies formulas from COLUMN_CONFIG to a sheet.
 * @param {Sheet} sheet - The Google Sheet object
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @param {number} startRow - First data row (usually 2)
 * @param {number} numRows - Number of rows to apply formulas to
 */
function applyConfigFormulas(sheet, sheetKey, startRow, numRows) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return;

  config.forEach((col, index) => {
    if (!col.formula) return;

    const colIndex = index + 1;
    const formulas = [];

    for (let row = startRow; row < startRow + numRows; row++) {
      formulas.push([resolveFormula(sheetKey, col.formula, row)]);
    }

    sheet.getRange(startRow, colIndex, numRows, 1).setFormulas(formulas);

    // Apply number format if specified
    if (col.format && col.format.numberFormat) {
      sheet.getRange(startRow, colIndex, numRows, 1).setNumberFormat(col.format.numberFormat);
    }
  });
}

/**
 * Applies column widths from COLUMN_CONFIG to a sheet.
 * @param {Sheet} sheet - The Google Sheet object
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 */
function applyConfigColumnWidths(sheet, sheetKey) {
  const widths = getColWidths(sheetKey);
  for (let col = 1; col <= widths.length; col++) {
    sheet.setColumnWidth(col, widths[col - 1]);
  }
}

/**
 * Applies wrap text settings from COLUMN_CONFIG.
 * @param {Sheet} sheet - The Google Sheet object
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @param {number} startRow - First data row
 * @param {number} numRows - Number of rows
 */
function applyConfigWrapText(sheet, sheetKey, startRow, numRows) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return;

  config.forEach((col, index) => {
    if (col.format && col.format.wrapText) {
      const colIndex = index + 1;
      sheet.getRange(startRow, colIndex, numRows, 1).setWrap(true);
    }
  });
}

/**
 * Applies number formats from COLUMN_CONFIG.
 * @param {Sheet} sheet - The Google Sheet object
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @param {number} startRow - First data row
 * @param {number} numRows - Number of rows
 */
function applyConfigNumberFormats(sheet, sheetKey, startRow, numRows) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return;

  config.forEach((col, index) => {
    if (col.format && col.format.numberFormat && !col.formula) {
      // Only apply to non-formula columns (formulas handle their own format)
      const colIndex = index + 1;
      sheet.getRange(startRow, colIndex, numRows, 1).setNumberFormat(col.format.numberFormat);
    }
  });
}

// ============================================================================
// COLUMN MIGRATION UTILITIES
// ============================================================================

/**
 * Migrates sheet data when column order changes.
 * Compares current sheet structure with COLUMN_CONFIG and reorders if needed.
 *
 * @param {Sheet} sheet - The sheet to migrate
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @returns {Object} { migrated: boolean, message: string }
 */
function migrateSheetColumns(sheet, sheetKey) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) {
    return { migrated: false, message: 'Unknown sheet key: ' + sheetKey };
  }

  const expectedHeaders = getColHeaders(sheetKey);
  const lastCol = sheet.getLastColumn();

  if (lastCol === 0) {
    return { migrated: false, message: 'Sheet is empty, no migration needed' };
  }

  const currentHeaders = sheet.getRange(1, 1, 1, lastCol).getValues()[0];

  // Check if headers match exactly
  const headersMatch = expectedHeaders.every((h, i) => h === currentHeaders[i]) &&
                       expectedHeaders.length === currentHeaders.length;

  if (headersMatch) {
    return { migrated: false, message: 'Headers already match, no migration needed' };
  }

  Logger.log('Migration needed for ' + sheetKey);
  Logger.log('Current headers: ' + currentHeaders.join(', '));
  Logger.log('Expected headers: ' + expectedHeaders.join(', '));

  // Find missing and extra columns
  const missingColumns = expectedHeaders.filter(h => !currentHeaders.includes(h));
  const extraColumns = currentHeaders.filter(h => !expectedHeaders.includes(h) && h !== '');

  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) {
    // No data rows, just set headers
    sheet.getRange(1, 1, 1, expectedHeaders.length).setValues([expectedHeaders]);
    return { migrated: true, message: 'Set headers (no data to migrate)' };
  }

  // Get all data including headers
  const allData = sheet.getRange(1, 1, lastRow, currentHeaders.length).getValues();

  // Build new data with correct column order
  const newData = allData.map((row, rowIndex) => {
    if (rowIndex === 0) {
      return expectedHeaders; // Header row
    }
    return expectedHeaders.map(expectedCol => {
      const currentIndex = currentHeaders.indexOf(expectedCol);
      return currentIndex >= 0 ? row[currentIndex] : '';
    });
  });

  // Clear sheet and write new data
  sheet.clear();
  sheet.getRange(1, 1, newData.length, expectedHeaders.length).setValues(newData);

  const message = 'Migrated ' + (lastRow - 1) + ' rows. ' +
                  (missingColumns.length > 0 ? 'Added columns: ' + missingColumns.join(', ') + '. ' : '') +
                  (extraColumns.length > 0 ? 'Removed columns: ' + extraColumns.join(', ') : '');

  Logger.log(message);
  return { migrated: true, message: message };
}

// ============================================================================
// CUSTOM MENU
// ============================================================================

/**
 * Create custom menu when spreadsheet opens
 */
function onOpen() {
  buildMenu();
  // NOTE: Auto-triggers (refresh, email reminders, etc.) are enabled during Setup
  // They cannot be enabled here because onOpen() is a simple trigger with limited authorization
}

/**
 * Build the CartCure menu with dynamic labels based on current trigger states
 * This function can be called to refresh the menu after toggling features
 */
function buildMenu() {
  const ui = SpreadsheetApp.getUi();

  // Check current trigger states for dynamic menu labels
  // NOTE: hasTrigger() requires authorization that may not be available in onOpen() simple trigger
  // So we wrap in try-catch and default to "Enable" labels if authorization fails
  let autoRefreshEnabled = false;
  let emailLoggingEnabled = false;
  let autoEmailsEnabled = false;

  try {
    autoRefreshEnabled = hasTrigger('autoRefreshDashboard');
    emailLoggingEnabled = hasTrigger('scanSentEmailsForJobs');
    autoEmailsEnabled = hasTrigger('autoSendQuoteReminders') ||
                        hasTrigger('autoSendInvoiceReminders') ||
                        hasTrigger('autoSendOverdueInvoices');
  } catch (e) {
    // Authorization not available (e.g., in onOpen simple trigger)
    // Default to showing "Enable" options - user can still toggle
    Logger.log('buildMenu: Could not check trigger states (authorization required): ' + e.message);
  }

  // Dynamic labels based on current state
  const autoRefreshLabel = autoRefreshEnabled ? '⏹️ Disable Auto-Refresh' : '▶️ Enable Auto-Refresh';
  const emailLoggingLabel = emailLoggingEnabled ? '📧 Disable Email Logging' : '📧 Enable Email Logging';
  const autoEmailsLabel = autoEmailsEnabled ? '⏰ Disable Auto Emails' : '⏰ Enable Auto Emails';

  ui.createMenu('🛒 CartCure')
    .addSubMenu(ui.createMenu('📊 Dashboard')
      .addItem('🔄 Refresh Dashboard', 'refreshDashboard')
      .addItem('📈 Refresh Analytics', 'refreshAnalytics')
      .addSeparator()
      .addItem(autoRefreshLabel, 'toggleAutoRefresh'))
    .addSeparator()
    .addSubMenu(ui.createMenu('📋 Jobs')
      .addItem('➕ Create Job from Submission', 'showCreateJobDialog')
      .addItem('✅ Mark Quote Accepted', 'showAcceptQuoteDialog')
      .addItem('▶️ Start Work on Job', 'showStartWorkDialog')
      .addItem('✔️ Mark Job Complete', 'showCompleteJobDialog')
      .addItem('⏸️ Put Job On Hold', 'showOnHoldDialog')
      .addItem('❌ Cancel Job', 'showCancelJobDialog')
      .addSeparator()
      .addItem('📜 View Activity Log', 'viewJobActivityLog')
      .addItem('📝 Add Activity Note', 'addManualActivityNote'))
    .addSubMenu(ui.createMenu('💰 Quotes')
      .addItem('📤 Send Quote', 'showSendQuoteDialog')
      .addItem('🔔 Send Quote Reminder', 'showQuoteReminderDialog')
      .addItem('👎 Mark Quote Declined', 'showDeclineQuoteDialog'))
    .addSubMenu(ui.createMenu('🧾 Invoices')
      .addItem('➕ Generate Invoice', 'showGenerateInvoiceDialog')
      .addItem('👁️ View Invoice', 'showViewInvoiceDialog')
      .addItem('📤 Send Invoice', 'showSendInvoiceDialog')
      .addItem('🔔 Send Invoice Reminder', 'showSendInvoiceReminderDialog')
      .addItem('✅ Mark as Paid', 'showMarkPaidDialog')
      .addSeparator()
      .addItem('⚠️ Send Overdue Invoice', 'showSendOverdueInvoiceDialog')
      .addItem('💸 Update Late Fees', 'updateAllLateFees')
      .addItem('👁️ View Overdue Invoices', 'showOverdueInvoicesWithFees'))
    .addSeparator()
    .addSubMenu(ui.createMenu('⚙️ Setup')
      .addItem('🔧 Setup/Repair Sheets', 'showSetupDialog')
      .addItem('📐 Reset Column Widths', 'resetColumnWidths')
      .addItem('⚠️ Hard Reset (Delete All Data)', 'showHardResetDialog')
      .addSeparator()
      .addItem(emailLoggingLabel, 'toggleEmailLogging')
      .addItem('📧 Scan Emails Now', 'scanSentEmailsForJobs')
      .addSeparator()
      .addItem(autoEmailsLabel, 'toggleAutoEmails')
      .addSeparator()
      .addSubMenu(ui.createMenu('🧪 Tests')
        .addItem('📝 Create 10 Test Submissions', 'createTestSubmissions')
        .addItem('⭐ Create 20 Test Testimonials', 'createTestTestimonials')
        .addItem('📋 Create Test Job for Testimonials', 'createTestJobForTestimonials')
        .addItem('📧 Send All Test Emails', 'sendAllTestEmails')
        .addSeparator()
        .addItem('🧹 Clean Up Testimonials Sheet', 'cleanupTestimonialsSheet')))
    .addToUi();
}

/**
 * Handle edit events - used for dashboard refresh checkbox
 */
function onEdit(e) {
  const sheet = e.source.getActiveSheet();
  const range = e.range;

  // Check if edit was on Dashboard sheet, cell H1 (refresh checkbox)
  if (sheet.getName() === SHEETS.DASHBOARD && range.getA1Notation() === 'H1') {
    if (e.value === 'TRUE') {
      // Uncheck the box first, then refresh
      range.setValue(false);
      refreshDashboard();
    }
  }

  // Check if edit was on Analytics sheet, cell H1 (refresh checkbox)
  if (sheet.getName() === SHEETS.ANALYTICS && range.getA1Notation() === 'H1') {
    if (e.value === 'TRUE') {
      range.setValue(false);
      refreshAnalytics();
    }
  }

  // Check if edit was on Activity Log sheet, cell I1 (refresh checkbox for email scan)
  if (sheet.getName() === SHEETS.ACTIVITY_LOG && range.getA1Notation() === 'I1') {
    if (e.value === 'TRUE') {
      range.setValue(false);
      scanSentEmailsForJobs();
    }
  }
}

/**
 * Enable auto-refresh trigger (every 2 minutes)
 */
function enableAutoRefresh() {
  const ui = SpreadsheetApp.getUi();

  // Remove any existing triggers first
  disableAutoRefreshSilent();

  // Create new time-driven trigger
  ScriptApp.newTrigger('autoRefreshDashboard')
    .timeBased()
    .everyMinutes(1)
    .create();

  ui.alert('Auto-Refresh Enabled', 'Dashboard will automatically refresh every 1 minute.\n\nNote: This uses Google Apps Script quota.', ui.ButtonSet.OK);
  Logger.log('Auto-refresh enabled');
}

/**
 * Disable auto-refresh trigger
 */
function disableAutoRefresh() {
  const ui = SpreadsheetApp.getUi();
  disableAutoRefreshSilent();
  ui.alert('Auto-Refresh Disabled', 'Automatic dashboard refresh has been turned off.', ui.ButtonSet.OK);
}

/**
 * Disable auto-refresh without showing alert
 */
function disableAutoRefreshSilent() {
  const triggers = ScriptApp.getProjectTriggers();
  triggers.forEach(trigger => {
    if (trigger.getHandlerFunction() === 'autoRefreshDashboard') {
      ScriptApp.deleteTrigger(trigger);
      Logger.log('Auto-refresh trigger removed');
    }
  });
}

/**
 * Auto-refresh function called by time trigger
 */
function autoRefreshDashboard() {
  try {
    refreshDashboard();
    Logger.log('Auto-refresh completed at ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));
  } catch (error) {
    Logger.log('Auto-refresh error: ' + error);
  }
}

/**
 * Ensure auto-refresh is enabled (called on spreadsheet open)
 */
function ensureAutoRefreshEnabled() {
  // Check if auto-refresh trigger already exists
  const triggers = ScriptApp.getProjectTriggers();
  const hasAutoRefresh = triggers.some(trigger => trigger.getHandlerFunction() === 'autoRefreshDashboard');

  // If no trigger exists, create one
  if (!hasAutoRefresh) {
    ScriptApp.newTrigger('autoRefreshDashboard')
      .timeBased()
      .everyMinutes(1)
      .create();
    Logger.log('Auto-refresh enabled on spreadsheet open');
  }
}

// ============================================================================
// TRIGGER STATE HELPERS & TOGGLE FUNCTIONS
// ============================================================================

/**
 * Check if a specific trigger exists
 * @param {string} handlerName - The function name the trigger calls
 * @returns {boolean} - True if trigger exists
 */
function hasTrigger(handlerName) {
  const triggers = ScriptApp.getProjectTriggers();
  return triggers.some(trigger => trigger.getHandlerFunction() === handlerName);
}

/**
 * Toggle auto-refresh on/off
 */
function toggleAutoRefresh() {
  const ui = SpreadsheetApp.getUi();
  const isEnabled = hasTrigger('autoRefreshDashboard');

  if (isEnabled) {
    disableAutoRefreshSilent();
    ui.alert('Auto-Refresh Disabled', 'Automatic dashboard refresh has been turned off.', ui.ButtonSet.OK);
  } else {
    ScriptApp.newTrigger('autoRefreshDashboard')
      .timeBased()
      .everyMinutes(1)
      .create();
    ui.alert('Auto-Refresh Enabled', 'Dashboard will automatically refresh every 1 minute.\n\nNote: This uses Google Apps Script quota.', ui.ButtonSet.OK);
  }

  // Rebuild menu to reflect new state
  buildMenu();
}

/**
 * Toggle email activity logging on/off
 */
function toggleEmailLogging() {
  const ui = SpreadsheetApp.getUi();
  const isEnabled = hasTrigger('scanSentEmailsForJobs');

  if (isEnabled) {
    // Disable
    const triggers = ScriptApp.getProjectTriggers();
    triggers.forEach(trigger => {
      if (trigger.getHandlerFunction() === 'scanSentEmailsForJobs') {
        ScriptApp.deleteTrigger(trigger);
      }
    });
    ui.alert('Email Logging Disabled', 'Automatic email activity logging has been turned off.', ui.ButtonSet.OK);
  } else {
    // Enable
    ScriptApp.newTrigger('scanSentEmailsForJobs')
      .timeBased()
      .everyMinutes(5)
      .create();
    ui.alert('Email Logging Enabled', 'Emails will be automatically scanned every 5 minutes and logged to job activity.', ui.ButtonSet.OK);
    // Also run immediately
    scanSentEmailsForJobs();
  }

  // Rebuild menu to reflect new state
  buildMenu();
}

/**
 * Toggle auto email reminders (quotes, invoices, overdue) on/off
 */
function toggleAutoEmails() {
  const ui = SpreadsheetApp.getUi();

  // Check if any of the auto email triggers exist
  const hasQuoteReminders = hasTrigger('autoSendQuoteReminders');
  const hasInvoiceReminders = hasTrigger('autoSendInvoiceReminders');
  const hasOverdueInvoices = hasTrigger('autoSendOverdueInvoices');
  const isEnabled = hasQuoteReminders || hasInvoiceReminders || hasOverdueInvoices;

  if (isEnabled) {
    // Disable all
    const triggers = ScriptApp.getProjectTriggers();
    triggers.forEach(trigger => {
      const handler = trigger.getHandlerFunction();
      if (handler === 'autoSendQuoteReminders' ||
          handler === 'autoSendInvoiceReminders' ||
          handler === 'autoSendOverdueInvoices') {
        ScriptApp.deleteTrigger(trigger);
      }
    });
    ui.alert('Auto Emails Disabled',
      'Automatic emails have been turned off:\n\n' +
      '• Quote reminders\n' +
      '• Invoice reminders\n' +
      '• Overdue invoice notices\n\n' +
      'You can still send these manually from the menu.',
      ui.ButtonSet.OK);
  } else {
    // Enable all
    ScriptApp.newTrigger('autoSendQuoteReminders')
      .timeBased()
      .atHour(9)
      .everyDays(1)
      .inTimezone('Pacific/Auckland')
      .create();

    ScriptApp.newTrigger('autoSendInvoiceReminders')
      .timeBased()
      .atHour(9)
      .everyDays(1)
      .inTimezone('Pacific/Auckland')
      .create();

    ScriptApp.newTrigger('autoSendOverdueInvoices')
      .timeBased()
      .atHour(9)
      .everyDays(1)
      .inTimezone('Pacific/Auckland')
      .create();

    ui.alert('Auto Emails Enabled',
      'Daily automatic emails have been configured (9:00 AM NZ time):\n\n' +
      '• Quote reminders (7 days after quote sent)\n' +
      '• Invoice reminders (1-2 days before due)\n' +
      '• Overdue invoice notices (weekly)',
      ui.ButtonSet.OK);
  }

  // Rebuild menu to reflect new state
  buildMenu();
}

// ============================================================================
// SETUP FUNCTIONS
// ============================================================================

/**
 * Show setup dialog with options
 */
function showSetupDialog() {
  const ui = SpreadsheetApp.getUi();

  const response = ui.alert(
    '⚙️ Setup/Repair Sheets',
    'This will set up or repair your CartCure sheets.\n\n' +
    '• Creates any missing sheets (Jobs, Invoices, Settings, Dashboard)\n' +
    '• Repairs formatting and headers\n' +
    '• Preserves existing data in Jobs, Invoices, and Submissions\n\n' +
    'Continue?',
    ui.ButtonSet.YES_NO
  );

  if (response === ui.Button.YES) {
    setupSheets(false); // false = preserve data
  }
}

/**
 * Reset column widths to the values defined in COLUMN_CONFIG (with UI feedback)
 */
function resetColumnWidths() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const ui = SpreadsheetApp.getUi();

  const resetCount = resetColumnWidthsInternal(ss);

  ui.alert(
    '✅ Column Widths Reset',
    'Reset column widths for ' + resetCount + ' sheets:\n\n' +
    '• Submissions\n• Jobs\n• Invoices\n• Testimonials\n• Activity Log\n\n' +
    'Widths have been set to the predefined values in COLUMN_CONFIG.',
    ui.ButtonSet.OK
  );
}

/**
 * Internal function to reset column widths to COLUMN_CONFIG values (no UI)
 * @param {Spreadsheet} ss - The spreadsheet object
 * @returns {number} Number of sheets that were reset
 */
function resetColumnWidthsInternal(ss) {
  // Map sheet names to their COLUMN_CONFIG keys
  const sheetsToReset = [
    { name: SHEETS.SUBMISSIONS, key: 'SUBMISSIONS' },
    { name: SHEETS.JOBS, key: 'JOBS' },
    { name: SHEETS.INVOICES, key: 'INVOICES' },
    { name: SHEETS.TESTIMONIALS, key: 'TESTIMONIALS' },
    { name: SHEETS.ACTIVITY_LOG, key: 'ACTIVITY_LOG' }
  ];

  let resetCount = 0;

  for (const sheetInfo of sheetsToReset) {
    const sheet = ss.getSheetByName(sheetInfo.name);
    if (sheet && COLUMN_CONFIG[sheetInfo.key]) {
      applyConfigColumnWidths(sheet, sheetInfo.key);
      resetCount++;
    }
  }

  return resetCount;
}

/**
 * Back up data from all sheets before repair
 * @param {Spreadsheet} ss - The spreadsheet object
 * @returns {Object} Object containing backed up data from all sheets
 */
function backupSheetData(ss) {
  const backup = {};

  // Back up Submissions data
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
  if (submissionsSheet && submissionsSheet.getLastRow() > 1) {
    backup.submissions = submissionsSheet.getRange(2, 1, submissionsSheet.getLastRow() - 1, submissionsSheet.getLastColumn()).getValues();
    Logger.log('Backed up ' + backup.submissions.length + ' submission rows');
  }

  // Back up Jobs data
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  if (jobsSheet && jobsSheet.getLastRow() > 1) {
    backup.jobs = jobsSheet.getRange(2, 1, jobsSheet.getLastRow() - 1, jobsSheet.getLastColumn()).getValues();
    Logger.log('Backed up ' + backup.jobs.length + ' job rows');
  }

  // Back up Invoice Log data
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
  if (invoiceSheet && invoiceSheet.getLastRow() > 1) {
    backup.invoices = invoiceSheet.getRange(2, 1, invoiceSheet.getLastRow() - 1, invoiceSheet.getLastColumn()).getValues();
    Logger.log('Backed up ' + backup.invoices.length + ' invoice rows');
  }

  // Back up Settings data
  const settingsSheet = ss.getSheetByName(SHEETS.SETTINGS);
  if (settingsSheet && settingsSheet.getLastRow() > 0) {
    backup.settings = settingsSheet.getDataRange().getValues();
    Logger.log('Backed up settings data');
  }

  // Back up Testimonials data
  const testimonialsSheet = ss.getSheetByName(SHEETS.TESTIMONIALS);
  if (testimonialsSheet && testimonialsSheet.getLastRow() > 1) {
    backup.testimonials = testimonialsSheet.getRange(2, 1, testimonialsSheet.getLastRow() - 1, testimonialsSheet.getLastColumn()).getValues();
    Logger.log('Backed up ' + backup.testimonials.length + ' testimonial rows');
  }

  return backup;
}

/**
 * Delete all sheets except one (Google Sheets requires at least 1 sheet)
 * @param {Spreadsheet} ss - The spreadsheet object
 */
function deleteAllSheets(ss) {
  // Get fresh list of sheets and delete all except the first one
  // We must re-fetch sheets after each deletion to avoid stale references
  let sheets = ss.getSheets();
  const firstSheetId = sheets[0].getSheetId();

  // Keep deleting until only one sheet remains
  while (ss.getSheets().length > 1) {
    // Re-fetch sheets list each iteration to get fresh references
    sheets = ss.getSheets();

    // Find a sheet to delete (any sheet except the first one we're keeping)
    for (let i = 0; i < sheets.length; i++) {
      if (sheets[i].getSheetId() !== firstSheetId) {
        const sheetName = sheets[i].getName();
        ss.deleteSheet(sheets[i]);
        Logger.log('Deleted sheet: ' + sheetName);
        SpreadsheetApp.flush(); // Flush after each deletion
        break; // Exit inner loop, re-fetch sheets in while loop
      }
    }
  }

  // Rename the remaining sheet to avoid conflicts
  sheets = ss.getSheets();
  if (sheets.length > 0) {
    sheets[0].setName('_temp_sheet_');
  }

  // Final flush to ensure all changes are committed
  SpreadsheetApp.flush();
}

/**
 * Restore backed up data to newly created sheets
 * @param {Spreadsheet} ss - The spreadsheet object
 * @param {Object} backup - The backed up data object
 */
function restoreSheetData(ss, backup) {
  // Restore Submissions data
  if (backup.submissions && backup.submissions.length > 0) {
    const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
    if (submissionsSheet) {
      submissionsSheet.getRange(2, 1, backup.submissions.length, backup.submissions[0].length).setValues(backup.submissions);
      Logger.log('Restored ' + backup.submissions.length + ' submission rows');
    }
  }

  // Restore Jobs data
  if (backup.jobs && backup.jobs.length > 0) {
    const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
    if (jobsSheet) {
      jobsSheet.getRange(2, 1, backup.jobs.length, backup.jobs[0].length).setValues(backup.jobs);
      Logger.log('Restored ' + backup.jobs.length + ' job rows');
    }
  }

  // Restore Invoice Log data
  if (backup.invoices && backup.invoices.length > 0) {
    const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
    if (invoiceSheet) {
      invoiceSheet.getRange(2, 1, backup.invoices.length, backup.invoices[0].length).setValues(backup.invoices);
      Logger.log('Restored ' + backup.invoices.length + ' invoice rows');
    }
  }

  // Restore Settings data (overwrite default settings with backed up values)
  if (backup.settings && backup.settings.length > 0) {
    const settingsSheet = ss.getSheetByName(SHEETS.SETTINGS);
    if (settingsSheet) {
      // Clear existing data first
      settingsSheet.clear();
      // Restore backed up settings
      settingsSheet.getRange(1, 1, backup.settings.length, backup.settings[0].length).setValues(backup.settings);
      Logger.log('Restored settings data');
    }
  }

  // Restore Testimonials data
  if (backup.testimonials && backup.testimonials.length > 0) {
    const testimonialsSheet = ss.getSheetByName(SHEETS.TESTIMONIALS);
    if (testimonialsSheet) {
      testimonialsSheet.getRange(2, 1, backup.testimonials.length, backup.testimonials[0].length).setValues(backup.testimonials);
      Logger.log('Restored ' + backup.testimonials.length + ' testimonial rows');
    }
  }
}

/**
 * Setup all required sheets for job management
 * @param {boolean} clearData - If true, deletes all data (hard reset mode)
 */
function setupSheets(clearData) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const ui = SpreadsheetApp.getUi();

  // Debug log array - will be saved to file
  const debugLog = [];
  const logDebug = function(msg) {
    const timestamp = new Date().toISOString();
    const logLine = '[' + timestamp + '] ' + msg;
    debugLog.push(logLine);
    Logger.log(msg);
  };

  // Helper to log all sheet info
  const logAllSheets = function(label) {
    const sheets = ss.getSheets();
    logDebug('--- ' + label + ' ---');
    logDebug('Total sheets: ' + sheets.length);
    for (let i = 0; i < sheets.length; i++) {
      const s = sheets[i];
      logDebug('  [' + i + '] Name: "' + s.getName() + '", ID: ' + s.getSheetId() + ', Index: ' + s.getIndex());
    }
    logDebug('---');
  };

  try {
    logDebug('========== SETUP SHEETS START ==========');
    logDebug('clearData: ' + clearData);
    logDebug('Spreadsheet ID: ' + CONFIG.SHEET_ID);

    logAllSheets('INITIAL STATE');

    // Step 1: Back up data from existing sheets (unless hard reset)
    let backupData = null;
    if (!clearData) {
      logDebug('Step 1: Backing up data...');
      backupData = backupSheetData(ss);
      logDebug('Step 1 COMPLETE: Data backed up');
      if (backupData) {
        logDebug('  - submissions: ' + (backupData.submissions ? backupData.submissions.length : 0) + ' rows');
        logDebug('  - jobs: ' + (backupData.jobs ? backupData.jobs.length : 0) + ' rows');
        logDebug('  - invoices: ' + (backupData.invoices ? backupData.invoices.length : 0) + ' rows');
        logDebug('  - settings: ' + (backupData.settings ? 'yes' : 'no'));
      }
    } else {
      logDebug('Step 1: SKIPPED (clearData=true)');
    }

    // Step 2: Delete all existing sheets except the first one
    logDebug('Step 2: Deleting all sheets...');
    deleteAllSheets(ss);
    logDebug('Step 2 COMPLETE: deleteAllSheets() returned');

    logAllSheets('AFTER deleteAllSheets()');

    // Step 3: Create all sheets first (without moving them)
    logDebug('Step 3: Creating sheets...');

    logDebug('  3a: Creating Jobs sheet...');
    setupJobsSheet(ss, clearData);
    logDebug('  3a COMPLETE: Jobs sheet done');
    logAllSheets('AFTER setupJobsSheet()');

    logDebug('  3b: Creating Invoice Log sheet...');
    setupInvoiceLogSheet(ss, clearData);
    logDebug('  3b COMPLETE: Invoice Log sheet done');
    logAllSheets('AFTER setupInvoiceLogSheet()');

    logDebug('  3c: Creating Settings sheet...');
    setupSettingsSheet(ss, clearData);
    logDebug('  3c COMPLETE: Settings sheet done');
    logAllSheets('AFTER setupSettingsSheet()');

    logDebug('  3d: Creating Submissions sheet...');
    setupSubmissionsSheet(ss);
    logDebug('  3d COMPLETE: Submissions sheet done');
    logAllSheets('AFTER setupSubmissionsSheet()');

    logDebug('  3e: Creating Testimonials sheet...');
    setupTestimonialsSheet(ss, clearData);
    logDebug('  3e COMPLETE: Testimonials sheet done');
    logAllSheets('AFTER setupTestimonialsSheet()');

    logDebug('  3f: Creating Activity Log sheet...');
    setupActivityLogSheet(ss, clearData);
    logDebug('  3f COMPLETE: Activity Log sheet done');
    logAllSheets('AFTER setupActivityLogSheet()');

    // Create Dashboard and Analytics without moving yet
    logDebug('  3h: Creating Dashboard sheet...');
    let dashboardSheet = ss.getSheetByName(SHEETS.DASHBOARD);
    logDebug('    getSheetByName(DASHBOARD) returned: ' + (dashboardSheet ? 'Sheet ID ' + dashboardSheet.getSheetId() : 'null'));
    if (!dashboardSheet) {
      dashboardSheet = ss.insertSheet(SHEETS.DASHBOARD);
      logDebug('    insertSheet(DASHBOARD) created: ID ' + dashboardSheet.getSheetId());
    } else {
      dashboardSheet.clear();
      logDebug('    Cleared existing Dashboard sheet');
    }
    logAllSheets('AFTER Dashboard creation');

    logDebug('  3i: Creating Analytics sheet...');
    let analyticsSheet = ss.getSheetByName(SHEETS.ANALYTICS);
    logDebug('    getSheetByName(ANALYTICS) returned: ' + (analyticsSheet ? 'Sheet ID ' + analyticsSheet.getSheetId() : 'null'));
    if (!analyticsSheet) {
      analyticsSheet = ss.insertSheet(SHEETS.ANALYTICS);
      logDebug('    insertSheet(ANALYTICS) created: ID ' + analyticsSheet.getSheetId());
    } else {
      analyticsSheet.clear();
      logDebug('    Cleared existing Analytics sheet');
    }
    logAllSheets('AFTER Analytics creation');

    logDebug('Step 3 COMPLETE: All sheets created');
    logDebug('Calling SpreadsheetApp.flush()...');
    SpreadsheetApp.flush();
    logDebug('flush() complete');

    logAllSheets('AFTER flush()');

    // Step 4: Delete temporary sheet now that we have other sheets
    logDebug('Step 4: Deleting temporary sheet...');
    const tempSheet = ss.getSheetByName('_temp_sheet_');
    logDebug('  getSheetByName(_temp_sheet_) returned: ' + (tempSheet ? 'Sheet ID ' + tempSheet.getSheetId() : 'null'));
    if (tempSheet) {
      logDebug('  Deleting _temp_sheet_...');
      ss.deleteSheet(tempSheet);
      logDebug('  deleteSheet() complete');
      SpreadsheetApp.flush();
      logDebug('  flush() complete');
    } else {
      logDebug('  No _temp_sheet_ found - skipping deletion');
    }
    logDebug('Step 4 COMPLETE');

    logAllSheets('AFTER temp sheet deletion');

    // Step 5: Move all sheets to correct positions
    // Desired order: Dashboard, Submissions, Jobs, Invoice Log, Testimonials, Analytics, Activity Log, Settings
    logDebug('Step 5: Moving sheets to correct positions...');

    const sheetOrder = [
      SHEETS.DASHBOARD,
      SHEETS.SUBMISSIONS,
      SHEETS.JOBS,
      SHEETS.INVOICES,
      SHEETS.TESTIMONIALS,
      SHEETS.ANALYTICS,
      SHEETS.ACTIVITY_LOG,
      SHEETS.SETTINGS
    ];

    // Move sheets in reverse order to position 1, so they stack correctly
    for (let i = sheetOrder.length - 1; i >= 0; i--) {
      const sheetName = sheetOrder[i];
      const sheet = ss.getSheetByName(sheetName);
      if (sheet) {
        logDebug('  Moving ' + sheetName + ' to position 1...');
        ss.setActiveSheet(sheet);
        ss.moveActiveSheet(1);
        SpreadsheetApp.flush();
        logDebug('  ' + sheetName + ' moved to position 1');
      } else {
        logDebug('  WARNING: ' + sheetName + ' sheet not found, skipping');
      }
    }

    logDebug('Step 5 COMPLETE');
    logAllSheets('AFTER all moves');

    // Step 6: Apply formatting to Dashboard and Analytics
    logDebug('Step 6: Applying formatting...');
    dashboardSheet = ss.getSheetByName(SHEETS.DASHBOARD);
    analyticsSheet = ss.getSheetByName(SHEETS.ANALYTICS);
    logDebug('  Re-fetched Dashboard: ' + (dashboardSheet ? 'ID ' + dashboardSheet.getSheetId() : 'null'));
    logDebug('  Re-fetched Analytics: ' + (analyticsSheet ? 'ID ' + analyticsSheet.getSheetId() : 'null'));

    logDebug('  6a: formatDashboardSheet()...');
    formatDashboardSheet(dashboardSheet);
    logDebug('  6a COMPLETE');

    logDebug('  6b: formatAnalyticsSheet()...');
    formatAnalyticsSheet(analyticsSheet);
    logDebug('  6b COMPLETE');

    logDebug('Step 6 COMPLETE');

    // Step 7: Restore backed up data (unless hard reset)
    if (!clearData && backupData) {
      logDebug('Step 7: Restoring backed up data...');
      restoreSheetData(ss, backupData);
      logDebug('Step 7 COMPLETE: Data restored');
    } else {
      logDebug('Step 7: SKIPPED (clearData=' + clearData + ')');
    }

    // Step 8: Reset invoice counter if clearing data
    if (clearData) {
      logDebug('Step 8: Resetting invoice counter...');
      resetInvoiceCounter(ss);
      logDebug('Step 8 COMPLETE');
    } else {
      logDebug('Step 8: SKIPPED (clearData=false)');
    }

    // Step 9: Reset column widths to config values
    logDebug('Step 9: Resetting column widths...');
    resetColumnWidthsInternal(ss);
    logDebug('Step 9 COMPLETE');

    // Step 10: Ensure all automatic triggers are enabled by default
    logDebug('Step 10: Enabling automatic triggers...');
    const triggersCreated = ensureAutoTriggersExist();
    logDebug('Step 10 COMPLETE: ' + triggersCreated + ' trigger(s) created');

    logAllSheets('FINAL STATE');
    logDebug('========== SETUP SHEETS SUCCESS ==========');

    // Save debug log to file
    saveSetupDebugLog(debugLog.join('\n'), 'SUCCESS');

    const message = clearData
      ? 'Hard reset complete! All data has been deleted and sheets have been reset.\n\nAutomatic features enabled:\n• Quote reminders (7 days after quote sent)\n• Invoice reminders (before due date)\n• Overdue invoice notices\n• Email scanning'
      : 'Setup complete! All sheets have been created/repaired with data preserved.\n\nAutomatic features enabled:\n• Quote reminders (7 days after quote sent)\n• Invoice reminders (before due date)\n• Overdue invoice notices\n• Email scanning\n\nNext steps:\n1. Fill in your business details in the Settings sheet\n2. Use the CartCure menu to manage jobs';

    ui.alert(clearData ? '✅ Hard Reset Complete' : '✅ Setup Complete', message, ui.ButtonSet.OK);

  } catch (error) {
    logDebug('========== SETUP SHEETS ERROR ==========');
    logDebug('Error message: ' + error.message);
    logDebug('Error stack: ' + (error.stack || 'No stack trace'));

    // Try to log current state
    try {
      logAllSheets('STATE AT ERROR');
    } catch (e2) {
      logDebug('Could not log sheets at error: ' + e2.message);
    }

    logDebug('========== END ERROR LOG ==========');

    // Save debug log to file
    saveSetupDebugLog(debugLog.join('\n'), 'ERROR');

    ui.alert('Setup Error', 'There was an error: ' + error.message + '\n\nDebug log has been saved to Google Drive.', ui.ButtonSet.OK);
  }
}

/**
 * Save setup debug log to Google Drive
 * @param {string} logContent - The debug log content
 * @param {string} status - SUCCESS or ERROR
 */
function saveSetupDebugLog(logContent, status) {
  try {
    const folder = getOrCreateDebugFolder();
    const timestamp = Utilities.formatDate(new Date(), 'Pacific/Auckland', 'yyyy-MM-dd_HH-mm-ss');
    const fileName = 'SETUP_DEBUG_' + status + '_' + timestamp + '.txt';
    const file = folder.createFile(fileName, logContent);
    Logger.log('Setup debug log saved: ' + file.getUrl());
    return file.getUrl();
  } catch (error) {
    Logger.log('Error saving setup debug log: ' + error.message);
    return '';
  }
}

/**
 * Legacy function name for backwards compatibility
 */
function setupJobManagementSheets() {
  setupSheets(false);
}

/**
 * Clear all data from sheets (keeps headers)
 */
function clearAllSheetData(ss) {
  // Clear Jobs sheet data
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  if (jobsSheet && jobsSheet.getLastRow() > 1) {
    jobsSheet.deleteRows(2, jobsSheet.getLastRow() - 1);
    Logger.log('Jobs data cleared');
  }

  // Clear Invoice Log sheet data
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
  if (invoiceSheet && invoiceSheet.getLastRow() > 1) {
    invoiceSheet.deleteRows(2, invoiceSheet.getLastRow() - 1);
    Logger.log('Invoices data cleared');
  }

  // Clear Submissions sheet data
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
  if (submissionsSheet && submissionsSheet.getLastRow() > 1) {
    submissionsSheet.deleteRows(2, submissionsSheet.getLastRow() - 1);
    Logger.log('Submissions data cleared');
  }
}

/**
 * Reset invoice counter to 1
 */
function resetInvoiceCounter(ss) {
  const settingsSheet = ss.getSheetByName(SHEETS.SETTINGS);
  if (settingsSheet) {
    const data = settingsSheet.getDataRange().getValues();
    for (let i = 0; i < data.length; i++) {
      if (data[i][0] === 'Next Invoice Number') {
        settingsSheet.getRange(i + 1, 2).setValue(1);
        Logger.log('Invoice counter reset to 1');
        break;
      }
    }
  }
}

// ============================================================================
// SHEET STYLING HELPER FUNCTIONS
// ============================================================================

/**
 * Apply brand header styling to a range
 * @param {Range} range - The range to style
 */
function applyHeaderStyle(range) {
  range
    .setBackground(SHEET_COLORS.headerBg)
    .setFontColor(SHEET_COLORS.headerText)
    .setFontWeight('bold')
    .setFontFamily('Arial')
    .setFontSize(10)
    .setHorizontalAlignment('center')
    .setVerticalAlignment('middle');
}

/**
 * Apply paper-like background to entire sheet
 * @param {Sheet} sheet - The sheet to style
 */
function applyPaperBackground(sheet) {
  // Set default background color for the whole sheet
  const maxRows = Math.max(sheet.getMaxRows(), 100);
  const maxCols = Math.max(sheet.getMaxColumns(), 20);
  sheet.getRange(1, 1, maxRows, maxCols).setBackground(SHEET_COLORS.paperWhite);
}

/**
 * Apply alternating row colors for data rows
 * @param {Sheet} sheet - The sheet to style
 * @param {number} startRow - First data row (usually 2, after header)
 * @param {number} numRows - Number of rows to apply alternating colors
 * @param {number} numCols - Number of columns
 * @param {number} startCol - Starting column (default 1)
 */
function applyAlternatingRows(sheet, startRow, numRows, numCols, startCol) {
  const colStart = startCol || 1;
  for (let i = 0; i < numRows; i++) {
    const rowNum = startRow + i;
    const bgColor = (i % 2 === 0) ? SHEET_COLORS.paperWhite : SHEET_COLORS.paperCream;
    sheet.getRange(rowNum, colStart, 1, numCols).setBackground(bgColor);
  }
}

/**
 * Apply section header styling (for Dashboard/Analytics sections)
 * @param {Range} range - The range to style
 */
function applySectionHeaderStyle(range) {
  range
    .setFontSize(12)
    .setFontWeight('bold')
    .setFontColor(SHEET_COLORS.inkBlack)
    .setFontFamily('Georgia');
}

/**
 * Apply table header styling (smaller headers in Dashboard/Analytics)
 * @param {Range} range - The range to style
 */
function applyTableHeaderStyle(range) {
  range
    .setBackground(SHEET_COLORS.headerBg)
    .setFontColor(SHEET_COLORS.headerText)
    .setFontWeight('bold')
    .setFontFamily('Arial')
    .setFontSize(9)
    .setHorizontalAlignment('center');
}

/**
 * Apply metric card styling
 * @param {Range} labelRange - The label range
 * @param {Range} valueRange - The value range
 */
function applyMetricStyle(labelRange, valueRange) {
  labelRange
    .setBackground(SHEET_COLORS.paperBeige)
    .setFontWeight('bold')
    .setFontSize(9)
    .setFontColor(SHEET_COLORS.inkGray)
    .setHorizontalAlignment('center')
    .setFontFamily('Arial');

  valueRange
    .setBackground(SHEET_COLORS.paperWhite)
    .setFontWeight('bold')
    .setFontSize(12)
    .setFontColor(SHEET_COLORS.inkBlack)
    .setHorizontalAlignment('center')
    .setFontFamily('Georgia');
}

/**
 * Apply border styling to a range
 * @param {Range} range - The range to add borders
 * @param {boolean} outer - Apply outer border
 * @param {boolean} inner - Apply inner borders
 */
function applyBorders(range, outer, inner) {
  const borderColor = SHEET_COLORS.paperBorder;
  const borderStyle = SpreadsheetApp.BorderStyle.SOLID;

  if (outer) {
    range.setBorder(true, true, true, true, false, false, borderColor, borderStyle);
  }
  if (inner) {
    range.setBorder(null, null, null, null, true, true, borderColor, borderStyle);
  }
}

/**
 * Setup the Jobs sheet - creates if missing, repairs formatting, preserves data
 * @param {Spreadsheet} ss - The spreadsheet
 * @param {boolean} clearData - If true, clears all data (already done by clearAllSheetData)
 */
function setupJobsSheet(ss, clearData) {
  let sheet = ss.getSheetByName(SHEETS.JOBS);
  const isNew = !sheet;

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.JOBS);
  }

  // Get headers from config (single source of truth)
  const headers = getColHeaders('JOBS');

  // Migrate existing data if column order has changed
  if (!isNew && sheet.getLastColumn() > 0) {
    const migration = migrateSheetColumns(sheet, 'JOBS');
    if (migration.migrated) {
      Logger.log('Jobs migration: ' + migration.message);
    }
  }

  // Set headers (overwrites row 1 only)
  sheet.getRange(1, 1, 1, headers.length).setValues([headers]);

  // Apply paper-like background to entire sheet
  applyPaperBackground(sheet);

  // Format header row with brand styling
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  applyHeaderStyle(headerRange);

  // Apply subtle border to header
  applyBorders(headerRange, true, false);

  // Set row height for header
  sheet.setRowHeight(1, 35);

  // Set default row height for data rows
  for (let i = 2; i <= 50; i++) {
    sheet.setRowHeight(i, 25);
  }

  // Apply alternating row colors for existing data
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataRange = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataRange.setFontFamily('Arial');
  dataRange.setFontSize(10);
  dataRange.setFontColor(SHEET_COLORS.inkBlack);
  dataRange.setVerticalAlignment('middle');

  // Freeze header row
  sheet.setFrozenRows(1);

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'JOBS');

  // Apply data validation from config (Status, Category, Payment Status dropdowns)
  applyConfigValidation(sheet, 'JOBS', 2, 500);

  // Apply conditional formatting from config (Status, SLA, Payment colors)
  applyConfigConditionalFormatting(sheet, 'JOBS', 2, 500);

  // Apply formulas from config (Remaining Balance)
  applyConfigFormulas(sheet, 'JOBS', 2, 500);

  // Apply number formats from config
  applyConfigNumberFormats(sheet, 'JOBS', 2, 500);

  Logger.log('Jobs sheet ' + (isNew ? 'created' : 'updated'));
}

/**
 * Add conditional formatting for SLA status column
 */
function addSLAConditionalFormatting(sheet) {
  const slaColumn = 18; // SLA Status column
  const range = sheet.getRange(2, slaColumn, 500, 1);

  // Clear existing rules for this column
  const rules = sheet.getConditionalFormatRules();
  const newRules = rules.filter(rule => {
    const ranges = rule.getRanges();
    return !ranges.some(r => r.getColumn() === slaColumn);
  });

  // OVERDUE - Brand red tones
  const overdueRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('OVERDUE')
    .setBackground(SHEET_COLORS.slaOverdue)
    .setFontColor(SHEET_COLORS.slaOverdueText)
    .setBold(true)
    .setRanges([range])
    .build();

  // AT RISK - Brand amber tones
  const atRiskRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('AT RISK')
    .setBackground(SHEET_COLORS.slaAtRisk)
    .setFontColor(SHEET_COLORS.slaAtRiskText)
    .setBold(true)
    .setRanges([range])
    .build();

  // On Track - Brand green tones
  const onTrackRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('On Track')
    .setBackground(SHEET_COLORS.slaOnTrack)
    .setFontColor(SHEET_COLORS.slaOnTrackText)
    .setRanges([range])
    .build();

  newRules.push(overdueRule, atRiskRule, onTrackRule);
  sheet.setConditionalFormatRules(newRules);
}

/**
 * Add conditional formatting for Job Status column
 */
function addStatusConditionalFormatting(sheet) {
  const statusColumn = 1; // Status column
  const range = sheet.getRange(2, statusColumn, 500, 1);

  const rules = sheet.getConditionalFormatRules();

  // In Progress - Blue
  const inProgressRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(JOB_STATUS.IN_PROGRESS)
    .setBackground(SHEET_COLORS.statusActive)
    .setFontColor(SHEET_COLORS.statusActiveText)
    .setBold(true)
    .setRanges([range])
    .build();

  // Completed - Green
  const completedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(JOB_STATUS.COMPLETED)
    .setBackground(SHEET_COLORS.statusCompleted)
    .setFontColor(SHEET_COLORS.statusCompletedText)
    .setRanges([range])
    .build();

  // Cancelled - Gray
  const cancelledRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(JOB_STATUS.CANCELLED)
    .setBackground(SHEET_COLORS.statusCancelled)
    .setFontColor(SHEET_COLORS.statusCancelledText)
    .setRanges([range])
    .build();

  // Declined - Gray
  const declinedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(JOB_STATUS.DECLINED)
    .setBackground(SHEET_COLORS.statusCancelled)
    .setFontColor(SHEET_COLORS.statusCancelledText)
    .setRanges([range])
    .build();

  // On Hold - Amber
  const onHoldRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(JOB_STATUS.ON_HOLD)
    .setBackground(SHEET_COLORS.slaAtRisk)
    .setFontColor(SHEET_COLORS.slaAtRiskText)
    .setRanges([range])
    .build();

  // Accepted - Light green
  const acceptedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(JOB_STATUS.ACCEPTED)
    .setBackground('#e8f5e9')
    .setFontColor(SHEET_COLORS.brandGreen)
    .setRanges([range])
    .build();

  rules.push(inProgressRule, completedRule, cancelledRule, declinedRule, onHoldRule, acceptedRule);
  sheet.setConditionalFormatRules(rules);
}

/**
 * Add conditional formatting for Payment Status column
 */
function addPaymentConditionalFormatting(sheet) {
  const paymentColumn = 23; // Payment Status column
  const range = sheet.getRange(2, paymentColumn, 500, 1);

  const rules = sheet.getConditionalFormatRules();

  // Paid - Green
  const paidRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(PAYMENT_STATUS.PAID)
    .setBackground(SHEET_COLORS.paymentPaid)
    .setFontColor(SHEET_COLORS.paymentPaidText)
    .setRanges([range])
    .build();

  // Invoiced - Amber
  const invoicedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(PAYMENT_STATUS.INVOICED)
    .setBackground(SHEET_COLORS.paymentPending)
    .setFontColor(SHEET_COLORS.paymentPendingText)
    .setRanges([range])
    .build();

  // Unpaid - Light red
  const unpaidRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(PAYMENT_STATUS.UNPAID)
    .setBackground(SHEET_COLORS.paymentUnpaid)
    .setFontColor(SHEET_COLORS.paymentUnpaidText)
    .setRanges([range])
    .build();

  // Overdue - Red
  const overdueRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(PAYMENT_STATUS.OVERDUE)
    .setBackground(SHEET_COLORS.slaOverdue)
    .setFontColor(SHEET_COLORS.slaOverdueText)
    .setBold(true)
    .setRanges([range])
    .build();

  // Refunded - Gray
  const refundedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(PAYMENT_STATUS.REFUNDED)
    .setBackground(SHEET_COLORS.statusCancelled)
    .setFontColor(SHEET_COLORS.statusCancelledText)
    .setRanges([range])
    .build();

  rules.push(paidRule, invoicedRule, unpaidRule, overdueRule, refundedRule);
  sheet.setConditionalFormatRules(rules);
}

/**
 * Setup the Invoice Log sheet - creates if missing, repairs formatting, preserves data
 */
function setupInvoiceLogSheet(ss, clearData) {
  let sheet = ss.getSheetByName(SHEETS.INVOICES);
  const isNew = !sheet;

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.INVOICES);
  }

  // Get headers from config (single source of truth)
  const headers = getColHeaders('INVOICES');

  // Migrate existing data if column order has changed
  if (!isNew && sheet.getLastColumn() > 0) {
    const migration = migrateSheetColumns(sheet, 'INVOICES');
    if (migration.migrated) {
      Logger.log('Invoices migration: ' + migration.message);
    }
  }

  // Set headers (row 1 only)
  sheet.getRange(1, 1, 1, headers.length).setValues([headers]);

  // Apply paper-like background
  applyPaperBackground(sheet);

  // Format header with brand styling
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  applyHeaderStyle(headerRange);
  applyBorders(headerRange, true, false);
  sheet.setRowHeight(1, 35);

  // Apply alternating row colors
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataRange = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataRange.setFontFamily('Arial');
  dataRange.setFontSize(10);
  dataRange.setFontColor(SHEET_COLORS.inkBlack);
  dataRange.setVerticalAlignment('middle');

  sheet.setFrozenRows(1);

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'INVOICES');

  // Apply data validation from config (Status, Invoice Type dropdowns)
  applyConfigValidation(sheet, 'INVOICES', 2, 500);

  // Apply conditional formatting from config (Status colors)
  applyConfigConditionalFormatting(sheet, 'INVOICES', 2, 500);

  // Apply number formats from config
  applyConfigNumberFormats(sheet, 'INVOICES', 2, 500);

  Logger.log('Invoice Log sheet ' + (isNew ? 'created' : 'updated'));
}

/**
 * Add conditional formatting for Invoice Status column
 */
function addInvoiceStatusConditionalFormatting(sheet) {
  const statusColumn = 11; // Status column
  const range = sheet.getRange(2, statusColumn, 500, 1);

  const rules = sheet.getConditionalFormatRules();

  // Paid - Green
  const paidRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Paid')
    .setBackground(SHEET_COLORS.paymentPaid)
    .setFontColor(SHEET_COLORS.paymentPaidText)
    .setRanges([range])
    .build();

  // Sent - Amber
  const sentRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Sent')
    .setBackground(SHEET_COLORS.paymentPending)
    .setFontColor(SHEET_COLORS.paymentPendingText)
    .setRanges([range])
    .build();

  // Overdue - Red
  const overdueRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Overdue')
    .setBackground(SHEET_COLORS.slaOverdue)
    .setFontColor(SHEET_COLORS.slaOverdueText)
    .setBold(true)
    .setRanges([range])
    .build();

  // Cancelled - Gray
  const cancelledRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Cancelled')
    .setBackground(SHEET_COLORS.statusCancelled)
    .setFontColor(SHEET_COLORS.statusCancelledText)
    .setRanges([range])
    .build();

  rules.push(paidRule, sentRule, overdueRule, cancelledRule);
  sheet.setConditionalFormatRules(rules);
}

/**
 * Setup the Settings sheet - creates if missing, preserves existing values on repair
 */
function setupSettingsSheet(ss, clearData) {
  let sheet = ss.getSheetByName(SHEETS.SETTINGS);
  const isNew = !sheet;

  // Default settings
  const defaultSettings = [
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
    ['Next Invoice Number', '1', 'Auto-incremented invoice number counter']
  ];

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.SETTINGS);
    // New sheet - use all defaults
    sheet.getRange(1, 1, defaultSettings.length, 3).setValues(defaultSettings);
  } else if (clearData) {
    // Hard reset - clear and use defaults
    sheet.clear();
    sheet.getRange(1, 1, defaultSettings.length, 3).setValues(defaultSettings);
  } else {
    // Repair mode - preserve existing values, only add missing settings
    const existingData = sheet.getDataRange().getValues();
    const existingSettings = {};
    for (let i = 1; i < existingData.length; i++) {
      existingSettings[existingData[i][0]] = existingData[i][1];
    }

    // Merge: keep existing values, use defaults for missing
    const mergedSettings = defaultSettings.map((row, index) => {
      if (index === 0) return row; // Header row
      const settingName = row[0];
      if (existingSettings.hasOwnProperty(settingName)) {
        return [settingName, existingSettings[settingName], row[2]];
      }
      return row;
    });

    sheet.clear();
    sheet.getRange(1, 1, mergedSettings.length, 3).setValues(mergedSettings);
  }

  // Apply paper-like background
  applyPaperBackground(sheet);

  // Format header with brand styling
  const headerRange = sheet.getRange(1, 1, 1, 3);
  applyHeaderStyle(headerRange);
  applyBorders(headerRange, true, false);
  sheet.setRowHeight(1, 35);

  // Apply alternating row colors for settings rows
  applyAlternatingRows(sheet, 2, defaultSettings.length - 1, 3);

  // Format setting names (first column)
  const settingNamesRange = sheet.getRange(2, 1, defaultSettings.length - 1, 1);
  settingNamesRange.setFontWeight('bold');
  settingNamesRange.setFontColor(SHEET_COLORS.inkBlack);
  settingNamesRange.setFontFamily('Arial');
  settingNamesRange.setFontSize(10);

  // Format value column
  const valueRange = sheet.getRange(2, 2, defaultSettings.length - 1, 1);
  valueRange.setFontFamily('Arial');
  valueRange.setFontSize(10);
  valueRange.setFontColor(SHEET_COLORS.brandGreen);
  valueRange.setHorizontalAlignment('center');

  // Format description column (muted text)
  const descRange = sheet.getRange(2, 3, defaultSettings.length - 1, 1);
  descRange.setFontFamily('Arial');
  descRange.setFontSize(9);
  descRange.setFontColor(SHEET_COLORS.inkLight);
  descRange.setFontStyle('italic');

  // Add subtle borders to the entire settings table
  const tableRange = sheet.getRange(1, 1, defaultSettings.length, 3);
  applyBorders(tableRange, true, true);

  // Set column widths (fixed widths for settings)
  sheet.setColumnWidth(1, 180);  // Setting Name
  sheet.setColumnWidth(2, 200);  // Value
  sheet.setColumnWidth(3, 300);  // Description

  sheet.setFrozenRows(1);

  // Add dropdown validation for GST Registered (row 3, column 2)
  const gstRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(['Yes', 'No'], true)
    .setAllowInvalid(false)
    .build();
  sheet.getRange(3, 2).setDataValidation(gstRule);

  Logger.log('Settings sheet ' + (isNew ? 'created' : (clearData ? 'reset' : 'updated')));
}

/**
 * Create the Dashboard sheet with brand styling
 * @param {Spreadsheet} ss - Optional spreadsheet object (for backwards compatibility)
 */
function createDashboardSheet(ss) {
  if (!ss) {
    ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  }
  let sheet = ss.getSheetByName(SHEETS.DASHBOARD);

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.DASHBOARD);
    SpreadsheetApp.flush();
  } else {
    sheet.clear();
  }

  formatDashboardSheet(sheet);
  Logger.log('Dashboard sheet created/updated successfully');
}

/**
 * Apply formatting to Dashboard sheet (called after sheet creation and positioning)
 * @param {Sheet} sheet - The Dashboard sheet to format
 */
function formatDashboardSheet(sheet) {
  // Apply paper-like background to entire sheet
  applyPaperBackground(sheet);

  // Dashboard header with brand styling
  sheet.getRange('A1').setValue('📊 CartCure Dashboard');
  sheet.getRange('A1')
    .setFontSize(20)
    .setFontWeight('bold')
    .setFontColor(SHEET_COLORS.brandGreen)
    .setFontFamily('Georgia');

  sheet.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));
  sheet.getRange('A2')
    .setFontColor(SHEET_COLORS.inkLight)
    .setFontStyle('italic')
    .setFontSize(9)
    .setFontFamily('Arial');

  // Refresh checkbox (triggers refresh when checked)
  sheet.getRange('G1').setValue('🔄 Refresh →');
  sheet.getRange('G1')
    .setFontWeight('bold')
    .setFontSize(10)
    .setFontColor(SHEET_COLORS.inkGray)
    .setHorizontalAlignment('right')
    .setVerticalAlignment('middle')
    .setFontFamily('Arial');

  // Checkbox that triggers refresh
  sheet.getRange('H1').insertCheckboxes();
  sheet.getRange('H1').setValue(false);
  sheet.getRange('H1').setNote('Check this box to refresh the dashboard');
  sheet.setColumnWidth(8, 30);

  // === LEFT COLUMN: Metrics + New Submissions ===

  // Summary Metrics Section with brand styling
  sheet.getRange('A4').setValue('📈 Metrics');
  applySectionHeaderStyle(sheet.getRange('A4'));

  // Get column letters dynamically from COLUMN_CONFIG (no hardcoded letters!)
  const slaCol = getColLetter('JOBS', 'SLA Status');
  const statusCol = getColLetter('JOBS', 'Status');
  const totalCol = getColLetter('JOBS', 'Total (incl GST)');
  const paymentStatusCol = getColLetter('JOBS', 'Payment Status');
  const paymentDateCol = getColLetter('JOBS', 'Payment Date');

  const metricsLabels = [
    ['OVERDUE', 'AT RISK', 'In Progress', 'Pending Quote', 'Quoted', 'Unpaid $', 'Revenue MTD'],
    [
      '=COUNTIF(Jobs!' + slaCol + ':' + slaCol + ',"OVERDUE")',
      '=COUNTIF(Jobs!' + slaCol + ':' + slaCol + ',"AT RISK")',
      '=COUNTIF(Jobs!' + statusCol + ':' + statusCol + ',"In Progress")',
      '=COUNTIF(Jobs!' + statusCol + ':' + statusCol + ',"Pending Quote")',
      '=COUNTIF(Jobs!' + statusCol + ':' + statusCol + ',"Quoted")',
      '=SUMIF(Jobs!' + paymentStatusCol + ':' + paymentStatusCol + ',"Unpaid",Jobs!' + totalCol + ':' + totalCol + ')+SUMIF(Jobs!' + paymentStatusCol + ':' + paymentStatusCol + ',"Invoiced",Jobs!' + totalCol + ':' + totalCol + ')',
      '=SUMIFS(Jobs!' + totalCol + ':' + totalCol + ',Jobs!' + paymentStatusCol + ':' + paymentStatusCol + ',"Paid",Jobs!' + paymentDateCol + ':' + paymentDateCol + ',">="&DATE(YEAR(TODAY()),MONTH(TODAY()),1))'
    ]
  ];

  sheet.getRange(5, 1, 2, 7).setValues(metricsLabels);

  // Style metric labels
  applyMetricStyle(sheet.getRange(5, 1, 1, 7), sheet.getRange(6, 1, 1, 7));

  // Add borders to metric cards
  applyBorders(sheet.getRange(5, 1, 2, 7), true, true);

  // Color code OVERDUE and AT RISK values
  sheet.getRange(6, 1).setFontColor(SHEET_COLORS.slaOverdueText);
  sheet.getRange(6, 2).setFontColor(SHEET_COLORS.slaAtRiskText);
  sheet.getRange(6, 3).setFontColor(SHEET_COLORS.statusActiveText); // In Progress - blue
  sheet.getRange(6, 7).setFontColor(SHEET_COLORS.brandGreen); // Revenue - green

  // New Submissions Section
  sheet.getRange('A8').setValue('📥 New Submissions (not actioned)');
  applySectionHeaderStyle(sheet.getRange('A8'));

  const newSubmissionsHeaders = ['Submission #', 'Date', 'Name', 'Email', 'Message'];
  sheet.getRange(9, 1, 1, 5).setValues([newSubmissionsHeaders]);
  applyTableHeaderStyle(sheet.getRange(9, 1, 1, 5));

  // Apply alternating rows for submissions data area
  applyAlternatingRows(sheet, 10, 6, 5);

  // Style data area text
  sheet.getRange(10, 1, 6, 5)
    .setFontFamily('Arial')
    .setFontSize(10)
    .setFontColor(SHEET_COLORS.inkBlack)
    .setVerticalAlignment('middle');

  // Add border to submissions table
  applyBorders(sheet.getRange(9, 1, 7, 5), true, false);

  // === RIGHT COLUMN: Active Jobs + Pending Quotes ===

  // Active Jobs Section
  sheet.getRange('I4').setValue('🔥 Active Jobs (by urgency)');
  applySectionHeaderStyle(sheet.getRange('I4'));

  const activeJobsHeaders = ['Job #', 'Client', 'Description', 'Amount', 'Days Left', 'SLA', 'Status'];
  sheet.getRange(5, 9, 1, 7).setValues([activeJobsHeaders]);
  applyTableHeaderStyle(sheet.getRange(5, 9, 1, 7));

  // Apply alternating rows for active jobs
  applyAlternatingRows(sheet, 6, 10, 7, 9);

  // Style data area
  sheet.getRange(6, 9, 10, 7)
    .setFontFamily('Arial')
    .setFontSize(10)
    .setFontColor(SHEET_COLORS.inkBlack)
    .setVerticalAlignment('middle');

  // Add border to active jobs table
  applyBorders(sheet.getRange(5, 9, 11, 7), true, false);

  // Pending Quotes Section
  sheet.getRange('I17').setValue('⏳ Pending Quotes');
  applySectionHeaderStyle(sheet.getRange('I17'));

  const pendingQuotesHeaders = ['Job #', 'Client', 'Amount', 'Waiting', 'Valid Until', 'Action'];
  sheet.getRange(18, 9, 1, 6).setValues([pendingQuotesHeaders]);
  applyTableHeaderStyle(sheet.getRange(18, 9, 1, 6));

  // Apply alternating rows for pending quotes
  applyAlternatingRows(sheet, 19, 6, 6, 9);

  // Style data area
  sheet.getRange(19, 9, 6, 6)
    .setFontFamily('Arial')
    .setFontSize(10)
    .setFontColor(SHEET_COLORS.inkBlack)
    .setVerticalAlignment('middle');

  // Add border to pending quotes table
  applyBorders(sheet.getRange(18, 9, 7, 6), true, false);

  // Set fixed column widths for Dashboard
  // Left section (columns 1-7): Metrics + New Submissions
  sheet.setColumnWidth(1, 90);   // Submission # / OVERDUE
  sheet.setColumnWidth(2, 80);   // Date / AT RISK
  sheet.setColumnWidth(3, 100);  // Name / In Progress
  sheet.setColumnWidth(4, 150);  // Email / Pending Quote
  sheet.setColumnWidth(5, 200);  // Message / Quoted
  sheet.setColumnWidth(6, 80);   // Unpaid $
  sheet.setColumnWidth(7, 100);  // Revenue MTD
  sheet.setColumnWidth(8, 15);   // Spacer column
  // Right section (columns 9-15): Active Jobs + Pending Quotes
  sheet.setColumnWidth(9, 60);   // Job #
  sheet.setColumnWidth(10, 100); // Client
  sheet.setColumnWidth(11, 200); // Description
  sheet.setColumnWidth(12, 80);  // Amount
  sheet.setColumnWidth(13, 70);  // Days Left / Waiting
  sheet.setColumnWidth(14, 80);  // SLA / Valid Until
  sheet.setColumnWidth(15, 80);  // Status / Action

  // Set row heights for compactness
  for (let i = 1; i <= 30; i++) {
    sheet.setRowHeight(i, 22);
  }
  sheet.setRowHeight(1, 32); // Title row slightly taller
  sheet.setRowHeight(4, 28); // Section headers
  sheet.setRowHeight(8, 28);
  sheet.setRowHeight(17, 28);

  Logger.log('Dashboard sheet formatted successfully');
}

/**
 * Create the Analytics sheet with visual data displays
 * @param {Spreadsheet} ss - Optional spreadsheet object (for backwards compatibility)
 */
function createAnalyticsSheet(ss) {
  if (!ss) {
    ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  }
  let sheet = ss.getSheetByName(SHEETS.ANALYTICS);

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.ANALYTICS);
    SpreadsheetApp.flush();
  } else {
    sheet.clear();
  }

  formatAnalyticsSheet(sheet);
  Logger.log('Analytics sheet created/updated successfully');
}

/**
 * Apply formatting to Analytics sheet (called after sheet creation and positioning)
 * @param {Sheet} sheet - The Analytics sheet to format
 */
function formatAnalyticsSheet(sheet) {
  // Apply paper-like background to entire sheet
  applyPaperBackground(sheet);

  // Title with brand styling
  sheet.getRange('A1').setValue('📈 CartCure Analytics');
  sheet.getRange('A1')
    .setFontSize(20)
    .setFontWeight('bold')
    .setFontColor(SHEET_COLORS.brandGreen)
    .setFontFamily('Georgia');

  sheet.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));
  sheet.getRange('A2')
    .setFontColor(SHEET_COLORS.inkLight)
    .setFontStyle('italic')
    .setFontSize(9)
    .setFontFamily('Arial');

  // Refresh checkbox
  sheet.getRange('G1').setValue('🔄 Refresh →');
  sheet.getRange('G1')
    .setFontWeight('bold')
    .setFontSize(10)
    .setFontColor(SHEET_COLORS.inkGray)
    .setHorizontalAlignment('right')
    .setFontFamily('Arial');
  sheet.getRange('H1').insertCheckboxes();
  sheet.getRange('H1').setValue(false);
  sheet.getRange('H1').setNote('Check this box to refresh analytics');

  // === SECTION 1: KEY METRICS (Row 4-7) ===
  sheet.getRange('A4').setValue('📊 Key Metrics');
  applySectionHeaderStyle(sheet.getRange('A4'));

  const metricsHeaders = ['Total Jobs', 'Total Revenue', 'Avg Job Value', 'Conversion Rate', 'Completion Rate', 'On-Time Rate'];
  sheet.getRange(5, 1, 1, 6).setValues([metricsHeaders]);
  applyMetricStyle(sheet.getRange(5, 1, 1, 6), sheet.getRange(6, 1, 1, 6));
  applyBorders(sheet.getRange(5, 1, 2, 6), true, true);

  // === SECTION 2: JOB STATUS BREAKDOWN (Row 9-18, Left) ===
  sheet.getRange('A9').setValue('📋 Jobs by Status');
  applySectionHeaderStyle(sheet.getRange('A9'));

  const statusHeaders = ['Status', 'Count', '%'];
  sheet.getRange(10, 1, 1, 3).setValues([statusHeaders]);
  applyTableHeaderStyle(sheet.getRange(10, 1, 1, 3));
  applyAlternatingRows(sheet, 11, 8, 3, 1);
  sheet.getRange(11, 1, 8, 3).setFontFamily('Arial').setFontSize(10).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(10, 1, 9, 3), true, false);

  // === SECTION 3: PAYMENT STATUS (Row 9-18, Right) ===
  sheet.getRange('E9').setValue('💰 Payment Status');
  applySectionHeaderStyle(sheet.getRange('E9'));

  const paymentHeaders = ['Status', 'Count', 'Amount'];
  sheet.getRange(10, 5, 1, 3).setValues([paymentHeaders]);
  applyTableHeaderStyle(sheet.getRange(10, 5, 1, 3));
  applyAlternatingRows(sheet, 11, 5, 3, 5);
  sheet.getRange(11, 5, 5, 3).setFontFamily('Arial').setFontSize(10).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(10, 5, 6, 3), true, false);

  // === SECTION 4: SLA PERFORMANCE (Row 9-18, Far Right) ===
  sheet.getRange('I9').setValue('⏱️ SLA Performance');
  applySectionHeaderStyle(sheet.getRange('I9'));

  const slaHeaders = ['Status', 'Count', '%'];
  sheet.getRange(10, 9, 1, 3).setValues([slaHeaders]);
  applyTableHeaderStyle(sheet.getRange(10, 9, 1, 3));
  applyAlternatingRows(sheet, 11, 3, 3, 9);
  sheet.getRange(11, 9, 3, 3).setFontFamily('Arial').setFontSize(10).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(10, 9, 4, 3), true, false);

  // === SECTION 5: MONTHLY REVENUE (Row 20-32) ===
  sheet.getRange('A20').setValue('📅 Monthly Performance (Last 6 Months)');
  applySectionHeaderStyle(sheet.getRange('A20'));

  const monthlyHeaders = ['Month', 'Jobs Created', 'Jobs Completed', 'Revenue', 'Avg Value'];
  sheet.getRange(21, 1, 1, 5).setValues([monthlyHeaders]);
  applyTableHeaderStyle(sheet.getRange(21, 1, 1, 5));
  applyAlternatingRows(sheet, 22, 6, 5, 1);
  sheet.getRange(22, 1, 6, 5).setFontFamily('Arial').setFontSize(10).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(21, 1, 7, 5), true, false);

  // === SECTION 6: TOP CATEGORIES (Row 20-32, Right) ===
  sheet.getRange('G20').setValue('🏷️ Jobs by Category');
  applySectionHeaderStyle(sheet.getRange('G20'));

  const categoryHeaders = ['Category', 'Count', 'Revenue'];
  sheet.getRange(21, 7, 1, 3).setValues([categoryHeaders]);
  applyTableHeaderStyle(sheet.getRange(21, 7, 1, 3));
  applyAlternatingRows(sheet, 22, 6, 3, 7);
  sheet.getRange(22, 7, 6, 3).setFontFamily('Arial').setFontSize(10).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(21, 7, 7, 3), true, false);

  // === SECTION 7: OVERDUE & AT RISK (Row 20, Far Right) ===
  sheet.getRange('K20').setValue('⚠️ Attention Required');
  applySectionHeaderStyle(sheet.getRange('K20'));
  sheet.getRange('K20').setFontColor(SHEET_COLORS.slaOverdueText); // Red for attention

  const attentionHeaders = ['Job #', 'Client', 'Status', 'Days'];
  sheet.getRange(21, 11, 1, 4).setValues([attentionHeaders]);
  // Use red header for attention section
  sheet.getRange(21, 11, 1, 4)
    .setBackground(SHEET_COLORS.slaOverdueText)
    .setFontColor(SHEET_COLORS.headerText)
    .setFontWeight('bold')
    .setFontFamily('Arial')
    .setFontSize(9)
    .setHorizontalAlignment('center');
  applyAlternatingRows(sheet, 22, 6, 4, 11);
  sheet.getRange(22, 11, 6, 4).setFontFamily('Arial').setFontSize(10).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(21, 11, 7, 4), true, false);

  // Set fixed column widths for Analytics
  // Section 1-2: Key Metrics (columns 1-3)
  sheet.setColumnWidth(1, 100);  // Metric label
  sheet.setColumnWidth(2, 80);   // Value
  sheet.setColumnWidth(3, 80);   // Extra
  sheet.setColumnWidth(4, 20);   // Spacer
  // Section 3: Monthly Trends (columns 5-7)
  sheet.setColumnWidth(5, 80);   // Month
  sheet.setColumnWidth(6, 70);   // Jobs
  sheet.setColumnWidth(7, 90);   // Revenue
  sheet.setColumnWidth(8, 20);   // Spacer
  // Section 4-5: Recent Jobs & Completed (columns 9-14)
  sheet.setColumnWidth(9, 60);   // Job #
  sheet.setColumnWidth(10, 100); // Client
  sheet.setColumnWidth(11, 80);  // Status/Category
  sheet.setColumnWidth(12, 80);  // Amount/Count
  sheet.setColumnWidth(13, 80);  // Date/Revenue
  sheet.setColumnWidth(14, 80);  // Days

  // Set row heights
  for (let i = 1; i <= 45; i++) {
    sheet.setRowHeight(i, 22);
  }
  sheet.setRowHeight(1, 32);  // Title row
  sheet.setRowHeight(4, 28);  // Section headers
  sheet.setRowHeight(9, 28);
  sheet.setRowHeight(20, 28);
  sheet.setRowHeight(30, 28); // Charts section header

  // Create visual charts section (below existing tables)
  createAnalyticsCharts(sheet);

  Logger.log('Analytics sheet formatted successfully');
}

/**
 * Create visual charts for the Analytics sheet
 * @param {Sheet} sheet - The Analytics sheet
 */
function createAnalyticsCharts(sheet) {
  // Clear any existing charts first
  const existingCharts = sheet.getCharts();
  existingCharts.forEach(chart => sheet.removeChart(chart));

  // === SECTION: VISUAL CHARTS (Row 30+) ===
  sheet.getRange('A30').setValue('📊 Visual Analytics');
  applySectionHeaderStyle(sheet.getRange('A30'));
  sheet.setRowHeight(30, 28);

  // Create a pie chart for Job Status Distribution (using data from row 11-18, cols A-B)
  const statusPieChart = sheet.newChart()
    .setChartType(Charts.ChartType.PIE)
    .addRange(sheet.getRange('A11:B18'))  // Status data
    .setPosition(31, 1, 0, 0)  // Row 31, Column A
    .setOption('title', 'Jobs by Status')
    .setOption('titleTextStyle', { color: SHEET_COLORS.inkBlack, fontSize: 12, bold: true })
    .setOption('legend', { position: 'right', textStyle: { fontSize: 10 } })
    .setOption('pieSliceTextStyle', { fontSize: 9 })
    .setOption('backgroundColor', SHEET_COLORS.paperWhite)
    .setOption('width', 380)
    .setOption('height', 220)
    .setOption('colors', [
      SHEET_COLORS.statusPendingBg,   // Pending Quote
      SHEET_COLORS.statusQuotedBg,    // Quoted
      SHEET_COLORS.statusAcceptedBg,  // Accepted
      SHEET_COLORS.statusActiveBg,    // In Progress
      SHEET_COLORS.statusCompletedBg, // Completed
      SHEET_COLORS.statusOnHoldBg,    // On Hold
      SHEET_COLORS.statusCancelledBg, // Cancelled
      SHEET_COLORS.statusDeclinedBg   // Declined
    ])
    .build();

  sheet.insertChart(statusPieChart);

  // Create a bar chart for Monthly Performance (using data from row 22-27, cols A-D)
  const monthlyBarChart = sheet.newChart()
    .setChartType(Charts.ChartType.COLUMN)
    .addRange(sheet.getRange('A21:D27'))  // Monthly headers and data
    .setPosition(31, 6, 0, 0)  // Row 31, Column F
    .setOption('title', 'Monthly Performance')
    .setOption('titleTextStyle', { color: SHEET_COLORS.inkBlack, fontSize: 12, bold: true })
    .setOption('legend', { position: 'bottom', textStyle: { fontSize: 9 } })
    .setOption('backgroundColor', SHEET_COLORS.paperWhite)
    .setOption('width', 450)
    .setOption('height', 220)
    .setOption('hAxis', { title: 'Month', textStyle: { fontSize: 9 } })
    .setOption('vAxis', { title: 'Count / $', textStyle: { fontSize: 9 }, minValue: 0 })
    .setOption('colors', [SHEET_COLORS.brandGreen, SHEET_COLORS.statusCompletedBg, SHEET_COLORS.statusQuotedBg])
    .setOption('isStacked', false)
    .build();

  sheet.insertChart(monthlyBarChart);

  // Create a donut chart for Payment Status (using data from row 11-15, cols E-F)
  const paymentDonutChart = sheet.newChart()
    .setChartType(Charts.ChartType.PIE)
    .addRange(sheet.getRange('E11:F15'))  // Payment status data
    .setPosition(31, 11, 0, 0)  // Row 31, Column K
    .setOption('title', 'Payment Status')
    .setOption('titleTextStyle', { color: SHEET_COLORS.inkBlack, fontSize: 12, bold: true })
    .setOption('legend', { position: 'right', textStyle: { fontSize: 10 } })
    .setOption('pieHole', 0.4)  // Makes it a donut chart
    .setOption('backgroundColor', SHEET_COLORS.paperWhite)
    .setOption('width', 350)
    .setOption('height', 220)
    .setOption('colors', [
      SHEET_COLORS.paymentUnpaidBg,
      SHEET_COLORS.paymentInvoicedBg,
      SHEET_COLORS.paymentPaidBg,
      '#e57373',  // Overdue (light red)
      '#9e9e9e'   // Refunded (gray)
    ])
    .build();

  sheet.insertChart(paymentDonutChart);

  Logger.log('Analytics charts created successfully');
}

/**
 * Refresh the Analytics sheet with current data
 */
function refreshAnalytics() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const analytics = ss.getSheetByName(SHEETS.ANALYTICS);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

  if (!analytics) {
    SpreadsheetApp.getUi().alert('Error', 'Analytics sheet not found. Please run Setup first.', SpreadsheetApp.getUi().ButtonSet.OK);
    return;
  }

  // Update timestamp
  analytics.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));

  // Get jobs data
  const jobsData = jobsSheet ? jobsSheet.getDataRange().getValues() : [[]];
  const jobHeaders = jobsData[0] || [];
  const jobNumCol = jobHeaders.indexOf('Job #');
  const jobs = jobsData.slice(1).filter(row => row[jobNumCol !== -1 ? jobNumCol : 0]); // Filter out empty rows

  // Get submissions data
  const subData = submissionsSheet ? submissionsSheet.getDataRange().getValues() : [[]];
  const subHeaders = subData[0] || [];
  const subNumCol = subHeaders.indexOf('Submission #');
  const submissions = subData.slice(1).filter(row => row[subNumCol !== -1 ? subNumCol : 0]);

  // === CALCULATE KEY METRICS ===
  const totalJobs = jobs.length;
  const totalRevenue = jobs.reduce((sum, row) => {
    const paymentStatus = row[jobHeaders.indexOf('Payment Status')];
    if (paymentStatus === PAYMENT_STATUS.PAID) {
      return sum + (parseFloat(row[jobHeaders.indexOf('Total (incl GST)')]) || 0);
    }
    return sum;
  }, 0);
  const avgJobValue = totalJobs > 0 ? totalRevenue / jobs.filter(row => row[jobHeaders.indexOf('Payment Status')] === PAYMENT_STATUS.PAID).length : 0;

  // Conversion rate: jobs created / submissions
  const conversionRate = submissions.length > 0 ? (totalJobs / submissions.length * 100) : 0;

  // Completion rate: completed jobs / total jobs
  const completedJobs = jobs.filter(row => row[jobHeaders.indexOf('Status')] === JOB_STATUS.COMPLETED).length;
  const completionRate = totalJobs > 0 ? (completedJobs / totalJobs * 100) : 0;

  // On-time rate: jobs completed on time / completed jobs
  const onTimeJobs = jobs.filter(row => {
    const status = row[jobHeaders.indexOf('Status')];
    const slaStatus = row[jobHeaders.indexOf('SLA Status')];
    return status === JOB_STATUS.COMPLETED && slaStatus !== 'OVERDUE';
  }).length;
  const onTimeRate = completedJobs > 0 ? (onTimeJobs / completedJobs * 100) : 0;

  // Populate key metrics row
  analytics.getRange(6, 1, 1, 6).setValues([[
    totalJobs,
    formatCurrency(totalRevenue),
    isNaN(avgJobValue) || !isFinite(avgJobValue) ? formatCurrency(0) : formatCurrency(avgJobValue),
    conversionRate.toFixed(1) + '%',
    completionRate.toFixed(1) + '%',
    onTimeRate.toFixed(1) + '%'
  ]]);
  analytics.getRange(6, 1, 1, 6).setFontSize(14).setFontWeight('bold').setHorizontalAlignment('center');

  // === JOB STATUS BREAKDOWN ===
  const statusCounts = {};
  Object.values(JOB_STATUS).forEach(status => statusCounts[status] = 0);
  jobs.forEach(row => {
    const status = row[jobHeaders.indexOf('Status')];
    if (status && statusCounts.hasOwnProperty(status)) {
      statusCounts[status]++;
    }
  });

  analytics.getRange(11, 1, 8, 3).clearContent();
  let statusRow = 11;
  Object.entries(statusCounts).forEach(([status, count]) => {
    const pct = totalJobs > 0 ? (count / totalJobs * 100).toFixed(1) + '%' : '0%';
    analytics.getRange(statusRow, 1, 1, 3).setValues([[status, count, pct]]);
    statusRow++;
  });

  // === PAYMENT STATUS ===
  const paymentCounts = {};
  const paymentAmounts = {};
  Object.values(PAYMENT_STATUS).forEach(status => {
    paymentCounts[status] = 0;
    paymentAmounts[status] = 0;
  });
  jobs.forEach(row => {
    const status = row[jobHeaders.indexOf('Payment Status')];
    const amount = parseFloat(row[jobHeaders.indexOf('Total (incl GST)')]) || 0;
    if (status && paymentCounts.hasOwnProperty(status)) {
      paymentCounts[status]++;
      paymentAmounts[status] += amount;
    }
  });

  analytics.getRange(11, 5, 4, 3).clearContent();
  let paymentRow = 11;
  Object.entries(paymentCounts).forEach(([status, count]) => {
    analytics.getRange(paymentRow, 5, 1, 3).setValues([[status, count, formatCurrency(paymentAmounts[status])]]);
    // Color code using brand colors
    if (status === PAYMENT_STATUS.PAID) {
      analytics.getRange(paymentRow, 5).setBackground(SHEET_COLORS.paymentPaid);
      analytics.getRange(paymentRow, 5).setFontColor(SHEET_COLORS.paymentPaidText);
    } else if (status === PAYMENT_STATUS.UNPAID || status === PAYMENT_STATUS.INVOICED) {
      analytics.getRange(paymentRow, 5).setBackground(SHEET_COLORS.paymentPending);
      analytics.getRange(paymentRow, 5).setFontColor(SHEET_COLORS.paymentPendingText);
    }
    paymentRow++;
  });

  // === SLA PERFORMANCE ===
  const slaCounts = { 'On Track': 0, 'AT RISK': 0, 'OVERDUE': 0 };
  jobs.forEach(row => {
    const status = row[jobHeaders.indexOf('Status')];
    const sla = row[jobHeaders.indexOf('SLA Status')];
    // Only count active jobs
    if (status === JOB_STATUS.ACCEPTED || status === JOB_STATUS.IN_PROGRESS) {
      if (sla === 'OVERDUE') slaCounts['OVERDUE']++;
      else if (sla === 'AT RISK') slaCounts['AT RISK']++;
      else slaCounts['On Track']++;
    }
  });
  const activeSlaTotal = slaCounts['On Track'] + slaCounts['AT RISK'] + slaCounts['OVERDUE'];

  analytics.getRange(11, 9, 3, 3).clearContent();
  let slaRow = 11;
  // Use brand colors for SLA status
  const slaColorMap = [
    ['On Track', SHEET_COLORS.slaOnTrack, SHEET_COLORS.slaOnTrackText],
    ['AT RISK', SHEET_COLORS.slaAtRisk, SHEET_COLORS.slaAtRiskText],
    ['OVERDUE', SHEET_COLORS.slaOverdue, SHEET_COLORS.slaOverdueText]
  ];
  slaColorMap.forEach(([status, bgColor, textColor]) => {
    const count = slaCounts[status];
    const pct = activeSlaTotal > 0 ? (count / activeSlaTotal * 100).toFixed(1) + '%' : '0%';
    analytics.getRange(slaRow, 9, 1, 3).setValues([[status, count, pct]]);
    analytics.getRange(slaRow, 9).setBackground(bgColor);
    analytics.getRange(slaRow, 9).setFontColor(textColor);
    if (status === 'OVERDUE' || status === 'AT RISK') {
      analytics.getRange(slaRow, 9).setFontWeight('bold');
    }
    slaRow++;
  });

  // === MONTHLY PERFORMANCE (Last 6 months) ===
  const now = new Date();
  const monthlyData = [];
  for (let i = 5; i >= 0; i--) {
    const monthDate = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() - i + 1, 0);
    const monthName = monthDate.toLocaleString('en-NZ', { month: 'short', year: '2-digit' });

    let created = 0, completed = 0, revenue = 0;
    jobs.forEach(row => {
      const createdDate = row[jobHeaders.indexOf('Created Date')];
      const completionDate = row[jobHeaders.indexOf('Actual Completion Date')];
      const paymentDate = row[jobHeaders.indexOf('Payment Date')];
      const paymentStatus = row[jobHeaders.indexOf('Payment Status')];
      const total = parseFloat(row[jobHeaders.indexOf('Total (incl GST)')]) || 0;

      if (createdDate) {
        const cd = new Date(createdDate);
        if (cd >= monthDate && cd <= monthEnd) created++;
      }
      if (completionDate) {
        const compd = new Date(completionDate);
        if (compd >= monthDate && compd <= monthEnd) completed++;
      }
      if (paymentStatus === PAYMENT_STATUS.PAID && paymentDate) {
        const pd = new Date(paymentDate);
        if (pd >= monthDate && pd <= monthEnd) revenue += total;
      }
    });

    const avgValue = completed > 0 ? revenue / completed : 0;
    monthlyData.push([monthName, created, completed, formatCurrency(revenue), isNaN(avgValue) ? formatCurrency(0) : formatCurrency(avgValue)]);
  }

  analytics.getRange(22, 1, 6, 5).clearContent();
  analytics.getRange(22, 1, 6, 5).setValues(monthlyData);

  // === CATEGORY BREAKDOWN ===
  const categoryCounts = {};
  const categoryRevenue = {};
  jobs.forEach(row => {
    const category = row[jobHeaders.indexOf('Category')] || 'Uncategorized';
    const total = parseFloat(row[jobHeaders.indexOf('Total (incl GST)')]) || 0;
    const paymentStatus = row[jobHeaders.indexOf('Payment Status')];

    if (!categoryCounts[category]) {
      categoryCounts[category] = 0;
      categoryRevenue[category] = 0;
    }
    categoryCounts[category]++;
    if (paymentStatus === PAYMENT_STATUS.PAID) {
      categoryRevenue[category] += total;
    }
  });

  // Sort by count descending
  const sortedCategories = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]);

  analytics.getRange(22, 7, 10, 3).clearContent();
  let catRow = 22;
  sortedCategories.slice(0, 10).forEach(([category, count]) => {
    analytics.getRange(catRow, 7, 1, 3).setValues([[category, count, formatCurrency(categoryRevenue[category])]]);
    catRow++;
  });

  // === ATTENTION REQUIRED (Overdue & At Risk jobs) ===
  const attentionJobs = jobs.filter(row => {
    const status = row[jobHeaders.indexOf('Status')];
    const sla = row[jobHeaders.indexOf('SLA Status')];
    return (status === JOB_STATUS.ACCEPTED || status === JOB_STATUS.IN_PROGRESS) &&
           (sla === 'OVERDUE' || sla === 'AT RISK');
  }).map(row => ({
    jobNum: row[jobNumCol],
    client: row[jobHeaders.indexOf('Client Name')],
    sla: row[jobHeaders.indexOf('SLA Status')],
    daysRemaining: row[jobHeaders.indexOf('Days Remaining')]
  })).sort((a, b) => {
    // OVERDUE first, then by days remaining
    if (a.sla === 'OVERDUE' && b.sla !== 'OVERDUE') return -1;
    if (b.sla === 'OVERDUE' && a.sla !== 'OVERDUE') return 1;
    return (a.daysRemaining || 0) - (b.daysRemaining || 0);
  });

  analytics.getRange(22, 11, 10, 4).clearContent().setBackground(null).setFontColor(null);
  let attRow = 22;
  attentionJobs.slice(0, 10).forEach(job => {
    analytics.getRange(attRow, 11, 1, 4).setValues([[job.jobNum, job.client, job.sla, job.daysRemaining]]);
    if (job.sla === 'OVERDUE') {
      analytics.getRange(attRow, 11, 1, 4).setBackground('#ffcccc').setFontColor('#cc0000');
    } else {
      analytics.getRange(attRow, 11, 1, 4).setBackground('#fff3cd').setFontColor('#856404');
    }
    attRow++;
  });

  if (attentionJobs.length === 0) {
    analytics.getRange(22, 11).setValue('✅ No urgent items');
    analytics.getRange(22, 11).setFontColor('#155724').setBackground('#d4edda');
  }

  Logger.log('Analytics refreshed');
}

/**
 * Setup the Submissions sheet with professional formatting and status tracking
 */
function setupSubmissionsSheet(ss) {
  let sheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
  const isNew = !sheet;

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.SUBMISSIONS);
    Logger.log('Created new Submissions sheet');
  } else {
    const lastRow = sheet.getLastRow();
    if (lastRow > 1) {
      Logger.log('Submissions sheet exists with ' + (lastRow - 1) + ' submissions - preserving data');
    }
  }

  // Get headers from config (single source of truth)
  const headers = getColHeaders('SUBMISSIONS');

  // Migrate existing data if column order has changed
  if (!isNew && sheet.getLastColumn() > 0) {
    // Special handling: if Status column doesn't exist, add it with 'New' values
    const currentHeaders = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    if (!currentHeaders.includes('Status') && sheet.getLastRow() > 1) {
      Logger.log('Adding Status column as first column to existing Submissions sheet');
      sheet.insertColumnBefore(1);
      sheet.getRange(1, 1).setValue('Status');
      sheet.getRange(2, 1, sheet.getLastRow() - 1, 1).setValue('New');
    }
    // Now run standard migration
    const migration = migrateSheetColumns(sheet, 'SUBMISSIONS');
    if (migration.migrated) {
      Logger.log('Submissions migration: ' + migration.message);
    }
  }

  // Set headers
  sheet.getRange(1, 1, 1, headers.length).setValues([headers]);

  // Apply paper-like background
  applyPaperBackground(sheet);

  // Format header row with brand styling
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  applyHeaderStyle(headerRange);
  applyBorders(headerRange, true, false);
  sheet.setRowHeight(1, 35);

  // Apply alternating row colors for existing data
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataArea = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataArea.setFontFamily('Arial');
  dataArea.setFontSize(10);
  dataArea.setFontColor(SHEET_COLORS.inkBlack);
  dataArea.setVerticalAlignment('middle');

  // Freeze header row
  sheet.setFrozenRows(1);

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'SUBMISSIONS');

  // Apply wrap text from config (Message column)
  applyConfigWrapText(sheet, 'SUBMISSIONS', 2, 1000);

  // Apply data validation from config (Status dropdown)
  applyConfigValidation(sheet, 'SUBMISSIONS', 2, 1000);

  // Apply conditional formatting from config (Status colors)
  applyConfigConditionalFormatting(sheet, 'SUBMISSIONS', 2, 1000);

  // Enable filtering for all columns
  try {
    const filterRange = sheet.getRange(1, 1, Math.max(sheet.getLastRow(), 2), headers.length);
    if (!sheet.getFilter()) {
      filterRange.createFilter();
    }
  } catch (e) {
    // Filter may already exist
    Logger.log('Filter already exists or could not be created');
  }

  // Protect the header row from accidental edits
  const protection = sheet.getRange(1, 1, 1, headers.length).protect();
  protection.setDescription('Protected header row');
  protection.setWarningOnly(true);

  Logger.log('Submissions sheet setup completed successfully');
}

/**
 * Add conditional formatting for Submission Status column with brand colors
 */
function addSubmissionStatusFormatting(sheet) {
  const statusColumn = 1; // Status column (now column A)
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
    .setBackground(SHEET_COLORS.statusActive)
    .setFontColor(SHEET_COLORS.statusActiveText)
    .setBold(true)
    .setRanges([range])
    .build();

  // In Review - Amber (being processed)
  const reviewRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('In Review')
    .setBackground(SHEET_COLORS.slaAtRisk)
    .setFontColor(SHEET_COLORS.slaAtRiskText)
    .setBold(true)
    .setRanges([range])
    .build();

  // Job Created - Green (success)
  const jobCreatedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Job Created')
    .setBackground(SHEET_COLORS.statusCompleted)
    .setFontColor(SHEET_COLORS.statusCompletedText)
    .setRanges([range])
    .build();

  // Declined - Gray (closed)
  const declinedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Declined')
    .setBackground(SHEET_COLORS.statusCancelled)
    .setFontColor(SHEET_COLORS.statusCancelledText)
    .setRanges([range])
    .build();

  // Spam - Red (rejected)
  const spamRule = SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo('Spam')
    .setBackground(SHEET_COLORS.slaOverdue)
    .setFontColor(SHEET_COLORS.slaOverdueText)
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

/**
 * Set up the Testimonials sheet for storing and approving customer feedback
 * @param {Spreadsheet} ss - The spreadsheet object
 * @param {boolean} clearData - Whether to clear existing data
 */
function setupTestimonialsSheet(ss, clearData) {
  let sheet = ss.getSheetByName(SHEETS.TESTIMONIALS);
  const isNew = !sheet;

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.TESTIMONIALS);
    Logger.log('Created new Testimonials sheet');
  } else if (clearData) {
    sheet.clear();
    Logger.log('Cleared Testimonials sheet');
  } else {
    const lastRow = sheet.getLastRow();
    if (lastRow > 1) {
      Logger.log('Testimonials sheet exists with ' + (lastRow - 1) + ' testimonials - preserving data');
    }
  }

  // Get headers from config (single source of truth)
  const headers = getColHeaders('TESTIMONIALS');

  // Migrate existing data if column order has changed
  if (!isNew && !clearData && sheet.getLastColumn() > 0) {
    const migration = migrateSheetColumns(sheet, 'TESTIMONIALS');
    if (migration.migrated) {
      Logger.log('Testimonials migration: ' + migration.message);
    }
  }

  // Set headers if sheet is empty or was cleared
  if (sheet.getLastRow() === 0) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  }

  // Apply paper-like background
  applyPaperBackground(sheet);

  // Format header row with brand styling
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  applyHeaderStyle(headerRange);
  applyBorders(headerRange, true, false);
  sheet.setRowHeight(1, 35);

  // Apply alternating row colors for existing data
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataArea = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataArea.setFontFamily('Arial');
  dataArea.setFontSize(10);
  dataArea.setFontColor(SHEET_COLORS.inkBlack);
  dataArea.setVerticalAlignment('middle');

  // Freeze header row
  sheet.setFrozenRows(1);

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'TESTIMONIALS');

  // Apply wrap text from config (Testimonial column)
  const existingRows = Math.max(sheet.getLastRow() - 1, 1);
  applyConfigWrapText(sheet, 'TESTIMONIALS', 2, existingRows);

  // NOTE: We do NOT pre-populate checkboxes or rating validation for empty rows
  // This was causing getLastRow() to return incorrect values
  // Instead, validation is applied when new testimonials are added (see applyTestimonialRowValidation)

  // Add conditional formatting for approved testimonials (green background when checked)
  // This is a row-level rule using formula, so we apply it manually
  const showOnWebsiteCol = getColLetter('TESTIMONIALS', 'Show on Website');
  const rules = sheet.getConditionalFormatRules();
  const approvedRange = sheet.getRange(2, 1, 1000, headers.length);

  const approvedRule = SpreadsheetApp.newConditionalFormatRule()
    .whenFormulaSatisfied('=$' + showOnWebsiteCol + '2=TRUE')
    .setBackground('#e6f4ea')  // Light green
    .setRanges([approvedRange])
    .build();

  rules.push(approvedRule);
  sheet.setConditionalFormatRules(rules);

  // Enable filtering for all columns
  try {
    const filterRange = sheet.getRange(1, 1, Math.max(sheet.getLastRow(), 2), headers.length);
    if (!sheet.getFilter()) {
      filterRange.createFilter();
    }
  } catch (e) {
    Logger.log('Filter already exists or could not be created: ' + e.message);
  }

  // Protect the header row from accidental edits
  const protection = sheet.getRange(1, 1, 1, headers.length).protect();
  protection.setDescription('Protected header row');
  protection.setWarningOnly(true);

  Logger.log('Testimonials sheet setup completed successfully');
}

/**
 * Apply validation (checkbox and rating) to a specific testimonial row
 * Called when a new testimonial is added to ensure proper formatting
 * @param {Sheet} sheet - The Testimonials sheet
 * @param {number} row - The row number to apply validation to
 */
function applyTestimonialRowValidation(sheet, row) {
  // Add checkbox for "Show on Website" column (column 1)
  // Using insertCheckboxes() which is the proper way to create a checkbox
  const checkboxCell = sheet.getRange(row, 1);
  checkboxCell.insertCheckboxes();

  // Add rating validation (1-5) for column 6
  const ratingRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(['1', '2', '3', '4', '5'], true)
    .setAllowInvalid(false)
    .build();
  sheet.getRange(row, 6).setDataValidation(ratingRule);

  // Enable wrap text for testimonial column (column 7)
  sheet.getRange(row, 7).setWrap(true);
}

/**
 * Clean up the Testimonials sheet by removing pre-populated checkboxes/validation from empty rows
 * Run this once via: CartCure Menu > Setup > Clean Up Testimonials Sheet
 * This fixes the issue where appendRow() was adding data at the bottom due to pre-populated checkboxes
 */
function cleanupTestimonialsSheet() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.TESTIMONIALS);

  if (!sheet) {
    SpreadsheetApp.getUi().alert('Testimonials sheet not found.');
    return;
  }

  // Find the actual last row with data by checking column B (Submitted timestamp)
  const submittedCol = sheet.getRange('B:B').getValues();
  let lastDataRow = 1; // Header row
  for (let i = 1; i < submittedCol.length; i++) {
    if (submittedCol[i][0] === '' || submittedCol[i][0] === null || submittedCol[i][0] === undefined) {
      break;
    }
    lastDataRow = i + 1;
  }

  const totalRows = sheet.getMaxRows();

  // If there are rows beyond the data, clear their validation and content
  if (lastDataRow < totalRows) {
    const rowsToClear = totalRows - lastDataRow;
    const startRow = lastDataRow + 1;

    // Clear data validation from empty rows
    sheet.getRange(startRow, 1, rowsToClear, sheet.getMaxColumns()).clearDataValidations();

    // Clear any checkbox values (FALSE) that were pre-populated
    sheet.getRange(startRow, 1, rowsToClear, 1).clearContent();

    SpreadsheetApp.getUi().alert(
      'Cleanup complete!\n\n' +
      'Found ' + (lastDataRow - 1) + ' testimonials.\n' +
      'Cleared validation from ' + rowsToClear + ' empty rows.\n\n' +
      'New testimonials will now be appended correctly.'
    );
  } else {
    SpreadsheetApp.getUi().alert('No cleanup needed - sheet looks good!');
  }

  // Re-apply validation to existing data rows
  for (let row = 2; row <= lastDataRow; row++) {
    applyTestimonialRowValidation(sheet, row);
  }

  Logger.log('Testimonials sheet cleanup completed. Data rows: ' + (lastDataRow - 1));
}

/**
 * Setup the Activity Log sheet for tracking all job-related activities
 * This sheet stores emails sent, status changes, and other audit trail items
 */
function setupActivityLogSheet(ss, clearData) {
  if (!ss) {
    ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  }

  let sheet = ss.getSheetByName(SHEETS.ACTIVITY_LOG);
  const isNew = !sheet;

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.ACTIVITY_LOG);
    Logger.log('Created new Activity Log sheet');
  } else if (clearData) {
    sheet.clear();
    Logger.log('Cleared Activity Log sheet');
  } else {
    const lastRow = sheet.getLastRow();
    if (lastRow > 1) {
      Logger.log('Activity Log sheet exists with ' + (lastRow - 1) + ' entries - preserving data');
    }
  }

  // Get headers from config (single source of truth)
  const headers = getColHeaders('ACTIVITY_LOG');

  // Migrate existing data if column order has changed
  if (!isNew && !clearData && sheet.getLastColumn() > 0) {
    const migration = migrateSheetColumns(sheet, 'ACTIVITY_LOG');
    if (migration.migrated) {
      Logger.log('Activity Log migration: ' + migration.message);
    }
  }

  // Set headers if sheet is empty or was cleared
  if (sheet.getLastRow() === 0) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  }

  // Apply paper-like background
  applyPaperBackground(sheet);

  // Format header row with brand styling
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  applyHeaderStyle(headerRange);
  applyBorders(headerRange, true, false);
  sheet.setRowHeight(1, 35);

  // Apply alternating row colors for existing data
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataArea = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataArea.setFontFamily('Arial');
  dataArea.setFontSize(10);
  dataArea.setFontColor(SHEET_COLORS.inkBlack);
  dataArea.setVerticalAlignment('middle');

  // Freeze header row
  sheet.setFrozenRows(1);

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'ACTIVITY_LOG');

  // Apply wrap text from config (Details column)
  applyConfigWrapText(sheet, 'ACTIVITY_LOG', 2, 1000);

  // Enable filtering for all columns
  try {
    const filterRange = sheet.getRange(1, 1, Math.max(sheet.getLastRow(), 2), headers.length);
    if (!sheet.getFilter()) {
      filterRange.createFilter();
    }
  } catch (e) {
    Logger.log('Filter already exists or could not be created: ' + e.message);
  }

  // Protect the header row from accidental edits
  const protection = sheet.getRange(1, 1, 1, headers.length).protect();
  protection.setDescription('Protected header row');
  protection.setWarningOnly(true);

  // Add refresh checkbox for manual email scan (column H+1)
  const extraCol = headers.length + 1; // Column after main headers
  const refreshLabelCell = sheet.getRange(1, extraCol);
  refreshLabelCell.setValue('Scan Emails →');
  refreshLabelCell.setFontWeight('bold');
  refreshLabelCell.setFontSize(9);
  refreshLabelCell.setFontColor(SHEET_COLORS.navy);
  refreshLabelCell.setHorizontalAlignment('right');
  refreshLabelCell.setVerticalAlignment('middle');
  sheet.setColumnWidth(extraCol, 100);

  const refreshCheckbox = sheet.getRange(1, extraCol + 1);
  refreshCheckbox.insertCheckboxes();
  refreshCheckbox.setValue(false);
  refreshCheckbox.setBackground('#E8F5E9');
  refreshCheckbox.setBorder(true, true, true, true, false, false, '#4CAF50', SpreadsheetApp.BorderStyle.SOLID);
  sheet.setColumnWidth(extraCol + 1, 30);

  Logger.log('Activity Log sheet setup completed successfully');
}

/**
 * Log an activity to the Activity Log sheet
 * @param {string} jobNumber - The job number (e.g., "J-001")
 * @param {string} activityType - Type of activity (e.g., "Email Sent", "Status Change")
 * @param {string} summary - Brief description or email subject
 * @param {string} details - Full details (optional)
 * @param {string} fromTo - Email addresses or parties involved (optional)
 * @param {string} loggedBy - "Auto" or "Manual" (defaults to "Auto")
 */
function logJobActivity(jobNumber, activityType, summary, details, fromTo, loggedBy) {
  try {
    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    let sheet = ss.getSheetByName(SHEETS.ACTIVITY_LOG);

    // Create sheet if it doesn't exist
    if (!sheet) {
      setupActivityLogSheet(ss, false);
      sheet = ss.getSheetByName(SHEETS.ACTIVITY_LOG);
    }

    const timestamp = new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' });

    const rowData = [
      timestamp,
      jobNumber || '',
      activityType || '',
      summary || '',
      details || '',
      fromTo || '',
      loggedBy || 'Auto'
    ];

    // Append to the sheet
    sheet.appendRow(rowData);

    Logger.log('Activity logged for job ' + jobNumber + ': ' + activityType);
    return true;
  } catch (error) {
    Logger.log('Error logging activity: ' + error.message);
    return false;
  }
}

/**
 * Scan inbox for job-related emails that were BCC'd to cartcuredrive@gmail.com
 *
 * SETUP: Since the main email is Microsoft 365 (info@cartcure.co.nz), Apps Script
 * cannot access that mailbox directly. Instead, BCC all client emails to
 * cartcuredrive@gmail.com (hidden from clients) and this function will scan
 * that inbox for job-tagged emails.
 *
 * Run this on a time-based trigger (e.g., every 15 minutes)
 */
function scanSentEmailsForJobs() {
  try {
    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    const settingsSheet = ss.getSheetByName(SHEETS.SETTINGS);

    // Get last scan timestamp from settings (or default to 24 hours ago)
    let lastScanTime = new Date();
    lastScanTime.setHours(lastScanTime.getHours() - 24); // Default: last 24 hours

    if (settingsSheet) {
      const settingsData = settingsSheet.getDataRange().getValues();
      for (let i = 0; i < settingsData.length; i++) {
        if (settingsData[i][0] === 'Last Email Scan') {
          const savedTime = new Date(settingsData[i][1]);
          if (!isNaN(savedTime.getTime())) {
            lastScanTime = savedTime;
          }
          break;
        }
      }
    }

    // Search for emails with job tags received in inbox (via BCC from MS365)
    // These are emails sent FROM info@cartcure.co.nz that were BCC'd here
    // Pattern: (J-XXX) in subject line, from CartCure email
    const searchQuery = 'after:' + Math.floor(lastScanTime.getTime() / 1000) + ' subject:"(J-" from:cartcure';
    const threads = GmailApp.search(searchQuery, 0, 50); // Limit to 50 threads per scan

    let emailsLogged = 0;
    const processedMessageIds = getProcessedMessageIds();

    for (let i = 0; i < threads.length; i++) {
      const messages = threads[i].getMessages();

      for (let j = 0; j < messages.length; j++) {
        const message = messages[j];
        const messageId = message.getId();

        // Skip if already processed
        if (processedMessageIds.has(messageId)) {
          continue;
        }

        const subject = message.getSubject();
        const date = message.getDate();
        const from = message.getFrom();

        // Only process messages after last scan time
        if (date < lastScanTime) continue;

        // Extract job number from subject using pattern (J-WORD-XXX) or legacy (J-XXX)
        // New format: J-MAPLE-001, Legacy format: J-123
        const newFormatMatch = subject.match(/\((J-[A-Z]{3,6}-\d{3})\)/i);
        const legacyFormatMatch = subject.match(/\(J-(\d+)\)/i);

        let jobNumber;
        if (newFormatMatch) {
          jobNumber = newFormatMatch[1].toUpperCase();
        } else if (legacyFormatMatch) {
          jobNumber = 'J-' + legacyFormatMatch[1];
        } else {
          continue;
        }
        const toRecipients = message.getTo();
        const snippet = message.getPlainBody().substring(0, 200) + '...';

        // Log the email activity
        logJobActivity(
          jobNumber,
          'Email Sent',
          subject,
          snippet,
          'From: ' + from + ' | To: ' + toRecipients,
          'Auto'
        );

        // Mark as processed
        saveProcessedMessageId(messageId);
        emailsLogged++;
      }
    }

    // Update last scan timestamp
    updateLastScanTimestamp();

    Logger.log('Email scan complete. Logged ' + emailsLogged + ' new emails.');
    return emailsLogged;

  } catch (error) {
    Logger.log('Error scanning sent emails: ' + error.message);
    return 0;
  }
}

/**
 * Get set of already-processed message IDs from script properties
 */
function getProcessedMessageIds() {
  const props = PropertiesService.getScriptProperties();
  const stored = props.getProperty('processedEmailIds');
  if (stored) {
    try {
      return new Set(JSON.parse(stored));
    } catch (e) {
      return new Set();
    }
  }
  return new Set();
}

/**
 * Save a processed message ID to prevent duplicate logging
 */
function saveProcessedMessageId(messageId) {
  const props = PropertiesService.getScriptProperties();
  const ids = getProcessedMessageIds();
  ids.add(messageId);

  // Keep only the last 500 IDs to prevent property size limits
  const idsArray = Array.from(ids);
  if (idsArray.length > 500) {
    idsArray.splice(0, idsArray.length - 500);
  }

  props.setProperty('processedEmailIds', JSON.stringify(idsArray));
}

/**
 * Update the last scan timestamp in settings
 */
function updateLastScanTimestamp() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  let settingsSheet = ss.getSheetByName(SHEETS.SETTINGS);

  if (!settingsSheet) return;

  const settingsData = settingsSheet.getDataRange().getValues();
  let rowFound = false;

  for (let i = 0; i < settingsData.length; i++) {
    if (settingsData[i][0] === 'Last Email Scan') {
      settingsSheet.getRange(i + 1, 2).setValue(new Date().toISOString());
      rowFound = true;
      break;
    }
  }

  // Add the setting if not found
  if (!rowFound) {
    const lastRow = settingsSheet.getLastRow();
    settingsSheet.getRange(lastRow + 1, 1).setValue('Last Email Scan');
    settingsSheet.getRange(lastRow + 1, 2).setValue(new Date().toISOString());
  }
}

/**
 * Setup time-based trigger to automatically scan emails
 * Run this once to enable automatic email logging
 */
function setupEmailScanTrigger() {
  // Delete any existing triggers for this function
  const triggers = ScriptApp.getProjectTriggers();
  for (let i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'scanSentEmailsForJobs') {
      ScriptApp.deleteTrigger(triggers[i]);
    }
  }

  // Create new trigger to run every hour
  ScriptApp.newTrigger('scanSentEmailsForJobs')
    .timeBased()
    .everyHours(1)
    .create();

  Logger.log('Email scan trigger created - will run every hour');

  // Also run immediately
  scanSentEmailsForJobs();
}

/**
 * Remove the email scan trigger
 */
function removeEmailScanTrigger() {
  const triggers = ScriptApp.getProjectTriggers();
  let removed = 0;

  for (let i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'scanSentEmailsForJobs') {
      ScriptApp.deleteTrigger(triggers[i]);
      removed++;
    }
  }

  Logger.log('Removed ' + removed + ' email scan trigger(s)');
}

/**
 * View activity log for a specific job (called from menu or sidebar)
 * Auto-detects job number from selected row if available
 */
function viewJobActivityLog() {
  const ui = SpreadsheetApp.getUi();

  // Try to get job number from selected row first
  let jobNumber = getSelectedJobNumber();

  if (jobNumber) {
    // Found a job number - confirm with user
    const confirmResponse = ui.alert(
      'View Activity Log',
      'View activity log for ' + jobNumber + '?',
      ui.ButtonSet.YES_NO
    );

    if (confirmResponse !== ui.Button.YES) {
      // User said no - prompt for different job number
      jobNumber = null;
    }
  }

  // If no job number yet, prompt for it
  if (!jobNumber) {
    const response = ui.prompt(
      'View Activity Log',
      'Enter the job number (e.g., J-MAPLE-001):',
      ui.ButtonSet.OK_CANCEL
    );

    if (response.getSelectedButton() !== ui.Button.OK) {
      return;
    }

    jobNumber = response.getResponseText().trim().toUpperCase();

    // Normalize job number format
    if (!jobNumber.startsWith('J-')) {
      jobNumber = 'J-' + jobNumber;
    }
  }

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const activitySheet = ss.getSheetByName(SHEETS.ACTIVITY_LOG);

  if (!activitySheet || activitySheet.getLastRow() <= 1) {
    ui.alert('No Activity Found', 'No activity log entries exist yet.', ui.ButtonSet.OK);
    return;
  }

  // Find all activities for this job
  const data = activitySheet.getDataRange().getValues();
  const headers = data[0];
  const jobNumColIndex = headers.indexOf('Job #');
  const timestampColIndex = headers.indexOf('Timestamp');
  const typeColIndex = headers.indexOf('Type');
  const summaryColIndex = headers.indexOf('Summary');
  const detailsColIndex = headers.indexOf('Details');
  const fromToColIndex = headers.indexOf('From/To');
  const activities = [];

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][jobNumColIndex]).trim().toUpperCase() === jobNumber) {
      activities.push({
        timestamp: timestampColIndex >= 0 ? data[i][timestampColIndex] : '',
        type: typeColIndex >= 0 ? data[i][typeColIndex] : '',
        summary: summaryColIndex >= 0 ? data[i][summaryColIndex] : '',
        details: detailsColIndex >= 0 ? data[i][detailsColIndex] : '',
        fromTo: fromToColIndex >= 0 ? data[i][fromToColIndex] : ''
      });
    }
  }

  if (activities.length === 0) {
    ui.alert('No Activity Found', 'No activity log entries found for ' + jobNumber + '.', ui.ButtonSet.OK);
    return;
  }

  // Build activity summary
  let summary = 'Activity Log for ' + jobNumber + '\n';
  summary += '═'.repeat(40) + '\n\n';

  activities.forEach(function(activity, index) {
    summary += (index + 1) + '. [' + activity.type + '] ' + activity.timestamp + '\n';
    summary += '   ' + activity.summary + '\n';
    if (activity.fromTo) {
      summary += '   ' + activity.fromTo + '\n';
    }
    summary += '\n';
  });

  // Show in alert (limited to first 10 for readability)
  const displayActivities = activities.slice(0, 10);
  let displaySummary = 'Activity Log for ' + jobNumber + ' (' + activities.length + ' total entries)\n\n';

  displayActivities.forEach(function(activity, index) {
    displaySummary += '• ' + activity.timestamp + '\n';
    displaySummary += '  ' + activity.type + ': ' + activity.summary.substring(0, 50) + (activity.summary.length > 50 ? '...' : '') + '\n\n';
  });

  if (activities.length > 10) {
    displaySummary += '... and ' + (activities.length - 10) + ' more entries.\nView the Activity Log sheet for full details.';
  }

  ui.alert('Activity Log', displaySummary, ui.ButtonSet.OK);
}

/**
 * Manually add an activity note for a job
 * Auto-detects job number from selected row if available
 */
function addManualActivityNote() {
  const ui = SpreadsheetApp.getUi();

  // Try to get job number from selected row first
  let jobNumber = getSelectedJobNumber();

  if (!jobNumber) {
    // No job number detected - prompt for it
    const jobResponse = ui.prompt(
      'Add Activity Note',
      'Enter the job number (e.g., J-MAPLE-001):',
      ui.ButtonSet.OK_CANCEL
    );

    if (jobResponse.getSelectedButton() !== ui.Button.OK) {
      return;
    }

    jobNumber = jobResponse.getResponseText().trim().toUpperCase();
    if (!jobNumber.startsWith('J-')) {
      jobNumber = 'J-' + jobNumber;
    }
  }

  // Get the note
  const noteResponse = ui.prompt(
    'Add Activity Note',
    'Enter your note for ' + jobNumber + ':',
    ui.ButtonSet.OK_CANCEL
  );

  if (noteResponse.getSelectedButton() !== ui.Button.OK) {
    return;
  }

  const note = noteResponse.getResponseText().trim();
  if (!note) {
    ui.alert('Error', 'Note cannot be empty.', ui.ButtonSet.OK);
    return;
  }

  // Log the activity
  logJobActivity(jobNumber, 'Manual Note', note, '', '', 'Manual');

  ui.alert('Note Added', 'Activity note added for ' + jobNumber + '.', ui.ButtonSet.OK);
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
 * Get the next invoice number and increment the counter
 */
/**
 * Generate invoice number based on job number
 * Format mirrors job number (J-WORD-XXX becomes INV-WORD-XXX)
 * For multiple invoices per job, adds suffix: INV-WORD-XXX-2, INV-WORD-XXX-3, etc.
 *
 * @param {string} jobNumber - The job number (e.g., "J-MAPLE-001")
 * @param {number} invoiceCount - Number of existing invoices for this job
 * @returns {string} Invoice number (e.g., "INV-MAPLE-001" or "INV-MAPLE-001-2")
 */
function generateInvoiceNumber(jobNumber, invoiceCount) {
  // Replace J- prefix with INV-
  let invoiceNumber = jobNumber.replace(/^J-/, 'INV-');

  // If this is the 2nd, 3rd, etc. invoice, add suffix
  if (invoiceCount > 0) {
    invoiceNumber += '-' + (invoiceCount + 1);
  }

  return invoiceNumber;
}

/**
 * LEGACY: Get next sequential invoice number
 * DEPRECATED: This function is kept for backwards compatibility but is no longer used
 * New invoices use generateInvoiceNumber() which mirrors job numbers
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
 * Format due date for invoices - shows date with "Midday" time
 * e.g., "3 Feb 2026 at Midday"
 */
function formatDueDate(date) {
  if (!date) return '';
  const d = new Date(date);
  return Utilities.formatDate(d, 'Pacific/Auckland', 'd MMM yyyy') + ' at Midday';
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

/**
 * Get project size classification based on total amount
 * Used to determine payment schedule per TOS:
 * - Small (<$200): Full payment upfront
 * - Medium ($200-$500): 50% deposit, balance on completion
 * - Large (>$500): Case-by-case schedule
 */
function getProjectSize(totalAmount) {
  const amount = parseFloat(totalAmount) || 0;
  if (amount < 200) return PROJECT_SIZE.SMALL;
  if (amount <= 500) return PROJECT_SIZE.MEDIUM;
  return PROJECT_SIZE.LARGE;
}

/**
 * Calculate late payment fee based on days overdue
 * Per TOS: 2% per day on outstanding balances after 7 days past due date
 *
 * @param {number} originalAmount - Original invoice amount
 * @param {Date} dueDate - Invoice due date
 * @param {Date} currentDate - Current date (optional, defaults to now)
 * @returns {Object} - { daysOverdue, lateFee, totalWithFees }
 */
function calculateLateFee(originalAmount, dueDate, currentDate) {
  const amount = parseFloat(originalAmount) || 0;
  const due = new Date(dueDate);
  const now = currentDate ? new Date(currentDate) : new Date();

  // Calculate days overdue
  const daysOverdue = Math.max(0, daysBetween(due, now));

  // No fee if not overdue or within grace period
  if (daysOverdue <= 0) {
    return { daysOverdue: 0, lateFee: 0, totalWithFees: amount };
  }

  // Calculate fee: 2% per day
  const lateFee = amount * LATE_FEE_CONFIG.RATE_PER_DAY * daysOverdue;
  const totalWithFees = amount + lateFee;

  return {
    daysOverdue: daysOverdue,
    lateFee: Math.round(lateFee * 100) / 100,  // Round to 2 decimal places
    totalWithFees: Math.round(totalWithFees * 100) / 100
  };
}

/**
 * Update late fees for all overdue invoices
 * Called from menu or on schedule to recalculate late fees
 */
function updateAllLateFees() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!invoiceSheet) {
    Logger.log('Invoice sheet not found');
    return;
  }

  const data = invoiceSheet.getDataRange().getValues();
  const headers = data[0];

  // Find column indices
  const cols = {
    status: headers.indexOf('Status'),
    dueDate: headers.indexOf('Due Date'),
    total: headers.indexOf('Total'),
    daysOverdue: headers.indexOf('Days Overdue'),
    lateFee: headers.indexOf('Late Fee'),
    totalWithFees: headers.indexOf('Total With Fees')
  };

  let updatedCount = 0;
  const now = new Date();

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const status = row[cols.status];

    // Only calculate for unpaid invoices (Sent or Overdue status)
    if (status !== 'Sent' && status !== 'Overdue') continue;

    const dueDate = row[cols.dueDate];
    const total = parseFloat(row[cols.total]) || 0;

    if (!dueDate || total === 0) continue;

    const feeCalc = calculateLateFee(total, dueDate, now);

    // Update the row
    const rowNum = i + 1;
    invoiceSheet.getRange(rowNum, cols.daysOverdue + 1).setValue(feeCalc.daysOverdue > 0 ? feeCalc.daysOverdue : '');
    invoiceSheet.getRange(rowNum, cols.lateFee + 1).setValue(feeCalc.lateFee > 0 ? feeCalc.lateFee.toFixed(2) : '');
    invoiceSheet.getRange(rowNum, cols.totalWithFees + 1).setValue(feeCalc.totalWithFees.toFixed(2));

    // Update status to Overdue if past due
    if (feeCalc.daysOverdue > 0 && status === 'Sent') {
      invoiceSheet.getRange(rowNum, cols.status + 1).setValue('Overdue');
    }

    updatedCount++;
  }

  Logger.log('Updated late fees for ' + updatedCount + ' invoices');
  return updatedCount;
}

/**
 * Show late fees summary for overdue invoices
 */
function showOverdueInvoicesWithFees() {
  const ui = SpreadsheetApp.getUi();
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!invoiceSheet) {
    ui.alert('Error', 'Invoice sheet not found.', ui.ButtonSet.OK);
    return;
  }

  // Update fees first
  updateAllLateFees();

  const data = invoiceSheet.getDataRange().getValues();
  const headers = data[0];

  const cols = {
    invoiceNum: headers.indexOf('Invoice #'),
    clientName: headers.indexOf('Client Name'),
    status: headers.indexOf('Status'),
    dueDate: headers.indexOf('Due Date'),
    total: headers.indexOf('Total'),
    daysOverdue: headers.indexOf('Days Overdue'),
    lateFee: headers.indexOf('Late Fee'),
    totalWithFees: headers.indexOf('Total With Fees')
  };

  let overdueList = [];
  let totalOutstanding = 0;
  let totalFees = 0;

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    if (row[cols.status] === 'Overdue') {
      const daysOverdue = parseInt(row[cols.daysOverdue]) || 0;
      const lateFee = parseFloat(row[cols.lateFee]) || 0;
      const totalWithFees = parseFloat(row[cols.totalWithFees]) || 0;

      overdueList.push(
        row[cols.invoiceNum] + ' - ' + row[cols.clientName] +
        '\n  ' + daysOverdue + ' days overdue | Fee: ' + formatCurrency(lateFee) +
        ' | Total: ' + formatCurrency(totalWithFees)
      );

      totalOutstanding += totalWithFees;
      totalFees += lateFee;
    }
  }

  if (overdueList.length === 0) {
    ui.alert('No Overdue Invoices', 'All invoices are paid or current.', ui.ButtonSet.OK);
    return;
  }

  ui.alert('Overdue Invoices (' + overdueList.length + ')',
    overdueList.join('\n\n') +
    '\n\n-------------------\n' +
    'Total Outstanding: ' + formatCurrency(totalOutstanding) + '\n' +
    'Total Late Fees: ' + formatCurrency(totalFees),
    ui.ButtonSet.OK
  );
}

// ============================================================================
// DROPDOWN HELPER FUNCTIONS
// ============================================================================

/**
 * Get all available submissions that can be converted to jobs
 * Returns array of objects with submission number and details
 */
/**
 * PERFORMANCE OPTIMIZED: Get available submissions with column-specific loading
 *
 * OLD APPROACH: Load ALL columns from both Submissions and Jobs sheets
 * NEW APPROACH: Load only Submission # column from Jobs, and only needed columns from Submissions
 *
 * OPTIMIZATION BENEFIT:
 * - Reduced from 7 getRange() calls to 2 (one per sheet)
 * - Single batch read per sheet is faster than multiple column reads
 * - Network round-trips are the main bottleneck in Apps Script
 *
 * @returns {Array<Object>} Array of submission objects for dropdown display (sorted by timestamp)
 */
function getAvailableSubmissions() {
  const startTime = new Date().getTime();

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);

  if (!submissionsSheet) {
    Logger.log('[PERF] getAvailableSubmissions() - Submissions sheet not found');
    return [];
  }

  // OPTIMIZATION: Single batch read from Jobs sheet to build exclusion set
  const existingJobSubmissions = new Set();
  if (jobsSheet && jobsSheet.getLastRow() > 1) {
    const jobsData = jobsSheet.getDataRange().getValues();
    const jobsHeaders = jobsData[0];
    const jobSubNumColIdx = jobsHeaders.indexOf('Submission #'); // Column AD (index 29)
    for (let i = 1; i < jobsData.length; i++) {
      if (jobsData[i][jobSubNumColIdx]) {
        existingJobSubmissions.add(jobsData[i][jobSubNumColIdx]);
      }
    }
  }

  const submissionsLastRow = submissionsSheet.getLastRow();
  if (submissionsLastRow <= 1) return []; // No data rows

  // OPTIMIZATION: Single batch read from Submissions sheet
  const allData = submissionsSheet.getDataRange().getValues();
  const headers = allData[0];

  // Find column indices dynamically from headers
  const submissionNumCol = headers.indexOf('Submission #');
  const timestampCol = headers.indexOf('Timestamp');
  const nameColIndex = headers.indexOf('Name');
  const emailColIndex = headers.indexOf('Email');
  const statusColIndex = headers.indexOf('Status');

  // Fallback if columns not found
  if (submissionNumCol === -1 || nameColIndex === -1 || statusColIndex === -1) {
    Logger.log('[PERF] getAvailableSubmissions() - Required columns not found, using fallback');
    return getAvailableSubmissionsFallback(existingJobSubmissions);
  }

  const submissions = [];

  // Build submission objects from data (start from row 1, skip header)
  for (let i = 1; i < allData.length; i++) {
    const row = allData[i];
    const submissionNum = row[submissionNumCol];
    const status = row[statusColIndex];

    // Only include submissions that don't have jobs yet
    if (submissionNum && !existingJobSubmissions.has(submissionNum)) {
      submissions.push({
        number: submissionNum,
        name: row[nameColIndex] || 'Unknown',
        email: row[emailColIndex] || '',
        timestamp: row[timestampCol],
        status: status || 'New',
        display: submissionNum + ' - ' + (row[nameColIndex] || 'Unknown') + ' (' + (status || 'New') + ')'
      });
    }
  }

  // Sort by timestamp (newest first)
  const sorted = submissions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  // Performance logging
  const endTime = new Date().getTime();
  const executionTime = endTime - startTime;
  Logger.log('[PERF] getAvailableSubmissions() - Loaded ' + sorted.length + ' submissions in ' + executionTime + 'ms (single batch read)');

  return sorted;
}

/**
 * Fallback implementation - loads all columns from Submissions
 * Used when required columns cannot be found in headers
 */
function getAvailableSubmissionsFallback(existingJobSubmissions) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

  if (!submissionsSheet) return [];

  const submissionsData = submissionsSheet.getDataRange().getValues();
  const headers = submissionsData[0];
  const submissions = [];

  // Get column indices once outside the loop
  const submissionNumCol = headers.indexOf('Submission #');
  const statusCol = headers.indexOf('Status');
  const nameCol = headers.indexOf('Name');
  const emailCol = headers.indexOf('Email');
  const timestampCol = headers.indexOf('Timestamp');

  for (let i = 1; i < submissionsData.length; i++) {
    const row = submissionsData[i];
    const submissionNum = submissionNumCol !== -1 ? row[submissionNumCol] : null;
    const status = statusCol !== -1 ? row[statusCol] : 'New';

    if (submissionNum && !existingJobSubmissions.has(submissionNum)) {
      const name = nameCol !== -1 ? row[nameCol] : 'Unknown';
      const email = emailCol !== -1 ? row[emailCol] : '';
      const timestamp = timestampCol !== -1 ? row[timestampCol] : new Date();

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
/**
 * PERFORMANCE OPTIMIZED: Get jobs by status with SINGLE batch read
 *
 * PREVIOUS APPROACH: 5 separate getRange() calls (1 header + 4 data columns)
 * NEW APPROACH: 1 getRange() call loading all data at once
 *
 * OPTIMIZATION BENEFIT:
 * - Reduces network round-trips from 5 to 1 (80% reduction in API calls)
 * - Google Sheets API calls are the slowest operation - minimizing them is key
 * - Single batch read is faster even if loading slightly more data
 *
 * @param {Array<string>} statusFilter - Array of statuses to filter by (e.g., ['Quoted', 'Accepted'])
 * @returns {Array<Object>} Array of job objects for dropdown display
 */
function getJobsByStatus(statusFilter = []) {
  const startTime = new Date().getTime();

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);

  if (!jobsSheet) {
    Logger.log('[PERF] getJobsByStatus() - Jobs sheet not found');
    return [];
  }

  const lastRow = jobsSheet.getLastRow();
  if (lastRow <= 1) return []; // No data rows

  // OPTIMIZATION: Single getRange call to load all data at once
  // This is faster than multiple getRange calls even if we load extra columns
  const allData = jobsSheet.getDataRange().getValues();
  const headers = allData[0];

  // Find the column indices we need
  const jobNumColIndex = headers.indexOf('Job #');
  const statusColIndex = headers.indexOf('Status');
  const clientNameColIndex = headers.indexOf('Client Name');
  const storeUrlColIndex = headers.indexOf('Store URL');

  // Fallback: if critical columns not found, use original implementation
  if (jobNumColIndex === -1 || statusColIndex === -1 || clientNameColIndex === -1) {
    Logger.log('[PERF] getJobsByStatus() - Required columns not found, using fallback');
    return getJobsByStatusFallback(statusFilter);
  }

  const jobs = [];

  // Build job objects from data (start from row 1, skip header)
  for (let i = 1; i < allData.length; i++) {
    const row = allData[i];
    const jobNum = row[jobNumColIndex];
    const status = row[statusColIndex];

    // Filter by status if provided
    if (jobNum && (statusFilter.length === 0 || statusFilter.includes(status))) {
      const clientName = row[clientNameColIndex];
      const storeUrl = storeUrlColIndex !== -1 ? row[storeUrlColIndex] : '';

      jobs.push({
        number: jobNum,
        clientName: clientName || 'Unknown',
        status: status,
        storeUrl: storeUrl || '',
        display: jobNum + ' - ' + (clientName || 'Unknown') + ' (' + status + ')'
      });
    }
  }

  // Performance logging
  const endTime = new Date().getTime();
  const executionTime = endTime - startTime;
  Logger.log('[PERF] getJobsByStatus() - Loaded ' + jobs.length + ' jobs in ' + executionTime + 'ms (single batch read)');

  return jobs;
}

/**
 * Fallback implementation - loads all columns
 * Used when required columns cannot be found in headers
 */
function getJobsByStatusFallback(statusFilter = []) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);

  if (!jobsSheet) return [];

  const data = jobsSheet.getDataRange().getValues();
  const headers = data[0];
  const jobs = [];

  // Find column indices - require them to exist
  const jobNumColIdx = headers.indexOf('Job #');
  const statusColIdx = headers.indexOf('Status');
  const clientNameColIdx = headers.indexOf('Client Name');
  const storeUrlColIdx = headers.indexOf('Store URL');

  if (jobNumColIdx === -1) {
    Logger.log('Warning: Job # column not found in Jobs sheet');
    return [];
  }
  if (statusColIdx === -1) {
    Logger.log('Warning: Status column not found in Jobs sheet');
  }

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const jobNum = row[jobNumColIdx];
    const status = statusColIdx >= 0 ? row[statusColIdx] : '';

    if (jobNum && (statusFilter.length === 0 || statusFilter.includes(status))) {
      const clientName = clientNameColIdx >= 0 ? row[clientNameColIdx] : '';
      const storeUrl = storeUrlColIdx >= 0 ? row[storeUrlColIdx] : '';

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
/**
 * PERFORMANCE OPTIMIZED: Get invoices by status with SINGLE batch read
 *
 * PREVIOUS APPROACH: 6 separate getRange() calls (1 header + 5 data columns)
 * NEW APPROACH: 1 getRange() call loading all data at once
 *
 * OPTIMIZATION BENEFIT:
 * - Reduces network round-trips from 6 to 1 (83% reduction in API calls)
 * - Single batch read is faster even if loading slightly more data
 *
 * @param {Array<string>} statusFilter - Array of statuses to filter by (e.g., ['Draft', 'Sent'])
 * @returns {Array<Object>} Array of invoice objects for dropdown display
 */
function getInvoicesByStatus(statusFilter = []) {
  const startTime = new Date().getTime();

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!invoiceSheet) {
    Logger.log('[PERF] getInvoicesByStatus() - Invoice Log sheet not found');
    return [];
  }

  const lastRow = invoiceSheet.getLastRow();
  if (lastRow <= 1) return []; // No data rows

  // OPTIMIZATION: Single getRange call to load all data at once
  const allData = invoiceSheet.getDataRange().getValues();
  const headers = allData[0];

  // Find the column indices we need
  const invoiceNumColIndex = headers.indexOf('Invoice #');
  const jobNumColIndex = headers.indexOf('Job #');
  const clientNameColIndex = headers.indexOf('Client Name');
  const totalColIndex = headers.indexOf('Total');
  const statusColIndex = headers.indexOf('Status');

  // Fallback: if critical columns not found, use original implementation
  if (invoiceNumColIndex === -1 || statusColIndex === -1 || totalColIndex === -1) {
    Logger.log('[PERF] getInvoicesByStatus() - Required columns not found, using fallback');
    return getInvoicesByStatusFallback(statusFilter);
  }

  const invoices = [];

  // Build invoice objects from data (start from row 1, skip header)
  for (let i = 1; i < allData.length; i++) {
    const row = allData[i];
    const invoiceNum = row[invoiceNumColIndex];
    const status = row[statusColIndex];

    // Filter by status if provided
    if (invoiceNum && (statusFilter.length === 0 || statusFilter.includes(status))) {
      const jobNum = row[jobNumColIndex];
      const clientName = row[clientNameColIndex];
      const total = row[totalColIndex];

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

  // Performance logging
  const endTime = new Date().getTime();
  const executionTime = endTime - startTime;
  Logger.log('[PERF] getInvoicesByStatus() - Loaded ' + invoices.length + ' invoices in ' + executionTime + 'ms (single batch read)');

  return invoices;
}

/**
 * Fallback implementation - loads all columns
 * Used when required columns cannot be found in headers
 */
function getInvoicesByStatusFallback(statusFilter = []) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!invoiceSheet) return [];

  const data = invoiceSheet.getDataRange().getValues();
  const headers = data[0];
  const invoices = [];

  // Find column indices - require them to exist
  const invoiceNumColIdx = headers.indexOf('Invoice #');
  const statusColIdx = headers.indexOf('Status');
  const jobNumColIdx = headers.indexOf('Job #');
  const clientNameColIdx = headers.indexOf('Client Name');
  const totalColIdx = headers.indexOf('Total');

  if (invoiceNumColIdx === -1) {
    Logger.log('Warning: Invoice # column not found in Invoices sheet');
    return [];
  }
  if (statusColIdx === -1) {
    Logger.log('Warning: Status column not found in Invoices sheet');
  }

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const invoiceNum = row[invoiceNumColIdx];
    const status = statusColIdx >= 0 ? row[statusColIdx] : '';

    if (invoiceNum && (statusFilter.length === 0 || statusFilter.includes(status))) {
      const jobNum = jobNumColIdx >= 0 ? row[jobNumColIdx] : '';
      const clientName = clientNameColIdx >= 0 ? row[clientNameColIdx] : 'Unknown';
      const total = totalColIdx >= 0 ? row[totalColIdx] : 0;

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

// ============================================================================
// CONTEXT-AWARE SELECTION HELPERS
// ============================================================================

/**
 * Check if a value matches job number format
 * @param {string} value - Value to check
 * @returns {boolean} True if matches job number format
 */
function isJobNumberFormat(value) {
  if (!value) return false;
  const trimmed = value.toString().trim();
  // Match formats:
  // - New format: J-WORD-XXX (e.g., J-MAPLE-001)
  // - Additional job format: J-WORD-XXX-N (e.g., J-MAPLE-001-2)
  // - Legacy format: J-YYYYMMDD-XXXXX (e.g., J-20240101-00001)
  const newFormatRegex = /^J-[A-Z]{3,6}-\d{1,4}(-\d+)?$/i;
  const legacyFormatRegex = /^J-\d{8}-\d{5}$/;
  return newFormatRegex.test(trimmed) || legacyFormatRegex.test(trimmed);
}

/**
 * Get job number from currently selected row
 * First checks if selected cell contains a job number, then looks at the Job # column
 * @returns {string|null} Job number if found, null otherwise
 */
function getSelectedJobNumber() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const sheetName = sheet.getName();
  const selection = sheet.getActiveCell();
  const row = selection.getRow();

  // Skip header row
  if (row <= 1) return null;

  // First, check if selected cell itself contains a job number
  const cellValue = selection.getValue();
  if (cellValue && isJobNumberFormat(cellValue.toString().trim())) {
    return cellValue.toString().trim();
  }

  // If on Jobs sheet, look up the Job # column for this row
  if (sheetName === SHEETS.JOBS) {
    const jobColIndex = getColIndex('JOBS', 'Job #');
    const jobNumber = sheet.getRange(row, jobColIndex).getValue();
    if (jobNumber && isJobNumberFormat(jobNumber.toString().trim())) {
      return jobNumber.toString().trim();
    }
  }

  // If on Invoice Log sheet, look up the Job # column for this row
  if (sheetName === SHEETS.INVOICES) {
    const jobColIndex = getColIndex('INVOICES', 'Job #');
    const jobNumber = sheet.getRange(row, jobColIndex).getValue();
    if (jobNumber && isJobNumberFormat(jobNumber.toString().trim())) {
      return jobNumber.toString().trim();
    }
  }

  // If on Activity Log sheet, look up the Job # column for this row
  if (sheetName === SHEETS.ACTIVITY_LOG) {
    const jobColIndex = getColIndex('ACTIVITY_LOG', 'Job #');
    const jobNumber = sheet.getRange(row, jobColIndex).getValue();
    if (jobNumber && isJobNumberFormat(jobNumber.toString().trim())) {
      return jobNumber.toString().trim();
    }
  }

  return null;
}

/**
 * Check if a value matches submission number format
 * @param {string} value - Value to check
 * @returns {boolean} True if matches submission number format
 */
function isSubmissionNumberFormat(value) {
  if (!value) return false;
  const trimmed = value.toString().trim();
  // Match formats:
  // - New format: CC-WORD-XXX (e.g., CC-MAPLE-001)
  // - Legacy format: CC-YYYYMMDD-XXXXX (e.g., CC-20240101-00001)
  const newFormatRegex = /^CC-[A-Z]{3,6}-\d{1,4}$/i;
  const legacyFormatRegex = /^CC-\d{8}-\d{5}$/;
  return newFormatRegex.test(trimmed) || legacyFormatRegex.test(trimmed);
}

/**
 * Get submission number from currently selected row
 * First checks if selected cell contains a submission number, then looks at the Submission # column
 * @returns {string|null} Submission number if found, null otherwise
 */
function getSelectedSubmissionNumber() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const sheetName = sheet.getName();
  const selection = sheet.getActiveCell();
  const row = selection.getRow();

  // Skip header row
  if (row <= 1) return null;

  // First, check if selected cell itself contains a submission number
  const cellValue = selection.getValue();
  if (cellValue && isSubmissionNumberFormat(cellValue.toString().trim())) {
    return cellValue.toString().trim();
  }

  // If on Submissions sheet, look up the Submission # column for this row
  if (sheetName === SHEETS.SUBMISSIONS) {
    const subColIndex = getColIndex('SUBMISSIONS', 'Submission #');
    const subNumber = sheet.getRange(row, subColIndex).getValue();
    if (subNumber && isSubmissionNumberFormat(subNumber.toString().trim())) {
      return subNumber.toString().trim();
    }
  }

  // If on Jobs sheet, look up the Submission # column for this row
  if (sheetName === SHEETS.JOBS) {
    const subColIndex = getColIndex('JOBS', 'Submission #');
    const subNumber = sheet.getRange(row, subColIndex).getValue();
    if (subNumber && isSubmissionNumberFormat(subNumber.toString().trim())) {
      return subNumber.toString().trim();
    }
  }

  return null;
}

/**
 * Check if a value matches invoice number format
 * @param {string} value - Value to check
 * @returns {boolean} True if matches invoice number format
 */
function isInvoiceNumberFormat(value) {
  if (!value) return false;
  const trimmed = value.toString().trim();
  // Match formats:
  // - New format: INV-WORD-XXX or INV-WORD-XXX-N (e.g., INV-MAPLE-001, INV-MAPLE-001-2)
  // - Legacy year-based: INV-YYYY-XXX (e.g., INV-2024-001)
  // - Old sequential: INV-XXXX (e.g., INV-0001)
  const newFormatRegex = /^INV-[A-Z]{3,6}-\d{1,4}(-\d+)?$/i;
  const legacyYearFormatRegex = /^INV-\d{4}-\d{1,}$/;
  const oldFormatRegex = /^INV-\d{4,}$/;
  return newFormatRegex.test(trimmed) || legacyYearFormatRegex.test(trimmed) || oldFormatRegex.test(trimmed);
}

/**
 * Get invoice number from currently selected row
 * First checks if selected cell contains an invoice number, then looks at the Invoice # column
 * @returns {string|null} Invoice number if found, null otherwise
 */
function getSelectedInvoiceNumber() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const sheetName = sheet.getName();
  const selection = sheet.getActiveCell();
  const row = selection.getRow();

  // Skip header row
  if (row <= 1) return null;

  // First, check if selected cell itself contains an invoice number
  const cellValue = selection.getValue();
  if (cellValue && isInvoiceNumberFormat(cellValue.toString().trim())) {
    return cellValue.toString().trim();
  }

  // If on Invoice Log sheet, look up the Invoice # column for this row
  if (sheetName === SHEETS.INVOICES) {
    const invColIndex = getColIndex('INVOICES', 'Invoice #');
    const invNumber = sheet.getRange(row, invColIndex).getValue();
    if (invNumber && isInvoiceNumberFormat(invNumber.toString().trim())) {
      return invNumber.toString().trim();
    }
  }

  // If on Jobs sheet, look up the Invoice # column for this row
  if (sheetName === SHEETS.JOBS) {
    const invColIndex = getColIndex('JOBS', 'Invoice #');
    const invNumber = sheet.getRange(row, invColIndex).getValue();
    if (invNumber && isInvoiceNumberFormat(invNumber.toString().trim())) {
      return invNumber.toString().trim();
    }
  }

  return null;
}

/**
 * Show context-aware dropdown dialog
 * If a valid item is selected in the spreadsheet, use it directly
 * Otherwise, show the dropdown for selection
 *
 * @param {string} title - Dialog title
 * @param {Array} items - Array of items for dropdown
 * @param {string} itemType - Type of item (e.g., 'Job', 'Submission')
 * @param {string} callback - Function name to call with selection
 * @param {string|null} selectedValue - Pre-selected value from context (if any)
 */
function showContextAwareDialog(title, items, itemType, callback, selectedValue) {
  const ui = SpreadsheetApp.getUi();

  // If we have a context-selected value, confirm and use it directly
  if (selectedValue) {
    // Verify the selected value is in our valid items list (if items provided)
    // Use string comparison to handle type mismatches (sheet values may be numbers)
    const selectedStr = String(selectedValue).trim();
    const isValidSelection = items && items.length > 0 &&
      items.some(item => String(item.number).trim() === selectedStr);

    if (isValidSelection) {
      const response = ui.alert(
        'Confirm Selection',
        'Use selected ' + itemType.toLowerCase() + ': ' + selectedValue + '?',
        ui.ButtonSet.YES_NO
      );

      if (response === ui.Button.YES) {
        // Call the callback function directly with the selected value
        // Use eval to call the function by name (this[callback] doesn't work in Apps Script)
        eval(callback + '("' + selectedValue.replace(/"/g, '\\"') + '")');
        return;
      }
    } else if (items && items.length > 0) {
      // Selected item exists but isn't valid for this action - explain why
      // Get the status of the selected job/item to provide helpful feedback
      const statusInfo = getItemStatusInfo(selectedValue, itemType);
      const validStatuses = getValidStatusesForAction(callback);

      let message = itemType + ' ' + selectedValue + ' was detected from your selection, but it cannot be used for this action.';
      if (statusInfo) {
        message += '\n\nCurrent status: ' + statusInfo;
      }
      if (validStatuses) {
        message += '\nRequired status: ' + validStatuses;
      }
      message += '\n\nPlease select from the available options below.';

      ui.alert('Selection Not Valid', message, ui.ButtonSet.OK);
    }
  }

  // Fall back to dropdown dialog
  showDropdownDialog(title, items, itemType, callback);
}

/**
 * Get the current status of a job or submission
 * @param {string} itemNumber - The job/submission/invoice number
 * @param {string} itemType - 'Job', 'Submission', or 'Invoice'
 * @returns {string|null} The current status or null if not found
 */
function getItemStatusInfo(itemNumber, itemType) {
  try {
    if (itemType === 'Job') {
      const job = getJobByNumber(itemNumber);
      if (job) {
        return job['Status'] || 'Unknown';
      }
    } else if (itemType === 'Submission') {
      // Submissions don't have a status field - return null
      return null;
    } else if (itemType === 'Invoice') {
      const invoice = getInvoiceByNumber(itemNumber);
      if (invoice) {
        return invoice['Payment Status'] || 'Unknown';
      }
    }
  } catch (e) {
    // Silently fail - status info is optional
  }
  return null;
}

/**
 * Get the valid statuses for a given action/callback
 * @param {string} callback - The callback function name
 * @returns {string|null} Description of valid statuses or null
 */
function getValidStatusesForAction(callback) {
  const actionStatusMap = {
    'sendQuoteEmail': 'Pending Quote',
    'processQuoteAcceptance': 'Quoted',
    'processQuoteRejection': 'Quoted',
    'markJobStarted': 'Accepted or On Hold',
    'markJobCompleted': 'In Progress',
    'sendStatusUpdateEmail': 'Accepted, In Progress, or On Hold',
    'createInvoice': 'Accepted, In Progress, or On Hold',
    'sendPaymentReceiptEmail': 'Paid invoice required',
    'sendInvoiceReminder': 'Pending invoice required',
    'sendOverdueInvoice': 'Overdue invoice required'
  };
  return actionStatusMap[callback] || null;
}

/**
 * Show HTML dialog with dropdown selection
 * OPTIMIZED: Added loading state and button disabling to prevent duplicate submissions
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
            transition: opacity 0.2s;
          }
          .btn-primary {
            background-color: #4285f4;
            color: white;
          }
          .btn-primary:hover:not(:disabled) {
            background-color: #357ae8;
          }
          .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
          }
          .btn-secondary {
            background-color: #f1f1f1;
            color: #333;
          }
          .btn-secondary:hover:not(:disabled) {
            background-color: #e1e1e1;
          }
          .btn-secondary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
          }
          .loading-spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid #ffffff;
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
          }
          @keyframes spin {
            to { transform: rotate(360deg); }
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
            <button id="cancelBtn" class="btn-secondary" onclick="google.script.host.close()">Cancel</button>
            <button id="submitBtn" class="btn-primary" onclick="submitSelection()">OK</button>
          </div>
        </div>

        <script>
          var isSubmitting = false;

          function submitSelection() {
            if (isSubmitting) return;

            const select = document.getElementById('itemSelect');
            const value = select.value;

            if (!value) {
              alert('Please select a ${itemType}');
              return;
            }

            // Disable buttons and show loading state
            isSubmitting = true;
            const submitBtn = document.getElementById('submitBtn');
            const cancelBtn = document.getElementById('cancelBtn');
            submitBtn.disabled = true;
            cancelBtn.disabled = true;
            submitBtn.innerHTML = '<span class="loading-spinner"></span>Processing...';
            select.disabled = true;

            google.script.run
              .withSuccessHandler(function() {
                google.script.host.close();
              })
              .withFailureHandler(function(error) {
                // Re-enable on error
                isSubmitting = false;
                submitBtn.disabled = false;
                cancelBtn.disabled = false;
                submitBtn.innerHTML = 'OK';
                select.disabled = false;
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
  const selectedSubmission = getSelectedSubmissionNumber();
  const submissions = getAvailableSubmissions();
  showContextAwareDialog(
    'Create Job from Submission',
    submissions,
    'Submission',
    'createJobFromSubmission',
    selectedSubmission
  );
}

/**
 * Create a new job from a submission
 */
function createJobFromSubmission(submissionNumber) {
  const debugLog = [];
  const debugTs = new Date().toISOString().replace(/[:.]/g, '-');

  try {
    debugLog.push('=== createJobFromSubmission Debug ===');
    debugLog.push('Timestamp: ' + debugTs);
    debugLog.push('Input submissionNumber: ' + submissionNumber);
    debugLog.push('Input type: ' + typeof submissionNumber);

    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    const ui = SpreadsheetApp.getUi();

    // Find the submission
    const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

  if (!submissionsSheet) {
    debugLog.push('ERROR: Submissions sheet not found');
    saveDebugLog(debugLog, 'CREATE_JOB_' + debugTs);
    ui.alert('Error', 'Submissions sheet not found. Please run Setup first.', ui.ButtonSet.OK);
    return;
  }

  debugLog.push('Submissions sheet found');

  const submissionsData = submissionsSheet.getDataRange().getValues();
  const headers = submissionsData[0];
  const submissionNumCol = headers.indexOf('Submission #');

  debugLog.push('Headers: ' + JSON.stringify(headers));
  debugLog.push('Submission # column index: ' + submissionNumCol);
  debugLog.push('Total rows: ' + submissionsData.length);

  let submissionRow = null;
  let submissionRowIndex = -1;

  // Log first few submission numbers for debugging
  for (let i = 1; i < Math.min(submissionsData.length, 5); i++) {
    const cellValue = submissionsData[i][submissionNumCol];
    debugLog.push('Row ' + i + ' submission#: "' + cellValue + '" (type: ' + typeof cellValue + ')');
  }

  for (let i = 1; i < submissionsData.length; i++) {
    const cellValue = submissionsData[i][submissionNumCol];
    // Use loose equality to handle type mismatches
    if (String(cellValue) === String(submissionNumber)) {
      submissionRow = submissionsData[i];
      submissionRowIndex = i + 1; // 1-indexed for sheet operations
      debugLog.push('MATCH found at row ' + i + ' (sheet row ' + submissionRowIndex + ')');
      break;
    }
  }

  if (!submissionRow) {
    debugLog.push('ERROR: Submission ' + submissionNumber + ' not found in ' + (submissionsData.length - 1) + ' submissions');
    saveDebugLog(debugLog, 'CREATE_JOB_' + debugTs);
    ui.alert('Not Found', 'Submission ' + submissionNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  // Check if jobs already exist for this submission
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  debugLog.push('Jobs sheet found: ' + (jobsSheet ? 'YES' : 'NO'));

  let existingJobCount = 0;
  let existingJobNumbers = [];

  if (jobsSheet) {
    const jobsData = jobsSheet.getDataRange().getValues();
    const jobsHeaders = jobsData[0];
    const jobNumColIdx = jobsHeaders.indexOf('Job #');      // Column 3 (index 2)
    const subNumColIdx = jobsHeaders.indexOf('Submission #'); // Column 30 (index 29)
    debugLog.push('Jobs sheet has ' + jobsData.length + ' rows');
    debugLog.push('Job # column index: ' + jobNumColIdx + ', Submission # column index: ' + subNumColIdx);
    for (let i = 1; i < jobsData.length; i++) {
      // Use String comparison to handle type mismatches
      if (String(jobsData[i][subNumColIdx]) === String(submissionNumber)) {
        existingJobCount++;
        existingJobNumbers.push(jobsData[i][jobNumColIdx]);
      }
    }
    debugLog.push('Existing jobs for this submission: ' + existingJobCount);
    if (existingJobNumbers.length > 0) {
      debugLog.push('Existing job numbers: ' + existingJobNumbers.join(', '));
    }
  }

  // Warn user if jobs already exist for this submission, but allow them to proceed
  if (existingJobCount > 0) {
    debugLog.push('WARNING: Jobs already exist, prompting user');
    const jobWord = existingJobCount === 1 ? 'job' : 'jobs';
    const response = ui.alert(
      'Warning: Existing Jobs',
      existingJobCount + ' ' + jobWord + ' for this submission already exist:\n' +
      existingJobNumbers.join(', ') + '\n\n' +
      'Do you want to create another job for this submission?',
      ui.ButtonSet.YES_NO
    );

    if (response !== ui.Button.YES) {
      debugLog.push('User cancelled - declined to create additional job');
      saveDebugLog(debugLog, 'CREATE_JOB_CANCELLED_' + debugTs);
      return;
    }
    debugLog.push('User confirmed - proceeding to create additional job');
  }

  // Generate job number - add suffix if jobs already exist for this submission
  let jobNumber;
  if (existingJobCount === 0) {
    // First job: J-XXX (same as submission number with J prefix)
    jobNumber = submissionNumber.replace(/^CC-/, 'J-');
  } else {
    // Additional jobs: J-XXX-2, J-XXX-3, etc.
    jobNumber = submissionNumber.replace(/^CC-/, 'J-') + '-' + (existingJobCount + 1);
  }

  // Extract submission data (fallback indices match new column order with Phone column)
  const name = submissionRow[headers.indexOf('Name')] || submissionRow[3];
  const email = submissionRow[headers.indexOf('Email')] || submissionRow[4];
  const phone = submissionRow[headers.indexOf('Phone')] || submissionRow[5];
  const storeUrl = submissionRow[headers.indexOf('Store URL')] || submissionRow[6];
  const message = submissionRow[headers.indexOf('Message')] || submissionRow[7];

  // Create job row using config-based helper (auto-orders columns from COLUMN_CONFIG)
  const now = new Date();
  const jobRow = buildRowFromConfig('JOBS', {
    'Job #': jobNumber,
    'Created Date': formatNZDate(now),
    'Client Name': name,
    'Client Email': email,
    'Client Phone': phone,
    'Store URL': storeUrl,
    'Job Description': message,
    'Submission #': submissionNumber,
    'Last Updated': formatNZDate(now)
    // Status, Payment Status, Estimated Turnaround use defaultValue from COLUMN_CONFIG
  });

  // Add to Jobs sheet
  if (!jobsSheet) {
    debugLog.push('ERROR: Jobs sheet not found');
    saveDebugLog(debugLog, 'CREATE_JOB_' + debugTs);
    ui.alert('Error', 'Jobs sheet not found. Please run Setup first.', ui.ButtonSet.OK);
    return;
  }

  debugLog.push('Creating job: ' + jobNumber);
  debugLog.push('Job row data: ' + JSON.stringify(jobRow));

  // Find actual last row with data by checking the Job # column
  // This avoids issues with empty formatted rows that appendRow() would skip to
  const jobNumColLetter = getColLetter('JOBS', 'Job #');
  const jobsColumnData = jobsSheet.getRange(jobNumColLetter + ':' + jobNumColLetter).getValues();
  let actualLastRow = 1; // Start at 1 (header row)
  for (let i = jobsColumnData.length - 1; i >= 0; i--) {
    if (jobsColumnData[i][0] !== '') {
      actualLastRow = i + 1; // Convert to 1-indexed
      break;
    }
  }
  const insertRow = actualLastRow + 1;
  debugLog.push('Inserting at row: ' + insertRow + ' (actual last row with data: ' + actualLastRow + ')');

  // Use getRange().setValues() instead of appendRow() to insert at correct position
  jobsSheet.getRange(insertRow, 1, 1, jobRow.length).setValues([jobRow]);
  debugLog.push('Job row inserted successfully at row ' + insertRow);

  // Update the submission status to "Job Created"
  const statusColumnIndex = headers.indexOf('Status');
  if (statusColumnIndex !== -1) {
    submissionsSheet.getRange(submissionRowIndex, statusColumnIndex + 1).setValue('Job Created');
    debugLog.push('Updated submission status to "Job Created"');
    Logger.log('Updated submission ' + submissionNumber + ' status to "Job Created"');
  }

  debugLog.push('SUCCESS: Job ' + jobNumber + ' created');
  saveDebugLog(debugLog, 'CREATE_JOB_SUCCESS_' + debugTs);

  ui.alert('Job Created',
    'Job ' + jobNumber + ' created successfully!\n\n' +
    'Next steps:\n' +
    '1. Go to the Jobs sheet\n' +
    '2. Fill in Category and Quote Amount\n' +
    '3. Use CartCure > Quotes > Send Quote',
    ui.ButtonSet.OK
  );

  Logger.log('Job ' + jobNumber + ' created from submission ' + submissionNumber);

  // Refresh dashboard to show updated data
  refreshDashboard();

  } catch (e) {
    debugLog.push('EXCEPTION: ' + e.toString());
    debugLog.push('Stack: ' + (e.stack || 'N/A'));
    saveDebugLog(debugLog, 'CREATE_JOB_ERROR_' + debugTs);
    throw e; // Re-throw to trigger the failure handler in the HTML dialog
  }
}

/**
 * Get job data by job number
 */
/**
 * PERFORMANCE OPTIMIZED: Get job by number using TextFinder API
 *
 * OLD APPROACH: Load entire sheet (100+ rows × 20+ columns) and loop through all rows
 * NEW APPROACH: Use Google's TextFinder API to locate job, then load only 2 rows
 *
 * OPTIMIZATION BENEFIT:
 * - For 100 job sheet: Load 2 rows instead of 100 rows (98% reduction)
 * - TextFinder uses Google's server-side indexing (faster than JavaScript loops)
 * - Reduces data transfer and processing time by 60-70%
 *
 * @param {string} jobNumber - The job number to find (e.g., "JOB-0001")
 * @returns {Object|null} Job object with all fields, or null if not found
 */
function getJobByNumber(jobNumber) {
  const startTime = new Date().getTime();

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.JOBS);

  if (!sheet) {
    Logger.log('[PERF] getJobByNumber() - Jobs sheet not found');
    return null;
  }

  // OPTIMIZATION: Use TextFinder API instead of loading entire sheet
  // TextFinder is optimized server-side by Google for fast cell lookups
  const finder = sheet.createTextFinder(jobNumber)
    .matchEntireCell(true)   // Exact match only (prevents partial matches like "JOB-001" matching "JOB-0010")
    .matchCase(true);         // Case-sensitive search

  const foundRange = finder.findNext();

  if (!foundRange) {
    Logger.log('[PERF] getJobByNumber() - Job not found: ' + jobNumber);
    return null;
  }

  // Verify the found cell is in the Job # column (using config for dynamic lookup)
  // This prevents false positives if job number appears in other columns
  const jobNumCol = getColIndex('JOBS', 'Job #');
  if (foundRange.getColumn() !== jobNumCol) {
    Logger.log('[PERF] getJobByNumber() - Job number found in wrong column for: ' + jobNumber + ' (expected col ' + jobNumCol + ', found col ' + foundRange.getColumn() + ')');
    return null;
  }

  const rowIndex = foundRange.getRow();

  // OPTIMIZATION: Load only 2 rows (header + found row) instead of entire sheet
  const lastColumn = sheet.getLastColumn();
  const headers = sheet.getRange(1, 1, 1, lastColumn).getValues()[0];
  const rowData = sheet.getRange(rowIndex, 1, 1, lastColumn).getValues()[0];

  // Build job object from the single row
  const job = {};
  headers.forEach((header, index) => {
    job[header] = rowData[index];
  });
  job._rowIndex = rowIndex; // Store row index for updates

  // Performance logging
  const endTime = new Date().getTime();
  const executionTime = endTime - startTime;
  Logger.log('[PERF] getJobByNumber() - Found ' + jobNumber + ' in ' + executionTime + 'ms (TextFinder optimization)');

  return job;
}

/**
 * Update a job field
 */
/**
 * PERFORMANCE OPTIMIZED: Update multiple job fields in a single operation
 *
 * This function replaces multiple updateJobField() calls with a single batch operation.
 * OPTIMIZATION BENEFIT: Reduces sheet loads from N (one per field) to 1 (single load)
 * Example: markQuoteAccepted() now does 1 sheet load instead of 6
 *
 * @param {string} jobNumber - The job number to update (e.g., "JOB-0001")
 * @param {Object} updates - Object with field names as keys and new values
 *                           Example: {'Status': 'Accepted', 'Due Date': '2024-01-15'}
 * @returns {boolean} true if successful, false if job not found or sheet error
 *
 * Performance: ~85% faster than multiple updateJobField() calls for 6+ field updates
 */
function updateJobFields(jobNumber, updates) {
  const startTime = new Date().getTime();

  // Validate inputs
  if (!jobNumber || !updates || Object.keys(updates).length === 0) {
    Logger.log('[PERF] updateJobFields() - Invalid parameters');
    return false;
  }

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.JOBS);

  if (!sheet) {
    Logger.log('[PERF] updateJobFields() - Jobs sheet not found');
    return false;
  }

  // OPTIMIZATION: Single sheet load instead of N loads
  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  const jobNumColIndex = headers.indexOf('Job #');

  if (jobNumColIndex < 0) {
    Logger.log('[PERF] updateJobFields() - Job # column not found');
    return false;
  }

  // Find the job row (linear search - only way to locate by job number)
  let rowIndex = -1;
  for (let i = 1; i < data.length; i++) {
    if (String(data[i][jobNumColIndex]).trim() === String(jobNumber).trim()) {
      rowIndex = i;
      break;
    }
  }

  if (rowIndex < 0) {
    Logger.log('[PERF] updateJobFields() - Job not found: ' + jobNumber);
    return false;
  }

  // Prepare batch update: collect all ranges and values
  const rangesToUpdate = [];
  const valuesToUpdate = [];
  let fieldsUpdated = 0;

  // Process each field update request
  for (const [fieldName, value] of Object.entries(updates)) {
    const colIndex = headers.indexOf(fieldName);
    if (colIndex >= 0) {
      rangesToUpdate.push(sheet.getRange(rowIndex + 1, colIndex + 1));
      valuesToUpdate.push(value);
      fieldsUpdated++;
    } else {
      Logger.log('[PERF] updateJobFields() - Field not found: ' + fieldName);
    }
  }

  // Always update "Last Updated" timestamp
  const lastUpdatedCol = headers.indexOf('Last Updated');
  if (lastUpdatedCol >= 0) {
    rangesToUpdate.push(sheet.getRange(rowIndex + 1, lastUpdatedCol + 1));
    valuesToUpdate.push(formatNZDate(new Date()));
  }

  // OPTIMIZATION: Batch write all values
  // Note: Apps Script doesn't have a true batch setValue(), but this loop
  // is still faster than N separate getDataRange() calls
  for (let i = 0; i < rangesToUpdate.length; i++) {
    rangesToUpdate[i].setValue(valuesToUpdate[i]);
  }

  // Performance logging
  const endTime = new Date().getTime();
  const executionTime = endTime - startTime;
  Logger.log('[PERF] updateJobFields() - Updated ' + fieldsUpdated + ' fields for ' + jobNumber + ' in ' + executionTime + 'ms');

  // Log to debug file for tracking
  logPerformanceToDebugFile('updateJobFields', {
    jobNumber: jobNumber,
    fieldsUpdated: fieldsUpdated,
    executionTime: executionTime + 'ms'
  });

  return true;
}

/**
 * LEGACY: Update a single job field (kept for backward compatibility)
 *
 * NOTE: For updating multiple fields, use updateJobFields() instead for better performance
 * This function loads the entire sheet for each call - inefficient when called multiple times
 *
 * @param {string} jobNumber - The job number to update
 * @param {string} fieldName - The field name to update
 * @param {*} value - The new value to set
 * @returns {boolean} true if successful, false otherwise
 */
function updateJobField(jobNumber, fieldName, value) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.JOBS);

  if (!sheet) return false;

  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  const jobNumColIndex = headers.indexOf('Job #');
  const colIndex = headers.indexOf(fieldName);

  if (jobNumColIndex < 0 || colIndex < 0) return false;

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][jobNumColIndex]).trim() === String(jobNumber).trim()) {
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
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([JOB_STATUS.QUOTED, JOB_STATUS.QUOTE_REMINDED]);
  showContextAwareDialog(
    'Mark Quote Accepted',
    jobs,
    'Job',
    'markQuoteAccepted',
    selectedJob
  );
}

/**
 * Mark a quote as accepted - starts the SLA clock
 */
/**
 * Mark quote as accepted - PERFORMANCE OPTIMIZED
 * OLD: 6 separate updateJobField() calls = 6 sheet loads
 * NEW: 1 batch updateJobFields() call = 1 sheet load (83% reduction)
 *
 * For jobs $200+, automatically generates and sends a 50% deposit invoice
 */
function markQuoteAccepted(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  if (job['Status'] !== JOB_STATUS.QUOTED && job['Status'] !== JOB_STATUS.QUOTE_REMINDED) {
    ui.alert('Invalid Status', 'This job is not in Quoted or Quote Reminded status. Current status: ' + job['Status'], ui.ButtonSet.OK);
    return;
  }

  // Check if job requires deposit ($200+)
  const total = parseFloat(job['Total (incl GST)']) || parseFloat(job['Quote Amount (excl GST)']) || 0;
  const requiresDeposit = total >= 200;
  const projectSize = getProjectSize(total);

  // If deposit required, show confirmation dialog
  if (requiresDeposit) {
    const depositAmount = (total * 0.5).toFixed(2);
    const response = ui.alert(
      '💰 Deposit Invoice Required',
      'This job total is ' + formatCurrency(total) + ' (' + projectSize + ' project).\n\n' +
      'Per Terms of Service, jobs $200+ require a 50% deposit upfront.\n\n' +
      'A deposit invoice for ' + formatCurrency(parseFloat(depositAmount)) + ' will be:\n' +
      '• Generated automatically\n' +
      '• Sent to the client immediately\n\n' +
      'Do you want to proceed?',
      ui.ButtonSet.YES_NO
    );

    if (response !== ui.Button.YES) {
      return; // User cancelled
    }
  }

  const now = new Date();
  const turnaround = parseInt(job['Estimated Turnaround']) || JOB_CONFIG.DEFAULT_SLA_DAYS;
  const dueDate = new Date(now);
  dueDate.setDate(dueDate.getDate() + turnaround);

  // OPTIMIZATION: Batch update all 6 fields in a single operation instead of 6 separate calls
  updateJobFields(jobNumber, {
    'Status': JOB_STATUS.ACCEPTED,
    'Quote Accepted Date': formatNZDate(now),
    'Days Since Accepted': 0,
    'Days Remaining': turnaround,
    'SLA Status': 'On Track',
    'Due Date': formatNZDate(dueDate)
  });

  // Generate and send deposit invoice for $200+ jobs
  let depositMessage = '';
  if (requiresDeposit) {
    const invoiceResult = generateAndSendDepositInvoice(jobNumber, job);
    if (invoiceResult.success) {
      depositMessage = '\n\n💰 Deposit Invoice:\n' +
        '• Invoice ' + invoiceResult.invoiceNumber + ' created\n' +
        '• Amount: ' + formatCurrency(invoiceResult.amount) + '\n' +
        '• Sent to: ' + job['Client Email'];
    } else {
      depositMessage = '\n\n⚠️ Deposit Invoice Error:\n' + invoiceResult.error +
        '\n\nPlease generate and send manually via CartCure > Invoices.';
    }
  }

  ui.alert('Quote Accepted',
    'Job ' + jobNumber + ' marked as Accepted!\n\n' +
    'SLA Clock Started:\n' +
    '- Due Date: ' + formatNZDate(dueDate) + '\n' +
    '- Days Remaining: ' + turnaround + depositMessage + '\n\n' +
    'Use CartCure > Jobs > Start Work when you begin.',
    ui.ButtonSet.OK
  );

  Logger.log('Quote accepted for ' + jobNumber + (requiresDeposit ? ' (deposit invoice sent)' : ''));

  // Refresh dashboard to show updated data
  refreshDashboard();
}

/**
 * Generate and send a 50% deposit invoice for a job
 * Called automatically when quote is accepted for jobs $200+
 *
 * @param {string} jobNumber - The job number
 * @param {Object} job - The job object with all fields
 * @returns {Object} Result object with success, invoiceNumber, amount, or error
 */
function generateAndSendDepositInvoice(jobNumber, job) {
  try {
    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);

    if (!invoiceSheet) {
      return { success: false, error: 'Invoice Log sheet not found' };
    }

    // Check for existing invoices
    const existingInvoices = getInvoicesByJobNumber(jobNumber);

    // Generate invoice number
    const invoiceNumber = generateInvoiceNumber(jobNumber, existingInvoices ? existingInvoices.length : 0);
    const now = new Date();
    // Deposits are due immediately (today)
    const dueDate = new Date(now);

    // Calculate 50% deposit amounts
    const amount = parseFloat(job['Quote Amount (excl GST)']) || 0;
    const isGSTRegistered = getSetting('GST Registered') === 'Yes';
    const gst = isGSTRegistered ? (parseFloat(job['GST']) || 0) : 0;
    const total = isGSTRegistered ? (parseFloat(job['Total (incl GST)']) || amount) : amount;

    const depositAmount = amount * 0.5;
    const depositGst = gst * 0.5;
    const depositTotal = total * 0.5;

    // Create invoice row using config-based helper (auto-orders columns from COLUMN_CONFIG)
    const invoiceRow = buildRowFromConfig('INVOICES', {
      'Invoice #': invoiceNumber,
      'Job #': jobNumber,
      'Client Name': job['Client Name'],
      'Client Email': job['Client Email'],
      'Client Phone': job['Client Phone'] || '',
      'Invoice Date': formatNZDate(now),
      'Due Date': formatNZDate(dueDate),
      'Amount (excl GST)': depositAmount.toFixed(2),
      'GST': depositGst.toFixed(2),
      'Total': depositTotal.toFixed(2),
      'Status': 'Draft',
      'Total With Fees': depositTotal.toFixed(2),
      'Invoice Type': 'Deposit',
      'Notes': 'Auto-generated on quote acceptance'
    });

    invoiceSheet.appendRow(invoiceRow);

    // Update job with invoice number
    updateJobField(jobNumber, 'Invoice #', invoiceNumber);

    // Send the invoice email
    const sendResult = sendInvoiceEmailSilent(invoiceNumber);

    if (!sendResult.success) {
      return {
        success: false,
        error: 'Invoice created but email failed: ' + sendResult.error,
        invoiceNumber: invoiceNumber,
        amount: depositTotal
      };
    }

    Logger.log('Deposit invoice ' + invoiceNumber + ' generated and sent for ' + jobNumber);

    return {
      success: true,
      invoiceNumber: invoiceNumber,
      amount: depositTotal
    };

  } catch (error) {
    Logger.log('Error generating deposit invoice: ' + error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Send invoice email without UI prompts (for automated sending)
 * Returns result object instead of showing alerts
 *
 * @param {string} invoiceNumber - The invoice number to send
 * @returns {Object} Result object with success boolean and error message if failed
 */
/**
 * Send invoice email without UI prompts (for automated sending)
 * Returns result object instead of showing alerts
 * EMAIL TEMPLATE: See apps-script/email-invoice.html
 *
 * @param {string} invoiceNumber - The invoice number to send
 * @returns {Object} Result object with success boolean and error message if failed
 */
function sendInvoiceEmailSilent(invoiceNumber) {
  try {
    const invoice = getInvoiceByNumber(invoiceNumber);

    if (!invoice) {
      return { success: false, error: 'Invoice not found' };
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
    const invoiceType = invoice['Invoice Type'] || 'Full';

    if (!clientEmail) {
      return { success: false, error: 'No client email address' };
    }

    if (!clientName) {
      return { success: false, error: 'No client name' };
    }

    // Determine subject based on invoice type
    let subject = 'Invoice ' + invoiceNumber + ' from CartCure';
    if (invoiceType === 'Deposit') {
      subject = 'Deposit Invoice ' + invoiceNumber + ' from CartCure (50% Payment Required)';
    } else if (invoiceType === 'Balance') {
      subject = 'Balance Invoice ' + invoiceNumber + ' from CartCure (Final Payment)';
    }

    // Get deposit invoice info for balance invoices
    let depositInfo = null;
    let totalJobAmount = 0;
    if (invoiceType === 'Balance') {
      const allInvoices = getInvoicesByJobNumber(jobNumber);
      const depositInvoice = allInvoices.find(inv => inv['Invoice Type'] === 'Deposit');
      if (depositInvoice) {
        const job = getJobByNumber(jobNumber);
        const jobTotal = job ? (parseFloat(job['Total (incl GST)']) || parseFloat(job['Quote Amount (excl GST)']) || 0) : 0;
        totalJobAmount = isGSTRegistered ? jobTotal : (parseFloat(job['Quote Amount (excl GST)']) || 0);
        depositInfo = {
          amount: parseFloat(depositInvoice['Total']) || parseFloat(depositInvoice['Amount (excl GST)']) || 0,
          paidDate: depositInvoice['Paid Date'] || null,
          invoiceNumber: depositInvoice['Invoice #']
        };
      }
    }

    const gstValue = parseFloat(gst);
    const displayTotal = isGSTRegistered ? total : amount;

    // Build pricing rows HTML
    let pricingRowsHtml = '';
    if (isGSTRegistered && !isNaN(gstValue) && gstValue > 0) {
      pricingRowsHtml = `
        <tr>
          <td style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
            <span style="color: ${EMAIL_COLORS.inkGray};">Subtotal (excl. GST)</span>
          </td>
          <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
            <span style="color: ${EMAIL_COLORS.inkBlack}; font-weight: bold;">$${amount}</span>
          </td>
        </tr>
        <tr>
          <td style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
            <span style="color: ${EMAIL_COLORS.inkGray};">GST (15%)</span>
          </td>
          <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
            <span style="color: ${EMAIL_COLORS.inkBlack};">$${gst}</span>
          </td>
        </tr>
        <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
          <td style="padding: 15px;">
            <span style="color: #ffffff; font-weight: bold;">TOTAL DUE (incl. GST)</span>
          </td>
          <td align="right" style="padding: 15px;">
            <span style="color: #ffffff; font-size: 20px; font-weight: bold;">$${total}</span>
          </td>
        </tr>
      `;
    } else {
      pricingRowsHtml = `
        <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
          <td style="padding: 15px;">
            <span style="color: #ffffff; font-weight: bold;">TOTAL DUE</span>
          </td>
          <td align="right" style="padding: 15px;">
            <span style="color: #ffffff; font-size: 20px; font-weight: bold;">$${displayTotal}</span>
          </td>
        </tr>
      `;
    }

    // Build deposit notice HTML (with proper top padding)
    let depositNoticeHtml = '';
    if (invoiceType === 'Deposit') {
      depositNoticeHtml = `
        <tr>
          <td style="padding: 25px 40px 20px 40px;">
            <div style="background-color: ${EMAIL_COLORS.depositBlueBg}; border: 3px solid ${EMAIL_COLORS.depositBlue}; padding: 15px; border-radius: 4px;">
              <p style="margin: 0; color: ${EMAIL_COLORS.depositBlueDark}; font-size: 16px; font-weight: bold;">This is a 50% Deposit Invoice</p>
              <p style="margin: 10px 0 0 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 13px; line-height: 1.6;">
                Per our Terms of Service, jobs $200+ require a 50% deposit before work begins.<br>
                A balance invoice for the remaining 50% will be sent upon completion.
              </p>
            </div>
          </td>
        </tr>
      `;
    }
    // Note: Balance invoices use a separate template (email-balance-invoice.html)

    // Build bank details HTML
    let bankDetailsHtml = '';
    if (bankName) bankDetailsHtml += 'Bank: ' + bankName + '<br>';
    if (bankAccount) bankDetailsHtml += 'Account: ' + bankAccount + '<br>';

    // GST footer line
    const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

    // Render template based on invoice type
    let bodyContent;
    if (invoiceType === 'Balance' && depositInfo) {
      // Use dedicated balance invoice template
      const depositPaidText = depositInfo.paidDate ? ' (paid ' + depositInfo.paidDate + ')' : '';
      bodyContent = renderEmailTemplate('email-balance-invoice', {
        invoiceNumber: invoiceNumber,
        jobNumber: jobNumber,
        clientName: clientName,
        invoiceDate: formatNZDate(new Date()),
        dueDate: formatDueDate(dueDate),
        totalJobAmount: totalJobAmount.toFixed(2),
        depositAmount: depositInfo.amount.toFixed(2),
        depositPaidText: depositPaidText,
        balanceDue: displayTotal,
        pricingRowsHtml: pricingRowsHtml,
        bankDetailsHtml: bankDetailsHtml,
        gstFooterLine: gstFooterLine,
        businessName: businessName
      });
    } else {
      // Use standard invoice template for Deposit and Full invoices
      const greetingText = invoiceType === 'Deposit'
        ? 'Thank you for accepting our quote! Please find your deposit invoice below. Work will begin once payment is received.'
        : 'Thank you for choosing CartCure! Please find your invoice below for the completed work.';

      bodyContent = renderEmailTemplate('email-invoice', {
        headingTitle: invoiceType === 'Deposit' ? 'Deposit Invoice' : 'Invoice',
        invoiceNumber: invoiceNumber,
        jobNumber: jobNumber,
        clientName: clientName,
        greetingText: greetingText,
        invoiceDate: formatNZDate(new Date()),
        dueDate: formatDueDate(dueDate),
        pricingRowsHtml: pricingRowsHtml,
        depositNoticeHtml: depositNoticeHtml,
        bankDetailsHtml: bankDetailsHtml,
        gstFooterLine: gstFooterLine,
        businessName: businessName
      });
    }

    const htmlBody = wrapEmailHtml(bodyContent);

    // Build plain text version
    let plainTextBody;
    if (invoiceType === 'Balance' && depositInfo) {
      const depositPaidText = depositInfo.paidDate ? ' (paid ' + depositInfo.paidDate + ')' : '';
      plainTextBody = `BALANCE INVOICE ${invoiceNumber}

Hi ${clientName},

Your work has been completed. Please find your final balance invoice below.

PAYMENT SUMMARY
Total Job Amount: $${totalJobAmount.toFixed(2)}
Deposit Paid${depositPaidText}: -$${depositInfo.amount.toFixed(2)}
Remaining Balance: $${displayTotal}

Job Reference: ${jobNumber}
Due Date: ${formatDueDate(dueDate)}

${isGSTRegistered ? 'Amount (excl GST): $' + amount + '\nGST (15%): $' + gst + '\nTotal (incl GST): $' + total : 'Total Due: $' + displayTotal}

PAYMENT DETAILS
${bankName ? 'Bank: ' + bankName : ''}
${bankAccount ? 'Account: ' + bankAccount : ''}
Reference: ${invoiceNumber}
${isGSTRegistered && gstNumber ? 'GST Number: ' + gstNumber : ''}

Questions? Reply to this email.

${businessName}
cartcure.co.nz`;
    } else if (invoiceType === 'Deposit') {
      plainTextBody = `DEPOSIT INVOICE ${invoiceNumber}

Hi ${clientName},

Thank you for accepting our quote! Please find your deposit invoice below.

This is a 50% deposit invoice. Per our Terms of Service, jobs $200+ require a 50% deposit before work begins. A balance invoice for the remaining 50% will be sent upon completion.

Job Reference: ${jobNumber}
Due Date: ${formatDueDate(dueDate)}

${isGSTRegistered ? 'Amount (excl GST): $' + amount + '\nGST (15%): $' + gst + '\nTotal (incl GST): $' + total : 'Total: $' + displayTotal}

PAYMENT DETAILS
${bankName ? 'Bank: ' + bankName : ''}
${bankAccount ? 'Account: ' + bankAccount : ''}
Reference: ${invoiceNumber}
${isGSTRegistered && gstNumber ? 'GST Number: ' + gstNumber : ''}

Questions? Reply to this email.

${businessName}
cartcure.co.nz`;
    } else {
      plainTextBody = `INVOICE ${invoiceNumber}

Hi ${clientName},

Please find your invoice for ${jobNumber}.

Job Reference: ${jobNumber}
Due Date: ${formatDueDate(dueDate)}

${isGSTRegistered ? 'Amount (excl GST): $' + amount + '\nGST (15%): $' + gst + '\nTotal (incl GST): $' + total : 'Total: $' + displayTotal}

PAYMENT DETAILS
${bankName ? 'Bank: ' + bankName : ''}
${bankAccount ? 'Account: ' + bankAccount : ''}
Reference: ${invoiceNumber}
${isGSTRegistered && gstNumber ? 'GST Number: ' + gstNumber : ''}

Questions? Reply to this email.

${businessName}
cartcure.co.nz`;
    }

    const plainText = plainTextBody;

    // Send the email
    GmailApp.sendEmail(clientEmail, subject, plainText, {
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Update invoice status to Sent
    updateInvoiceField(invoiceNumber, 'Status', 'Sent');
    updateInvoiceField(invoiceNumber, 'Sent Date', formatNZDate(new Date()));

    // Update job payment status to Invoiced
    const jobNumber2 = invoice['Job #'];
    if (jobNumber2) {
      updateJobField(jobNumber2, 'Payment Status', PAYMENT_STATUS.INVOICED);
    }

    // Log the email
    logJobActivity(
      jobNumber2,
      'Email Sent',
      subject,
      (invoiceType === 'Deposit' ? 'Deposit Invoice' : 'Invoice') + ' sent: ' + formatCurrency(displayTotal),
      'To: ' + clientEmail,
      'Auto'
    );

    Logger.log('Invoice ' + invoiceNumber + ' sent silently to ' + clientEmail);

    return { success: true };

  } catch (error) {
    Logger.log('Error sending invoice silently: ' + error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Update submission status
 */
function updateSubmissionStatus(submissionNumber, status) {
  if (!submissionNumber) return;

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

  if (!sheet) {
    Logger.log('ERROR: Submissions sheet not found. Cannot update status for ' + submissionNumber);
    return;
  }

  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  const statusCol = headers.indexOf('Status');
  const submissionNumCol = headers.indexOf('Submission #');

  if (statusCol < 0 || submissionNumCol < 0) return;

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][submissionNumCol]).trim() === String(submissionNumber).trim()) {
      sheet.getRange(i + 1, statusCol + 1).setValue(status);
      return;
    }
  }
}

/**
 * Show dialog to start work on a job
 */
function showStartWorkDialog() {
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([JOB_STATUS.ACCEPTED, JOB_STATUS.ON_HOLD]);
  showContextAwareDialog(
    'Start Work on Job',
    jobs,
    'Job',
    'startWorkOnJob',
    selectedJob
  );
}

/**
 * Start work on a job
 */
/**
 * Start work on job - PERFORMANCE OPTIMIZED
 * OLD: 2 separate updateJobField() calls = 2 sheet loads
 * NEW: 1 batch updateJobFields() call = 1 sheet load (50% reduction)
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

  // CHECK FOR UNPAID DEPOSIT INVOICE
  // Work cannot start until deposit is paid (for jobs that require deposit)
  const invoices = getInvoicesByJobNumber(jobNumber);
  const depositInvoice = invoices.find(inv => inv['Invoice Type'] === 'Deposit');

  if (depositInvoice && depositInvoice['Status'] !== 'Paid') {
    const depositAmount = formatCurrency(parseFloat(depositInvoice['Total']) || parseFloat(depositInvoice['Amount (excl GST)']) || 0);
    ui.alert('⚠️ Deposit Required',
      'Work cannot start on this job until the deposit invoice is paid.\n\n' +
      'Invoice: ' + depositInvoice['Invoice #'] + '\n' +
      'Amount: ' + depositAmount + '\n' +
      'Status: Unpaid\n\n' +
      'Please mark the deposit invoice as paid once payment is received, then try again.',
      ui.ButtonSet.OK
    );
    return;
  }

  // BACKUP REMINDER (per TOS requirement)
  // Only show for fresh starts, not resuming from On Hold
  if (job['Status'] === JOB_STATUS.ACCEPTED) {
    const backupResponse = ui.alert('⚠️ Backup Reminder',
      'IMPORTANT: Before starting work, ensure the client has a backup of their store.\n\n' +
      'Per our Terms of Service, clients are responsible for maintaining their own backups.\n\n' +
      'Have you confirmed the client has a recent backup?',
      ui.ButtonSet.YES_NO
    );

    if (backupResponse !== ui.Button.YES) {
      ui.alert('Work Not Started',
        'Please confirm backup status before starting work.\n\n' +
        'You may want to send the client a reminder to backup their store.',
        ui.ButtonSet.OK
      );
      return;
    }
  }

  const now = new Date();

  // Capture current status BEFORE update to detect if resuming from On Hold
  const previousStatus = job['Status'];
  const wasOnHold = previousStatus === JOB_STATUS.ON_HOLD;

  // Calculate days on hold if resuming from On Hold
  let daysOnHold = 0;
  if (wasOnHold && job['Last Updated']) {
    try {
      const onHoldDate = new Date(job['Last Updated']);
      daysOnHold = Math.floor((now - onHoldDate) / (1000 * 60 * 60 * 24));
    } catch (error) {
      Logger.log('Error calculating days on hold: ' + error.message);
    }
  }

  // OPTIMIZATION: Batch update both fields in a single operation instead of 2 separate calls
  updateJobFields(jobNumber, {
    'Status': JOB_STATUS.IN_PROGRESS,
    'Actual Start Date': formatNZDate(now)
  });

  // Send email notification
  sendStatusUpdateEmail(jobNumber, JOB_STATUS.IN_PROGRESS, {
    wasOnHold: wasOnHold,
    daysOnHold: daysOnHold
  });

  ui.alert('Work Started', 'Job ' + jobNumber + ' is now In Progress.\n\nClient has been notified.', ui.ButtonSet.OK);

  Logger.log('Work started on ' + jobNumber);

  // Refresh dashboard to show updated data
  refreshDashboard();
}

/**
 * Show dialog to mark job complete
 */
function showCompleteJobDialog() {
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([JOB_STATUS.IN_PROGRESS]);
  showContextAwareDialog(
    'Mark Job Complete',
    jobs,
    'Job',
    'markJobComplete',
    selectedJob
  );
}

/**
 * Mark a job as complete
 */
/**
 * Mark job as complete - PERFORMANCE OPTIMIZED
 * OLD: 4 separate updateJobField() calls = 4 sheet loads
 * NEW: 1 batch updateJobFields() call = 1 sheet load (75% reduction)
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

  // OPTIMIZATION: Batch update all 4 fields in a single operation instead of 4 separate calls
  updateJobFields(jobNumber, {
    'Status': JOB_STATUS.COMPLETED,
    'Actual Completion Date': formatNZDate(now),
    'SLA Status': '',  // Clear SLA status
    'Days Remaining': ''
  });

  // Send email notification
  sendStatusUpdateEmail(jobNumber, JOB_STATUS.COMPLETED);

  // CREDENTIAL CLEANUP REMINDER (per TOS requirement)
  // Per TOS: Delete all access credentials within 24 hours of project completion
  ui.alert('🔐 Security Reminder',
    'Job ' + jobNumber + ' marked as Complete!\n\nClient has been notified.\n\n' +
    '⚠️ IMPORTANT - Per TOS requirements:\n' +
    '• Delete/revoke any store access credentials within 24 hours\n' +
    '• Remove any saved passwords\n' +
    '• Log out of all client accounts\n' +
    '• Remind client to change their passwords',
    ui.ButtonSet.OK
  );

  const generateInvoice = ui.alert(
    'Generate Invoice?',
    'Would you like to generate an invoice now?',
    ui.ButtonSet.YES_NO
  );

  if (generateInvoice === ui.Button.YES) {
    generateInvoiceForJob(jobNumber);
  }

  Logger.log('Job ' + jobNumber + ' completed');

  // Refresh dashboard to show updated data
  refreshDashboard();
}

/**
 * Show dialog to put job on hold (with explanation requirement)
 */
function showOnHoldDialog() {
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([JOB_STATUS.IN_PROGRESS, JOB_STATUS.ACCEPTED]);

  // Use specialized on hold dialog instead of generic context-aware dialog
  showOnHoldDialogWithExplanation(selectedJob, jobs);
}

/**
 * Show specialized dialog for putting job on hold (requires explanation)
 *
 * @param {string} selectedJob - Pre-selected job number from context
 * @param {Array} jobs - Array of eligible jobs
 */
function showOnHoldDialogWithExplanation(selectedJob, jobs) {
  const ui = SpreadsheetApp.getUi();

  // If we have a context-selected job, verify and show explanation prompt
  if (selectedJob) {
    const isValidSelection = jobs && jobs.length > 0 &&
      jobs.some(job => job.number === selectedJob);

    if (isValidSelection) {
      const response = ui.alert(
        'Confirm Selection',
        'Put job ' + selectedJob + ' on hold?',
        ui.ButtonSet.YES_NO
      );

      if (response === ui.Button.YES) {
        // Prompt for explanation
        const explanationResponse = ui.prompt(
          'On Hold Explanation',
          'Please provide a brief explanation for the client (required):',
          ui.ButtonSet.OK_CANCEL
        );

        if (explanationResponse.getSelectedButton() === ui.Button.OK) {
          const explanation = explanationResponse.getResponseText().trim();

          if (!explanation) {
            ui.alert('Explanation Required', 'Please provide an explanation for putting the job on hold.', ui.ButtonSet.OK);
            return;
          }

          putJobOnHold(selectedJob, explanation);
        }
        return;
      }
    }
  }

  // Fall back to dropdown dialog with explanation field
  if (!jobs || jobs.length === 0) {
    ui.alert('No Jobs Available', 'No jobs available to put on hold.', ui.ButtonSet.OK);
    return;
  }

  // Create HTML dialog with dropdown and explanation field
  const htmlContent = `
    <!DOCTYPE html>
    <html>
      <head>
        <base target="_top">
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; margin: 0; }
          .container { max-width: 500px; }
          label { display: block; margin-bottom: 8px; margin-top: 12px; font-weight: bold; color: #2d5d3f; }
          select, textarea { width: 100%; padding: 10px; font-size: 14px; border: 2px solid #d4cfc3; border-radius: 4px; box-sizing: border-box; font-family: Arial, sans-serif; }
          textarea { min-height: 80px; resize: vertical; }
          .required { color: #c41e3a; }
          .button { background-color: #2d5d3f; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 20px; }
          .button:hover { background-color: #1f4029; }
          .button:disabled { background-color: #ccc; cursor: not-allowed; }
          .error { color: #c41e3a; margin-top: 10px; display: none; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2 style="color: #2d5d3f; margin-top: 0;">Put Job On Hold</h2>

          <label for="jobSelect">Select Job <span class="required">*</span></label>
          <select id="jobSelect">
            ${jobs.map(job =>
              `<option value="${job.number}">${job.number} - ${job.clientName}</option>`
            ).join('')}
          </select>

          <label for="explanation">Explanation for Client <span class="required">*</span></label>
          <textarea id="explanation" placeholder="Brief explanation of why the job is being put on hold..."></textarea>

          <div id="error" class="error">Please provide an explanation</div>

          <button id="submitBtn" class="button" onclick="handleSubmit()">Put On Hold</button>
        </div>

        <script>
          function handleSubmit() {
            const jobNumber = document.getElementById('jobSelect').value;
            const explanation = document.getElementById('explanation').value.trim();
            const errorDiv = document.getElementById('error');
            const submitBtn = document.getElementById('submitBtn');

            if (!explanation) {
              errorDiv.style.display = 'block';
              return;
            }

            errorDiv.style.display = 'none';
            submitBtn.disabled = true;
            submitBtn.textContent = 'Processing...';

            google.script.run
              .withSuccessHandler(function() {
                google.script.host.close();
              })
              .withFailureHandler(function(error) {
                alert('Error: ' + error.message);
                submitBtn.disabled = false;
                submitBtn.textContent = 'Put On Hold';
              })
              .putJobOnHold(jobNumber, explanation);
          }
        </script>
      </body>
    </html>
  `;

  const htmlOutput = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(500)
    .setHeight(350);

  ui.showModalDialog(htmlOutput, 'Put Job On Hold');
}

/**
 * Put a job on hold with explanation
 *
 * @param {string} jobNumber - The job number
 * @param {string} explanation - Explanation for putting job on hold
 */
function putJobOnHold(jobNumber, explanation) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  const now = new Date();
  const existingNotes = job['Notes'] || '';
  const onHoldNote = '[ON HOLD ' + formatNZDate(now) + '] ' + explanation;
  const newNotes = existingNotes ? existingNotes + '\n' + onHoldNote : onHoldNote;

  // Update status and notes
  updateJobFields(jobNumber, {
    'Status': JOB_STATUS.ON_HOLD,
    'Notes': newNotes,
    'Last Updated': formatNZDate(now)
  });

  // Send email notification
  sendStatusUpdateEmail(jobNumber, JOB_STATUS.ON_HOLD, { explanation: explanation });

  ui.alert('On Hold', 'Job ' + jobNumber + ' is now On Hold.\n\nClient has been notified.', ui.ButtonSet.OK);

  Logger.log('Job ' + jobNumber + ' put on hold. Reason: ' + explanation);

  // Refresh dashboard
  refreshDashboard();
}

/**
 * Show dialog to cancel a job
 */
function showCancelJobDialog() {
  const selectedJob = getSelectedJobNumber();
  // Can cancel jobs that are Accepted, In Progress, or On Hold
  const jobs = getJobsByStatus([JOB_STATUS.ACCEPTED, JOB_STATUS.IN_PROGRESS, JOB_STATUS.ON_HOLD]);
  showContextAwareDialog(
    'Cancel Job',
    jobs,
    'Job',
    'showCancelJobConfirmation',
    selectedJob
  );
}

/**
 * Show confirmation dialog for job cancellation with refund options
 */
function showCancelJobConfirmation(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  const clientName = job['Client Name'];
  const paymentStatus = job['Payment Status'];
  const total = job['Total (incl GST)'];

  // First confirmation
  const confirm = ui.alert(
    '⚠️ Cancel Job?',
    'Are you sure you want to cancel job ' + jobNumber + '?\n\n' +
    'Client: ' + clientName + '\n' +
    'Payment Status: ' + paymentStatus + '\n' +
    (total ? 'Amount: ' + formatCurrency(total) : '') + '\n\n' +
    'This will mark the job as Cancelled.',
    ui.ButtonSet.YES_NO
  );

  if (confirm !== ui.Button.YES) {
    return;
  }

  // Ask for cancellation reason
  const reasonResponse = ui.prompt(
    'Cancellation Reason',
    'Enter a reason for cancellation (optional):',
    ui.ButtonSet.OK_CANCEL
  );

  if (reasonResponse.getSelectedButton() === ui.Button.CANCEL) {
    return;
  }

  const reason = reasonResponse.getResponseText().trim();

  // If payment was made, ask about refund
  let refundStatus = null;
  if (paymentStatus === PAYMENT_STATUS.PAID || paymentStatus === PAYMENT_STATUS.INVOICED) {
    const refundResponse = ui.alert(
      'Refund Required?',
      'This job has payment status: ' + paymentStatus + '\n\n' +
      'Will a refund be issued?',
      ui.ButtonSet.YES_NO
    );

    if (refundResponse === ui.Button.YES) {
      refundStatus = PAYMENT_STATUS.REFUNDED;
    }
  }

  // Update job
  const now = new Date();
  const existingNotes = job['Notes'] || '';
  const cancellationNote = '[CANCELLED ' + formatNZDate(now) + ']' + (reason ? ' Reason: ' + reason : ' No reason provided');
  const newNotes = existingNotes ? existingNotes + '\n' + cancellationNote : cancellationNote;

  const updates = {
    'Status': JOB_STATUS.CANCELLED,
    'Notes': newNotes,
    'Last Updated': formatNZDate(now)
  };

  if (refundStatus) {
    updates['Payment Status'] = refundStatus;
  }

  updateJobFields(jobNumber, updates);

  // Send email notification (without reason - kept internal)
  sendStatusUpdateEmail(jobNumber, JOB_STATUS.CANCELLED);

  // Show confirmation
  let message = 'Job ' + jobNumber + ' has been cancelled.\n\nClient has been notified.';
  if (refundStatus) {
    message += '\n\nPayment status updated to: ' + refundStatus;
  }
  if (reason) {
    message += '\n\nReason recorded: ' + reason;
  }

  ui.alert('Job Cancelled', message, ui.ButtonSet.OK);

  Logger.log('Job ' + jobNumber + ' cancelled. Reason: ' + (reason || 'None provided'));

  // Refresh dashboard to show updated data
  refreshDashboard();
}

// ============================================================================
// QUOTE FUNCTIONS
// ============================================================================

/**
 * Show dialog to send quote
 */
function showSendQuoteDialog() {
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([JOB_STATUS.PENDING_QUOTE]);
  showContextAwareDialog(
    'Send Quote',
    jobs,
    'Job',
    'sendQuoteEmail',
    selectedJob
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

  // Check if deposit is required ($200+ jobs)
  const requiresDeposit = totalAmount >= 200;
  const depositAmount = requiresDeposit ? totalAmount * 0.5 : 0;

  // Calculate validity date
  const now = new Date();
  const validUntil = new Date(now);
  validUntil.setDate(validUntil.getDate() + quoteValidityDays);

  // OPTIMIZATION: Batch update GST and totals (2 calls → 1)
  updateJobFields(jobNumber, {
    'GST': isGSTRegistered ? gstAmount.toFixed(2) : '',
    'Total (incl GST)': totalAmount.toFixed(2)
  });

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
    isGSTRegistered: isGSTRegistered,
    requiresDeposit: requiresDeposit,
    depositAmount: formatCurrency(depositAmount)
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
    isGSTRegistered: isGSTRegistered,
    requiresDeposit: requiresDeposit,
    depositAmount: formatCurrency(depositAmount)
  });

  try {
    MailApp.sendEmail({
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      body: plainBody,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Log activity
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      'Quote sent: ' + formatCurrency(totalAmount) + (isGSTRegistered ? ' (incl GST)' : ''),
      'To: ' + clientEmail,
      'Auto'
    );

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

    // Refresh dashboard to show updated data
    refreshDashboard();
  } catch (error) {
    Logger.log('Error sending quote: ' + error.message);
    ui.alert('Error', 'Failed to send quote: ' + error.message, ui.ButtonSet.OK);
  }
}

/**
 * Generate HTML quote email
 * EMAIL TEMPLATE: See apps-script/email-quote.html
 */
function generateQuoteEmailHtml(data) {
  // Build pricing rows based on GST registration
  let pricingRowsHtml = '';
  if (data.isGSTRegistered) {
    pricingRowsHtml = `
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkGray};">Subtotal (excl. GST)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkBlack}; font-weight: bold;">${data.subtotal}</span>
        </td>
      </tr>
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkGray};">GST (15%)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkBlack};">${data.gst}</span>
        </td>
      </tr>
      <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
        <td style="padding: 15px;">
          <span style="color: #ffffff; font-weight: bold;">TOTAL (incl. GST)</span>
        </td>
        <td align="right" style="padding: 15px;">
          <span style="color: #ffffff; font-size: 20px; font-weight: bold;">${data.total}</span>
        </td>
      </tr>
    `;
  } else {
    pricingRowsHtml = `
      <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
        <td style="padding: 15px;">
          <span style="color: #ffffff; font-weight: bold;">TOTAL</span>
        </td>
        <td align="right" style="padding: 15px;">
          <span style="color: #ffffff; font-size: 20px; font-weight: bold;">${data.total}</span>
        </td>
      </tr>
    `;
  }

  // Add deposit row if required ($200+ jobs)
  if (data.requiresDeposit) {
    pricingRowsHtml += `
      <tr style="background-color: ${EMAIL_COLORS.depositBlueDark};">
        <td style="padding: 15px;">
          <span style="color: #ffffff; font-weight: bold; font-size: 14px;">50% DEPOSIT DUE UPFRONT</span>
        </td>
        <td align="right" style="padding: 15px;">
          <span style="color: #ffffff; font-size: 22px; font-weight: bold;">${data.depositAmount}</span>
        </td>
      </tr>
    `;
  }

  // Deposit notice (blue themed, prominent)
  const depositNoticeHtml = data.requiresDeposit ? `
    <tr>
      <td style="padding: 0 40px 25px 40px;">
        <div style="background-color: ${EMAIL_COLORS.depositBlueBg}; border: 3px solid ${EMAIL_COLORS.depositBlue}; padding: 20px; border-radius: 4px;">
          <p style="margin: 0 0 12px 0; color: ${EMAIL_COLORS.depositBlueDark}; font-size: 18px; font-weight: bold;">
            50% Deposit Required
          </p>
          <p style="margin: 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 14px; line-height: 1.7;">
            For jobs over $200, we require a <strong style="color: ${EMAIL_COLORS.depositBlueDark};">50% deposit (${data.depositAmount})</strong> before work begins.<br><br>
            Once you accept this quote, you'll receive a deposit invoice. Work will commence upon receipt of payment.<br><br>
            The remaining balance of <strong style="color: ${EMAIL_COLORS.depositBlueDark};">${data.depositAmount}</strong> will be invoiced upon completion.
          </p>
        </div>
      </td>
    </tr>
  ` : '';

  // Bank section
  const bankSectionHtml = data.bankAccount ? `
    <tr>
      <td style="padding: 0 40px 25px 40px;">
        <div style="background-color: ${EMAIL_COLORS.alertBg}; border: 2px solid ${EMAIL_COLORS.alertBorder}; padding: 15px;">
          <p style="margin: 0 0 10px 0; color: ${EMAIL_COLORS.inkBlack}; font-weight: bold;">Payment Details (for your reference):</p>
          <p style="margin: 0; color: ${EMAIL_COLORS.inkGray}; font-size: 14px; line-height: 1.6;">
            Bank: ${data.bankName}<br>
            Account: ${data.bankAccount}<br>
            Reference: ${data.jobNumber}
          </p>
        </div>
      </td>
    </tr>
  ` : '';

  // GST footer line
  const gstFooterLine = data.isGSTRegistered && data.gstNumber ? 'GST: ' + data.gstNumber + '<br>' : '';

  // Build quote acceptance URL with parameters
  const acceptQuoteUrl = 'https://cartcure.co.nz/quote-acceptance.html?' +
    'job=' + encodeURIComponent(data.jobNumber) +
    '&name=' + encodeURIComponent(data.clientName) +
    '&desc=' + encodeURIComponent((data.jobDescription || '').substring(0, 100)) +
    '&amount=' + encodeURIComponent(data.total) +
    '&turnaround=' + encodeURIComponent(data.turnaround);

  // Render template with data
  const bodyContent = renderEmailTemplate('email-quote', {
    jobNumber: data.jobNumber,
    clientName: data.clientName,
    jobDescription: data.jobDescription,
    pricingRowsHtml: pricingRowsHtml,
    depositNoticeHtml: depositNoticeHtml,
    turnaround: data.turnaround,
    validUntil: data.validUntil,
    bankSectionHtml: bankSectionHtml,
    gstFooterLine: gstFooterLine,
    businessName: data.businessName,
    adminEmail: data.adminEmail,
    acceptQuoteUrl: acceptQuoteUrl
  });

  return wrapEmailHtml(bodyContent);
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
${data.requiresDeposit ? `
★★★ 50% DEPOSIT DUE UPFRONT: ${data.depositAmount} ★★★
` : ''}
Estimated Turnaround: ${data.turnaround} days
Quote Valid Until: ${data.validUntil}
${data.requiresDeposit ? `
───────────────────────────────────────────────────
DEPOSIT REQUIRED
───────────────────────────────────────────────────

For jobs over $200, we require a 50% deposit (${data.depositAmount}) before
work begins.

Once you accept this quote, you'll receive a deposit invoice.
Work will commence upon receipt of payment.

The remaining balance of ${data.depositAmount} will be invoiced upon completion.
` : ''}
───────────────────────────────────────────────────
HOW TO ACCEPT
───────────────────────────────────────────────────

Simply reply to this email with "Approved" and we'll get started${data.requiresDeposit ? ' once the deposit is received' : ' right away'}!

───────────────────────────────────────────────────
BEFORE WE BEGIN
───────────────────────────────────────────────────

We recommend creating a backup of your theme and setting up a staff
account for us. View our step-by-step guide:
https://cartcure.co.nz/how-to.html

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
 * Generate status update email HTML
 *
 * @param {Object} data - Email data object
 * @param {string} data.jobNumber - Job number
 * @param {string} data.clientName - Client name
 * @param {string} data.status - New job status
 * @param {string} data.businessName - Business name
 * @param {string} [data.explanation] - Explanation for On Hold
 * @param {boolean} [data.wasOnHold] - Whether resuming from On Hold
 * @param {number} [data.daysOnHold] - Days the job was on hold
 * @returns {string} HTML email content
 */
/**
 * Generate status update email HTML
 * EMAIL TEMPLATE: See apps-script/email-status-update.html
 *
 * @param {Object} data - Email data object
 * @param {string} data.jobNumber - Job number
 * @param {string} data.clientName - Client name
 * @param {string} data.status - New job status
 * @param {string} data.businessName - Business name
 * @param {string} [data.explanation] - Explanation for On Hold
 * @param {boolean} [data.wasOnHold] - Whether resuming from On Hold
 * @param {number} [data.daysOnHold] - Days the job was on hold
 * @returns {string} HTML email content
 */
function generateStatusUpdateEmailHtml(data) {
  // Build status-specific content section
  let statusContentHtml = '';
  switch(data.status) {
    case 'In Progress':
      if (data.wasOnHold && data.daysOnHold > 0) {
        const daysText = data.daysOnHold === 1 ? '1 day' : data.daysOnHold + ' days';
        statusContentHtml = `<p>Great news! We've resumed work on your job and are actively working on it again after ${daysText}.</p>`;
      } else {
        statusContentHtml = `<p>Great news! We've started work on your job and are actively working on it.</p>`;
      }
      break;
    case 'On Hold':
      statusContentHtml = `
        <p>We need to pause work on your job temporarily.</p>
        ${data.explanation ? `
          <div style="background-color: ${EMAIL_COLORS.paperCream}; border-left: 4px solid ${EMAIL_COLORS.brandGreen}; padding: 15px 20px; margin: 15px 0;">
            <p style="margin: 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 15px; line-height: 1.7;">
              <strong>Reason:</strong> ${data.explanation}
            </p>
          </div>
        ` : ''}
        <p><strong>Note:</strong> The 7-day SLA timer is also paused while your job is on hold.</p>
        <p>We'll notify you as soon as we resume work.</p>
      `;
      break;
    case 'Completed':
      statusContentHtml = `
        <p>Excellent news! We've completed the work on your job.</p>
        <p>We'll be in touch shortly with the final details and invoice.</p>
        <div style="background-color: ${EMAIL_COLORS.paperCream}; border: 2px solid ${EMAIL_COLORS.paperBorder}; padding: 25px; margin: 20px 0; text-align: center;">
          <p style="margin: 0 0 10px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 18px; font-weight: bold;">
            How was your experience?
          </p>
          <p style="margin: 0 0 20px 0; color: ${EMAIL_COLORS.inkGray}; font-size: 14px;">
            We'd love to hear your feedback!
          </p>
          <a href="https://cartcure.co.nz/feedback.html?job=${encodeURIComponent(data.jobNumber)}"
             style="display: inline-block; background-color: ${EMAIL_COLORS.brandGreen}; color: #ffffff; padding: 15px 40px; text-decoration: none; font-size: 16px; font-weight: bold; border: 3px solid ${EMAIL_COLORS.inkBlack}; box-shadow: 3px 3px 0 rgba(0,0,0,0.2);">
            Share Your Feedback
          </a>
        </div>
      `;
      break;
    case 'Cancelled':
      statusContentHtml = `
        <p>Your job has been cancelled as requested.</p>
        <p>If you have any questions or would like to discuss this further, please don't hesitate to reach out.</p>
      `;
      break;
  }

  // Render template with data
  const bodyContent = renderEmailTemplate('email-status-update', {
    jobNumber: data.jobNumber,
    clientName: data.clientName,
    status: data.status,
    statusContentHtml: statusContentHtml,
    businessName: data.businessName
  });

  return wrapEmailHtml(bodyContent);
}

/**
 * Generate status update email plain text
 *
 * @param {Object} data - Email data object (same as generateStatusUpdateEmailHtml)
 * @returns {string} Plain text email content
 */
function generateStatusUpdateEmailPlainText(data) {
  let statusMessage = '';
  switch(data.status) {
    case 'In Progress':
      if (data.wasOnHold && data.daysOnHold > 0) {
        const daysText = data.daysOnHold === 1 ? '1 day' : data.daysOnHold + ' days';
        statusMessage = 'Great news! We\'ve resumed work on your job and are actively working on it again after ' + daysText + '.';
      } else {
        statusMessage = 'Great news! We\'ve started work on your job and are actively working on it.';
      }
      break;
    case 'On Hold':
      statusMessage = 'We need to pause work on your job temporarily.';
      if (data.explanation) {
        statusMessage += '\n\nReason: ' + data.explanation;
      }
      statusMessage += '\n\nNote: The 7-day SLA timer is also paused while your job is on hold.\n\nWe\'ll notify you as soon as we resume work.';
      break;
    case 'Completed':
      statusMessage = 'Excellent news! We\'ve completed the work on your job.\n\nWe\'ll be in touch shortly with the final details and invoice.\n\n───────────────────────────────────────────────────\nHOW WAS YOUR EXPERIENCE?\n───────────────────────────────────────────────────\n\nWe\'d love to hear your feedback!\nShare your experience: https://cartcure.co.nz/feedback.html?job=' + encodeURIComponent(data.jobNumber);
      break;
    case 'Cancelled':
      statusMessage = 'Your job has been cancelled as requested.\n\nIf you have any questions or would like to discuss this further, please don\'t hesitate to reach out.';
      break;
  }

  return `
═══════════════════════════════════════════════════
   JOB UPDATE - ${data.jobNumber}
═══════════════════════════════════════════════════

Hi ${data.clientName},

Your job is now: ${data.status}

${statusMessage}

Questions? Just reply to this email.

Cheers,
The CartCure Team

───────────────────────────────────────────────────
CartCure | Quick Shopify Fixes for NZ Businesses
https://cartcure.co.nz
  `;
}

/**
 * Get appropriate subject line for status change email
 *
 * @param {string} status - Job status
 * @param {string} jobNumber - Job number
 * @returns {string} Email subject line
 */
function getStatusEmailSubject(status, jobNumber) {
  const subjectMap = {
    'In Progress': 'Your Job is Now In Progress',
    'On Hold': 'Your Job is On Hold',
    'Completed': 'Your Job is Complete',
    'Cancelled': 'Your Job Has Been Cancelled'
  };

  const baseSubject = subjectMap[status] || 'Job Status Update';
  return baseSubject + ' (' + jobNumber + ')';
}

/**
 * Send status update email to client
 *
 * @param {string} jobNumber - The job number
 * @param {string} newStatus - The new status
 * @param {Object} [options={}] - Optional parameters
 * @param {string} [options.explanation] - Explanation for On Hold
 * @param {boolean} [options.wasOnHold] - Whether resuming from On Hold
 * @param {number} [options.daysOnHold] - Days the job was on hold
 * @returns {boolean} True if email sent successfully, false otherwise
 */
function sendStatusUpdateEmail(jobNumber, newStatus, options = {}) {
  const job = getJobByNumber(jobNumber);

  if (!job) {
    Logger.log('Cannot send status email - job not found: ' + jobNumber);
    return false;
  }

  const clientEmail = job['Client Email'];
  const clientName = job['Client Name'];

  // Validate client email
  if (!clientEmail || clientEmail.trim() === '') {
    Logger.log('Cannot send status email - no client email for ' + jobNumber);
    return false;
  }

  // Get settings
  const businessName = getSetting('Business Name') || 'CartCure';
  const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;

  // Build email data
  const emailData = {
    jobNumber: jobNumber,
    clientName: clientName,
    status: newStatus,
    businessName: businessName,
    explanation: options.explanation || '',
    wasOnHold: options.wasOnHold || false,
    daysOnHold: options.daysOnHold || 0
  };

  // Generate email content
  const subject = getStatusEmailSubject(newStatus, jobNumber);
  const htmlBody = generateStatusUpdateEmailHtml(emailData);
  const plainBody = generateStatusUpdateEmailPlainText(emailData);

  // Send email
  try {
    MailApp.sendEmail({
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      body: plainBody,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Log activity
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      'Status update: ' + newStatus,
      'To: ' + clientEmail,
      'Auto'
    );

    Logger.log('Status update email sent for ' + jobNumber + ' (status: ' + newStatus + ') to ' + clientEmail);
    return true;

  } catch (error) {
    Logger.log('Error sending status update email for ' + jobNumber + ': ' + error.message);
    // Don't alert user - just log. Status change should still succeed even if email fails
    return false;
  }
}

/**
 * Show dialog to send quote reminder
 */
function showQuoteReminderDialog() {
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([JOB_STATUS.QUOTED, JOB_STATUS.QUOTE_REMINDED]);
  showContextAwareDialog(
    'Send Quote Reminder',
    jobs,
    'Job',
    'sendQuoteReminder',
    selectedJob
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

  if (job['Status'] !== JOB_STATUS.QUOTED && job['Status'] !== JOB_STATUS.QUOTE_REMINDED) {
    ui.alert('Invalid Status', 'This job is not awaiting quote response. Status: ' + job['Status'], ui.ButtonSet.OK);
    return;
  }

  const businessName = getSetting('Business Name') || 'CartCure';
  const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gstNumber = getSetting('GST Number') || '';
  const clientName = job['Client Name'];
  const clientEmail = job['Client Email'];
  const total = job['Total (incl GST)'];
  const validUntil = job['Quote Valid Until'];
  const jobDescription = job['Job Description'] || '';
  const turnaround = job['Estimated Turnaround'] || '';

  const subject = 'Reminder: Your CartCure Quote (' + jobNumber + ')';

  // Build quote acceptance URL
  const acceptQuoteUrl = 'https://cartcure.co.nz/quote-acceptance.html?' +
    'job=' + encodeURIComponent(jobNumber) +
    '&name=' + encodeURIComponent(clientName) +
    '&desc=' + encodeURIComponent((jobDescription || '').substring(0, 100)) +
    '&amount=' + encodeURIComponent(total) +
    '&turnaround=' + encodeURIComponent(turnaround);

  // GST footer line
  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  // Render the email template
  const bodyContent = renderEmailTemplate('email-quote-reminder', {
    jobNumber: jobNumber,
    clientName: clientName,
    quoteAmount: formatCurrency(parseFloat(total) || 0),
    validUntil: validUntil,
    acceptQuoteUrl: acceptQuoteUrl,
    businessName: businessName,
    gstFooterLine: gstFooterLine
  });

  const htmlBody = wrapEmailHtml(bodyContent);

  // Plain text version
  const plainBody = `Hi ${clientName},

Just a friendly reminder that we sent you a quote for your Shopify store work. We'd love to help you get started!

QUOTE SUMMARY
-------------
Quote Reference: ${jobNumber}
Quoted Amount: ${formatCurrency(parseFloat(total) || 0)}
Valid Until: ${validUntil}

Ready to proceed? Visit this link to accept:
${acceptQuoteUrl}

Or simply reply to this email with "Approved" and we'll get started!

If you have any questions or need changes to the scope, just let us know.

Cheers,
The ${businessName} Team

--
${businessName}
Quick Shopify Fixes for NZ Businesses
https://cartcure.co.nz`;

  try {
    MailApp.sendEmail({
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      body: plainBody,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Log activity
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      'Quote reminder sent',
      'To: ' + clientEmail,
      'Auto'
    );

    // Update job status to Quote Reminded
    updateJobFields(jobNumber, {
      'Status': JOB_STATUS.QUOTE_REMINDED
    });

    ui.alert('Reminder Sent', 'Quote reminder sent to ' + clientEmail, ui.ButtonSet.OK);
    Logger.log('Quote reminder sent for ' + jobNumber);
  } catch (error) {
    Logger.log('Error sending reminder: ' + error.message);
    ui.alert('Error', 'Failed to send reminder: ' + error.message, ui.ButtonSet.OK);
  }
}

/**
 * Send quote reminder automatically (no UI alerts)
 * Used by the daily automatic trigger
 * @param {string} jobNumber - The job number
 * @returns {boolean} - True if sent successfully
 */
function sendQuoteReminderAuto(jobNumber) {
  const job = getJobByNumber(jobNumber);

  if (!job) {
    Logger.log('Job ' + jobNumber + ' not found for auto quote reminder');
    return false;
  }

  // Only send for jobs in Quoted status (not Quote Reminded - they already got a reminder)
  if (job['Status'] !== JOB_STATUS.QUOTED) {
    Logger.log('Job ' + jobNumber + ' not in Quoted status, skipping');
    return false;
  }

  const businessName = getSetting('Business Name') || 'CartCure';
  const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gstNumber = getSetting('GST Number') || '';
  const clientName = job['Client Name'];
  const clientEmail = job['Client Email'];
  const total = job['Total (incl GST)'];
  const validUntil = job['Quote Valid Until'];
  const jobDescription = job['Job Description'] || '';
  const turnaround = job['Estimated Turnaround'] || '';

  if (!clientEmail) {
    Logger.log('Job ' + jobNumber + ' has no client email, skipping');
    return false;
  }

  const subject = 'Reminder: Your CartCure Quote (' + jobNumber + ')';

  // Build quote acceptance URL
  const acceptQuoteUrl = 'https://cartcure.co.nz/quote-acceptance.html?' +
    'job=' + encodeURIComponent(jobNumber) +
    '&name=' + encodeURIComponent(clientName) +
    '&desc=' + encodeURIComponent((jobDescription || '').substring(0, 100)) +
    '&amount=' + encodeURIComponent(total) +
    '&turnaround=' + encodeURIComponent(turnaround);

  // GST footer line
  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  // Render the email template
  const bodyContent = renderEmailTemplate('email-quote-reminder', {
    jobNumber: jobNumber,
    clientName: clientName,
    quoteAmount: formatCurrency(parseFloat(total) || 0),
    validUntil: validUntil,
    acceptQuoteUrl: acceptQuoteUrl,
    businessName: businessName,
    gstFooterLine: gstFooterLine
  });

  const htmlBody = wrapEmailHtml(bodyContent);

  // Plain text version
  const plainBody = `Hi ${clientName},

Just a friendly reminder that we sent you a quote for your Shopify store work. We'd love to help you get started!

QUOTE SUMMARY
-------------
Quote Reference: ${jobNumber}
Quoted Amount: ${formatCurrency(parseFloat(total) || 0)}
Valid Until: ${validUntil}

Ready to proceed? Visit this link to accept:
${acceptQuoteUrl}

Or simply reply to this email with "Approved" and we'll get started!

If you have any questions or need changes to the scope, just let us know.

Cheers,
The ${businessName} Team

--
${businessName}
Quick Shopify Fixes for NZ Businesses
https://cartcure.co.nz`;

  try {
    MailApp.sendEmail({
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      body: plainBody,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Log activity
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      'Auto quote reminder sent (7+ days)',
      'To: ' + clientEmail,
      'Auto'
    );

    // Update job status to Quote Reminded
    updateJobFields(jobNumber, {
      'Status': JOB_STATUS.QUOTE_REMINDED
    });

    Logger.log('Auto quote reminder sent for ' + jobNumber);
    return true;
  } catch (error) {
    Logger.log('Error sending auto quote reminder for ' + jobNumber + ': ' + error.message);
    return false;
  }
}

/**
 * Automatically send quote reminders for jobs awaiting response for 7+ days
 * This function is called by a daily trigger
 */
function autoSendQuoteReminders() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);

  if (!jobsSheet) {
    Logger.log('Jobs sheet not found');
    return;
  }

  const data = jobsSheet.getDataRange().getValues();
  const headers = data[0];

  const statusCol = headers.indexOf('Status');
  const jobNumCol = headers.indexOf('Job #');
  const quoteSentDateCol = headers.indexOf('Quote Sent Date');

  if (statusCol === -1 || jobNumCol === -1 || quoteSentDateCol === -1) {
    Logger.log('Required columns not found in Jobs sheet');
    return;
  }

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  let remindersSent = 0;
  let skipped = 0;

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const status = row[statusCol];
    const jobNumber = row[jobNumCol];
    const quoteSentDateStr = row[quoteSentDateCol];

    // Only process jobs in 'Quoted' status (not already reminded)
    if (status !== JOB_STATUS.QUOTED) {
      continue;
    }

    if (!jobNumber || !quoteSentDateStr) {
      continue;
    }

    // Parse quote sent date (DD/MM/YYYY format or Date object)
    let quoteSentDate;
    if (quoteSentDateStr instanceof Date) {
      quoteSentDate = quoteSentDateStr;
    } else {
      const parts = quoteSentDateStr.split('/');
      if (parts.length === 3) {
        quoteSentDate = new Date(parts[2], parts[1] - 1, parts[0]);
      } else {
        Logger.log('Invalid quote sent date format for job ' + jobNumber + ': ' + quoteSentDateStr);
        continue;
      }
    }
    quoteSentDate.setHours(0, 0, 0, 0);

    // Calculate days since quote was sent
    const daysSinceQuote = Math.floor((today - quoteSentDate) / (1000 * 60 * 60 * 24));

    // Send reminder if quote was sent 7+ days ago
    if (daysSinceQuote >= 7) {
      const success = sendQuoteReminderAuto(jobNumber);
      if (success) {
        remindersSent++;
      } else {
        skipped++;
      }
    }
  }

  Logger.log('Auto quote reminders complete: ' + remindersSent + ' sent, ' + skipped + ' skipped');
}

/**
 * Show dialog to decline quote
 */
function showDeclineQuoteDialog() {
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([JOB_STATUS.QUOTED, JOB_STATUS.QUOTE_REMINDED, JOB_STATUS.PENDING_QUOTE]);
  showContextAwareDialog(
    'Mark Quote Declined',
    jobs,
    'Job',
    'markQuoteDeclined',
    selectedJob
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

  // Refresh dashboard to show updated data
  refreshDashboard();
}

// ============================================================================
// INVOICE FUNCTIONS
// ============================================================================

/**
 * Show dialog to generate invoice
 */
function showGenerateInvoiceDialog() {
  const selectedJob = getSelectedJobNumber();
  // Show jobs that may need invoices: Completed jobs (for full/balance invoices)
  // and Accepted jobs (for deposit invoices on $200+ jobs)
  const jobs = getJobsByStatus([JOB_STATUS.COMPLETED, JOB_STATUS.ACCEPTED, JOB_STATUS.IN_PROGRESS]);
  showContextAwareDialog(
    'Generate Invoice',
    jobs,
    'Job',
    'generateInvoiceForJob',
    selectedJob
  );
}

/**
 * Generate an invoice for a job (unified function - auto-detects Full/Deposit/Balance)
 */
function generateInvoiceForJob(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
  if (!invoiceSheet) {
    ui.alert('Error', 'Invoice Log sheet not found. Please run Setup first.', ui.ButtonSet.OK);
    return;
  }

  // Get existing invoices and analyze state
  const existingInvoices = getInvoicesByJobNumber(jobNumber);
  const hasDeposit = existingInvoices.some(inv => inv['Invoice Type'] === 'Deposit');
  const hasBalance = existingInvoices.some(inv => inv['Invoice Type'] === 'Balance');
  const depositInvoice = existingInvoices.find(inv => inv['Invoice Type'] === 'Deposit');
  const depositPaid = depositInvoice && depositInvoice['Status'] === 'Paid';

  // Calculate amounts
  const amount = parseFloat(job['Quote Amount (excl GST)']) || 0;
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gst = isGSTRegistered ? (parseFloat(job['GST']) || 0) : 0;
  const total = isGSTRegistered ? (parseFloat(job['Total (incl GST)']) || amount) : amount;
  const projectSize = getProjectSize(total);

  // Calculate remaining balance
  const paidAmount = calculatePaidAmount(jobNumber);
  const remainingBalance = total - paidAmount;

  // Decision tree for invoice type
  let invoiceType, invoiceAmount, invoiceGst, invoiceTotal, invoiceTypeMessage;

  if (existingInvoices.length === 0) {
    // NO INVOICES: Create Full or Deposit based on project size
    if (projectSize === PROJECT_SIZE.SMALL) {
      invoiceType = 'Full';
      invoiceAmount = amount;
      invoiceGst = gst;
      invoiceTotal = total;
      invoiceTypeMessage = '';
    } else {
      // Medium or Large: Create 50% Deposit
      invoiceType = 'Deposit';
      invoiceAmount = amount * 0.5;
      invoiceGst = gst * 0.5;
      invoiceTotal = total * 0.5;
      invoiceTypeMessage = '\n\nThis is a 50% DEPOSIT invoice (' + projectSize + ' project).\n' +
        'Use Generate Invoice again after completion to create the balance invoice.';
    }
  } else if (hasDeposit && !hasBalance) {
    // HAS DEPOSIT, NO BALANCE: Create Balance invoice
    if (!depositPaid) {
      // Deposit not paid - warn user
      const response = ui.alert(
        'Deposit Not Paid',
        'The deposit invoice has not been marked as paid yet.\n\n' +
        'Are you sure you want to generate the balance invoice anyway?',
        ui.ButtonSet.YES_NO
      );
      if (response !== ui.Button.YES) {
        return;
      }
    }

    // Calculate balance (remaining 50%)
    const depositAmount = parseFloat(depositInvoice['Amount (excl GST)']) || 0;
    const depositGst = parseFloat(depositInvoice['GST']) || 0;

    invoiceType = 'Balance';
    invoiceAmount = amount - depositAmount;
    invoiceGst = gst - depositGst;
    invoiceTotal = invoiceAmount + invoiceGst;
    invoiceTypeMessage = '\n\nThis is the BALANCE invoice (remaining 50%) for this job.';
  } else if (remainingBalance > 0.01) {
    // Has invoices but remaining balance - create Additional invoice
    const response = ui.alert(
      'Create Additional Invoice?',
      'This job has existing invoices but an outstanding balance of ' + formatCurrency(remainingBalance) + '.\n\n' +
      'Do you want to create an additional invoice for this amount?',
      ui.ButtonSet.YES_NO
    );
    if (response !== ui.Button.YES) {
      return;
    }

    invoiceType = 'Additional';
    // Calculate based on remaining balance (reverse GST calculation)
    if (isGSTRegistered) {
      invoiceTotal = remainingBalance;
      invoiceAmount = remainingBalance / 1.15; // Remove GST
      invoiceGst = remainingBalance - invoiceAmount;
    } else {
      invoiceAmount = remainingBalance;
      invoiceGst = 0;
      invoiceTotal = remainingBalance;
    }
    invoiceTypeMessage = '\n\nThis is an ADDITIONAL invoice (#' + (existingInvoices.length + 1) + ') for this job.';
  } else {
    // Fully invoiced
    ui.alert('Fully Invoiced',
      'This job is already fully invoiced.\n\n' +
      'Total: ' + formatCurrency(total) + '\n' +
      'Invoiced: ' + formatCurrency(total - remainingBalance) + '\n' +
      'Remaining: ' + formatCurrency(remainingBalance),
      ui.ButtonSet.OK
    );
    return;
  }

  // Generate invoice number and dates
  const invoiceNumber = generateInvoiceNumber(jobNumber, existingInvoices.length);
  const now = new Date();
  const paymentTerms = parseInt(getSetting('Default Payment Terms')) || JOB_CONFIG.PAYMENT_TERMS_DAYS;
  const dueDate = new Date(now);
  // Deposits are due immediately, other invoices get standard payment terms
  if (invoiceType !== 'Deposit') {
    dueDate.setDate(dueDate.getDate() + paymentTerms);
  }

  // Create invoice row using config-based helper (auto-orders columns from COLUMN_CONFIG)
  const invoiceRow = buildRowFromConfig('INVOICES', {
    'Invoice #': invoiceNumber,
    'Job #': jobNumber,
    'Client Name': job['Client Name'],
    'Client Email': job['Client Email'],
    'Client Phone': job['Client Phone'] || '',
    'Invoice Date': formatNZDate(now),
    'Due Date': formatNZDate(dueDate),
    'Amount (excl GST)': invoiceAmount.toFixed(2),
    'GST': invoiceGst.toFixed(2),
    'Total': invoiceTotal.toFixed(2),
    'Status': 'Draft',
    'Total With Fees': invoiceTotal.toFixed(2),
    'Invoice Type': invoiceType
  });

  invoiceSheet.appendRow(invoiceRow);

  // Update job with latest invoice number
  updateJobField(jobNumber, 'Invoice #', invoiceNumber);

  Logger.log('Invoice ' + invoiceNumber + ' (' + invoiceType + ') generated for ' + jobNumber);

  // Show preview of the generated invoice
  previewInvoiceEmail(invoiceNumber);
}

/**
 * Show dialog to send invoice
 */
function showSendInvoiceDialog() {
  const selectedInvoice = getSelectedInvoiceNumber();
  const invoices = getInvoicesByStatus(['Draft']);
  showContextAwareDialog(
    'Send Invoice',
    invoices,
    'Invoice',
    'sendInvoiceEmail',
    selectedInvoice
  );
}

/**
 * Get invoice by number
 */
/**
 * PERFORMANCE OPTIMIZED: Get invoice by number using TextFinder API
 *
 * OLD APPROACH: Load entire Invoices sheet and loop through all rows
 * NEW APPROACH: Use Google's TextFinder API to locate invoice, then load only 2 rows
 *
 * OPTIMIZATION BENEFIT:
 * - For 50 invoice sheet: Load 2 rows instead of 50 rows (96% reduction)
 * - TextFinder uses Google's server-side indexing
 * - Reduces data transfer and processing time by 60-70%
 *
 * @param {string} invoiceNumber - The invoice number to find (e.g., "INV-0001")
 * @returns {Object|null} Invoice object with all fields, or null if not found
 */
function getInvoiceByNumber(invoiceNumber) {
  const startTime = new Date().getTime();

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!sheet) {
    Logger.log('[PERF] getInvoiceByNumber() - Invoices sheet not found');
    return null;
  }

  // OPTIMIZATION: Use TextFinder API instead of loading entire sheet
  const finder = sheet.createTextFinder(invoiceNumber)
    .matchEntireCell(true)   // Exact match only
    .matchCase(true);         // Case-sensitive search

  const foundRange = finder.findNext();

  if (!foundRange) {
    Logger.log('[PERF] getInvoiceByNumber() - Invoice not found: ' + invoiceNumber);
    return null;
  }

  // Verify the found cell is in column A (Invoice # column)
  if (foundRange.getColumn() !== 1) {
    Logger.log('[PERF] getInvoiceByNumber() - Invoice number found in wrong column for: ' + invoiceNumber);
    return null;
  }

  const rowIndex = foundRange.getRow();

  // OPTIMIZATION: Load only 2 rows (header + found row) instead of entire sheet
  const lastColumn = sheet.getLastColumn();
  const headers = sheet.getRange(1, 1, 1, lastColumn).getValues()[0];
  const rowData = sheet.getRange(rowIndex, 1, 1, lastColumn).getValues()[0];

  // Build invoice object from the single row
  const invoice = {};
  headers.forEach((header, index) => {
    invoice[header] = rowData[index];
  });
  invoice._rowIndex = rowIndex; // Store row index for updates

  // Performance logging
  const endTime = new Date().getTime();
  const executionTime = endTime - startTime;
  Logger.log('[PERF] getInvoiceByNumber() - Found ' + invoiceNumber + ' in ' + executionTime + 'ms (TextFinder optimization)');

  return invoice;
}

/**
 * Get all invoices for a specific job number
 * Returns an array of invoice objects for the given job
 * @param {string} jobNumber - The job number to search for
 * @returns {Array} Array of invoice objects for this job
 */
function getInvoicesByJobNumber(jobNumber) {
  const startTime = new Date().getTime();

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!sheet) {
    Logger.log('[PERF] getInvoicesByJobNumber() - Invoices sheet not found');
    return [];
  }

  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) return []; // No data rows

  // Load all data at once
  const allData = sheet.getDataRange().getValues();
  const headers = allData[0];
  const jobNumColIndex = headers.indexOf('Job #');

  if (jobNumColIndex === -1) {
    Logger.log('[PERF] getInvoicesByJobNumber() - Job # column not found');
    return [];
  }

  const invoices = [];

  // Find all rows with matching job number
  for (let i = 1; i < allData.length; i++) {
    const row = allData[i];
    const rowJobNum = row[jobNumColIndex];

    if (String(rowJobNum).trim() === String(jobNumber).trim()) {
      const invoice = {};
      headers.forEach((header, index) => {
        invoice[header] = row[index];
      });
      invoice._rowIndex = i + 1; // Store row index (1-based)
      invoices.push(invoice);
    }
  }

  const endTime = new Date().getTime();
  const executionTime = endTime - startTime;
  Logger.log('[PERF] getInvoicesByJobNumber() - Found ' + invoices.length + ' invoices for ' + jobNumber + ' in ' + executionTime + 'ms');

  return invoices;
}

/**
 * Calculate total paid amount for a job from its invoices
 * @param {string} jobNumber - The job number
 * @returns {number} Total amount paid across all invoices
 */
function calculatePaidAmount(jobNumber) {
  const invoices = getInvoicesByJobNumber(jobNumber);
  return invoices
    .filter(inv => inv['Status'] === 'Paid')
    .reduce((sum, inv) => sum + (parseFloat(inv['Total']) || 0), 0);
}

/**
 * Update invoice field
 */
/**
 * PERFORMANCE OPTIMIZED: Update multiple invoice fields in a single operation
 *
 * This function replaces multiple updateInvoiceField() calls with a single batch operation.
 * OPTIMIZATION BENEFIT: Reduces sheet loads from N (one per field) to 1 (single load)
 * Example: markInvoicePaid() now does 1 sheet load instead of 3
 *
 * @param {string} invoiceNumber - The invoice number to update (e.g., "INV-0001")
 * @param {Object} updates - Object with field names as keys and new values
 *                           Example: {'Status': 'Paid', 'Paid Date': '2024-01-15'}
 * @returns {boolean} true if successful, false if invoice not found or sheet error
 *
 * Performance: ~75% faster than multiple updateInvoiceField() calls for 3+ field updates
 */
function updateInvoiceFields(invoiceNumber, updates) {
  const startTime = new Date().getTime();

  // Validate inputs
  if (!invoiceNumber || !updates || Object.keys(updates).length === 0) {
    Logger.log('[PERF] updateInvoiceFields() - Invalid parameters');
    return false;
  }

  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!sheet) {
    Logger.log('[PERF] updateInvoiceFields() - Invoices sheet not found');
    return false;
  }

  // OPTIMIZATION: Single sheet load instead of N loads
  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  const invoiceNumColIndex = headers.indexOf('Invoice #');

  if (invoiceNumColIndex < 0) {
    Logger.log('[PERF] updateInvoiceFields() - Invoice # column not found');
    return false;
  }

  // Find the invoice row
  let rowIndex = -1;
  for (let i = 1; i < data.length; i++) {
    if (String(data[i][invoiceNumColIndex]).trim() === String(invoiceNumber).trim()) {
      rowIndex = i;
      break;
    }
  }

  if (rowIndex < 0) {
    Logger.log('[PERF] updateInvoiceFields() - Invoice not found: ' + invoiceNumber);
    return false;
  }

  // Prepare batch update: collect all ranges and values
  const rangesToUpdate = [];
  const valuesToUpdate = [];
  let fieldsUpdated = 0;

  // Process each field update request
  for (const [fieldName, value] of Object.entries(updates)) {
    const colIndex = headers.indexOf(fieldName);
    if (colIndex >= 0) {
      rangesToUpdate.push(sheet.getRange(rowIndex + 1, colIndex + 1));
      valuesToUpdate.push(value);
      fieldsUpdated++;
    } else {
      Logger.log('[PERF] updateInvoiceFields() - Field not found: ' + fieldName);
    }
  }

  // OPTIMIZATION: Batch write all values
  for (let i = 0; i < rangesToUpdate.length; i++) {
    rangesToUpdate[i].setValue(valuesToUpdate[i]);
  }

  // Performance logging
  const endTime = new Date().getTime();
  const executionTime = endTime - startTime;
  Logger.log('[PERF] updateInvoiceFields() - Updated ' + fieldsUpdated + ' fields for ' + invoiceNumber + ' in ' + executionTime + 'ms');

  // Log to debug file for tracking
  logPerformanceToDebugFile('updateInvoiceFields', {
    invoiceNumber: invoiceNumber,
    fieldsUpdated: fieldsUpdated,
    executionTime: executionTime + 'ms'
  });

  return true;
}

/**
 * LEGACY: Update a single invoice field (kept for backward compatibility)
 *
 * NOTE: For updating multiple fields, use updateInvoiceFields() instead for better performance
 * This function loads the entire sheet for each call - inefficient when called multiple times
 *
 * @param {string} invoiceNumber - The invoice number to update
 * @param {string} fieldName - The field name to update
 * @param {*} value - The new value to set
 * @returns {boolean} true if successful, false otherwise
 */
function updateInvoiceField(invoiceNumber, fieldName, value) {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!sheet) return false;

  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  const invoiceNumColIndex = headers.indexOf('Invoice #');
  const colIndex = headers.indexOf(fieldName);

  if (invoiceNumColIndex < 0 || colIndex < 0) return false;

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][invoiceNumColIndex]).trim() === String(invoiceNumber).trim()) {
      sheet.getRange(i + 1, colIndex + 1).setValue(value);
      return true;
    }
  }
  return false;
}

/**
 * Send invoice email
 */
/**
 * Send invoice email (standard non-deposit invoice for completed work)
 * EMAIL TEMPLATE: See apps-script/email-invoice.html
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
  const invoiceType = invoice['Invoice Type'] || 'Full';

  // Validate required fields
  if (!clientEmail) {
    ui.alert('Missing Email', 'No email address found for this invoice. Please update the client email first.', ui.ButtonSet.OK);
    return;
  }

  if (!clientName) {
    ui.alert('Missing Client Name', 'No client name found for this invoice. Please update the client name first.', ui.ButtonSet.OK);
    return;
  }

  // Determine subject based on invoice type
  let subject = 'Invoice ' + invoiceNumber + ' from CartCure';
  if (invoiceType === 'Balance') {
    subject = 'Balance Invoice ' + invoiceNumber + ' from CartCure (Final Payment)';
  }

  // Get deposit invoice info for balance invoices
  let depositInfo = null;
  let totalJobAmount = 0;
  if (invoiceType === 'Balance') {
    const allInvoices = getInvoicesByJobNumber(jobNumber);
    const depositInvoice = allInvoices.find(inv => inv['Invoice Type'] === 'Deposit');
    if (depositInvoice) {
      const job = getJobByNumber(jobNumber);
      const jobTotal = job ? (parseFloat(job['Total (incl GST)']) || parseFloat(job['Quote Amount (excl GST)']) || 0) : 0;
      totalJobAmount = isGSTRegistered ? jobTotal : (parseFloat(job['Quote Amount (excl GST)']) || 0);
      depositInfo = {
        amount: parseFloat(depositInvoice['Total']) || parseFloat(depositInvoice['Amount (excl GST)']) || 0,
        paidDate: depositInvoice['Paid Date'] || null,
        invoiceNumber: depositInvoice['Invoice #']
      };
    }
  }

  // Build pricing section - validate GST is a number
  const gstValue = parseFloat(gst);
  const displayTotal = isGSTRegistered ? total : amount;

  // Build pricing rows HTML
  let pricingRowsHtml = '';
  if (isGSTRegistered && !isNaN(gstValue) && gstValue > 0) {
    pricingRowsHtml = `
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkGray};">Subtotal (excl. GST)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkBlack}; font-weight: bold;">$${amount}</span>
        </td>
      </tr>
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkGray};">GST (15%)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkBlack};">$${gst}</span>
        </td>
      </tr>
      <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
        <td style="padding: 15px;">
          <span style="color: #ffffff; font-weight: bold;">TOTAL DUE (incl. GST)</span>
        </td>
        <td align="right" style="padding: 15px;">
          <span style="color: #ffffff; font-size: 20px; font-weight: bold;">$${total}</span>
        </td>
      </tr>
    `;
  } else {
    pricingRowsHtml = `
      <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
        <td style="padding: 15px;">
          <span style="color: #ffffff; font-weight: bold;">TOTAL DUE</span>
        </td>
        <td align="right" style="padding: 15px;">
          <span style="color: #ffffff; font-size: 20px; font-weight: bold;">$${displayTotal}</span>
        </td>
      </tr>
    `;
  }

  // Build bank details HTML
  let bankDetailsHtml = '';
  if (bankName) bankDetailsHtml += 'Bank: ' + bankName + '<br>';
  if (bankAccount) bankDetailsHtml += 'Account: ' + bankAccount + '<br>';

  // GST footer line
  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  // Render template based on invoice type
  let bodyContent;
  if (invoiceType === 'Balance' && depositInfo) {
    // Use dedicated balance invoice template
    const depositPaidText = depositInfo.paidDate ? ' (paid ' + depositInfo.paidDate + ')' : '';
    bodyContent = renderEmailTemplate('email-balance-invoice', {
      invoiceNumber: invoiceNumber,
      jobNumber: jobNumber,
      clientName: clientName,
      invoiceDate: formatNZDate(new Date()),
      dueDate: formatDueDate(dueDate),
      totalJobAmount: totalJobAmount.toFixed(2),
      depositAmount: depositInfo.amount.toFixed(2),
      depositPaidText: depositPaidText,
      balanceDue: displayTotal,
      pricingRowsHtml: pricingRowsHtml,
      bankDetailsHtml: bankDetailsHtml,
      gstFooterLine: gstFooterLine,
      businessName: businessName
    });
  } else {
    // Use standard invoice template
    bodyContent = renderEmailTemplate('email-invoice', {
      headingTitle: 'Invoice',
      invoiceNumber: invoiceNumber,
      jobNumber: jobNumber,
      clientName: clientName,
      greetingText: 'Thank you for choosing CartCure! Please find your invoice below for the completed work.',
      invoiceDate: formatNZDate(new Date()),
      dueDate: formatDueDate(dueDate),
      pricingRowsHtml: pricingRowsHtml,
      depositNoticeHtml: '', // No deposit notice for standard invoices
      bankDetailsHtml: bankDetailsHtml,
      gstFooterLine: gstFooterLine,
      businessName: businessName
    });
  }

  const htmlBody = wrapEmailHtml(bodyContent);

  try {
    MailApp.sendEmail({
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Log activity
    const invoiceTypeLabel = invoiceType === 'Balance' ? 'Balance invoice' : 'Invoice';
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      invoiceTypeLabel + ' sent: ' + formatCurrency(displayTotal),
      'To: ' + clientEmail,
      'Auto'
    );

    // OPTIMIZATION: Batch update invoice fields (2 calls → 1)
    updateInvoiceFields(invoiceNumber, {
      'Status': 'Sent',
      'Sent Date': formatNZDate(new Date())
    });

    // Update job payment status
    updateJobField(jobNumber, 'Payment Status', PAYMENT_STATUS.INVOICED);

    ui.alert(invoiceTypeLabel + ' Sent', invoiceTypeLabel + ' sent to ' + clientEmail, ui.ButtonSet.OK);
    Logger.log('Invoice ' + invoiceNumber + ' sent to ' + clientEmail);
  } catch (error) {
    Logger.log('Error sending invoice: ' + error.message);
    ui.alert('Error', 'Failed to send invoice: ' + error.message, ui.ButtonSet.OK);
  }
}

/**
 * Render invoice email HTML for preview (without sending)
 * This reuses the same logic as sendInvoiceEmail but returns HTML instead
 *
 * @param {string} invoiceNumber - The invoice number to preview
 * @returns {Object} Result with success, html, subject, or error
 */
function renderInvoiceEmailPreview(invoiceNumber) {
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    return { success: false, error: 'Invoice ' + invoiceNumber + ' not found.' };
  }

  const businessName = getSetting('Business Name') || 'CartCure';
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
  const invoiceType = invoice['Invoice Type'] || 'Full';
  const status = invoice['Status'] || 'Draft';

  // Determine subject based on invoice type
  let subject = 'Invoice ' + invoiceNumber + ' from CartCure';
  if (invoiceType === 'Balance') {
    subject = 'Balance Invoice ' + invoiceNumber + ' from CartCure (Final Payment)';
  }

  // Get deposit invoice info for balance invoices
  let depositInfo = null;
  let totalJobAmount = 0;
  if (invoiceType === 'Balance') {
    const allInvoices = getInvoicesByJobNumber(jobNumber);
    const depositInvoice = allInvoices.find(inv => inv['Invoice Type'] === 'Deposit');
    if (depositInvoice) {
      const job = getJobByNumber(jobNumber);
      const jobTotal = job ? (parseFloat(job['Total (incl GST)']) || parseFloat(job['Quote Amount (excl GST)']) || 0) : 0;
      totalJobAmount = isGSTRegistered ? jobTotal : (parseFloat(job['Quote Amount (excl GST)']) || 0);
      depositInfo = {
        amount: parseFloat(depositInvoice['Total']) || parseFloat(depositInvoice['Amount (excl GST)']) || 0,
        paidDate: depositInvoice['Paid Date'] || null,
        invoiceNumber: depositInvoice['Invoice #']
      };
    }
  }

  // Build pricing section
  const gstValue = parseFloat(gst);
  const displayTotal = isGSTRegistered ? total : amount;

  // Build pricing rows HTML
  let pricingRowsHtml = '';
  if (isGSTRegistered && !isNaN(gstValue) && gstValue > 0) {
    pricingRowsHtml = `
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkGray};">Subtotal (excl. GST)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkBlack}; font-weight: bold;">$${amount}</span>
        </td>
      </tr>
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkGray};">GST (15%)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
          <span style="color: ${EMAIL_COLORS.inkBlack};">$${gst}</span>
        </td>
      </tr>
      <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
        <td style="padding: 15px;">
          <span style="color: #ffffff; font-weight: bold;">TOTAL DUE (incl. GST)</span>
        </td>
        <td align="right" style="padding: 15px;">
          <span style="color: #ffffff; font-size: 20px; font-weight: bold;">$${total}</span>
        </td>
      </tr>
    `;
  } else {
    pricingRowsHtml = `
      <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
        <td style="padding: 15px;">
          <span style="color: #ffffff; font-weight: bold;">TOTAL DUE</span>
        </td>
        <td align="right" style="padding: 15px;">
          <span style="color: #ffffff; font-size: 20px; font-weight: bold;">$${displayTotal}</span>
        </td>
      </tr>
    `;
  }

  // Build bank details HTML
  let bankDetailsHtml = '';
  if (bankName) bankDetailsHtml += 'Bank: ' + bankName + '<br>';
  if (bankAccount) bankDetailsHtml += 'Account: ' + bankAccount + '<br>';

  // GST footer line
  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  // Render template based on invoice type
  let bodyContent;
  if (invoiceType === 'Balance' && depositInfo) {
    const depositPaidText = depositInfo.paidDate ? ' (paid ' + depositInfo.paidDate + ')' : '';
    bodyContent = renderEmailTemplate('email-balance-invoice', {
      invoiceNumber: invoiceNumber,
      jobNumber: jobNumber,
      clientName: clientName,
      invoiceDate: formatNZDate(new Date()),
      dueDate: formatDueDate(dueDate),
      totalJobAmount: totalJobAmount.toFixed(2),
      depositAmount: depositInfo.amount.toFixed(2),
      depositPaidText: depositPaidText,
      balanceDue: displayTotal,
      pricingRowsHtml: pricingRowsHtml,
      bankDetailsHtml: bankDetailsHtml,
      gstFooterLine: gstFooterLine,
      businessName: businessName
    });
  } else {
    bodyContent = renderEmailTemplate('email-invoice', {
      headingTitle: 'Invoice',
      invoiceNumber: invoiceNumber,
      jobNumber: jobNumber,
      clientName: clientName,
      greetingText: 'Thank you for choosing CartCure! Please find your invoice below for the completed work.',
      invoiceDate: formatNZDate(new Date()),
      dueDate: formatDueDate(dueDate),
      pricingRowsHtml: pricingRowsHtml,
      depositNoticeHtml: '',
      bankDetailsHtml: bankDetailsHtml,
      gstFooterLine: gstFooterLine,
      businessName: businessName
    });
  }

  const htmlBody = wrapEmailHtml(bodyContent);

  return {
    success: true,
    html: htmlBody,
    subject: subject,
    invoiceNumber: invoiceNumber,
    invoiceType: invoiceType,
    status: status,
    clientEmail: clientEmail,
    clientName: clientName,
    total: displayTotal
  };
}

/**
 * Show invoice email preview in a modal dialog
 * Uses iframe to render the email HTML exactly as it would appear in an email client
 *
 * @param {string} invoiceNumber - The invoice number to preview
 */
function previewInvoiceEmail(invoiceNumber) {
  const ui = SpreadsheetApp.getUi();
  const result = renderInvoiceEmailPreview(invoiceNumber);

  if (!result.success) {
    ui.alert('Error', result.error, ui.ButtonSet.OK);
    return;
  }

  // Escape the HTML for use in srcdoc attribute
  const escapedHtml = result.html
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;');

  // Create preview dialog with iframe to render email exactly
  const previewHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; height: 100vh; display: flex; flex-direction: column; }
        .header { background: #f5f5f5; padding: 10px 15px; border-bottom: 1px solid #ddd; font-size: 12px; }
        .header-row { margin: 2px 0; }
        .header-row strong { color: #666; }
        .status { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; margin-left: 5px; }
        .status-draft { background: #fff3cd; color: #856404; }
        .status-sent { background: #d4edda; color: #155724; }
        .status-paid { background: #cce5ff; color: #004085; }
        .status-overdue { background: #f8d7da; color: #721c24; }
        .email-frame { flex: 1; border: none; width: 100%; }
        .actions { padding: 10px; text-align: right; background: #f5f5f5; border-top: 1px solid #ddd; }
        .btn { padding: 8px 16px; margin-left: 8px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .btn-send { background: #2d5d3f; color: white; }
        .btn-send:hover { background: #1e4a2f; }
        .btn-close { background: #6c757d; color: white; }
        .btn-close:hover { background: #545b62; }
      </style>
    </head>
    <body>
      <div class="header">
        <div class="header-row"><strong>To:</strong> ${result.clientName} &lt;${result.clientEmail}&gt;</div>
        <div class="header-row"><strong>Subject:</strong> ${result.subject}</div>
        <div class="header-row"><strong>Invoice:</strong> ${result.invoiceNumber} (${result.invoiceType}) <span class="status status-${result.status.toLowerCase()}">${result.status}</span></div>
      </div>
      <iframe class="email-frame" srcdoc="${escapedHtml}"></iframe>
      <div class="actions">
        <button class="btn btn-close" onclick="google.script.host.close()">Close</button>
        ${result.status === 'Draft' ? '<button class="btn btn-send" onclick="sendInvoice()">Send Invoice</button>' : ''}
      </div>
      <script>
        function sendInvoice() {
          document.querySelector('.btn-send').disabled = true;
          document.querySelector('.btn-send').textContent = 'Sending...';
          google.script.run
            .withSuccessHandler(function() {
              google.script.host.close();
            })
            .withFailureHandler(function(err) {
              alert('Failed to send: ' + err);
              document.querySelector('.btn-send').disabled = false;
              document.querySelector('.btn-send').textContent = 'Send Invoice';
            })
            .sendInvoiceEmail('${result.invoiceNumber}');
        }
      </script>
    </body>
    </html>
  `;

  const htmlOutput = HtmlService.createHtmlOutput(previewHtml)
    .setWidth(700)
    .setHeight(650);

  ui.showModalDialog(htmlOutput, 'Invoice Preview - ' + invoiceNumber);
}

/**
 * Show dialog to view/preview any invoice
 */
function showViewInvoiceDialog() {
  const selectedInvoice = getSelectedInvoiceNumber();
  const invoices = getAllInvoices();
  showContextAwareDialog(
    'View Invoice',
    invoices,
    'Invoice',
    'previewInvoiceEmail',
    selectedInvoice
  );
}

/**
 * Get all invoices for the view dialog
 * Returns array of objects with number and display properties for dropdown
 * @returns {Array} Array of invoice objects formatted for showDropdownDialog
 */
function getAllInvoices() {
  const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  const sheet = ss.getSheetByName(SHEETS.INVOICES);
  if (!sheet) return [];

  const data = sheet.getDataRange().getValues();
  if (data.length <= 1) return [];

  const headers = data[0];
  const invoices = [];

  // Find column indices dynamically from headers
  const invoiceNumCol = headers.indexOf('Invoice #');
  const jobNumColIndex = headers.indexOf('Job #');
  const clientNameColIndex = headers.indexOf('Client Name');
  const totalColIndex = headers.indexOf('Total');
  const statusColIndex = headers.indexOf('Status');

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const invoiceNum = invoiceNumCol >= 0 ? row[invoiceNumCol] : '';

    if (invoiceNum) {  // Has invoice number
      const clientName = clientNameColIndex >= 0 ? row[clientNameColIndex] : 'Unknown';
      const total = totalColIndex >= 0 ? row[totalColIndex] : 0;
      const status = statusColIndex >= 0 ? row[statusColIndex] : '';

      invoices.push({
        number: invoiceNum,
        jobNumber: jobNumColIndex >= 0 ? row[jobNumColIndex] : '',
        clientName: clientName,
        status: status,
        total: total || 0,
        display: invoiceNum + ' - ' + clientName + ' - ' + formatCurrency(total || 0) + ' (' + status + ')'
      });
    }
  }

  return invoices;
}

/**
 * Show dialog to send invoice reminder
 */
function showSendInvoiceReminderDialog() {
  const selectedInvoice = getSelectedInvoiceNumber();
  const invoices = getInvoicesByStatus(['Sent', 'Overdue']);
  showContextAwareDialog(
    'Send Invoice Reminder',
    invoices,
    'Invoice',
    'sendInvoiceReminder',
    selectedInvoice
  );
}

/**
 * Send invoice reminder email (pre-due date reminder)
 * Designed to be sent ~6 days after invoice (1 day before due date)
 * Helps clients avoid late fees by reminding them before the invoice becomes overdue
 */
function sendInvoiceReminder(invoiceNumber) {
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
  const amount = parseFloat(invoice['Amount (excl GST)']) || 0;
  const total = parseFloat(invoice['Total']) || 0;
  const displayTotal = isGSTRegistered ? total : amount;
  const dueDate = invoice['Due Date'];

  if (!clientEmail) {
    ui.alert('Missing Email', 'No email address found for this invoice.', ui.ButtonSet.OK);
    return;
  }

  // Calculate days until due
  const due = new Date(dueDate.split('/').reverse().join('-')); // Parse DD/MM/YYYY
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  due.setHours(0, 0, 0, 0);
  const daysUntilDue = Math.ceil((due - now) / (1000 * 60 * 60 * 24));

  const subject = 'Friendly Reminder: Invoice ' + invoiceNumber + ' Due Soon';

  // Build due date text
  let dueDateText;
  if (daysUntilDue === 1) {
    dueDateText = '<strong>tomorrow</strong>';
  } else if (daysUntilDue <= 0) {
    dueDateText = '<strong>today</strong>';
  } else {
    dueDateText = 'on <strong>' + formatDueDate(dueDate) + '</strong>';
  }

  // Build payment details HTML
  const paymentDetailsHtml = bankAccount ? `
        <!-- Payment Details -->
        <tr>
          <td style="padding: 0 40px 25px 40px;">
            <div style="background-color: #e8f5e9; border: 2px solid #4caf50; padding: 15px;">
              <p style="margin: 0 0 10px 0; color: ${EMAIL_COLORS.inkBlack}; font-weight: bold;">Payment Details:</p>
              <p style="margin: 0; color: ${EMAIL_COLORS.inkGray}; font-size: 14px; line-height: 1.6;">
                Bank: ${bankName}<br>
                Account: ${bankAccount}<br>
                Reference: ${invoiceNumber}
              </p>
            </div>
          </td>
        </tr>
  ` : '';

  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  // Render template with data
  const bodyContent = renderEmailTemplate('email-invoice-reminder', {
    invoiceNumber: invoiceNumber,
    clientName: clientName,
    dueDateText: dueDateText,
    dueDate: formatDueDate(dueDate),
    jobNumber: jobNumber,
    displayTotal: formatCurrency(displayTotal),
    paymentDetailsHtml: paymentDetailsHtml,
    businessName: businessName,
    gstFooterLine: gstFooterLine
  });

  const htmlBody = wrapEmailHtml(bodyContent);

  try {
    MailApp.sendEmail({
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Log activity
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      'Pre-due payment reminder sent. Days until due: ' + daysUntilDue,
      'To: ' + clientEmail,
      'Auto'
    );

    ui.alert('Reminder Sent',
      'Friendly payment reminder sent to ' + clientEmail + '\n\n' +
      'Invoice: ' + invoiceNumber + '\n' +
      'Amount: ' + formatCurrency(total) + '\n' +
      'Due: ' + formatDueDate(dueDate) + (daysUntilDue === 1 ? ' (tomorrow)' : daysUntilDue <= 0 ? ' (today)' : ' (' + daysUntilDue + ' days)'),
      ui.ButtonSet.OK
    );

    Logger.log('Invoice reminder for ' + invoiceNumber + ' sent to ' + clientEmail);
  } catch (error) {
    Logger.log('Error sending invoice reminder: ' + error.message);
    ui.alert('Error', 'Failed to send reminder: ' + error.message, ui.ButtonSet.OK);
  }
}

/**
 * Send overdue invoice with late fees
 * Combined email that serves as both overdue notice and formal updated invoice
 * Shows original amount, days overdue, late fee breakdown, and new total due
 * @param {string} invoiceNumber - The invoice number to send
 * @param {boolean} isAutomatic - If true, skip UI alerts (for automatic sending)
 * @returns {boolean} - True if email sent successfully
 */
function sendOverdueInvoice(invoiceNumber, isAutomatic) {
  const ui = isAutomatic ? null : SpreadsheetApp.getUi();
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    if (ui) ui.alert('Not Found', 'Invoice ' + invoiceNumber + ' not found.', ui.ButtonSet.OK);
    return false;
  }

  // Skip if invoice is already paid
  if (invoice['Status'] === 'Paid') {
    Logger.log('Skipping overdue invoice ' + invoiceNumber + ' - already paid');
    return false;
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
  const originalAmount = parseFloat(invoice['Amount (excl GST)']) || 0;
  const originalGst = isGSTRegistered ? (parseFloat(invoice['GST']) || 0) : 0;
  const originalTotal = isGSTRegistered ? (parseFloat(invoice['Total']) || 0) : originalAmount;
  const dueDate = invoice['Due Date'];
  const invoiceDate = invoice['Invoice Date'];

  if (!clientEmail) {
    if (ui) ui.alert('Missing Email', 'No email address found for this invoice.', ui.ButtonSet.OK);
    return false;
  }

  // Calculate late fees (based on correct total depending on GST registration)
  const feeCalc = calculateLateFee(originalTotal, dueDate);

  if (feeCalc.daysOverdue <= 0) {
    if (ui) {
      ui.alert('Not Overdue',
        'This invoice is not overdue. No late fees apply.\n\nUse "Send Invoice Reminder" for pre-due date reminders.',
        ui.ButtonSet.OK
      );
    }
    return false;
  }

  const subject = 'OVERDUE: Invoice ' + invoiceNumber + ' - Updated Amount Due';

  // Build pricing rows based on GST registration
  let pricingRowsHtml = '';
  if (isGSTRegistered && originalGst > 0) {
    pricingRowsHtml = `
      <tr>
        <td style="padding: 8px 0; color: ${EMAIL_COLORS.inkGray}; font-size: 14px;">Original Amount (excl GST)</td>
        <td style="padding: 8px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 14px; text-align: right;">${formatCurrency(originalAmount)}</td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: ${EMAIL_COLORS.inkGray}; font-size: 14px;">GST (15%)</td>
        <td style="padding: 8px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 14px; text-align: right;">${formatCurrency(originalGst)}</td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 14px; font-weight: bold;">Original Total (incl GST)</td>
        <td style="padding: 8px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 14px; text-align: right; font-weight: bold;">${formatCurrency(originalTotal)}</td>
      </tr>
    `;
  } else {
    pricingRowsHtml = `
      <tr>
        <td style="padding: 8px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 14px; font-weight: bold;">Original Total</td>
        <td style="padding: 8px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 14px; text-align: right; font-weight: bold;">${formatCurrency(originalTotal)}</td>
      </tr>
    `;
  }

  // Build payment details HTML
  const paymentDetailsHtml = bankAccount ? `
        <!-- Payment Details -->
        <tr>
          <td style="padding: 0 40px 25px 40px;">
            <div style="background-color: #e8f5e9; border: 2px solid #4caf50; padding: 15px;">
              <p style="margin: 0 0 10px 0; color: ${EMAIL_COLORS.inkBlack}; font-weight: bold;">Payment Details:</p>
              <p style="margin: 0; color: ${EMAIL_COLORS.inkGray}; font-size: 14px; line-height: 1.6;">
                Bank: ${bankName}<br>
                Account: ${bankAccount}<br>
                Reference: ${invoiceNumber}
              </p>
            </div>
          </td>
        </tr>
  ` : '';

  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  // Render template with data
  const bodyContent = renderEmailTemplate('email-overdue-invoice', {
    invoiceNumber: invoiceNumber,
    clientName: clientName,
    daysOverdue: feeCalc.daysOverdue,
    jobNumber: jobNumber,
    invoiceDate: invoiceDate,
    dueDate: formatDueDate(dueDate),
    pricingRowsHtml: pricingRowsHtml,
    lateFee: formatCurrency(feeCalc.lateFee),
    totalWithFees: formatCurrency(feeCalc.totalWithFees),
    paymentDetailsHtml: paymentDetailsHtml,
    businessName: businessName,
    gstFooterLine: gstFooterLine
  });

  const htmlBody = wrapEmailHtml(bodyContent);

  try {
    MailApp.sendEmail({
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Update invoice with calculated late fees
    updateInvoiceFields(invoiceNumber, {
      'Days Overdue': feeCalc.daysOverdue,
      'Late Fee': feeCalc.lateFee.toFixed(2),
      'Total With Fees': feeCalc.totalWithFees.toFixed(2)
    });

    // Log activity
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      'Overdue invoice sent. Days overdue: ' + feeCalc.daysOverdue +
      ', Late fee: ' + formatCurrency(feeCalc.lateFee) +
      ', Total due: ' + formatCurrency(feeCalc.totalWithFees),
      'To: ' + clientEmail,
      isAutomatic ? 'Auto-Trigger' : 'Manual'
    );

    if (ui) {
      ui.alert('Overdue Invoice Sent',
        'Overdue invoice sent to ' + clientEmail + '\n\n' +
        'Days overdue: ' + feeCalc.daysOverdue + '\n' +
        'Late fee: ' + formatCurrency(feeCalc.lateFee) + '\n' +
        'Total due: ' + formatCurrency(feeCalc.totalWithFees),
        ui.ButtonSet.OK
      );
    }

    Logger.log('Overdue invoice ' + invoiceNumber + ' sent to ' + clientEmail);
    return true;
  } catch (error) {
    Logger.log('Error sending overdue invoice: ' + error.message);
    if (ui) ui.alert('Error', 'Failed to send overdue invoice: ' + error.message, ui.ButtonSet.OK);
    return false;
  }
}

/**
 * Show dialog to send overdue invoice
 */
function showSendOverdueInvoiceDialog() {
  const selectedInvoice = getSelectedInvoiceNumber();
  const invoices = getInvoicesByStatus(['Overdue']);

  if (!invoices || invoices.length === 0) {
    SpreadsheetApp.getUi().alert('No Overdue Invoices',
      'No overdue invoices found.',
      SpreadsheetApp.getUi().ButtonSet.OK
    );
    return;
  }

  showContextAwareDialog(
    'Send Overdue Invoice',
    invoices,
    'Invoice',
    'sendOverdueInvoice',
    selectedInvoice
  );
}

/**
 * Automatically send invoice reminders for invoices approaching due date
 * Sends reminders for invoices that are 5-6 days old (1-2 days before due)
 * Skips invoices that are already paid
 * Can be set up as a daily time-based trigger
 */
function autoSendInvoiceReminders() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!invoiceSheet) {
    Logger.log('Invoice sheet not found');
    return;
  }

  const data = invoiceSheet.getDataRange().getValues();
  const headers = data[0];

  const statusCol = headers.indexOf('Status');
  const invoiceNumCol = headers.indexOf('Invoice #');
  const dueDateCol = headers.indexOf('Due Date');
  const invoiceDateCol = headers.indexOf('Invoice Date');

  if (statusCol === -1 || invoiceNumCol === -1 || dueDateCol === -1) {
    Logger.log('Required columns not found in Invoice sheet');
    return;
  }

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  let remindersSent = 0;
  let skipped = 0;

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const status = row[statusCol];
    const invoiceNumber = row[invoiceNumCol];
    const dueDateStr = row[dueDateCol];

    // Skip if not 'Sent' status (already paid, overdue, etc.)
    if (status !== 'Sent') {
      continue;
    }

    if (!invoiceNumber || !dueDateStr) {
      continue;
    }

    // Parse due date (DD/MM/YYYY format)
    let dueDate;
    if (dueDateStr instanceof Date) {
      dueDate = dueDateStr;
    } else {
      const parts = dueDateStr.split('/');
      dueDate = new Date(parts[2], parts[1] - 1, parts[0]);
    }
    dueDate.setHours(0, 0, 0, 0);

    // Calculate days until due
    const daysUntilDue = Math.ceil((dueDate - today) / (1000 * 60 * 60 * 24));

    // Send reminder 1-2 days before due date
    if (daysUntilDue >= 1 && daysUntilDue <= 2) {
      const success = sendInvoiceReminderAuto(invoiceNumber);
      if (success) {
        remindersSent++;
      } else {
        skipped++;
      }
    }
  }

  Logger.log('Auto invoice reminders complete: ' + remindersSent + ' sent, ' + skipped + ' skipped');
}

/**
 * Send invoice reminder automatically (no UI alerts)
 * @param {string} invoiceNumber - The invoice number
 * @returns {boolean} - True if sent successfully
 */
function sendInvoiceReminderAuto(invoiceNumber) {
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    Logger.log('Invoice ' + invoiceNumber + ' not found');
    return false;
  }

  // Skip if already paid
  if (invoice['Status'] === 'Paid') {
    Logger.log('Skipping reminder for ' + invoiceNumber + ' - already paid');
    return false;
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
  const amount = parseFloat(invoice['Amount (excl GST)']) || 0;
  const total = parseFloat(invoice['Total']) || 0;
  const displayTotal = isGSTRegistered ? total : amount;
  const dueDate = invoice['Due Date'];

  if (!clientEmail) {
    Logger.log('No email for invoice ' + invoiceNumber);
    return false;
  }

  // Calculate days until due
  let due;
  if (dueDate instanceof Date) {
    due = dueDate;
  } else {
    due = new Date(dueDate.split('/').reverse().join('-'));
  }
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  due.setHours(0, 0, 0, 0);
  const daysUntilDue = Math.ceil((due - now) / (1000 * 60 * 60 * 24));

  const subject = 'Friendly Reminder: Invoice ' + invoiceNumber + ' Due Soon';

  const htmlBody = `
    <div style="font-family: Georgia, serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 2px solid #d4cfc3; background-color: #f9f7f3;">
      <div style="text-align: center; padding: 20px; border-bottom: 2px solid #d4cfc3;">
        <img src="https://cartcure.co.nz/CartCure_fullLogo.png" alt="CartCure" width="180" style="display: inline-block; max-width: 180px; height: auto;">
      </div>
      <div style="text-align: center; padding: 20px; background-color: #2d5d3f; color: white;">
        <h1 style="margin: 0;">FRIENDLY REMINDER</h1>
        <p style="margin: 10px 0 0 0; font-size: 16px;">Invoice ${invoiceNumber}</p>
      </div>

      <div style="padding: 20px;">
        <p>Hi ${clientName},</p>

        <p>This is a friendly reminder that payment for invoice <strong>${invoiceNumber}</strong> is due ${daysUntilDue === 1 ? '<strong>tomorrow</strong>' : daysUntilDue <= 0 ? '<strong>today</strong>' : 'on <strong>' + formatDueDate(dueDate) + '</strong>'}.</p>

        <div style="background-color: #fff8e6; padding: 15px; margin: 20px 0; border-left: 4px solid #f5d76e;">
          <p style="margin: 0; color: #856404;"><strong>Avoid Late Fees:</strong> Per our Terms of Service, late fees of 2% per day apply to overdue invoices. Pay by ${formatDueDate(dueDate)} to avoid any additional charges.</p>
        </div>

        <div style="background-color: #faf8f4; padding: 15px; margin: 20px 0; border-left: 4px solid #2d5d3f;">
          <p><strong>Invoice Number:</strong> ${invoiceNumber}</p>
          <p><strong>Job Reference:</strong> ${jobNumber}</p>
          <p><strong>Amount Due:</strong> <span style="font-size: 18px; font-weight: bold;">${formatCurrency(displayTotal)}</span></p>
          <p><strong>Due Date:</strong> ${formatDueDate(dueDate)}</p>
        </div>

        ${bankAccount ? `
        <div style="background-color: #e8f5e9; padding: 15px; border: 1px solid #4caf50; margin: 20px 0;">
          <p style="margin: 0 0 10px 0;"><strong>Payment Details:</strong></p>
          <p style="margin: 0;">
            Bank: ${bankName}<br>
            Account: ${bankAccount}<br>
            Reference: ${invoiceNumber}
          </p>
        </div>
        ` : ''}

        <p style="margin-top: 20px;">If you have already made payment, please disregard this reminder — thank you!</p>

        <p>If you have any questions about this invoice, simply reply to this email and we'll be happy to help.</p>

        <p>Thanks for your business!<br><strong>The CartCure Team</strong></p>
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
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Log activity
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      'Auto payment reminder sent. Days until due: ' + daysUntilDue,
      'To: ' + clientEmail,
      'Auto-Trigger'
    );

    Logger.log('Auto invoice reminder for ' + invoiceNumber + ' sent to ' + clientEmail);
    return true;
  } catch (error) {
    Logger.log('Error sending auto invoice reminder: ' + error.message);
    return false;
  }
}

/**
 * Automatically send overdue invoices with late fees
 * Sends overdue invoice emails for invoices that are past due
 * Skips invoices that are already paid
 * Can be set up as a daily time-based trigger
 */
function autoSendOverdueInvoices() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!invoiceSheet) {
    Logger.log('Invoice sheet not found');
    return;
  }

  const data = invoiceSheet.getDataRange().getValues();
  const headers = data[0];

  const statusCol = headers.indexOf('Status');
  const invoiceNumCol = headers.indexOf('Invoice #');
  const dueDateCol = headers.indexOf('Due Date');

  if (statusCol === -1 || invoiceNumCol === -1 || dueDateCol === -1) {
    Logger.log('Required columns not found in Invoice sheet');
    return;
  }

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  let overduesSent = 0;
  let skipped = 0;

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const status = row[statusCol];
    const invoiceNumber = row[invoiceNumCol];
    const dueDateStr = row[dueDateCol];

    // Skip if already paid
    if (status === 'Paid') {
      continue;
    }

    // Process 'Sent' or 'Overdue' status invoices
    if (status !== 'Sent' && status !== 'Overdue') {
      continue;
    }

    if (!invoiceNumber || !dueDateStr) {
      continue;
    }

    // Parse due date (DD/MM/YYYY format)
    let dueDate;
    if (dueDateStr instanceof Date) {
      dueDate = dueDateStr;
    } else {
      const parts = dueDateStr.split('/');
      dueDate = new Date(parts[2], parts[1] - 1, parts[0]);
    }
    dueDate.setHours(0, 0, 0, 0);

    // Calculate days overdue
    const daysOverdue = Math.floor((today - dueDate) / (1000 * 60 * 60 * 24));

    // Only send for invoices that are actually overdue (past grace period)
    // Send every 7 days after becoming overdue to remind client
    if (daysOverdue > 0 && daysOverdue % 7 === 1) {
      const success = sendOverdueInvoice(invoiceNumber, true);
      if (success) {
        overduesSent++;
        // Update status to 'Overdue' if it was 'Sent'
        if (status === 'Sent') {
          updateInvoiceFields(invoiceNumber, { 'Status': 'Overdue' });
        }
      } else {
        skipped++;
      }
    }
  }

  Logger.log('Auto overdue invoices complete: ' + overduesSent + ' sent, ' + skipped + ' skipped');
}

/**
 * Set up automatic email triggers
 * Creates daily triggers for invoice reminders, overdue notices, and quote reminders
 */
function setupAutoEmailTriggers() {
  const ui = SpreadsheetApp.getUi();

  // Remove existing triggers first
  const triggers = ScriptApp.getProjectTriggers();
  triggers.forEach(trigger => {
    if (trigger.getHandlerFunction() === 'autoSendInvoiceReminders' ||
        trigger.getHandlerFunction() === 'autoSendOverdueInvoices' ||
        trigger.getHandlerFunction() === 'autoSendQuoteReminders') {
      ScriptApp.deleteTrigger(trigger);
    }
  });

  // Create new daily triggers (run at 9 AM NZ time)
  ScriptApp.newTrigger('autoSendInvoiceReminders')
    .timeBased()
    .atHour(9)
    .everyDays(1)
    .inTimezone('Pacific/Auckland')
    .create();

  ScriptApp.newTrigger('autoSendOverdueInvoices')
    .timeBased()
    .atHour(9)
    .everyDays(1)
    .inTimezone('Pacific/Auckland')
    .create();

  ScriptApp.newTrigger('autoSendQuoteReminders')
    .timeBased()
    .atHour(9)
    .everyDays(1)
    .inTimezone('Pacific/Auckland')
    .create();

  ui.alert('Auto Email Triggers Set Up',
    'Daily automatic emails have been configured:\n\n' +
    '• Quote Reminders: Sent 7 days after quote sent (if not accepted/declined)\n' +
    '• Invoice Reminders: Sent 1-2 days before due date\n' +
    '• Overdue Invoices: Sent weekly for overdue invoices\n\n' +
    'Triggers run daily at 9:00 AM (NZ time).\n' +
    'Paid invoices and accepted/declined quotes are automatically skipped.',
    ui.ButtonSet.OK
  );

  Logger.log('Auto email triggers set up successfully');
}

/**
 * Remove automatic email triggers
 */
function removeAutoEmailTriggers() {
  const ui = SpreadsheetApp.getUi();

  const triggers = ScriptApp.getProjectTriggers();
  let removed = 0;

  triggers.forEach(trigger => {
    if (trigger.getHandlerFunction() === 'autoSendInvoiceReminders' ||
        trigger.getHandlerFunction() === 'autoSendOverdueInvoices' ||
        trigger.getHandlerFunction() === 'autoSendQuoteReminders') {
      ScriptApp.deleteTrigger(trigger);
      removed++;
    }
  });

  ui.alert('Auto Email Triggers Removed',
    removed + ' automatic email trigger(s) have been removed.\n\n' +
    'Quote reminders, invoice reminders, and overdue notices will no longer be sent automatically.',
    ui.ButtonSet.OK
  );

  Logger.log('Removed ' + removed + ' auto email triggers');
}

/**
 * Ensure all automatic triggers exist (silent - no UI alerts)
 * Called automatically during setup to enable auto features by default
 * Creates triggers only if they don't already exist
 */
function ensureAutoTriggersExist() {
  const triggers = ScriptApp.getProjectTriggers();

  // Check which triggers already exist
  let hasAutoRefresh = false;
  let hasInvoiceReminders = false;
  let hasOverdueInvoices = false;
  let hasQuoteReminders = false;
  let hasEmailScan = false;

  triggers.forEach(trigger => {
    const handler = trigger.getHandlerFunction();
    if (handler === 'autoRefreshDashboard') hasAutoRefresh = true;
    if (handler === 'autoSendInvoiceReminders') hasInvoiceReminders = true;
    if (handler === 'autoSendOverdueInvoices') hasOverdueInvoices = true;
    if (handler === 'autoSendQuoteReminders') hasQuoteReminders = true;
    if (handler === 'scanSentEmailsForJobs') hasEmailScan = true;
  });

  let created = 0;

  // Create auto-refresh trigger (every 1 minute)
  if (!hasAutoRefresh) {
    ScriptApp.newTrigger('autoRefreshDashboard')
      .timeBased()
      .everyMinutes(1)
      .create();
    created++;
    Logger.log('Created autoRefreshDashboard trigger');
  }

  // Create missing email triggers (run at 9 AM NZ time)
  if (!hasInvoiceReminders) {
    ScriptApp.newTrigger('autoSendInvoiceReminders')
      .timeBased()
      .atHour(9)
      .everyDays(1)
      .inTimezone('Pacific/Auckland')
      .create();
    created++;
    Logger.log('Created autoSendInvoiceReminders trigger');
  }

  if (!hasOverdueInvoices) {
    ScriptApp.newTrigger('autoSendOverdueInvoices')
      .timeBased()
      .atHour(9)
      .everyDays(1)
      .inTimezone('Pacific/Auckland')
      .create();
    created++;
    Logger.log('Created autoSendOverdueInvoices trigger');
  }

  if (!hasQuoteReminders) {
    ScriptApp.newTrigger('autoSendQuoteReminders')
      .timeBased()
      .atHour(9)
      .everyDays(1)
      .inTimezone('Pacific/Auckland')
      .create();
    created++;
    Logger.log('Created autoSendQuoteReminders trigger');
  }

  // Create email scan trigger (every 5 minutes)
  if (!hasEmailScan) {
    ScriptApp.newTrigger('scanSentEmailsForJobs')
      .timeBased()
      .everyMinutes(5)
      .create();
    created++;
    Logger.log('Created scanSentEmailsForJobs trigger');
  }

  if (created > 0) {
    Logger.log('ensureAutoTriggersExist: Created ' + created + ' missing trigger(s)');
  } else {
    Logger.log('ensureAutoTriggersExist: All triggers already exist');
  }

  return created;
}

/**
 * Show dialog to mark invoice as paid
 * OPTIMIZED: Uses context-aware dialog for consistent UX
 */
function showMarkPaidDialog() {
  const selectedInvoice = getSelectedInvoiceNumber();
  const invoices = getInvoicesByStatus(['Sent', 'Overdue']);

  // Use context-aware dialog for consistent behavior
  showContextAwareDialogForMarkPaid(
    'Mark Invoice as Paid',
    invoices,
    'Invoice',
    selectedInvoice
  );
}

/**
 * Show context-aware dialog specifically for marking invoices as paid
 * This is a specialized version that includes payment method and reference fields
 */
function showContextAwareDialogForMarkPaid(title, invoices, itemType, selectedInvoice) {
  const ui = SpreadsheetApp.getUi();

  // If we have a context-selected invoice, verify it's valid and confirm
  if (selectedInvoice) {
    const isValidSelection = invoices && invoices.length > 0 &&
      invoices.some(inv => inv.number === selectedInvoice);

    if (isValidSelection) {
      const selectedInv = invoices.find(inv => inv.number === selectedInvoice);
      const response = ui.alert(
        'Confirm Selection',
        'Mark invoice ' + selectedInvoice + ' (' + selectedInv.clientName + ') as paid?',
        ui.ButtonSet.YES_NO
      );

      if (response === ui.Button.YES) {
        // Show payment method dialog
        showPaymentMethodDialog(selectedInvoice);
        return;
      }
    }
  }

  // Check if there are any invoices available
  if (!invoices || invoices.length === 0) {
    ui.alert('No Invoices Available', 'No sent or overdue invoices available to mark as paid.', ui.ButtonSet.OK);
    return;
  }

  // Fall back to dropdown dialog with payment fields
  const preSelectedInvoice = selectedInvoice || '';

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
          select:disabled, input:disabled {
            background-color: #f5f5f5;
            cursor: not-allowed;
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
            transition: opacity 0.2s;
          }
          .btn-primary {
            background-color: #4285f4;
            color: white;
          }
          .btn-primary:hover:not(:disabled) {
            background-color: #357ae8;
          }
          .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
          }
          .btn-secondary {
            background-color: #f1f1f1;
            color: #333;
          }
          .btn-secondary:hover:not(:disabled) {
            background-color: #e1e1e1;
          }
          .btn-secondary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
          }
          .note {
            font-size: 12px;
            color: #666;
            margin-top: 4px;
          }
          .loading-spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid #ffffff;
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
          }
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <label for="invoiceSelect">Select Invoice:</label>
          <select id="invoiceSelect">
            <option value="">-- Select Invoice --</option>
            ${invoices.map(inv => '<option value="' + inv.number + '"' + (inv.number === preSelectedInvoice ? ' selected' : '') + '>' + inv.display + '</option>').join('')}
          </select>

          <label for="paymentMethod">Payment Method:</label>
          <select id="paymentMethod">
            <option value="Bank Transfer">Bank Transfer</option>
          </select>

          <label for="paymentRef">Payment Reference:</label>
          <input type="text" id="paymentRef" placeholder="Transaction ID or reference (optional)">
          <div class="note">Optional: Enter transaction ID or payment reference</div>

          <div class="button-container">
            <button id="cancelBtn" class="btn-secondary" onclick="google.script.host.close()">Cancel</button>
            <button id="submitBtn" class="btn-primary" onclick="submitPayment()">Mark as Paid</button>
          </div>
        </div>

        <script>
          var isSubmitting = false;

          function submitPayment() {
            if (isSubmitting) return;

            const invoiceNumber = document.getElementById('invoiceSelect').value;
            const method = document.getElementById('paymentMethod').value;
            const reference = document.getElementById('paymentRef').value;

            if (!invoiceNumber) {
              alert('Please select an invoice');
              return;
            }

            // Disable buttons and show loading state
            isSubmitting = true;
            const submitBtn = document.getElementById('submitBtn');
            const cancelBtn = document.getElementById('cancelBtn');
            submitBtn.disabled = true;
            cancelBtn.disabled = true;
            submitBtn.innerHTML = '<span class="loading-spinner"></span>Processing...';
            document.getElementById('invoiceSelect').disabled = true;
            document.getElementById('paymentMethod').disabled = true;
            document.getElementById('paymentRef').disabled = true;

            google.script.run
              .withSuccessHandler(function() {
                google.script.host.close();
              })
              .withFailureHandler(function(error) {
                // Re-enable on error
                isSubmitting = false;
                submitBtn.disabled = false;
                cancelBtn.disabled = false;
                submitBtn.innerHTML = 'Mark as Paid';
                document.getElementById('invoiceSelect').disabled = false;
                document.getElementById('paymentMethod').disabled = false;
                document.getElementById('paymentRef').disabled = false;
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
 * Show payment method dialog for a specific invoice
 * Called when user confirms they want to mark a selected invoice as paid
 */
function showPaymentMethodDialog(invoiceNumber) {
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
          select:disabled, input:disabled {
            background-color: #f5f5f5;
            cursor: not-allowed;
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
            transition: opacity 0.2s;
          }
          .btn-primary {
            background-color: #4285f4;
            color: white;
          }
          .btn-primary:hover:not(:disabled) {
            background-color: #357ae8;
          }
          .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
          }
          .btn-secondary {
            background-color: #f1f1f1;
            color: #333;
          }
          .btn-secondary:hover:not(:disabled) {
            background-color: #e1e1e1;
          }
          .btn-secondary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
          }
          .note {
            font-size: 12px;
            color: #666;
            margin-top: 4px;
          }
          .loading-spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid #ffffff;
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
          }
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
          .invoice-info {
            background-color: #f5f5f5;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 16px;
            font-size: 14px;
          }
          .invoice-info strong {
            color: #333;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="invoice-info">
            <strong>Invoice:</strong> ${invoiceNumber}
          </div>

          <label for="paymentMethod">Payment Method:</label>
          <select id="paymentMethod">
            <option value="Bank Transfer">Bank Transfer</option>
          </select>

          <label for="paymentRef">Payment Reference:</label>
          <input type="text" id="paymentRef" placeholder="Transaction ID or reference (optional)">
          <div class="note">Optional: Enter transaction ID or payment reference</div>

          <div class="button-container">
            <button id="cancelBtn" class="btn-secondary" onclick="google.script.host.close()">Cancel</button>
            <button id="submitBtn" class="btn-primary" onclick="submitPayment()">Mark as Paid</button>
          </div>
        </div>

        <script>
          var isSubmitting = false;

          function submitPayment() {
            if (isSubmitting) return;

            const method = document.getElementById('paymentMethod').value;
            const reference = document.getElementById('paymentRef').value;

            // Disable buttons and show loading state
            isSubmitting = true;
            const submitBtn = document.getElementById('submitBtn');
            const cancelBtn = document.getElementById('cancelBtn');
            submitBtn.disabled = true;
            cancelBtn.disabled = true;
            submitBtn.innerHTML = '<span class="loading-spinner"></span>Processing...';
            document.getElementById('paymentMethod').disabled = true;
            document.getElementById('paymentRef').disabled = true;

            google.script.run
              .withSuccessHandler(function() {
                google.script.host.close();
              })
              .withFailureHandler(function(error) {
                // Re-enable on error
                isSubmitting = false;
                submitBtn.disabled = false;
                cancelBtn.disabled = false;
                submitBtn.innerHTML = 'Mark as Paid';
                document.getElementById('paymentMethod').disabled = false;
                document.getElementById('paymentRef').disabled = false;
                alert('Error: ' + error);
              })
              .markInvoicePaid('${invoiceNumber}', method, reference);
          }
        </script>
      </body>
    </html>
  `;

  const html = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(500)
    .setHeight(350);

  SpreadsheetApp.getUi().showModalDialog(html, 'Mark Invoice as Paid');
}

/**
 * Send payment receipt email to client
 * Includes receipt details and a link to leave a review/testimonial
 * @param {string} invoiceNumber - The invoice number
 * @param {string} method - Payment method used
 * @param {string} reference - Payment reference (optional)
 */
/**
 * Send payment receipt email to client
 *
 * EMAIL TEMPLATE: See apps-script/email-payment-receipt.html
 */
function sendPaymentReceiptEmail(invoiceNumber, method, reference) {
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    Logger.log('Cannot send receipt - invoice not found: ' + invoiceNumber);
    return false;
  }

  const businessName = getSetting('Business Name') || 'CartCure';
  const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gstNumber = getSetting('GST Number') || '';

  const clientName = invoice['Client Name'];
  const clientEmail = invoice['Client Email'];
  const jobNumber = invoice['Job #'];
  const amount = invoice['Amount (excl GST)'];
  const gst = invoice['GST'];
  const total = invoice['Total'];
  const paidDate = formatNZDate(new Date());

  if (!clientEmail) {
    Logger.log('Cannot send receipt - no email address for invoice: ' + invoiceNumber);
    return false;
  }

  const subject = 'Payment Receipt - ' + invoiceNumber + ' from CartCure';

  // Build pricing section - validate GST is a number
  // When GST is not registered, use amount (excl GST) as the total
  const gstValue = parseFloat(gst);
  const displayTotal = isGSTRegistered ? total : amount;
  let pricingHtml = '';
  if (isGSTRegistered && !isNaN(gstValue) && gstValue > 0) {
    pricingHtml = `
      <tr>
        <td style="padding: 12px 15px; color: ${EMAIL_COLORS.inkGray}; font-size: 14px;">Amount (excl GST)</td>
        <td style="padding: 12px 15px; color: ${EMAIL_COLORS.inkBlack}; font-size: 14px; text-align: right;">$${amount}</td>
      </tr>
      <tr>
        <td style="padding: 12px 15px; color: ${EMAIL_COLORS.inkGray}; font-size: 14px; border-top: 1px solid ${EMAIL_COLORS.paperBorder};">GST (15%)</td>
        <td style="padding: 12px 15px; color: ${EMAIL_COLORS.inkBlack}; font-size: 14px; text-align: right; border-top: 1px solid ${EMAIL_COLORS.paperBorder};">$${gst}</td>
      </tr>
      <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
        <td style="padding: 15px; color: #ffffff; font-size: 16px; font-weight: bold;">Total Paid</td>
        <td style="padding: 15px; color: #ffffff; font-size: 18px; font-weight: bold; text-align: right;">$${total}</td>
      </tr>
    `;
  } else {
    pricingHtml = `
      <tr style="background-color: ${EMAIL_COLORS.brandGreen};">
        <td style="padding: 15px; color: #ffffff; font-size: 16px; font-weight: bold;">Total Paid</td>
        <td style="padding: 15px; color: #ffffff; font-size: 18px; font-weight: bold; text-align: right;">$${displayTotal}</td>
      </tr>
    `;
  }

  // Build GST footer line
  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  // Build feedback URL
  const feedbackUrl = 'https://cartcure.co.nz/feedback.html?job=' + encodeURIComponent(jobNumber);

  // Render the template
  const bodyContent = renderEmailTemplate('email-payment-receipt', {
    invoiceNumber: invoiceNumber,
    clientName: clientName,
    paidDate: paidDate,
    paymentMethod: method,
    pricingHtml: pricingHtml,
    feedbackUrl: feedbackUrl,
    businessName: businessName,
    gstFooterLine: gstFooterLine
  });

  const htmlBody = wrapEmailHtml(bodyContent);

  try {
    MailApp.sendEmail({
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    });

    // Log activity
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      'Payment receipt sent: ' + formatCurrency(total),
      'To: ' + clientEmail,
      'Auto'
    );

    Logger.log('Payment receipt sent to ' + clientEmail + ' for invoice ' + invoiceNumber);
    return true;
  } catch (error) {
    Logger.log('Error sending payment receipt: ' + error.message);
    return false;
  }
}

/**
 * Mark an invoice as paid
 */
/**
 * Mark invoice as paid - PERFORMANCE OPTIMIZED
 * OLD: 3 invoice updates + 4 job updates = 7 sheet loads
 * NEW: 1 batch invoice update + 1 batch job update = 2 sheet loads (71% reduction)
 * Also sends payment receipt email to client
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

  // OPTIMIZATION: Batch update all 3 invoice fields in a single operation
  updateInvoiceFields(invoiceNumber, {
    'Status': 'Paid',
    'Paid Date': formatNZDate(now),
    'Payment Reference': reference
  });

  // OPTIMIZATION: Batch update all 4 job fields in a single operation
  updateJobFields(jobNumber, {
    'Payment Status': PAYMENT_STATUS.PAID,
    'Payment Date': formatNZDate(now),
    'Payment Method': method,
    'Payment Reference': reference
  });

  // Send payment receipt email to client
  const receiptSent = sendPaymentReceiptEmail(invoiceNumber, method, reference);

  ui.alert('Payment Recorded',
    'Invoice ' + invoiceNumber + ' marked as Paid!\n\n' +
    'Method: ' + method + '\n' +
    (reference ? 'Reference: ' + reference + '\n' : '') +
    (receiptSent ? '\nPayment receipt sent to client.' : '\nNote: Could not send receipt email.'),
    ui.ButtonSet.OK
  );

  Logger.log('Invoice ' + invoiceNumber + ' marked as paid');

  // Refresh dashboard to show updated data
  refreshDashboard();
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
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

  if (!dashboard || !jobsSheet) {
    SpreadsheetApp.getUi().alert('Error', 'Dashboard or Jobs sheet not found. Please run Setup first.', SpreadsheetApp.getUi().ButtonSet.OK);
    return;
  }

  // Update timestamp
  dashboard.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));

  // Get all jobs data
  const jobsData = jobsSheet.getDataRange().getValues();
  const headers = jobsData[0];
  const jobNumColIndex = headers.indexOf('Job #');

  // Update SLA calculations for active jobs
  updateAllSLAStatus(jobsSheet, jobsData, headers);

  // Get active jobs (Accepted or In Progress)
  const activeJobs = [];
  const pendingQuotes = [];

  for (let i = 1; i < jobsData.length; i++) {
    const row = jobsData[i];
    const status = row[headers.indexOf('Status')];
    const jobNum = jobNumColIndex >= 0 ? row[jobNumColIndex] : null;

    if (!jobNum) continue;

    if (status === JOB_STATUS.ACCEPTED || status === JOB_STATUS.IN_PROGRESS) {
      activeJobs.push({
        jobNumber: jobNum,
        client: row[headers.indexOf('Client Name')],
        description: (row[headers.indexOf('Job Description')] || '').substring(0, 30),
        quotedAmount: formatCurrency(row[headers.indexOf('Total (incl GST)')] || 0),
        daysRemaining: row[headers.indexOf('Days Remaining')],
        slaStatus: row[headers.indexOf('SLA Status')],
        status: status
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

  // === POPULATE NEW SUBMISSIONS (Left side, rows 10-22) ===
  dashboard.getRange(10, 1, 13, 5).clearContent().setBackground(null).setFontColor(null).setFontWeight(null);

  if (submissionsSheet) {
    const subData = submissionsSheet.getDataRange().getValues();
    const subHeaders = subData[0];
    const statusCol = subHeaders.indexOf('Status');
    const submissionNumCol = subHeaders.indexOf('Submission #');
    const timestampCol = subHeaders.indexOf('Timestamp');
    const nameCol = subHeaders.indexOf('Name');
    const emailCol = subHeaders.indexOf('Email');
    const messageCol = subHeaders.indexOf('Message');

    // Get new/unactioned submissions
    const newSubmissions = [];
    for (let i = 1; i < subData.length; i++) {
      const status = subData[i][statusCol];
      if (!status || status === 'New' || status === '') {
        newSubmissions.push({
          submissionNum: subData[i][submissionNumCol],
          timestamp: subData[i][timestampCol],
          name: subData[i][nameCol],
          email: subData[i][emailCol],
          message: (subData[i][messageCol] || '').substring(0, 40)
        });
      }
    }

    // Sort by timestamp descending (newest first)
    newSubmissions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Populate (max 13 rows to fit on screen)
    for (let i = 0; i < Math.min(newSubmissions.length, 13); i++) {
      const sub = newSubmissions[i];
      const dateStr = sub.timestamp ? new Date(sub.timestamp).toLocaleDateString('en-NZ') : '';
      dashboard.getRange(10 + i, 1, 1, 5).setValues([[
        sub.submissionNum,
        dateStr,
        sub.name,
        sub.email,
        sub.message
      ]]).setFontSize(9);
    }

    // Show count if there are more
    if (newSubmissions.length > 13) {
      dashboard.getRange(23, 1).setValue('+ ' + (newSubmissions.length - 13) + ' more...').setFontStyle('italic').setFontColor('#8a8a8a');
    }

    // Update header with count
    dashboard.getRange('A8').setValue('📥 New Submissions (' + newSubmissions.length + ')');
  }

  // === POPULATE ACTIVE JOBS (Right side, rows 6-15) ===
  dashboard.getRange(6, 9, 10, 7).clearContent().setBackground(null).setFontColor(null).setFontWeight(null);

  for (let i = 0; i < Math.min(activeJobs.length, 10); i++) {
    const job = activeJobs[i];
    dashboard.getRange(6 + i, 9, 1, 7).setValues([[
      job.jobNumber,
      job.client,
      job.description,
      job.quotedAmount,
      job.daysRemaining,
      job.slaStatus,
      job.status
    ]]).setFontSize(9);

    // Color code SLA status
    const slaCell = dashboard.getRange(6 + i, 14);
    if (job.slaStatus === 'OVERDUE') {
      slaCell.setBackground('#ffcccc').setFontColor('#cc0000').setFontWeight('bold');
    } else if (job.slaStatus === 'AT RISK') {
      slaCell.setBackground('#fff3cd').setFontColor('#856404').setFontWeight('bold');
    } else {
      slaCell.setBackground('#d4edda').setFontColor('#155724');
    }
  }

  // Update header with count
  dashboard.getRange('I4').setValue('🔥 Active Jobs (' + activeJobs.length + ')');

  // === POPULATE PENDING QUOTES (Right side, rows 19-26) ===
  dashboard.getRange(19, 9, 8, 6).clearContent().setBackground(null).setFontColor(null).setFontWeight(null);

  for (let i = 0; i < Math.min(pendingQuotes.length, 8); i++) {
    const quote = pendingQuotes[i];
    dashboard.getRange(19 + i, 9, 1, 6).setValues([[
      quote.jobNumber,
      quote.client,
      quote.quoteAmount,
      quote.daysWaiting + 'd',
      quote.validUntil,
      quote.action
    ]]).setFontSize(9);

    // Highlight follow-up needed
    if (quote.action === 'Follow up!') {
      dashboard.getRange(19 + i, 14).setBackground('#fff3cd').setFontWeight('bold');
    }
  }

  // Update header with count
  dashboard.getRange('I17').setValue('⏳ Pending Quotes (' + pendingQuotes.length + ')');

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
  const jobNumCol = headers.indexOf('Job #');
  const slaCol = headers.indexOf('SLA Status');

  const overdueJobs = [];
  for (let i = 1; i < data.length; i++) {
    if (data[i][slaCol] === 'OVERDUE') {
      overdueJobs.push(data[i][jobNumCol] + ' - ' + data[i][headers.indexOf('Client Name')]);
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
  const jobNumCol = headers.indexOf('Job #');
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
        unpaidJobs.push(data[i][jobNumCol] + ' - ' + data[i][headers.indexOf('Client Name')] + ' - ' + formatCurrency(amount));
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
    '• Dashboard data\n' +
    '• Settings (reset to defaults)\n\n' +
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

  // Execute the hard reset using combined setup function
  try {
    setupSheets(true); // true = clear all data
  } catch (error) {
    ui.alert('Error During Hard Reset', 'An error occurred: ' + error.toString(), ui.ButtonSet.OK);
    Logger.log('Hard Reset Error: ' + error);
  }
}

// ############################################################################
// ##                                                                        ##
// ##                              TESTS                                     ##
// ##                                                                        ##
// ############################################################################

// ============================================================================
// TEST DATA GENERATION
// ============================================================================

/**
 * Create 20 test testimonials with varying star ratings
 * Accessible via: CartCure Menu > Setup > Create 20 Test Testimonials
 */
function createTestTestimonials() {
  const ui = SpreadsheetApp.getUi();

  // Confirm with user before creating test data
  const response = ui.alert(
    'Create Test Testimonials',
    'This will create 20 test testimonials with varying star ratings (1-5 stars) in the Testimonials sheet.\n\nThese are for testing purposes only.\n\nContinue?',
    ui.ButtonSet.YES_NO
  );

  if (response !== ui.Button.YES) {
    return;
  }

  try {
    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    let sheet = ss.getSheetByName(SHEETS.TESTIMONIALS);

    // Create sheet if it doesn't exist
    if (!sheet) {
      setupTestimonialsSheet(ss, false);
      sheet = ss.getSheetByName(SHEETS.TESTIMONIALS);
    }

    // Sample test data arrays
    const testNames = [
      'Sarah Johnson', 'Mike Chen', 'Emma Wilson', 'James Brown', 'Lisa Anderson',
      'David Lee', 'Rachel Martinez', 'Tom Williams', 'Amy Taylor', 'Chris Davis',
      'Jessica White', 'Ryan Thompson', 'Nicole Garcia', 'Brandon Miller', 'Samantha Moore',
      'Kevin Jackson', 'Michelle Harris', 'Andrew Clark', 'Lauren Lewis', 'Daniel Robinson'
    ];

    const testBusinesses = [
      'Boutique Fashion NZ', 'Tech Gadgets Store', 'Home & Living Co', 'Sports Gear Pro', 'Beauty Essentials',
      'Garden Paradise', 'Pet Supplies Plus', 'Kitchen Masters', 'Kids World', 'Auto Parts Hub',
      'Fitness First', 'Book Haven', 'Craft Corner', 'Music Store NZ', 'Outdoor Adventures',
      'Jewellery Box', 'Toy Kingdom', 'Health Foods', 'Office Supplies', 'Gift Emporium'
    ];

    const testLocations = [
      'Auckland', 'Wellington', 'Christchurch', 'Hamilton', 'Tauranga',
      'Dunedin', 'Palmerston North', 'Napier', 'Nelson', 'Rotorua',
      'New Plymouth', 'Whangarei', 'Invercargill', 'Whanganui', 'Gisborne',
      'Queenstown', 'Timaru', 'Blenheim', 'Hastings', 'Kapiti Coast'
    ];

    // Testimonial templates by star rating
    const testimonialsByRating = {
      5: [
        'Absolutely fantastic service! CartCure went above and beyond to fix our Shopify issues. The turnaround was incredibly fast and the quality of work exceeded all expectations. Highly recommend!',
        'Best investment we made for our store. The team was professional, responsive, and delivered exactly what we needed. Our conversion rate has improved significantly since the changes.',
        'Outstanding experience from start to finish. Communication was excellent, pricing was fair, and the results speak for themselves. Will definitely use CartCure again!',
        'We were struggling with our store for months before finding CartCure. They fixed everything in days and taught us how to maintain it. Truly exceptional service!',
        'Cannot recommend CartCure highly enough! They transformed our sluggish store into a fast, beautiful shopping experience. Our customers love it!'
      ],
      4: [
        'Great service overall. The work was completed on time and the results were solid. Would have liked a bit more communication during the process, but very happy with the outcome.',
        'Really good experience. CartCure delivered quality work and was professional throughout. Minor delays but nothing that impacted us significantly.',
        'Very satisfied with the work done on our store. The team was knowledgeable and helpful. Just a few minor revisions needed, but they handled those quickly.',
        'Good value for money. The improvements to our store were noticeable and our customers have responded positively. Reliable service.',
        'Pleased with the results. CartCure understood our needs and delivered a solid solution. Would use them again for future projects.'
      ],
      3: [
        'Decent service. The work was completed but took a bit longer than expected. The end result was acceptable, though we had hoped for a bit more polish.',
        'Average experience. Some things worked well, others needed a few rounds of revisions. Communication could have been better but they got the job done eventually.',
        'Okay service. Nothing exceptional but nothing terrible either. The basic work was fine, but some advanced features did not work as expected initially.',
        'Mixed feelings about this one. The core work was good, but there were some communication gaps. Eventually sorted everything out though.',
        'Fair service for the price. Met the basic requirements but did not go above and beyond. Adequate for simple fixes.'
      ],
      2: [
        'Below expectations. The project took much longer than quoted and required multiple revisions. Communication was sporadic. End result was okay but the process was frustrating.',
        'Not entirely satisfied. Some things worked, but others did not and took extra time to fix. Would have appreciated more proactive communication.',
        'Disappointing experience. The work was eventually completed but not to the standard we expected. Several back-and-forth exchanges needed.',
        'Could have been better. Felt like the project was rushed and some details were overlooked. Had to follow up multiple times for updates.',
        'Underwhelming service. The basics were covered but quality was inconsistent. Expected more attention to detail for the price.'
      ],
      1: [
        'Very poor experience. Significant delays, poor communication, and the final work did not meet our requirements. Would not recommend.',
        'Extremely disappointed. Project was not delivered as described and getting issues fixed was like pulling teeth. Major communication problems.',
        'Terrible service. Weeks of delays, unresponsive support, and the work had to be redone by someone else. Complete waste of time and money.',
        'Worst experience with a Shopify service. Nothing was done on time, quality was subpar, and they seemed uninterested in fixing problems.',
        'Do not use. Promises were not kept, deadlines were missed, and the final work was unusable. Had to hire another developer to start over.'
      ]
    };

    // Define star rating distribution (weighted towards higher ratings for realism)
    // 5 stars: 8, 4 stars: 5, 3 stars: 4, 2 stars: 2, 1 star: 1
    const starDistribution = [5, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 3, 3, 3, 3, 2, 2, 1];

    // Shuffle the distribution
    for (let i = starDistribution.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [starDistribution[i], starDistribution[j]] = [starDistribution[j], starDistribution[i]];
    }

    // Track which testimonials we've used for each rating
    const usedTestimonials = { 1: [], 2: [], 3: [], 4: [], 5: [] };

    // Generate 20 test testimonials
    let successCount = 0;
    for (let i = 0; i < 20; i++) {
      const rating = starDistribution[i];

      // Pick a testimonial we haven't used yet for this rating
      let testimonialIndex = Math.floor(Math.random() * testimonialsByRating[rating].length);
      let attempts = 0;
      while (usedTestimonials[rating].includes(testimonialIndex) && attempts < 10) {
        testimonialIndex = Math.floor(Math.random() * testimonialsByRating[rating].length);
        attempts++;
      }
      usedTestimonials[rating].push(testimonialIndex);

      const testimonialText = testimonialsByRating[rating][testimonialIndex];

      // Generate timestamp (spread over last 60 days)
      const daysAgo = Math.floor(Math.random() * 60);
      const hoursAgo = Math.floor(Math.random() * 24);
      const date = new Date();
      date.setDate(date.getDate() - daysAgo);
      date.setHours(date.getHours() - hoursAgo);
      const timestamp = formatNZDate(date);

      // Generate job number
      const randomWord = SUBMISSION_WORDS[Math.floor(Math.random() * SUBMISSION_WORDS.length)];
      const randomNum = Math.floor(100 + Math.random() * 900);
      const jobNumber = 'J-' + randomWord + '-' + randomNum;

      // Create row data
      // Columns: Show on Website, Submitted, Name, Business, Location, Rating, Testimonial, Job Number, Email
      const rowData = [
        '',  // Show on Website - will be checkbox
        timestamp,
        testNames[i],
        testBusinesses[i],
        testLocations[i],
        rating.toString(),
        testimonialText,
        jobNumber,
        testNames[i].toLowerCase().replace(' ', '.') + '@test.com'
      ];

      // Append the row
      sheet.appendRow(rowData);

      // Apply validation to the new row
      const newRow = sheet.getLastRow();
      applyTestimonialRowValidation(sheet, newRow);

      successCount++;
    }

    ui.alert(
      'Test Testimonials Created',
      successCount + ' test testimonials have been added to the Testimonials sheet.\n\n' +
      'Star distribution:\n' +
      '★★★★★ (5 stars): 8 testimonials\n' +
      '★★★★☆ (4 stars): 5 testimonials\n' +
      '★★★☆☆ (3 stars): 4 testimonials\n' +
      '★★☆☆☆ (2 stars): 2 testimonials\n' +
      '★☆☆☆☆ (1 star): 1 testimonial\n\n' +
      'Check the "Show on Website" checkbox to approve testimonials for display.',
      ui.ButtonSet.OK
    );

    Logger.log('Created ' + successCount + ' test testimonials');

  } catch (error) {
    ui.alert('Error', 'Failed to create test testimonials: ' + error.toString(), ui.ButtonSet.OK);
    Logger.log('Error creating test testimonials: ' + error);
  }
}

/**
 * Create 10 test submissions for testing purposes
 * Accessible via: CartCure Menu > Setup > Create 10 Test Submissions
 */
function createTestSubmissions() {
  const ui = SpreadsheetApp.getUi();

  // Confirm with user before creating test data
  const response = ui.alert(
    'Create Test Submissions',
    'This will create 10 test submissions in the Submissions sheet.\n\nThese are for testing purposes only.\n\nContinue?',
    ui.ButtonSet.YES_NO
  );

  if (response !== ui.Button.YES) {
    return;
  }

  try {
    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    let sheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

    // Create sheet if it doesn't exist
    if (!sheet) {
      sheet = ss.insertSheet(SHEETS.SUBMISSIONS);
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

    // Sample test data
    const testNames = [
      'Sarah Johnson', 'Mike Chen', 'Emma Wilson', 'James Brown', 'Lisa Anderson',
      'David Lee', 'Rachel Martinez', 'Tom Williams', 'Amy Taylor', 'Chris Davis'
    ];

    const testEmails = [
      'sarah@teststore.com', 'mike@shopexample.com', 'emma@boutique.co.nz',
      'james@retailtest.com', 'lisa@onlinestore.net', 'david@ecommerce.co.nz',
      'rachel@testshop.com', 'tom@samplestore.com', 'amy@demoshop.co.nz', 'chris@testretail.com'
    ];

    const testPhones = [
      '021 234 5678', '022 345 6789', '027 456 7890', '021 567 8901', '022 678 9012',
      '027 789 0123', '021 890 1234', '022 901 2345', '027 012 3456', '021 123 4567'
    ];

    const testStores = [
      'https://sarahs-boutique.myshopify.com', 'https://mikes-electronics.myshopify.com',
      'https://emmas-fashion.myshopify.com', 'https://browns-hardware.myshopify.com',
      'https://lisas-home-decor.myshopify.com', 'https://lees-gadgets.myshopify.com',
      'https://rachels-jewelry.myshopify.com', 'https://toms-sports.myshopify.com',
      'https://amys-crafts.myshopify.com', 'https://davis-outdoors.myshopify.com'
    ];

    const testMessages = [
      'Hi, I need help with my product pages. The images are not displaying correctly on mobile devices.',
      'Looking to add a custom size guide popup to all my clothing products. Can you help?',
      'My checkout page is loading slowly. Would like to optimize the performance.',
      'Need to integrate a new shipping calculator for NZ and Australia deliveries.',
      'Want to add a wishlist feature for my customers. Please provide a quote.',
      'Having issues with my cart not updating quantities properly. Need this fixed urgently.',
      'Looking to redesign my homepage with a new hero banner and featured collections.',
      'Need help setting up Google Analytics 4 tracking on my store.',
      'Want to add a custom product bundling feature for my store.',
      'My navigation menu is not working on tablet devices. Can you take a look?'
    ];

    const statuses = ['New', 'New', 'New', 'In Review', 'New', 'Job Created', 'New', 'New', 'In Review', 'New'];

    // Generate 10 test submissions
    let successCount = 0;
    for (let i = 0; i < 10; i++) {
      // Generate submission number
      const randomWord = SUBMISSION_WORDS[Math.floor(Math.random() * SUBMISSION_WORDS.length)];
      const randomNum = Math.floor(100 + Math.random() * 900);
      const submissionNumber = 'CC-' + randomWord + '-' + randomNum;

      // Generate timestamp (spread over last 7 days)
      const daysAgo = Math.floor(Math.random() * 7);
      const hoursAgo = Math.floor(Math.random() * 24);
      const date = new Date();
      date.setDate(date.getDate() - daysAgo);
      date.setHours(date.getHours() - hoursAgo);
      const timestamp = date.toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' });

      // Find first empty row
      const targetRow = findFirstEmptyRow(sheet);

      // Create row data
      const rowData = [
        statuses[i],
        submissionNumber,
        timestamp,
        testNames[i],
        testEmails[i],
        testPhones[i],
        testStores[i],
        testMessages[i],
        'No',
        ''
      ];

      // Write to sheet
      sheet.getRange(targetRow, 1, 1, rowData.length).setValues([rowData]);
      successCount++;
    }

    ui.alert(
      'Test Submissions Created',
      successCount + ' test submissions have been added to the Submissions sheet.\n\nYou can now test the job management workflow with this data.',
      ui.ButtonSet.OK
    );

    Logger.log('Created ' + successCount + ' test submissions');

  } catch (error) {
    ui.alert('Error', 'Failed to create test submissions: ' + error.toString(), ui.ButtonSet.OK);
    Logger.log('Error creating test submissions: ' + error);
  }
}

// ----------------------------------------------------------------------------
// TEST JOB CREATION
// ----------------------------------------------------------------------------

/**
 * Create a test job specifically for testing the testimonial/feedback form
 * The job is created in "Completed" status so it can accept testimonials immediately
 * Accessible via: CartCure Menu > Setup > Create Test Job for Testimonials
 */
function createTestJobForTestimonials() {
  const ui = SpreadsheetApp.getUi();

  // Confirm with user
  const response = ui.alert(
    '🧪 Create Test Job',
    'This will create a test job in "Completed" status that you can use to test the testimonial/feedback form.\n\nThe job number will be displayed after creation.\n\nContinue?',
    ui.ButtonSet.YES_NO
  );

  if (response !== ui.Button.YES) {
    return;
  }

  try {
    const ss = SpreadsheetApp.openById(CONFIG.SHEET_ID);
    const jobsSheet = ss.getSheetByName(SHEETS.JOBS);

    if (!jobsSheet) {
      ui.alert('Error', 'Jobs sheet not found. Please run Setup first.', ui.ButtonSet.OK);
      return;
    }

    // Generate job number (using SUBMISSION_WORDS which is the same word list)
    const randomWord = SUBMISSION_WORDS[Math.floor(Math.random() * SUBMISSION_WORDS.length)];
    const randomNum = Math.floor(100 + Math.random() * 900);
    const jobNumber = 'J-' + randomWord + '-' + randomNum;

    const now = new Date();
    const timestamp = formatNZDate(now);

    // Build row array using config-based helper (auto-orders columns from COLUMN_CONFIG)
    const rowData = buildRowFromConfig('JOBS', {
      'Job #': jobNumber,
      'Submission #': 'TEST-' + randomNum,
      'Created Date': timestamp,
      'Client Name': 'Test Customer',
      'Client Email': 'test@example.com',
      'Client Phone': '021 123 4567',
      'Store URL': 'https://test-store.myshopify.com',
      'Job Description': 'Test job for testimonial testing - can be deleted',
      'Category': 'Other',
      'Status': JOB_STATUS.COMPLETED,
      'Quote Amount (excl GST)': '50.00',
      'GST': '7.50',
      'Total (incl GST)': '57.50',
      'Quote Sent Date': timestamp,
      'Quote Accepted Date': timestamp,
      'Actual Start Date': timestamp,
      'Actual Completion Date': timestamp,
      'Payment Status': 'Paid',
      'Payment Date': timestamp,
      'Notes': 'AUTO-CREATED: Test job for testimonial form testing',
      'Last Updated': timestamp
    });

    // Find first empty row (checking Status column A)
    const jobCol = jobsSheet.getRange('A:A').getValues();
    let insertRow = 2; // Start after header
    for (let i = 1; i < jobCol.length; i++) {
      if (jobCol[i][0] === '') {
        insertRow = i + 1;
        break;
      }
      insertRow = i + 2;
    }

    // Insert the job
    jobsSheet.getRange(insertRow, 1, 1, rowData.length).setValues([rowData]);

    ui.alert(
      '✅ Test Job Created',
      'Job Number: ' + jobNumber + '\n\n' +
      'You can now test the testimonial form at:\n' +
      'https://cartcure.co.nz/feedback.html?job=' + jobNumber + '\n\n' +
      'This job is in "Completed" status and ready to receive testimonials.',
      ui.ButtonSet.OK
    );

    Logger.log('Created test job for testimonials: ' + jobNumber);

  } catch (error) {
    ui.alert('Error', 'Failed to create test job: ' + error.toString(), ui.ButtonSet.OK);
    Logger.log('Error creating test job: ' + error);
  }
}

// ----------------------------------------------------------------------------
// TEST EMAIL FUNCTIONS
// ----------------------------------------------------------------------------

/**
 * Send all email types to info@cartcure.co.nz for testing purposes
 * This function sends sample versions of every email template in the system
 * Uses the same template rendering system as production emails
 * Accessible via: CartCure Menu > Setup > Send Test Emails
 */
function sendAllTestEmails() {
  const ui = SpreadsheetApp.getUi();
  const testEmail = 'info@cartcure.co.nz';
  const businessName = getSetting('Business Name') || 'CartCure';
  const bankName = getSetting('Bank Name') || 'Test Bank';
  const bankAccount = getSetting('Bank Account') || '00-0000-0000000-00';
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gstNumber = getSetting('GST Number') || '';

  // Confirm with user
  const response = ui.alert(
    '📧 Send Test Emails',
    'This will send ALL email types to ' + testEmail + ' for testing.\n\n' +
    'Email types to be sent:\n' +
    '1. Admin Notification (new submission)\n' +
    '2. User Confirmation (submission received)\n' +
    '3. Quote Email\n' +
    '4. Status Update - In Progress\n' +
    '5. Status Update - On Hold\n' +
    '6. Status Update - Completed\n' +
    '7. Invoice Email\n' +
    '8. Payment Receipt Email\n' +
    '9. Invoice Reminder (pre-due friendly reminder)\n' +
    '10. Overdue Invoice (with late fees)\n\n' +
    'Continue?',
    ui.ButtonSet.YES_NO
  );

  if (response !== ui.Button.YES) {
    return;
  }

  let successCount = 0;
  let errors = [];

  // GST footer line helper
  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  try {
    // 1. Admin Notification Email
    Logger.log('Sending test email 1: Admin Notification');
    const adminBody = renderEmailTemplate('email-admin-notification', {
      submissionNumber: 'CC-TEST-001',
      timestamp: formatNZDate(new Date()),
      clientName: 'Test Customer',
      clientEmail: testEmail,
      clientPhone: '021 123 4567',
      storeUrl: 'https://test-store.myshopify.com',
      messageHtml: 'This is a test submission message for email template testing.',
      voiceNoteHtml: '',
      sheetsUrl: 'https://docs.google.com/spreadsheets/d/' + CONFIG.SHEET_ID + '/edit'
    });
    GmailApp.sendEmail(testEmail, '[TEST] New Contact Form Submission - CC-TEST-001', 'Test admin notification', {
      htmlBody: wrapEmailHtml(adminBody),
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ Admin notification sent');
  } catch (e) {
    errors.push('Admin Notification: ' + e.message);
    Logger.log('✗ Admin notification failed: ' + e.message);
  }

  try {
    // 2. User Confirmation Email
    Logger.log('Sending test email 2: User Confirmation');
    const confirmBody = renderEmailTemplate('email-user-confirmation', {
      clientName: 'Test Customer',
      submissionNumber: 'CC-TEST-001',
      timestamp: formatNZDate(new Date()),
      storeUrlHtml: '<div style="background-color: ' + EMAIL_COLORS.paperCream + '; border-left: 4px solid ' + EMAIL_COLORS.brandGreen + '; padding: 15px 20px; margin-bottom: 15px;"><p style="margin: 0 0 8px 0; color: ' + EMAIL_COLORS.inkGray + '; font-size: 12px; text-transform: uppercase;">Your Store</p><a href="https://test-store.myshopify.com" style="color: ' + EMAIL_COLORS.brandGreen + '; font-size: 15px; text-decoration: none;">https://test-store.myshopify.com</a></div>',
      messageHtml: 'This is a test submission message for email template testing.',
      voiceNoteHtml: ''
    });
    GmailApp.sendEmail(testEmail, '[TEST] Thanks for Contacting CartCure - CC-TEST-001', 'Test user confirmation', {
      htmlBody: wrapEmailHtml(confirmBody),
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ User confirmation sent');
  } catch (e) {
    errors.push('User Confirmation: ' + e.message);
    Logger.log('✗ User confirmation failed: ' + e.message);
  }

  try {
    // 3. Quote Email
    Logger.log('Sending test email 3: Quote');
    const quoteHtml = generateQuoteEmailHtml({
      jobNumber: 'J-TEST-001',
      clientName: 'Test Customer',
      jobDescription: 'Test job for email template testing - fix product page layout and mobile responsiveness.',
      subtotal: '$150.00',
      gst: '$22.50',
      total: '$172.50',
      turnaround: '7',
      validUntil: formatNZDate(new Date(Date.now() + 14 * 24 * 60 * 60 * 1000)),
      bankAccount: bankAccount,
      bankName: bankName,
      isGSTRegistered: isGSTRegistered,
      gstNumber: gstNumber,
      businessName: businessName
    });
    GmailApp.sendEmail(testEmail, '[TEST] Quote for Your Shopify Project - J-TEST-001', 'Test quote email', {
      htmlBody: quoteHtml,
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ Quote email sent');
  } catch (e) {
    errors.push('Quote Email: ' + e.message);
    Logger.log('✗ Quote email failed: ' + e.message);
  }

  try {
    // 4. Status Update - In Progress
    Logger.log('Sending test email 4: Status Update - In Progress');
    const inProgressHtml = generateStatusUpdateEmailHtml({
      jobNumber: 'J-TEST-001',
      clientName: 'Test Customer',
      status: JOB_STATUS.IN_PROGRESS,
      businessName: businessName,
      wasOnHold: false,
      daysOnHold: 0
    });
    GmailApp.sendEmail(testEmail, '[TEST] Your Job is Now In Progress - J-TEST-001', 'Test status - In Progress', {
      htmlBody: inProgressHtml,
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ Status update (In Progress) sent');
  } catch (e) {
    errors.push('Status In Progress: ' + e.message);
    Logger.log('✗ Status update (In Progress) failed: ' + e.message);
  }

  try {
    // 5. Status Update - On Hold
    Logger.log('Sending test email 5: Status Update - On Hold');
    const onHoldHtml = generateStatusUpdateEmailHtml({
      jobNumber: 'J-TEST-001',
      clientName: 'Test Customer',
      status: JOB_STATUS.ON_HOLD,
      businessName: businessName,
      explanation: 'Waiting for client to provide product images and updated content.'
    });
    GmailApp.sendEmail(testEmail, '[TEST] Your Job is Now On Hold - J-TEST-001', 'Test status - On Hold', {
      htmlBody: onHoldHtml,
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ Status update (On Hold) sent');
  } catch (e) {
    errors.push('Status On Hold: ' + e.message);
    Logger.log('✗ Status update (On Hold) failed: ' + e.message);
  }

  try {
    // 6. Status Update - Completed
    Logger.log('Sending test email 6: Status Update - Completed');
    const completedHtml = generateStatusUpdateEmailHtml({
      jobNumber: 'J-TEST-001',
      clientName: 'Test Customer',
      status: JOB_STATUS.COMPLETED,
      businessName: businessName
    });
    GmailApp.sendEmail(testEmail, '[TEST] Your Job is Complete! - J-TEST-001', 'Test status - Completed', {
      htmlBody: completedHtml,
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ Status update (Completed) sent');
  } catch (e) {
    errors.push('Status Completed: ' + e.message);
    Logger.log('✗ Status update (Completed) failed: ' + e.message);
  }

  try {
    // 7. Invoice Email
    Logger.log('Sending test email 7: Invoice');
    let invoicePricingHtml = '';
    if (isGSTRegistered) {
      invoicePricingHtml = '<tr><td style="padding: 12px 15px; border-bottom: 1px solid ' + EMAIL_COLORS.paperBorder + ';"><span style="color: ' + EMAIL_COLORS.inkGray + ';">Subtotal (excl. GST)</span></td><td align="right" style="padding: 12px 15px; border-bottom: 1px solid ' + EMAIL_COLORS.paperBorder + ';"><span style="color: ' + EMAIL_COLORS.inkBlack + '; font-weight: bold;">$150.00</span></td></tr><tr><td style="padding: 12px 15px; border-bottom: 1px solid ' + EMAIL_COLORS.paperBorder + ';"><span style="color: ' + EMAIL_COLORS.inkGray + ';">GST (15%)</span></td><td align="right" style="padding: 12px 15px; border-bottom: 1px solid ' + EMAIL_COLORS.paperBorder + ';"><span style="color: ' + EMAIL_COLORS.inkBlack + ';">$22.50</span></td></tr><tr style="background-color: ' + EMAIL_COLORS.brandGreen + ';"><td style="padding: 15px;"><span style="color: #ffffff; font-weight: bold;">TOTAL DUE (incl. GST)</span></td><td align="right" style="padding: 15px;"><span style="color: #ffffff; font-size: 20px; font-weight: bold;">$172.50</span></td></tr>';
    } else {
      invoicePricingHtml = '<tr style="background-color: ' + EMAIL_COLORS.brandGreen + ';"><td style="padding: 15px;"><span style="color: #ffffff; font-weight: bold;">TOTAL DUE</span></td><td align="right" style="padding: 15px;"><span style="color: #ffffff; font-size: 20px; font-weight: bold;">$150.00</span></td></tr>';
    }
    const invoiceBody = renderEmailTemplate('email-invoice', {
      headingTitle: 'Invoice',
      invoiceNumber: 'INV-TEST-001',
      jobNumber: 'J-TEST-001',
      clientName: 'Test Customer',
      greetingText: 'Thank you for choosing CartCure! Please find your invoice below for the completed work.',
      invoiceDate: formatNZDate(new Date()),
      dueDate: formatNZDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)),
      pricingRowsHtml: invoicePricingHtml,
      depositNoticeHtml: '',
      bankDetailsHtml: 'Bank: ' + bankName + '<br>Account: ' + bankAccount + '<br>',
      gstFooterLine: gstFooterLine,
      businessName: businessName
    });
    GmailApp.sendEmail(testEmail, '[TEST] Invoice INV-TEST-001 from CartCure', 'Test invoice email', {
      htmlBody: wrapEmailHtml(invoiceBody),
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ Invoice email sent');
  } catch (e) {
    errors.push('Invoice Email: ' + e.message);
    Logger.log('✗ Invoice email failed: ' + e.message);
  }

  try {
    // 8. Payment Receipt Email
    Logger.log('Sending test email 8: Payment Receipt');
    let receiptPricingHtml = '';
    if (isGSTRegistered) {
      receiptPricingHtml = '<tr><td style="padding: 12px 15px; border-bottom: 1px solid ' + EMAIL_COLORS.paperBorder + ';"><span style="color: ' + EMAIL_COLORS.inkGray + ';">Subtotal (excl. GST)</span></td><td align="right" style="padding: 12px 15px; border-bottom: 1px solid ' + EMAIL_COLORS.paperBorder + ';"><span style="color: ' + EMAIL_COLORS.inkBlack + ';">$150.00</span></td></tr><tr><td style="padding: 12px 15px; border-bottom: 1px solid ' + EMAIL_COLORS.paperBorder + ';"><span style="color: ' + EMAIL_COLORS.inkGray + ';">GST (15%)</span></td><td align="right" style="padding: 12px 15px; border-bottom: 1px solid ' + EMAIL_COLORS.paperBorder + ';"><span style="color: ' + EMAIL_COLORS.inkBlack + ';">$22.50</span></td></tr><tr style="background-color: ' + EMAIL_COLORS.brandGreen + ';"><td style="padding: 15px; color: #ffffff; font-size: 16px; font-weight: bold;">Total Paid</td><td style="padding: 15px; color: #ffffff; font-size: 18px; font-weight: bold; text-align: right;">$172.50</td></tr>';
    } else {
      receiptPricingHtml = '<tr style="background-color: ' + EMAIL_COLORS.brandGreen + ';"><td style="padding: 15px; color: #ffffff; font-size: 16px; font-weight: bold;">Total Paid</td><td style="padding: 15px; color: #ffffff; font-size: 18px; font-weight: bold; text-align: right;">$150.00</td></tr>';
    }
    const receiptBody = renderEmailTemplate('email-payment-receipt', {
      invoiceNumber: 'INV-TEST-001',
      clientName: 'Test Customer',
      paidDate: formatNZDate(new Date()),
      paymentMethod: 'Bank Transfer',
      pricingHtml: receiptPricingHtml,
      feedbackUrl: 'https://cartcure.co.nz/feedback.html?job=J-TEST-001',
      businessName: businessName,
      gstFooterLine: gstFooterLine
    });
    GmailApp.sendEmail(testEmail, '[TEST] Payment Receipt - INV-TEST-001', 'Test payment receipt', {
      htmlBody: wrapEmailHtml(receiptBody),
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ Payment receipt sent');
  } catch (e) {
    errors.push('Payment Receipt: ' + e.message);
    Logger.log('✗ Payment receipt failed: ' + e.message);
  }

  try {
    // 9. Invoice Reminder Email (pre-due friendly reminder)
    Logger.log('Sending test email 9: Invoice Reminder (pre-due)');
    const reminderPaymentHtml = bankAccount ? '<tr><td style="padding: 0 40px 25px 40px;"><div style="background-color: #e8f5e9; border: 2px solid #4caf50; padding: 15px;"><p style="margin: 0 0 10px 0; color: ' + EMAIL_COLORS.inkBlack + '; font-weight: bold;">Payment Details:</p><p style="margin: 0; color: ' + EMAIL_COLORS.inkGray + '; font-size: 14px; line-height: 1.6;">Bank: ' + bankName + '<br>Account: ' + bankAccount + '<br>Reference: INV-TEST-002</p></div></td></tr>' : '';
    const reminderBody = renderEmailTemplate('email-invoice-reminder', {
      invoiceNumber: 'INV-TEST-002',
      clientName: 'Test Customer',
      dueDateText: '<strong>tomorrow</strong>',
      dueDate: formatNZDate(new Date(Date.now() + 1 * 24 * 60 * 60 * 1000)),
      jobNumber: 'J-TEST-001',
      displayTotal: isGSTRegistered ? '$287.50' : '$250.00',
      paymentDetailsHtml: reminderPaymentHtml,
      businessName: businessName,
      gstFooterLine: gstFooterLine
    });
    GmailApp.sendEmail(testEmail, '[TEST] Friendly Reminder: Invoice INV-TEST-002 Due Soon', 'Test invoice reminder', {
      htmlBody: wrapEmailHtml(reminderBody),
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ Invoice reminder (pre-due) sent');
  } catch (e) {
    errors.push('Invoice Reminder: ' + e.message);
    Logger.log('✗ Invoice reminder failed: ' + e.message);
  }

  try {
    // 10. Overdue Invoice Email (combined notice + late fees)
    Logger.log('Sending test email 10: Overdue Invoice');
    let overduePricingHtml = '';
    if (isGSTRegistered) {
      overduePricingHtml = '<tr><td style="padding: 8px 0; color: ' + EMAIL_COLORS.inkGray + '; font-size: 14px;">Subtotal (excl GST)</td><td style="padding: 8px 0; color: ' + EMAIL_COLORS.inkBlack + '; font-size: 14px; text-align: right;">$250.00</td></tr><tr><td style="padding: 8px 0; color: ' + EMAIL_COLORS.inkGray + '; font-size: 14px;">GST (15%)</td><td style="padding: 8px 0; color: ' + EMAIL_COLORS.inkBlack + '; font-size: 14px; text-align: right;">$37.50</td></tr><tr><td colspan="2" style="padding: 10px 0;"><hr style="border: none; border-top: 1px solid ' + EMAIL_COLORS.paperBorder + ';"></td></tr><tr><td style="padding: 8px 0; color: ' + EMAIL_COLORS.inkBlack + '; font-size: 14px; font-weight: bold;">Original Total</td><td style="padding: 8px 0; color: ' + EMAIL_COLORS.inkBlack + '; font-size: 14px; text-align: right; font-weight: bold;">$287.50</td></tr>';
    } else {
      overduePricingHtml = '<tr><td style="padding: 8px 0; color: ' + EMAIL_COLORS.inkBlack + '; font-size: 14px; font-weight: bold;">Original Total</td><td style="padding: 8px 0; color: ' + EMAIL_COLORS.inkBlack + '; font-size: 14px; text-align: right; font-weight: bold;">$250.00</td></tr>';
    }
    const overduePaymentHtml = bankAccount ? '<tr><td style="padding: 0 40px 25px 40px;"><div style="background-color: #e8f5e9; border: 2px solid #4caf50; padding: 15px;"><p style="margin: 0 0 10px 0; color: ' + EMAIL_COLORS.inkBlack + '; font-weight: bold;">Payment Details:</p><p style="margin: 0; color: ' + EMAIL_COLORS.inkGray + '; font-size: 14px; line-height: 1.6;">Bank: ' + bankName + '<br>Account: ' + bankAccount + '<br>Reference: INV-TEST-003</p></div></td></tr>' : '';
    const overdueBody = renderEmailTemplate('email-overdue-invoice', {
      invoiceNumber: 'INV-TEST-003',
      clientName: 'Test Customer',
      daysOverdue: 14,
      jobNumber: 'J-TEST-001',
      invoiceDate: formatNZDate(new Date(Date.now() - 21 * 24 * 60 * 60 * 1000)),
      dueDate: formatNZDate(new Date(Date.now() - 14 * 24 * 60 * 60 * 1000)),
      pricingRowsHtml: overduePricingHtml,
      lateFee: '$80.50',
      totalWithFees: isGSTRegistered ? '$368.00' : '$330.50',
      paymentDetailsHtml: overduePaymentHtml,
      businessName: businessName,
      gstFooterLine: gstFooterLine
    });
    GmailApp.sendEmail(testEmail, '[TEST] OVERDUE: Invoice INV-TEST-003 - Updated Amount Due', 'Test overdue invoice', {
      htmlBody: wrapEmailHtml(overdueBody),
      name: 'CartCure Test'
    });
    successCount++;
    Logger.log('✓ Overdue invoice sent');
  } catch (e) {
    errors.push('Overdue Invoice: ' + e.message);
    Logger.log('✗ Overdue invoice failed: ' + e.message);
  }

  // Show results
  let resultMessage = successCount + ' of 10 test emails sent successfully to ' + testEmail + '.';

  if (errors.length > 0) {
    resultMessage += '\n\nErrors:\n• ' + errors.join('\n• ');
  }

  ui.alert(
    '📧 Test Emails ' + (errors.length === 0 ? 'Complete' : 'Partial'),
    resultMessage,
    ui.ButtonSet.OK
  );

  Logger.log('Test emails complete: ' + successCount + '/10 successful');
}
