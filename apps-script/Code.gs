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
var IS_PRODUCTION = true; // Set to true for production (disables debug file creation)

// Get configuration from Script Properties
var CONFIG = {
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

// Validation/Formatting Row Configuration
// Controls how many rows receive dropdowns, conditional formatting, etc.
var VALIDATION_CONFIG = {
  BUFFER_ROWS: 100,        // Extra rows beyond current data to pre-format
  MIN_ROWS: 50,            // Minimum rows to validate/format (for new sheets)
  MAX_ROWS: 10000          // Safety cap to prevent excessive processing time
};

// Validation regexes
var REGEX = {
  EMAIL: /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
  URL: /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$/,
  SUSPICIOUS_PATTERNS: /<script|<iframe|javascript:|data:|vbscript:|onload=|onerror=|onclick=/gi
};

// Blocked URL patterns
var BLOCKED_PATTERNS = [
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
var SUBMISSION_WORDS = [
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

/**
 * Returns a JSON response for web app endpoints (doPost/doGet).
 * @param {Object} data - The response payload
 * @returns {TextOutput} ContentService JSON response
 */
function respondJson(data) {
  return ContentService.createTextOutput(JSON.stringify(data)).setMimeType(ContentService.MimeType.JSON);
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

    // Handle payment confirmation from web form (client clicked "I have paid")
    if (action === 'confirmPaymentReceived') {
      return handlePaymentConfirmation(data);
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
    return respondJson({ success: true, message: 'Form submitted successfully' });

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

    return respondJson(errorResponse);
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
  return respondJson({ status: 'ok', message: 'CartCure Form Handler is running', timestamp: new Date().toISOString() });
}

/**
 * Get all approved testimonials for display on the website
 * Returns testimonials where "Show on Website" checkbox is TRUE
 * @param {boolean} fiveStarOnly - If true, only return 5-star testimonials
 * @param {number|null} limit - Maximum number of testimonials to return (null for all)
 */
function getApprovedTestimonials(fiveStarOnly, limit) {
  try {
    const ss = getSpreadsheet();
    const sheet = ss.getSheetByName(SHEETS.TESTIMONIALS);

    if (!sheet) {
      return respondJson({ success: true, testimonials: [] });
    }

    const lastRow = sheet.getLastRow();
    if (lastRow <= 1) {
      return respondJson({ success: true, testimonials: [] });
    }

    // Get all data (header not needed since we use COLUMN_CONFIG)
    const allData = sheet.getDataRange().getValues();
    const data = allData.slice(1); // Exclude header row

    // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
    const approvedColIndex = getColIndex('TESTIMONIALS', 'Show on Website') - 1;
    const nameColIndex = getColIndex('TESTIMONIALS', 'Name') - 1;
    const businessColIndex = getColIndex('TESTIMONIALS', 'Business') - 1;
    const locationColIndex = getColIndex('TESTIMONIALS', 'Location') - 1;
    const ratingColIndex = getColIndex('TESTIMONIALS', 'Rating') - 1;
    const testimonialColIndex = getColIndex('TESTIMONIALS', 'Testimonial') - 1;

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

    return respondJson({ success: true, testimonials: approvedTestimonials });

  } catch (error) {
    Logger.log('Error fetching testimonials: ' + error.message);
    return respondJson({ success: false, error: 'Failed to load testimonials', testimonials: [] });
  }
}

/**
 * Handle testimonial form submission
 * Requires valid job number and limits to one testimonial per job
 */
function handleTestimonialSubmission(data) {
  // Create debug file FIRST before anything else can fail (only in development mode)
  if (!IS_PRODUCTION) {
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
      return respondJson({ success: false, message: 'Name and testimonial are required' });
    }

    // Job number is required
    if (!jobNumber) {
      return respondJson({ success: false, message: 'Job reference number is required to submit feedback' });
    }

    const ss = getSpreadsheet();

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

      return respondJson({ success: false, message: 'Unable to verify job reference. Please try again later.' });
    }
    debugLog.push('Jobs sheet found: YES');

    const jobsData = jobsSheet.getDataRange().getValues();
    // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
    const jobNumberColIndex = getColIndex('JOBS', 'Job #') - 1;
    debugLog.push('Row count: ' + jobsData.length);
    debugLog.push('Job Number column index (from COLUMN_CONFIG): ' + jobNumberColIndex);

    if (jobNumberColIndex < 0) {
      debugLog.push('ERROR: Job Number column not found in headers');

      // Save debug file
      if (!IS_PRODUCTION) {
        saveTestimonialDebugFile(jobNumber, debugLog);
      }

      return respondJson({ success: false, message: 'Unable to verify job reference. Please try again later.' });
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
    saveDebugLog('TESTIMONIAL_JOB_CHECK', 'Job exists check for "' + jobNumber + '": ' + jobExists + '\nAll jobs: ' + jobsData.slice(1).map(row => row[jobNumberColIndex]).join(', '));

    if (!jobExists) {
      return respondJson({ success: false, message: 'Job reference not found. Please check your job number and try again.' });
    }

    // Check if testimonial already exists for this job
    let testimonialsSheet = ss.getSheetByName(SHEETS.TESTIMONIALS);

    // Debug: Log testimonials sheet check
    saveDebugLog('TESTIMONIAL_SHEET_CHECK', 'Testimonials sheet: ' + (testimonialsSheet ? testimonialsSheet.getName() : 'NULL') + '\nLast row: ' + (testimonialsSheet ? testimonialsSheet.getLastRow() : 'N/A'));

    if (testimonialsSheet && testimonialsSheet.getLastRow() > 1) {
      const testimonialData = testimonialsSheet.getDataRange().getValues();
      // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
      const jobColIndex = getColIndex('TESTIMONIALS', 'Job Number') - 1;
      if (jobColIndex >= 0) {
        const alreadySubmitted = testimonialData.slice(1).some(row => {
          const cellValue = (row[jobColIndex] || '').toString().toUpperCase();
          return cellValue === jobNumber;
        });

        // Debug: Log already submitted check
        saveDebugLog('TESTIMONIAL_DUPLICATE_CHECK', 'Already submitted for ' + jobNumber + ': ' + alreadySubmitted);

        if (alreadySubmitted) {
          return respondJson({ success: false, message: 'Feedback has already been submitted for this job. Thank you!' });
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
      saveDebugLog('TESTIMONIAL_SHEET_CREATE', 'Creating testimonials sheet...');
      setupTestimonialsSheet(ss, false);
      testimonialsSheet = ss.getSheetByName(SHEETS.TESTIMONIALS);
    }

    // Debug: Log what we're about to append
    saveDebugLog('TESTIMONIAL_APPEND', [
      '=== Testimonial Append Debug ===',
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
    ]);

    // Insert testimonial at top (row 2) so newest appear first
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
    insertAtTopSafe(testimonialsSheet, rowData, false); // false = no toast (doPost context)

    // Apply validation (checkbox, rating dropdown, text wrap) to the newly added row (always row 2)
    // This must happen AFTER insert so the checkbox validation is set before the value
    applyTestimonialRowValidation(testimonialsSheet, 2);

    // Debug: Confirm append completed
    saveDebugLog('TESTIMONIAL_APPENDED', 'Row appended successfully at row ' + newRow + '. Last row: ' + testimonialsSheet.getLastRow());

    // Queue notification email to admin (async for faster response)
    if (CONFIG.ADMIN_EMAIL) {
      queueDeferredEmail('testimonial', sanitizedData);
    }

    Logger.log('Testimonial submitted for job ' + sanitizedData.jobNumber + ' by: ' + sanitizedData.name);

    return respondJson({ success: true, message: 'Thank you for your feedback! Your testimonial will be reviewed shortly.' });

  } catch (error) {
    Logger.log('Error saving testimonial: ' + error.message);
    return respondJson({ success: false, message: 'Sorry, there was an error submitting your testimonial. Please try again.' });
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
      return respondJson({ success: false, message: 'Job number is required' });
    }

    if (!fullName) {
      return respondJson({ success: false, message: 'Full name is required' });
    }

    if (!signatureData) {
      return respondJson({ success: false, message: 'Signature is required' });
    }

    if (!termsAccepted) {
      return respondJson({ success: false, message: 'You must accept the Terms of Service to proceed' });
    }

    // Get the job
    const job = getJobByNumber(jobNumber);

    if (!job) {
      return respondJson({ success: false, message: 'Job not found. Please check the job number and try again.' });
    }

    // Check if job is in Quoted or Quote Reminded status
    if (job['Status'] !== JOB_STATUS.QUOTED && job['Status'] !== JOB_STATUS.QUOTE_REMINDED) {
      // Job might already be accepted
      if (job['Status'] === JOB_STATUS.ACCEPTED || job['Status'] === JOB_STATUS.IN_PROGRESS || job['Status'] === JOB_STATUS.COMPLETED) {
        return respondJson({ success: false, message: 'This quote has already been accepted. If you have questions, please contact us.' });
      }
      return respondJson({ success: false, message: 'This job is not in a quotable status. Current status: ' + job['Status'] });
    }

    // Calculate due date
    const now = new Date();
    const turnaround = parseInt(job['Estimated Turnaround']) || JOB_CONFIG.DEFAULT_SLA_DAYS;
    const dueDate = new Date(now);
    dueDate.setDate(dueDate.getDate() + turnaround);

    // CRITICAL: Update job status immediately (this is what the user is waiting for)
    updateJobFields(jobNumber, {
      'Status': JOB_STATUS.ACCEPTED,
      'Quote Accepted Date': formatNZDate(now),
      'Days Since Accepted': 0,
      'Days Remaining': turnaround,
      'SLA Status': 'On Track',
      'Due Date': formatNZDate(dueDate)
    });

    // Queue background tasks (signature save, emails, invoice, client update) for async processing
    const taskData = {
      type: 'quoteAcceptance',
      jobNumber: jobNumber,
      fullName: fullName,
      acceptanceDate: acceptanceDate || formatNZDate(now),
      signatureData: signatureData,
      comments: comments,
      clientName: job['Client Name'],
      clientEmail: job['Client Email'],
      clientPhone: job['Client Phone'] || '',
      storeUrl: job['Store URL'] || '',
      total: parseFloat(job['Total (incl GST)']) || parseFloat(job['Quote Amount (excl GST)']) || 0,
      dueDate: formatNZDate(dueDate),
      turnaround: turnaround,
      jobDescription: job['Job Description'] || '',
      timestamp: now.toISOString()
    };

    // Debug logging for deposit invoice issues
    Logger.log('Quote acceptance taskData - Total (incl GST): ' + job['Total (incl GST)'] +
               ', Quote Amount (excl GST): ' + job['Quote Amount (excl GST)'] +
               ', Calculated total: ' + taskData.total +
               ', requiresDeposit: ' + (taskData.total >= 200));

    queueBackgroundTask(taskData);

    Logger.log('Quote accepted for ' + jobNumber + ' - background tasks queued');

    // Return success immediately - background tasks will process async
    const total = taskData.total;
    const requiresDeposit = total >= 200;
    const depositInfo = requiresDeposit
      ? ' A deposit invoice will be sent to your email shortly.'
      : '';

    return respondJson({ success: true, message: 'Quote accepted successfully!' + depositInfo, jobNumber: jobNumber });

  } catch (error) {
    Logger.log('Error processing quote acceptance: ' + error.message);
    return respondJson({ success: false, message: 'Sorry, there was an error processing your acceptance. Please try again or contact us directly.' });
  }
}

/**
 * Handle payment confirmation from web form
 * Called when client clicks "I have paid" button in invoice reminder email
 */
function handlePaymentConfirmation(data) {
  try {
    const invoiceNumber = (data.invoiceNumber || '').trim().toUpperCase();
    const jobNumber = (data.jobNumber || '').trim().toUpperCase();

    if (!invoiceNumber) {
      return respondJson({ success: false, message: 'Invoice number is required' });
    }

    // Get the invoice
    const invoice = getInvoiceByNumber(invoiceNumber);

    if (!invoice) {
      return respondJson({ success: false, message: 'Invoice not found. Please check the invoice number and try again.' });
    }

    const currentStatus = invoice['Status'];

    // Check current status
    if (currentStatus === 'Paid') {
      return respondJson({ success: true, alreadyPaid: true, message: 'This invoice has already been marked as paid. Thank you!' });
    }

    if (currentStatus === 'Paid?') {
      return respondJson({ success: true, alreadyMarked: true, message: 'We already received your payment notification. We\'ll verify it shortly. Thank you!' });
    }

    if (currentStatus === 'Draft' || currentStatus === 'Cancelled') {
      return respondJson({ success: false, message: 'This invoice cannot be marked as paid. Please contact us if you have questions.' });
    }

    // Update invoice status to "Paid?"
    // NOTE: Must use getSheet() instead of getActiveSpreadsheet() because
    // getActiveSpreadsheet() returns null in web app context (doPost)
    const invoiceSheet = getSheet(SHEETS.INVOICES);
    if (!invoiceSheet) {
      throw new Error('Invoice Log sheet not found');
    }

    // Use _rowIndex from getInvoiceByNumber and column helper for efficiency
    const statusCol = getColIndex('INVOICES', 'Status');
    invoiceSheet.getRange(invoice._rowIndex, statusCol).setValue('Paid?');

    // Log activity
    const clientName = invoice['Client Name'] || 'Unknown';
    const total = invoice['Total'] || 0;
    logJobActivity(
      jobNumber || invoice['Job #'] || '',
      'Payment Claimed',
      'Client clicked "I have paid"',
      'Client ' + clientName + ' clicked "I have paid" for ' + invoiceNumber + ' ($' + total.toFixed(2) + ')',
      '',
      'Auto'
    );

    // Send admin notification email
    sendPaymentClaimedNotification(invoiceNumber, invoice);

    Logger.log('Payment confirmation received for ' + invoiceNumber);

    return respondJson({ success: true, message: 'Thank you for letting us know! We\'ll verify your payment shortly.', invoiceNumber: invoiceNumber });

  } catch (error) {
    Logger.log('Error processing payment confirmation: ' + error.message);
    return respondJson({ success: false, message: 'Sorry, there was an error. Please try again or contact us directly.' });
  }
}

/**
 * Send admin notification when client claims they have paid
 */
function sendPaymentClaimedNotification(invoiceNumber, invoice) {
  try {
    const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;
    const businessName = getSetting('Business Name') || 'CartCure';
    const clientName = invoice['Client Name'] || 'Unknown';
    const clientEmail = invoice['Client Email'] || '';
    const jobNumber = invoice['Job #'] || '';
    const total = parseFloat(invoice['Total']) || 0;
    // Use getSpreadsheet() helper instead of getActiveSpreadsheet() for web app context
    const ss = getSpreadsheet();
    const invoiceSheet = ss.getSheetByName('Invoice Log');
    const sheetUrl = ss.getUrl() + '#gid=' + (invoiceSheet ? invoiceSheet.getSheetId() : 0);

    const bodyContent = renderEmailTemplate('email-client-paid-notification', {
      invoiceNumber: invoiceNumber,
      clientName: clientName,
      clientEmail: clientEmail,
      jobNumber: jobNumber,
      total: total.toFixed(2),
      sheetUrl: sheetUrl,
      businessName: businessName
    });

    MailApp.sendEmail({
      to: adminEmail,
      subject: '💰 Client marked invoice as paid - ' + invoiceNumber,
      htmlBody: bodyContent
    });

    Logger.log('Admin notification sent for payment claim: ' + invoiceNumber);
  } catch (error) {
    Logger.log('Error sending admin notification: ' + error.message);
    // Don't throw - admin notification failure shouldn't break the flow
  }
}

