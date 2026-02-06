// ============================================================================
// EMAIL TEMPLATE SYSTEM
// ============================================================================

/**
 * Paperlike theme colors used across all email templates.
 * This single source of truth ensures consistent styling.
 */
var EMAIL_COLORS = {
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
// DEFERRED EMAIL PROCESSING (Performance Optimization)
// ============================================================================
// Emails are queued and sent asynchronously to return responses faster to users.
// The queue uses CacheService for temporary storage and time-based triggers for processing.

/**
 * Queue an email for deferred sending (returns immediately, email sent async)
 * @param {string} type - Email type ('admin' or 'user')
 * @param {Object} data - Email data
 */
function queueDeferredEmail(type, data) {
  try {
    const cache = CacheService.getScriptCache();
    const queueKey = 'EMAIL_QUEUE';

    // Get existing queue or create new one
    const existingQueue = cache.get(queueKey);
    const queue = existingQueue ? JSON.parse(existingQueue) : [];

    // Add new email to queue
    queue.push({
      type: type,
      data: data,
      timestamp: new Date().toISOString()
    });

    // Save queue (cache expires in 6 hours max, but we process quickly)
    cache.put(queueKey, JSON.stringify(queue), 21600);

    // Create a trigger to process the queue if one doesn't exist
    ensureEmailProcessorTrigger();

    return true;
  } catch (error) {
    Logger.log('Error queueing email: ' + error.message);
    // Fall back to synchronous sending if queue fails
    return false;
  }
}

/**
 * Ensure a time-based trigger exists to process the email queue
 */
function ensureEmailProcessorTrigger() {
  const cache = CacheService.getScriptCache();
  const triggerFlag = cache.get('EMAIL_TRIGGER_PENDING');

  // If trigger already pending, don't create another
  if (triggerFlag) {
    return;
  }

  // Set flag to prevent duplicate triggers (expires in 2 minutes)
  cache.put('EMAIL_TRIGGER_PENDING', 'true', 120);

  // Delete any existing email processor triggers to avoid accumulation
  const triggers = ScriptApp.getProjectTriggers();
  triggers.forEach(trigger => {
    if (trigger.getHandlerFunction() === 'processEmailQueue') {
      ScriptApp.deleteTrigger(trigger);
    }
  });

  // Create a trigger to run in ~1 second (minimum is actually ~1 minute for time-based)
  // Using "after" with 1 creates a trigger that runs ASAP
  ScriptApp.newTrigger('processEmailQueue')
    .timeBased()
    .after(1000) // 1 second (actually runs as soon as possible)
    .create();
}

/**
 * Process the email queue (called by time-based trigger)
 */
function processEmailQueue() {
  const cache = CacheService.getScriptCache();

  // Clear the trigger flag
  cache.remove('EMAIL_TRIGGER_PENDING');

  // Get and clear the queue
  const queueKey = 'EMAIL_QUEUE';
  const queueData = cache.get(queueKey);

  if (!queueData) {
    return; // Nothing to process
  }

  // Clear queue immediately to prevent double-processing
  cache.remove(queueKey);

  const queue = JSON.parse(queueData);

  // Process each email
  queue.forEach(item => {
    try {
      if (item.type === 'admin') {
        sendEmailNotificationSync(item.data);
      } else if (item.type === 'user') {
        sendUserConfirmationEmailSync(item.data);
      } else if (item.type === 'testimonial') {
        sendTestimonialNotificationEmail(item.data);
      }
    } catch (error) {
      Logger.log('Error processing queued email: ' + error.message);
    }
  });

  // Clean up the trigger that called us
  const triggers = ScriptApp.getProjectTriggers();
  triggers.forEach(trigger => {
    if (trigger.getHandlerFunction() === 'processEmailQueue') {
      ScriptApp.deleteTrigger(trigger);
    }
  });
}

// ============================================================================
// EMAIL NOTIFICATIONS
// ============================================================================

/**
 * Send email notification to admin (async wrapper - queues for background processing)
 * @param {Object} data - Submission data
 */
function sendEmailNotification(data) {
  // Queue email for async processing (returns immediately)
  if (!queueDeferredEmail('admin', data)) {
    // Fall back to sync if queue fails
    sendEmailNotificationSync(data);
  }
}

/**
 * Send email notification to admin (synchronous)
 * EMAIL TEMPLATE: See apps-script/email-admin-notification.html
 */
function sendEmailNotificationSync(data) {
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
 * Send confirmation email to user (async wrapper - queues for background processing)
 * @param {Object} data - Submission data
 */
function sendUserConfirmationEmail(data) {
  // Queue email for async processing (returns immediately)
  if (!queueDeferredEmail('user', data)) {
    // Fall back to sync if queue fails
    sendUserConfirmationEmailSync(data);
  }
}

/**
 * Send confirmation email to the user who submitted the form (synchronous)
 * EMAIL TEMPLATE: See apps-script/email-user-confirmation.html
 */
function sendUserConfirmationEmailSync(data) {
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

/**
 * Send testimonial notification email to admin
 * @param {Object} data - Testimonial data (sanitized)
 */
function sendTestimonialNotificationEmail(data) {
  if (!CONFIG.ADMIN_EMAIL) return;

  try {
    const subject = 'New Testimonial Submitted - ' + data.name + ' [' + data.jobNumber + ']';
    const body = `A new testimonial has been submitted and is awaiting your approval.

Job Reference: ${data.jobNumber}
Name: ${data.name}
Business: ${data.business || 'Not provided'}
Location: ${data.location || 'Not provided'}
Rating: ${'★'.repeat(data.rating)}${'☆'.repeat(5 - data.rating)}

Testimonial:
"${data.testimonial}"

To approve this testimonial for display on the website:
1. Open the CartCure spreadsheet
2. Go to the Testimonials tab
3. Check the "Show on Website" checkbox

Submitted: ${data.submitted}`;

    MailApp.sendEmail({
      to: CONFIG.ADMIN_EMAIL,
      subject: subject,
      body: body
    });
    Logger.log('Testimonial notification email sent');
  } catch (error) {
    Logger.log('Error sending testimonial notification: ' + error.message);
  }
}
