// ============================================================================
// BACKGROUND TASK QUEUE SYSTEM
// ============================================================================

/**
 * Add a task to the background processing queue
 * Tasks are stored in ScriptProperties and processed by a time trigger
 */
function queueBackgroundTask(taskData) {
  const props = PropertiesService.getScriptProperties();
  const queueKey = 'BACKGROUND_TASK_QUEUE';

  // Get existing queue
  let queue = [];
  try {
    const existingQueue = props.getProperty(queueKey);
    if (existingQueue) {
      queue = JSON.parse(existingQueue);
    }
  } catch (e) {
    queue = [];
  }

  // Add new task
  queue.push(taskData);

  // Save queue (limit to 50 tasks to avoid property size limits)
  if (queue.length > 50) {
    queue = queue.slice(-50);
  }
  props.setProperty(queueKey, JSON.stringify(queue));

  Logger.log('Task queued: ' + taskData.type + ' for ' + (taskData.jobNumber || 'unknown'));
}

/**
 * Process all pending background tasks
 * This should be called by a time-based trigger (every 1 minute)
 * Run setupBackgroundTaskTrigger() once to create the trigger
 */
function processBackgroundTasks() {
  // DEBUG: Log that this function was called at all
  saveDebugLog('BG_TASK_RUN', 'processBackgroundTasks called at ' + new Date().toISOString());

  const props = PropertiesService.getScriptProperties();
  const queueKey = 'BACKGROUND_TASK_QUEUE';

  // Get and clear queue atomically
  const existingQueue = props.getProperty(queueKey);
  if (!existingQueue) return;

  let queue = [];
  try {
    queue = JSON.parse(existingQueue);
  } catch (e) {
    Logger.log('Error parsing task queue: ' + e.message);
    props.deleteProperty(queueKey);
    return;
  }

  if (queue.length === 0) return;

  // Clear queue before processing (to avoid reprocessing on failure)
  props.deleteProperty(queueKey);

  Logger.log('Processing ' + queue.length + ' background tasks');

  const failedTasks = [];
  const MAX_RETRIES = 3;

  // Process each task
  for (const task of queue) {
    try {
      if (task.type === 'quoteAcceptance') {
        const result = processQuoteAcceptanceTask(task);

        // If there were failures, check if we should retry
        if (result.failures && result.failures.length > 0) {
          const retryCount = (task.retryCount || 0) + 1;

          if (retryCount < MAX_RETRIES) {
            // Re-queue with incremented retry count and only failed subtasks
            const retryTask = {
              ...task,
              retryCount: retryCount,
              pendingSubtasks: result.failures
            };
            failedTasks.push(retryTask);
            Logger.log('Task ' + task.jobNumber + ' had failures, queued for retry ' + retryCount + '/' + MAX_RETRIES);
          } else {
            // Max retries reached - notify admin
            notifyTaskFailure(task, result.failures);
          }
        }
      }
      // Add other task types here as needed
    } catch (taskError) {
      Logger.log('Error processing task ' + task.type + ': ' + taskError.message);

      // Re-queue the entire task if it completely failed
      const retryCount = (task.retryCount || 0) + 1;
      if (retryCount < MAX_RETRIES) {
        failedTasks.push({ ...task, retryCount: retryCount, error: taskError.message });
      } else {
        notifyTaskFailure(task, ['Complete task failure: ' + taskError.message]);
      }
    }
  }

  // Re-queue failed tasks for retry
  if (failedTasks.length > 0) {
    for (const task of failedTasks) {
      queueBackgroundTask(task);
    }
    Logger.log('Re-queued ' + failedTasks.length + ' tasks for retry');
  }
}

/**
 * Notify admin when a background task has permanently failed
 */
function notifyTaskFailure(task, failures) {
  const jobNumber = task.jobNumber || 'Unknown';
  Logger.log('TASK PERMANENTLY FAILED for ' + jobNumber + ': ' + failures.join(', '));

  // Try to send admin notification about the failure
  if (CONFIG.ADMIN_EMAIL) {
    try {
      const subject = '⚠️ Background Task Failed - ' + jobNumber;
      const body = `A background task failed after ${task.retryCount || 3} retries.

Job Number: ${jobNumber}
Task Type: ${task.type}
Original Timestamp: ${task.timestamp}

Failed Operations:
${failures.map(f => '- ' + f).join('\n')}

Please check manually:
1. Verify the job status is correct
2. Check if deposit invoice needs to be sent manually
3. Send confirmation emails if needed

The job status was updated successfully - only the follow-up tasks failed.`;

      MailApp.sendEmail({
        to: CONFIG.ADMIN_EMAIL,
        subject: subject,
        body: body
      });
      Logger.log('Failure notification sent to admin for ' + jobNumber);
    } catch (notifyError) {
      Logger.log('Could not send failure notification: ' + notifyError.message);
    }
  }
}

/**
 * Process a quote acceptance background task
 * Handles: signature save, activity log, deposit invoice, admin email, client email
 * Returns: { success: boolean, failures: string[] } for retry handling
 */
function processQuoteAcceptanceTask(task) {
  const jobNumber = task.jobNumber;
  const fullName = task.fullName;
  const acceptanceDate = task.acceptanceDate;
  const signatureData = task.signatureData;
  const comments = task.comments;
  const clientName = task.clientName;
  const clientEmail = task.clientEmail;
  const total = task.total;
  const dueDate = task.dueDate;
  const turnaround = task.turnaround;
  const jobDescription = task.jobDescription || '';

  // Track which subtasks need to run (on retry, only run failed ones)
  const pendingSubtasks = task.pendingSubtasks || ['signature', 'activityLog', 'clientUpdate', 'depositInvoice', 'adminEmail', 'clientEmail'];
  const failures = [];

  // DEBUG: Write to Drive file to diagnose deposit invoice issues
  const debugLog = [];
  debugLog.push('=== QUOTE ACCEPTANCE TASK DEBUG ===');
  debugLog.push('Timestamp: ' + new Date().toISOString());
  debugLog.push('Job Number: ' + jobNumber);
  debugLog.push('Total from task: ' + total + ' (type: ' + typeof total + ')');
  debugLog.push('Requires Deposit (total >= 200): ' + (total >= 200));
  debugLog.push('Pending Subtasks: ' + pendingSubtasks.join(', '));
  debugLog.push('Includes depositInvoice: ' + pendingSubtasks.includes('depositInvoice'));

  Logger.log('Processing quote acceptance task for ' + jobNumber + ' (subtasks: ' + pendingSubtasks.join(', ') + ')');
  Logger.log('Quote acceptance task data - total: ' + total + ', type: ' + typeof total + ', requiresDeposit: ' + (total >= 200));

  const requiresDeposit = total >= 200;

  // 1. Save signature to Google Drive
  let signatureFileUrl = task.signatureFileUrl || ''; // Use cached URL if available from previous attempt
  if (pendingSubtasks.includes('signature') && signatureData && !signatureFileUrl) {
    try {
      const base64Data = signatureData.replace(/^data:image\/png;base64,/, '');
      const signatureBlob = Utilities.newBlob(Utilities.base64Decode(base64Data), 'image/png', 'signature.png');
      const signatureFolder = getOrCreateSignaturesFolder();
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const fileName = 'Signature_' + jobNumber + '_' + timestamp + '.png';
      const driveBlob = signatureBlob.copyBlob();
      driveBlob.setName(fileName);
      const file = signatureFolder.createFile(driveBlob);
      signatureFileUrl = file.getUrl();
      Logger.log('Signature saved: ' + signatureFileUrl);
    } catch (sigError) {
      Logger.log('Error saving signature: ' + sigError.message);
      failures.push('signature');
    }
  }

  // 2. Log acceptance to Activity Log (non-critical, don't retry)
  if (pendingSubtasks.includes('activityLog')) {
    try {
      const acceptanceDetails = [
        'Accepted by: ' + escapeHtml(fullName),
        acceptanceDate ? 'Date: ' + acceptanceDate : '',
        signatureFileUrl ? 'Signature: ' + signatureFileUrl : '',
        comments ? 'Client Comments: ' + escapeHtml(comments.substring(0, 500)) : ''
      ].filter(Boolean).join(', ');
      logJobActivity(jobNumber, 'Quote Accepted', 'Quote accepted via web form', acceptanceDetails, '', 'Auto');
    } catch (logError) {
      Logger.log('Error logging activity: ' + logError.message);
      // Don't add to failures - activity log is non-critical
    }
  }

  // 2b. Add or update client in Clients sheet (non-critical, don't retry)
  if (pendingSubtasks.includes('clientUpdate')) {
    try {
      const clientResult = addOrUpdateClient({
        email: clientEmail,
        name: clientName,
        phone: task.clientPhone || '',
        storeUrl: task.storeUrl || '',
        jobNumber: jobNumber,
        jobTotal: total
      });
      if (clientResult.success) {
        Logger.log('Client ' + (clientResult.isNew ? 'added' : 'updated') + ': ' + clientEmail);
      }
    } catch (clientError) {
      Logger.log('Error updating client: ' + clientError.message);
      // Don't add to failures - client tracking is non-critical
    }
  }

  // 3. Generate and send deposit invoice if required
  debugLog.push('');
  debugLog.push('--- DEPOSIT INVOICE SECTION ---');
  debugLog.push('Condition check: pendingSubtasks.includes("depositInvoice") = ' + pendingSubtasks.includes('depositInvoice'));
  debugLog.push('Condition check: requiresDeposit = ' + requiresDeposit);
  debugLog.push('Will generate deposit invoice: ' + (pendingSubtasks.includes('depositInvoice') && requiresDeposit));

  if (pendingSubtasks.includes('depositInvoice') && requiresDeposit) {
    debugLog.push('ENTERING deposit invoice generation block');
    Logger.log('Deposit invoice required for ' + jobNumber + ' (total: $' + total + ')');
    try {
      const job = getJobByNumber(jobNumber);
      debugLog.push('Job lookup result: ' + (job ? 'FOUND' : 'NOT FOUND'));
      if (job) {
        debugLog.push('Job Total (incl GST): ' + job['Total (incl GST)']);
        debugLog.push('Job Quote Amount (excl GST): ' + job['Quote Amount (excl GST)']);
        Logger.log('Job found for deposit invoice, calling generateAndSendDepositInvoice()');
        debugLog.push('Calling generateAndSendDepositInvoice()...');
        const invoiceResult = generateAndSendDepositInvoice(jobNumber, job);
        debugLog.push('Invoice result: ' + JSON.stringify(invoiceResult));
        if (invoiceResult.success) {
          debugLog.push('SUCCESS: Invoice ' + invoiceResult.invoiceNumber + ' created');
          Logger.log('Deposit invoice generated for ' + jobNumber + ': ' + invoiceResult.invoiceNumber);
        } else {
          debugLog.push('FAILED: ' + invoiceResult.error);
          Logger.log('Failed to generate deposit invoice for ' + jobNumber + ': ' + invoiceResult.error);
          failures.push('depositInvoice');
        }
      } else {
        debugLog.push('ERROR: Job not found in sheet');
        Logger.log('Job not found when generating deposit invoice for ' + jobNumber);
        failures.push('depositInvoice');
      }
    } catch (invoiceError) {
      debugLog.push('EXCEPTION: ' + invoiceError.message);
      debugLog.push('Stack: ' + invoiceError.stack);
      Logger.log('Error with deposit invoice: ' + invoiceError.message);
      failures.push('depositInvoice');
    }
  } else if (pendingSubtasks.includes('depositInvoice') && !requiresDeposit) {
    debugLog.push('SKIPPED: Total $' + total + ' is below $200 threshold');
    Logger.log('Deposit invoice NOT required for ' + jobNumber + ' (total: $' + total + ' is below $200 threshold)');
  } else {
    debugLog.push('SKIPPED: depositInvoice not in pendingSubtasks');
  }

  // Write debug log to Drive
  saveDebugLog('QUOTE_ACCEPT_' + jobNumber, debugLog);

  // 4. Send admin notification
  if (pendingSubtasks.includes('adminEmail') && CONFIG.ADMIN_EMAIL) {
    const adminSubject = 'Quote Accepted - ' + jobNumber + ' - ' + fullName;
    const adminBody = `A quote has been accepted via the web form.

Job Number: ${jobNumber}
Client: ${clientName} (${clientEmail})
Accepted By: ${fullName}
Acceptance Date: ${acceptanceDate}
Terms Accepted: Yes
${signatureFileUrl ? 'Signature: ' + signatureFileUrl : ''}

Quote Amount: ${formatCurrency(total)}
${requiresDeposit ? 'Deposit Required: Yes (50% = ' + formatCurrency(total * 0.5) + ')' : 'Deposit Required: No (under $200)'}

${comments ? 'Client Comments:\n' + comments : ''}

SLA:
- Due Date: ${dueDate}
- Days Remaining: ${turnaround}

---
Use CartCure > Jobs > Start Work when you begin.`;

    try {
      MailApp.sendEmail({
        to: CONFIG.ADMIN_EMAIL,
        subject: adminSubject,
        body: adminBody
      });
      Logger.log('Admin notification sent for ' + jobNumber);
    } catch (emailError) {
      Logger.log('Failed to send admin notification: ' + emailError.message);
      failures.push('adminEmail');
    }
  }

  // 5. Send confirmation email to client
  if (pendingSubtasks.includes('clientEmail') && clientEmail) {
    try {
      const businessName = getSetting('Business Name') || 'CartCure';
      const bankName = getSetting('Bank Name') || '';
      const bankAccount = getSetting('Bank Account') || '';
      const isGSTRegistered = getSetting('GST Registered') === 'Yes';
      const gstNumber = getSetting('GST Number') || '';
      const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

      const depositAmount = formatCurrency(total * 0.5);
      const depositMessage = requiresDeposit
        ? 'You\'ll receive a deposit invoice shortly. Payment of 50% (' + depositAmount + ') is required to begin work.'
        : 'No deposit is required. We\'ll begin work and invoice you upon completion.';

      // Build payment details HTML for deposit payments
      let paymentDetailsHtml = '';
      if (requiresDeposit && (bankName || bankAccount)) {
        paymentDetailsHtml = `
        <tr>
          <td style="padding: 0 40px 25px 40px;">
            <h2 style="margin: 0 0 15px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 16px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 2px solid ${EMAIL_COLORS.paperBorder}; padding-bottom: 10px;">
              Payment Details
            </h2>
            <div style="background-color: ${EMAIL_COLORS.alertBg}; border: 2px solid ${EMAIL_COLORS.alertBorder}; padding: 20px;">
              <p style="margin: 0 0 15px 0; color: ${EMAIL_COLORS.inkBlack}; font-weight: bold; font-size: 16px;">
                Deposit Amount: <span style="color: ${EMAIL_COLORS.brandGreen};">${depositAmount}</span>
              </p>
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td style="padding: 8px 0; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                      <tr>
                        <td width="100" style="color: ${EMAIL_COLORS.inkGray}; font-size: 13px;">Bank:</td>
                        <td style="font-family: 'Courier New', monospace; font-size: 15px; font-weight: bold; color: ${EMAIL_COLORS.inkBlack};">${bankName}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 8px 0; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                      <tr>
                        <td width="100" style="color: ${EMAIL_COLORS.inkGray}; font-size: 13px;">Account:</td>
                        <td style="font-family: 'Courier New', monospace; font-size: 15px; font-weight: bold; color: ${EMAIL_COLORS.inkBlack};">${bankAccount}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 8px 0; border-bottom: 1px solid ${EMAIL_COLORS.paperBorder};">
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                      <tr>
                        <td width="100" style="color: ${EMAIL_COLORS.inkGray}; font-size: 13px;">Payee:</td>
                        <td style="font-family: 'Courier New', monospace; font-size: 15px; font-weight: bold; color: ${EMAIL_COLORS.inkBlack};">${businessName}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 8px 0;">
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                      <tr>
                        <td width="100" style="color: ${EMAIL_COLORS.inkGray}; font-size: 13px;">Reference:</td>
                        <td style="font-family: 'Courier New', monospace; font-size: 15px; font-weight: bold; color: ${EMAIL_COLORS.brandGreen};">${jobNumber}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
              <p style="margin: 15px 0 0 0; color: ${EMAIL_COLORS.inkGray}; font-size: 12px; font-style: italic;">
                Tip: Select and copy each value, or wait for the deposit invoice email with full details.
              </p>
            </div>
          </td>
        </tr>`;
      }

      const bodyContent = renderEmailTemplate('email-quote-accepted', {
        jobNumber: jobNumber,
        clientName: clientName || fullName,
        acceptedBy: fullName,
        acceptanceDate: acceptanceDate,
        quoteAmount: formatCurrency(total),
        depositInfo: depositMessage,
        dueDate: dueDate,
        businessName: businessName,
        gstFooterLine: gstFooterLine,
        paymentDetailsHtml: paymentDetailsHtml,
        jobDescription: jobDescription
      });

      const htmlBody = wrapEmailHtml(bodyContent);

      // Build plain text payment details for deposit payments
      let plainPaymentDetails = '';
      if (requiresDeposit && (bankName || bankAccount)) {
        plainPaymentDetails = `

PAYMENT DETAILS
---------------
Deposit Amount: ${depositAmount}
Bank: ${bankName}
Account: ${bankAccount}
Payee: ${businessName}
Reference: ${jobNumber}`;
      }

      const plainBody = `Hi ${clientName || fullName},

Thank you for accepting the quote for job ${jobNumber}!

ACCEPTANCE DETAILS
------------------
Accepted By: ${fullName}
Date: ${acceptanceDate}
Quote Amount: ${formatCurrency(total)}

WHAT HAPPENS NEXT
-----------------
${depositMessage}

We'll begin work on your project and keep you updated on progress.
Estimated completion: ${dueDate}${plainPaymentDetails}

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
        name: businessName
      });

      Logger.log('Client confirmation email sent to: ' + clientEmail);
    } catch (clientEmailError) {
      Logger.log('Failed to send client confirmation email: ' + clientEmailError.message);
      failures.push('clientEmail');
    }
  }

  if (failures.length > 0) {
    Logger.log('Quote acceptance task for ' + jobNumber + ' completed with failures: ' + failures.join(', '));
  } else {
    Logger.log('Quote acceptance task completed successfully for ' + jobNumber);
  }

  return { success: failures.length === 0, failures: failures, signatureFileUrl: signatureFileUrl };
}

/**
 * Set up the background task processing trigger
 * Run this once from the CartCure menu or script editor
 */
function setupBackgroundTaskTrigger() {
  // Delete any existing triggers for this function
  const triggers = ScriptApp.getProjectTriggers();
  for (const trigger of triggers) {
    if (trigger.getHandlerFunction() === 'processBackgroundTasks') {
      ScriptApp.deleteTrigger(trigger);
    }
  }

  // Create new trigger to run every 1 minute for fast processing
  ScriptApp.newTrigger('processBackgroundTasks')
    .timeBased()
    .everyMinutes(1)
    .create();

  Logger.log('Background task trigger created (runs every 1 minute)');
  SpreadsheetApp.getUi().alert('Background Task Trigger', 'Trigger created successfully. Background tasks will now process every 1 minute.', SpreadsheetApp.getUi().ButtonSet.OK);
}

/**
 * Diagnostic function to check background task system status
 * Run this from CartCure > Settings > Diagnose Background Tasks
 */
function diagnoseBackgroundTasks() {
  const ui = SpreadsheetApp.getUi();
  const props = PropertiesService.getScriptProperties();
  const triggers = ScriptApp.getProjectTriggers();

  let report = [];
  report.push('=== BACKGROUND TASK DIAGNOSTICS ===\n');

  // Check for background task trigger
  let hasBackgroundTrigger = false;
  let triggerInfo = '';
  for (const trigger of triggers) {
    if (trigger.getHandlerFunction() === 'processBackgroundTasks') {
      hasBackgroundTrigger = true;
      triggerInfo = 'Found: runs every ' + (trigger.getEventType() === ScriptApp.EventType.CLOCK ? 'minute (time-based)' : 'unknown');
      break;
    }
  }
  report.push('Background Task Trigger: ' + (hasBackgroundTrigger ? '✅ ' + triggerInfo : '❌ NOT INSTALLED'));

  if (!hasBackgroundTrigger) {
    report.push('  → Run "Setup Background Tasks" from Settings menu to fix');
  }

  // Check queue status
  const queueKey = 'BACKGROUND_TASK_QUEUE';
  const existingQueue = props.getProperty(queueKey);
  let queueCount = 0;
  let queueDetails = '';
  if (existingQueue) {
    try {
      const queue = JSON.parse(existingQueue);
      queueCount = queue.length;
      if (queueCount > 0) {
        queueDetails = queue.map(t => '  - ' + t.type + ' for ' + (t.jobNumber || 'unknown') + ' (queued: ' + t.timestamp + ')').join('\n');
      }
    } catch (e) {
      queueDetails = '  Error parsing queue: ' + e.message;
    }
  }
  report.push('\nPending Tasks in Queue: ' + queueCount);
  if (queueDetails) {
    report.push(queueDetails);
  }

  // Check recent execution
  report.push('\nTo check execution logs:');
  report.push('  1. Open Apps Script editor (Extensions > Apps Script)');
  report.push('  2. Go to Executions in the left sidebar');
  report.push('  3. Look for "processBackgroundTasks" entries');

  ui.alert('Background Task Diagnostics', report.join('\n'), ui.ButtonSet.OK);
  Logger.log(report.join('\n'));
}

/**
 * Manually process pending background tasks (for debugging)
 * Run this if tasks are stuck in the queue
 */
function manuallyProcessBackgroundTasks() {
  const ui = SpreadsheetApp.getUi();
  const props = PropertiesService.getScriptProperties();
  const queueKey = 'BACKGROUND_TASK_QUEUE';
  const existingQueue = props.getProperty(queueKey);

  if (!existingQueue) {
    ui.alert('No Pending Tasks', 'The background task queue is empty.', ui.ButtonSet.OK);
    return;
  }

  let queue = [];
  try {
    queue = JSON.parse(existingQueue);
  } catch (e) {
    ui.alert('Queue Error', 'Failed to parse task queue: ' + e.message, ui.ButtonSet.OK);
    return;
  }

  if (queue.length === 0) {
    ui.alert('No Pending Tasks', 'The background task queue is empty.', ui.ButtonSet.OK);
    return;
  }

  const confirm = ui.alert(
    'Process Tasks',
    'Found ' + queue.length + ' pending task(s). Process them now?',
    ui.ButtonSet.YES_NO
  );

  if (confirm === ui.Button.YES) {
    processBackgroundTasks();
    ui.alert('Done', 'Background tasks have been processed. Check the Activity Log for results.', ui.ButtonSet.OK);
  }
}

/**
 * Get or create the Signatures folder in Google Drive
 * Uses caching to avoid repeated Drive searches
 * @returns {Folder} The Signatures folder
 */
let _signaturesFolderCache = null;
function getOrCreateSignaturesFolder() {
  // Return cached folder if available
  if (_signaturesFolderCache) {
    return _signaturesFolderCache;
  }

  const folderName = 'CartCure Signatures';
  const folders = DriveApp.getFoldersByName(folderName);

  if (folders.hasNext()) {
    _signaturesFolderCache = folders.next();
    return _signaturesFolderCache;
  }

  // Create folder if it doesn't exist
  _signaturesFolderCache = DriveApp.createFolder(folderName);
  return _signaturesFolderCache;
}

/**
 * Run all tests - use this to verify the script is working correctly
 * Tests: Drive permissions, debug file creation, and full form submission
 * Saves results to CartCure Debug Logs folder
 */
function runIntegrationTests() {
  const timestamp = new Date().toISOString();
  const testLog = [];
  testLog.push('========== CARTCURE INTEGRATION TESTS ==========');
  testLog.push('Timestamp: ' + timestamp);
  testLog.push('');

  const results = { drive: false, debug: false, form: false };
  const details = { drive: '', debug: '', form: '' };

  // Test 1: Drive permissions
  testLog.push('--- Test 1: Drive Permissions ---');
  try {
    const folder = getOrCreateDebugFolder();
    const testFile = folder.createFile('_test_' + Date.now() + '.txt', 'test');
    testFile.setTrashed(true);
    results.drive = true;
    details.drive = 'Successfully created and deleted test file';
    testLog.push('PASS: Drive permissions OK');
  } catch (e) {
    details.drive = e.message;
    testLog.push('FAIL: ' + e.message);
  }
  testLog.push('');

  // Test 2: Debug file creation
  testLog.push('--- Test 2: Debug File Creation ---');
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
    details.debug = debugUrl || 'No URL returned';
    testLog.push(debugUrl ? 'PASS: Debug file created' : 'FAIL: No URL returned');
    testLog.push('URL: ' + (debugUrl || 'N/A'));
  } catch (e) {
    details.debug = e.message;
    testLog.push('FAIL: ' + e.message);
  }
  testLog.push('');

  // Test 3: Full form submission
  testLog.push('--- Test 3: Form Submission ---');
  try {
    const formResult = doPost({
      postData: { type: 'application/x-www-form-urlencoded', contents: '' },
      parameter: {
        name: 'Integration Test User',
        email: 'test@example.com',
        phone: '021 123 4567',
        storeUrl: 'https://example.com',
        message: 'Test submission from runIntegrationTests() - ' + new Date().toISOString(),
        hasVoiceNote: 'No',
        voiceNoteData: ''
        // Note: No origin parameter - internal tests bypass origin validation
      }
    });
    const response = JSON.parse(formResult.getContent());
    results.form = response.success;
    details.form = response.success ? 'Submission #: ' + (response.submissionNumber || 'unknown') : response.message;
    testLog.push(response.success ? 'PASS: Form submission OK' : 'FAIL: ' + response.message);
    if (response.submissionNumber) {
      testLog.push('Submission #: ' + response.submissionNumber);
    }
  } catch (e) {
    details.form = e.message;
    testLog.push('FAIL: ' + e.message);
  }
  testLog.push('');

  // Summary
  const passed = (results.drive ? 1 : 0) + (results.debug ? 1 : 0) + (results.form ? 1 : 0);
  testLog.push('========== SUMMARY ==========');
  testLog.push('Drive Permissions: ' + (results.drive ? 'PASS' : 'FAIL'));
  testLog.push('Debug File:        ' + (results.debug ? 'PASS' : 'FAIL'));
  testLog.push('Form Submission:   ' + (results.form ? 'PASS' : 'FAIL'));
  testLog.push('-----------------------------');
  testLog.push('TOTAL: ' + passed + '/3 tests passed');
  testLog.push('=============================');

  // Save results to Drive
  let fileUrl = '';
  try {
    const folder = getOrCreateDebugFolder();
    const fileName = 'INTEGRATION_TEST_RESULTS_' + timestamp.replace(/[:.]/g, '-') + '.txt';
    const file = folder.createFile(fileName, testLog.join('\n'), 'text/plain');
    fileUrl = file.getUrl();
  } catch (e) {
    // If we can't save, that's OK - we'll show results in the alert
  }

  // Show UI alert
  const ui = SpreadsheetApp.getUi();
  let message = passed + ' of 3 integration tests passed.\n\n';
  message += 'Drive Permissions: ' + (results.drive ? '✅ PASS' : '❌ FAIL') + '\n';
  message += 'Debug File Creation: ' + (results.debug ? '✅ PASS' : '❌ FAIL') + '\n';
  message += 'Form Submission: ' + (results.form ? '✅ PASS' : '❌ FAIL') + '\n';

  if (fileUrl) {
    message += '\nResults saved to:\n' + fileUrl;
  }

  ui.alert(
    passed === 3 ? '✅ All Integration Tests Passed' : '⚠️ Some Tests Failed',
    message,
    ui.ButtonSet.OK
  );

  return results;
}

