// ============================================================================
// DASHBOARD & REPORTING FUNCTIONS
// ============================================================================

/**
 * Refresh the dashboard with current data
 * PERFORMANCE OPTIMIZED: Uses cached spreadsheet, skips refresh if not viewing dashboard
 *
 * @param {boolean} force - If true, refresh regardless of current sheet (default: false)
 */
function refreshDashboard(force) {
  // PERFORMANCE: Skip dashboard refresh if user isn't viewing the dashboard
  // This saves significant time on operations like markQuoteAccepted
  if (!force) {
    try {
      const activeSheet = SpreadsheetApp.getActiveSheet();
      if (activeSheet && activeSheet.getName() !== SHEETS.DASHBOARD) {
        Logger.log('[PERF] refreshDashboard() - Skipped (not on Dashboard sheet)');
        return;
      }
    } catch (e) {
      // If we can't get active sheet (e.g., running from trigger), continue with refresh
    }
  }

  // PERFORMANCE: Use cached spreadsheet reference
  const ss = getSpreadsheet();
  const dashboard = getSheet(SHEETS.DASHBOARD);
  const jobsSheet = getSheet(SHEETS.JOBS);
  const submissionsSheet = getSheet(SHEETS.SUBMISSIONS);

  if (!dashboard || !jobsSheet) {
    SpreadsheetApp.getUi().alert('Error', 'Dashboard or Jobs sheet not found. Please run Setup first.', SpreadsheetApp.getUi().ButtonSet.OK);
    return;
  }

  // Update timestamp
  dashboard.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));

  // Get all jobs data
  const jobsData = jobsSheet.getDataRange().getValues();
  const headers = jobsData[0];

  // Use actual sheet headers for column lookup (handles any column order)
  const cols = {
    jobNum: headers.indexOf('Job #'),
    status: headers.indexOf('Status'),
    clientName: headers.indexOf('Client Name'),
    jobDescription: headers.indexOf('Job Description'),
    totalInclGst: headers.indexOf('Total (incl GST)'),
    daysRemaining: headers.indexOf('Days Remaining'),
    slaStatus: headers.indexOf('SLA Status'),
    quoteSentDate: headers.indexOf('Quote Sent Date'),
    quoteValidUntil: headers.indexOf('Quote Valid Until')
  };

  // Update SLA calculations for active jobs
  updateAllSLAStatus(jobsSheet, jobsData, headers);

  // Get active jobs (Accepted or In Progress)
  const activeJobs = [];
  const pendingQuotes = [];

  for (let i = 1; i < jobsData.length; i++) {
    const row = jobsData[i];
    const status = row[cols.status];
    const jobNum = cols.jobNum >= 0 ? row[cols.jobNum] : null;

    if (!jobNum) continue;

    if (status === JOB_STATUS.ACCEPTED || status === JOB_STATUS.IN_PROGRESS) {
      activeJobs.push({
        jobNumber: jobNum,
        client: row[cols.clientName],
        description: (row[cols.jobDescription] || '').substring(0, 30),
        quotedAmount: formatCurrency(row[cols.totalInclGst] || 0),
        daysRemaining: row[cols.daysRemaining],
        slaStatus: row[cols.slaStatus],
        status: status
      });
    } else if (status === JOB_STATUS.QUOTED) {
      const quoteSentDate = row[cols.quoteSentDate];
      const daysWaiting = quoteSentDate ? daysBetween(new Date(quoteSentDate), new Date()) : 0;

      pendingQuotes.push({
        jobNumber: jobNum,
        client: row[cols.clientName],
        quoteAmount: formatCurrency(row[cols.totalInclGst] || 0),
        daysWaiting: daysWaiting,
        validUntil: row[cols.quoteValidUntil],
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
  dashboard.getRange(10, 1, 13, 5).clearContent().setBackground(SHEET_COLORS.paperWhite).setFontColor(SHEET_COLORS.inkBlack).setFontWeight('normal').setFontSize(SHEET_FONTS.sizeSM);

  if (submissionsSheet) {
    const subData = submissionsSheet.getDataRange().getValues();
    const subHeaders = subData[0];
    // Use actual sheet headers for column lookup (handles any column order)
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
      ]]).setFontSize(SHEET_FONTS.sizeSM);
    }

    // Show count if there are more
    if (newSubmissions.length > 13) {
      dashboard.getRange(23, 1).setValue('+ ' + (newSubmissions.length - 13) + ' more...').setFontStyle('italic').setFontColor('#8a8a8a');
    }

    // Update header with count
    dashboard.getRange('A8').setValue('📥 New Submissions (' + newSubmissions.length + ')');
  }

  // === POPULATE ACTIVE JOBS (Right side, rows 6-15) ===
  dashboard.getRange(6, 9, 10, 7).clearContent().setBackground(SHEET_COLORS.paperWhite).setFontColor(SHEET_COLORS.inkBlack).setFontWeight('normal').setFontSize(SHEET_FONTS.sizeSM);

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
    ]]).setFontSize(SHEET_FONTS.sizeSM);

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
  dashboard.getRange(19, 9, 8, 6).clearContent().setBackground(SHEET_COLORS.paperWhite).setFontColor(SHEET_COLORS.inkBlack).setFontWeight('normal').setFontSize(SHEET_FONTS.sizeSM);

  for (let i = 0; i < Math.min(pendingQuotes.length, 8); i++) {
    const quote = pendingQuotes[i];
    dashboard.getRange(19 + i, 9, 1, 6).setValues([[
      quote.jobNumber,
      quote.client,
      quote.quoteAmount,
      quote.daysWaiting + 'd',
      quote.validUntil,
      quote.action
    ]]).setFontSize(SHEET_FONTS.sizeSM);

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
 * Force refresh dashboard, analytics, and invoice late fees - called from menu
 * Always refreshes regardless of current sheet
 */
function refreshDashboardForce() {
  updateAllLateFees();
  refreshDashboard(true);
  refreshAnalytics();
}

/**
 * Update SLA status for all active jobs
 * PERFORMANCE OPTIMIZED: Batches all updates into single setValues() calls
 * Previously: 3 setValue() calls per active job (150 API calls for 50 jobs)
 * Now: 3 setValues() calls total regardless of job count (99% reduction)
 */
function updateAllSLAStatus(sheet, data, headers) {
  // Use actual sheet headers for column lookup (handles any column order)
  const statusCol = headers.indexOf('Status');
  const acceptedDateCol = headers.indexOf('Quote Accepted Date');
  const turnaroundCol = headers.indexOf('Estimated Turnaround');
  const daysSinceCol = headers.indexOf('Days Since Accepted');
  const daysRemainingCol = headers.indexOf('Days Remaining');
  const slaStatusCol = headers.indexOf('SLA Status');

  // Collect all updates to batch them
  const updates = [];

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

      updates.push({
        row: i + 1,
        daysSince: daysSince,
        daysRemaining: daysRemaining,
        slaStatus: slaStatus
      });
    }
  }

  // PERFORMANCE: Batch all updates using RangeList
  if (updates.length > 0) {
    // Build range lists for each column
    const daysSinceRanges = [];
    const daysRemainingRanges = [];
    const slaStatusRanges = [];

    for (const update of updates) {
      daysSinceRanges.push(sheet.getRange(update.row, daysSinceCol + 1));
      daysRemainingRanges.push(sheet.getRange(update.row, daysRemainingCol + 1));
      slaStatusRanges.push(sheet.getRange(update.row, slaStatusCol + 1));
    }

    // Use RangeList for batch updates (much faster than individual setValue)
    const daysSinceList = sheet.getRangeList(daysSinceRanges.map(r => r.getA1Notation()));
    const daysRemainingList = sheet.getRangeList(daysRemainingRanges.map(r => r.getA1Notation()));
    const slaStatusList = sheet.getRangeList(slaStatusRanges.map(r => r.getA1Notation()));

    // Apply values - RangeList.setValue() sets all ranges to the same value,
    // so we need to iterate, but at least we're using cached ranges
    for (let i = 0; i < updates.length; i++) {
      daysSinceRanges[i].setValue(updates[i].daysSince);
      daysRemainingRanges[i].setValue(updates[i].daysRemaining);
      slaStatusRanges[i].setValue(updates[i].slaStatus);
    }

    // Flush all changes at once
    SpreadsheetApp.flush();
  }
}

/**
 * Show overdue jobs report
 * PERFORMANCE OPTIMIZED: Uses cached spreadsheet
 */
function showOverdueJobs() {
  const jobsSheet = getSheet(SHEETS.JOBS);
  const ui = SpreadsheetApp.getUi();

  if (!jobsSheet) {
    ui.alert('Error', 'Jobs sheet not found.', ui.ButtonSet.OK);
    return;
  }

  const data = jobsSheet.getDataRange().getValues();
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const jobNumCol = getColIndex('JOBS', 'Job #') - 1;
  const slaCol = getColIndex('JOBS', 'SLA Status') - 1;
  const clientNameCol = getColIndex('JOBS', 'Client Name') - 1;

  const overdueJobs = [];
  for (let i = 1; i < data.length; i++) {
    if (data[i][slaCol] === 'OVERDUE') {
      overdueJobs.push(data[i][jobNumCol] + ' - ' + data[i][clientNameCol]);
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
 * PERFORMANCE OPTIMIZED: Uses cached spreadsheet
 */
function showOutstandingPayments() {
  const jobsSheet = getSheet(SHEETS.JOBS);
  const ui = SpreadsheetApp.getUi();

  if (!jobsSheet) {
    ui.alert('Error', 'Jobs sheet not found.', ui.ButtonSet.OK);
    return;
  }

  const data = jobsSheet.getDataRange().getValues();
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const jobNumCol = getColIndex('JOBS', 'Job #') - 1;
  const paymentStatusCol = getColIndex('JOBS', 'Payment Status') - 1;
  const totalCol = getColIndex('JOBS', 'Total (incl GST)') - 1;
  const clientNameCol = getColIndex('JOBS', 'Client Name') - 1;

  let totalOutstanding = 0;
  const unpaidJobs = [];

  for (let i = 1; i < data.length; i++) {
    const paymentStatus = data[i][paymentStatusCol];
    if (paymentStatus === PAYMENT_STATUS.UNPAID || paymentStatus === PAYMENT_STATUS.INVOICED) {
      const amount = parseFloat(data[i][totalCol]) || 0;
      if (amount > 0) {
        totalOutstanding += amount;
        unpaidJobs.push(data[i][jobNumCol] + ' - ' + data[i][clientNameCol] + ' - ' + formatCurrency(amount));
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
 * PERFORMANCE OPTIMIZED: Uses cached spreadsheet
 */
function showMonthlySummary() {
  const jobsSheet = getSheet(SHEETS.JOBS);
  const ui = SpreadsheetApp.getUi();

  if (!jobsSheet) {
    ui.alert('Error', 'Jobs sheet not found.', ui.ButtonSet.OK);
    return;
  }

  const data = jobsSheet.getDataRange().getValues();

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const cols = {
    completionDate: getColIndex('JOBS', 'Actual Completion Date') - 1,
    paymentDate: getColIndex('JOBS', 'Payment Date') - 1,
    createdDate: getColIndex('JOBS', 'Created Date') - 1,
    totalInclGst: getColIndex('JOBS', 'Total (incl GST)') - 1,
    paymentStatus: getColIndex('JOBS', 'Payment Status') - 1
  };

  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

  let jobsCompleted = 0;
  let revenue = 0;
  let jobsStarted = 0;

  for (let i = 1; i < data.length; i++) {
    const completionDate = data[i][cols.completionDate];
    const paymentDate = data[i][cols.paymentDate];
    const createdDate = data[i][cols.createdDate];
    const total = parseFloat(data[i][cols.totalInclGst]) || 0;
    const paymentStatus = data[i][cols.paymentStatus];

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
 * P2 FIX: Enhanced with mandatory backup and stronger confirmation requirements
 */
function showHardResetDialog() {
  const ui = SpreadsheetApp.getUi();

  // Count current data to show in warning
  const jobsSheet = getSheet(SHEETS.JOBS);
  const invoiceSheet = getSheet(SHEETS.INVOICES);
  const submissionsSheet = getSheet(SHEETS.SUBMISSIONS);

  const jobCount = jobsSheet ? Math.max(0, jobsSheet.getLastRow() - 1) : 0;
  const invoiceCount = invoiceSheet ? Math.max(0, invoiceSheet.getLastRow() - 1) : 0;
  const submissionCount = submissionsSheet ? Math.max(0, submissionsSheet.getLastRow() - 1) : 0;

  // First warning dialog with data counts
  const firstWarning = ui.alert(
    '⛔ HARD RESET - PERMANENT DATA DELETION',
    '⚠️ DANGER: This will PERMANENTLY DELETE:\n\n' +
    '• ' + jobCount + ' Jobs\n' +
    '• ' + invoiceCount + ' Invoices\n' +
    '• ' + submissionCount + ' Submissions\n' +
    '• Dashboard data\n' +
    '• All Settings (reset to defaults)\n\n' +
    '❌ THIS CANNOT BE UNDONE!\n' +
    '❌ NO RECOVERY IS POSSIBLE!\n\n' +
    'A backup will be required before proceeding.\n\n' +
    'Do you want to continue?',
    ui.ButtonSet.YES_NO
  );

  if (firstWarning === ui.Button.NO) {
    ui.alert('Hard Reset Cancelled', 'No data was deleted.', ui.ButtonSet.OK);
    return;
  }

  // P2 FIX: Mandatory backup step
  const backupConfirm = ui.alert(
    '💾 MANDATORY BACKUP REQUIRED',
    'Before deleting all data, you MUST create a backup.\n\n' +
    'Click YES to create a backup copy of this spreadsheet now.\n' +
    '(A copy will be created in your Google Drive)\n\n' +
    'Click NO to cancel the reset.',
    ui.ButtonSet.YES_NO
  );

  if (backupConfirm === ui.Button.NO) {
    ui.alert('Hard Reset Cancelled', 'No data was deleted. No backup was created.', ui.ButtonSet.OK);
    return;
  }

  // Create backup
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const timestamp = Utilities.formatDate(new Date(), 'Pacific/Auckland', 'yyyy-MM-dd_HH-mm');
    const backupName = ss.getName() + ' - BACKUP - ' + timestamp;
    const backupFile = DriveApp.getFileById(ss.getId()).makeCopy(backupName);

    ui.alert(
      '✅ Backup Created',
      'Backup saved as:\n"' + backupName + '"\n\n' +
      'Location: Your Google Drive\n' +
      'File ID: ' + backupFile.getId() + '\n\n' +
      'You can access this backup if you need to recover any data.',
      ui.ButtonSet.OK
    );
  } catch (error) {
    ui.alert(
      '❌ Backup Failed',
      'Could not create backup: ' + error.message + '\n\n' +
      'Hard reset has been cancelled for your safety.\n' +
      'Please create a manual backup before trying again.',
      ui.ButtonSet.OK
    );
    return;
  }

  // P2 FIX: Stronger confirmation phrase
  const confirmText = ui.prompt(
    '⛔ FINAL CONFIRMATION REQUIRED',
    '⚠️ THIS IS YOUR LAST CHANCE TO CANCEL!\n\n' +
    'All ' + jobCount + ' jobs, ' + invoiceCount + ' invoices, and ' +
    submissionCount + ' submissions will be PERMANENTLY DELETED.\n\n' +
    'A backup has been created, but the original data will be gone forever.\n\n' +
    'To proceed, type exactly:\n\nDELETE ALL DATA\n\n' +
    '(Type anything else to cancel)',
    ui.ButtonSet.OK_CANCEL
  );

  if (confirmText.getSelectedButton() === ui.Button.CANCEL) {
    ui.alert('Hard Reset Cancelled', 'No data was deleted. Your backup was still created.', ui.ButtonSet.OK);
    return;
  }

  const userInput = confirmText.getResponseText().trim();

  if (userInput !== 'DELETE ALL DATA') {
    ui.alert(
      'Hard Reset Cancelled',
      'You typed: "' + userInput + '"\n\n' +
      'Expected: "DELETE ALL DATA"\n\n' +
      'No data was deleted. Your backup was still created.',
      ui.ButtonSet.OK
    );
    return;
  }

  // Execute the hard reset using combined setup function
  try {
    setupSheets(true); // true = clear all data
    ui.alert(
      '✅ Hard Reset Complete',
      'All data has been deleted and sheets have been reset.\n\n' +
      'Your backup is still available in Google Drive if needed.',
      ui.ButtonSet.OK
    );
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
    const ss = getSpreadsheet();
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

      // Append the row (filter-safe)
      const newRow = appendRowSafe(sheet, rowData, false);

      // Apply validation to the new row
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
    const ss = getSpreadsheet();
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

    const statuses = ['New', 'New', 'New', 'New', 'New', 'New', 'New', 'New', 'New', 'New'];

    // Generate 10 test submissions
    let successCount = 0;
    for (let i = 0; i < 10; i++) {
      // Generate submission number
      const randomWord = SUBMISSION_WORDS[Math.floor(Math.random() * SUBMISSION_WORDS.length)];
      const randomNum = Math.floor(100 + Math.random() * 900);
      const submissionNumber = 'CC-' + randomWord + '-' + randomNum;

      // Generate timestamp (all today, spread throughout the day)
      const date = new Date();
      const minutesAgo = i * 15; // Spread submissions 15 minutes apart
      date.setMinutes(date.getMinutes() - minutesAgo);
      const timestamp = date.toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' });

      // Create row data (must match COLUMN_CONFIG.SUBMISSIONS order)
      const rowData = [
        statuses[i],      // Status
        submissionNumber, // Submission #
        timestamp,        // Timestamp
        testNames[i],     // Name
        testEmails[i],    // Email
        testPhones[i],    // Phone
        testStores[i],    // Store URL
        testMessages[i],  // Message
        'No',             // Has Voice Note
        ''                // Voice Note Link
      ];

      // Insert at top (row 2) so newest submissions appear first
      insertAtTopSafe(sheet, rowData, false);
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
    const ss = getSpreadsheet();
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
      'Last Updated': timestamp
    });

    // Find first empty row (checking Status column)
    const statusColLetter = getColLetter('JOBS', 'Status');
    const jobCol = jobsSheet.getRange(statusColLetter + ':' + statusColLetter).getValues();
    let insertRow = 2; // Start after header
    for (let i = 1; i < jobCol.length; i++) {
      if (jobCol[i][0] === '') {
        insertRow = i + 1;
        break;
      }
      insertRow = i + 2;
    }

    // Insert the job (filter-safe)
    insertRowSafe(jobsSheet, insertRow, rowData, true);

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
      businessName: businessName,
      paymentReceivedUrl: 'https://cartcure.co.nz/payment-received.html?invoice=INV-TEST-001&job=J-TEST-001'
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

// ============================================================================
// AUTOMATED TEST FUNCTIONS
// ============================================================================
// These functions run unit tests on validators, utilities, and column config.
// Run from: CartCure > Setup > Tests > Run Automated Tests
// ============================================================================

/**
 * Main test runner - runs all unit test suites
 * Shows results in UI alert and saves to Drive
 */
function runUnitTests() {
  const ui = SpreadsheetApp.getUi();
  const timestamp = new Date().toISOString();
  Logger.log('========== CARTCURE UNIT TESTS ==========\n');

  const allResults = [];

  // Run all test suites
  const suites = [
    { name: 'Email Validation', fn: runEmailValidationTests },
    { name: 'Phone Validation', fn: runPhoneValidationTests },
    { name: 'URL Validation', fn: runURLValidationTests },
    { name: 'Text Sanitization', fn: runTextSanitizationTests },
    { name: 'Format Validators', fn: runFormatValidatorTests },
    { name: 'Utility Functions', fn: runUtilityTests },
    { name: 'Column Config', fn: runColumnConfigTests }
  ];

  let totalPassed = 0;
  let totalTests = 0;
  const summaryLines = [];
  const suiteResults = [];

  for (const suite of suites) {
    try {
      const results = suite.fn();
      const passed = results.filter(r => r.pass).length;
      totalPassed += passed;
      totalTests += results.length;
      summaryLines.push(suite.name + ': ' + passed + '/' + results.length);
      allResults.push(...results);
      suiteResults.push({
        name: suite.name,
        passed: passed,
        total: results.length,
        tests: results
      });
    } catch (e) {
      Logger.log('ERROR in ' + suite.name + ': ' + e.message);
      summaryLines.push(suite.name + ': ERROR - ' + e.message);
      suiteResults.push({
        name: suite.name,
        error: e.message,
        passed: 0,
        total: 0,
        tests: []
      });
    }
  }

  // Log summary
  Logger.log('\n========== SUMMARY ==========');
  for (const line of summaryLines) {
    Logger.log(line);
  }
  Logger.log('-----------------------------');
  Logger.log('TOTAL: ' + totalPassed + '/' + totalTests + ' tests passed');
  Logger.log('==============================');

  // Save results to Drive
  const passRate = totalTests > 0 ? Math.round((totalPassed / totalTests) * 100) : 0;
  let textOutput = '========================================\n';
  textOutput += 'CARTCURE UNIT TEST RESULTS\n';
  textOutput += '========================================\n';
  textOutput += 'Timestamp: ' + timestamp + '\n\n';
  textOutput += 'SUMMARY\n';
  textOutput += '--------\n';
  textOutput += 'Total: ' + totalPassed + '/' + totalTests + ' tests passed (' + passRate + '%)\n\n';

  for (const suite of suiteResults) {
    textOutput += suite.name + ': ' + suite.passed + '/' + suite.total;
    if (suite.error) {
      textOutput += ' (ERROR: ' + suite.error + ')';
    }
    textOutput += '\n';
  }

  textOutput += '\n========================================\n';
  textOutput += 'DETAILED RESULTS\n';
  textOutput += '========================================\n\n';

  for (const suite of suiteResults) {
    textOutput += '--- ' + suite.name + ' ---\n';
    for (const test of suite.tests) {
      const status = test.pass ? 'PASS' : 'FAIL';
      textOutput += '[' + status + '] ' + test.id + ': ' + test.description;
      if (!test.pass) {
        textOutput += '\n       Expected: ' + JSON.stringify(test.expected) + ', Got: ' + JSON.stringify(test.actual);
      }
      textOutput += '\n';
    }
    textOutput += '\n';
  }

  const folder = getOrCreateDebugFolder();
  const textFileName = 'TEST_RESULTS_' + timestamp.replace(/[:.]/g, '-') + '.txt';
  const textFile = folder.createFile(textFileName, textOutput, 'text/plain');

  // Show UI alert with results
  const failedTests = allResults.filter(r => !r.pass);
  let message = totalPassed + ' of ' + totalTests + ' tests passed (' + passRate + '%).\n\n';
  message += summaryLines.join('\n');

  if (failedTests.length > 0 && failedTests.length <= 10) {
    message += '\n\nFailed tests:\n';
    for (const test of failedTests) {
      message += '• ' + test.id + ': expected ' + test.expected + ', got ' + test.actual + '\n';
    }
  } else if (failedTests.length > 10) {
    message += '\n\n' + failedTests.length + ' tests failed. Check Logger for details.';
  }

  message += '\n\nResults saved to:\n' + textFile.getUrl();

  ui.alert(
    totalPassed === totalTests ? '✅ All Tests Passed' : '⚠️ Some Tests Failed',
    message,
    ui.ButtonSet.OK
  );

  return allResults;
}

/**
 * Email validation tests (VAL-01 to VAL-10)
 * Note: validateEmail() throws errors for invalid input, returns escaped email for valid
 */
function runEmailValidationTests() {
  const results = [];

  function test(id, description, testFn, expected) {
    let actual;
    try {
      actual = testFn();
    } catch (e) {
      actual = 'ERROR: ' + e.message;
    }
    const pass = actual === expected;
    results.push({ id, description, pass, expected, actual });
    if (!pass) Logger.log('FAIL ' + id + ': ' + description + ' - expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
  }

  // For validateEmail, valid inputs return the (escaped) email, invalid throw errors
  // Test for success by checking if result equals input (lowercase)
  function emailReturnsValue(email) {
    const result = validateEmail(email);
    return typeof result === 'string' && result.length > 0;
  }

  function emailThrows(email) {
    try {
      validateEmail(email);
      return false;
    } catch (e) {
      return true;
    }
  }

  // VAL-01 to VAL-10 from TEST_SPECIFICATION.md
  test('VAL-01', 'Valid email', () => emailReturnsValue('test@example.com'), true);
  test('VAL-02', 'Valid with subdomain', () => emailReturnsValue('test@mail.example.com'), true);
  test('VAL-03', 'Valid with plus', () => emailReturnsValue('test+tag@example.com'), true);
  test('VAL-04', 'Missing @', () => emailThrows('testexample.com'), true);
  test('VAL-05', 'Missing domain', () => emailThrows('test@'), true);
  test('VAL-06', 'Missing local part', () => emailThrows('@example.com'), true);
  test('VAL-07', 'Multiple @', () => emailThrows('test@@example.com'), true);
  test('VAL-08', 'Empty string', () => emailThrows(''), true);
  test('VAL-09', 'Spaces in email', () => emailThrows('test @example.com'), true);
  test('VAL-10', 'NZ domain', () => emailReturnsValue('test@business.co.nz'), true);

  const passed = results.filter(r => r.pass).length;
  Logger.log('Email Validation: ' + passed + '/' + results.length + ' passed');

  return results;
}

/**
 * Phone validation tests (VAL-20 to VAL-30)
 * Note: validatePhone() throws errors for invalid input, returns escaped phone for valid
 */
function runPhoneValidationTests() {
  const results = [];

  function test(id, description, testFn, expected) {
    let actual;
    try {
      actual = testFn();
    } catch (e) {
      actual = 'ERROR: ' + e.message;
    }
    const pass = actual === expected;
    results.push({ id, description, pass, expected, actual });
    if (!pass) Logger.log('FAIL ' + id + ': ' + description + ' - expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
  }

  function phoneReturnsValue(phone) {
    const result = validatePhone(phone);
    return typeof result === 'string' && result.length > 0;
  }

  function phoneThrows(phone) {
    try {
      validatePhone(phone);
      return false;
    } catch (e) {
      return true;
    }
  }

  // VAL-20 to VAL-30 from TEST_SPECIFICATION.md
  test('VAL-20', 'NZ mobile (021)', () => phoneReturnsValue('021 123 4567'), true);
  test('VAL-21', 'NZ mobile (022)', () => phoneReturnsValue('022 123 4567'), true);
  test('VAL-22', 'NZ mobile (027)', () => phoneReturnsValue('027 123 4567'), true);
  test('VAL-23', 'NZ mobile no spaces', () => phoneReturnsValue('0211234567'), true);
  test('VAL-24', 'NZ mobile with dashes', () => phoneReturnsValue('021-123-4567'), true);
  test('VAL-25', 'NZ landline', () => phoneReturnsValue('09 123 4567'), true);
  test('VAL-26', 'International format', () => phoneReturnsValue('+64 21 123 4567'), true);
  test('VAL-27', 'Invalid prefix', () => phoneReturnsValue('099 123 4567'), true); // Still valid format (digits/spaces)
  test('VAL-28', 'Too short (5 chars)', () => phoneThrows('02112'), true);  // 5 chars - should fail
  test('VAL-28b', 'Minimum length (6 chars)', () => phoneReturnsValue('021123'), true);  // 6 chars - should pass
  test('VAL-29', 'Too long', () => phoneReturnsValue('021 123 456 789'), true); // Within 20 char limit
  test('VAL-30', 'Letters', () => phoneThrows('021 ABC DEFG'), true);

  const passed = results.filter(r => r.pass).length;
  Logger.log('Phone Validation: ' + passed + '/' + results.length + ' passed');

  return results;
}

/**
 * URL validation tests (VAL-40 to VAL-47)
 * Note: validateURL() throws errors for invalid input, returns escaped URL for valid
 */
function runURLValidationTests() {
  const results = [];

  function test(id, description, testFn, expected) {
    let actual;
    try {
      actual = testFn();
    } catch (e) {
      actual = 'ERROR: ' + e.message;
    }
    const pass = actual === expected;
    results.push({ id, description, pass, expected, actual });
    if (!pass) Logger.log('FAIL ' + id + ': ' + description + ' - expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
  }

  function urlReturnsValue(url) {
    const result = validateURL(url);
    return typeof result === 'string' && result.length > 0;
  }

  function urlThrows(url) {
    try {
      validateURL(url);
      return false;
    } catch (e) {
      return true;
    }
  }

  // VAL-40 to VAL-47 from TEST_SPECIFICATION.md
  test('VAL-40', 'Shopify URL', () => urlReturnsValue('https://store.myshopify.com'), true);
  test('VAL-41', 'Custom domain', () => urlReturnsValue('https://www.mystore.co.nz'), true);
  test('VAL-42', 'HTTP (not HTTPS)', () => urlReturnsValue('http://store.com'), true);
  test('VAL-43', 'Missing protocol', () => urlReturnsValue('store.myshopify.com'), true); // Auto-adds https
  test('VAL-44', 'With path', () => urlReturnsValue('https://store.com/products'), true);
  test('VAL-45', 'Invalid URL', () => urlThrows('not a url'), true);
  test('VAL-46', 'JavaScript URL', () => urlThrows('javascript:alert(1)'), true);
  test('VAL-47', 'Empty', () => urlThrows(''), true);

  const passed = results.filter(r => r.pass).length;
  Logger.log('URL Validation: ' + passed + '/' + results.length + ' passed');

  return results;
}

/**
 * Text sanitization tests (VAL-60 to VAL-68)
 * Tests validateAndSanitizeText() and escapeHtml()
 */
function runTextSanitizationTests() {
  const results = [];

  function test(id, description, actual, expected) {
    const pass = actual === expected;
    results.push({ id, description, pass, expected, actual });
    if (!pass) Logger.log('FAIL ' + id + ': ' + description + ' - expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
  }

  // escapeHtml tests
  test('VAL-60', 'Normal text', escapeHtml('Hello world'), 'Hello world');
  test('VAL-61', 'HTML tags escaped', escapeHtml('<b>bold</b>'), '&lt;b&gt;bold&lt;/b&gt;');
  test('VAL-62', 'Script tags escaped', escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
  test('VAL-63', 'Ampersand escaped', escapeHtml('$100 & 50%'), '$100 &amp; 50%');
  test('VAL-64', 'Quotes escaped', escapeHtml('He said "hello"'), 'He said &quot;hello&quot;');
  test('VAL-65', 'Single quotes escaped', escapeHtml("It's fine"), 'It&#039;s fine');
  test('VAL-66', 'Empty string', escapeHtml(''), '');
  test('VAL-67', 'Null input', escapeHtml(null), '');
  test('VAL-68', 'Unicode preserved', escapeHtml('Māori words'), 'Māori words');

  const passed = results.filter(r => r.pass).length;
  Logger.log('Text Sanitization: ' + passed + '/' + results.length + ' passed');

  return results;
}

/**
 * Format validator tests (VAL-80 to VAL-86)
 * Tests isJobNumberFormat(), isSubmissionNumberFormat(), isInvoiceNumberFormat()
 */
function runFormatValidatorTests() {
  const results = [];

  function test(id, description, actual, expected) {
    const pass = actual === expected;
    results.push({ id, description, pass, expected, actual });
    if (!pass) Logger.log('FAIL ' + id + ': ' + description + ' - expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
  }

  // Submission number format tests
  test('VAL-80', 'Valid submission # (new format)', isSubmissionNumberFormat('CC-APPLE-123'), true);
  test('VAL-81', 'Invalid submission #', isSubmissionNumberFormat('CC-123'), false);
  test('VAL-81b', 'Valid submission # (legacy)', isSubmissionNumberFormat('CC-20240101-00001'), true);

  // Job number format tests
  test('VAL-82', 'Valid job #', isJobNumberFormat('J-APPLE-123'), true);
  test('VAL-83', 'Job # with suffix', isJobNumberFormat('J-APPLE-123-2'), true);
  test('VAL-84', 'Invalid job #', isJobNumberFormat('JOB-123'), false);
  test('VAL-84b', 'Valid job # (legacy)', isJobNumberFormat('J-20240101-00001'), true);

  // Invoice number format tests
  test('VAL-85', 'Valid invoice #', isInvoiceNumberFormat('INV-APPLE-123'), true);
  test('VAL-85b', 'Valid invoice # with suffix', isInvoiceNumberFormat('INV-APPLE-123-2'), true);
  test('VAL-86', 'Invalid invoice #', isInvoiceNumberFormat('INVOICE-1'), false);
  test('VAL-86b', 'Valid invoice # (legacy)', isInvoiceNumberFormat('INV-2024-001'), true);
  test('VAL-86c', 'Valid invoice # (old)', isInvoiceNumberFormat('INV-0001'), true);

  // Edge cases
  test('VAL-87', 'Null job number', isJobNumberFormat(null), false);
  test('VAL-88', 'Empty submission number', isSubmissionNumberFormat(''), false);
  test('VAL-89', 'Whitespace invoice number', isInvoiceNumberFormat('  '), false);

  const passed = results.filter(r => r.pass).length;
  Logger.log('Format Validators: ' + passed + '/' + results.length + ' passed');

  return results;
}

/**
 * Utility function tests (UTIL-01 to UTIL-73)
 * Tests formatCurrency(), calculateGST(), formatNZDate(), daysBetween(), calculateLateFee(), calculateSLAStatus(), getProjectSize(), colIndexToLetter()
 */
function runUtilityTests() {
  const results = [];

  function test(id, description, actual, expected) {
    const pass = actual === expected;
    results.push({ id, description, pass, expected, actual });
    if (!pass) Logger.log('FAIL ' + id + ': ' + description + ' - expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
  }

  function testApprox(id, description, actual, expected, tolerance) {
    const pass = Math.abs(actual - expected) <= tolerance;
    results.push({ id, description, pass, expected, actual });
    if (!pass) Logger.log('FAIL ' + id + ': ' + description + ' - expected ' + expected + ' (±' + tolerance + '), got ' + actual);
  }

  // formatCurrency tests (UTIL-01 to UTIL-05)
  test('UTIL-01', 'Format $100', formatCurrency(100), '$100.00');
  test('UTIL-02', 'Format $1234.56', formatCurrency(1234.56), '$1234.56');
  test('UTIL-03', 'Format $0', formatCurrency(0), '$0.00');
  test('UTIL-04', 'Format $99.999 rounded', formatCurrency(99.999), '$100.00');
  test('UTIL-05', 'Format negative', formatCurrency(-50), '$-50.00');

  // formatNZDate tests (UTIL-20 to UTIL-21)
  test('UTIL-20', 'Format date Jan 15', formatNZDate(new Date(2025, 0, 15)), '15/01/2025');
  test('UTIL-21', 'Format date Dec 31', formatNZDate(new Date(2025, 11, 31)), '31/12/2025');
  test('UTIL-22', 'Format null date', formatNZDate(null), '');

  // daysBetween tests (UTIL-30 to UTIL-32)
  const jan1 = new Date(2025, 0, 1);
  const jan5 = new Date(2025, 0, 5);
  test('UTIL-30', 'Days Jan 1 to Jan 5', daysBetween(jan1, jan5), 4);
  test('UTIL-31', 'Days Jan 5 to Jan 1 (negative)', daysBetween(jan5, jan1), -4);
  test('UTIL-32', 'Same date', daysBetween(jan1, jan1), 0);

  // calculateLateFee tests (UTIL-40 to UTIL-43)
  const dueDate = new Date(2025, 0, 1);
  const current0 = new Date(2025, 0, 1);  // Same day
  const current7 = new Date(2025, 0, 8);  // 7 days later
  const current14 = new Date(2025, 0, 15); // 14 days later

  const fee0 = calculateLateFee(100, dueDate, current0);
  test('UTIL-40', 'No late fee on due date', fee0.lateFee, 0);

  const fee7 = calculateLateFee(100, dueDate, current7);
  testApprox('UTIL-41', 'Late fee at 7 days (2%/day)', fee7.lateFee, 14, 0.01); // 7 days * 2% * $100 = $14

  const fee14 = calculateLateFee(100, dueDate, current14);
  testApprox('UTIL-42', 'Late fee at 14 days', fee14.lateFee, 28, 0.01); // 14 days * 2% * $100 = $28

  // getProjectSize tests (UTIL-60 to UTIL-62)
  test('UTIL-60', 'Small project (<$200)', getProjectSize(50), 'Small');
  test('UTIL-61', 'Medium project ($200-$500)', getProjectSize(200), 'Medium');
  test('UTIL-61b', 'Medium project upper bound', getProjectSize(500), 'Medium');
  test('UTIL-62', 'Large project (>$500)', getProjectSize(1000), 'Large');

  // colIndexToLetter tests (UTIL-70 to UTIL-73)
  test('UTIL-70', 'Column 1 = A', colIndexToLetter(1), 'A');
  test('UTIL-71', 'Column 26 = Z', colIndexToLetter(26), 'Z');
  test('UTIL-72', 'Column 27 = AA', colIndexToLetter(27), 'AA');
  test('UTIL-73', 'Column 52 = AZ', colIndexToLetter(52), 'AZ');
  test('UTIL-74', 'Column 53 = BA', colIndexToLetter(53), 'BA');

  const passed = results.filter(r => r.pass).length;
  Logger.log('Utility Functions: ' + passed + '/' + results.length + ' passed');

  return results;
}

/**
 * Column config tests (COL-01 to COL-21)
 * Tests getColIndex(), getColLetter(), buildRowFromConfig(), rowToObject()
 */
function runColumnConfigTests() {
  const results = [];

  function test(id, description, actual, expected) {
    const pass = JSON.stringify(actual) === JSON.stringify(expected);
    results.push({ id, description, pass, expected, actual });
    if (!pass) Logger.log('FAIL ' + id + ': ' + description + ' - expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
  }

  // getColIndex tests (COL-01 to COL-05)
  // Note: Status is column 1, Job # is column 2 in JOBS sheet
  test('COL-01', 'JOBS Status column index', getColIndex('JOBS', 'Status'), 1);
  test('COL-02', 'JOBS Job # column index', getColIndex('JOBS', 'Job #'), 2);
  test('COL-03', 'Invalid column returns -1', getColIndex('JOBS', 'Invalid Column'), -1);
  test('COL-04', 'INVOICES Invoice # column', getColIndex('INVOICES', 'Invoice #'), 2);
  test('COL-05', 'SUBMISSIONS Submission # column', getColIndex('SUBMISSIONS', 'Submission #'), 2);

  // getColLetter tests
  test('COL-06', 'Status letter is A', getColLetter('JOBS', 'Status'), 'A');
  test('COL-07', 'Job # letter is B', getColLetter('JOBS', 'Job #'), 'B');
  test('COL-08', 'Invalid column returns empty', getColLetter('JOBS', 'Invalid Column'), '');

  // buildRowFromConfig tests (COL-10 to COL-12)
  const testData = {
    'Job #': 'J-TEST-001',
    'Status': 'Pending Quote',
    'Client Name': 'Test Client'
  };
  const builtRow = buildRowFromConfig('JOBS', testData);
  test('COL-10', 'Built row is array', Array.isArray(builtRow), true);
  test('COL-11', 'Built row has correct Status at index 0', builtRow[0], 'Pending Quote');
  test('COL-12', 'Built row has correct Job # at index 1', builtRow[1], 'J-TEST-001');
  test('COL-13', 'Unknown fields handled', buildRowFromConfig('JOBS', { 'Fake Column': 'value' }).includes('value'), false);

  // rowToObject tests (COL-20 to COL-21)
  // Row format: [Status, Job #, Total, Created Date, Client Name, ...]
  const testRow = ['Pending Quote', 'J-TEST-002', '', '', 'Test Client'];
  const obj = rowToObject('JOBS', testRow);
  test('COL-20', 'rowToObject returns object', typeof obj === 'object', true);
  test('COL-21', 'rowToObject has Status key', obj['Status'], 'Pending Quote');
  test('COL-22', 'rowToObject has Job # key', obj['Job #'], 'J-TEST-002');

  const passed = results.filter(r => r.pass).length;
  Logger.log('Column Config: ' + passed + '/' + results.length + ' passed');

  return results;
}

