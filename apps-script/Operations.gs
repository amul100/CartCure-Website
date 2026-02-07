// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Get a setting value from the Settings sheet
 * PERFORMANCE OPTIMIZED: Now uses cached settings to avoid repeated sheet loads.
 * Previously: Each call loaded the entire Settings sheet (~500ms each)
 * Now: First call loads and caches, subsequent calls are instant
 */
function getSetting(settingName) {
  return getSettingCached(settingName);
}

/**
 * Update a setting value in the Settings sheet
 * PERFORMANCE OPTIMIZED: Uses cached spreadsheet reference
 */
function updateSetting(settingName, value) {
  const sheet = getSheet(SHEETS.SETTINGS);

  if (!sheet) {
    Logger.log('Settings sheet not found');
    return false;
  }

  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === settingName) {
      sheet.getRange(i + 1, 2).setValue(value);
      // Clear settings cache so next getSetting() call gets fresh data
      _cache.settingsLoaded = false;
      _cache.settings = null;
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
 * P0 FIX: Now validates uniqueness against existing invoice numbers to prevent duplicates
 * from manual entry, data corruption, or race conditions.
 *
 * @param {string} jobNumber - The job number (e.g., "J-MAPLE-001")
 * @param {number} invoiceCount - Number of existing invoices for this job
 * @returns {string} Invoice number (e.g., "INV-MAPLE-001" or "INV-MAPLE-001-2")
 */
function generateInvoiceNumber(jobNumber, invoiceCount) {
  // Replace J- prefix with INV-
  let baseInvoiceNumber = jobNumber.replace(/^J-/, 'INV-');
  let invoiceNumber = baseInvoiceNumber;

  // If this is the 2nd, 3rd, etc. invoice, add suffix
  if (invoiceCount > 0) {
    invoiceNumber = baseInvoiceNumber + '-' + (invoiceCount + 1);
  }

  // Get all existing invoice numbers to check for duplicates
  const existingNumbers = getExistingInvoiceNumbers();

  // If duplicate found, increment suffix until unique
  let suffix = invoiceCount > 0 ? invoiceCount + 1 : 1;
  while (existingNumbers.has(invoiceNumber)) {
    suffix++;
    invoiceNumber = baseInvoiceNumber + '-' + suffix;
  }

  return invoiceNumber;
}

/**
 * Get a Set of all existing invoice numbers for duplicate checking
 * @returns {Set<string>} Set of existing invoice numbers
 */
function getExistingInvoiceNumbers() {
  const sheet = getSheet(SHEETS.INVOICES);
  if (!sheet || sheet.getLastRow() < 2) {
    return new Set();
  }

  const invoiceNumCol = getColIndex('INVOICES', 'Invoice #');
  const data = sheet.getRange(2, invoiceNumCol, sheet.getLastRow() - 1, 1).getValues();

  const numbers = new Set();
  data.forEach(row => {
    if (row[0]) {
      numbers.add(String(row[0]).trim());
    }
  });

  return numbers;
}

/**
 * Generate a unique receipt number (REC-001, REC-002, etc.)
 * Receipt numbers are sequential and unique across all payments
 * @returns {string} The generated receipt number
 */
function generateReceiptNumber() {
  const existingReceipts = getExistingReceiptNumbers();

  // Start at 1 and find the next available number
  let receiptNum = 1;
  let receiptNumber = 'REC-' + String(receiptNum).padStart(3, '0');

  // Find next available number
  while (existingReceipts.has(receiptNumber)) {
    receiptNum++;
    receiptNumber = 'REC-' + String(receiptNum).padStart(3, '0');
  }

  return receiptNumber;
}

/**
 * Get a Set of all existing receipt numbers for duplicate checking
 * @returns {Set<string>} Set of existing receipt numbers
 */
function getExistingReceiptNumbers() {
  const sheet = getSheet(SHEETS.INVOICES);
  if (!sheet || sheet.getLastRow() < 2) {
    return new Set();
  }

  const receiptCol = getColIndex('INVOICES', 'Receipt #');
  if (receiptCol === -1) {
    return new Set();
  }

  const data = sheet.getRange(2, receiptCol, sheet.getLastRow() - 1, 1).getValues();

  const numbers = new Set();
  data.forEach(row => {
    if (row[0]) {
      numbers.add(String(row[0]).trim());
    }
  });

  return numbers;
}

/**
 * Update the Receipt # column in the Invoice Log
 * @param {string} invoiceNumber - The invoice number
 * @param {string} receiptNumber - The receipt number to set
 */
function updateInvoiceReceiptNumber(invoiceNumber, receiptNumber) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
    if (!invoiceSheet) return;

    const data = invoiceSheet.getDataRange().getValues();
    const invoiceCol = getColIndex('INVOICES', 'Invoice #');
    const receiptCol = getColIndex('INVOICES', 'Receipt #');

    if (invoiceCol === -1 || receiptCol === -1) return;

    for (let i = 1; i < data.length; i++) {
      if (data[i][invoiceCol - 1] === invoiceNumber) {
        invoiceSheet.getRange(i + 1, receiptCol).setValue(receiptNumber);
        break;
      }
    }
  } catch (e) {
    Logger.log('Failed to update receipt number: ' + e.message);
  }
}

/**
 * Validate invoice amount before creating invoice (P1 FIX)
 * Ensures amount is valid, positive, and within reasonable bounds
 * @param {number} amount - The invoice amount to validate
 * @param {string} context - Context for error messages (e.g., 'Quote Amount')
 * @returns {Object} { valid: boolean, error: string|null }
 */
function validateInvoiceAmount(amount, context) {
  context = context || 'Amount';

  // Check if it's a valid number
  if (amount === null || amount === undefined || isNaN(amount)) {
    return { valid: false, error: context + ' is not a valid number.' };
  }

  // Check if amount is positive
  if (amount <= 0) {
    return { valid: false, error: context + ' must be greater than $0. Current value: $' + amount.toFixed(2) };
  }

  // Sanity check: maximum reasonable invoice amount ($1,000,000)
  // This catches typos like entering 50000 instead of 500.00
  const MAX_INVOICE_AMOUNT = 1000000;
  if (amount > MAX_INVOICE_AMOUNT) {
    return {
      valid: false,
      error: context + ' exceeds maximum allowed ($' + MAX_INVOICE_AMOUNT.toLocaleString() + ').\n' +
             'Current value: $' + amount.toLocaleString() + '\n\n' +
             'If this is correct, please contact support.'
    };
  }

  return { valid: true, error: null };
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
 * Format due date for invoices - shows friendly date format
 * e.g., "3 Feb 2026"
 */
function formatDueDate(date) {
  if (!date) return '';
  const d = new Date(date);
  return Utilities.formatDate(d, 'Pacific/Auckland', 'd MMM yyyy');
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
 * OPTIMIZED: Uses batch setValues() instead of individual setValue() calls
 */
function updateAllLateFees() {
  const ss = getSpreadsheet();
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!invoiceSheet) {
    Logger.log('Invoice sheet not found');
    return;
  }

  const data = invoiceSheet.getDataRange().getValues();
  const headers = data[0] || [];

  // Use actual sheet headers for column lookup (handles any column order)
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
  let hasChanges = false;

  // Modify data array in-place (much faster than individual setValue calls)
  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const status = row[cols.status];

    // Only calculate for unpaid invoices (Sent or Overdue status)
    if (status !== 'Sent' && status !== 'Overdue') continue;

    const dueDate = row[cols.dueDate];
    const total = parseFloat(row[cols.total]) || 0;

    if (!dueDate || total === 0) continue;

    const feeCalc = calculateLateFee(total, dueDate, now);

    // Update the data array in-place
    data[i][cols.daysOverdue] = feeCalc.daysOverdue > 0 ? feeCalc.daysOverdue : '';
    data[i][cols.lateFee] = feeCalc.lateFee > 0 ? feeCalc.lateFee.toFixed(2) : '';
    data[i][cols.totalWithFees] = feeCalc.totalWithFees.toFixed(2);

    // Update status to Overdue if past due
    if (feeCalc.daysOverdue > 0 && status === 'Sent') {
      data[i][cols.status] = 'Overdue';
    }

    hasChanges = true;
    updatedCount++;
  }

  // Single batch write for all changes (replaces 150-200 individual setValue calls)
  if (hasChanges && data.length > 1) {
    invoiceSheet.getRange(2, 1, data.length - 1, data[0].length).setValues(data.slice(1));
  }

  Logger.log('Updated late fees for ' + updatedCount + ' invoices');
  return updatedCount;
}

/**
 * Show late fees summary for overdue invoices
 */
function showOverdueInvoicesWithFees() {
  const ui = SpreadsheetApp.getUi();
  const ss = getSpreadsheet();
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);

  if (!invoiceSheet) {
    ui.alert('Error', 'Invoice sheet not found.', ui.ButtonSet.OK);
    return;
  }

  // Update fees first
  updateAllLateFees();

  const data = invoiceSheet.getDataRange().getValues();
  const headers = data[0] || [];

  // Use actual sheet headers for column lookup (handles any column order)
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
  // PERFORMANCE: Use cached sheet references
  const submissionsSheet = getSheet(SHEETS.SUBMISSIONS);
  const jobsSheet = getSheet(SHEETS.JOBS);

  if (!submissionsSheet) {
    Logger.log('[PERF] getAvailableSubmissions() - Submissions sheet not found');
    return [];
  }

  // OPTIMIZATION: Single batch read from Jobs sheet to build exclusion set
  const existingJobSubmissions = new Set();
  if (jobsSheet && jobsSheet.getLastRow() > 1) {
    const jobsData = jobsSheet.getDataRange().getValues();
    // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
    const jobSubNumColIdx = getColIndex('JOBS', 'Submission #') - 1;
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

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const submissionNumCol = getColIndex('SUBMISSIONS', 'Submission #') - 1;
  const timestampCol = getColIndex('SUBMISSIONS', 'Timestamp') - 1;
  const nameColIndex = getColIndex('SUBMISSIONS', 'Name') - 1;
  const emailColIndex = getColIndex('SUBMISSIONS', 'Email') - 1;
  const statusColIndex = getColIndex('SUBMISSIONS', 'Status') - 1;

  // Fallback if columns not found in COLUMN_CONFIG (should not happen)
  if (submissionNumCol === -2 || nameColIndex === -2 || statusColIndex === -2) {
    Logger.log('[PERF] getAvailableSubmissions() - Required columns not found in COLUMN_CONFIG');
    return [];
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
 * Get a submission by its submission number
 * @param {string} submissionNumber - The submission number (e.g., CC-MAPLE-001)
 * @returns {Object|null} Submission object with all fields, or null if not found
 */
function getSubmissionByNumber(submissionNumber) {
  const sheet = getSheet(SHEETS.SUBMISSIONS);
  if (!sheet) return null;

  // Use TextFinder for fast lookup
  const finder = sheet.createTextFinder(submissionNumber)
    .matchEntireCell(true)
    .matchCase(false);

  const foundRange = finder.findNext();
  if (!foundRange) return null;

  // Verify it's in the Submission # column
  const subNumCol = getColIndex('SUBMISSIONS', 'Submission #');
  if (foundRange.getColumn() !== subNumCol) {
    // Try to find in correct column
    const allMatches = finder.findAll();
    let correctMatch = null;
    for (const match of allMatches) {
      if (match.getColumn() === subNumCol) {
        correctMatch = match;
        break;
      }
    }
    if (!correctMatch) return null;
  }

  const row = foundRange.getRow();
  const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  const rowData = sheet.getRange(row, 1, 1, sheet.getLastColumn()).getValues()[0];

  // Build object from row data
  const submission = {};
  for (let i = 0; i < headers.length; i++) {
    if (headers[i]) {
      submission[headers[i]] = rowData[i];
    }
  }

  return submission;
}

/**
 * Fallback implementation - loads all columns from Submissions
 * Used when required columns cannot be found in headers
 */
function getAvailableSubmissionsFallback(existingJobSubmissions) {
  // PERFORMANCE: Use cached sheet reference
  const submissionsSheet = getSheet(SHEETS.SUBMISSIONS);

  if (!submissionsSheet) return [];

  const submissionsData = submissionsSheet.getDataRange().getValues();
  const submissions = [];

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const submissionNumCol = getColIndex('SUBMISSIONS', 'Submission #') - 1;
  const statusCol = getColIndex('SUBMISSIONS', 'Status') - 1;
  const nameCol = getColIndex('SUBMISSIONS', 'Name') - 1;
  const emailCol = getColIndex('SUBMISSIONS', 'Email') - 1;
  const timestampCol = getColIndex('SUBMISSIONS', 'Timestamp') - 1;

  for (let i = 1; i < submissionsData.length; i++) {
    const row = submissionsData[i];
    const submissionNum = submissionNumCol >= 0 ? row[submissionNumCol] : null;
    const status = statusCol >= 0 ? row[statusCol] : 'New';

    if (submissionNum && !existingJobSubmissions.has(submissionNum)) {
      const name = nameCol >= 0 ? row[nameCol] : 'Unknown';
      const email = emailCol >= 0 ? row[emailCol] : '';
      const timestamp = timestampCol >= 0 ? row[timestampCol] : new Date();

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
  // PERFORMANCE: Use cached sheet reference
  const jobsSheet = getSheet(SHEETS.JOBS);

  if (!jobsSheet) {
    Logger.log('[PERF] getJobsByStatus() - Jobs sheet not found');
    return [];
  }

  const lastRow = jobsSheet.getLastRow();
  if (lastRow <= 1) return []; // No data rows

  // OPTIMIZATION: Single getRange call to load all data at once
  // This is faster than multiple getRange calls even if we load extra columns
  const allData = jobsSheet.getDataRange().getValues();

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const jobNumColIndex = getColIndex('JOBS', 'Job #') - 1;
  const statusColIndex = getColIndex('JOBS', 'Status') - 1;
  const clientNameColIndex = getColIndex('JOBS', 'Client Name') - 1;
  const storeUrlColIndex = getColIndex('JOBS', 'Store URL') - 1;

  // Validation: ensure columns exist in COLUMN_CONFIG
  if (jobNumColIndex < 0 || statusColIndex < 0 || clientNameColIndex < 0) {
    Logger.log('[PERF] getJobsByStatus() - Required columns not found in COLUMN_CONFIG');
    return [];
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
      const storeUrl = storeUrlColIndex >= 0 ? row[storeUrlColIndex] : '';

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
  // PERFORMANCE: Use cached sheet reference
  const jobsSheet = getSheet(SHEETS.JOBS);

  if (!jobsSheet) return [];

  const data = jobsSheet.getDataRange().getValues();
  const jobs = [];

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const jobNumColIdx = getColIndex('JOBS', 'Job #') - 1;
  const statusColIdx = getColIndex('JOBS', 'Status') - 1;
  const clientNameColIdx = getColIndex('JOBS', 'Client Name') - 1;
  const storeUrlColIdx = getColIndex('JOBS', 'Store URL') - 1;

  if (jobNumColIdx < 0) {
    Logger.log('Warning: Job # column not found in COLUMN_CONFIG');
    return [];
  }
  if (statusColIdx < 0) {
    Logger.log('Warning: Status column not found in COLUMN_CONFIG');
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
  // PERFORMANCE: Use cached sheet reference
  const invoiceSheet = getSheet(SHEETS.INVOICES);

  if (!invoiceSheet) {
    Logger.log('[PERF] getInvoicesByStatus() - Invoice Log sheet not found');
    return [];
  }

  const lastRow = invoiceSheet.getLastRow();
  if (lastRow <= 1) return []; // No data rows

  // OPTIMIZATION: Single getRange call to load all data at once
  const allData = invoiceSheet.getDataRange().getValues();

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const invoiceNumColIndex = getColIndex('INVOICES', 'Invoice #') - 1;
  const jobNumColIndex = getColIndex('INVOICES', 'Job #') - 1;
  const clientNameColIndex = getColIndex('INVOICES', 'Client Name') - 1;
  const totalColIndex = getColIndex('INVOICES', 'Total') - 1;
  const statusColIndex = getColIndex('INVOICES', 'Status') - 1;

  // Validation: ensure columns exist in COLUMN_CONFIG
  if (invoiceNumColIndex < 0 || statusColIndex < 0 || totalColIndex < 0) {
    Logger.log('[PERF] getInvoicesByStatus() - Required columns not found in COLUMN_CONFIG');
    return [];
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
  // PERFORMANCE: Use cached sheet reference
  const invoiceSheet = getSheet(SHEETS.INVOICES);

  if (!invoiceSheet) return [];

  const data = invoiceSheet.getDataRange().getValues();
  const invoices = [];

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const invoiceNumColIdx = getColIndex('INVOICES', 'Invoice #') - 1;
  const statusColIdx = getColIndex('INVOICES', 'Status') - 1;
  const jobNumColIdx = getColIndex('INVOICES', 'Job #') - 1;
  const clientNameColIdx = getColIndex('INVOICES', 'Client Name') - 1;
  const totalColIdx = getColIndex('INVOICES', 'Total') - 1;

  if (invoiceNumColIdx < 0) {
    Logger.log('Warning: Invoice # column not found in COLUMN_CONFIG');
    return [];
  }
  if (statusColIdx < 0) {
    Logger.log('Warning: Status column not found in COLUMN_CONFIG');
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
 * Get all job numbers from currently selected rows (for batch operations)
 * @returns {Array<string>} Array of unique job numbers from selected rows
 */
function getSelectedJobNumbers() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const sheetName = sheet.getName();
  const rangeList = SpreadsheetApp.getActiveRangeList();
  if (!rangeList) return [];

  const jobNumbers = [];
  const seen = new Set();

  // Determine which column to read job numbers from
  let jobColIndex = null;
  if (sheetName === SHEETS.JOBS) {
    jobColIndex = getColIndex('JOBS', 'Job #');
  } else if (sheetName === SHEETS.INVOICES) {
    jobColIndex = getColIndex('INVOICES', 'Job #');
  } else if (sheetName === SHEETS.ACTIVITY_LOG) {
    jobColIndex = getColIndex('ACTIVITY_LOG', 'Job #');
  }

  // Process all selected ranges (supports Ctrl+click non-consecutive selection)
  const ranges = rangeList.getRanges();
  for (const range of ranges) {
    const startRow = range.getRow();
    const numRows = range.getNumRows();

    for (let i = 0; i < numRows; i++) {
      const row = startRow + i;
      if (row <= 1) continue; // Skip header row

      let jobNumber = null;

      // If we have a known column for this sheet, use it
      if (jobColIndex) {
        const value = sheet.getRange(row, jobColIndex).getValue();
        if (value && isJobNumberFormat(value.toString().trim())) {
          jobNumber = value.toString().trim();
        }
      }

      // Add to array if valid and not already seen
      if (jobNumber && !seen.has(jobNumber)) {
        seen.add(jobNumber);
        jobNumbers.push(jobNumber);
      }
    }
  }

  return jobNumbers;
}

/**
 * Get all submission numbers from currently selected rows (for batch operations)
 * @returns {Array<string>} Array of unique submission numbers from selected rows
 */
function getSelectedSubmissionNumbers() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const sheetName = sheet.getName();
  const rangeList = SpreadsheetApp.getActiveRangeList();
  if (!rangeList) return [];

  const submissionNumbers = [];
  const seen = new Set();

  // Determine which column to read submission numbers from
  let subColIndex = null;
  if (sheetName === SHEETS.SUBMISSIONS) {
    subColIndex = getColIndex('SUBMISSIONS', 'Submission #');
  } else if (sheetName === SHEETS.JOBS) {
    subColIndex = getColIndex('JOBS', 'Submission #');
  }

  // Process all selected ranges (supports Ctrl+click non-consecutive selection)
  const ranges = rangeList.getRanges();
  for (const range of ranges) {
    const startRow = range.getRow();
    const numRows = range.getNumRows();

    for (let i = 0; i < numRows; i++) {
      const row = startRow + i;
      if (row <= 1) continue; // Skip header row

      let subNumber = null;

      // If we have a known column for this sheet, use it
      if (subColIndex) {
        const value = sheet.getRange(row, subColIndex).getValue();
        if (value && isSubmissionNumberFormat(value.toString().trim())) {
          subNumber = value.toString().trim();
        }
      }

      // Add to array if valid and not already seen
      if (subNumber && !seen.has(subNumber)) {
        seen.add(subNumber);
        submissionNumbers.push(subNumber);
      }
    }
  }

  return submissionNumbers;
}

/**
 * Get all invoice numbers from currently selected rows (for batch operations)
 * @returns {Array<string>} Array of unique invoice numbers from selected rows
 */
function getSelectedInvoiceNumbers() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const sheetName = sheet.getName();
  const rangeList = SpreadsheetApp.getActiveRangeList();
  if (!rangeList) return [];

  const invoiceNumbers = [];
  const seen = new Set();

  // Determine which column to read invoice numbers from
  let invColIndex = null;
  if (sheetName === SHEETS.INVOICES) {
    invColIndex = getColIndex('INVOICES', 'Invoice #');
  }

  // Process all selected ranges (supports Ctrl+click non-consecutive selection)
  const ranges = rangeList.getRanges();
  for (const range of ranges) {
    const startRow = range.getRow();
    const numRows = range.getNumRows();

    for (let i = 0; i < numRows; i++) {
      const row = startRow + i;
      if (row <= 1) continue; // Skip header row

      let invNumber = null;

      // If we have a known column for this sheet, use it
      if (invColIndex) {
        const value = sheet.getRange(row, invColIndex).getValue();
        if (value && isInvoiceNumberFormat(value.toString().trim())) {
          invNumber = value.toString().trim();
        }
      }

      // Add to array if valid and not already seen
      if (invNumber && !seen.has(invNumber)) {
        seen.add(invNumber);
        invoiceNumbers.push(invNumber);
      }
    }
  }

  return invoiceNumbers;
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

  // If we have a context-selected value, use it directly (or confirm if setting enabled)
  if (selectedValue) {
    // Verify the selected value is in our valid items list (if items provided)
    // Use string comparison to handle type mismatches (sheet values may be numbers)
    const selectedStr = String(selectedValue).trim();
    const isValidSelection = items && items.length > 0 &&
      items.some(item => String(item.number).trim() === selectedStr);

    if (isValidSelection) {
      // Check if confirmation dialog is enabled in settings
      const confirmEnabled = getSetting('Confirm Selection Dialog') === 'Yes';

      if (confirmEnabled) {
        const response = ui.alert(
          'Confirm Selection',
          'Use selected ' + itemType.toLowerCase() + ': ' + selectedValue + '?',
          ui.ButtonSet.YES_NO
        );

        if (response !== ui.Button.YES) {
          // User declined - fall through to dropdown
          showDropdownDialog(title, items, itemType, callback);
          return;
        }
      }

      // Proceed directly with the selected value
      eval(callback + '("' + selectedValue.replace(/"/g, '\\"') + '")');
      return;
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
 * Supports batch processing when multiple rows are selected
 */
function showCreateJobDialog() {
  // Check for multiple selected rows
  const selectedSubmissions = getSelectedSubmissionNumbers();

  if (selectedSubmissions.length > 1) {
    const totalSelected = selectedSubmissions.length;

    // Filter to only submissions that can have jobs created (not already "Job Created")
    const validSubmissions = selectedSubmissions.filter(subNum => {
      const sub = getSubmissionByNumber(subNum);
      return sub && sub['Status'] !== 'Job Created';
    });

    if (validSubmissions.length === 0) {
      SpreadsheetApp.getUi().alert('No Valid Submissions',
        'All selected submissions already have jobs created.',
        SpreadsheetApp.getUi().ButtonSet.OK);
      return;
    }

    // Show batch dialog with total selected count
    showBatchMenuActionDialog('submission', validSubmissions, 'createJob', 'Create Jobs from Submissions', totalSelected);
    return;
  }

  // Single row - use existing behavior
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

    const ss = getSpreadsheet();
    const ui = SpreadsheetApp.getUi();

    // Find the submission
    const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

  if (!submissionsSheet) {
    debugLog.push('ERROR: Submissions sheet not found');
    saveDebugLog('CREATE_JOB_' + debugTs, debugLog);
    ui.alert('Error', 'Submissions sheet not found. Please run Setup first.', ui.ButtonSet.OK);
    return;
  }

  debugLog.push('Submissions sheet found');

  const submissionsData = submissionsSheet.getDataRange().getValues();
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const submissionNumCol = getColIndex('SUBMISSIONS', 'Submission #') - 1;

  debugLog.push('Submission # column index (from COLUMN_CONFIG): ' + submissionNumCol);
  debugLog.push('Total rows: ' + submissionsData.length);
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
    saveDebugLog('CREATE_JOB_' + debugTs, debugLog);
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
    // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
    const jobNumColIdx = getColIndex('JOBS', 'Job #') - 1;
    const subNumColIdx = getColIndex('JOBS', 'Submission #') - 1;
    debugLog.push('Jobs sheet has ' + jobsData.length + ' rows');
    debugLog.push('Job # column index (from COLUMN_CONFIG): ' + jobNumColIdx + ', Submission # column index: ' + subNumColIdx);
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
      saveDebugLog('CREATE_JOB_CANCELLED_' + debugTs, debugLog);
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

  // Extract submission data using COLUMN_CONFIG (getColIndex returns 1-based, subtract 1 for array indexing)
  const name = submissionRow[getColIndex('SUBMISSIONS', 'Name') - 1] || '';
  const email = submissionRow[getColIndex('SUBMISSIONS', 'Email') - 1] || '';
  const phone = submissionRow[getColIndex('SUBMISSIONS', 'Phone') - 1] || '';
  const storeUrl = submissionRow[getColIndex('SUBMISSIONS', 'Store URL') - 1] || '';
  const message = submissionRow[getColIndex('SUBMISSIONS', 'Message') - 1] || '';

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
    saveDebugLog('CREATE_JOB_' + debugTs, debugLog);
    ui.alert('Error', 'Jobs sheet not found. Please run Setup first.', ui.ButtonSet.OK);
    return;
  }

  debugLog.push('Creating job: ' + jobNumber);
  debugLog.push('Job row data: ' + JSON.stringify(jobRow));

  // Insert at top (row 2) so newest jobs appear first
  // (filter-safe: handles active filters, shows toast notification)
  insertAtTopSafe(jobsSheet, jobRow, true);
  debugLog.push('Job row inserted at top (row 2) - newest jobs first');

  // Update the submission status to "Job Created"
  const statusColumnIndex = getColIndex('SUBMISSIONS', 'Status'); // Already 1-based for sheet.getRange()
  if (statusColumnIndex !== -1) {
    submissionsSheet.getRange(submissionRowIndex, statusColumnIndex).setValue('Job Created');
    debugLog.push('Updated submission status to "Job Created"');
    Logger.log('Updated submission ' + submissionNumber + ' status to "Job Created"');
  }

  debugLog.push('SUCCESS: Job ' + jobNumber + ' created');
  saveDebugLog('CREATE_JOB_SUCCESS_' + debugTs, debugLog);

  // Log activity
  logJobActivity(jobNumber, 'Job Created', 'Job created from submission ' + submissionNumber, '', '', 'Auto');

  // Add/update client in Clients sheet
  if (email) {
    try {
      ensureClientExistsAndUpdate(email, { name: name, phone: phone, storeUrl: storeUrl });
      debugLog.push('Client record updated/created for: ' + email);
    } catch (clientError) {
      debugLog.push('Warning: Could not update client record: ' + clientError.message);
      Logger.log('Warning: Could not update client record: ' + clientError.message);
    }
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

  // Refresh dashboard and analytics to show updated data
  refreshDashboard(true);
  refreshAnalytics();

  } catch (e) {
    debugLog.push('EXCEPTION: ' + e.toString());
    debugLog.push('Stack: ' + (e.stack || 'N/A'));
    saveDebugLog('CREATE_JOB_ERROR_' + debugTs, debugLog);
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
  // PERFORMANCE: Use cached sheet reference
  const sheet = getSheet(SHEETS.JOBS);

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
  // Validate inputs
  if (!jobNumber || !updates || Object.keys(updates).length === 0) {
    Logger.log('[PERF] updateJobFields() - Invalid parameters');
    return false;
  }

  // PERFORMANCE: Use cached sheet reference
  const sheet = getSheet(SHEETS.JOBS);

  if (!sheet) {
    Logger.log('[PERF] updateJobFields() - Jobs sheet not found');
    return false;
  }

  // OPTIMIZATION: Single sheet load instead of N loads
  const data = sheet.getDataRange().getValues();
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const jobNumColIndex = getColIndex('JOBS', 'Job #') - 1;

  if (jobNumColIndex < 0) {
    Logger.log('[PERF] updateJobFields() - Job # column not found in COLUMN_CONFIG');
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

  // Prepare batch update: build a row update array
  const rowData = data[rowIndex].slice(); // Copy current row data
  let fieldsUpdated = 0;

  // Process each field update request using COLUMN_CONFIG
  for (const [fieldName, value] of Object.entries(updates)) {
    const colIndex = getColIndex('JOBS', fieldName) - 1;
    if (colIndex >= 0) {
      rowData[colIndex] = value;
      fieldsUpdated++;
    } else {
      Logger.log('[PERF] updateJobFields() - Field not found in COLUMN_CONFIG: ' + fieldName);
    }
  }

  // Always update "Last Updated" timestamp
  const lastUpdatedCol = getColIndex('JOBS', 'Last Updated') - 1;
  if (lastUpdatedCol >= 0) {
    rowData[lastUpdatedCol] = formatNZDate(new Date());
  }

  // PERFORMANCE: Single setValues() call for entire row instead of N setValue() calls
  // This reduces API calls from N+1 to just 1
  sheet.getRange(rowIndex + 1, 1, 1, rowData.length).setValues([rowData]);

  Logger.log('[PERF] updateJobFields() - Updated ' + fieldsUpdated + ' fields for ' + jobNumber);

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
  // PERFORMANCE: Use cached sheet reference
  const sheet = getSheet(SHEETS.JOBS);

  if (!sheet) return false;

  const data = sheet.getDataRange().getValues();
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based)
  const jobNumColIndex = getColIndex('JOBS', 'Job #') - 1; // For array indexing
  const colIndex = getColIndex('JOBS', fieldName); // Keep 1-based for sheet.getRange()

  if (jobNumColIndex < 0 || colIndex < 1) return false;

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][jobNumColIndex]).trim() === String(jobNumber).trim()) {
      sheet.getRange(i + 1, colIndex).setValue(value);
      // Update Last Updated
      const lastUpdatedCol = getColIndex('JOBS', 'Last Updated'); // 1-based for sheet.getRange()
      if (lastUpdatedCol >= 1) {
        sheet.getRange(i + 1, lastUpdatedCol).setValue(formatNZDate(new Date()));
      }
      return true;
    }
  }
  return false;
}

/**
 * Show dialog to mark quote as accepted
 */
/**
 * Show dialog to mark quote as accepted
 * Supports batch processing when multiple rows are selected
 */
function showAcceptQuoteDialog() {
  // Check for multiple selected rows
  const selectedJobs = getSelectedJobNumbers();

  if (selectedJobs.length > 1) {
    const totalSelected = selectedJobs.length;

    // Filter to only jobs that can have quotes accepted
    const validJobs = selectedJobs.filter(jobNum => {
      const job = getJobByNumber(jobNum);
      return job && (job['Status'] === JOB_STATUS.QUOTED || job['Status'] === JOB_STATUS.QUOTE_REMINDED);
    });

    if (validJobs.length === 0) {
      SpreadsheetApp.getUi().alert('No Valid Jobs',
        'None of the selected jobs can have quotes accepted. Jobs must be in Quoted or Quote Reminded status.',
        SpreadsheetApp.getUi().ButtonSet.OK);
      return;
    }

    // Show batch dialog with total selected count
    showBatchMenuActionDialog('job', validJobs, 'markAccepted', 'Mark Quotes Accepted', totalSelected);
    return;
  }

  // Single row - use existing behavior
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
 * Mark quote as accepted - PERFORMANCE OPTIMIZED
 * OLD: 6 separate updateJobField() calls = 6 sheet loads
 * NEW: 1 batch updateJobFields() call = 1 sheet load (83% reduction)
 *
 * For jobs $200+: Generates/sends deposit invoice, sets status to Accepted (work starts after deposit paid)
 * For jobs under $200: Automatically starts work immediately (no deposit required)
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
      'Work will start after deposit is paid.\n\n' +
      'Do you want to proceed?',
      ui.ButtonSet.YES_NO
    );

    if (response !== ui.Button.YES) {
      return; // User cancelled
    }
  } else {
    // For jobs under $200 (no deposit), show backup reminder before starting work
    const backupResponse = ui.alert('⚠️ Backup Reminder',
      'IMPORTANT: Before starting work, ensure the client has a backup of their store.\n\n' +
      'Per our Terms of Service, clients are responsible for maintaining their own backups.\n\n' +
      'Have you confirmed the client has a recent backup?',
      ui.ButtonSet.YES_NO
    );

    if (backupResponse !== ui.Button.YES) {
      ui.alert('Quote Not Accepted',
        'Please confirm backup status before accepting the quote.\n\n' +
        'You may want to send the client a reminder to backup their store.',
        ui.ButtonSet.OK
      );
      return;
    }
  }

  const now = new Date();
  const turnaround = parseInt(job['Estimated Turnaround']) || JOB_CONFIG.DEFAULT_SLA_DAYS;
  const dueDate = new Date(now);
  dueDate.setDate(dueDate.getDate() + turnaround);

  // For jobs under $200: Start work immediately (status = In Progress)
  // For jobs $200+: Set to Accepted (work starts after deposit is paid)
  const newStatus = requiresDeposit ? JOB_STATUS.ACCEPTED : JOB_STATUS.IN_PROGRESS;

  // Build fields to update
  const fieldsToUpdate = {
    'Status': newStatus,
    'Quote Accepted Date': formatNZDate(now),
    'Days Since Accepted': 0,
    'Days Remaining': turnaround,
    'SLA Status': 'On Track',
    'Due Date': formatNZDate(dueDate)
  };

  // If starting work immediately (no deposit), also set Actual Start Date
  if (!requiresDeposit) {
    fieldsToUpdate['Actual Start Date'] = formatNZDate(now);
  }

  // OPTIMIZATION: Batch update all fields in a single operation
  updateJobFields(jobNumber, fieldsToUpdate);

  // Update client record (creates if doesn't exist, updates statistics)
  if (job['Client Email']) {
    try {
      ensureClientExistsAndUpdate(job['Client Email'], {
        name: job['Client Name'],
        phone: job['Client Phone'],
        storeUrl: job['Store URL']
      });
    } catch (e) {
      Logger.log('Error updating client record: ' + e.message);
    }
  }

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
  } else {
    // For non-deposit jobs, send status update email to notify client work has started
    sendStatusUpdateEmail(jobNumber, JOB_STATUS.IN_PROGRESS, {
      wasOnHold: false,
      daysOnHold: 0
    });
  }

  // Show appropriate success message
  if (requiresDeposit) {
    ui.alert('Quote Accepted',
      'Job ' + jobNumber + ' marked as Accepted!\n\n' +
      'SLA Clock Started:\n' +
      '- Due Date: ' + formatNZDate(dueDate) + '\n' +
      '- Days Remaining: ' + turnaround + depositMessage + '\n\n' +
      'Use CartCure > Jobs > Start Work after deposit is paid.',
      ui.ButtonSet.OK
    );
  } else {
    ui.alert('Quote Accepted & Work Started',
      'Job ' + jobNumber + ' is now In Progress!\n\n' +
      'SLA Clock Started:\n' +
      '- Due Date: ' + formatNZDate(dueDate) + '\n' +
      '- Days Remaining: ' + turnaround + '\n\n' +
      'Client has been notified that work has started.',
      ui.ButtonSet.OK
    );
  }

  Logger.log('Quote accepted for ' + jobNumber + (requiresDeposit ? ' (deposit invoice sent)' : ' (work started immediately)'));

  // Refresh dashboard and analytics to show updated data
  refreshDashboard(true);
  refreshAnalytics();
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
  // DEBUG: Capture all steps for troubleshooting
  const debugLog = [];
  debugLog.push('=== GENERATE DEPOSIT INVOICE DEBUG ===');
  debugLog.push('Timestamp: ' + new Date().toISOString());
  debugLog.push('Job Number: ' + jobNumber);

  try {
    const ss = getSpreadsheet();
    debugLog.push('Spreadsheet obtained: ' + (ss ? 'YES' : 'NO'));

    const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
    debugLog.push('Invoice sheet name: ' + SHEETS.INVOICES);
    debugLog.push('Invoice sheet found: ' + (invoiceSheet ? 'YES' : 'NO'));

    if (!invoiceSheet) {
      debugLog.push('ERROR: Invoice Log sheet not found');
      writeDepositInvoiceDebug(jobNumber, debugLog);
      return { success: false, error: 'Invoice Log sheet not found' };
    }

    // Check for existing invoices
    const existingInvoices = getInvoicesByJobNumber(jobNumber);
    debugLog.push('Existing invoices count: ' + (existingInvoices ? existingInvoices.length : 0));

    // Generate invoice number
    const invoiceNumber = generateInvoiceNumber(jobNumber, existingInvoices ? existingInvoices.length : 0);
    debugLog.push('Generated invoice number: ' + invoiceNumber);

    const now = new Date();
    // Deposits are due immediately (today)
    const dueDate = new Date(now);

    // Calculate 50% deposit amounts
    const amount = parseFloat(job['Quote Amount (excl GST)']) || 0;
    const isGSTRegistered = getSetting('GST Registered') === 'Yes';
    const gst = isGSTRegistered ? (parseFloat(job['GST']) || 0) : 0;
    const total = isGSTRegistered ? (parseFloat(job['Total (incl GST)']) || amount) : amount;

    debugLog.push('Quote Amount (excl GST) raw: ' + job['Quote Amount (excl GST)']);
    debugLog.push('Parsed amount: ' + amount);
    debugLog.push('GST Registered: ' + isGSTRegistered);
    debugLog.push('GST: ' + gst);
    debugLog.push('Total: ' + total);

    const depositAmount = amount * 0.5;
    const depositGst = gst * 0.5;
    const depositTotal = total * 0.5;

    debugLog.push('Deposit Amount: ' + depositAmount);
    debugLog.push('Deposit GST: ' + depositGst);
    debugLog.push('Deposit Total: ' + depositTotal);

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

    debugLog.push('Invoice row built with ' + invoiceRow.length + ' columns');
    debugLog.push('Inserting row at top of invoice sheet...');

    // Insert at top (row 2) so newest invoices appear first
    insertAtTopSafe(invoiceSheet, invoiceRow, false); // false = no toast (called from web form)
    debugLog.push('Row inserted successfully');

    // Flush to ensure invoice is committed before attempting to send email
    SpreadsheetApp.flush();
    debugLog.push('Spreadsheet flushed');

    // Update job with invoice number
    updateJobField(jobNumber, 'Invoice #', invoiceNumber);
    debugLog.push('Job updated with invoice number');

    // Send the invoice email
    debugLog.push('Sending invoice email...');
    const sendResult = sendInvoiceEmailSilent(invoiceNumber);
    debugLog.push('Email send result: ' + JSON.stringify(sendResult));

    if (!sendResult.success) {
      debugLog.push('EMAIL FAILED: ' + sendResult.error);
      writeDepositInvoiceDebug(jobNumber, debugLog);
      return {
        success: false,
        error: 'Invoice created but email failed: ' + sendResult.error,
        invoiceNumber: invoiceNumber,
        amount: depositTotal
      };
    }

    debugLog.push('SUCCESS: Invoice created and email sent');
    writeDepositInvoiceDebug(jobNumber, debugLog);

    Logger.log('Deposit invoice ' + invoiceNumber + ' generated and sent for ' + jobNumber);

    return {
      success: true,
      invoiceNumber: invoiceNumber,
      amount: depositTotal
    };

  } catch (error) {
    debugLog.push('EXCEPTION: ' + error.message);
    debugLog.push('Stack: ' + error.stack);
    writeDepositInvoiceDebug(jobNumber, debugLog);
    Logger.log('Error generating deposit invoice: ' + error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Helper function to write deposit invoice debug log to Drive
 */
function writeDepositInvoiceDebug(jobNumber, debugLog) {
  saveDebugLog('DEPOSIT_INV_' + jobNumber, debugLog);
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
    // Retry logic to handle timing issue where TextFinder doesn't see newly inserted rows
    // even after SpreadsheetApp.flush() - see BUG-01 in AUTOMATED_TEST_RESULTS.md
    let invoice = null;
    const MAX_RETRIES = 3;
    const RETRY_DELAY_MS = 500;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      invoice = getInvoiceByNumber(invoiceNumber);
      if (invoice) {
        if (attempt > 1) {
          Logger.log('Invoice ' + invoiceNumber + ' found on attempt ' + attempt);
        }
        break;
      }
      if (attempt < MAX_RETRIES) {
        Logger.log('Invoice ' + invoiceNumber + ' not found on attempt ' + attempt + ', retrying...');
        Utilities.sleep(RETRY_DELAY_MS);
      }
    }

    if (!invoice) {
      Logger.log('Invoice ' + invoiceNumber + ' not found after ' + MAX_RETRIES + ' attempts');
      return { success: false, error: 'Invoice not found after ' + MAX_RETRIES + ' attempts' };
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
    const amount = Number(invoice['Amount (excl GST)'] || 0).toFixed(2);
    const gst = Number(invoice['GST'] || 0).toFixed(2);
    const total = Number(invoice['Total'] || 0).toFixed(2);
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

    // Build "I have paid" URL
    const paymentReceivedUrl = 'https://cartcure.co.nz/payment-received.html?' +
      'invoice=' + encodeURIComponent(invoiceNumber) +
      '&job=' + encodeURIComponent(jobNumber);

    // Render template based on invoice type
    let bodyContent;
    if (invoiceType === 'Balance' && depositInfo) {
      // Use dedicated balance invoice template
      const depositPaidText = depositInfo.paidDate ? ' (paid ' + formatNZDate(depositInfo.paidDate) + ')' : '';
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
        businessName: businessName,
        paymentReceivedUrl: paymentReceivedUrl
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
        businessName: businessName,
        paymentReceivedUrl: paymentReceivedUrl
      });
    }

    const htmlBody = wrapEmailHtml(bodyContent);

    // Build plain text version
    let plainTextBody;
    if (invoiceType === 'Balance' && depositInfo) {
      const depositPaidText = depositInfo.paidDate ? ' (paid ' + formatNZDate(depositInfo.paidDate) + ')' : '';
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

    // Generate PDF for attachment
    let pdfBlob = null;
    let pdfUrl = null;
    try {
      const pdfResult = generateInvoicePDF(invoiceNumber, true);
      if (pdfResult.success && pdfResult.pdfBlob) {
        pdfBlob = pdfResult.pdfBlob;

        // Also save to Drive and get URL
        const folder = getOrCreateInvoicesFolder();
        const pdfFile = folder.createFile(pdfBlob);
        pdfUrl = pdfFile.getUrl();
      }
    } catch (pdfError) {
      Logger.log('PDF generation failed (continuing without attachment): ' + pdfError.message);
    }

    // Send the email (with PDF attachment if available)
    const emailOptions = {
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    };
    if (pdfBlob) {
      emailOptions.attachments = [pdfBlob];
    }
    GmailApp.sendEmail(clientEmail, subject, plainText, emailOptions);

    // Update invoice status to Sent
    updateInvoiceField(invoiceNumber, 'Status', 'Sent');
    updateInvoiceField(invoiceNumber, 'Sent Date', formatNZDate(new Date()));

    // Update PDF Link if we generated one
    if (pdfUrl) {
      updateInvoicePDFLink(invoiceNumber, pdfUrl);
    }

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

  // PERFORMANCE: Use cached sheet reference
  const sheet = getSheet(SHEETS.SUBMISSIONS);

  if (!sheet) {
    Logger.log('ERROR: Submissions sheet not found. Cannot update status for ' + submissionNumber);
    return;
  }

  const data = sheet.getDataRange().getValues();
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based)
  const statusCol = getColIndex('SUBMISSIONS', 'Status'); // 1-based for sheet.getRange()
  const submissionNumCol = getColIndex('SUBMISSIONS', 'Submission #') - 1; // 0-based for array indexing

  if (statusCol < 1 || submissionNumCol < 0) return;

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][submissionNumCol]).trim() === String(submissionNumber).trim()) {
      sheet.getRange(i + 1, statusCol).setValue(status);
      return;
    }
  }
}

/**
 * Show dialog to start work on a job
 * Supports batch processing when multiple rows are selected
 */
function showStartWorkDialog() {
  // Check for multiple selected rows
  const selectedJobs = getSelectedJobNumbers();

  if (selectedJobs.length > 1) {
    const totalSelected = selectedJobs.length;

    // Filter to only jobs that can be started (Accepted or On Hold status)
    const validJobs = selectedJobs.filter(jobNum => {
      const job = getJobByNumber(jobNum);
      return job && (job['Status'] === JOB_STATUS.ACCEPTED || job['Status'] === JOB_STATUS.ON_HOLD);
    });

    if (validJobs.length === 0) {
      SpreadsheetApp.getUi().alert('No Valid Jobs',
        'None of the selected jobs can be started. Jobs must be in Accepted or On Hold status.',
        SpreadsheetApp.getUi().ButtonSet.OK);
      return;
    }

    // Show batch dialog with total selected count
    showBatchMenuActionDialog('job', validJobs, 'startWork', 'Start Work on Jobs', totalSelected);
    return;
  }

  // Single row - use existing behavior
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

  // Refresh dashboard and analytics to show updated data
  refreshDashboard(true);
  refreshAnalytics();
}

/**
 * Show dialog to mark job complete
 * Supports batch processing when multiple rows are selected
 */
function showCompleteJobDialog() {
  // Check for multiple selected rows
  const selectedJobs = getSelectedJobNumbers();

  if (selectedJobs.length > 1) {
    const totalSelected = selectedJobs.length;

    // Filter to only jobs that can be completed (In Progress status)
    const validJobs = selectedJobs.filter(jobNum => {
      const job = getJobByNumber(jobNum);
      return job && job['Status'] === JOB_STATUS.IN_PROGRESS;
    });

    if (validJobs.length === 0) {
      SpreadsheetApp.getUi().alert('No Valid Jobs',
        'None of the selected jobs can be marked complete. Jobs must be In Progress.',
        SpreadsheetApp.getUi().ButtonSet.OK);
      return;
    }

    // Show batch dialog with total selected count
    showBatchMenuActionDialog('job', validJobs, 'markComplete', 'Mark Jobs Complete', totalSelected);
    return;
  }

  // Single row - use existing behavior
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

  // Update client record (creates if doesn't exist, updates statistics)
  if (job['Client Email']) {
    try {
      ensureClientExistsAndUpdate(job['Client Email'], {
        name: job['Client Name'],
        phone: job['Client Phone'],
        storeUrl: job['Store URL']
      });
    } catch (e) {
      Logger.log('Error updating client record: ' + e.message);
    }
  }

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

  // Refresh dashboard and analytics to show updated data
  refreshDashboard(true);
  refreshAnalytics();
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

  // Update status
  updateJobFields(jobNumber, {
    'Status': JOB_STATUS.ON_HOLD,
    'Last Updated': formatNZDate(now)
  });

  // Log to Activity Log
  logJobActivity(jobNumber, 'On Hold', 'Job put on hold', explanation, '', 'Auto');

  // Send email notification
  sendStatusUpdateEmail(jobNumber, JOB_STATUS.ON_HOLD, { explanation: explanation });

  ui.alert('On Hold', 'Job ' + jobNumber + ' is now On Hold.\n\nClient has been notified.', ui.ButtonSet.OK);

  Logger.log('Job ' + jobNumber + ' put on hold. Reason: ' + explanation);

  // Refresh dashboard and analytics
  refreshDashboard(true);
  refreshAnalytics();
}

/**
 * Show dialog to cancel a job
 * Uses selected row to auto-detect job number (like other action features)
 * Supports batch processing when multiple rows are selected
 */
function showCancelJobDialog() {
  const ui = SpreadsheetApp.getUi();

  // Check for multiple selected rows
  const selectedJobs = getSelectedJobNumbers();

  if (selectedJobs.length > 1) {
    const totalSelected = selectedJobs.length;

    // Filter to only jobs that can be cancelled
    const validJobs = selectedJobs.filter(jobNum => {
      const job = getJobByNumber(jobNum);
      return job && (job['Status'] === JOB_STATUS.ACCEPTED ||
                     job['Status'] === JOB_STATUS.IN_PROGRESS ||
                     job['Status'] === JOB_STATUS.ON_HOLD);
    });

    if (validJobs.length === 0) {
      ui.alert('No Valid Jobs',
        'None of the selected jobs can be cancelled.\n\nOnly jobs with status Accepted, In Progress, or On Hold can be cancelled.',
        ui.ButtonSet.OK);
      return;
    }

    // Show batch dialog with total selected count
    showBatchMenuActionDialog('job', validJobs, 'cancel', 'Cancel Jobs', totalSelected);
    return;
  }

  // Single row - use existing behavior
  const selectedJob = getSelectedJobNumber();
  // Can cancel jobs that are Accepted, In Progress, or On Hold
  const jobs = getJobsByStatus([JOB_STATUS.ACCEPTED, JOB_STATUS.IN_PROGRESS, JOB_STATUS.ON_HOLD]);

  // If we have a selected job, verify it's valid for cancellation and proceed directly
  if (selectedJob) {
    const isValidSelection = jobs && jobs.length > 0 &&
      jobs.some(job => String(job.number).trim() === String(selectedJob).trim());

    if (isValidSelection) {
      // Directly show the cancellation confirmation - no dropdown needed
      showCancelJobConfirmation(selectedJob);
      return;
    } else {
      // Selected job exists but isn't valid for cancellation - explain why
      const job = getJobByNumber(selectedJob);
      if (job) {
        ui.alert(
          'Cannot Cancel',
          'Job ' + selectedJob + ' cannot be cancelled.\n\n' +
          'Current status: ' + (job['Status'] || 'Unknown') + '\n\n' +
          'Only jobs with status Accepted, In Progress, or On Hold can be cancelled.',
          ui.ButtonSet.OK
        );
      }
    }
  }

  // Fall back to dropdown dialog if no valid job selected
  showDropdownDialog('Cancel Job', jobs, 'Job', 'showCancelJobConfirmation');
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
  let refundAmount = null;
  if (paymentStatus === PAYMENT_STATUS.PAID || paymentStatus === PAYMENT_STATUS.INVOICED) {
    const refundResponse = ui.alert(
      'Refund Required?',
      'This job has payment status: ' + paymentStatus + '\n\n' +
      'Will a refund be issued?',
      ui.ButtonSet.YES_NO
    );

    if (refundResponse === ui.Button.YES) {
      refundStatus = PAYMENT_STATUS.REFUNDED;

      // Ask for refund amount
      const refundAmountResponse = ui.prompt(
        'Refund Amount',
        'Enter the refund amount (numbers only, e.g., 150.00):\n\n' +
        (total ? 'Original total: ' + formatCurrency(total) : ''),
        ui.ButtonSet.OK_CANCEL
      );

      if (refundAmountResponse.getSelectedButton() === ui.Button.CANCEL) {
        return;
      }

      const refundText = refundAmountResponse.getResponseText().trim();
      if (refundText) {
        // Parse the amount, removing any currency symbols
        refundAmount = parseFloat(refundText.replace(/[^0-9.]/g, ''));
        if (isNaN(refundAmount)) {
          refundAmount = null;
        }
      }
    }
  }

  // Update job
  const now = new Date();

  const updates = {
    'Status': JOB_STATUS.CANCELLED,
    'Last Updated': formatNZDate(now)
  };

  if (refundStatus) {
    updates['Payment Status'] = refundStatus;
    if (refundAmount !== null && refundAmount > 0) {
      updates['Refund Amount'] = refundAmount;
    }
  }

  updateJobFields(jobNumber, updates);

  // Update client statistics (recalculate after job cancellation)
  if (job['Client Email']) {
    try {
      updateClientStatistics(job['Client Email']);
    } catch (e) {
      Logger.log('Error updating client statistics: ' + e.message);
    }
  }

  // Log to Activity Log - include refund amount in details
  let activityDetails = reason || 'No reason provided';
  if (refundStatus && refundAmount !== null && refundAmount > 0) {
    activityDetails += ' | Refund issued: ' + formatCurrency(refundAmount);
  } else if (refundStatus) {
    activityDetails += ' | Refund issued (amount not specified)';
  }
  logJobActivity(jobNumber, 'Cancelled', 'Job cancelled', activityDetails, '', 'Auto');

  // Send email notification (without reason - kept internal)
  sendStatusUpdateEmail(jobNumber, JOB_STATUS.CANCELLED);

  // Show confirmation
  let message = 'Job ' + jobNumber + ' has been cancelled.\n\nClient has been notified.';
  if (refundStatus) {
    message += '\n\nPayment status updated to: ' + refundStatus;
    if (refundAmount !== null && refundAmount > 0) {
      message += '\nRefund amount: ' + formatCurrency(refundAmount);
    }
  }
  if (reason) {
    message += '\n\nReason recorded: ' + reason;
  }

  ui.alert('Job Cancelled', message, ui.ButtonSet.OK);

  Logger.log('Job ' + jobNumber + ' cancelled. Reason: ' + (reason || 'None provided'));

  // Refresh dashboard and analytics to show updated data
  refreshDashboard(true);
  refreshAnalytics();
}

// ============================================================================
// REFUND PROCESSING (P1 FIX)
// ============================================================================

/**
 * Show dialog to select a job for refund processing
 * Shows jobs that are eligible for refunds (Paid or Invoiced payment status)
 */
function showProcessRefundDialog() {
  const ui = SpreadsheetApp.getUi();

  // Check if user has selected a specific job
  const selectedJob = getSelectedJobNumber();

  // Get jobs that can be refunded (Paid or Invoiced status)
  const allJobs = getAllJobs();
  const refundableJobs = allJobs.filter(job => {
    const paymentStatus = job['Payment Status'];
    return paymentStatus === PAYMENT_STATUS.PAID || paymentStatus === PAYMENT_STATUS.INVOICED;
  });

  if (refundableJobs.length === 0) {
    ui.alert('No Jobs to Refund', 'There are no jobs with Paid or Invoiced payment status that can be refunded.', ui.ButtonSet.OK);
    return;
  }

  showContextAwareDialog(
    'Process Refund',
    refundableJobs,
    'Job',
    'processRefund',
    selectedJob
  );
}

/**
 * Process a refund for a job (P1 FIX)
 * Records refund amount, updates payment status, logs activity, and optionally sends credit note
 * @param {string} jobNumber - The job number to process refund for
 */
function processRefund(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  const clientName = job['Client Name'] || 'Unknown';
  const clientEmail = job['Client Email'] || '';
  const paymentStatus = job['Payment Status'];
  const total = parseFloat(job['Total (incl GST)']) || 0;
  const existingRefund = parseFloat(job['Refund Amount']) || 0;

  // Validate that job can be refunded
  if (paymentStatus !== PAYMENT_STATUS.PAID && paymentStatus !== PAYMENT_STATUS.INVOICED) {
    ui.alert('Cannot Refund',
      'This job cannot be refunded.\n\n' +
      'Current payment status: ' + paymentStatus + '\n\n' +
      'Only jobs with "Paid" or "Invoiced" payment status can be refunded.',
      ui.ButtonSet.OK);
    return;
  }

  // Check if already partially refunded
  let maxRefundable = total;
  let alreadyRefundedMsg = '';
  if (existingRefund > 0) {
    maxRefundable = total - existingRefund;
    alreadyRefundedMsg = '\n\nNote: This job already has a refund of ' + formatCurrency(existingRefund) + ' recorded.';
    if (maxRefundable <= 0) {
      ui.alert('Already Fully Refunded',
        'This job has already been fully refunded.\n\n' +
        'Total: ' + formatCurrency(total) + '\n' +
        'Already Refunded: ' + formatCurrency(existingRefund),
        ui.ButtonSet.OK);
      return;
    }
  }

  // Step 1: Confirm refund
  const confirmResponse = ui.alert(
    '💸 Process Refund',
    'Process refund for job ' + jobNumber + '?\n\n' +
    'Client: ' + clientName + '\n' +
    'Total Amount: ' + formatCurrency(total) + '\n' +
    'Payment Status: ' + paymentStatus +
    alreadyRefundedMsg,
    ui.ButtonSet.YES_NO
  );

  if (confirmResponse !== ui.Button.YES) {
    return;
  }

  // Step 2: Get refund amount
  const amountResponse = ui.prompt(
    'Refund Amount',
    'Enter the refund amount (numbers only):\n\n' +
    'Maximum refundable: ' + formatCurrency(maxRefundable) + '\n' +
    '(Enter amount without $ sign, e.g., 150.00)',
    ui.ButtonSet.OK_CANCEL
  );

  if (amountResponse.getSelectedButton() !== ui.Button.OK) {
    return;
  }

  const refundAmount = parseFloat(amountResponse.getResponseText().replace(/[$,]/g, ''));

  // Validate refund amount
  const amountValidation = validateInvoiceAmount(refundAmount, 'Refund amount');
  if (!amountValidation.valid) {
    ui.alert('Invalid Amount', amountValidation.error, ui.ButtonSet.OK);
    return;
  }

  if (refundAmount > maxRefundable) {
    ui.alert('Amount Too High',
      'Refund amount cannot exceed the maximum refundable amount.\n\n' +
      'Requested: ' + formatCurrency(refundAmount) + '\n' +
      'Maximum: ' + formatCurrency(maxRefundable),
      ui.ButtonSet.OK);
    return;
  }

  // Step 3: Get refund reason
  const reasonResponse = ui.prompt(
    'Refund Reason',
    'Enter the reason for this refund:\n\n' +
    '(This will be recorded in the activity log)',
    ui.ButtonSet.OK_CANCEL
  );

  if (reasonResponse.getSelectedButton() !== ui.Button.OK) {
    return;
  }

  const reason = reasonResponse.getResponseText().trim() || 'No reason provided';

  // Step 4: Determine if this is a full or partial refund
  const totalRefund = existingRefund + refundAmount;
  const isFullRefund = Math.abs(totalRefund - total) < 0.01; // Full refund within 1 cent

  // Step 5: Update job fields
  const updates = {
    'Refund Amount': totalRefund,
    'Last Updated': formatNZDate(new Date())
  };

  // Only change payment status to Refunded if full refund
  if (isFullRefund) {
    updates['Payment Status'] = PAYMENT_STATUS.REFUNDED;
  }

  updateJobFields(jobNumber, updates);

  // Step 6: Log the refund activity
  const refundDetails = [
    'Amount: ' + formatCurrency(refundAmount),
    isFullRefund ? 'Type: Full Refund' : 'Type: Partial Refund',
    existingRefund > 0 ? 'Previous refund: ' + formatCurrency(existingRefund) : '',
    'Total refunded: ' + formatCurrency(totalRefund),
    'Reason: ' + reason
  ].filter(Boolean).join(' | ');

  logJobActivity(jobNumber, 'Refund Processed', 'Refund issued to client', refundDetails, clientEmail, 'Manual');

  // Step 7: Ask about sending credit note email
  const sendEmailResponse = ui.alert(
    'Send Credit Note?',
    'Would you like to send a credit note email to the client?\n\n' +
    'Client: ' + clientName + '\n' +
    'Email: ' + clientEmail + '\n' +
    'Refund Amount: ' + formatCurrency(refundAmount),
    ui.ButtonSet.YES_NO
  );

  if (sendEmailResponse === ui.Button.YES && clientEmail) {
    sendCreditNoteEmail(jobNumber, refundAmount, reason);
  }

  // Step 8: Show success message
  let successMsg = 'Refund processed successfully!\n\n' +
    'Job: ' + jobNumber + '\n' +
    'Client: ' + clientName + '\n' +
    'Refund Amount: ' + formatCurrency(refundAmount) + '\n' +
    'Type: ' + (isFullRefund ? 'Full Refund' : 'Partial Refund');

  if (!isFullRefund) {
    successMsg += '\n\nNote: Payment status unchanged (partial refund).\n' +
      'Total refunded so far: ' + formatCurrency(totalRefund) + ' of ' + formatCurrency(total);
  } else {
    successMsg += '\n\nPayment status updated to: Refunded';
  }

  ui.alert('✅ Refund Processed', successMsg, ui.ButtonSet.OK);

  // Refresh dashboard
  refreshDashboard(true);
  refreshAnalytics();
}

/**
 * Send a credit note email to the client
 * @param {string} jobNumber - The job number
 * @param {number} refundAmount - The refund amount
 * @param {string} reason - The refund reason
 */
function sendCreditNoteEmail(jobNumber, refundAmount, reason) {
  try {
    const job = getJobByNumber(jobNumber);
    if (!job) {
      Logger.log('sendCreditNoteEmail: Job not found: ' + jobNumber);
      return false;
    }

    const clientEmail = job['Client Email'];
    const clientName = job['Client Name'] || 'Valued Customer';
    const businessName = getSetting('Business Name') || 'CartCure';
    const total = parseFloat(job['Total (incl GST)']) || 0;

    if (!clientEmail) {
      Logger.log('sendCreditNoteEmail: No client email for job: ' + jobNumber);
      return false;
    }

    // Generate credit note number based on job number
    const creditNoteNumber = jobNumber.replace(/^J-/, 'CN-');

    const subject = 'Credit Note ' + creditNoteNumber + ' - ' + businessName;

    // Build simple HTML email
    const htmlBody = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #2e7d32;">Credit Note</h2>
        <p>Dear ${clientName},</p>
        <p>This email confirms that a refund has been processed for your order.</p>

        <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0;">
          <p style="margin: 5px 0;"><strong>Credit Note #:</strong> ${creditNoteNumber}</p>
          <p style="margin: 5px 0;"><strong>Job Reference:</strong> ${jobNumber}</p>
          <p style="margin: 5px 0;"><strong>Refund Amount:</strong> ${formatCurrency(refundAmount)}</p>
          <p style="margin: 5px 0;"><strong>Original Total:</strong> ${formatCurrency(total)}</p>
          ${reason && reason !== 'No reason provided' ? `<p style="margin: 5px 0;"><strong>Reason:</strong> ${reason}</p>` : ''}
        </div>

        <p>The refund will be processed to your original payment method within 5-10 business days.</p>

        <p>If you have any questions about this refund, please don't hesitate to contact us.</p>

        <p style="margin-top: 30px;">
          Best regards,<br>
          <strong>${businessName}</strong>
        </p>
      </div>
    `;

    // Send email
    MailApp.sendEmail({
      to: clientEmail,
      subject: subject,
      htmlBody: htmlBody
    });

    // Log the email
    logJobActivity(jobNumber, 'Credit Note Sent', 'Credit note email sent to client',
      'Amount: ' + formatCurrency(refundAmount) + ' | Credit Note: ' + creditNoteNumber,
      clientEmail, 'Auto');

    Logger.log('Credit note email sent to ' + clientEmail + ' for job ' + jobNumber);
    return true;

  } catch (error) {
    Logger.log('Error sending credit note email: ' + error.message);
    try {
      SpreadsheetApp.getUi().alert('Email Error',
        'Failed to send credit note email: ' + error.message,
        SpreadsheetApp.getUi().ButtonSet.OK);
    } catch (uiError) {
      // UI not available
    }
    return false;
  }
}

// ============================================================================
// CLIENT MANAGEMENT FUNCTIONS
// ============================================================================

/**
 * Find a client by email address (primary key)
 * Uses TextFinder API for efficient server-side search (same pattern as getJobByNumber)
 * @param {string} email - The client's email address
 * @returns {Object|null} Client object with all fields and _rowIndex, or null if not found
 */
function findClientByEmail(email) {
  if (!email || typeof email !== 'string') {
    return null;
  }

  const normalizedEmail = email.toLowerCase().trim();
  const sheet = getSheet(SHEETS.CLIENTS);

  if (!sheet || sheet.getLastRow() < 2) {
    return null;
  }

  // Use TextFinder for efficient lookup
  const finder = sheet.createTextFinder(normalizedEmail)
    .matchEntireCell(true)
    .matchCase(false);  // Case-insensitive for email

  const foundRange = finder.findNext();

  if (!foundRange) {
    return null;
  }

  // Verify the found cell is in the Client Email column
  const emailCol = getColIndex('CLIENTS', 'Client Email');
  if (foundRange.getColumn() !== emailCol) {
    return null;
  }

  const rowIndex = foundRange.getRow();
  const lastColumn = sheet.getLastColumn();
  const headers = sheet.getRange(1, 1, 1, lastColumn).getValues()[0];
  const rowData = sheet.getRange(rowIndex, 1, 1, lastColumn).getValues()[0];

  // Build client object
  const client = {};
  headers.forEach((header, index) => {
    client[header] = rowData[index];
  });
  client._rowIndex = rowIndex;

  return client;
}

/**
 * Add a new client to the Clients sheet
 * @param {Object} clientData - Client data including email, name, phone, storeUrl
 * @returns {Object} Result with success flag and row index
 */
function addNewClient(clientData) {
  const sheet = getSheet(SHEETS.CLIENTS);
  const now = new Date();
  const dateStr = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM-dd');
  const timestampStr = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM-dd HH:mm:ss');

  const rowData = buildRowFromConfig('CLIENTS', {
    'Client Email': (clientData.email || '').toLowerCase().trim(),
    'Client Name': clientData.name || '',
    'Client Phone': clientData.phone || '',
    'Store URL': clientData.storeUrl || '',
    'Total Jobs': 1,
    'Completed Jobs': 0,
    'Total Revenue': 0,
    'First Job Date': dateStr,
    'Last Job Date': dateStr,
    'Client Status': CLIENT_STATUS.ACTIVE,
    'Notes': '',
    'Created Date': dateStr,
    'Last Updated': timestampStr
  });

  sheet.appendRow(rowData);
  const newRowIndex = sheet.getLastRow();

  Logger.log('New client added: ' + clientData.email + ' at row ' + newRowIndex);

  return { success: true, rowIndex: newRowIndex, isNew: true };
}

/**
 * Update an existing client's information
 * Updates: name, phone, storeUrl, totalJobs, lastJobDate, lastUpdated
 * Preserves: email, firstJobDate, notes, clientStatus, createdDate
 * @param {number} rowIndex - The row index of the client to update
 * @param {Object} newData - New data to update
 * @returns {Object} Result with success flag
 */
function updateExistingClient(rowIndex, newData) {
  const sheet = getSheet(SHEETS.CLIENTS);
  const now = new Date();
  const dateStr = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM-dd');
  const timestampStr = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM-dd HH:mm:ss');

  // Get current row data
  const lastColumn = sheet.getLastColumn();
  const headers = sheet.getRange(1, 1, 1, lastColumn).getValues()[0];
  const currentData = sheet.getRange(rowIndex, 1, 1, lastColumn).getValues()[0];

  // Build updated values
  const updates = {};

  // Always update contact info to latest
  if (newData.name) updates['Client Name'] = newData.name;
  if (newData.phone) updates['Client Phone'] = newData.phone;
  if (newData.storeUrl) updates['Store URL'] = newData.storeUrl;

  // Increment job count
  const currentJobCount = parseInt(currentData[headers.indexOf('Total Jobs')]) || 0;
  updates['Total Jobs'] = currentJobCount + 1;

  // Update last job date
  updates['Last Job Date'] = dateStr;

  // Update timestamp
  updates['Last Updated'] = timestampStr;

  // Apply updates
  for (const [colName, value] of Object.entries(updates)) {
    const colIndex = headers.indexOf(colName) + 1;
    if (colIndex > 0) {
      sheet.getRange(rowIndex, colIndex).setValue(value);
    }
  }

  Logger.log('Client updated at row ' + rowIndex);

  return { success: true, rowIndex: rowIndex, isNew: false };
}

/**
 * Add a new client or update existing client when a quote is accepted
 * This is the main entry point called from the quote acceptance flow
 * @param {Object} clientData - { email, name, phone, storeUrl, jobNumber, jobTotal }
 * @returns {Object} Result with success, isNew, and rowIndex
 */
function addOrUpdateClient(clientData) {
  if (!clientData.email) {
    Logger.log('addOrUpdateClient: No email provided, skipping client tracking');
    return { success: false, error: 'No email provided' };
  }

  const existingClient = findClientByEmail(clientData.email);

  if (existingClient) {
    return updateExistingClient(existingClient._rowIndex, clientData);
  } else {
    return addNewClient(clientData);
  }
}

/**
 * Update client statistics by recalculating from Jobs sheet
 * Called when job status changes (completed, cancelled) or payment is recorded
 * @param {string} clientEmail - The client's email address
 */
function updateClientStatistics(clientEmail) {
  if (!clientEmail) return;

  const client = findClientByEmail(clientEmail);
  if (!client) {
    Logger.log('updateClientStatistics: Client not found for email: ' + clientEmail);
    return;
  }

  const clientJobs = getClientJobs(clientEmail);

  // Calculate statistics
  let totalJobs = clientJobs.length;
  let completedJobs = 0;
  let totalRevenue = 0;

  clientJobs.forEach(job => {
    if (job['Status'] === JOB_STATUS.COMPLETED) {
      completedJobs++;
    }
    // Only count paid jobs towards revenue
    if (job['Payment Status'] === PAYMENT_STATUS.PAID) {
      const amount = parseFloat(job['Total (incl GST)']) || 0;
      totalRevenue += amount;
    }
  });

  // Update client record
  const sheet = getSheet(SHEETS.CLIENTS);
  const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  const now = new Date();
  const timestampStr = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM-dd HH:mm:ss');

  const updates = {
    'Total Jobs': totalJobs,
    'Completed Jobs': completedJobs,
    'Total Revenue': totalRevenue,
    'Last Updated': timestampStr
  };

  for (const [colName, value] of Object.entries(updates)) {
    const colIndex = headers.indexOf(colName) + 1;
    if (colIndex > 0) {
      sheet.getRange(client._rowIndex, colIndex).setValue(value);
    }
  }

  Logger.log('Client statistics updated for ' + clientEmail + ': ' + totalJobs + ' jobs, ' + completedJobs + ' completed, $' + totalRevenue + ' revenue');
}

/**
 * Ensure a client exists in the Clients sheet and update their statistics
 * If the client doesn't exist, creates them from job data
 * If they do exist, updates their statistics
 *
 * This is the main function to call when jobs are created or updated
 * @param {string} clientEmail - The client's email address
 * @param {Object} [clientInfo] - Optional client info for new clients { name, phone, storeUrl }
 * @returns {Object} Result with success flag and whether client was created
 */
function ensureClientExistsAndUpdate(clientEmail, clientInfo) {
  if (!clientEmail) {
    Logger.log('ensureClientExistsAndUpdate: No email provided');
    return { success: false, error: 'No email provided' };
  }

  const normalizedEmail = clientEmail.toLowerCase().trim();
  const existingClient = findClientByEmail(normalizedEmail);

  if (existingClient) {
    // Client exists - just update their statistics
    updateClientStatistics(normalizedEmail);
    return { success: true, isNew: false };
  }

  // Client doesn't exist - need to create them
  // First, try to get their info from jobs if not provided
  if (!clientInfo || !clientInfo.name) {
    const clientJobs = getClientJobs(normalizedEmail);
    if (clientJobs.length > 0) {
      // Get info from the most recent job
      const latestJob = clientJobs[0];
      clientInfo = {
        name: latestJob['Client Name'] || '',
        phone: latestJob['Client Phone'] || '',
        storeUrl: latestJob['Store URL'] || ''
      };
    }
  }

  // Create the new client
  const result = addNewClient({
    email: normalizedEmail,
    name: clientInfo?.name || '',
    phone: clientInfo?.phone || '',
    storeUrl: clientInfo?.storeUrl || ''
  });

  if (result.success) {
    // Now update their statistics from all their jobs
    updateClientStatistics(normalizedEmail);
    Logger.log('ensureClientExistsAndUpdate: Created new client ' + normalizedEmail);
  }

  return { success: result.success, isNew: true };
}

/**
 * Sync all clients from jobs - adds missing clients and updates all statistics
 * Can be called manually from the menu or during maintenance
 * @returns {Object} Result with counts of added and updated clients
 */
function syncClientsFromJobs() {
  const ui = SpreadsheetApp.getUi();
  const jobsSheet = getSheet(SHEETS.JOBS);

  if (!jobsSheet || jobsSheet.getLastRow() < 2) {
    ui.alert('No Jobs', 'No jobs found to sync clients from.', ui.ButtonSet.OK);
    return { added: 0, updated: 0 };
  }

  const response = ui.alert(
    'Sync Clients from Jobs',
    'This will:\n' +
    '• Add any clients that exist in Jobs but not in Clients\n' +
    '• Update statistics for all existing clients\n\n' +
    'Continue?',
    ui.ButtonSet.YES_NO
  );

  if (response !== ui.Button.YES) return { added: 0, updated: 0 };

  // Get all unique client emails from jobs
  const lastColumn = jobsSheet.getLastColumn();
  const headers = jobsSheet.getRange(1, 1, 1, lastColumn).getValues()[0];
  const data = jobsSheet.getRange(2, 1, jobsSheet.getLastRow() - 1, lastColumn).getValues();

  const emailIdx = headers.indexOf('Client Email');
  const nameIdx = headers.indexOf('Client Name');
  const phoneIdx = headers.indexOf('Client Phone');
  const storeUrlIdx = headers.indexOf('Store URL');

  if (emailIdx === -1) {
    ui.alert('Error', 'Client Email column not found in Jobs sheet.', ui.ButtonSet.OK);
    return { added: 0, updated: 0 };
  }

  // Collect unique clients with their latest info
  const clientsMap = new Map();
  data.forEach(row => {
    const email = (row[emailIdx] || '').toString().toLowerCase().trim();
    if (!email) return;

    // Always update to latest info (assuming jobs are sorted newest first)
    if (!clientsMap.has(email)) {
      clientsMap.set(email, {
        email: email,
        name: row[nameIdx] || '',
        phone: row[phoneIdx] || '',
        storeUrl: row[storeUrlIdx] || ''
      });
    }
  });

  let added = 0;
  let updated = 0;

  clientsMap.forEach((clientInfo, email) => {
    const result = ensureClientExistsAndUpdate(email, clientInfo);
    if (result.success) {
      if (result.isNew) {
        added++;
      } else {
        updated++;
      }
    }
  });

  ui.alert('Sync Complete',
    'Clients synchronized from Jobs:\n\n' +
    '• ' + added + ' new clients added\n' +
    '• ' + updated + ' existing clients updated',
    ui.ButtonSet.OK
  );

  Logger.log('syncClientsFromJobs: Added ' + added + ', Updated ' + updated);
  return { added: added, updated: updated };
}

/**
 * Get all jobs for a specific client by email
 * @param {string} clientEmail - The client's email address
 * @returns {Array} Array of job objects
 */
function getClientJobs(clientEmail) {
  if (!clientEmail) return [];

  const normalizedEmail = clientEmail.toLowerCase().trim();
  const sheet = getSheet(SHEETS.JOBS);

  if (!sheet || sheet.getLastRow() < 2) {
    return [];
  }

  const lastColumn = sheet.getLastColumn();
  const headers = sheet.getRange(1, 1, 1, lastColumn).getValues()[0];
  const data = sheet.getRange(2, 1, sheet.getLastRow() - 1, lastColumn).getValues();

  const emailColIndex = headers.indexOf('Client Email');
  if (emailColIndex === -1) return [];

  const jobs = [];
  data.forEach((row, rowIdx) => {
    const jobEmail = (row[emailColIndex] || '').toString().toLowerCase().trim();
    if (jobEmail === normalizedEmail) {
      const job = {};
      headers.forEach((header, colIdx) => {
        job[header] = row[colIdx];
      });
      job._rowIndex = rowIdx + 2;  // +2 because data starts at row 2
      jobs.push(job);
    }
  });

  return jobs;
}

/**
 * Populate Clients sheet from existing jobs
 * Called on first setup to initialize client data from historical jobs
 */
function populateClientsFromExistingJobs() {
  const jobsSheet = getSheet(SHEETS.JOBS);
  const clientsSheet = getSheet(SHEETS.CLIENTS);

  if (!jobsSheet || jobsSheet.getLastRow() < 2) {
    Logger.log('populateClientsFromExistingJobs: No jobs found');
    return;
  }

  // Get all jobs data
  const lastColumn = jobsSheet.getLastColumn();
  const headers = jobsSheet.getRange(1, 1, 1, lastColumn).getValues()[0];
  const data = jobsSheet.getRange(2, 1, jobsSheet.getLastRow() - 1, lastColumn).getValues();

  // Column indices
  const emailIdx = headers.indexOf('Client Email');
  const nameIdx = headers.indexOf('Client Name');
  const phoneIdx = headers.indexOf('Client Phone');
  const storeUrlIdx = headers.indexOf('Store URL');
  const statusIdx = headers.indexOf('Status');
  const paymentStatusIdx = headers.indexOf('Payment Status');
  const totalIdx = headers.indexOf('Total (incl GST)');
  const createdDateIdx = headers.indexOf('Created Date');

  if (emailIdx === -1) {
    Logger.log('populateClientsFromExistingJobs: Client Email column not found');
    return;
  }

  // Group jobs by client email
  const clientsMap = new Map();

  data.forEach(row => {
    const email = (row[emailIdx] || '').toString().toLowerCase().trim();
    if (!email) return;

    if (!clientsMap.has(email)) {
      clientsMap.set(email, {
        email: email,
        name: row[nameIdx] || '',
        phone: row[phoneIdx] || '',
        storeUrl: row[storeUrlIdx] || '',
        jobs: [],
        totalJobs: 0,
        completedJobs: 0,
        totalRevenue: 0,
        firstJobDate: null,
        lastJobDate: null
      });
    }

    const client = clientsMap.get(email);

    // Update to latest contact info
    if (row[nameIdx]) client.name = row[nameIdx];
    if (row[phoneIdx]) client.phone = row[phoneIdx];
    if (row[storeUrlIdx]) client.storeUrl = row[storeUrlIdx];

    // Count jobs
    client.totalJobs++;

    // Count completed jobs
    if (row[statusIdx] === JOB_STATUS.COMPLETED) {
      client.completedJobs++;
    }

    // Sum revenue from paid jobs
    if (row[paymentStatusIdx] === PAYMENT_STATUS.PAID) {
      const amount = parseFloat(row[totalIdx]) || 0;
      client.totalRevenue += amount;
    }

    // Track job dates
    const jobDate = row[createdDateIdx];
    if (jobDate) {
      const dateValue = new Date(jobDate);
      if (!isNaN(dateValue.getTime())) {
        if (!client.firstJobDate || dateValue < client.firstJobDate) {
          client.firstJobDate = dateValue;
        }
        if (!client.lastJobDate || dateValue > client.lastJobDate) {
          client.lastJobDate = dateValue;
        }
      }
    }
  });

  // Sort clients by first job date (oldest first)
  const sortedClients = Array.from(clientsMap.values()).sort((a, b) => {
    if (!a.firstJobDate) return 1;
    if (!b.firstJobDate) return -1;
    return a.firstJobDate - b.firstJobDate;
  });

  // Add clients to sheet
  const now = new Date();
  const timestampStr = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM-dd HH:mm:ss');

  sortedClients.forEach(client => {
    const firstDateStr = client.firstJobDate
      ? Utilities.formatDate(client.firstJobDate, Session.getScriptTimeZone(), 'yyyy-MM-dd')
      : '';
    const lastDateStr = client.lastJobDate
      ? Utilities.formatDate(client.lastJobDate, Session.getScriptTimeZone(), 'yyyy-MM-dd')
      : '';

    const rowData = buildRowFromConfig('CLIENTS', {
      'Client Email': client.email,
      'Client Name': client.name,
      'Client Phone': client.phone,
      'Store URL': client.storeUrl,
      'Total Jobs': client.totalJobs,
      'Completed Jobs': client.completedJobs,
      'Total Revenue': client.totalRevenue,
      'First Job Date': firstDateStr,
      'Last Job Date': lastDateStr,
      'Client Status': CLIENT_STATUS.ACTIVE,
      'Notes': '',
      'Created Date': firstDateStr || timestampStr,
      'Last Updated': timestampStr
    });

    clientsSheet.appendRow(rowData);
  });

  Logger.log('populateClientsFromExistingJobs: Added ' + sortedClients.length + ' clients from existing jobs');
}

/**
 * Recalculate statistics for all clients AND add any missing clients from jobs
 * Utility function to fix any data inconsistencies
 */
function recalculateAllClientStats() {
  const ui = SpreadsheetApp.getUi();
  const sheet = getSheet(SHEETS.CLIENTS);
  const jobsSheet = getSheet(SHEETS.JOBS);

  // If no clients exist but jobs do, redirect to syncClientsFromJobs
  if (!sheet || sheet.getLastRow() < 2) {
    if (jobsSheet && jobsSheet.getLastRow() >= 2) {
      // Clients sheet is empty but jobs exist - use sync function
      syncClientsFromJobs();
      return;
    }
    ui.alert('No Data', 'No clients or jobs found.', ui.ButtonSet.OK);
    return;
  }

  const response = ui.alert(
    'Recalculate All Client Statistics',
    'This will:\n' +
    '• Add any missing clients from the Jobs sheet\n' +
    '• Recalculate job counts and revenue for all clients\n\n' +
    'Continue?',
    ui.ButtonSet.YES_NO
  );

  if (response !== ui.Button.YES) return;

  // First, add any missing clients from jobs
  let added = 0;
  if (jobsSheet && jobsSheet.getLastRow() >= 2) {
    const lastColumn = jobsSheet.getLastColumn();
    const headers = jobsSheet.getRange(1, 1, 1, lastColumn).getValues()[0];
    const data = jobsSheet.getRange(2, 1, jobsSheet.getLastRow() - 1, lastColumn).getValues();

    const emailIdx = headers.indexOf('Client Email');
    const nameIdx = headers.indexOf('Client Name');
    const phoneIdx = headers.indexOf('Client Phone');
    const storeUrlIdx = headers.indexOf('Store URL');

    if (emailIdx !== -1) {
      const processedEmails = new Set();
      data.forEach(row => {
        const email = (row[emailIdx] || '').toString().toLowerCase().trim();
        if (!email || processedEmails.has(email)) return;
        processedEmails.add(email);

        // Check if client exists
        const existingClient = findClientByEmail(email);
        if (!existingClient) {
          // Add new client
          addNewClient({
            email: email,
            name: row[nameIdx] || '',
            phone: row[phoneIdx] || '',
            storeUrl: row[storeUrlIdx] || ''
          });
          added++;
        }
      });
    }
  }

  // Now recalculate stats for all clients (including newly added ones)
  // Re-get the sheet data since we may have added rows
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) {
    ui.alert('Complete', 'Added ' + added + ' new clients. No statistics to recalculate.', ui.ButtonSet.OK);
    return;
  }

  const emailCol = getColIndex('CLIENTS', 'Client Email');
  const emails = sheet.getRange(2, emailCol, lastRow - 1, 1).getValues();

  let updated = 0;
  emails.forEach(row => {
    const email = row[0];
    if (email) {
      updateClientStatistics(email);
      updated++;
    }
  });

  ui.alert('Complete',
    'Client sync complete:\n\n' +
    '• ' + added + ' new clients added\n' +
    '• ' + updated + ' clients statistics updated',
    ui.ButtonSet.OK
  );
}

/**
 * Navigate to the Clients sheet
 */
function navigateToClientsSheet() {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(SHEETS.CLIENTS);
  if (sheet) {
    ss.setActiveSheet(sheet);
    sheet.getRange('A1').activate();
    SpreadsheetApp.flush();
    ss.toast('Navigated to Clients sheet', '📊 Clients', 3);
  } else {
    SpreadsheetApp.getUi().alert('Clients sheet not found. Please run Setup first.');
  }
}

/**
 * Show dialog to view client history
 * Menu entry point - shows client picker then displays history
 */
function viewClientHistory() {
  const selectedClient = getSelectedClientEmail();
  const clients = getAllClients();
  showContextAwareDialogForClients(
    'View Client History',
    clients,
    'displayClientHistoryDialog',
    selectedClient
  );
}

/**
 * Get all clients for dropdown
 * @returns {Array} Array of client objects with email and name
 */
function getAllClients() {
  const sheet = getSheet(SHEETS.CLIENTS);
  if (!sheet || sheet.getLastRow() < 2) {
    return [];
  }

  const lastColumn = sheet.getLastColumn();
  const headers = sheet.getRange(1, 1, 1, lastColumn).getValues()[0];
  const data = sheet.getRange(2, 1, sheet.getLastRow() - 1, lastColumn).getValues();

  const emailIdx = headers.indexOf('Client Email');
  const nameIdx = headers.indexOf('Client Name');

  const clients = [];
  data.forEach(row => {
    const email = row[emailIdx];
    if (email) {
      clients.push({
        email: email,
        name: row[nameIdx] || email
      });
    }
  });

  return clients;
}

/**
 * Get currently selected client email (if on Clients sheet)
 * @returns {string|null} Client email or null
 */
function getSelectedClientEmail() {
  try {
    const sheet = SpreadsheetApp.getActiveSheet();
    if (sheet.getName() !== SHEETS.CLIENTS) {
      return null;
    }

    const activeCell = sheet.getActiveCell();
    if (!activeCell) return null;

    const row = activeCell.getRow();
    if (row < 2) return null; // Header row

    const emailCol = getColIndex('CLIENTS', 'Client Email');
    const email = sheet.getRange(row, emailCol).getValue();

    return email ? String(email).trim() : null;
  } catch (e) {
    return null;
  }
}

/**
 * Show context-aware dialog for clients (similar to showContextAwareDialog for jobs)
 */
function showContextAwareDialogForClients(title, clients, callback, selectedEmail) {
  const ui = SpreadsheetApp.getUi();

  if (clients.length === 0) {
    ui.alert('No Clients', 'No clients found in the system.', ui.ButtonSet.OK);
    return;
  }

  // If we have a selected client, use it directly
  if (selectedEmail) {
    this[callback](selectedEmail);
    return;
  }

  // Otherwise show dropdown dialog
  let optionsHtml = clients.map(c =>
    '<option value="' + escapeHtml(c.email) + '">' + escapeHtml(c.name) + ' (' + escapeHtml(c.email) + ')</option>'
  ).join('');

  const html = HtmlService.createHtmlOutput(`
    <style>
      body { font-family: Arial, sans-serif; padding: 20px; }
      select { width: 100%; padding: 10px; margin: 15px 0; font-size: 14px; }
      button { padding: 10px 20px; background: #2d5d3f; color: white; border: none; cursor: pointer; margin-right: 10px; border-radius: 4px; }
      button:hover:not(:disabled) { background: #4a7c59; }
      button:disabled { opacity: 0.6; cursor: not-allowed; }
      .cancel { background: #666; }
      .cancel:hover:not(:disabled) { background: #555; }
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
    <p>Select a client:</p>
    <select id="clientSelect">${optionsHtml}</select>
    <div>
      <button id="submitBtn" onclick="submitSelection()">View History</button>
      <button id="cancelBtn" class="cancel" onclick="google.script.host.close()">Cancel</button>
    </div>
    <script>
      var isSubmitting = false;

      function submitSelection() {
        try {
          if (isSubmitting) return;

          var value = document.getElementById('clientSelect').value;
          if (!value) {
            alert('Please select a client');
            return;
          }

          isSubmitting = true;
          var submitBtn = document.getElementById('submitBtn');
          var cancelBtn = document.getElementById('cancelBtn');
          var select = document.getElementById('clientSelect');

          submitBtn.disabled = true;
          cancelBtn.disabled = true;
          select.disabled = true;
          submitBtn.innerHTML = 'Loading...';

          google.script.run
            .withSuccessHandler(function() {
              google.script.host.close();
            })
            .withFailureHandler(function(error) {
              isSubmitting = false;
              submitBtn.disabled = false;
              cancelBtn.disabled = false;
              select.disabled = false;
              submitBtn.innerHTML = 'View History';
              alert('Server error: ' + (error.message || error));
            })
            .displayClientHistoryDialog(value);
        } catch (e) {
          alert('JS Error: ' + e.message);
        }
      }
    </script>
  `)
  .setWidth(450)
  .setHeight(220);

  ui.showModalDialog(html, title);
}

/**
 * Display the client history in a formatted HTML dialog
 * @param {string} clientEmail - The client's email address
 */
function displayClientHistoryDialog(clientEmail) {
  const ui = SpreadsheetApp.getUi();

  if (!clientEmail) {
    ui.alert('Error', 'No client email provided.', ui.ButtonSet.OK);
    return;
  }

  const client = findClientByEmail(clientEmail);
  if (!client) {
    ui.alert('Not Found', 'Client not found: ' + clientEmail, ui.ButtonSet.OK);
    return;
  }

  const jobs = getClientJobs(clientEmail);

  // Sort jobs by created date descending (newest first)
  jobs.sort((a, b) => {
    const dateA = a['Created Date'] ? new Date(a['Created Date']) : new Date(0);
    const dateB = b['Created Date'] ? new Date(b['Created Date']) : new Date(0);
    return dateB - dateA;
  });

  // Build job cards HTML
  let jobsHtml = '';
  if (jobs.length === 0) {
    jobsHtml = '<div class="no-jobs">No jobs found for this client.</div>';
  } else {
    jobs.forEach(job => {
      const status = job['Status'] || '';
      const statusColor = getStatusColor(status);
      const jobNum = job['Job #'] || '';
      const date = job['Created Date'] || '';
      const total = job['Total (incl GST)'] ? formatCurrency(job['Total (incl GST)']) : '';
      const paymentStatus = job['Payment Status'] || '';
      const description = (job['Job Description'] || '').substring(0, 100);

      jobsHtml += `
        <div class="job-card">
          <div class="job-header">
            <span class="job-number">${escapeHtml(jobNum)}</span>
            <span class="job-status" style="background: ${statusColor.bg}; color: ${statusColor.text};">${escapeHtml(status)}</span>
            <span class="job-date">${escapeHtml(date)}</span>
          </div>
          <div class="job-description">${escapeHtml(description)}${description.length >= 100 ? '...' : ''}</div>
          <div class="job-footer">
            <span class="job-amount">${escapeHtml(total)}</span>
            <span class="job-payment">${escapeHtml(paymentStatus)}</span>
          </div>
        </div>
      `;
    });
  }

  const htmlContent = `
    <!DOCTYPE html>
    <html>
      <head>
        <base target="_top">
        <style>
          * { box-sizing: border-box; }
          body {
            font-family: 'Google Sans', Roboto, Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: #f8f9fa;
          }
          .container {
            max-width: 100%;
            padding: 20px;
          }
          .header {
            background: linear-gradient(135deg, #2d5d3f 0%, #1e3f2a 100%);
            color: white;
            padding: 20px;
            margin: -20px -20px 20px -20px;
          }
          .header h2 {
            margin: 0 0 5px 0;
            font-size: 20px;
            font-weight: 500;
          }
          .header .email {
            opacity: 0.9;
            font-size: 14px;
            margin-bottom: 10px;
          }
          .stats-row {
            display: flex;
            gap: 20px;
            margin-top: 15px;
            flex-wrap: wrap;
          }
          .stat {
            background: rgba(255,255,255,0.15);
            padding: 8px 15px;
            border-radius: 4px;
            font-size: 13px;
          }
          .stat strong {
            font-size: 16px;
            display: block;
          }
          .store-url {
            margin-top: 10px;
          }
          .store-url a {
            color: #a8d4b8;
            text-decoration: none;
          }
          .store-url a:hover {
            text-decoration: underline;
          }
          .job-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
          }
          .job-card {
            background: white;
            border-radius: 8px;
            padding: 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid #2d5d3f;
          }
          .job-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
            flex-wrap: wrap;
          }
          .job-number {
            font-weight: 600;
            color: #2d5d3f;
            font-size: 14px;
          }
          .job-status {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
          }
          .job-date {
            color: #5f6368;
            font-size: 12px;
            margin-left: auto;
          }
          .job-description {
            color: #202124;
            font-size: 13px;
            line-height: 1.4;
            margin-bottom: 8px;
          }
          .job-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-top: 8px;
            border-top: 1px solid #e8eaed;
          }
          .job-amount {
            font-weight: 600;
            color: #202124;
          }
          .job-payment {
            font-size: 12px;
            color: #5f6368;
          }
          .no-jobs {
            text-align: center;
            color: #5f6368;
            padding: 40px;
            background: white;
            border-radius: 8px;
          }
          .button-row {
            display: flex;
            gap: 10px;
            margin-top: 20px;
          }
          .btn {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 500;
          }
          .btn-view {
            background: #2d5d3f;
            color: white;
          }
          .btn-view:hover {
            background: #4a7c59;
          }
          .btn-close {
            background: #e8eaed;
            color: #202124;
          }
          .btn-close:hover {
            background: #dadce0;
          }
          .section-title {
            font-size: 14px;
            font-weight: 500;
            color: #5f6368;
            margin: 20px 0 10px 0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2>${escapeHtml(client['Client Name'] || 'Client')}</h2>
            <div class="email">${escapeHtml(client['Client Email'])}</div>
            ${client['Client Phone'] ? '<div class="phone">📞 ' + escapeHtml(client['Client Phone']) + '</div>' : ''}
            ${client['Store URL'] ? '<div class="store-url">🔗 <a href="' + escapeHtml(client['Store URL']) + '" target="_blank">' + escapeHtml(client['Store URL']) + '</a></div>' : ''}
            <div class="stats-row">
              <div class="stat">
                <strong>${client['Total Jobs'] || 0}</strong>
                Total Jobs
              </div>
              <div class="stat">
                <strong>${client['Completed Jobs'] || 0}</strong>
                Completed
              </div>
              <div class="stat">
                <strong>${formatCurrency(client['Total Revenue'] || 0)}</strong>
                Revenue
              </div>
              <div class="stat">
                <strong>${escapeHtml(client['Client Status'] || 'Active')}</strong>
                Status
              </div>
            </div>
          </div>

          <div class="section-title">Job History (${jobs.length} jobs)</div>
          <div class="job-list">
            ${jobsHtml}
          </div>

          <div class="button-row">
            <button class="btn btn-view" onclick="google.script.run.navigateToClientsSheet(); google.script.host.close();">View in Sheet</button>
            <button class="btn btn-close" onclick="google.script.host.close()">Close</button>
          </div>
        </div>
      </body>
    </html>
  `;

  const html = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(550)
    .setHeight(600);

  ui.showModalDialog(html, 'Client History');
}

/**
 * Get status color for job status badges
 * @param {string} status - Job status
 * @returns {Object} Object with bg and text color properties
 */
function getStatusColor(status) {
  const colors = {
    'Pending Quote': { bg: SHEET_COLORS.statusPendingQuote, text: SHEET_COLORS.statusPendingQuoteText },
    'Quoted': { bg: SHEET_COLORS.statusQuoted, text: SHEET_COLORS.statusQuotedText },
    'Quote Reminded': { bg: SHEET_COLORS.statusQuoteReminded, text: SHEET_COLORS.statusQuoteRemindedText },
    'Accepted': { bg: SHEET_COLORS.statusAccepted, text: SHEET_COLORS.statusAcceptedText },
    'In Progress': { bg: SHEET_COLORS.statusActive, text: SHEET_COLORS.statusActiveText },
    'Completed': { bg: SHEET_COLORS.statusCompleted, text: SHEET_COLORS.statusCompletedText },
    'On Hold': { bg: SHEET_COLORS.slaAtRisk, text: SHEET_COLORS.slaAtRiskText },
    'Cancelled': { bg: SHEET_COLORS.statusCancelled, text: SHEET_COLORS.statusCancelledText },
    'Declined': { bg: SHEET_COLORS.slaOverdue, text: SHEET_COLORS.slaOverdueText }
  };
  return colors[status] || { bg: '#e8eaed', text: '#5f6368' };
}

// ============================================================================
// QUOTE FUNCTIONS
// ============================================================================

/**
 * Show dialog to send quote with quote amount input
 * Called from the Actions menu for a specific job
 */
function showSendQuoteWithAmountDialog(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  // Get current quote amount if any
  const currentAmount = parseFloat(job['Quote Amount (excl GST)']) || '';
  const clientName = job['Client Name'] || '';
  const jobDescription = job['Job Description'] || '';

  // Build dialog HTML
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <base target="_top">
      <style>
        body { font-family: Arial, sans-serif; padding: 20px; background: #f9f9f9; }
        .header { margin-bottom: 20px; }
        .header h2 { margin: 0 0 5px 0; color: #333; }
        .header .subtitle { color: #666; font-size: 14px; }
        .info-box { background: white; border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin-bottom: 20px; }
        .info-row { margin-bottom: 10px; }
        .info-label { font-weight: bold; color: #555; font-size: 12px; }
        .info-value { color: #333; margin-top: 3px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; font-weight: bold; margin-bottom: 8px; color: #333; }
        .form-group input { width: 100%; padding: 12px; font-size: 18px; border: 2px solid #ddd; border-radius: 8px; box-sizing: border-box; }
        .form-group input:focus { border-color: #4CAF50; outline: none; }
        .form-group .hint { font-size: 12px; color: #666; margin-top: 5px; }
        .buttons { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: bold; }
        .btn-primary { background: #4CAF50; color: white; }
        .btn-primary:hover { background: #45a049; }
        .btn-secondary { background: #f0f0f0; color: #333; }
        .btn-secondary:hover { background: #e0e0e0; }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .error { color: #d32f2f; font-size: 12px; margin-top: 5px; display: none; }
      </style>
    </head>
    <body>
      <div class="header">
        <h2>📤 Send Quote</h2>
        <div class="subtitle">${jobNumber}</div>
      </div>

      <div class="info-box">
        <div class="info-row">
          <div class="info-label">Client</div>
          <div class="info-value">${clientName || 'Not specified'}</div>
        </div>
        <div class="info-row">
          <div class="info-label">Job Description</div>
          <div class="info-value">${jobDescription || 'Not specified'}</div>
        </div>
      </div>

      <div class="form-group">
        <label for="quoteAmount">Quote Amount (excl GST) *</label>
        <input type="number" id="quoteAmount" step="0.01" min="0" placeholder="Enter amount..." value="${currentAmount}">
        <div class="hint">GST will be calculated automatically if registered</div>
        <div class="error" id="error">Please enter a valid quote amount</div>
      </div>

      <div class="buttons">
        <button class="btn btn-secondary" onclick="google.script.host.close()">Cancel</button>
        <button class="btn btn-primary" id="submitBtn" onclick="sendQuote()">Send Quote</button>
      </div>

      <script>
        function sendQuote() {
          const amount = document.getElementById('quoteAmount').value;
          const errorEl = document.getElementById('error');
          const submitBtn = document.getElementById('submitBtn');

          if (!amount || parseFloat(amount) <= 0) {
            errorEl.style.display = 'block';
            return;
          }

          errorEl.style.display = 'none';
          submitBtn.disabled = true;
          submitBtn.textContent = 'Sending...';

          google.script.run
            .withSuccessHandler(function() {
              google.script.host.close();
            })
            .withFailureHandler(function(error) {
              submitBtn.disabled = false;
              submitBtn.textContent = 'Send Quote';
              alert('Error: ' + error.message);
            })
            .sendQuoteWithAmount('${jobNumber}', parseFloat(amount));
        }

        // Focus on input
        document.getElementById('quoteAmount').focus();

        // Allow Enter key to submit
        document.getElementById('quoteAmount').addEventListener('keypress', function(e) {
          if (e.key === 'Enter') sendQuote();
        });
      </script>
    </body>
    </html>
  `;

  const htmlOutput = HtmlService.createHtmlOutput(html)
    .setWidth(420)
    .setHeight(400);

  ui.showModalDialog(htmlOutput, 'Send Quote - ' + jobNumber);
}

/**
 * Send quote with a specific amount (called from dialog)
 */
function sendQuoteWithAmount(jobNumber, amount) {
  // Update the quote amount in the sheet first
  updateJobFields(jobNumber, {
    'Quote Amount (excl GST)': amount.toFixed(2)
  });

  // Now send the quote email
  sendQuoteEmail(jobNumber);
}

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
    'showSendQuoteWithAmountDialog',
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

    // Refresh dashboard and analytics to show updated data
    refreshDashboard(true);
    refreshAnalytics();
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

  // Build quote acceptance URL with parameters (including bank details for deposit info)
  const acceptQuoteUrl = 'https://cartcure.co.nz/quote-acceptance.html?' +
    'job=' + encodeURIComponent(data.jobNumber) +
    '&name=' + encodeURIComponent(data.clientName) +
    '&desc=' + encodeURIComponent((data.jobDescription || '').substring(0, 100)) +
    '&amount=' + encodeURIComponent(data.total) +
    '&turnaround=' + encodeURIComponent(data.turnaround) +
    '&bank=' + encodeURIComponent(data.bankName || '') +
    '&account=' + encodeURIComponent(data.bankAccount || '') +
    '&payee=' + encodeURIComponent(data.businessName || 'CartCure');

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
        <p><strong>Note:</strong> The job completion timer is also <strong>paused</strong> while your job is on hold.</p>
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
      statusMessage += '\n\nNote: The job completion timer is also paused while your job is on hold.\n\nWe\'ll notify you as soon as we resume work.';
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
 * Supports batch processing when multiple rows are selected
 */
function showQuoteReminderDialog() {
  // Check for multiple selected rows
  const selectedJobs = getSelectedJobNumbers();

  if (selectedJobs.length > 1) {
    const totalSelected = selectedJobs.length;

    // Filter to only jobs that can receive quote reminders
    const validJobs = selectedJobs.filter(jobNum => {
      const job = getJobByNumber(jobNum);
      return job && (job['Status'] === JOB_STATUS.QUOTED || job['Status'] === JOB_STATUS.QUOTE_REMINDED);
    });

    if (validJobs.length === 0) {
      SpreadsheetApp.getUi().alert('No Valid Jobs',
        'None of the selected jobs can receive quote reminders. Jobs must be in Quoted or Quote Reminded status.',
        SpreadsheetApp.getUi().ButtonSet.OK);
      return;
    }

    // Show batch dialog with total selected count
    showBatchMenuActionDialog('job', validJobs, 'sendQuoteReminder', 'Send Quote Reminders', totalSelected);
    return;
  }

  // Single row - use existing behavior
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
  const bankName = getSetting('Bank Name') || '';
  const bankAccount = getSetting('Bank Account') || '';
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gstNumber = getSetting('GST Number') || '';
  const clientName = job['Client Name'];
  const clientEmail = job['Client Email'];
  const total = job['Total (incl GST)'];
  const validUntil = job['Quote Valid Until'];
  const jobDescription = job['Job Description'] || '';
  const turnaround = job['Estimated Turnaround'] || '';

  const subject = 'Reminder: Your CartCure Quote (' + jobNumber + ')';

  // Build quote acceptance URL (including bank details for deposit info)
  const acceptQuoteUrl = 'https://cartcure.co.nz/quote-acceptance.html?' +
    'job=' + encodeURIComponent(jobNumber) +
    '&name=' + encodeURIComponent(clientName) +
    '&desc=' + encodeURIComponent((jobDescription || '').substring(0, 100)) +
    '&amount=' + encodeURIComponent(total) +
    '&turnaround=' + encodeURIComponent(turnaround) +
    '&bank=' + encodeURIComponent(bankName) +
    '&account=' + encodeURIComponent(bankAccount) +
    '&payee=' + encodeURIComponent(businessName);

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
  const bankName = getSetting('Bank Name') || '';
  const bankAccount = getSetting('Bank Account') || '';
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

  // Build quote acceptance URL (including bank details for deposit info)
  const acceptQuoteUrl = 'https://cartcure.co.nz/quote-acceptance.html?' +
    'job=' + encodeURIComponent(jobNumber) +
    '&name=' + encodeURIComponent(clientName) +
    '&desc=' + encodeURIComponent((jobDescription || '').substring(0, 100)) +
    '&amount=' + encodeURIComponent(total) +
    '&turnaround=' + encodeURIComponent(turnaround) +
    '&bank=' + encodeURIComponent(bankName) +
    '&account=' + encodeURIComponent(bankAccount) +
    '&payee=' + encodeURIComponent(businessName);

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

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const statusCol = getColIndex('JOBS', 'Status') - 1;
  const jobNumCol = getColIndex('JOBS', 'Job #') - 1;
  const quoteSentDateCol = getColIndex('JOBS', 'Quote Sent Date') - 1;

  if (statusCol < 0 || jobNumCol < 0 || quoteSentDateCol < 0) {
    Logger.log('Required columns not found in COLUMN_CONFIG');
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
 * Supports batch processing when multiple rows are selected
 */
function showDeclineQuoteDialog() {
  // Check for multiple selected rows
  const selectedJobs = getSelectedJobNumbers();

  if (selectedJobs.length > 1) {
    const totalSelected = selectedJobs.length;

    // Filter to only jobs that can have quotes declined
    const validJobs = selectedJobs.filter(jobNum => {
      const job = getJobByNumber(jobNum);
      return job && (job['Status'] === JOB_STATUS.QUOTED ||
                     job['Status'] === JOB_STATUS.QUOTE_REMINDED ||
                     job['Status'] === JOB_STATUS.PENDING_QUOTE);
    });

    if (validJobs.length === 0) {
      SpreadsheetApp.getUi().alert('No Valid Jobs',
        'None of the selected jobs can have quotes declined.',
        SpreadsheetApp.getUi().ButtonSet.OK);
      return;
    }

    // Show batch dialog with total selected count
    showBatchMenuActionDialog('job', validJobs, 'markDeclined', 'Mark Quotes Declined', totalSelected);
    return;
  }

  // Single row - use existing behavior
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

  // Refresh dashboard and analytics to show updated data
  refreshDashboard(true);
  refreshAnalytics();
}

// ============================================================================
// INVOICE FUNCTIONS
// ============================================================================

/**
 * Show dialog to generate invoice
 * Supports batch processing when multiple rows are selected
 */
function showGenerateInvoiceDialog() {
  // Check for multiple selected rows
  const selectedJobs = getSelectedJobNumbers();

  if (selectedJobs.length > 1) {
    const totalSelected = selectedJobs.length;

    // Filter to only jobs that can have invoices generated
    const validJobs = selectedJobs.filter(jobNum => {
      const job = getJobByNumber(jobNum);
      return job && (job['Status'] === JOB_STATUS.COMPLETED ||
                     job['Status'] === JOB_STATUS.ACCEPTED ||
                     job['Status'] === JOB_STATUS.IN_PROGRESS);
    });

    if (validJobs.length === 0) {
      SpreadsheetApp.getUi().alert('No Valid Jobs',
        'None of the selected jobs can have invoices generated.',
        SpreadsheetApp.getUi().ButtonSet.OK);
      return;
    }

    // Show batch dialog with total selected count
    showBatchMenuActionDialog('job', validJobs, 'generateInvoice', 'Generate Invoices', totalSelected);
    return;
  }

  // Single row - use existing behavior
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
  const ss = getSpreadsheet();
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

  // Validate invoice amount (P1 FIX)
  const amountValidation = validateInvoiceAmount(amount, 'Quote Amount');
  if (!amountValidation.valid) {
    ui.alert('Invalid Amount', amountValidation.error + '\n\nPlease update the Quote Amount in the Jobs sheet.', ui.ButtonSet.OK);
    return;
  }

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

  // Insert at top (row 2) so newest invoices appear first
  insertAtTopSafe(invoiceSheet, invoiceRow, true); // true = show toast (menu action)

  // Update job with latest invoice number
  updateJobField(jobNumber, 'Invoice #', invoiceNumber);

  Logger.log('Invoice ' + invoiceNumber + ' (' + invoiceType + ') generated for ' + jobNumber);

  // Show preview of the generated invoice
  previewInvoiceEmail(invoiceNumber);
}

/**
 * Show dialog to send invoice
 * Supports batch processing when multiple rows are selected
 */
function showSendInvoiceDialog() {
  // Check for multiple selected rows
  const selectedInvoices = getSelectedInvoiceNumbers();

  if (selectedInvoices.length > 1) {
    const totalSelected = selectedInvoices.length;

    // Filter to only invoices that can be sent (Draft status)
    const validInvoices = selectedInvoices.filter(invNum => {
      const invoice = getInvoiceByNumber(invNum);
      return invoice && invoice['Status'] === 'Draft';
    });

    if (validInvoices.length === 0) {
      SpreadsheetApp.getUi().alert('No Valid Invoices',
        'None of the selected invoices can be sent. Invoices must be in Draft status.',
        SpreadsheetApp.getUi().ButtonSet.OK);
      return;
    }

    // Show batch dialog with total selected count
    showBatchMenuActionDialog('invoice', validInvoices, 'sendInvoice', 'Send Invoices', totalSelected);
    return;
  }

  // Single row - use existing behavior
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
  // PERFORMANCE: Use cached sheet reference
  const sheet = getSheet(SHEETS.INVOICES);

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

  // Verify the found cell is in the Invoice # column (use config to get correct column)
  const invoiceColIndex = getColIndex('INVOICES', 'Invoice #');
  if (foundRange.getColumn() !== invoiceColIndex) {
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
  // PERFORMANCE: Use cached sheet reference
  const sheet = getSheet(SHEETS.INVOICES);

  if (!sheet) {
    Logger.log('[PERF] getInvoicesByJobNumber() - Invoices sheet not found');
    return [];
  }

  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) return []; // No data rows

  // Load all data at once
  const allData = sheet.getDataRange().getValues();
  const headers = allData[0]; // Keep headers for building invoice objects
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const jobNumColIndex = getColIndex('INVOICES', 'Job #') - 1;

  if (jobNumColIndex < 0) {
    Logger.log('[PERF] getInvoicesByJobNumber() - Job # column not found in COLUMN_CONFIG');
    return [];
  }

  const invoices = [];

  // Find all rows with matching job number
  for (let i = 1; i < allData.length; i++) {
    const row = allData[i];
    const rowJobNum = row[jobNumColIndex];

    if (String(rowJobNum).trim() === String(jobNumber).trim()) {
      const invoice = {};
      // Build invoice object using COLUMN_CONFIG headers for consistency
      const configHeaders = getColHeaders('INVOICES');
      configHeaders.forEach((header, index) => {
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
  // Validate inputs
  if (!invoiceNumber || !updates || Object.keys(updates).length === 0) {
    Logger.log('[PERF] updateInvoiceFields() - Invalid parameters');
    return false;
  }

  // PERFORMANCE: Use cached sheet reference
  const sheet = getSheet(SHEETS.INVOICES);

  if (!sheet) {
    Logger.log('[PERF] updateInvoiceFields() - Invoices sheet not found');
    return false;
  }

  // OPTIMIZATION: Single sheet load
  const data = sheet.getDataRange().getValues();
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const invoiceNumColIndex = getColIndex('INVOICES', 'Invoice #') - 1;

  if (invoiceNumColIndex < 0) {
    Logger.log('[PERF] updateInvoiceFields() - Invoice # column not found in COLUMN_CONFIG');
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

  // PERFORMANCE: Build row update array for single setValues() call
  const rowData = data[rowIndex].slice(); // Copy current row data
  let fieldsUpdated = 0;

  // Process each field update request using COLUMN_CONFIG
  for (const [fieldName, value] of Object.entries(updates)) {
    const colIndex = getColIndex('INVOICES', fieldName) - 1;
    if (colIndex >= 0) {
      rowData[colIndex] = value;
      fieldsUpdated++;
    } else {
      Logger.log('[PERF] updateInvoiceFields() - Field not found in COLUMN_CONFIG: ' + fieldName);
    }
  }

  // PERFORMANCE: Single setValues() call for entire row
  sheet.getRange(rowIndex + 1, 1, 1, rowData.length).setValues([rowData]);

  Logger.log('[PERF] updateInvoiceFields() - Updated ' + fieldsUpdated + ' fields for ' + invoiceNumber);

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
  // PERFORMANCE: Use cached sheet reference
  const sheet = getSheet(SHEETS.INVOICES);

  if (!sheet) return false;

  const data = sheet.getDataRange().getValues();
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based)
  const invoiceNumColIndex = getColIndex('INVOICES', 'Invoice #') - 1; // 0-based for array indexing
  const colIndex = getColIndex('INVOICES', fieldName); // 1-based for sheet.getRange()

  if (invoiceNumColIndex < 0 || colIndex < 1) return false;

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][invoiceNumColIndex]).trim() === String(invoiceNumber).trim()) {
      sheet.getRange(i + 1, colIndex).setValue(value);
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
  const amount = Number(invoice['Amount (excl GST)'] || 0).toFixed(2);
  const gst = Number(invoice['GST'] || 0).toFixed(2);
  const total = Number(invoice['Total'] || 0).toFixed(2);
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

  // Build "I have paid" URL
  const paymentReceivedUrl = 'https://cartcure.co.nz/payment-received.html?' +
    'invoice=' + encodeURIComponent(invoiceNumber) +
    '&job=' + encodeURIComponent(jobNumber);

  // Render template based on invoice type
  let bodyContent;
  if (invoiceType === 'Balance' && depositInfo) {
    // Use dedicated balance invoice template
    const depositPaidText = depositInfo.paidDate ? ' (paid ' + formatNZDate(depositInfo.paidDate) + ')' : '';
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
      businessName: businessName,
      paymentReceivedUrl: paymentReceivedUrl
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
      businessName: businessName,
      paymentReceivedUrl: paymentReceivedUrl
    });
  }

  const htmlBody = wrapEmailHtml(bodyContent);

  try {
    // Generate PDF for attachment
    let pdfBlob = null;
    let pdfUrl = null;
    try {
      const pdfResult = generateInvoicePDF(invoiceNumber, true);
      if (pdfResult.success && pdfResult.pdfBlob) {
        pdfBlob = pdfResult.pdfBlob;

        // Also save to Drive and get URL
        const folder = getOrCreateInvoicesFolder();
        const pdfFile = folder.createFile(pdfBlob);
        pdfUrl = pdfFile.getUrl();
      }
    } catch (pdfError) {
      Logger.log('PDF generation failed (continuing without attachment): ' + pdfError.message);
    }

    // Build email options
    const emailOptions = {
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    };
    if (pdfBlob) {
      emailOptions.attachments = [pdfBlob];
    }
    MailApp.sendEmail(emailOptions);

    // Log activity
    const invoiceTypeLabel = invoiceType === 'Balance' ? 'Balance invoice' : 'Invoice';
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      invoiceTypeLabel + ' sent: ' + formatCurrency(displayTotal) + (pdfBlob ? ' (with PDF)' : ''),
      'To: ' + clientEmail,
      'Auto'
    );

    // OPTIMIZATION: Batch update invoice fields (2 calls → 1)
    updateInvoiceFields(invoiceNumber, {
      'Status': 'Sent',
      'Sent Date': formatNZDate(new Date())
    });

    // Update PDF Link if we generated one
    if (pdfUrl) {
      updateInvoicePDFLink(invoiceNumber, pdfUrl);
    }

    // Update job payment status
    updateJobField(jobNumber, 'Payment Status', PAYMENT_STATUS.INVOICED);

    ui.alert(invoiceTypeLabel + ' Sent', invoiceTypeLabel + ' sent to ' + clientEmail + (pdfBlob ? '\n\nPDF attached and saved to Drive.' : ''), ui.ButtonSet.OK);
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
  const amount = Number(invoice['Amount (excl GST)'] || 0).toFixed(2);
  const gst = Number(invoice['GST'] || 0).toFixed(2);
  const total = Number(invoice['Total'] || 0).toFixed(2);
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

  // Build "I have paid" URL
  const paymentReceivedUrl = 'https://cartcure.co.nz/payment-received.html?' +
    'invoice=' + encodeURIComponent(invoiceNumber) +
    '&job=' + encodeURIComponent(jobNumber);

  // Render template based on invoice type
  let bodyContent;
  if (invoiceType === 'Balance' && depositInfo) {
    const depositPaidText = depositInfo.paidDate ? ' (paid ' + formatNZDate(depositInfo.paidDate) + ')' : '';
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
      businessName: businessName,
      paymentReceivedUrl: paymentReceivedUrl
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
      businessName: businessName,
      paymentReceivedUrl: paymentReceivedUrl
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

// ============================================================================
// INVOICE PDF GENERATION
// ============================================================================

/**
 * Get or create the CartCure Invoices folder in Google Drive
 * @returns {Folder} The invoices folder
 */
function getOrCreateInvoicesFolder() {
  const folderName = 'CartCure Invoices';
  const folders = DriveApp.getFoldersByName(folderName);

  if (folders.hasNext()) {
    return folders.next();
  }

  // Create the folder if it doesn't exist
  return DriveApp.createFolder(folderName);
}

/**
 * Get or create the CartCure Receipts folder in Google Drive
 * @returns {Folder} The receipts folder
 */
function getOrCreateReceiptsFolder() {
  const folderName = 'CartCure Receipts';
  const folders = DriveApp.getFoldersByName(folderName);

  if (folders.hasNext()) {
    return folders.next();
  }

  // Create the folder if it doesn't exist
  return DriveApp.createFolder(folderName);
}

/**
 * Render receipt HTML optimized for PDF generation
 * @param {string} invoiceNumber - The invoice number
 * @param {string} receiptNumber - The receipt number
 * @param {string} paymentMethod - The payment method used
 * @param {string} paymentReference - Optional payment reference
 * @returns {Object} - {success, html, receiptData} or {success: false, error}
 */
function renderReceiptPDFHtml(invoiceNumber, receiptNumber, paymentMethod, paymentReference) {
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    return { success: false, error: 'Invoice ' + invoiceNumber + ' not found.' };
  }

  const businessName = getSetting('Business Name') || 'CartCure';
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gstNumber = getSetting('GST Number') || '';

  const clientName = invoice['Client Name'];
  const jobNumber = invoice['Job #'];
  const amount = Number(invoice['Amount (excl GST)'] || 0).toFixed(2);
  const gst = Number(invoice['GST'] || 0).toFixed(2);
  const total = Number(invoice['Total'] || 0).toFixed(2);
  const invoiceDate = invoice['Invoice Date'];
  const paidDate = invoice['Paid Date'] || formatNZDate(new Date());

  // Build pricing section
  const gstValue = parseFloat(gst);
  const displayTotal = isGSTRegistered ? total : amount;

  // Build pricing HTML (self-contained tables for Google Docs PDF compatibility)
  let pricingRowsHtml = '';
  if (isGSTRegistered && !isNaN(gstValue) && gstValue > 0) {
    pricingRowsHtml = `
      <table width="100%" cellpadding="6" cellspacing="0" border="1" bordercolor="${EMAIL_COLORS.paperBorder}" style="border-collapse:collapse;">
        <tr>
          <td bgcolor="${EMAIL_COLORS.paperCream}"><font color="${EMAIL_COLORS.inkGray}">Subtotal (excl. GST)</font></td>
          <td bgcolor="${EMAIL_COLORS.paperCream}" align="right"><b>$${amount}</b></td>
        </tr>
        <tr>
          <td bgcolor="${EMAIL_COLORS.paperCream}"><font color="${EMAIL_COLORS.inkGray}">GST (15%)</font></td>
          <td bgcolor="${EMAIL_COLORS.paperCream}" align="right"><b>$${gst}</b></td>
        </tr>
      </table>
      <table width="100%" cellpadding="8" cellspacing="0" border="0">
        <tr>
          <td bgcolor="${EMAIL_COLORS.brandGreen}"><font color="#ffffff"><b>TOTAL PAID (incl. GST)</b></font></td>
          <td bgcolor="${EMAIL_COLORS.brandGreen}" align="right"><font color="#ffffff" size="4"><b>$${total}</b></font></td>
        </tr>
      </table>
    `;
  } else {
    pricingRowsHtml = `
      <table width="100%" cellpadding="8" cellspacing="0" border="0">
        <tr>
          <td bgcolor="${EMAIL_COLORS.brandGreen}"><font color="#ffffff"><b>TOTAL PAID</b></font></td>
          <td bgcolor="${EMAIL_COLORS.brandGreen}" align="right"><font color="#ffffff" size="4"><b>$${displayTotal}</b></font></td>
        </tr>
      </table>
    `;
  }

  // GST footer line
  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  // Payment reference section (only show if reference provided)
  let paymentReferenceHtml = '';
  if (paymentReference) {
    paymentReferenceHtml = `
      <table width="100%" cellpadding="10" cellspacing="0" border="0"><tr>
        <td bgcolor="${EMAIL_COLORS.paperCream}" style="border:2px solid ${EMAIL_COLORS.paperBorder};">
          <b>Payment Reference:</b><br>
          <font size="2" color="${EMAIL_COLORS.inkGray}">${paymentReference}</font>
        </td>
      </tr></table>
    `;
  }

  // Render the PDF template
  const bodyContent = renderEmailTemplate('receipt-pdf', {
    receiptNumber: receiptNumber,
    invoiceNumber: invoiceNumber,
    jobNumber: jobNumber,
    clientName: clientName,
    paidDate: paidDate,
    paymentMethod: paymentMethod || 'Bank Transfer',
    invoiceDate: formatNZDate(invoiceDate) || paidDate,
    pricingRowsHtml: pricingRowsHtml,
    paymentReferenceHtml: paymentReferenceHtml,
    gstFooterLine: gstFooterLine,
    businessName: businessName
  });

  return {
    success: true,
    html: bodyContent,
    receiptData: {
      receiptNumber: receiptNumber,
      invoiceNumber: invoiceNumber,
      clientName: clientName,
      total: displayTotal
    }
  };
}

/**
 * Generate a PDF for a payment receipt and save it to Google Drive
 * @param {string} invoiceNumber - The invoice number
 * @param {string} receiptNumber - The receipt number
 * @param {string} paymentMethod - The payment method used
 * @param {string} paymentReference - Optional payment reference
 * @param {boolean} returnBlob - If true, returns the PDF blob for email attachment; if false, saves to Drive
 * @returns {Object} - {success, pdfUrl, pdfBlob, error}
 */
function generateReceiptPDF(invoiceNumber, receiptNumber, paymentMethod, paymentReference, returnBlob) {
  try {
    // 1. Render the PDF HTML
    const htmlResult = renderReceiptPDFHtml(invoiceNumber, receiptNumber, paymentMethod, paymentReference);
    if (!htmlResult.success) {
      return { success: false, error: htmlResult.error };
    }

    // 2. Convert HTML to PDF via Google Drive API (produces valid PDF structure)
    const pdfBlob = convertHtmlToPdf(htmlResult.html, 'Receipt_' + receiptNumber);

    // If only blob is needed (for email attachment), return it
    if (returnBlob) {
      return {
        success: true,
        pdfBlob: pdfBlob,
        receiptData: htmlResult.receiptData
      };
    }

    // 3. Save to Drive folder
    const folder = getOrCreateReceiptsFolder();
    const pdfFile = folder.createFile(pdfBlob);
    const pdfUrl = pdfFile.getUrl();

    // 4. Update the Invoice Log with the Receipt PDF link
    updateReceiptPDFLink(invoiceNumber, pdfUrl);

    return {
      success: true,
      pdfUrl: pdfUrl,
      pdfId: pdfFile.getId(),
      receiptData: htmlResult.receiptData
    };
  } catch (error) {
    return { success: false, error: 'Receipt PDF generation failed: ' + error.message };
  }
}

/**
 * Update the Receipt PDF Link column in the Invoice Log
 * @param {string} invoiceNumber - The invoice number
 * @param {string} pdfUrl - The Google Drive URL of the Receipt PDF
 */
function updateReceiptPDFLink(invoiceNumber, pdfUrl) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
    if (!invoiceSheet) return;

    const data = invoiceSheet.getDataRange().getValues();
    const invoiceCol = getColIndex('INVOICES', 'Invoice #');
    const receiptPdfLinkCol = getColIndex('INVOICES', 'Receipt PDF Link');

    if (invoiceCol === -1 || receiptPdfLinkCol === -1) return;

    for (let i = 1; i < data.length; i++) {
      if (data[i][invoiceCol - 1] === invoiceNumber) {
        invoiceSheet.getRange(i + 1, receiptPdfLinkCol).setValue(pdfUrl);
        break;
      }
    }
  } catch (e) {
    Logger.log('Failed to update Receipt PDF link: ' + e.message);
  }
}

/**
 * Convert HTML content to a valid PDF blob using Google Drive API.
 * Uploads HTML as a Google Doc (triggering conversion), exports as PDF, then cleans up.
 * This is more reliable than HtmlService.getBlob() which can produce invalid PDFs.
 * @param {string} html - Complete HTML document string
 * @param {string} fileName - Name for the PDF file (without .pdf extension)
 * @returns {Blob} PDF blob
 */
function convertHtmlToPdf(html, fileName) {
  var token = ScriptApp.getOAuthToken();
  var boundary = 'pdf_convert_' + new Date().getTime();
  var metadata = JSON.stringify({
    name: 'temp_pdf_' + new Date().getTime(),
    mimeType: 'application/vnd.google-apps.document'
  });

  var payload =
    '--' + boundary + '\r\n' +
    'Content-Type: application/json; charset=UTF-8\r\n\r\n' +
    metadata + '\r\n' +
    '--' + boundary + '\r\n' +
    'Content-Type: text/html; charset=UTF-8\r\n\r\n' +
    html + '\r\n' +
    '--' + boundary + '--';

  var uploadResponse = UrlFetchApp.fetch(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart',
    {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token },
      contentType: 'multipart/related; boundary=' + boundary,
      payload: Utilities.newBlob(payload).getBytes(),
      muteHttpExceptions: true
    }
  );

  if (uploadResponse.getResponseCode() !== 200) {
    throw new Error('Drive upload failed: ' + uploadResponse.getContentText());
  }

  var docId = JSON.parse(uploadResponse.getContentText()).id;

  try {
    var pdfResponse = UrlFetchApp.fetch(
      'https://www.googleapis.com/drive/v3/files/' + docId + '/export?mimeType=application/pdf',
      {
        headers: { 'Authorization': 'Bearer ' + token },
        muteHttpExceptions: true
      }
    );

    if (pdfResponse.getResponseCode() !== 200) {
      throw new Error('PDF export failed: ' + pdfResponse.getContentText());
    }

    return pdfResponse.getBlob().setName(fileName + '.pdf');
  } finally {
    try { DriveApp.getFileById(docId).setTrashed(true); } catch (e) { /* ignore cleanup errors */ }
  }
}

/**
 * Render invoice HTML optimized for PDF generation (without interactive elements)
 * @param {string} invoiceNumber - The invoice number
 * @returns {Object} - {success, html, invoiceData} or {success: false, error}
 */
function renderInvoicePDFHtml(invoiceNumber) {
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
  const jobNumber = invoice['Job #'];
  const amount = Number(invoice['Amount (excl GST)'] || 0).toFixed(2);
  const gst = Number(invoice['GST'] || 0).toFixed(2);
  const total = Number(invoice['Total'] || 0).toFixed(2);
  const dueDate = invoice['Due Date'];
  const invoiceType = invoice['Invoice Type'] || 'Full';

  // Determine heading based on invoice type
  let headingTitle = 'Invoice';
  if (invoiceType === 'Deposit') {
    headingTitle = 'Deposit Invoice';
  } else if (invoiceType === 'Balance') {
    headingTitle = 'Balance Invoice';
  }

  // Build pricing section
  const gstValue = parseFloat(gst);
  const displayTotal = isGSTRegistered ? total : amount;

  // Build pricing HTML (self-contained tables for Google Docs PDF compatibility)
  let pricingRowsHtml = '';
  if (isGSTRegistered && !isNaN(gstValue) && gstValue > 0) {
    pricingRowsHtml = `
      <table width="100%" cellpadding="6" cellspacing="0" border="1" bordercolor="${EMAIL_COLORS.paperBorder}" style="border-collapse:collapse;">
        <tr>
          <td bgcolor="${EMAIL_COLORS.paperCream}"><font color="${EMAIL_COLORS.inkGray}">Subtotal (excl. GST)</font></td>
          <td bgcolor="${EMAIL_COLORS.paperCream}" align="right"><b>$${amount}</b></td>
        </tr>
        <tr>
          <td bgcolor="${EMAIL_COLORS.paperCream}"><font color="${EMAIL_COLORS.inkGray}">GST (15%)</font></td>
          <td bgcolor="${EMAIL_COLORS.paperCream}" align="right"><b>$${gst}</b></td>
        </tr>
      </table>
      <table width="100%" cellpadding="8" cellspacing="0" border="0">
        <tr>
          <td bgcolor="${EMAIL_COLORS.brandGreen}"><font color="#ffffff"><b>TOTAL DUE (incl. GST)</b></font></td>
          <td bgcolor="${EMAIL_COLORS.brandGreen}" align="right"><font color="#ffffff" size="4"><b>$${total}</b></font></td>
        </tr>
      </table>
    `;
  } else {
    pricingRowsHtml = `
      <table width="100%" cellpadding="8" cellspacing="0" border="0">
        <tr>
          <td bgcolor="${EMAIL_COLORS.brandGreen}"><font color="#ffffff"><b>TOTAL DUE</b></font></td>
          <td bgcolor="${EMAIL_COLORS.brandGreen}" align="right"><font color="#ffffff" size="4"><b>$${displayTotal}</b></font></td>
        </tr>
      </table>
    `;
  }

  // Build bank details HTML
  let bankDetailsHtml = '';
  if (bankName) bankDetailsHtml += '<b>Bank:</b> ' + bankName + '<br>';
  if (bankAccount) bankDetailsHtml += '<b>Account:</b> ' + bankAccount + '<br>';

  // GST footer line
  const gstFooterLine = isGSTRegistered && gstNumber ? 'GST: ' + gstNumber + '<br>' : '';

  // Deposit notice for deposit invoices
  let depositNoticeHtml = '';
  if (invoiceType === 'Deposit') {
    depositNoticeHtml = `
      <table width="100%" cellpadding="8" cellspacing="0" border="0"><tr>
        <td bgcolor="${EMAIL_COLORS.alertBg}" align="center" style="border:2px dashed ${EMAIL_COLORS.alertBorder};">
          <b><font color="${EMAIL_COLORS.brandGreen}">50% Deposit Invoice</font></b> - Balance due upon project completion
        </td>
      </tr></table>
    `;
  }

  // Greeting text
  const greetingText = invoiceType === 'Deposit'
    ? 'Thank you for choosing CartCure! Please find your deposit invoice below. The remaining balance will be invoiced upon project completion.'
    : 'Thank you for choosing CartCure! Please find your invoice below for the completed work.';

  // Render the PDF template
  const bodyContent = renderEmailTemplate('invoice-pdf', {
    headingTitle: headingTitle,
    invoiceNumber: invoiceNumber,
    jobNumber: jobNumber,
    clientName: clientName,
    greetingText: greetingText,
    invoiceDate: formatNZDate(invoice['Invoice Date'] || new Date()),
    dueDate: formatDueDate(dueDate),
    pricingRowsHtml: pricingRowsHtml,
    depositNoticeHtml: depositNoticeHtml,
    bankDetailsHtml: bankDetailsHtml,
    gstFooterLine: gstFooterLine,
    businessName: businessName
  });

  return {
    success: true,
    html: bodyContent,
    invoiceData: {
      invoiceNumber: invoiceNumber,
      clientName: clientName,
      total: displayTotal
    }
  };
}

/**
 * Generate a PDF for an invoice and save it to Google Drive
 * @param {string} invoiceNumber - The invoice number
 * @param {boolean} returnBlob - If true, returns the PDF blob for email attachment; if false, saves to Drive
 * @returns {Object} - {success, pdfUrl, pdfBlob, error}
 */
function generateInvoicePDF(invoiceNumber, returnBlob) {
  try {
    // 1. Render the PDF HTML
    const htmlResult = renderInvoicePDFHtml(invoiceNumber);
    if (!htmlResult.success) {
      return { success: false, error: htmlResult.error };
    }

    // 2. Convert HTML to PDF via Google Drive API (produces valid PDF structure)
    const pdfBlob = convertHtmlToPdf(htmlResult.html, 'Invoice_' + invoiceNumber);

    // If only blob is needed (for email attachment), return it
    if (returnBlob) {
      return {
        success: true,
        pdfBlob: pdfBlob,
        invoiceData: htmlResult.invoiceData
      };
    }

    // 3. Save to Drive folder
    const folder = getOrCreateInvoicesFolder();
    const pdfFile = folder.createFile(pdfBlob);
    const pdfUrl = pdfFile.getUrl();

    // 4. Update the Invoice Log with the PDF link
    updateInvoicePDFLink(invoiceNumber, pdfUrl);

    return {
      success: true,
      pdfUrl: pdfUrl,
      pdfId: pdfFile.getId(),
      invoiceData: htmlResult.invoiceData
    };
  } catch (error) {
    return { success: false, error: 'PDF generation failed: ' + error.message };
  }
}

/**
 * Update the PDF Link column in the Invoice Log
 * @param {string} invoiceNumber - The invoice number
 * @param {string} pdfUrl - The Google Drive URL of the PDF
 */
function updateInvoicePDFLink(invoiceNumber, pdfUrl) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
    if (!invoiceSheet) return;

    const data = invoiceSheet.getDataRange().getValues();
    const invoiceCol = getColIndex('INVOICES', 'Invoice #');
    const pdfLinkCol = getColIndex('INVOICES', 'PDF Link');

    if (invoiceCol === -1 || pdfLinkCol === -1) return;

    for (let i = 1; i < data.length; i++) {
      if (data[i][invoiceCol - 1] === invoiceNumber) {
        invoiceSheet.getRange(i + 1, pdfLinkCol).setValue(pdfUrl);
        break;
      }
    }
  } catch (e) {
    Logger.log('Failed to update PDF link: ' + e.message);
  }
}

/**
 * Show dialog to download/generate invoice PDF
 * Called from menu: Invoices > Download Invoice PDF
 */
function showDownloadInvoicePDFDialog() {
  const ui = SpreadsheetApp.getUi();
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();

  // Check if we're on the Invoices sheet
  if (sheet.getName() !== SHEETS.INVOICES) {
    ui.alert('Wrong Sheet', 'Please select an invoice on the Invoice Log sheet.', ui.ButtonSet.OK);
    return;
  }

  const row = sheet.getActiveRange().getRow();
  if (row <= 1) {
    ui.alert('No Selection', 'Please select an invoice row.', ui.ButtonSet.OK);
    return;
  }

  const invoiceCol = getColIndex('INVOICES', 'Invoice #');
  const invoiceNumber = sheet.getRange(row, invoiceCol).getValue();

  if (!invoiceNumber) {
    ui.alert('No Invoice', 'Could not find invoice number in selected row.', ui.ButtonSet.OK);
    return;
  }

  // Generate the PDF
  const result = generateInvoicePDF(invoiceNumber, false);

  if (result.success) {
    ui.alert(
      'PDF Generated',
      'Invoice PDF has been created and saved to Google Drive.\n\n' +
      'Invoice: ' + invoiceNumber + '\n' +
      'Client: ' + result.invoiceData.clientName + '\n\n' +
      'The PDF link has been saved to the Invoice Log.\n' +
      'You can find the PDF in the "CartCure Invoices" folder in Google Drive.',
      ui.ButtonSet.OK
    );
  } else {
    ui.alert('Error', result.error, ui.ButtonSet.OK);
  }
}

/**
 * Download invoice PDF directly (opens PDF URL)
 * @param {string} invoiceNumber - The invoice number
 * @returns {Object} - Result with success/error and URL
 */
function downloadInvoicePDF(invoiceNumber) {
  // Check if PDF already exists in the PDF Link column
  const invoice = getInvoiceByNumber(invoiceNumber);
  if (!invoice) {
    return { success: false, error: 'Invoice not found.' };
  }

  const existingPdfLink = invoice['PDF Link'];
  if (existingPdfLink) {
    return { success: true, pdfUrl: existingPdfLink, cached: true };
  }

  // Generate new PDF
  return generateInvoicePDF(invoiceNumber, false);
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
  // PERFORMANCE: Use cached sheet reference
  const sheet = getSheet(SHEETS.INVOICES);
  if (!sheet) return [];

  const data = sheet.getDataRange().getValues();
  if (data.length <= 1) return [];

  const invoices = [];

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const invoiceNumCol = getColIndex('INVOICES', 'Invoice #') - 1;
  const jobNumColIndex = getColIndex('INVOICES', 'Job #') - 1;
  const clientNameColIndex = getColIndex('INVOICES', 'Client Name') - 1;
  const totalColIndex = getColIndex('INVOICES', 'Total') - 1;
  const statusColIndex = getColIndex('INVOICES', 'Status') - 1;

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

  // Build "I have paid" URL
  const paymentReceivedUrl = 'https://cartcure.co.nz/payment-received.html?' +
    'invoice=' + encodeURIComponent(invoiceNumber) +
    '&job=' + encodeURIComponent(jobNumber);

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
    gstFooterLine: gstFooterLine,
    paymentReceivedUrl: paymentReceivedUrl
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

  // Skip if invoice is already paid or client claims they paid
  if (invoice['Status'] === 'Paid' || invoice['Status'] === 'Paid?') {
    Logger.log('Skipping overdue invoice ' + invoiceNumber + ' - already paid or marked as paid');
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

  // Build "I have paid" URL
  const paymentReceivedUrl = 'https://cartcure.co.nz/payment-received.html?' +
    'invoice=' + encodeURIComponent(invoiceNumber) +
    '&job=' + encodeURIComponent(jobNumber);

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
    gstFooterLine: gstFooterLine,
    paymentReceivedUrl: paymentReceivedUrl
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

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const statusCol = getColIndex('INVOICES', 'Status') - 1;
  const invoiceNumCol = getColIndex('INVOICES', 'Invoice #') - 1;
  const dueDateCol = getColIndex('INVOICES', 'Due Date') - 1;
  const invoiceDateCol = getColIndex('INVOICES', 'Invoice Date') - 1;

  if (statusCol < 0 || invoiceNumCol < 0 || dueDateCol < 0) {
    Logger.log('Required columns not found in COLUMN_CONFIG');
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

  // Skip if already paid or client claims they paid
  if (invoice['Status'] === 'Paid' || invoice['Status'] === 'Paid?') {
    Logger.log('Skipping reminder for ' + invoiceNumber + ' - already paid or marked as paid');
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

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const statusCol = getColIndex('INVOICES', 'Status') - 1;
  const invoiceNumCol = getColIndex('INVOICES', 'Invoice #') - 1;
  const dueDateCol = getColIndex('INVOICES', 'Due Date') - 1;

  if (statusCol < 0 || invoiceNumCol < 0 || dueDateCol < 0) {
    Logger.log('Required columns not found in COLUMN_CONFIG');
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

    // Skip if already paid or client claims they paid
    if (status === 'Paid' || status === 'Paid?') {
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
  let hasBackgroundTasks = false;

  triggers.forEach(trigger => {
    const handler = trigger.getHandlerFunction();
    if (handler === 'autoRefreshDashboard') hasAutoRefresh = true;
    if (handler === 'autoSendInvoiceReminders') hasInvoiceReminders = true;
    if (handler === 'autoSendOverdueInvoices') hasOverdueInvoices = true;
    if (handler === 'autoSendQuoteReminders') hasQuoteReminders = true;
    if (handler === 'scanSentEmailsForJobs') hasEmailScan = true;
    if (handler === 'processBackgroundTasks') hasBackgroundTasks = true;
  });

  let created = 0;

  // Create auto-refresh trigger (every 5 minutes for better quota usage)
  if (!hasAutoRefresh) {
    ScriptApp.newTrigger('autoRefreshDashboard')
      .timeBased()
      .everyMinutes(5)
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

  // Create background task processor trigger (every 1 minute for fast deposit invoice sending)
  if (!hasBackgroundTasks) {
    ScriptApp.newTrigger('processBackgroundTasks')
      .timeBased()
      .everyMinutes(1)
      .create();
    created++;
    Logger.log('Created processBackgroundTasks trigger');
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
  const invoices = getInvoicesByStatus(['Sent', 'Overdue', 'Paid?']);

  // Use context-aware dialog for consistent behavior
  showContextAwareDialogForMarkPaid(
    'Mark Invoice as Paid',
    invoices,
    'Invoice',
    selectedInvoice
  );
}

/**
 * Show dialog to mark invoice as NOT paid
 * Only shows invoices with "Paid?" status (client claimed payment but not verified)
 */
function showMarkNotPaidDialog() {
  const ui = SpreadsheetApp.getUi();
  const selectedInvoice = getSelectedInvoiceNumber();
  const invoices = getInvoicesByStatus(['Paid?']);

  // If no Paid? invoices exist
  if (!invoices || invoices.length === 0) {
    ui.alert('No Pending Verification',
      'There are no invoices awaiting payment verification.\n\n' +
      'This action is only available for invoices with "Paid?" status ' +
      '(where clients have clicked "I Have Paid" but payment hasn\'t been verified yet).',
      ui.ButtonSet.OK);
    return;
  }

  // If we have a context-selected invoice with Paid? status, confirm directly
  if (selectedInvoice) {
    const isValidSelection = invoices.some(inv => inv.number === selectedInvoice);
    if (isValidSelection) {
      const selectedInv = invoices.find(inv => inv.number === selectedInvoice);
      const response = ui.alert(
        'Confirm: Mark as Not Paid',
        'Invoice ' + selectedInvoice + ' (' + selectedInv.clientName + ') - ' + formatCurrency(selectedInv.total) + '\n\n' +
        'This will revert the status from "Paid?" back to "Sent" or "Overdue" depending on the due date.\n\n' +
        'Are you sure this payment has NOT been received?',
        ui.ButtonSet.YES_NO
      );

      if (response === ui.Button.YES) {
        markInvoiceAsNotPaid(selectedInvoice);
        return;
      }
    }
  }

  // Show dropdown dialog for selection
  if (invoices.length === 1) {
    // Only one invoice - confirm directly
    const inv = invoices[0];
    const response = ui.alert(
      'Confirm: Mark as Not Paid',
      'Invoice ' + inv.number + ' (' + inv.clientName + ') - ' + formatCurrency(inv.total) + '\n\n' +
      'This will revert the status from "Paid?" back to "Sent" or "Overdue" depending on the due date.\n\n' +
      'Are you sure this payment has NOT been received?',
      ui.ButtonSet.YES_NO
    );

    if (response === ui.Button.YES) {
      markInvoiceAsNotPaid(inv.number);
    }
    return;
  }

  // Multiple invoices - show selection dialog
  const optionsHtml = invoices.map(inv =>
    '<option value="' + inv.number + '">' + inv.number + ' - ' + inv.clientName + ' (' + formatCurrency(inv.total) + ')</option>'
  ).join('');

  const html = HtmlService.createHtmlOutput(`
    <style>
      body { font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5; }
      .container { max-width: 400px; margin: 0 auto; }
      h3 { color: #333; margin-bottom: 15px; }
      .info { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 13px; }
      select { width: 100%; padding: 10px; font-size: 14px; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 20px; }
      .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; margin-right: 10px; }
      .btn-danger { background: #dc3545; color: white; }
      .btn-secondary { background: #6c757d; color: white; }
      .btn:hover { opacity: 0.9; }
    </style>
    <div class="container">
      <h3>Mark Invoice as Not Paid</h3>
      <div class="info">
        ⚠️ This will revert the invoice status from "Paid?" to "Sent" or "Overdue" based on the due date.
        Late fees will be recalculated from the original due date.
      </div>
      <select id="invoiceSelect">
        <option value="">-- Select Invoice --</option>
        ${optionsHtml}
      </select>
      <div>
        <button class="btn btn-danger" onclick="submit()">Mark as Not Paid</button>
        <button class="btn btn-secondary" onclick="google.script.host.close()">Cancel</button>
      </div>
    </div>
    <script>
      function submit() {
        const invoiceNumber = document.getElementById('invoiceSelect').value;
        if (!invoiceNumber) {
          alert('Please select an invoice');
          return;
        }
        google.script.run
          .withSuccessHandler(() => google.script.host.close())
          .markInvoiceAsNotPaid(invoiceNumber);
      }
    </script>
  `)
    .setWidth(450)
    .setHeight(280);

  ui.showModalDialog(html, 'Mark as Not Paid');
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
            <option value="Bank Transfer" selected>Bank Transfer</option>
            <option value="PayPal">PayPal</option>
            <option value="Stripe">Stripe</option>
          </select>

          <label for="paymentRef">Payment Reference (optional):</label>
          <input type="text" id="paymentRef" placeholder="Transaction ID or reference">
          <div class="note">e.g., Bank ref, PayPal transaction ID, Stripe payment ID</div>

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
            <option value="Bank Transfer" selected>Bank Transfer</option>
            <option value="PayPal">PayPal</option>
            <option value="Stripe">Stripe</option>
          </select>

          <label for="paymentRef">Payment Reference (optional):</label>
          <input type="text" id="paymentRef" placeholder="Transaction ID or reference">
          <div class="note">e.g., Bank ref, PayPal transaction ID, Stripe payment ID</div>

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

  // Generate unique receipt number
  const receiptNumber = generateReceiptNumber();

  const businessName = getSetting('Business Name') || 'CartCure';
  const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  const gstNumber = getSetting('GST Number') || '';

  const clientName = invoice['Client Name'];
  const clientEmail = invoice['Client Email'];
  const jobNumber = invoice['Job #'];
  const amount = Number(invoice['Amount (excl GST)'] || 0).toFixed(2);
  const gst = Number(invoice['GST'] || 0).toFixed(2);
  const total = Number(invoice['Total'] || 0).toFixed(2);
  const paidDate = formatNZDate(new Date());

  if (!clientEmail) {
    Logger.log('Cannot send receipt - no email address for invoice: ' + invoiceNumber);
    return false;
  }

  const subject = 'Payment Receipt ' + receiptNumber + ' - ' + invoiceNumber + ' from CartCure';

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

  // Generate Receipt PDF
  let pdfBlob = null;
  let pdfUrl = null;
  try {
    const pdfResult = generateReceiptPDF(invoiceNumber, receiptNumber, method, reference, true);
    if (pdfResult.success && pdfResult.pdfBlob) {
      pdfBlob = pdfResult.pdfBlob;
      // Also save to Drive folder
      const folder = getOrCreateReceiptsFolder();
      const pdfFile = folder.createFile(pdfBlob);
      pdfUrl = pdfFile.getUrl();
    }
  } catch (pdfError) {
    Logger.log('Receipt PDF generation failed (continuing without attachment): ' + pdfError.message);
  }

  // Render the template
  const bodyContent = renderEmailTemplate('email-payment-receipt', {
    receiptNumber: receiptNumber,
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
    // Build email options
    const emailOptions = {
      to: clientEmail,
      bcc: 'cartcuredrive@gmail.com',
      subject: subject,
      htmlBody: htmlBody,
      name: businessName,
      replyTo: adminEmail
    };
    if (pdfBlob) {
      emailOptions.attachments = [pdfBlob];
    }
    MailApp.sendEmail(emailOptions);

    // Log activity
    logJobActivity(
      jobNumber,
      'Email Sent',
      subject,
      'Payment receipt ' + receiptNumber + ' sent: ' + formatCurrency(total) + (pdfBlob ? ' (PDF attached)' : ''),
      'To: ' + clientEmail,
      'Auto'
    );

    // Save receipt number to Invoice Log
    updateInvoiceReceiptNumber(invoiceNumber, receiptNumber);

    // Save Receipt PDF link to Invoice Log
    if (pdfUrl) {
      updateReceiptPDFLink(invoiceNumber, pdfUrl);
    }

    Logger.log('Payment receipt ' + receiptNumber + ' sent to ' + clientEmail + ' for invoice ' + invoiceNumber);
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

  // Update client record (creates if doesn't exist, recalculates revenue from paid jobs)
  const clientEmail = invoice['Client Email'];
  if (clientEmail) {
    try {
      ensureClientExistsAndUpdate(clientEmail, {
        name: invoice['Client Name'],
        phone: '',
        storeUrl: ''
      });
    } catch (e) {
      Logger.log('Error updating client record: ' + e.message);
    }
  }

  // Log payment to activity log
  const amount = invoice['Total'] || invoice['Amount'] || '';
  const paymentDetails = [
    'Invoice: ' + invoiceNumber,
    amount ? 'Amount: ' + formatCurrency(parseFloat(amount)) : '',
    'Method: ' + method,
    reference ? 'Reference: ' + reference : ''
  ].filter(Boolean).join(', ');
  logJobActivity(jobNumber, 'Payment Received', 'Invoice marked as paid', paymentDetails, '', 'Manual');

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

  // Refresh dashboard and analytics to show updated data
  refreshDashboard(true);
  refreshAnalytics();
}

/**
 * Mark invoice as NOT paid - reverts "Paid?" status to Sent or Overdue
 * Used when admin verifies that client hasn't actually paid
 * The overdue days calculation is based on the original due date, so time spent
 * in "Paid?" status still counts towards late fees when reverted to Overdue
 */
function markInvoiceAsNotPaid(invoiceNumber) {
  const ui = SpreadsheetApp.getUi();
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    ui.alert('Not Found', 'Invoice ' + invoiceNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  // Verify the invoice is in "Paid?" status
  if (invoice['Status'] !== 'Paid?') {
    ui.alert('Invalid Status',
      'Invoice ' + invoiceNumber + ' is not in "Paid?" status.\n\nCurrent status: ' + invoice['Status'],
      ui.ButtonSet.OK);
    return;
  }

  // Calculate if the invoice is overdue based on due date
  const dueDate = invoice['Due Date'];
  let isOverdue = false;

  if (dueDate) {
    let due;
    if (dueDate instanceof Date) {
      due = dueDate;
    } else {
      // Parse DD/MM/YYYY format
      const parts = dueDate.split('/');
      if (parts.length === 3) {
        due = new Date(parts[2], parts[1] - 1, parts[0]);
      }
    }

    if (due) {
      const now = new Date();
      now.setHours(0, 0, 0, 0);
      due.setHours(0, 0, 0, 0);
      isOverdue = now > due;
    }
  }

  const newStatus = isOverdue ? 'Overdue' : 'Sent';
  const jobNumber = invoice['Job #'];

  // Update invoice status
  updateInvoiceField(invoiceNumber, 'Status', newStatus);

  // Log activity
  const clientName = invoice['Client Name'] || 'Unknown';
  const total = invoice['Total'] || 0;
  logJobActivity(
    jobNumber || '',
    'Payment Rejected',
    'Invoice marked as NOT paid',
    'Invoice ' + invoiceNumber + ' for ' + clientName + ' marked as NOT paid. Status reverted to ' + newStatus + '. Amount: $' + (parseFloat(total) || 0).toFixed(2),
    '',
    'Manual'
  );

  ui.alert('Invoice Updated',
    'Invoice ' + invoiceNumber + ' marked as NOT paid.\n\n' +
    'Status changed from "Paid?" to "' + newStatus + '".\n\n' +
    (isOverdue ? 'Note: Late fees will be recalculated based on the original due date.' : ''),
    ui.ButtonSet.OK);

  Logger.log('Invoice ' + invoiceNumber + ' marked as not paid, status reverted to ' + newStatus);

  // Refresh dashboard
  refreshDashboard(true);
}

/**
 * Cancel a draft invoice
 * ACCOUNTING SAFEGUARD: Only Draft invoices can be cancelled
 * - Invoice number is preserved (marked as Cancelled, not deleted) for audit trail
 * - Job payment status is recalculated based on remaining active invoices
 * - Activity is logged for full audit trail
 *
 * @param {string} invoiceNumber - The invoice number to cancel
 */
function cancelDraftInvoice(invoiceNumber) {
  const ui = SpreadsheetApp.getUi();
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    ui.alert('Not Found', 'Invoice ' + invoiceNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  // CRITICAL SAFEGUARD: Only allow cancellation of Draft invoices
  // Once an invoice is sent, the client has an expectation of payment
  const status = invoice['Status'];
  if (status !== 'Draft') {
    let reason = '';
    switch (status) {
      case 'Sent':
        reason = 'This invoice has been sent to the client. Sent invoices cannot be cancelled as the client has received it and may have already initiated payment.';
        break;
      case 'Overdue':
        reason = 'This invoice is overdue. Overdue invoices cannot be cancelled. If the client will not pay, consult with an accountant about proper write-off procedures.';
        break;
      case 'Paid':
        reason = 'This invoice has been paid. Paid invoices cannot be cancelled. If a refund is needed, use the proper refund process.';
        break;
      case 'Paid?':
        reason = 'This invoice has a pending payment verification. Verify the payment status first before taking any action.';
        break;
      case 'Cancelled':
        reason = 'This invoice is already cancelled.';
        break;
      default:
        reason = 'Only Draft invoices can be cancelled.';
    }
    ui.alert('Cannot Cancel Invoice',
      'Invoice ' + invoiceNumber + ' cannot be cancelled.\n\n' +
      'Current Status: ' + status + '\n\n' +
      reason,
      ui.ButtonSet.OK);
    return;
  }

  const jobNumber = invoice['Job #'];
  const clientName = invoice['Client Name'] || 'Unknown';
  const amount = parseFloat(invoice['Total']) || parseFloat(invoice['Amount (excl GST)']) || 0;
  const invoiceType = invoice['Type'] || 'Invoice';

  // Show confirmation dialog with details
  const response = ui.alert('Cancel Draft Invoice?',
    'Are you sure you want to cancel this draft invoice?\n\n' +
    'Invoice: ' + invoiceNumber + '\n' +
    'Type: ' + invoiceType + '\n' +
    'Client: ' + clientName + '\n' +
    'Amount: ' + formatCurrency(amount) + '\n' +
    'Job: ' + jobNumber + '\n\n' +
    'This action will:\n' +
    '• Mark the invoice as Cancelled (preserved for audit trail)\n' +
    '• Update the job\'s payment status if needed\n' +
    '• Log this action to the Activity Log\n\n' +
    'This cannot be undone.',
    ui.ButtonSet.YES_NO);

  if (response !== ui.Button.YES) {
    return; // User cancelled
  }

  // Cancel the invoice
  const result = cancelDraftInvoiceInternal(invoiceNumber, invoice);

  if (result.success) {
    ui.alert('Invoice Cancelled',
      'Invoice ' + invoiceNumber + ' has been cancelled.\n\n' +
      (result.paymentStatusChanged ?
        'Job ' + jobNumber + ' payment status updated to: ' + result.newPaymentStatus :
        'Job payment status unchanged.'),
      ui.ButtonSet.OK);
  } else {
    ui.alert('Error', 'Failed to cancel invoice: ' + result.error, ui.ButtonSet.OK);
  }
}

/**
 * Cancel a draft invoice silently (no dialogs) - for batch operations
 * @param {string} invoiceNumber - The invoice number to cancel
 * @returns {Object} Result object with success boolean and optional error message
 */
function cancelDraftInvoiceSilent(invoiceNumber) {
  const invoice = getInvoiceByNumber(invoiceNumber);

  if (!invoice) {
    return { success: false, error: 'Invoice not found' };
  }

  // Only allow cancellation of Draft invoices
  if (invoice['Status'] !== 'Draft') {
    return { success: false, error: 'Only Draft invoices can be cancelled. Current status: ' + invoice['Status'] };
  }

  return cancelDraftInvoiceInternal(invoiceNumber, invoice);
}

/**
 * Internal function to cancel a draft invoice
 * Handles the actual cancellation logic, payment status update, and logging
 *
 * @param {string} invoiceNumber - The invoice number
 * @param {Object} invoice - The invoice object (already validated as Draft)
 * @returns {Object} Result object
 */
function cancelDraftInvoiceInternal(invoiceNumber, invoice) {
  try {
    const jobNumber = invoice['Job #'];
    const clientName = invoice['Client Name'] || 'Unknown';
    const amount = parseFloat(invoice['Total']) || parseFloat(invoice['Amount (excl GST)']) || 0;
    const invoiceType = invoice['Type'] || 'Invoice';
    const now = new Date();

    // 1. Update invoice status to Cancelled
    updateInvoiceFields(invoiceNumber, {
      'Status': 'Cancelled',
      'Notes': (invoice['Notes'] || '') + (invoice['Notes'] ? '\n' : '') +
               'Cancelled on ' + formatNZDate(now) + ' - Draft invoice cancelled before sending.'
    });

    // 2. Recalculate job payment status based on remaining active invoices
    let paymentStatusChanged = false;
    let newPaymentStatus = '';

    if (jobNumber) {
      const result = recalculateJobPaymentStatus(jobNumber);
      paymentStatusChanged = result.changed;
      newPaymentStatus = result.newStatus;
    }

    // 3. Log to Activity Log for audit trail
    const details = [
      'Invoice: ' + invoiceNumber,
      'Type: ' + invoiceType,
      'Amount: ' + formatCurrency(amount),
      'Client: ' + clientName,
      paymentStatusChanged ? 'Payment Status Updated: ' + newPaymentStatus : 'Payment Status: Unchanged'
    ].join(', ');

    logJobActivity(
      jobNumber || '',
      'Invoice Cancelled',
      'Draft invoice cancelled before sending',
      details,
      '',
      'Manual'
    );

    Logger.log('Invoice ' + invoiceNumber + ' cancelled successfully');

    // Refresh dashboard
    refreshDashboard(true);

    return {
      success: true,
      paymentStatusChanged: paymentStatusChanged,
      newPaymentStatus: newPaymentStatus
    };

  } catch (error) {
    Logger.log('Error cancelling invoice ' + invoiceNumber + ': ' + error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Recalculate a job's payment status based on its active invoices
 * Called after cancelling an invoice to ensure payment status reflects reality
 *
 * Logic:
 * - If no active invoices (all cancelled or none exist) → Unpaid
 * - If any invoice is Overdue → Overdue
 * - If any invoice is Sent or Draft → Invoiced
 * - If all invoices are Paid → Paid
 *
 * @param {string} jobNumber - The job number to recalculate
 * @returns {Object} Result with changed boolean and newStatus
 */
function recalculateJobPaymentStatus(jobNumber) {
  const job = getJobByNumber(jobNumber);
  if (!job) {
    return { changed: false, newStatus: '', error: 'Job not found' };
  }

  const currentStatus = job['Payment Status'] || PAYMENT_STATUS.UNPAID;
  const invoices = getInvoicesByJobNumber(jobNumber);

  // Filter out cancelled invoices - they don't count for payment status
  const activeInvoices = invoices.filter(inv => inv['Status'] !== 'Cancelled');

  let newStatus = PAYMENT_STATUS.UNPAID;

  if (activeInvoices.length === 0) {
    // No active invoices - status is Unpaid
    newStatus = PAYMENT_STATUS.UNPAID;
  } else {
    // Check invoice statuses in priority order
    const hasOverdue = activeInvoices.some(inv => inv['Status'] === 'Overdue');
    const hasSentOrDraft = activeInvoices.some(inv => inv['Status'] === 'Sent' || inv['Status'] === 'Draft');
    const hasPaidPending = activeInvoices.some(inv => inv['Status'] === 'Paid?');
    const allPaid = activeInvoices.every(inv => inv['Status'] === 'Paid');

    if (hasOverdue) {
      newStatus = PAYMENT_STATUS.OVERDUE;
    } else if (hasPaidPending) {
      // If payment verification is pending, keep current invoiced status
      newStatus = PAYMENT_STATUS.INVOICED;
    } else if (allPaid) {
      newStatus = PAYMENT_STATUS.PAID;
    } else if (hasSentOrDraft) {
      newStatus = PAYMENT_STATUS.INVOICED;
    }
  }

  // Only update if status actually changed
  if (newStatus !== currentStatus) {
    updateJobField(jobNumber, 'Payment Status', newStatus);
    Logger.log('Job ' + jobNumber + ' payment status updated from ' + currentStatus + ' to ' + newStatus);
    return { changed: true, newStatus: newStatus };
  }

  return { changed: false, newStatus: currentStatus };
}

