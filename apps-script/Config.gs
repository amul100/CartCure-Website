
// ============================================================================
// JOB MANAGEMENT SYSTEM
// ============================================================================
// This section handles quotes, job tracking, invoices, and workflow management
// ============================================================================

// Job Management Configuration
var JOB_CONFIG = {
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
var SHEETS = {
  SUBMISSIONS: 'Submissions',
  JOBS: 'Jobs',
  INVOICES: 'Invoice Log',
  CLIENTS: 'Clients',
  SETTINGS: 'Settings',
  DASHBOARD: 'Dashboard',
  ANALYTICS: 'Analytics',
  TESTIMONIALS: 'Testimonials',
  ACTIVITY_LOG: 'Activity Log'
};

// Client Status Constants
var CLIENT_STATUS = {
  ACTIVE: 'Active',
  INACTIVE: 'Inactive',
  VIP: 'VIP'
};

// ============================================================================
// PERFORMANCE OPTIMIZATION: Spreadsheet & Settings Cache
// ============================================================================
// These caches persist for the duration of a single script execution.
// Google Apps Script creates a new execution context for each trigger/menu action,
// so the cache is automatically cleared between user actions.

/**
 * Cache object for spreadsheet and sheet references.
 * Reduces API calls from ~400+ to ~10 per operation.
 */
var _cache = {
  spreadsheet: null,
  sheets: {},
  settings: null,
  settingsLoaded: false
};

/**
 * PERFORMANCE: Get cached spreadsheet instance
 * Instead of calling SpreadsheetApp.openById() 400+ times, we call it once.
 *
 * @returns {Spreadsheet} The cached spreadsheet object
 */
function getSpreadsheet() {
  if (!_cache.spreadsheet) {
    _cache.spreadsheet = SpreadsheetApp.openById(CONFIG.SHEET_ID);
  }
  return _cache.spreadsheet;
}

/**
 * PERFORMANCE: Get cached sheet by name
 * Avoids repeated getSheetByName() calls for the same sheet.
 *
 * @param {string} sheetName - Name of the sheet (use SHEETS.* constants)
 * @returns {Sheet|null} The cached sheet object or null if not found
 */
function getSheet(sheetName) {
  if (!_cache.sheets[sheetName]) {
    _cache.sheets[sheetName] = getSpreadsheet().getSheetByName(sheetName);
  }
  return _cache.sheets[sheetName];
}

/**
 * PERFORMANCE: Get all settings at once, cached for the execution
 * Instead of 6+ getSetting() calls each loading the full sheet,
 * we load once and return from cache.
 *
 * @returns {Object} Object with setting names as keys
 */
function getAllSettings() {
  if (!_cache.settingsLoaded) {
    _cache.settings = {};
    const sheet = getSheet(SHEETS.SETTINGS);
    if (sheet) {
      const data = sheet.getDataRange().getValues();
      for (let i = 1; i < data.length; i++) {
        if (data[i][0]) {
          _cache.settings[data[i][0]] = data[i][1];
        }
      }
    }
    _cache.settingsLoaded = true;
  }
  return _cache.settings;
}

/**
 * PERFORMANCE: Get a single setting from cache
 * Use this instead of the old getSetting() for better performance.
 *
 * @param {string} settingName - Name of the setting to retrieve
 * @returns {*} The setting value or null if not found
 */
function getSettingCached(settingName) {
  const settings = getAllSettings();
  return settings.hasOwnProperty(settingName) ? settings[settingName] : null;
}

/**
 * Clear the cache (call this if you need to force a refresh)
 * Normally not needed as cache clears automatically between executions.
 */
function clearCache() {
  _cache.spreadsheet = null;
  _cache.sheets = {};
  _cache.settings = null;
  _cache.settingsLoaded = false;
}

// ============================================================================
// SETTINGS DIALOG
// ============================================================================

/**
 * Show the dark mode settings dialog
 */
function showSettingsDialog() {
  const html = HtmlService.createHtmlOutputFromFile('settings-dialog')
    .setWidth(480)
    .setHeight(720);
  SpreadsheetApp.getUi().showModalDialog(html, 'Settings');
}

/**
 * Get all settings for the settings dialog
 * Called from the dialog HTML via google.script.run
 * @returns {Object} Object with setting names as keys
 */
function getSettingsForDialog() {
  clearCache(); // Ensure fresh data
  return getAllSettings();
}

/**
 * Save settings from the settings dialog
 * Called from the dialog HTML via google.script.run
 * @param {Object} settings - Object with setting names as keys and values
 */
function saveSettingsFromDialog(settings) {
  const sheet = getSheet(SHEETS.SETTINGS);
  if (!sheet) {
    throw new Error('Settings sheet not found');
  }

  const data = sheet.getDataRange().getValues();

  // Update each setting in the sheet
  for (let i = 1; i < data.length; i++) {
    const settingName = data[i][0];
    if (settings.hasOwnProperty(settingName)) {
      sheet.getRange(i + 1, 2).setValue(settings[settingName]);
    }
  }

  // Clear cache so next read gets fresh values
  clearCache();

  Logger.log('Settings saved from dialog');
}

/**
 * Apply dark mode styling to the Settings sheet
 * Can be run standalone from the menu
 */
function styleSettingsSheet() {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(SHEETS.SETTINGS);

  if (!sheet) {
    SpreadsheetApp.getUi().alert('Error', 'Settings sheet not found. Please run Setup first.', SpreadsheetApp.getUi().ButtonSet.OK);
    return;
  }

  const ui = SpreadsheetApp.getUi();

  // Dark mode colors matching the dialog
  const dark = {
    bg: '#1a1a2e',
    bgAlt: '#16213e',
    header: '#0f3460',
    text: '#e4e4e7',
    accent: '#00d4aa',
    muted: '#71717a',
    border: '#2d3748'
  };

  // Get data range
  const lastRow = Math.max(sheet.getLastRow(), 16);

  // Apply dark background to entire sheet area
  sheet.getRange(1, 1, 100, 26).setBackground(dark.bg);

  // Style header row
  const headerRange = sheet.getRange(1, 1, 1, 3);
  headerRange.setBackground(dark.header);
  headerRange.setFontColor('#ffffff');
  headerRange.setFontWeight('bold');
  headerRange.setFontFamily(SHEET_FONTS.primary);
  headerRange.setFontSize(SHEET_FONTS.sizeMD + 1);
  headerRange.setHorizontalAlignment('center');
  headerRange.setVerticalAlignment('middle');
  sheet.setRowHeight(1, 40);

  // Style data rows with alternating colors
  for (let i = 2; i <= lastRow; i++) {
    const rowRange = sheet.getRange(i, 1, 1, 3);
    rowRange.setBackground((i % 2 === 0) ? dark.bgAlt : dark.bg);
    sheet.setRowHeight(i, 32);
  }

  // Setting names - white bold
  const namesRange = sheet.getRange(2, 1, lastRow - 1, 1);
  namesRange.setFontColor(dark.text);
  namesRange.setFontWeight('bold');
  namesRange.setFontFamily(SHEET_FONTS.primary);
  namesRange.setFontSize(SHEET_FONTS.sizeMD);
  namesRange.setVerticalAlignment('middle');

  // Values - green accent
  const valuesRange = sheet.getRange(2, 2, lastRow - 1, 1);
  valuesRange.setFontColor(dark.accent);
  valuesRange.setFontWeight('bold');
  valuesRange.setFontFamily(SHEET_FONTS.primary);
  valuesRange.setFontSize(SHEET_FONTS.sizeMD);
  valuesRange.setHorizontalAlignment('center');
  valuesRange.setVerticalAlignment('middle');

  // Descriptions - muted gray italic
  const descRange = sheet.getRange(2, 3, lastRow - 1, 1);
  descRange.setFontColor(dark.muted);
  descRange.setFontFamily(SHEET_FONTS.primary);
  descRange.setFontSize(SHEET_FONTS.sizeSM);
  descRange.setFontStyle('italic');
  descRange.setVerticalAlignment('middle');

  // Borders
  sheet.getRange(1, 1, lastRow, 3).setBorder(true, true, true, true, true, true, dark.border, SpreadsheetApp.BorderStyle.SOLID);

  // Column widths
  sheet.setColumnWidth(1, 200);
  sheet.setColumnWidth(2, 180);
  sheet.setColumnWidth(3, 320);

  // Hide gridlines
  sheet.setHiddenGridlines(true);

  // Freeze header
  sheet.setFrozenRows(1);

  ui.alert('Dark Mode Applied', 'Settings sheet has been styled with dark mode.', ui.ButtonSet.OK);
}

// Job Status Constants
var JOB_STATUS = {
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
var PAYMENT_STATUS = {
  UNPAID: 'Unpaid',
  INVOICED: 'Invoiced',
  PAID: 'Paid',
  OVERDUE: 'Overdue',
  REFUNDED: 'Refunded'
};

// Job Categories (matching TOS services)
var JOB_CATEGORIES = [
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
var PROJECT_SIZE = {
  SMALL: 'Small',       // Under $200 - full payment upfront
  MEDIUM: 'Medium',     // $200-$500 - 50% deposit, balance on completion
  LARGE: 'Large'        // Over $500 - case-by-case schedule
};

// Late Payment Fee Configuration
var LATE_FEE_CONFIG = {
  RATE_PER_DAY: 0.02,   // 2% per day as per TOS
  GRACE_PERIOD_DAYS: 7  // Days after due date before fees apply
};

// ============================================================================
// SHEET STYLING - Brand Color Palette
// ============================================================================
// Colors matching CartCure website and email design
var SHEET_COLORS = {
  // Primary brand colors
  brandGreen: '#2d5d3f',        // Primary accent - headers, buttons
  brandGreenLight: '#4a7c59',   // Lighter green for hover states

  // Paper-like background colors (warm off-whites)
  paperWhite: '#f9f7f3',        // Primary background
  paperCream: '#f3f0e8',        // Alternate row color (warm oatmeal)
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
// TYPOGRAPHY CONFIGURATION
// ============================================================================
var SHEET_FONTS = {
  // Primary font for all body text and headers
  primary: 'Inter',
  // Monospace for IDs, reference numbers
  mono: 'Roboto Mono',

  // Font sizes
  sizeXS: 8,
  sizeSM: 9,
  sizeMD: 10,
  sizeLG: 12,
  sizeXL: 16,
  sizeXXL: 20,

  // Row heights
  headerRowHeight: 38,
  dataRowHeight: 28,
  dashboardRowHeight: 24,
  sectionHeaderHeight: 30,
  titleRowHeight: 36,
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

var COLUMN_CONFIG = {
  // -------------------------------------------------------------------------
  // JOBS SHEET (33 columns)
  // -------------------------------------------------------------------------
  JOBS: [
    {
      name: 'Status',
      width: 120,
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
    { name: 'Job #', width: 120, format: { fontWeight: 'bold' } },
    { name: 'Total (incl GST)', width: 130, format: { numberFormat: '$#,##0.00' } },
    { name: 'Created Date', width: 120 },
    { name: 'Client Name', width: 140, format: { fontWeight: 'bold' } },
    { name: 'Client Email', width: 200 },
    { name: 'Client Phone', width: 130, format: { numberFormat: '@' } },
    { name: 'Store URL', width: 200 },
    { name: 'Job Description', width: 300, format: { wrapText: true } },
    { name: 'Category', width: 120, validation: { type: 'list', values: JOB_CATEGORIES, allowInvalid: false } },
    { name: 'Quote Amount (excl GST)', width: 170, format: { numberFormat: '$#,##0.00' } },
    { name: 'GST', width: 80, format: { numberFormat: '$#,##0.00' } },
    { name: 'Quote Sent Date', width: 140 },
    { name: 'Quote Valid Until', width: 140 },
    { name: 'Quote Accepted Date', width: 160 },
    { name: 'Days Since Accepted', width: 160 },
    { name: 'Days Remaining', width: 140 },
    {
      name: 'SLA Status',
      width: 110,
      format: {
        conditionalRules: [
          { when: 'equals', value: 'OVERDUE', background: SHEET_COLORS.slaOverdue, fontColor: SHEET_COLORS.slaOverdueText, bold: true },
          { when: 'equals', value: 'AT RISK', background: SHEET_COLORS.slaAtRisk, fontColor: SHEET_COLORS.slaAtRiskText, bold: true },
          { when: 'equals', value: 'On Track', background: SHEET_COLORS.slaOnTrack, fontColor: SHEET_COLORS.slaOnTrackText }
        ]
      }
    },
    { name: 'Estimated Turnaround', width: 170, defaultValue: JOB_CONFIG.DEFAULT_SLA_DAYS },
    { name: 'Due Date', width: 110 },
    { name: 'Actual Start Date', width: 150 },
    { name: 'Actual Completion Date', width: 180 },
    {
      name: 'Payment Status',
      width: 130,
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
    { name: 'Refund Amount', width: 130, format: { numberFormat: '$#,##0.00' } },
    { name: 'Payment Date', width: 130 },
    {
      name: 'Payment Method',
      width: 150,
      validation: { type: 'list', values: ['Bank Transfer', 'PayPal', 'Stripe'], allowInvalid: false },
      defaultValue: 'Bank Transfer'
    },
    { name: 'Payment Reference', width: 160 },
    { name: 'Invoice #', width: 100 },
    {
      name: 'Remaining Balance',
      width: 160,
      // Formula uses column name placeholders: {{Total (incl GST)}} and {{Job #}}
      formula: '=IF({{Total (incl GST)}}{{row}}="","",{{Total (incl GST)}}{{row}}-SUMIFS(\'Invoice Log\'!{{INVOICES.Total}}:{{INVOICES.Total}},\'Invoice Log\'!{{INVOICES.Job #}}:{{INVOICES.Job #}},{{Job #}}{{row}},\'Invoice Log\'!{{INVOICES.Status}}:{{INVOICES.Status}},"Paid"))',
      format: { numberFormat: '$#,##0.00' }
    },
    { name: 'Submission #', width: 130 },
    { name: 'Last Updated', width: 140 }
  ],

  // -------------------------------------------------------------------------
  // INVOICE LOG SHEET (21 columns)
  // -------------------------------------------------------------------------
  INVOICES: [
    {
      name: 'Status',
      width: 100,
      validation: { type: 'list', values: ['Draft', 'Sent', 'Paid', 'Paid?', 'Overdue', 'Cancelled'], allowInvalid: false },
      format: {
        conditionalRules: [
          { when: 'equals', value: 'Paid', background: SHEET_COLORS.paymentPaid, fontColor: SHEET_COLORS.paymentPaidText },
          { when: 'equals', value: 'Paid?', background: SHEET_COLORS.slaAtRisk, fontColor: SHEET_COLORS.slaAtRiskText },
          { when: 'equals', value: 'Sent', background: SHEET_COLORS.paymentPending, fontColor: SHEET_COLORS.paymentPendingText },
          { when: 'equals', value: 'Overdue', background: SHEET_COLORS.slaOverdue, fontColor: SHEET_COLORS.slaOverdueText, bold: true },
          { when: 'equals', value: 'Cancelled', background: SHEET_COLORS.statusCancelled, fontColor: SHEET_COLORS.statusCancelledText }
        ]
      }
    },
    { name: 'Invoice #', width: 100, format: { fontWeight: 'bold' } },
    { name: 'Job #', width: 120, format: { fontWeight: 'bold' } },
    { name: 'Client Name', width: 140, format: { fontWeight: 'bold' } },
    { name: 'Client Email', width: 200 },
    { name: 'Client Phone', width: 130, format: { numberFormat: '@' } },
    { name: 'Invoice Date', width: 120 },
    { name: 'Due Date', width: 110 },
    { name: 'Amount (excl GST)', width: 160, format: { numberFormat: '$#,##0.00' } },
    { name: 'GST', width: 80, format: { numberFormat: '$#,##0.00' } },
    { name: 'Total', width: 100, format: { numberFormat: '$#,##0.00' } },
    { name: 'Sent Date', width: 110 },
    { name: 'Paid Date', width: 110 },
    { name: 'Payment Reference', width: 160 },
    { name: 'Receipt #', width: 120 },
    { name: 'Days Overdue', width: 130 },
    { name: 'Late Fee', width: 100, format: { numberFormat: '$#,##0.00' } },
    { name: 'Total With Fees', width: 140, format: { numberFormat: '$#,##0.00' } },
    {
      name: 'Invoice Type',
      width: 120,
      validation: { type: 'list', values: ['Full', 'Deposit', 'Balance', 'Additional'], allowInvalid: false }
    },
    { name: 'Notes', width: 180 },
    { name: 'PDF Link', width: 100 },
    { name: 'Receipt PDF Link', width: 130 }
  ],

  // -------------------------------------------------------------------------
  // CLIENTS SHEET (14 columns)
  // -------------------------------------------------------------------------
  CLIENTS: [
    { name: 'Client Email', width: 220, format: { fontWeight: 'bold' } },  // PRIMARY KEY - unique identifier
    { name: 'Client Name', width: 160, format: { fontWeight: 'bold' } },
    { name: 'Client Phone', width: 130, format: { numberFormat: '@' } },
    { name: 'Store URL', width: 200 },
    { name: 'Total Jobs', width: 100, format: { numberFormat: '0' } },
    { name: 'Completed Jobs', width: 130, format: { numberFormat: '0' } },
    { name: 'Total Revenue', width: 140, format: { numberFormat: '$#,##0.00' } },
    { name: 'First Job Date', width: 120 },
    { name: 'Last Job Date', width: 120 },
    {
      name: 'Client Status',
      width: 120,
      validation: { type: 'list', values: Object.values(CLIENT_STATUS), allowInvalid: false },
      format: {
        conditionalRules: [
          { when: 'equals', value: CLIENT_STATUS.ACTIVE, background: SHEET_COLORS.statusCompleted, fontColor: SHEET_COLORS.statusCompletedText },
          { when: 'equals', value: CLIENT_STATUS.INACTIVE, background: SHEET_COLORS.statusCancelled, fontColor: SHEET_COLORS.statusCancelledText },
          { when: 'equals', value: CLIENT_STATUS.VIP, background: SHEET_COLORS.brandGreen, fontColor: '#ffffff' }
        ]
      },
      defaultValue: CLIENT_STATUS.ACTIVE
    },
    { name: 'Notes', width: 280, format: { wrapText: true } },
    { name: 'Created Date', width: 120 },
    { name: 'Last Updated', width: 130 }
  ],

  // -------------------------------------------------------------------------
  // SUBMISSIONS SHEET (11 columns)
  // -------------------------------------------------------------------------
  SUBMISSIONS: [
    {
      name: 'Status',
      width: 100,
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
    { name: 'Submission #', width: 140 },
    { name: 'Timestamp', width: 160 },
    { name: 'Name', width: 140 },
    { name: 'Email', width: 200 },
    { name: 'Phone', width: 130, format: { numberFormat: '@' } },
    { name: 'Store URL', width: 220 },
    { name: 'Message', width: 250, format: { wrapText: true } },
    { name: 'Has Voice Note', width: 120 },
    { name: 'Voice Note Link', width: 160 }
  ],

  // -------------------------------------------------------------------------
  // TESTIMONIALS SHEET (9 columns)
  // -------------------------------------------------------------------------
  TESTIMONIALS: [
    { name: 'Show on Website', width: 140, validation: { type: 'checkbox' } },
    { name: 'Submitted', width: 160 },
    { name: 'Name', width: 140 },
    { name: 'Business', width: 170 },
    { name: 'Location', width: 120 },
    { name: 'Rating', width: 80, validation: { type: 'list', values: ['1', '2', '3', '4', '5'], allowInvalid: false } },
    { name: 'Testimonial', width: 350, format: { wrapText: true } },
    { name: 'Job Number', width: 120 },
    { name: 'Email', width: 200 }
  ],

  // -------------------------------------------------------------------------
  // ACTIVITY LOG SHEET (7 columns)
  // -------------------------------------------------------------------------
  ACTIVITY_LOG: [
    { name: 'Timestamp', width: 170 },
    { name: 'Job #', width: 120 },
    { name: 'Activity Type', width: 140 },
    { name: 'Subject/Summary', width: 280 },
    { name: 'Details', width: 350, format: { wrapText: true } },
    { name: 'From/To', width: 220 },
    { name: 'Logged By', width: 120 }
  ]
};

// ============================================================================
// EDITABLE COLUMNS - Columns the admin can freely edit in the spreadsheet
// Any column NOT listed here will be reverted with a warning when edited.
// Toggle this protection via: CartCure > Setup > Column Protection
// ============================================================================
var EDITABLE_COLUMNS = {
  JOBS: [
    'Status', 'Total (incl GST)', 'Client Name', 'Client Email', 'Client Phone',
    'Store URL', 'Job Description', 'Category', 'Quote Amount (excl GST)', 'GST',
    'Quote Valid Until', 'Estimated Turnaround', 'Actual Start Date',
    'Actual Completion Date', 'Payment Status', 'Refund Amount', 'Payment Date',
    'Payment Method', 'Payment Reference'
  ],
  INVOICES: [
    'Status', 'Due Date', 'Payment Reference', 'Notes'
  ],
  CLIENTS: [
    'Client Name', 'Client Phone', 'Store URL', 'Client Status', 'Notes'
  ],
  SUBMISSIONS: [
    'Status'
  ],
  TESTIMONIALS: [
    'Show on Website', 'Job Number'
  ],
  ACTIVITY_LOG: [
    // Entire sheet is read-only — audit trail
  ]
};

// Reverse lookup: sheet display name → EDITABLE_COLUMNS key
var SHEET_TO_CONFIG_KEY = {
  [SHEETS.JOBS]: 'JOBS',
  [SHEETS.INVOICES]: 'INVOICES',
  [SHEETS.CLIENTS]: 'CLIENTS',
  [SHEETS.SUBMISSIONS]: 'SUBMISSIONS',
  [SHEETS.TESTIMONIALS]: 'TESTIMONIALS',
  [SHEETS.ACTIVITY_LOG]: 'ACTIVITY_LOG'
};

