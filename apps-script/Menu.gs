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

  // Check settings-based toggles
  let confirmSelectionEnabled = false;
  let headerProtectionEnabled = false;
  let columnProtectionEnabled = false;
  try {
    confirmSelectionEnabled = getSetting('Confirm Selection Dialog') === 'Yes';
    headerProtectionEnabled = getSetting('Header Row Protection') === 'Yes';
    columnProtectionEnabled = getSetting('Column Protection') === 'Yes';
  } catch (e) {
    // Settings may not be available yet
  }

  // Dynamic labels based on current state
  const autoRefreshLabel = autoRefreshEnabled ? '⏹️ Disable Auto-Refresh' : '▶️ Enable Auto-Refresh';
  const emailLoggingLabel = emailLoggingEnabled ? '📧 Disable Email Logging' : '📧 Enable Email Logging';
  const autoEmailsLabel = autoEmailsEnabled ? '⏰ Disable Auto Emails' : '⏰ Enable Auto Emails';
  const confirmSelectionLabel = confirmSelectionEnabled ? '✓ Disable Selection Confirmation' : '☐ Enable Selection Confirmation';
  const headerProtectionLabel = headerProtectionEnabled ? '🔒 Disable Header Protection' : '🔓 Enable Header Protection';
  const columnProtectionLabel = columnProtectionEnabled ? '🔒 Disable Column Protection' : '🔓 Enable Column Protection';

  ui.createMenu('🛒 CartCure')
    .addItem('⚡ Actions', 'showActionsForSelectedRow')
    .addSeparator()
    .addSubMenu(ui.createMenu('📊 Dashboard')
      .addItem('🔄 Refresh Dashboard', 'refreshDashboardForce')
      .addItem('📈 Refresh Analytics', 'refreshAnalytics')
      .addSeparator()
      .addItem(autoRefreshLabel, 'toggleAutoRefresh'))
    .addSeparator()
    .addSubMenu(ui.createMenu('📥 Submissions')
      .addItem('➕ Create Job', 'showCreateJobDialog')
      .addItem('👀 Mark In Review', 'showMarkInReviewDialog')
      .addItem('👎 Decline', 'showDeclineSubmissionDialog')
      .addItem('🚫 Mark as Spam', 'showMarkSpamDialog'))
    .addSubMenu(ui.createMenu('📋 Jobs')
      .addSubMenu(ui.createMenu('💰 Quotes')
        .addItem('📤 Send Quote', 'showSendQuoteDialog')
        .addItem('🔔 Send Quote Reminder', 'showQuoteReminderDialog')
        .addItem('✅ Mark Quote Accepted', 'showAcceptQuoteDialog')
        .addItem('👎 Mark Quote Declined', 'showDeclineQuoteDialog'))
      .addSeparator()
      .addItem('▶️ Start Work on Job', 'showStartWorkDialog')
      .addItem('✔️ Mark Job Complete', 'showCompleteJobDialog')
      .addItem('⏸️ Put Job On Hold', 'showOnHoldDialog')
      .addItem('❌ Cancel Job', 'showCancelJobDialog')
      .addItem('💸 Process Refund', 'showProcessRefundDialog')
      .addSeparator()
      .addItem('📜 View Activity Log', 'viewJobActivityLog')
      .addItem('📝 Add Activity Note', 'addManualActivityNote')
      .addItem('⭐ Request Testimonial', 'showRequestTestimonialDialog')
      .addSeparator()
      .addItem('🔽 Sort Newest First', 'sortJobsNewestFirst'))
    .addSubMenu(ui.createMenu('🧾 Invoices')
      .addItem('➕ Generate Invoice', 'showGenerateInvoiceDialog')
      .addItem('👁️ View Invoice', 'showViewInvoiceDialog')
      .addItem('📄 Download PDF', 'showDownloadInvoicePDFDialog')
      .addItem('📤 Send Invoice', 'showSendInvoiceDialog')
      .addItem('🔔 Send Invoice Reminder', 'showSendInvoiceReminderDialog')
      .addItem('✅ Mark as Paid', 'showMarkPaidDialog')
      .addItem('❌ Mark as Not Paid', 'showMarkNotPaidDialog')
      .addSeparator()
      .addItem('⚠️ Send Overdue Invoice', 'showSendOverdueInvoiceDialog')
      .addItem('💸 Update Late Fees', 'updateAllLateFees')
      .addItem('👁️ View Overdue Invoices', 'showOverdueInvoicesWithFees'))
    .addSubMenu(ui.createMenu('👥 Clients')
      .addItem('📋 View Client History', 'viewClientHistory')
      .addItem('🔄 Recalculate Stats', 'showRecalculateClientStatsDialog')
      .addSeparator()
      .addItem('⭐ Set VIP', 'showSetClientVIPDialog')
      .addItem('✅ Set Active', 'showSetClientActiveDialog')
      .addItem('⏸️ Set Inactive', 'showSetClientInactiveDialog')
      .addSeparator()
      .addItem('🔄 Sync Clients from Jobs', 'syncClientsFromJobs')
      .addItem('📈 Recalculate All Stats', 'recalculateAllClientStats'))
    .addSubMenu(ui.createMenu('📊 Reports')
      .addItem('📅 Monthly Report', 'showMonthlyReportDialog')
      .addItem('⏰ Aging Report', 'generateAgingReport')
      .addItem('🧾 GST Summary', 'showGSTSummaryDialog')
      .addSeparator()
      .addItem('🔍 Reconciliation Check', 'runReconciliationCheck'))
    .addSeparator()
    .addSubMenu(ui.createMenu('⚙️ Setup')
      // Settings & Preferences
      .addItem('⚙️ Settings', 'showSettingsDialog')
      .addItem(confirmSelectionLabel, 'toggleConfirmSelection')
      .addItem(headerProtectionLabel, 'toggleHeaderProtection')
      .addItem(columnProtectionLabel, 'toggleColumnProtection')
      .addSeparator()
      // Sheet Setup & Repair
      .addSubMenu(ui.createMenu('🔧 Sheet Setup')
        .addItem('🔧 Setup/Repair Sheets', 'confirmAndSetupSheets')
        .addItem('📐 Reset Column Widths', 'resetColumnWidths')
        .addItem('🔄 Repair Validation & Formatting', 'repairValidationRanges')
        .addItem('🧹 Repair Testimonials Validation', 'repairTestimonialsValidation')
        .addItem('🌙 Style Settings Sheet', 'styleSettingsSheet')
        .addSeparator()
        .addItem('🔘 Install Edit Trigger', 'installEditTrigger')
        .addSeparator()
        .addItem('⚠️ Hard Reset (Delete All Data)', 'showHardResetDialog'))
      // Email
      .addSubMenu(ui.createMenu('📧 Email')
        .addItem(autoEmailsLabel, 'toggleAutoEmails')
        .addItem(emailLoggingLabel, 'toggleEmailLogging')
        .addItem('📧 Scan Emails Now', 'scanSentEmailsForJobs'))
      // Background Tasks
      .addSubMenu(ui.createMenu('🔌 Background Tasks')
        .addItem('🔍 Diagnose Tasks', 'diagnoseBackgroundTasks')
        .addItem('▶️ Manually Process Tasks', 'manuallyProcessBackgroundTasks')
        .addSeparator()
        .addItem('⏱️ Setup Task Trigger', 'setupBackgroundTaskTrigger'))
      // Archiving
      .addSubMenu(ui.createMenu('🗄️ Archiving')
        .addItem('📦 Archive Old Jobs', 'archiveOldJobs')
        .addItem('📋 Archive Old Activity', 'archiveOldActivity')
        .addItem('📊 View Archive Stats', 'showArchiveStats'))
      .addSeparator()
      // Tests
      .addSubMenu(ui.createMenu('🧪 Tests')
        .addItem('▶️ Run Unit Tests', 'runUnitTests')
        .addItem('🔌 Run Integration Tests', 'runIntegrationTests')
        .addSeparator()
        .addItem('📝 Create 10 Test Submissions', 'createTestSubmissions')
        .addItem('⭐ Create 20 Test Testimonials', 'createTestTestimonials')
        .addItem('📋 Create Test Job for Testimonials', 'createTestJobForTestimonials')
        .addItem('📧 Send All Test Emails', 'sendAllTestEmails')))
    .addToUi();
}

/**
 * Handle edit events - used for dashboard refresh checkbox
 * This is a simple trigger with limited permissions.
 * For full functionality, run installEditTrigger() to install the trigger.
 */
function onEdit(e) {
  try {
    onEditHandler(e);
  } catch (error) {
    // Simple triggers can't show UI, so just log
    Logger.log('onEdit error: ' + error.message);
  }
}

/**
 * Main edit handler - called by both simple and installable triggers
 * @param {Object} e - The edit event object
 */
function onEditHandler(e) {
  if (!e || !e.source || !e.range) return;

  const sheet = e.source.getActiveSheet();
  const range = e.range;
  const sheetName = sheet.getName();
  const cellAddress = range.getA1Notation();

  // Check if edit was on Dashboard sheet, cell H1 (refresh checkbox)
  if (sheetName === SHEETS.DASHBOARD && cellAddress === 'H1') {
    if (e.value === 'TRUE' || range.getValue() === true) {
      // Uncheck the box first, then refresh dashboard, analytics, and invoice late fees
      range.setValue(false);
      try { updateAllLateFees(); } catch (err) { Logger.log('Late fees error: ' + err.message); }
      try { refreshDashboard(true); } catch (err) { Logger.log('Dashboard refresh error: ' + err.message); }
      try { refreshAnalytics(); } catch (err) { Logger.log('Analytics refresh error: ' + err.message); }
    }
  }

  // Check if edit was on Analytics sheet, cell H1 (refresh checkbox)
  if (sheetName === SHEETS.ANALYTICS && cellAddress === 'H1') {
    if (e.value === 'TRUE' || range.getValue() === true) {
      range.setValue(false);
      try { refreshAnalytics(); } catch (err) { Logger.log('Analytics refresh error: ' + err.message); }
    }
  }

  // Check if edit was on Activity Log sheet, cell I1 (refresh checkbox for email scan)
  if (sheetName === SHEETS.ACTIVITY_LOG && cellAddress === 'I1') {
    if (e.value === 'TRUE' || range.getValue() === true) {
      range.setValue(false);
      try { scanSentEmailsForJobs(); } catch (err) { Logger.log('Email scan error: ' + err.message); }
    }
  }

  // =========================================================================
  // INVOICE AMOUNT PROTECTION (P0 FIX) — always active regardless of toggle
  // Prevent editing of financial columns on non-Draft invoices
  // =========================================================================
  if (sheetName === SHEETS.INVOICES) {
    const row = range.getRow();
    if (row > 1) {
      const invoiceProtectedCols = ['Amount (excl GST)', 'GST', 'Total'];
      const editedCol = range.getColumn();
      let editedColumnName = null;
      for (const colName of invoiceProtectedCols) {
        if (getColIndex('INVOICES', colName) === editedCol) {
          editedColumnName = colName;
          break;
        }
      }
      if (editedColumnName) {
        const statusCol = getColIndex('INVOICES', 'Status');
        const status = sheet.getRange(row, statusCol).getValue();
        if (status && status !== 'Draft') {
          const oldValue = e.oldValue !== undefined ? e.oldValue : '';
          range.setValue(oldValue);
          try {
            SpreadsheetApp.getUi().alert(
              '⚠️ Protected Field',
              'Invoice amounts cannot be edited after the invoice has been sent.\n\n' +
              'Status: ' + status + '\n' +
              'Column: ' + editedColumnName + '\n\n' +
              'To modify amounts, either:\n' +
              '• Change status back to "Draft" first (if appropriate)\n' +
              '• Cancel this invoice and create a new one',
              SpreadsheetApp.getUi().ButtonSet.OK
            );
          } catch (uiError) {
            Logger.log('Invoice edit blocked: ' + editedColumnName + ' on row ' + row + ' (status: ' + status + ')');
          }
          return;
        }
      }
    }
  }

  // =========================================================================
  // GENERAL COLUMN PROTECTION
  // Reverts edits on system-managed columns. Toggle via Setup > Column Protection.
  // =========================================================================
  const configKey = SHEET_TO_CONFIG_KEY[sheetName];
  if (configKey) {
    const row = range.getRow();
    // Skip header row
    if (row <= 1) return;

    // Check if column protection is enabled
    let columnProtectionEnabled = false;
    try {
      columnProtectionEnabled = getSetting('Column Protection') === 'Yes';
    } catch (e) { /* settings not available yet */ }
    if (!columnProtectionEnabled) return;

    const editedCol = range.getColumn();
    const editableList = EDITABLE_COLUMNS[configKey] || [];
    const columnConfig = COLUMN_CONFIG[configKey];

    // Find the name of the edited column from COLUMN_CONFIG
    let editedColumnName = null;
    if (columnConfig && editedCol >= 1 && editedCol <= columnConfig.length) {
      editedColumnName = columnConfig[editedCol - 1].name;
    }
    if (!editedColumnName) return; // Column outside config range, allow edit

    // If column is in the editable list, allow it
    if (editableList.includes(editedColumnName)) return;

    // Column is protected — revert the change
    const oldValue = e.oldValue !== undefined ? e.oldValue : '';
    range.setValue(oldValue);

    try {
      SpreadsheetApp.getUi().alert(
        '🔒 Protected Column',
        '"' + editedColumnName + '" is a system-managed column and cannot be edited directly.\n\n' +
        'Sheet: ' + sheetName + '\n\n' +
        'This column is automatically populated by the system. ' +
        'To temporarily unlock all columns, go to:\n' +
        'CartCure > Setup > 🔓 Disable Column Protection',
        SpreadsheetApp.getUi().ButtonSet.OK
      );
    } catch (uiError) {
      Logger.log('Column edit blocked: ' + sheetName + '.' + editedColumnName + ' on row ' + row);
    }
  }
}

/**
 * Set up an installable edit trigger for better reliability
 * Run this once if the H1 refresh checkbox stops working
 * Installable triggers have more permissions than simple triggers
 */
function installEditTrigger() {
  const ui = SpreadsheetApp.getUi();

  // Remove any existing edit triggers first
  const triggers = ScriptApp.getProjectTriggers();
  let removed = 0;
  triggers.forEach(trigger => {
    if (trigger.getEventType() === ScriptApp.EventType.ON_EDIT) {
      ScriptApp.deleteTrigger(trigger);
      removed++;
    }
  });

  // Create new installable edit trigger
  ScriptApp.newTrigger('onEditHandler')
    .forSpreadsheet(SpreadsheetApp.getActive())
    .onEdit()
    .create();

  ui.alert('Edit Trigger Installed',
    (removed > 0 ? 'Removed ' + removed + ' old trigger(s).\n\n' : '') +
    'Installable edit trigger created successfully.\n\n' +
    'The H1 refresh checkbox should now work reliably.',
    ui.ButtonSet.OK
  );

  Logger.log('Installable edit trigger created');
}

/**
 * Get all selected rows from the current selection (excluding header)
 * @returns {Array<number>} Array of row numbers
 */
function getSelectedRows() {
  const rangeList = SpreadsheetApp.getActiveRangeList();
  if (!rangeList) return [];

  const rowSet = new Set(); // Use Set to avoid duplicates
  const ranges = rangeList.getRanges();

  for (const range of ranges) {
    const startRow = range.getRow();
    const numRows = range.getNumRows();
    for (let i = 0; i < numRows; i++) {
      const row = startRow + i;
      if (row > 1) rowSet.add(row); // Skip header row
    }
  }

  // Convert to sorted array
  return Array.from(rowSet).sort((a, b) => a - b);
}

/**
 * Show actions dialog for the currently selected row(s)
 * Called from the CartCure menu
 * Supports both single-row and multi-row selection
 */
function showActionsForSelectedRow() {
  const ui = SpreadsheetApp.getUi();
  const sheet = SpreadsheetApp.getActiveSheet();
  const sheetName = sheet.getName();
  const selectedRows = getSelectedRows();

  // Check if on a supported sheet
  const supportedSheets = [SHEETS.JOBS, SHEETS.SUBMISSIONS, SHEETS.INVOICES, SHEETS.CLIENTS];
  if (!supportedSheets.includes(sheetName)) {
    ui.alert('Unsupported Sheet', 'Actions are only available on Jobs, Submissions, Invoices, or Clients sheets.', ui.ButtonSet.OK);
    return;
  }

  // Check if any valid rows selected
  if (selectedRows.length === 0) {
    ui.alert('Select a Row', 'Please select a row (not the header) to see available actions.', ui.ButtonSet.OK);
    return;
  }

  // Single row - use existing dialog
  if (selectedRows.length === 1) {
    showActionsDialogForRow(sheet, sheetName, selectedRows[0]);
    return;
  }

  // Multiple rows - use multi-row dialog
  showMultiRowActionsDialog(sheet, sheetName, selectedRows);
}

// ============================================================================
// ACTIONS COLUMN FUNCTIONS
// ============================================================================

/**
 * Get valid actions for a job based on its current status
 * @param {string} status - The job's current status
 * @returns {Array} Array of action objects with id, label, and icon
 */
function getValidJobActions(status) {
  const actions = {
    [JOB_STATUS.PENDING_QUOTE]: [
      { id: 'sendQuote', label: 'Send Quote', icon: '📤' },
      { id: 'markDeclined', label: 'Mark Quote Declined', icon: '👎' },
      { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
      { id: 'addNote', label: 'Add Note', icon: '📝' }
    ],
    [JOB_STATUS.QUOTED]: [
      { id: 'sendQuoteReminder', label: 'Send Quote Reminder', icon: '🔔' },
      { id: 'markAccepted', label: 'Mark Quote Accepted', icon: '✅' },
      { id: 'markDeclined', label: 'Mark Quote Declined', icon: '👎' },
      { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
      { id: 'addNote', label: 'Add Note', icon: '📝' }
    ],
    [JOB_STATUS.QUOTE_REMINDED]: [
      { id: 'markAccepted', label: 'Mark Quote Accepted', icon: '✅' },
      { id: 'markDeclined', label: 'Mark Quote Declined', icon: '👎' },
      { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
      { id: 'addNote', label: 'Add Note', icon: '📝' }
    ],
    [JOB_STATUS.ACCEPTED]: [
      { id: 'startWork', label: 'Start Work', icon: '▶️' },
      { id: 'generateInvoice', label: 'Generate Invoice', icon: '🧾' },
      { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
      { id: 'addNote', label: 'Add Note', icon: '📝' },
      { id: 'onHold', label: 'Put On Hold', icon: '⏸️' },
      { id: 'cancel', label: 'Cancel Job', icon: '❌' }
    ],
    [JOB_STATUS.IN_PROGRESS]: [
      { id: 'markComplete', label: 'Mark Complete', icon: '✔️' },
      { id: 'generateInvoice', label: 'Generate Invoice', icon: '🧾' },
      { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
      { id: 'addNote', label: 'Add Note', icon: '📝' },
      { id: 'onHold', label: 'Put On Hold', icon: '⏸️' },
      { id: 'cancel', label: 'Cancel Job', icon: '❌' }
    ],
    [JOB_STATUS.COMPLETED]: [
      { id: 'generateInvoice', label: 'Generate Invoice', icon: '🧾' },
      { id: 'requestTestimonial', label: 'Request Testimonial', icon: '⭐' },
      { id: 'processRefund', label: 'Process Refund', icon: '💸' },
      { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
      { id: 'addNote', label: 'Add Note', icon: '📝' }
    ],
    [JOB_STATUS.ON_HOLD]: [
      { id: 'startWork', label: 'Resume Work', icon: '▶️' },
      { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
      { id: 'addNote', label: 'Add Note', icon: '📝' },
      { id: 'cancel', label: 'Cancel Job', icon: '❌' }
    ],
    [JOB_STATUS.CANCELLED]: [
      { id: 'processRefund', label: 'Process Refund', icon: '💸' },
      { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
      { id: 'addNote', label: 'Add Note', icon: '📝' }
    ],
    [JOB_STATUS.DECLINED]: [
      { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
      { id: 'addNote', label: 'Add Note', icon: '📝' }
    ]
  };

  return actions[status] || [
    { id: 'viewActivity', label: 'View Activity Log', icon: '📜' },
    { id: 'addNote', label: 'Add Note', icon: '📝' }
  ];
}

/**
 * Get valid actions for a submission based on its current status
 * @param {string} status - The submission's current status
 * @returns {Array} Array of action objects with id, label, and icon
 */
function getValidSubmissionActions(status) {
  const actions = {
    'New': [
      { id: 'createJob', label: 'Create Job', icon: '➕' },
      { id: 'markInReview', label: 'Mark In Review', icon: '👀' },
      { id: 'decline', label: 'Decline', icon: '👎' },
      { id: 'markSpam', label: 'Mark as Spam', icon: '🚫' }
    ],
    'In Review': [
      { id: 'createJob', label: 'Create Job', icon: '➕' },
      { id: 'decline', label: 'Decline', icon: '👎' },
      { id: 'markSpam', label: 'Mark as Spam', icon: '🚫' }
    ],
    'Job Created': [],
    'Declined': [
      { id: 'createJob', label: 'Create Job', icon: '➕' }
    ],
    'Spam': [
      { id: 'createJob', label: 'Create Job', icon: '➕' }
    ]
  };

  return actions[status] || [];
}

/**
 * Get valid actions for an invoice based on its current status
 * @param {string} status - The invoice's current status
 * @returns {Array} Array of action objects with id, label, and icon
 */
function getValidInvoiceActions(status) {
  const actions = {
    'Draft': [
      { id: 'viewInvoice', label: 'View Invoice', icon: '👁️' },
      { id: 'downloadPDF', label: 'Download PDF', icon: '📄' },
      { id: 'sendInvoice', label: 'Send Invoice', icon: '📤' },
      { id: 'cancelInvoice', label: 'Cancel Invoice', icon: '🗑️' }
    ],
    'Sent': [
      { id: 'viewInvoice', label: 'View Invoice', icon: '👁️' },
      { id: 'downloadPDF', label: 'Download PDF', icon: '📄' },
      { id: 'sendReminder', label: 'Send Reminder', icon: '🔔' },
      { id: 'markPaid', label: 'Mark as Paid', icon: '✅' }
    ],
    'Overdue': [
      { id: 'viewInvoice', label: 'View Invoice', icon: '👁️' },
      { id: 'downloadPDF', label: 'Download PDF', icon: '📄' },
      { id: 'sendReminder', label: 'Send Reminder', icon: '🔔' },
      { id: 'sendOverdue', label: 'Send Overdue Notice', icon: '⚠️' },
      { id: 'markPaid', label: 'Mark as Paid', icon: '✅' }
    ],
    'Paid?': [
      { id: 'viewInvoice', label: 'View Invoice', icon: '👁️' },
      { id: 'downloadPDF', label: 'Download PDF', icon: '📄' },
      { id: 'markPaid', label: 'Confirm Payment', icon: '✅' },
      { id: 'markNotPaid', label: 'Mark as Not Paid', icon: '❌' }
    ],
    'Paid': [
      { id: 'viewInvoice', label: 'View Invoice', icon: '👁️' },
      { id: 'downloadPDF', label: 'Download PDF', icon: '📄' }
    ],
    'Cancelled': [
      { id: 'viewInvoice', label: 'View Invoice', icon: '👁️' },
      { id: 'downloadPDF', label: 'Download PDF', icon: '📄' }
    ]
  };

  return actions[status] || [{ id: 'viewInvoice', label: 'View Invoice', icon: '👁️' }];
}

/**
 * Get valid actions for a client based on current status
 * @param {string} status - Current client status
 * @returns {Array} Array of action objects
 */
function getValidClientActions(status) {
  // All clients have the same actions regardless of status
  const actions = [
    { id: 'viewClientHistory', label: 'View History', icon: '📋' },
    { id: 'setStatusActive', label: 'Set Active', icon: '✅' },
    { id: 'setStatusInactive', label: 'Set Inactive', icon: '⏸️' },
    { id: 'setStatusVIP', label: 'Set VIP', icon: '⭐' },
    { id: 'recalculateStats', label: 'Recalculate Stats', icon: '🔄' }
  ];

  // Filter out the current status option
  return actions.filter(action => {
    if (status === CLIENT_STATUS.ACTIVE && action.id === 'setStatusActive') return false;
    if (status === CLIENT_STATUS.INACTIVE && action.id === 'setStatusInactive') return false;
    if (status === CLIENT_STATUS.VIP && action.id === 'setStatusVIP') return false;
    return true;
  });
}

/**
 * Show the actions dialog for a specific row
 * @param {Sheet} sheet - The active sheet
 * @param {string} sheetName - Name of the sheet (JOBS, SUBMISSIONS, INVOICES, CLIENTS)
 * @param {number} row - The row number
 */
function showActionsDialogForRow(sheet, sheetName, row) {
  const ui = SpreadsheetApp.getUi();

  // Get entity info based on sheet type
  let entityType, entityId, entityLabel, status, actions;

  if (sheetName === SHEETS.JOBS) {
    const statusCol = getColIndex('JOBS', 'Status');
    const jobNumCol = getColIndex('JOBS', 'Job #');
    const clientCol = getColIndex('JOBS', 'Client Name');

    status = sheet.getRange(row, statusCol).getValue();
    entityId = sheet.getRange(row, jobNumCol).getValue();
    const clientName = sheet.getRange(row, clientCol).getValue();

    if (!entityId) {
      ui.alert('No Job', 'This row does not contain a job.', ui.ButtonSet.OK);
      return;
    }

    entityType = 'job';
    entityLabel = entityId + (clientName ? ' - ' + clientName : '');
    actions = getValidJobActions(status);

  } else if (sheetName === SHEETS.SUBMISSIONS) {
    const statusCol = getColIndex('SUBMISSIONS', 'Status');
    const subNumCol = getColIndex('SUBMISSIONS', 'Submission #');
    const nameCol = getColIndex('SUBMISSIONS', 'Name');

    status = sheet.getRange(row, statusCol).getValue();
    entityId = sheet.getRange(row, subNumCol).getValue();
    const name = sheet.getRange(row, nameCol).getValue();

    if (!entityId) {
      ui.alert('No Submission', 'This row does not contain a submission.', ui.ButtonSet.OK);
      return;
    }

    entityType = 'submission';
    entityLabel = entityId + (name ? ' - ' + name : '');
    actions = getValidSubmissionActions(status);

  } else if (sheetName === SHEETS.INVOICES) {
    const statusCol = getColIndex('INVOICES', 'Status');
    const invNumCol = getColIndex('INVOICES', 'Invoice #');
    const clientCol = getColIndex('INVOICES', 'Client Name');

    status = sheet.getRange(row, statusCol).getValue();
    entityId = sheet.getRange(row, invNumCol).getValue();
    const clientName = sheet.getRange(row, clientCol).getValue();

    if (!entityId) {
      ui.alert('No Invoice', 'This row does not contain an invoice.', ui.ButtonSet.OK);
      return;
    }

    entityType = 'invoice';
    entityLabel = entityId + (clientName ? ' - ' + clientName : '');
    actions = getValidInvoiceActions(status);

  } else if (sheetName === SHEETS.CLIENTS) {
    const emailCol = getColIndex('CLIENTS', 'Client Email');
    const nameCol = getColIndex('CLIENTS', 'Client Name');
    const statusCol = getColIndex('CLIENTS', 'Client Status');

    entityId = sheet.getRange(row, emailCol).getValue();
    const clientName = sheet.getRange(row, nameCol).getValue();
    status = sheet.getRange(row, statusCol).getValue();

    if (!entityId) {
      ui.alert('No Client', 'This row does not contain a client.', ui.ButtonSet.OK);
      return;
    }

    entityType = 'client';
    // Keep label short to prevent dialog from expanding width
    entityLabel = clientName || entityId;
    actions = getValidClientActions(status);
  }

  // If no actions available, show message
  if (!actions || actions.length === 0) {
    ui.alert('No Actions Available', 'There are no actions available for this ' + entityType + ' with status "' + status + '".', ui.ButtonSet.OK);
    return;
  }

  // Build and show the dialog
  const htmlContent = buildActionsDialogHtml(entityType, entityId, entityLabel, status, actions);
  // Height: 100px header + 80px footer/cancel + (actions * 65px each) + 40px padding
  const dialogHeight = 100 + 80 + (actions.length * 65) + 40;
  const htmlOutput = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(500)
    .setHeight(dialogHeight);

  ui.showModalDialog(htmlOutput, 'Actions - ' + entityLabel);
}

/**
 * Build HTML for the actions dialog
 * @param {string} entityType - 'job', 'submission', or 'invoice'
 * @param {string} entityId - The entity ID (job #, submission #, invoice #)
 * @param {string} entityLabel - Display label for the entity
 * @param {string} status - Current status
 * @param {Array} actions - Array of action objects
 * @returns {string} HTML content
 */
function buildActionsDialogHtml(entityType, entityId, entityLabel, status, actions) {
  // Build action buttons HTML
  let buttonsHtml = '';
  actions.forEach(action => {
    buttonsHtml += `
      <button class="action-btn" onclick="executeAction('${entityType}', '${escapeHtml(entityId)}', '${action.id}')">
        <span class="action-icon">${action.icon}</span>
        <span class="action-label">${escapeHtml(action.label)}</span>
      </button>
    `;
  });

  return `
    <!DOCTYPE html>
    <html>
      <head>
        <base target="_top">
        <style>
          * { box-sizing: border-box; }
          html, body {
            font-family: 'Google Sans', Roboto, Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: #f8f9fa;
            min-width: 100%;
          }
          .container {
            padding: 16px;
            width: 100%;
            box-sizing: border-box;
          }
          .header {
            background: linear-gradient(135deg, #2d5d3f 0%, #1e4a2f 100%);
            color: white;
            padding: 20px;
            margin: -16px -16px 16px -16px;
          }
          .header h3 {
            margin: 0 0 8px 0;
            font-size: 18px;
            font-weight: 500;
          }
          .header .status {
            font-size: 12px;
            opacity: 0.9;
            background: rgba(255,255,255,0.2);
            padding: 4px 12px;
            border-radius: 12px;
            display: inline-block;
          }
          .actions-list {
            display: grid;
            grid-template-columns: 1fr;
            gap: 10px;
            width: 100%;
          }
          .action-btn {
            display: flex;
            align-items: center;
            justify-self: stretch;
            gap: 14px;
            width: 100%;
            min-width: 100%;
            padding: 14px 18px;
            background: white;
            border: 1px solid #dadce0;
            border-radius: 8px;
            cursor: pointer;
            text-align: left;
            font-size: 14px;
            transition: all 0.15s;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
          }
          .action-btn:hover {
            background: #f1f3f4;
            border-color: #2d5d3f;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          .action-btn:active {
            background: #e8f0eb;
          }
          .action-icon {
            font-size: 20px;
            width: 24px;
            text-align: center;
          }
          .action-label {
            color: #202124;
            font-weight: 500;
          }
          .btn-close {
            display: block;
            width: 100%;
            padding: 12px;
            margin-top: 20px;
            background: #f1f3f4;
            color: #5f6368;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
          }
          .btn-close:hover {
            background: #e8eaed;
          }
          .loading {
            display: none;
            text-align: center;
            padding: 50px 20px;
            color: #202124;
            background: #f8f9fa;
            border: 2px solid #2d5d3f;
            border-radius: 12px;
            margin: 10px 0;
          }
          .loading.show {
            display: block;
          }
          .spinner {
            display: inline-block;
            width: 48px;
            height: 48px;
            border: 5px solid #e8eaed;
            border-top-color: #2d5d3f;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 16px;
          }
          .loading-text {
            font-size: 16px;
            font-weight: 500;
            color: #2d5d3f;
          }
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
          .actions-list.hidden {
            display: none;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h3>⚡ Select Action</h3>
            <span class="status">${escapeHtml(status)}</span>
          </div>
          <div id="loadingIndicator" class="loading">
            <div class="spinner"></div>
            <div class="loading-text">Executing action...</div>
          </div>
          <div id="actionsList" class="actions-list">
            ${buttonsHtml}
          </div>
          <button class="btn-close" onclick="google.script.host.close()">Cancel</button>
        </div>
        <script>
          function executeAction(entityType, entityId, actionId) {
            // Show loading state
            document.getElementById('loadingIndicator').classList.add('show');
            document.getElementById('actionsList').classList.add('hidden');

            google.script.run
              .withSuccessHandler(function(result) {
                if (result && result.keepOpen) {
                  // Action opened another dialog, just close this one
                  google.script.host.close();
                } else if (result && result.error) {
                  alert('Error: ' + result.error);
                  document.getElementById('loadingIndicator').classList.remove('show');
                  document.getElementById('actionsList').classList.remove('hidden');
                } else {
                  // Success - close the dialog
                  google.script.host.close();
                }
              })
              .withFailureHandler(function(error) {
                alert('Error: ' + error.message);
                document.getElementById('loadingIndicator').classList.remove('show');
                document.getElementById('actionsList').classList.remove('hidden');
              })
              .executeActionFromDialog(entityType, entityId, actionId);
          }
        </script>
      </body>
    </html>
  `;
}

// ============================================================================
// MULTI-ROW ACTION SUPPORT
// ============================================================================

/**
 * Actions that support batch operations (can be performed on multiple items)
 * Actions not in this list require individual input and can only work on single items
 */
const BATCH_SUPPORTED_ACTIONS = {
  job: ['sendQuoteReminder', 'markAccepted', 'markDeclined', 'startWork', 'markComplete',
        'cancel', 'generateInvoice', 'requestTestimonial'],
  submission: ['createJob', 'markInReview', 'decline', 'markSpam'],
  invoice: ['sendInvoice', 'sendReminder', 'sendOverdue', 'markNotPaid'],
  client: ['setStatusActive', 'setStatusInactive', 'setStatusVIP', 'recalculateStats']
};

/**
 * Actions that open dialogs requiring user input (not batchable)
 */
const NON_BATCH_ACTIONS = {
  job: ['sendQuote', 'onHold', 'viewActivity', 'addNote'],
  submission: [],
  invoice: ['viewInvoice', 'markPaid'],
  client: ['viewClientHistory']
};

/**
 * Get entity information from multiple rows for Jobs sheet
 * @param {Sheet} sheet - The Jobs sheet
 * @param {Array<number>} rows - Array of row numbers
 * @returns {Array<Object>} Array of entity objects
 */
function getJobsFromRows(sheet, rows) {
  const statusCol = getColIndex('JOBS', 'Status');
  const jobNumCol = getColIndex('JOBS', 'Job #');
  const clientCol = getColIndex('JOBS', 'Client Name');

  const entities = [];
  for (const row of rows) {
    const jobNumber = sheet.getRange(row, jobNumCol).getValue();
    if (!jobNumber) continue;

    entities.push({
      row: row,
      entityId: String(jobNumber).trim(),
      status: sheet.getRange(row, statusCol).getValue(),
      label: sheet.getRange(row, clientCol).getValue() || jobNumber
    });
  }
  return entities;
}

/**
 * Get entity information from multiple rows for Submissions sheet
 * @param {Sheet} sheet - The Submissions sheet
 * @param {Array<number>} rows - Array of row numbers
 * @returns {Array<Object>} Array of entity objects
 */
function getSubmissionsFromRows(sheet, rows) {
  const statusCol = getColIndex('SUBMISSIONS', 'Status');
  const subNumCol = getColIndex('SUBMISSIONS', 'Submission #');
  const nameCol = getColIndex('SUBMISSIONS', 'Name');

  const entities = [];
  for (const row of rows) {
    const subNumber = sheet.getRange(row, subNumCol).getValue();
    if (!subNumber) continue;

    entities.push({
      row: row,
      entityId: String(subNumber).trim(),
      status: sheet.getRange(row, statusCol).getValue(),
      label: sheet.getRange(row, nameCol).getValue() || subNumber
    });
  }
  return entities;
}

/**
 * Get entity information from multiple rows for Invoices sheet
 * @param {Sheet} sheet - The Invoices sheet
 * @param {Array<number>} rows - Array of row numbers
 * @returns {Array<Object>} Array of entity objects
 */
function getInvoicesFromRows(sheet, rows) {
  const statusCol = getColIndex('INVOICES', 'Status');
  const invNumCol = getColIndex('INVOICES', 'Invoice #');
  const clientCol = getColIndex('INVOICES', 'Client Name');

  const entities = [];
  for (const row of rows) {
    const invNumber = sheet.getRange(row, invNumCol).getValue();
    if (!invNumber) continue;

    entities.push({
      row: row,
      entityId: String(invNumber).trim(),
      status: sheet.getRange(row, statusCol).getValue(),
      label: sheet.getRange(row, clientCol).getValue() || invNumber
    });
  }
  return entities;
}

/**
 * Get entity information from multiple rows for Clients sheet
 * @param {Sheet} sheet - The Clients sheet
 * @param {Array<number>} rows - Array of row numbers
 * @returns {Array<Object>} Array of entity objects
 */
function getClientsFromRows(sheet, rows) {
  const emailCol = getColIndex('CLIENTS', 'Client Email');
  const nameCol = getColIndex('CLIENTS', 'Client Name');
  const statusCol = getColIndex('CLIENTS', 'Client Status');

  const entities = [];
  for (const row of rows) {
    const email = sheet.getRange(row, emailCol).getValue();
    if (!email) continue;

    entities.push({
      row: row,
      entityId: String(email).trim(),
      status: sheet.getRange(row, statusCol).getValue(),
      label: sheet.getRange(row, nameCol).getValue() || email
    });
  }
  return entities;
}

/**
 * Get entities from rows based on sheet type
 * @param {Sheet} sheet - The active sheet
 * @param {string} sheetName - Name of the sheet
 * @param {Array<number>} rows - Array of row numbers
 * @returns {Object} Object with entityType and entities array
 */
function getEntitiesFromRows(sheet, sheetName, rows) {
  if (sheetName === SHEETS.JOBS) {
    return { entityType: 'job', entities: getJobsFromRows(sheet, rows) };
  } else if (sheetName === SHEETS.SUBMISSIONS) {
    return { entityType: 'submission', entities: getSubmissionsFromRows(sheet, rows) };
  } else if (sheetName === SHEETS.INVOICES) {
    return { entityType: 'invoice', entities: getInvoicesFromRows(sheet, rows) };
  } else if (sheetName === SHEETS.CLIENTS) {
    return { entityType: 'client', entities: getClientsFromRows(sheet, rows) };
  }
  return { entityType: null, entities: [] };
}

/**
 * Calculate common actions available for all selected entities
 * @param {string} entityType - Type of entity (job, submission, invoice, client)
 * @param {Array<Object>} entities - Array of entity objects with status
 * @returns {Object} Object with commonActions, partialActions, statusBreakdown, actionEntityMap
 */
function getCommonActionsForEntities(entityType, entities) {
  // Get the appropriate getValidActions function
  const getValidActions = {
    'job': getValidJobActions,
    'submission': getValidSubmissionActions,
    'invoice': getValidInvoiceActions,
    'client': getValidClientActions
  }[entityType];

  if (!getValidActions) {
    return { commonActions: [], partialActions: [], statusBreakdown: {}, actionEntityMap: {} };
  }

  // Count entities by status
  const statusBreakdown = {};
  entities.forEach(entity => {
    const status = entity.status || 'Unknown';
    statusBreakdown[status] = (statusBreakdown[status] || 0) + 1;
  });

  // Get valid actions for each entity and track which entities support each action
  const actionCounts = {};
  const actionDetails = {};
  const actionEntityMap = {}; // Maps actionId -> array of entityIds that support it

  entities.forEach(entity => {
    const actions = getValidActions(entity.status);
    actions.forEach(action => {
      if (!actionCounts[action.id]) {
        actionCounts[action.id] = 0;
        actionDetails[action.id] = action;
        actionEntityMap[action.id] = [];
      }
      actionCounts[action.id]++;
      actionEntityMap[action.id].push(entity.entityId);
    });
  });

  const totalEntities = entities.length;
  const batchSupported = BATCH_SUPPORTED_ACTIONS[entityType] || [];
  const nonBatch = NON_BATCH_ACTIONS[entityType] || [];

  // Separate into common (all entities), partial (some entities), and single-only
  const commonActions = [];
  const partialActions = [];

  Object.keys(actionCounts).forEach(actionId => {
    const count = actionCounts[actionId];
    const action = { ...actionDetails[actionId] };
    action.count = count;
    action.total = totalEntities;
    action.isBatchable = batchSupported.includes(actionId);
    action.isNonBatch = nonBatch.includes(actionId);
    action.validEntityIds = actionEntityMap[actionId]; // Add the list of valid entity IDs

    if (count === totalEntities) {
      // Available for all selected items
      if (action.isBatchable) {
        commonActions.push(action);
      } else if (action.isNonBatch) {
        // Non-batchable actions shown with indicator
        action.label = action.label + ' (single item only)';
        action.singleOnly = true;
        partialActions.push(action);
      }
    } else if (count > 0 && action.isBatchable) {
      // Available for some items only - add to partial
      action.label = action.label + ' (' + count + ' of ' + totalEntities + ')';
      action.partial = true;
      partialActions.push(action);
    }
  });

  return {
    commonActions,
    partialActions,
    statusBreakdown,
    totalEntities,
    actionEntityMap
  };
}

/**
 * Show the multi-row actions dialog
 * @param {Sheet} sheet - The active sheet
 * @param {string} sheetName - Name of the sheet
 * @param {Array<number>} rows - Array of selected row numbers
 */
function showMultiRowActionsDialog(sheet, sheetName, rows) {
  const ui = SpreadsheetApp.getUi();

  // Get entities from rows
  const { entityType, entities } = getEntitiesFromRows(sheet, sheetName, rows);

  if (entities.length === 0) {
    ui.alert('No Items', 'No valid items found in the selected rows.', ui.ButtonSet.OK);
    return;
  }

  // Calculate common actions
  const { commonActions, partialActions, statusBreakdown, totalEntities, actionEntityMap } =
    getCommonActionsForEntities(entityType, entities);

  // Check if any actions available
  if (commonActions.length === 0 && partialActions.length === 0) {
    ui.alert('No Actions Available',
      'There are no batch actions available for the selected items. ' +
      'The selected items may have different statuses that don\'t share any common actions.',
      ui.ButtonSet.OK);
    return;
  }

  // Build and show the dialog
  const entityIds = entities.map(e => e.entityId);
  const htmlContent = buildMultiRowActionsDialogHtml(
    entityType, entityIds, entities, statusBreakdown, commonActions, partialActions, actionEntityMap
  );

  // Calculate height based on content
  const actionCount = commonActions.length + partialActions.length;
  const statusCount = Object.keys(statusBreakdown).length;
  const dialogHeight = 180 + (statusCount * 24) + (actionCount * 65) + 60;

  const htmlOutput = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(520)
    .setHeight(Math.min(dialogHeight, 600));

  ui.showModalDialog(htmlOutput, 'Batch Actions - ' + totalEntities + ' Items Selected');
}

/**
 * Build HTML for the multi-row actions dialog
 * @param {string} entityType - Type of entity
 * @param {Array<string>} entityIds - Array of entity IDs
 * @param {Array<Object>} entities - Array of entity objects
 * @param {Object} statusBreakdown - Count of entities by status
 * @param {Array<Object>} commonActions - Actions available for all
 * @param {Array<Object>} partialActions - Actions available for some
 * @param {Object} actionEntityMap - Maps actionId to array of valid entity IDs
 * @returns {string} HTML content
 */
function buildMultiRowActionsDialogHtml(entityType, entityIds, entities, statusBreakdown, commonActions, partialActions, actionEntityMap) {
  // Build status breakdown HTML
  let statusHtml = '';
  Object.keys(statusBreakdown).forEach(status => {
    statusHtml += '<div class="status-item"><span class="status-badge">' +
      escapeHtml(status) + '</span> <span class="status-count">' +
      statusBreakdown[status] + '</span></div>';
  });

  // Build selected items list HTML
  let selectedItemsHtml = '';
  entities.forEach(entity => {
    const statusClass = (entity.status || '').toLowerCase().replace(/[^a-z]/g, '-');
    selectedItemsHtml += '<div class="selected-item">' +
      '<span class="item-id">' + escapeHtml(entity.entityId) + '</span>' +
      '<span class="item-label">' + escapeHtml(entity.label || '') + '</span>' +
      '</div>';
  });

  // Build common action buttons (use all entity IDs since all support the action)
  let commonButtonsHtml = '';
  commonActions.forEach(action => {
    commonButtonsHtml += `
      <button class="action-btn" onclick="executeBatchAction('${entityType}', '${action.id}', null)">
        <span class="action-icon">${action.icon}</span>
        <span class="action-label">${escapeHtml(action.label)}</span>
        <span class="action-count">All ${entities.length}</span>
      </button>
    `;
  });

  // Build partial action buttons (use only valid entity IDs for each action)
  let partialButtonsHtml = '';
  partialActions.forEach(action => {
    if (action.singleOnly) {
      // Non-batchable action - disabled with tooltip
      partialButtonsHtml += `
        <button class="action-btn action-disabled" disabled title="This action requires individual input for each item">
          <span class="action-icon">${action.icon}</span>
          <span class="action-label">${escapeHtml(action.label)}</span>
        </button>
      `;
    } else {
      // Partial action - pass only valid entity IDs for this action
      const validIdsJson = JSON.stringify(action.validEntityIds || []);
      partialButtonsHtml += `
        <button class="action-btn action-partial" onclick="executeBatchAction('${entityType}', '${action.id}', ${validIdsJson})">
          <span class="action-icon">${action.icon}</span>
          <span class="action-label">${escapeHtml(action.label)}</span>
        </button>
      `;
    }
  });

  // Serialize entity IDs for JavaScript (all IDs for common actions)
  const entityIdsJson = JSON.stringify(entityIds);

  return `
    <!DOCTYPE html>
    <html>
      <head>
        <base target="_top">
        <style>
          * { box-sizing: border-box; }
          html, body {
            font-family: 'Google Sans', Roboto, Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: #f8f9fa;
            min-width: 100%;
          }
          .container {
            padding: 16px;
            width: 100%;
            box-sizing: border-box;
          }
          .header {
            background: linear-gradient(135deg, #1a73e8 0%, #1557b0 100%);
            color: white;
            padding: 20px;
            margin: -16px -16px 16px -16px;
          }
          .header h3 {
            margin: 0 0 12px 0;
            font-size: 18px;
            font-weight: 500;
          }
          .warning-banner {
            background: #fef7e0;
            border: 1px solid #f9ab00;
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
          }
          .warning-banner .icon {
            font-size: 20px;
          }
          .warning-banner .text {
            color: #b06000;
            font-size: 13px;
          }
          .status-breakdown {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
          }
          .status-item {
            display: flex;
            align-items: center;
            gap: 6px;
            background: rgba(255,255,255,0.15);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
          }
          .status-badge {
            opacity: 0.9;
          }
          .status-count {
            font-weight: 600;
          }
          .selected-items-toggle {
            background: rgba(255,255,255,0.1);
            border: none;
            color: white;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-top: 10px;
            display: flex;
            align-items: center;
            gap: 6px;
          }
          .selected-items-toggle:hover {
            background: rgba(255,255,255,0.2);
          }
          .selected-items-list {
            display: none;
            background: rgba(255,255,255,0.1);
            border-radius: 6px;
            padding: 8px;
            margin-top: 8px;
            max-height: 120px;
            overflow-y: auto;
          }
          .selected-items-list.show {
            display: block;
          }
          .selected-item {
            display: flex;
            justify-content: space-between;
            padding: 4px 8px;
            font-size: 12px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
          }
          .selected-item:last-child {
            border-bottom: none;
          }
          .item-id {
            font-weight: 600;
            opacity: 0.9;
          }
          .item-label {
            opacity: 0.8;
            text-align: right;
            max-width: 60%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
          }
          .section-title {
            font-size: 12px;
            font-weight: 600;
            color: #5f6368;
            text-transform: uppercase;
            margin: 16px 0 10px 0;
            letter-spacing: 0.5px;
          }
          .actions-list {
            display: grid;
            grid-template-columns: 1fr;
            gap: 10px;
            width: 100%;
          }
          .action-btn {
            display: flex;
            align-items: center;
            justify-self: stretch;
            gap: 14px;
            width: 100%;
            min-width: 100%;
            padding: 14px 18px;
            background: white;
            border: 1px solid #dadce0;
            border-radius: 8px;
            cursor: pointer;
            text-align: left;
            font-size: 14px;
            transition: all 0.15s;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
          }
          .action-btn:hover:not(:disabled) {
            background: #f1f3f4;
            border-color: #1a73e8;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          .action-btn:active:not(:disabled) {
            background: #e8f0fe;
          }
          .action-btn.action-disabled {
            opacity: 0.5;
            cursor: not-allowed;
            background: #f5f5f5;
          }
          .action-btn.action-partial {
            border-left: 3px solid #f9ab00;
          }
          .action-icon {
            font-size: 20px;
            width: 24px;
            text-align: center;
          }
          .action-label {
            color: #202124;
            font-weight: 500;
            flex: 1;
          }
          .action-count {
            color: #5f6368;
            font-size: 12px;
            background: #e8f0fe;
            padding: 2px 8px;
            border-radius: 10px;
          }
          .btn-close {
            display: block;
            width: 100%;
            padding: 12px;
            margin-top: 20px;
            background: #f1f3f4;
            color: #5f6368;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
          }
          .btn-close:hover {
            background: #e8eaed;
          }
          .loading {
            display: none;
            text-align: center;
            padding: 60px 20px;
            color: #202124;
            background: #f8f9fa;
            border: 3px solid #2d5d3f;
            border-radius: 12px;
            margin: 20px 0;
          }
          .loading.show {
            display: block;
          }
          .content.hidden {
            display: none;
          }
          .spinner {
            display: inline-block;
            width: 56px;
            height: 56px;
            border: 6px solid #e8eaed;
            border-top-color: #2d5d3f;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 20px;
          }
          .loading-text {
            font-size: 18px;
            font-weight: 600;
            color: #2d5d3f;
          }
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h3>⚡ Batch Actions</h3>
            <div class="status-breakdown">
              ${statusHtml}
            </div>
            <button class="selected-items-toggle" onclick="toggleSelectedItems()">
              <span>📋</span> View Selected Items (${entities.length})
              <span id="toggleArrow">▼</span>
            </button>
            <div id="selectedItemsList" class="selected-items-list">
              ${selectedItemsHtml}
            </div>
          </div>

          <div id="loadingIndicator" class="loading">
            <div class="spinner"></div>
            <div class="loading-text" id="loadingText">Processing...</div>
          </div>

          <div id="content" class="content">
            <div class="warning-banner">
              <span class="icon">⚠️</span>
              <span class="text">Actions will be applied to <strong>all ${entities.length} selected items</strong>. This cannot be undone.</span>
            </div>

            ${commonActions.length > 0 ? '<div class="section-title">Available for All Items</div>' : ''}
            <div class="actions-list">
              ${commonButtonsHtml}
            </div>

            ${partialActions.length > 0 ? '<div class="section-title">Other Actions</div>' : ''}
            <div class="actions-list">
              ${partialButtonsHtml}
            </div>

            <button class="btn-close" onclick="google.script.host.close()">Cancel</button>
          </div>
        </div>
        <script>
          const allEntityIds = ${entityIdsJson};

          function executeBatchAction(entityType, actionId, specificEntityIds) {
            // Use specific entity IDs if provided (for partial actions), otherwise use all
            const idsToProcess = specificEntityIds || allEntityIds;
            const itemCount = idsToProcess.length;

            // Show confirmation with accurate count
            const confirmed = confirm(
              'Are you sure you want to perform this action on ' + itemCount + ' item' + (itemCount !== 1 ? 's' : '') + '?\\n\\n' +
              'This action cannot be undone.'
            );

            if (!confirmed) return;

            // Show loading state
            document.getElementById('loadingIndicator').classList.add('show');
            document.getElementById('content').classList.add('hidden');
            document.getElementById('loadingText').textContent = 'Processing ' + itemCount + ' item' + (itemCount !== 1 ? 's' : '') + '...';

            google.script.run
              .withSuccessHandler(function(result) {
                if (result && result.error) {
                  alert('Error: ' + result.error);
                  document.getElementById('loadingIndicator').classList.remove('show');
                  document.getElementById('content').classList.remove('hidden');
                } else if (result && result.results) {
                  const failures = result.results.filter(r => !r.success);

                  // Only show alert if there were failures
                  if (failures.length > 0) {
                    let message = 'Some items failed:\\n\\n';
                    failures.slice(0, 5).forEach(f => {
                      message += '- ' + f.entityId + ': ' + (f.error || 'Unknown error') + '\\n';
                    });
                    if (failures.length > 5) {
                      message += '... and ' + (failures.length - 5) + ' more\\n';
                    }
                    alert(message);
                  }
                  google.script.host.close();
                } else {
                  google.script.host.close();
                }
              })
              .withFailureHandler(function(error) {
                alert('Error: ' + (error.message || 'Unknown error'));
                document.getElementById('loadingIndicator').classList.remove('show');
                document.getElementById('content').classList.remove('hidden');
              })
              .executeBatchActionFromDialog(entityType, idsToProcess, actionId);
          }

          function toggleSelectedItems() {
            const list = document.getElementById('selectedItemsList');
            const arrow = document.getElementById('toggleArrow');
            if (list.classList.contains('show')) {
              list.classList.remove('show');
              arrow.textContent = '▼';
            } else {
              list.classList.add('show');
              arrow.textContent = '▲';
            }
          }
        </script>
      </body>
    </html>
  `;
}

/**
 * Execute a batch action from the multi-row actions dialog
 * Processes items with chunking to prevent timeouts and stores progress for polling
 * @param {string} entityType - Type of entity (job, submission, invoice, client)
 * @param {Array<string>} entityIds - Array of entity IDs to process
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object with results array
 */
function executeBatchActionFromDialog(entityType, entityIds, actionId) {
  const results = [];
  const totalItems = entityIds.length;
  const CHUNK_SIZE = 10; // Process in chunks to prevent timeout
  const DELAY_BETWEEN_ITEMS_MS = 100; // Small delay to prevent rate limiting

  // Generate a unique batch ID for progress tracking
  const batchId = 'batch_' + new Date().getTime() + '_' + Math.random().toString(36).substr(2, 9);
  const cache = CacheService.getUserCache();

  // Store initial progress
  cache.put(batchId, JSON.stringify({ processed: 0, total: totalItems, status: 'running' }), 300);

  for (let i = 0; i < entityIds.length; i++) {
    const entityId = entityIds[i];

    try {
      let result;
      if (entityType === 'job') {
        result = executeBatchJobAction(entityId, actionId);
      } else if (entityType === 'submission') {
        result = executeBatchSubmissionAction(entityId, actionId);
      } else if (entityType === 'invoice') {
        result = executeBatchInvoiceAction(entityId, actionId);
      } else if (entityType === 'client') {
        result = executeBatchClientAction(entityId, actionId);
      } else {
        result = { success: false, error: 'Unknown entity type' };
      }

      results.push({
        entityId: entityId,
        success: result ? (result.success || false) : false,
        error: result ? (result.error || null) : 'No result returned'
      });
    } catch (error) {
      results.push({
        entityId: entityId,
        success: false,
        error: error.message || 'Unknown error'
      });
    }

    // Update progress in cache every item
    cache.put(batchId, JSON.stringify({ processed: i + 1, total: totalItems, status: 'running' }), 300);

    // Small delay between items to prevent rate limiting (skip on last item)
    if (i < entityIds.length - 1 && DELAY_BETWEEN_ITEMS_MS > 0) {
      Utilities.sleep(DELAY_BETWEEN_ITEMS_MS);
    }

    // Yield periodically to prevent script timeout on very large batches
    if ((i + 1) % CHUNK_SIZE === 0 && i < entityIds.length - 1) {
      // Flush the spreadsheet changes
      SpreadsheetApp.flush();
    }
  }

  // Mark batch as complete
  cache.put(batchId, JSON.stringify({ processed: totalItems, total: totalItems, status: 'complete' }), 60);

  return { results: results, batchId: batchId };
}

/**
 * Get the progress of a batch operation
 * Called by the client to poll for progress updates
 * @param {string} batchId - The batch ID from executeBatchActionFromDialog
 * @returns {Object} Progress object with processed, total, and status
 */
function getBatchProgress(batchId) {
  const cache = CacheService.getUserCache();
  const progressJson = cache.get(batchId);

  if (!progressJson) {
    return { processed: 0, total: 0, status: 'unknown' };
  }

  try {
    return JSON.parse(progressJson);
  } catch (e) {
    return { processed: 0, total: 0, status: 'error' };
  }
}

/**
 * Execute a batch job action (no dialogs, silent operation)
 * @param {string} jobNumber - The job number
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object
 */
function executeBatchJobAction(jobNumber, actionId) {
  switch (actionId) {
    case 'sendQuoteReminder':
      return sendQuoteReminderSilent(jobNumber);

    case 'markAccepted':
      return markQuoteAcceptedSilent(jobNumber);

    case 'markDeclined':
      return markQuoteDeclinedSilent(jobNumber);

    case 'startWork':
      return startWorkOnJobSilent(jobNumber);

    case 'markComplete':
      return markJobCompleteSilent(jobNumber);

    case 'cancel':
      return cancelJobSilent(jobNumber, 'Batch cancelled');

    case 'generateInvoice':
      return generateInvoiceForJobSilent(jobNumber);

    case 'requestTestimonial':
      return sendTestimonialRequestSilent(jobNumber);

    default:
      return { success: false, error: 'Action not supported for batch: ' + actionId };
  }
}

/**
 * Execute a batch submission action (no dialogs, silent operation)
 * @param {string} submissionNumber - The submission number
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object
 */
function executeBatchSubmissionAction(submissionNumber, actionId) {
  switch (actionId) {
    case 'createJob':
      return createJobFromSubmissionSilent(submissionNumber);

    case 'markInReview':
      updateSubmissionStatus(submissionNumber, 'In Review');
      return { success: true };

    case 'decline':
      updateSubmissionStatus(submissionNumber, 'Declined');
      return { success: true };

    case 'markSpam':
      updateSubmissionStatus(submissionNumber, 'Spam');
      return { success: true };

    default:
      return { success: false, error: 'Action not supported for batch: ' + actionId };
  }
}

/**
 * Execute a batch invoice action (no dialogs, silent operation)
 * @param {string} invoiceNumber - The invoice number
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object
 */
function executeBatchInvoiceAction(invoiceNumber, actionId) {
  switch (actionId) {
    case 'sendInvoice':
      return sendInvoiceEmailSilent(invoiceNumber);

    case 'sendReminder':
      return sendInvoiceReminderSilent(invoiceNumber);

    case 'sendOverdue':
      return sendOverdueInvoiceSilent(invoiceNumber);

    case 'markNotPaid':
      return markInvoiceAsNotPaidSilent(invoiceNumber);

    case 'cancelInvoice':
      return cancelDraftInvoiceSilent(invoiceNumber);

    default:
      return { success: false, error: 'Action not supported for batch: ' + actionId };
  }
}

/**
 * Execute a batch client action (no dialogs, silent operation)
 * @param {string} clientEmail - The client's email
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object
 */
function executeBatchClientAction(clientEmail, actionId) {
  try {
    // Verify client exists before any operation
    const client = findClientByEmail(clientEmail);
    if (!client) {
      return { success: false, error: 'Client not found' };
    }

    switch (actionId) {
      case 'setStatusActive':
        updateClientStatus(clientEmail, CLIENT_STATUS.ACTIVE);
        return { success: true };

      case 'setStatusInactive':
        updateClientStatus(clientEmail, CLIENT_STATUS.INACTIVE);
        return { success: true };

      case 'setStatusVIP':
        updateClientStatus(clientEmail, CLIENT_STATUS.VIP);
        return { success: true };

      case 'recalculateStats':
        updateClientStatistics(clientEmail);
        return { success: true };

      default:
        return { success: false, error: 'Action not supported for batch: ' + actionId };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Show a batch action confirmation dialog for menu-triggered actions
 * Used when user selects multiple rows and uses a menu action
 * @param {string} entityType - Type of entity (job, submission, invoice, client)
 * @param {Array<string>} entityIds - Array of entity IDs to process
 * @param {string} actionId - The action to execute
 * @param {string} actionLabel - Human-readable label for the action
 * @param {number} totalSelected - Total number of rows selected (optional, for showing filtered info)
 */
function showBatchMenuActionDialog(entityType, entityIds, actionId, actionLabel, totalSelected) {
  const ui = SpreadsheetApp.getUi();
  const validCount = entityIds.length;
  const totalCount = totalSelected || validCount;

  // Get proper entity type label
  const entityLabels = {
    'job': 'Job',
    'submission': 'Submission',
    'invoice': 'Invoice',
    'client': 'Client'
  };
  const entityLabel = entityLabels[entityType] || 'Item';
  const entityLabelPlural = entityLabel + 's';

  // Build the selection info message
  let selectionInfo = '';
  if (totalCount > validCount) {
    selectionInfo = `<div class="selection-warning">
      <strong>${totalCount} rows selected</strong> - ${validCount} valid for this action
    </div>`;
  } else {
    selectionInfo = `<div class="selection-info">
      <strong>${validCount} ${validCount === 1 ? entityLabel : entityLabelPlural}</strong> selected
    </div>`;
  }

  const htmlContent = `
    <!DOCTYPE html>
    <html>
      <head>
        <base target="_top">
        <style>
          * { box-sizing: border-box; }
          html, body { margin: 0; padding: 0; min-width: 100%; }
          body { font-family: Arial, sans-serif; padding: 20px; }
          .container { width: 100%; }
          h3 { margin: 0 0 12px 0; color: #333; }
          .selection-info {
            background: #e8f5e9;
            border: 1px solid #4caf50;
            border-radius: 6px;
            padding: 10px 14px;
            margin-bottom: 12px;
            color: #2e7d32;
            font-size: 14px;
          }
          .selection-warning {
            background: #fff3e0;
            border: 1px solid #ff9800;
            border-radius: 6px;
            padding: 10px 14px;
            margin-bottom: 12px;
            color: #e65100;
            font-size: 14px;
          }
          .entity-section-label {
            font-size: 12px;
            color: #666;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
          }
          .entity-list {
            max-height: 180px;
            overflow-y: auto;
            border: 2px solid #2d5d3f;
            border-radius: 6px;
            padding: 0;
            margin-bottom: 15px;
            font-size: 13px;
            background: #fff;
          }
          .entity-item {
            padding: 8px 12px;
            color: #333;
            border-bottom: 1px solid #eee;
            font-family: 'Courier New', monospace;
            font-weight: 500;
          }
          .entity-item:last-child { border-bottom: none; }
          .entity-item:nth-child(odd) { background: #f8f9fa; }
          .buttons {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
          }
          button {
            padding: 12px 20px;
            font-size: 14px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
          }
          .confirm { background: #2d5d3f; color: white; }
          .confirm:hover:not(:disabled) { background: #4a7c59; }
          .cancel { background: #e0e0e0; color: #333; }
          .cancel:hover:not(:disabled) { background: #d0d0d0; }
          button:disabled { opacity: 0.6; cursor: not-allowed; }
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
          .loading-overlay {
            display: none;
            text-align: center;
            padding: 50px 20px;
            background: #f8f9fa;
            border: 3px solid #2d5d3f;
            border-radius: 12px;
            margin-top: 20px;
          }
          .loading-overlay.show {
            display: block;
          }
          .spinner-large {
            display: inline-block;
            width: 56px;
            height: 56px;
            border: 6px solid #e8eaed;
            border-top-color: #2d5d3f;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 20px;
          }
          .loading-text {
            font-size: 18px;
            font-weight: 600;
            color: #2d5d3f;
          }
          .content-area.hidden {
            display: none;
          }
          @keyframes spin { to { transform: rotate(360deg); } }
        </style>
      </head>
      <body>
        <div class="container">
          <h3>${escapeHtml(actionLabel)}</h3>
          ${selectionInfo}
          <div id="loadingOverlay" class="loading-overlay">
            <div class="spinner-large"></div>
            <div class="loading-text" id="loadingText">Processing ${validCount} item${validCount !== 1 ? 's' : ''}...</div>
          </div>
          <div id="contentArea" class="content-area">
            <div class="entity-section-label">${entityLabelPlural} to be affected:</div>
            <div class="entity-list">
              ${entityIds.map(id => '<div class="entity-item">' + escapeHtml(id) + '</div>').join('')}
            </div>
            <div class="buttons">
              <button class="cancel" id="cancelBtn" onclick="google.script.host.close()">Cancel</button>
              <button class="confirm" id="confirmBtn" onclick="executeBatch()">Confirm (${validCount})</button>
            </div>
          </div>
        </div>
        <script>
          var entityIds = ${JSON.stringify(entityIds)};
          var entityType = '${entityType}';
          var actionId = '${actionId}';
          var isProcessing = false;

          function executeBatch() {
            if (isProcessing) return;
            isProcessing = true;

            // Show full-screen loading
            document.getElementById('loadingOverlay').classList.add('show');
            document.getElementById('contentArea').classList.add('hidden');

            google.script.run
              .withSuccessHandler(function(result) {
                if (result && result.error) {
                  alert('Error: ' + result.error);
                  google.script.host.close();
                } else if (result && result.results) {
                  var failures = result.results.filter(function(r) { return !r.success; });

                  // Only show alert if there were failures
                  if (failures.length > 0) {
                    var message = 'Some items failed:\\n\\n';
                    failures.slice(0, 5).forEach(function(f) {
                      message += '- ' + f.entityId + ': ' + (f.error || 'Unknown error') + '\\n';
                    });
                    if (failures.length > 5) {
                      message += '... and ' + (failures.length - 5) + ' more\\n';
                    }
                    alert(message);
                  }
                  google.script.host.close();
                } else {
                  google.script.host.close();
                }
              })
              .withFailureHandler(function(error) {
                alert('Error: ' + (error.message || 'Unknown error'));
                google.script.host.close();
              })
              .executeBatchActionFromDialog(entityType, entityIds, actionId);
          }
        </script>
      </body>
    </html>
  `;

  // Calculate dynamic height based on number of items
  const baseHeight = 280;
  const itemHeight = 35;
  const maxListHeight = 180;
  const listHeight = Math.min(validCount * itemHeight, maxListHeight);
  const dialogHeight = Math.min(baseHeight + listHeight, 480);

  const html = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(450)
    .setHeight(dialogHeight);

  ui.showModalDialog(html, actionLabel + ' - Batch');
}

// ============================================================================
// SILENT BATCH ACTION HELPERS
// These are versions of existing functions that don't show UI dialogs
// ============================================================================

/**
 * Send quote reminder silently (for batch operations)
 * @param {string} jobNumber - The job number
 * @returns {Object} Result object with success boolean and error message if failed
 */
function sendQuoteReminderSilent(jobNumber) {
  try {
    const job = getJobByNumber(jobNumber);
    if (!job) {
      return { success: false, error: 'Job not found' };
    }

    // Check status - sendQuoteReminderAuto only works for QUOTED status
    const status = job['Status'];
    if (status !== JOB_STATUS.QUOTED) {
      return { success: false, error: 'Job must be in Quoted status (current: ' + status + ')' };
    }

    // Call the auto version which doesn't show dialogs
    const result = sendQuoteReminderAuto(jobNumber);
    if (result === false) {
      return { success: false, error: 'Failed to send quote reminder' };
    }
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Mark quote accepted silently (for batch operations)
 * Handles both deposit-required ($200+) and direct-start jobs
 * @param {string} jobNumber - The job number
 * @returns {Object} Result object
 */
function markQuoteAcceptedSilent(jobNumber) {
  try {
    const job = getJobByNumber(jobNumber);
    if (!job) {
      return { success: false, error: 'Job not found' };
    }

    const status = job['Status'];
    if (status !== JOB_STATUS.QUOTED && status !== JOB_STATUS.QUOTE_REMINDED) {
      return { success: false, error: 'Job status must be Quoted or Quote Reminded' };
    }

    // Check if job requires deposit ($200+)
    const total = parseFloat(job['Total (incl GST)']) || parseFloat(job['Quote Amount (excl GST)']) || 0;
    const requiresDeposit = total >= 200;

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

    updateJobFields(jobNumber, fieldsToUpdate);

    // Update client record
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
    if (requiresDeposit) {
      generateAndSendDepositInvoice(jobNumber, job);
    } else {
      // For non-deposit jobs, send status update email
      sendStatusUpdateEmail(jobNumber, JOB_STATUS.IN_PROGRESS, {
        wasOnHold: false,
        daysOnHold: 0
      });
    }

    logJobActivity(jobNumber, 'Quote Accepted', 'Quote accepted via batch action' + (requiresDeposit ? ' (deposit invoice sent)' : ' (work started)'));
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Mark quote declined silently (for batch operations)
 * @param {string} jobNumber - The job number
 * @returns {Object} Result object with success boolean and error message if failed
 */
function markQuoteDeclinedSilent(jobNumber) {
  try {
    const job = getJobByNumber(jobNumber);
    if (!job) {
      return { success: false, error: 'Job not found' };
    }

    // Validate status - can only decline jobs that have been quoted
    const status = job['Status'];
    if (status !== JOB_STATUS.QUOTED && status !== JOB_STATUS.QUOTE_REMINDED) {
      return { success: false, error: 'Job must be in Quoted or Quote Reminded status (current: ' + status + ')' };
    }

    updateJobFields(jobNumber, {
      'Status': JOB_STATUS.DECLINED
    });

    // Also update submission if exists
    const submissionNumber = job['Submission #'];
    if (submissionNumber) {
      updateSubmissionStatus(submissionNumber, 'Declined');
    }

    logJobActivity(jobNumber, 'Quote Declined', 'Quote declined via batch action');
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Start work on job silently (for batch operations)
 * Checks for unpaid deposit invoices before allowing work to start
 * @param {string} jobNumber - The job number
 * @returns {Object} Result object
 */
function startWorkOnJobSilent(jobNumber) {
  try {
    const job = getJobByNumber(jobNumber);
    if (!job) {
      return { success: false, error: 'Job not found' };
    }

    const status = job['Status'];
    if (status !== JOB_STATUS.ACCEPTED && status !== JOB_STATUS.ON_HOLD) {
      return { success: false, error: 'Job must be Accepted or On Hold' };
    }

    // Check for unpaid deposit invoice (for jobs that require deposit)
    const invoices = getInvoicesByJobNumber(jobNumber);
    const depositInvoice = invoices.find(inv => inv['Invoice Type'] === 'Deposit');

    if (depositInvoice && depositInvoice['Status'] !== 'Paid') {
      return { success: false, error: 'Deposit not yet paid' };
    }

    // Capture current status to detect if resuming from On Hold
    const wasOnHold = status === JOB_STATUS.ON_HOLD;
    let daysOnHold = 0;
    if (wasOnHold && job['Last Updated']) {
      try {
        const onHoldDate = new Date(job['Last Updated']);
        const now = new Date();
        daysOnHold = Math.floor((now - onHoldDate) / (1000 * 60 * 60 * 24));
      } catch (e) {
        Logger.log('Error calculating days on hold: ' + e.message);
      }
    }

    // Start the work
    const now = new Date();

    updateJobFields(jobNumber, {
      'Status': JOB_STATUS.IN_PROGRESS,
      'Actual Start Date': formatNZDate(now)
    });

    logJobActivity(jobNumber, 'Work Started', 'Work started via batch action');

    // Send status update email
    sendStatusUpdateEmail(jobNumber, JOB_STATUS.IN_PROGRESS, {
      wasOnHold: wasOnHold,
      daysOnHold: daysOnHold
    });

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Mark job complete silently (for batch operations)
 * @param {string} jobNumber - The job number
 * @returns {Object} Result object
 */
function markJobCompleteSilent(jobNumber) {
  try {
    const job = getJobByNumber(jobNumber);
    if (!job) {
      return { success: false, error: 'Job not found' };
    }

    if (job['Status'] !== JOB_STATUS.IN_PROGRESS) {
      return { success: false, error: 'Job must be In Progress' };
    }

    const now = new Date();

    updateJobFields(jobNumber, {
      'Status': JOB_STATUS.COMPLETED,
      'Actual Completion Date': formatNZDate(now),
      'SLA Status': '',
      'Days Remaining': ''
    });

    logJobActivity(jobNumber, 'Job Completed', 'Job completed via batch action');
    sendStatusUpdateEmail(jobNumber, JOB_STATUS.COMPLETED, {});

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Cancel job silently (for batch operations)
 * @param {string} jobNumber - The job number
 * @param {string} reason - Cancellation reason
 * @returns {Object} Result object with success boolean and error message if failed
 */
function cancelJobSilent(jobNumber, reason) {
  try {
    const job = getJobByNumber(jobNumber);
    if (!job) {
      return { success: false, error: 'Job not found' };
    }

    // Check if job can be cancelled (not already completed or cancelled)
    const status = job['Status'];
    if (status === JOB_STATUS.COMPLETED) {
      return { success: false, error: 'Cannot cancel a completed job' };
    }
    if (status === JOB_STATUS.CANCELLED) {
      return { success: false, error: 'Job is already cancelled' };
    }

    updateJobFields(jobNumber, {
      'Status': JOB_STATUS.CANCELLED
    });
    logJobActivity(jobNumber, 'Job Cancelled', reason || 'Cancelled via batch action');
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Generate invoice for job silently (for batch operations)
 * Automatically determines invoice type (Full, Deposit, or Balance)
 * @param {string} jobNumber - The job number
 * @returns {Object} Result object
 */
function generateInvoiceForJobSilent(jobNumber) {
  try {
    const ss = getSpreadsheet();
    const job = getJobByNumber(jobNumber);
    if (!job) {
      return { success: false, error: 'Job not found' };
    }

    const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
    if (!invoiceSheet) {
      return { success: false, error: 'Invoice Log sheet not found' };
    }

    // Get existing invoices and analyze state
    const existingInvoices = getInvoicesByJobNumber(jobNumber);
    const hasDeposit = existingInvoices.some(inv => inv['Invoice Type'] === 'Deposit');
    const hasBalance = existingInvoices.some(inv => inv['Invoice Type'] === 'Balance');
    const depositInvoice = existingInvoices.find(inv => inv['Invoice Type'] === 'Deposit');

    // Calculate amounts
    const amount = parseFloat(job['Quote Amount (excl GST)']) || 0;

    // Validate invoice amount (P1 FIX)
    const amountValidation = validateInvoiceAmount(amount, 'Quote Amount');
    if (!amountValidation.valid) {
      return { success: false, error: amountValidation.error };
    }

    const isGSTRegistered = getSetting('GST Registered') === 'Yes';
    const gst = isGSTRegistered ? (parseFloat(job['GST']) || 0) : 0;
    const total = isGSTRegistered ? (parseFloat(job['Total (incl GST)']) || amount) : amount;
    const projectSize = getProjectSize(total);

    // Calculate remaining balance
    const paidAmount = calculatePaidAmount(jobNumber);
    const remainingBalance = total - paidAmount;

    // Decision tree for invoice type
    let invoiceType, invoiceAmount, invoiceGst, invoiceTotal;

    if (existingInvoices.length === 0) {
      // NO INVOICES: Create Full or Deposit based on project size
      if (projectSize === PROJECT_SIZE.SMALL) {
        invoiceType = 'Full';
        invoiceAmount = amount;
        invoiceGst = gst;
        invoiceTotal = total;
      } else {
        // Medium or Large: Create 50% Deposit
        invoiceType = 'Deposit';
        invoiceAmount = amount * 0.5;
        invoiceGst = gst * 0.5;
        invoiceTotal = total * 0.5;
      }
    } else if (hasDeposit && !hasBalance) {
      // HAS DEPOSIT, NO BALANCE: Create Balance invoice
      const depositAmount = parseFloat(depositInvoice['Amount (excl GST)']) || 0;
      const depositGst = parseFloat(depositInvoice['GST']) || 0;

      invoiceType = 'Balance';
      invoiceAmount = amount - depositAmount;
      invoiceGst = gst - depositGst;
      invoiceTotal = invoiceAmount + invoiceGst;
    } else if (remainingBalance > 0.01) {
      // Has invoices but remaining balance - create Additional invoice
      invoiceType = 'Additional';
      if (isGSTRegistered) {
        invoiceTotal = remainingBalance;
        invoiceAmount = remainingBalance / 1.15;
        invoiceGst = remainingBalance - invoiceAmount;
      } else {
        invoiceAmount = remainingBalance;
        invoiceGst = 0;
        invoiceTotal = remainingBalance;
      }
    } else {
      return { success: false, error: 'Job is already fully invoiced' };
    }

    // Generate invoice number and dates
    const invoiceNumber = generateInvoiceNumber(jobNumber, existingInvoices.length);
    const now = new Date();
    const paymentTerms = parseInt(getSetting('Default Payment Terms')) || JOB_CONFIG.PAYMENT_TERMS_DAYS;
    const dueDate = new Date(now);
    if (invoiceType !== 'Deposit') {
      dueDate.setDate(dueDate.getDate() + paymentTerms);
    }

    // Create invoice row
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

    // Insert at top
    insertAtTopSafe(invoiceSheet, invoiceRow, false); // false = no toast for batch

    // Update job with latest invoice number
    updateJobField(jobNumber, 'Invoice #', invoiceNumber);

    Logger.log('Invoice ' + invoiceNumber + ' (' + invoiceType + ') generated for ' + jobNumber + ' (batch)');
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Send testimonial request silently (for batch operations)
 * @param {string} jobNumber - The job number
 * @returns {Object} Result object
 */
function sendTestimonialRequestSilent(jobNumber) {
  try {
    const job = getJobByNumber(jobNumber);
    if (!job) {
      return { success: false, error: 'Job not found' };
    }

    if (job['Status'] !== JOB_STATUS.COMPLETED) {
      return { success: false, error: 'Job must be Completed' };
    }

    const clientEmail = job['Client Email'];
    if (!clientEmail) {
      return { success: false, error: 'No client email' };
    }

    // Send the testimonial request email (uses existing sendTestimonialRequest logic)
    const clientName = job['Client Name'];
    const businessName = getSetting('Business Name') || 'CartCure';
    const feedbackUrl = 'https://cartcure.co.nz/feedback.html?job=' + encodeURIComponent(jobNumber);
    const subject = 'How was your experience with CartCure?';

    // Use a simplified email for batch operations
    const body = `
      <p>Hi ${escapeHtml(clientName)},</p>
      <p>We hope you're enjoying your updated Shopify store!</p>
      <p>We'd love to hear about your experience working with CartCure. Your feedback helps us improve and helps other store owners find reliable help.</p>
      <p><a href="${feedbackUrl}" style="display:inline-block;padding:12px 24px;background:#2d5d3f;color:white;text-decoration:none;border-radius:6px;">Share Your Feedback</a></p>
      <p>Thank you for choosing CartCure!</p>
      <p>Best regards,<br>${businessName}</p>
    `;

    MailApp.sendEmail({
      to: clientEmail,
      subject: subject,
      htmlBody: body,
      name: businessName
    });

    // Mark testimonial as requested
    updateJobField(jobNumber, 'Testimonial Requested', 'Yes');
    logJobActivity(jobNumber, 'Testimonial Requested', 'Testimonial request sent via batch action');

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Create job from submission silently (for batch operations)
 * @param {string} submissionNumber - The submission number
 * @returns {Object} Result object
 */
function createJobFromSubmissionSilent(submissionNumber) {
  try {
    const ss = getSpreadsheet();
    const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
    const jobsSheet = ss.getSheetByName(SHEETS.JOBS);

    if (!submissionsSheet || !jobsSheet) {
      return { success: false, error: 'Required sheets not found' };
    }

    // Find the submission
    const submissionsData = submissionsSheet.getDataRange().getValues();
    const submissionNumCol = getColIndex('SUBMISSIONS', 'Submission #') - 1;
    const statusCol = getColIndex('SUBMISSIONS', 'Status') - 1;

    let submissionRow = null;
    let submissionRowIndex = -1;

    for (let i = 1; i < submissionsData.length; i++) {
      if (String(submissionsData[i][submissionNumCol]).trim().toUpperCase() === submissionNumber.toUpperCase()) {
        submissionRow = submissionsData[i];
        submissionRowIndex = i + 1; // 1-indexed for sheet operations
        break;
      }
    }

    if (!submissionRow) {
      return { success: false, error: 'Submission not found' };
    }

    // Check if already has a job
    const currentStatus = submissionRow[statusCol];
    if (currentStatus === 'Job Created') {
      return { success: false, error: 'Job already created from this submission' };
    }

    // Count existing jobs for this submission (to handle additional jobs)
    const jobsData = jobsSheet.getDataRange().getValues();
    const jobSubNumColIdx = getColIndex('JOBS', 'Submission #') - 1;
    let existingJobCount = 0;
    for (let i = 1; i < jobsData.length; i++) {
      if (String(jobsData[i][jobSubNumColIdx]).trim().toUpperCase() === submissionNumber.toUpperCase()) {
        existingJobCount++;
      }
    }

    // Generate job number
    let jobNumber;
    if (existingJobCount === 0) {
      jobNumber = submissionNumber.replace(/^CC-/i, 'J-');
    } else {
      jobNumber = submissionNumber.replace(/^CC-/i, 'J-') + '-' + (existingJobCount + 1);
    }

    // Extract submission data using COLUMN_CONFIG
    const name = submissionRow[getColIndex('SUBMISSIONS', 'Name') - 1] || '';
    const email = submissionRow[getColIndex('SUBMISSIONS', 'Email') - 1] || '';
    const phone = submissionRow[getColIndex('SUBMISSIONS', 'Phone') - 1] || '';
    const storeUrl = submissionRow[getColIndex('SUBMISSIONS', 'Store URL') - 1] || '';
    const message = submissionRow[getColIndex('SUBMISSIONS', 'Message') - 1] || '';

    // Create job row
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
    });

    // Add to Jobs sheet at top
    insertAtTopSafe(jobsSheet, jobRow, false); // false = no toast for batch

    // Update submission status
    const statusColumnIndex = getColIndex('SUBMISSIONS', 'Status');
    submissionsSheet.getRange(submissionRowIndex, statusColumnIndex).setValue('Job Created');

    // Log activity
    logJobActivity(jobNumber, 'Job Created', 'Job created from submission ' + submissionNumber + ' (batch)', '', '', 'Auto');

    // Add/update client in Clients sheet
    if (email) {
      try {
        ensureClientExistsAndUpdate(email, { name: name, phone: phone, storeUrl: storeUrl });
      } catch (e) {
        Logger.log('Warning: Could not update client record: ' + e.message);
      }
    }

    Logger.log('Job ' + jobNumber + ' created from submission ' + submissionNumber + ' (batch)');
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Send invoice reminder silently (for batch operations)
 * Uses existing sendInvoiceReminderAuto which doesn't show UI
 * @param {string} invoiceNumber - The invoice number
 * @returns {Object} Result object
 */
function sendInvoiceReminderSilent(invoiceNumber) {
  try {
    sendInvoiceReminderAuto(invoiceNumber);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Send overdue invoice silently (for batch operations)
 * @param {string} invoiceNumber - The invoice number
 * @returns {Object} Result object
 */
function sendOverdueInvoiceSilent(invoiceNumber) {
  try {
    sendOverdueInvoice(invoiceNumber, true); // true = auto/silent mode
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Mark invoice as not paid silently (for batch operations)
 * Reverts status to Sent or Overdue based on due date
 * @param {string} invoiceNumber - The invoice number
 * @returns {Object} Result object
 */
function markInvoiceAsNotPaidSilent(invoiceNumber) {
  try {
    const invoice = getInvoiceByNumber(invoiceNumber);
    if (!invoice) {
      return { success: false, error: 'Invoice not found' };
    }

    // Determine new status based on due date
    const dueDate = new Date(invoice['Due Date']);
    const now = new Date();
    const newStatus = (now > dueDate) ? 'Overdue' : 'Sent';

    updateInvoiceFields(invoiceNumber, {
      'Status': newStatus
    });

    const jobNumber = invoice['Job #'];
    if (jobNumber) {
      logJobActivity(jobNumber, 'Invoice Updated', 'Invoice ' + invoiceNumber + ' marked as Not Paid (batch action)');
    }

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Execute an action from the actions dialog
 * Called via google.script.run from the dialog
 * @param {string} entityType - 'job', 'submission', or 'invoice'
 * @param {string} entityId - The entity ID
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object
 */
function executeActionFromDialog(entityType, entityId, actionId) {
  try {
    if (entityType === 'job') {
      return executeJobAction(entityId, actionId);
    } else if (entityType === 'submission') {
      return executeSubmissionAction(entityId, actionId);
    } else if (entityType === 'invoice') {
      return executeInvoiceAction(entityId, actionId);
    } else if (entityType === 'client') {
      return executeClientAction(entityId, actionId);
    }
    return { error: 'Unknown entity type' };
  } catch (error) {
    Logger.log('Error executing action: ' + error.message);
    return { error: error.message };
  }
}

/**
 * Execute a job action
 * @param {string} jobNumber - The job number
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object
 */
function executeJobAction(jobNumber, actionId) {
  switch (actionId) {
    case 'sendQuote':
      showSendQuoteWithAmountDialog(jobNumber);
      return { keepOpen: true };

    case 'sendQuoteReminder':
      sendQuoteReminder(jobNumber);
      return { success: true };

    case 'markAccepted':
      markQuoteAccepted(jobNumber);
      return { success: true };

    case 'markDeclined':
      markQuoteDeclined(jobNumber);
      return { success: true };

    case 'startWork':
      startWorkOnJob(jobNumber);
      return { success: true };

    case 'markComplete':
      markJobComplete(jobNumber);
      return { success: true };

    case 'onHold':
      // This shows another dialog, so return keepOpen
      showOnHoldDialogWithJob(jobNumber);
      return { keepOpen: true };

    case 'cancel':
      // This shows a confirmation dialog
      showCancelJobConfirmation(jobNumber);
      return { keepOpen: true };

    case 'viewActivity':
      displayActivityLogForJob(jobNumber);
      return { keepOpen: true };

    case 'addNote':
      promptForActivityNote(jobNumber);
      return { keepOpen: true };

    case 'generateInvoice':
      generateInvoiceForJob(jobNumber);
      return { keepOpen: true };

    case 'requestTestimonial':
      sendTestimonialRequest(jobNumber);
      return { success: true };

    case 'processRefund':
      processRefund(jobNumber);
      return { keepOpen: true };

    default:
      return { error: 'Unknown action: ' + actionId };
  }
}

/**
 * Execute a submission action
 * @param {string} submissionNumber - The submission number
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object
 */
function executeSubmissionAction(submissionNumber, actionId) {
  const ss = getSpreadsheet();
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);

  switch (actionId) {
    case 'createJob':
      createJobFromSubmission(submissionNumber);
      return { success: true };

    case 'markInReview':
      updateSubmissionStatus(submissionNumber, 'In Review');
      SpreadsheetApp.getUi().alert('Updated', 'Submission marked as In Review.', SpreadsheetApp.getUi().ButtonSet.OK);
      return { success: true };

    case 'decline':
      updateSubmissionStatus(submissionNumber, 'Declined');
      SpreadsheetApp.getUi().alert('Declined', 'Submission has been declined.', SpreadsheetApp.getUi().ButtonSet.OK);
      return { success: true };

    case 'markSpam':
      updateSubmissionStatus(submissionNumber, 'Spam');
      SpreadsheetApp.getUi().alert('Marked as Spam', 'Submission has been marked as spam.', SpreadsheetApp.getUi().ButtonSet.OK);
      return { success: true };

    default:
      return { error: 'Unknown action: ' + actionId };
  }
}

/**
 * Execute an invoice action
 * @param {string} invoiceNumber - The invoice number
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object
 */
function executeInvoiceAction(invoiceNumber, actionId) {
  switch (actionId) {
    case 'viewInvoice':
      previewInvoiceEmail(invoiceNumber);
      return { keepOpen: true };

    case 'downloadPDF':
      const pdfResult = downloadInvoicePDF(invoiceNumber);
      if (pdfResult.success) {
        SpreadsheetApp.getUi().alert(
          'PDF Ready',
          'Invoice PDF has been generated and saved to Google Drive.\n\n' +
          'Location: CartCure Invoices folder\n' +
          (pdfResult.cached ? '(Using existing PDF)' : '(New PDF generated)') +
          '\n\nThe PDF link is also saved in the Invoice Log.',
          SpreadsheetApp.getUi().ButtonSet.OK
        );
        return { success: true };
      } else {
        return { error: pdfResult.error };
      }

    case 'sendInvoice':
      sendInvoiceEmail(invoiceNumber);
      return { success: true };

    case 'sendReminder':
      sendInvoiceReminder(invoiceNumber);
      return { success: true };

    case 'markPaid':
      showPaymentMethodDialogForInvoice(invoiceNumber);
      return { keepOpen: true };

    case 'sendOverdue':
      sendOverdueInvoice(invoiceNumber);
      return { success: true };

    case 'markNotPaid':
      markInvoiceAsNotPaid(invoiceNumber);
      return { success: true };

    case 'cancelInvoice':
      cancelDraftInvoice(invoiceNumber);
      return { success: true };

    default:
      return { error: 'Unknown action: ' + actionId };
  }
}

/**
 * Execute a client action
 * @param {string} clientEmail - The client's email address
 * @param {string} actionId - The action to execute
 * @returns {Object} Result object
 */
function executeClientAction(clientEmail, actionId) {
  switch (actionId) {
    case 'viewClientHistory':
      displayClientHistoryDialog(clientEmail);
      return { keepOpen: true };

    case 'setStatusActive':
      updateClientStatus(clientEmail, CLIENT_STATUS.ACTIVE);
      return { success: true };

    case 'setStatusInactive':
      updateClientStatus(clientEmail, CLIENT_STATUS.INACTIVE);
      return { success: true };

    case 'setStatusVIP':
      updateClientStatus(clientEmail, CLIENT_STATUS.VIP);
      return { success: true };

    case 'recalculateStats':
      updateClientStatistics(clientEmail);
      return { success: true };

    default:
      return { error: 'Unknown action: ' + actionId };
  }
}

/**
 * Update a client's status
 * @param {string} clientEmail - The client's email address
 * @param {string} newStatus - The new status (Active, Inactive, VIP)
 */
function updateClientStatus(clientEmail, newStatus) {
  const client = findClientByEmail(clientEmail);
  if (!client) {
    Logger.log('updateClientStatus: Client not found: ' + clientEmail);
    return;
  }

  const sheet = getSheet(SHEETS.CLIENTS);
  const statusCol = getColIndex('CLIENTS', 'Client Status');
  const lastUpdatedCol = getColIndex('CLIENTS', 'Last Updated');
  const now = new Date();
  const timestampStr = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM-dd HH:mm:ss');

  sheet.getRange(client._rowIndex, statusCol).setValue(newStatus);
  sheet.getRange(client._rowIndex, lastUpdatedCol).setValue(timestampStr);

  Logger.log('Client status updated: ' + clientEmail + ' -> ' + newStatus);
}

// ============================================================================
// CLIENT STATUS MENU FUNCTIONS
// ============================================================================

/**
 * Menu function: Set selected client(s) to VIP status
 */
function showSetClientVIPDialog() {
  executeClientStatusChangeFromMenu(CLIENT_STATUS.VIP, 'Set VIP');
}

/**
 * Menu function: Set selected client(s) to Active status
 */
function showSetClientActiveDialog() {
  executeClientStatusChangeFromMenu(CLIENT_STATUS.ACTIVE, 'Set Active');
}

/**
 * Menu function: Set selected client(s) to Inactive status
 */
function showSetClientInactiveDialog() {
  executeClientStatusChangeFromMenu(CLIENT_STATUS.INACTIVE, 'Set Inactive');
}

/**
 * Helper: Execute client status change from menu selection
 */
function executeClientStatusChangeFromMenu(newStatus, actionLabel) {
  const ui = SpreadsheetApp.getUi();
  const sheet = SpreadsheetApp.getActiveSheet();

  if (sheet.getName() !== SHEETS.CLIENTS) {
    ui.alert('Wrong Sheet', 'Please select rows on the Clients sheet.', ui.ButtonSet.OK);
    return;
  }

  const selectedRows = getSelectedRows();
  if (selectedRows.length === 0) {
    ui.alert('Select a Client', 'Please select one or more client rows.', ui.ButtonSet.OK);
    return;
  }

  const emailCol = getColIndex('CLIENTS', 'Client Email') - 1;
  const data = sheet.getDataRange().getValues();
  const emails = selectedRows.map(row => data[row - 1][emailCol]).filter(e => e);

  if (emails.length === 0) {
    ui.alert('No Valid Clients', 'No valid client emails found in selection.', ui.ButtonSet.OK);
    return;
  }

  const confirmMsg = emails.length === 1
    ? 'Set ' + emails[0] + ' to ' + newStatus + '?'
    : 'Set ' + emails.length + ' clients to ' + newStatus + '?';

  const response = ui.alert(actionLabel, confirmMsg, ui.ButtonSet.YES_NO);
  if (response !== ui.Button.YES) return;

  let successCount = 0;
  emails.forEach(email => {
    try {
      updateClientStatus(email, newStatus);
      successCount++;
    } catch (e) {
      Logger.log('Failed to update ' + email + ': ' + e.message);
    }
  });

  ui.alert('Complete', successCount + ' of ' + emails.length + ' clients updated to ' + newStatus + '.', ui.ButtonSet.OK);
}

/**
 * Menu function: Recalculate stats for selected client(s)
 */
function showRecalculateClientStatsDialog() {
  const ui = SpreadsheetApp.getUi();
  const sheet = SpreadsheetApp.getActiveSheet();

  if (sheet.getName() !== SHEETS.CLIENTS) {
    ui.alert('Wrong Sheet', 'Please select rows on the Clients sheet.', ui.ButtonSet.OK);
    return;
  }

  const selectedRows = getSelectedRows();
  if (selectedRows.length === 0) {
    ui.alert('Select a Client', 'Please select one or more client rows.', ui.ButtonSet.OK);
    return;
  }

  const emailCol = getColIndex('CLIENTS', 'Client Email') - 1;
  const data = sheet.getDataRange().getValues();
  const emails = selectedRows.map(row => data[row - 1][emailCol]).filter(e => e);

  if (emails.length === 0) {
    ui.alert('No Valid Clients', 'No valid client emails found in selection.', ui.ButtonSet.OK);
    return;
  }

  const confirmMsg = emails.length === 1
    ? 'Recalculate stats for ' + emails[0] + '?'
    : 'Recalculate stats for ' + emails.length + ' clients?';

  const response = ui.alert('Recalculate Stats', confirmMsg, ui.ButtonSet.YES_NO);
  if (response !== ui.Button.YES) return;

  let successCount = 0;
  emails.forEach(email => {
    try {
      updateClientStatistics(email);
      successCount++;
    } catch (e) {
      Logger.log('Failed to recalculate stats for ' + email + ': ' + e.message);
    }
  });

  ui.alert('Complete', 'Stats recalculated for ' + successCount + ' of ' + emails.length + ' clients.', ui.ButtonSet.OK);
}

// ============================================================================
// SUBMISSION STATUS MENU FUNCTIONS
// ============================================================================

/**
 * Menu function: Mark selected submission(s) as In Review
 */
function showMarkInReviewDialog() {
  executeSubmissionStatusChangeFromMenu('In Review', 'Mark In Review');
}

/**
 * Menu function: Mark selected submission(s) as Spam
 */
function showMarkSpamDialog() {
  executeSubmissionStatusChangeFromMenu('Spam', 'Mark as Spam');
}

/**
 * Menu function: Decline selected submission(s)
 */
function showDeclineSubmissionDialog() {
  executeSubmissionStatusChangeFromMenu('Declined', 'Decline Submission');
}

/**
 * Helper: Execute submission status change from menu selection
 */
function executeSubmissionStatusChangeFromMenu(newStatus, actionLabel) {
  const ui = SpreadsheetApp.getUi();
  const sheet = SpreadsheetApp.getActiveSheet();

  if (sheet.getName() !== SHEETS.SUBMISSIONS) {
    ui.alert('Wrong Sheet', 'Please select rows on the Submissions sheet.', ui.ButtonSet.OK);
    return;
  }

  const selectedRows = getSelectedRows();
  if (selectedRows.length === 0) {
    ui.alert('Select a Submission', 'Please select one or more submission rows.', ui.ButtonSet.OK);
    return;
  }

  const subNumCol = getColIndex('SUBMISSIONS', 'Submission #') - 1;
  const data = sheet.getDataRange().getValues();
  const submissionNumbers = selectedRows.map(row => data[row - 1][subNumCol]).filter(s => s);

  if (submissionNumbers.length === 0) {
    ui.alert('No Valid Submissions', 'No valid submission numbers found in selection.', ui.ButtonSet.OK);
    return;
  }

  const confirmMsg = submissionNumbers.length === 1
    ? 'Mark ' + submissionNumbers[0] + ' as ' + newStatus + '?'
    : 'Mark ' + submissionNumbers.length + ' submissions as ' + newStatus + '?';

  const response = ui.alert(actionLabel, confirmMsg, ui.ButtonSet.YES_NO);
  if (response !== ui.Button.YES) return;

  let successCount = 0;
  submissionNumbers.forEach(subNum => {
    try {
      updateSubmissionStatus(subNum, newStatus);
      successCount++;
    } catch (e) {
      Logger.log('Failed to update ' + subNum + ': ' + e.message);
    }
  });

  ui.alert('Complete', successCount + ' of ' + submissionNumbers.length + ' submissions marked as ' + newStatus + '.', ui.ButtonSet.OK);
}

/**
 * Show on hold dialog for a specific job
 * @param {string} jobNumber - The job number
 */
function showOnHoldDialogWithJob(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const response = ui.prompt(
    'Put Job On Hold',
    'Enter reason for putting ' + jobNumber + ' on hold:',
    ui.ButtonSet.OK_CANCEL
  );

  if (response.getSelectedButton() === ui.Button.OK) {
    const reason = response.getResponseText();
    putJobOnHold(jobNumber, reason);
    ui.alert('Job On Hold', jobNumber + ' has been put on hold.', ui.ButtonSet.OK);
  }
}

/**
 * Show payment method dialog for a specific invoice
 * Uses HTML dialog with dropdown for consistent payment method selection
 * @param {string} invoiceNumber - The invoice number
 */
function showPaymentMethodDialogForInvoice(invoiceNumber) {
  const ui = SpreadsheetApp.getUi();

  const htmlContent = `
    <!DOCTYPE html>
    <html>
      <head>
        <base target="_top">
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; margin: 0; }
          .container { max-width: 350px; }
          label { display: block; margin-bottom: 6px; font-weight: bold; color: #333; }
          select, input { width: 100%; padding: 10px; margin-bottom: 16px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; box-sizing: border-box; }
          select:focus, input:focus { outline: none; border-color: #2d5d3f; }
          .invoice-info { background: #f5f5f5; padding: 12px; border-radius: 4px; margin-bottom: 16px; font-size: 14px; }
          .invoice-info strong { color: #333; }
          .note { font-size: 12px; color: #666; margin-top: -12px; margin-bottom: 16px; }
          .button-container { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; }
          button { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
          .btn-primary { background: #2d5d3f; color: white; }
          .btn-primary:hover { background: #4a7c59; }
          .btn-primary:disabled { background: #ccc; cursor: not-allowed; }
          .btn-secondary { background: #666; color: white; }
          .btn-secondary:hover { background: #555; }
          .btn-secondary:disabled { background: #ccc; cursor: not-allowed; }
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
            <button class="btn-secondary" onclick="google.script.host.close()">Cancel</button>
            <button id="submitBtn" class="btn-primary" onclick="submitPayment()">Mark as Paid</button>
          </div>
        </div>

        <script>
          function submitPayment() {
            const method = document.getElementById('paymentMethod').value;
            const reference = document.getElementById('paymentRef').value;
            document.getElementById('submitBtn').disabled = true;
            document.getElementById('submitBtn').textContent = 'Processing...';

            google.script.run
              .withSuccessHandler(function() {
                google.script.host.close();
              })
              .withFailureHandler(function(error) {
                document.getElementById('submitBtn').disabled = false;
                document.getElementById('submitBtn').textContent = 'Mark as Paid';
                alert('Error: ' + error);
              })
              .markInvoicePaid('${invoiceNumber}', method, reference);
          }
        </script>
      </body>
    </html>
  `;

  const html = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(400)
    .setHeight(320);

  ui.showModalDialog(html, 'Record Payment - ' + invoiceNumber);
}

/**
 * Enable auto-refresh trigger (every 2 minutes)
 */
function enableAutoRefresh() {
  const ui = SpreadsheetApp.getUi();

  // Remove any existing triggers first
  disableAutoRefreshSilent();

  // Create new time-driven trigger (5 min interval for better quota usage)
  ScriptApp.newTrigger('autoRefreshDashboard')
    .timeBased()
    .everyMinutes(5)
    .create();

  ui.alert('Auto-Refresh Enabled', 'Dashboard will automatically refresh every 5 minutes.\n\nNote: This uses Google Apps Script quota.', ui.ButtonSet.OK);
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
    updateAllLateFees(); // Update invoice late fees first
    refreshDashboard(true); // Force refresh when called from trigger
    refreshAnalytics();
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

  // If no trigger exists, create one (5 min interval for better quota usage)
  if (!hasAutoRefresh) {
    ScriptApp.newTrigger('autoRefreshDashboard')
      .timeBased()
      .everyMinutes(5)
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
      .everyMinutes(5)
      .create();
    ui.alert('Auto-Refresh Enabled', 'Dashboard will automatically refresh every 5 minutes.\n\nNote: This uses Google Apps Script quota.', ui.ButtonSet.OK);
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

/**
 * Toggle selection confirmation dialog on/off
 * When off (default): Auto-detected jobs/invoices proceed immediately
 * When on: Shows "Use selected job: J-XXX?" confirmation first
 */
function toggleConfirmSelection() {
  const ui = SpreadsheetApp.getUi();
  const currentValue = getSetting('Confirm Selection Dialog');
  const isEnabled = currentValue === 'Yes';

  if (isEnabled) {
    updateSetting('Confirm Selection Dialog', 'No');
    ui.alert('Selection Confirmation Disabled',
      'When you select a job or invoice and use a menu action, it will proceed immediately without asking for confirmation.',
      ui.ButtonSet.OK);
  } else {
    updateSetting('Confirm Selection Dialog', 'Yes');
    ui.alert('Selection Confirmation Enabled',
      'When you select a job or invoice and use a menu action, you will be asked to confirm before proceeding.',
      ui.ButtonSet.OK);
  }

  // Rebuild menu to reflect new state
  buildMenu();
}

/**
 * Toggle header row protection on/off
 * When enabled, shows a warning dialog when trying to edit header rows
 */
function toggleHeaderProtection() {
  const ui = SpreadsheetApp.getUi();
  const currentValue = getSetting('Header Row Protection');
  const isEnabled = currentValue === 'Yes';

  if (isEnabled) {
    removeHeaderProtections();
    updateSetting('Header Row Protection', 'No');
    ui.alert('Header Protection Disabled',
      'You can now edit header rows, apply filters, and resize columns without warnings.',
      ui.ButtonSet.OK);
  } else {
    applyHeaderProtections();
    updateSetting('Header Row Protection', 'Yes');
    ui.alert('Header Protection Enabled',
      'Header rows are now protected. You will see a warning if you try to edit them.\n\n' +
      'Note: This warning also appears when applying filters or resizing columns.',
      ui.ButtonSet.OK);
  }

  // Rebuild menu to reflect new state
  buildMenu();
}

/**
 * Toggle column protection on/off
 * When enabled, system-managed columns cannot be edited in the spreadsheet.
 * Editable columns are defined in EDITABLE_COLUMNS config.
 */
function toggleColumnProtection() {
  const ui = SpreadsheetApp.getUi();
  const currentValue = getSetting('Column Protection');
  const isEnabled = currentValue === 'Yes';

  if (isEnabled) {
    updateSetting('Column Protection', 'No');
    ui.alert('Column Protection Disabled',
      'All columns can now be freely edited.\n\n' +
      'Note: Invoice amount protection (Amount, GST, Total on non-Draft invoices) remains active regardless of this setting.',
      ui.ButtonSet.OK);
  } else {
    updateSetting('Column Protection', 'Yes');
    ui.alert('Column Protection Enabled',
      'System-managed columns are now protected. Edits to auto-generated fields (IDs, dates, formulas, etc.) will be reverted with a warning.\n\n' +
      'You can still edit admin-managed fields like Status, pricing, notes, and dates.\n\n' +
      'To temporarily unlock, use: CartCure > Setup > Disable Column Protection',
      ui.ButtonSet.OK);
  }

  // Rebuild menu to reflect new state
  buildMenu();
}

/**
 * Apply warning-only protection to header rows on key sheets
 */
function applyHeaderProtections() {
  const ss = getSpreadsheet();
  const sheetsToProtect = [
    { name: SHEETS.SUBMISSIONS, cols: 10 },
    { name: SHEETS.JOBS, cols: COLUMN_CONFIG.JOBS.length },
    { name: SHEETS.INVOICES, cols: COLUMN_CONFIG.INVOICES.length },
    { name: SHEETS.TESTIMONIALS, cols: 9 },
    { name: SHEETS.ACTIVITY_LOG, cols: 7 }
  ];

  sheetsToProtect.forEach(({ name, cols }) => {
    const sheet = ss.getSheetByName(name);
    if (sheet) {
      try {
        const protection = sheet.getRange(1, 1, 1, cols).protect();
        protection.setDescription('Protected header row - ' + name);
        protection.setWarningOnly(true);
      } catch (e) {
        Logger.log('Could not protect ' + name + ': ' + e.message);
      }
    }
  });

  Logger.log('Header protections applied');
}

/**
 * Remove all header row protections from sheets
 */
function removeHeaderProtections() {
  const ss = getSpreadsheet();
  const sheets = ss.getSheets();

  sheets.forEach(sheet => {
    try {
      const protections = sheet.getProtections(SpreadsheetApp.ProtectionType.RANGE);
      protections.forEach(protection => {
        if (protection.getDescription().startsWith('Protected header row')) {
          protection.remove();
        }
      });
    } catch (e) {
      Logger.log('Could not remove protection from ' + sheet.getName() + ': ' + e.message);
    }
  });

  Logger.log('Header protections removed');
}

