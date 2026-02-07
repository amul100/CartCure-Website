// ============================================================================
// SETUP FUNCTIONS
// ============================================================================

/**
 * Show setup dialog with options
 */
function confirmAndSetupSheets() {
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
  const ss = getSpreadsheet();
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

  // Back up Submissions data (include headers for column mapping during restore)
  const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
  if (submissionsSheet && submissionsSheet.getLastRow() > 1) {
    const subLastCol = submissionsSheet.getLastColumn();
    backup.submissionHeaders = submissionsSheet.getRange(1, 1, 1, subLastCol).getValues()[0];
    backup.submissions = submissionsSheet.getRange(2, 1, submissionsSheet.getLastRow() - 1, subLastCol).getValues();
    Logger.log('Backed up ' + backup.submissions.length + ' submission rows with ' + backup.submissionHeaders.length + ' columns');
  }

  // Back up Jobs data (include headers for column mapping during restore)
  const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
  if (jobsSheet && jobsSheet.getLastRow() > 1) {
    const jobsLastCol = jobsSheet.getLastColumn();
    backup.jobHeaders = jobsSheet.getRange(1, 1, 1, jobsLastCol).getValues()[0];
    backup.jobs = jobsSheet.getRange(2, 1, jobsSheet.getLastRow() - 1, jobsLastCol).getValues();
    Logger.log('Backed up ' + backup.jobs.length + ' job rows with ' + backup.jobHeaders.length + ' columns');
  }

  // Back up Invoice Log data (include headers for column mapping during restore)
  const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
  if (invoiceSheet && invoiceSheet.getLastRow() > 1) {
    const lastCol = invoiceSheet.getLastColumn();
    backup.invoiceHeaders = invoiceSheet.getRange(1, 1, 1, lastCol).getValues()[0];
    backup.invoices = invoiceSheet.getRange(2, 1, invoiceSheet.getLastRow() - 1, lastCol).getValues();
    Logger.log('Backed up ' + backup.invoices.length + ' invoice rows with ' + backup.invoiceHeaders.length + ' columns');
  }

  // Back up Settings data
  const settingsSheet = ss.getSheetByName(SHEETS.SETTINGS);
  if (settingsSheet && settingsSheet.getLastRow() > 0) {
    backup.settings = settingsSheet.getDataRange().getValues();
    Logger.log('Backed up settings data');

    // Also save critical settings to PropertiesService as a persistent safety net
    // This protects GST number, bank account, etc. even if repair crashes mid-process
    try {
      const settingsMap = {};
      for (let i = 1; i < backup.settings.length; i++) {
        if (backup.settings[i][0]) {
          settingsMap[backup.settings[i][0]] = String(backup.settings[i][1] !== undefined ? backup.settings[i][1] : '');
        }
      }
      PropertiesService.getScriptProperties().setProperty('SETTINGS_BACKUP', JSON.stringify(settingsMap));
      Logger.log('Settings saved to PropertiesService as safety net');
    } catch (e) {
      Logger.log('Could not save settings to PropertiesService: ' + e.message);
    }
  }

  // Back up Testimonials data (include headers for column mapping during restore)
  const testimonialsSheet = ss.getSheetByName(SHEETS.TESTIMONIALS);
  if (testimonialsSheet && testimonialsSheet.getLastRow() > 1) {
    const testLastCol = testimonialsSheet.getLastColumn();
    backup.testimonialHeaders = testimonialsSheet.getRange(1, 1, 1, testLastCol).getValues()[0];
    backup.testimonials = testimonialsSheet.getRange(2, 1, testimonialsSheet.getLastRow() - 1, testLastCol).getValues();
    Logger.log('Backed up ' + backup.testimonials.length + ' testimonial rows with ' + backup.testimonialHeaders.length + ' columns');
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
  // Helper function to map data from old column order to new column order
  function mapDataToNewColumns(oldHeaders, oldData, newHeaders) {
    return oldData.map(row => {
      return newHeaders.map(newCol => {
        const oldIndex = oldHeaders.indexOf(newCol);
        if (oldIndex >= 0 && oldIndex < row.length) {
          return row[oldIndex];
        }
        return ''; // New column that didn't exist in backup
      });
    });
  }

  // Restore Submissions data with column mapping
  if (backup.submissions && backup.submissions.length > 0) {
    const submissionsSheet = ss.getSheetByName(SHEETS.SUBMISSIONS);
    if (submissionsSheet) {
      const newHeaders = submissionsSheet.getRange(1, 1, 1, submissionsSheet.getLastColumn()).getValues()[0];
      const oldHeaders = backup.submissionHeaders || newHeaders; // Fallback for backwards compatibility
      const mappedData = mapDataToNewColumns(oldHeaders, backup.submissions, newHeaders);
      submissionsSheet.getRange(2, 1, mappedData.length, newHeaders.length).setValues(mappedData);
      Logger.log('Restored ' + mappedData.length + ' submission rows (mapped from ' + oldHeaders.length + ' to ' + newHeaders.length + ' columns)');
    }
  }

  // Restore Jobs data with column mapping
  if (backup.jobs && backup.jobs.length > 0) {
    const jobsSheet = ss.getSheetByName(SHEETS.JOBS);
    if (jobsSheet) {
      const newHeaders = jobsSheet.getRange(1, 1, 1, jobsSheet.getLastColumn()).getValues()[0];
      const oldHeaders = backup.jobHeaders || newHeaders; // Fallback for backwards compatibility
      const mappedData = mapDataToNewColumns(oldHeaders, backup.jobs, newHeaders);
      jobsSheet.getRange(2, 1, mappedData.length, newHeaders.length).setValues(mappedData);
      Logger.log('Restored ' + mappedData.length + ' job rows (mapped from ' + oldHeaders.length + ' to ' + newHeaders.length + ' columns)');
    }
  }

  // Restore Invoice Log data with column mapping
  if (backup.invoices && backup.invoices.length > 0) {
    const invoiceSheet = ss.getSheetByName(SHEETS.INVOICES);
    if (invoiceSheet) {
      const newHeaders = invoiceSheet.getRange(1, 1, 1, invoiceSheet.getLastColumn()).getValues()[0];
      const oldHeaders = backup.invoiceHeaders || newHeaders; // Fallback for backwards compatibility
      const mappedData = mapDataToNewColumns(oldHeaders, backup.invoices, newHeaders);
      invoiceSheet.getRange(2, 1, mappedData.length, newHeaders.length).setValues(mappedData);
      Logger.log('Restored ' + mappedData.length + ' invoice rows (mapped from ' + oldHeaders.length + ' to ' + newHeaders.length + ' columns)');
    }
  }

  // Restore Settings data - merge backed up values into the new sheet (preserves styling)
  if (backup.settings && backup.settings.length > 0) {
    const settingsSheet = ss.getSheetByName(SHEETS.SETTINGS);
    if (settingsSheet) {
      // Build a map of backed-up settings (setting name -> value)
      const backedUpValues = {};
      for (let i = 1; i < backup.settings.length; i++) {
        const settingName = backup.settings[i][0];
        const settingValue = backup.settings[i][1];
        if (settingName) {
          backedUpValues[settingName] = settingValue;
        }
      }

      // Update each setting in the new sheet with the backed-up value
      const currentData = settingsSheet.getDataRange().getValues();
      let updatedCount = 0;
      for (let i = 1; i < currentData.length; i++) {
        const settingName = currentData[i][0];
        if (settingName && backedUpValues.hasOwnProperty(settingName)) {
          // Restore the backed-up value
          settingsSheet.getRange(i + 1, 2).setValue(backedUpValues[settingName]);
          updatedCount++;
        }
      }
      Logger.log('Restored ' + updatedCount + ' settings values (preserved styling)');

      // Clear PropertiesService safety net now that in-memory restore succeeded
      try {
        PropertiesService.getScriptProperties().deleteProperty('SETTINGS_BACKUP');
      } catch (e) {
        Logger.log('Could not clear PropertiesService backup: ' + e.message);
      }
    }
  }

  // Restore Testimonials data with column mapping
  if (backup.testimonials && backup.testimonials.length > 0) {
    const testimonialsSheet = ss.getSheetByName(SHEETS.TESTIMONIALS);
    if (testimonialsSheet) {
      const newHeaders = testimonialsSheet.getRange(1, 1, 1, testimonialsSheet.getLastColumn()).getValues()[0];
      const oldHeaders = backup.testimonialHeaders || newHeaders; // Fallback for backwards compatibility
      const mappedData = mapDataToNewColumns(oldHeaders, backup.testimonials, newHeaders);
      testimonialsSheet.getRange(2, 1, mappedData.length, newHeaders.length).setValues(mappedData);
      Logger.log('Restored ' + mappedData.length + ' testimonial rows (mapped from ' + oldHeaders.length + ' to ' + newHeaders.length + ' columns)');
    }
  }
}

/**
 * Setup all required sheets for job management
 * @param {boolean} clearData - If true, deletes all data (hard reset mode)
 */
function setupSheets(clearData) {
  const ss = getSpreadsheet();
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

    logDebug('  3b2: Creating Clients sheet...');
    setupClientsSheet(ss, clearData);
    logDebug('  3b2 COMPLETE: Clients sheet done');
    logAllSheets('AFTER setupClientsSheet()');

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
      SHEETS.CLIENTS,
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

    // Step 11: Refresh Dashboard and Analytics with actual data
    logDebug('Step 11: Refreshing Dashboard and Analytics...');
    try {
      refreshDashboard(true);
      logDebug('  Dashboard refreshed');
    } catch (dashErr) {
      logDebug('  Dashboard refresh error: ' + dashErr.message);
    }
    try {
      refreshAnalytics();
      logDebug('  Analytics refreshed');
    } catch (analyticsErr) {
      logDebug('  Analytics refresh error: ' + analyticsErr.message);
    }
    logDebug('Step 11 COMPLETE');

    logAllSheets('FINAL STATE');
    logDebug('========== SETUP SHEETS SUCCESS ==========');

    // Save debug log to file
    saveSetupDebugLog(debugLog.join('\n'), 'SUCCESS');

    const message = clearData
      ? 'Hard reset complete! All data has been deleted and sheets have been reset.\n\nAutomatic features enabled:\n• Quote reminders (7 days after quote sent)\n• Invoice reminders (before due date)\n• Overdue invoice notices\n• Email scanning\n• Background task processing'
      : 'Setup complete! All sheets have been created/repaired with data preserved.\n\nAutomatic features enabled:\n• Quote reminders (7 days after quote sent)\n• Invoice reminders (before due date)\n• Overdue invoice notices\n• Email scanning\n• Background task processing\n\nNext steps:\n1. Fill in your business details in the Settings sheet\n2. Use the CartCure menu to manage jobs';

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
    .setFontFamily(SHEET_FONTS.primary)
    .setFontSize(SHEET_FONTS.sizeMD + 1)
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
  // Hide gridlines for clean, modern look
  sheet.setHiddenGridlines(true);
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
    .setFontSize(SHEET_FONTS.sizeLG)
    .setFontWeight('bold')
    .setFontColor(SHEET_COLORS.inkBlack)
    .setFontFamily(SHEET_FONTS.primary);
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
    .setFontFamily(SHEET_FONTS.primary)
    .setFontSize(SHEET_FONTS.sizeSM)
    .setHorizontalAlignment('center');
}

/**
 * Apply metric card styling
 * @param {Range} labelRange - The label range
 * @param {Range} valueRange - The value range
 */
function applyMetricStyle(labelRange, valueRange) {
  labelRange
    .setBackground(SHEET_COLORS.paperCream)
    .setFontWeight('bold')
    .setFontSize(SHEET_FONTS.sizeXS)
    .setFontColor(SHEET_COLORS.inkGray)
    .setHorizontalAlignment('center')
    .setFontFamily(SHEET_FONTS.primary);

  valueRange
    .setBackground(SHEET_COLORS.paperWhite)
    .setFontWeight('bold')
    .setFontSize(SHEET_FONTS.sizeLG + 2)
    .setFontColor(SHEET_COLORS.inkBlack)
    .setHorizontalAlignment('center')
    .setFontFamily(SHEET_FONTS.primary);
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
 * Apply light borders for data sheets - horizontal only, no vertical dividers
 * Creates clean row separation without a grid-like appearance
 * @param {Range} range - The data range (excluding header)
 */
function applyLightBorders(range) {
  const borderColor = SHEET_COLORS.paperBorder;
  const borderStyle = SpreadsheetApp.BorderStyle.SOLID;
  // Outer border + horizontal inner borders only (no vertical)
  range.setBorder(true, true, true, true, false, true, borderColor, borderStyle);
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
    // Clear all data validation before migration to prevent conflicts
    try {
      const fullRange = sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns());
      fullRange.clearDataValidations();
      Logger.log('Cleared data validations before Jobs migration');
    } catch (e) {
      Logger.log('Could not clear validations: ' + e.message);
    }

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
  sheet.setRowHeight(1, SHEET_FONTS.headerRowHeight);

  // Set default row height for data rows
  for (let i = 2; i <= 50; i++) {
    sheet.setRowHeight(i, SHEET_FONTS.dataRowHeight);
  }

  // Apply alternating row colors for existing data
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataRange = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataRange.setFontFamily(SHEET_FONTS.primary);
  dataRange.setFontSize(SHEET_FONTS.sizeMD);
  dataRange.setFontColor(SHEET_COLORS.inkBlack);
  dataRange.setVerticalAlignment('middle');
  applyLightBorders(dataRange);

  // Freeze header row
  sheet.setFrozenRows(1);
  sheet.setTabColor('#1565c0');

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'JOBS');

  // Use dynamic row count instead of hardcoded 500 for scalability
  const numRows = getDynamicRowCount(sheet);

  // Clean up invalid Status values before applying validation
  // This handles cases where old Actions column data (☰) ended up in Status column
  const statusCol = getColIndex('JOBS', 'Status');
  const validStatuses = Object.values(JOB_STATUS);
  const lastDataRow = sheet.getLastRow();
  if (lastDataRow > 1) {
    const statusRange = sheet.getRange(2, statusCol, lastDataRow - 1, 1);
    const statusValues = statusRange.getValues();
    let fixed = 0;
    for (let i = 0; i < statusValues.length; i++) {
      const val = statusValues[i][0];
      if (val && !validStatuses.includes(val)) {
        statusValues[i][0] = JOB_STATUS.PENDING_QUOTE;
        fixed++;
      }
    }
    if (fixed > 0) {
      statusRange.setValues(statusValues);
      Logger.log('Fixed ' + fixed + ' invalid Status values in Jobs');
    }
  }

  // Apply data validation from config (Status, Category, Payment Status dropdowns)
  applyConfigValidation(sheet, 'JOBS', 2, numRows);

  // Apply conditional formatting from config (Status, SLA, Payment colors)
  applyConfigConditionalFormatting(sheet, 'JOBS', 2, numRows);

  // Apply formulas from config (Remaining Balance)
  applyConfigFormulas(sheet, 'JOBS', 2, numRows);

  // Apply number formats from config
  applyConfigNumberFormats(sheet, 'JOBS', 2, numRows);

  // Apply font weights from config (bold key identifier columns)
  applyConfigFontWeights(sheet, 'JOBS', 2, numRows);

  // Enable filtering for all columns
  try {
    const filterRange = sheet.getRange(1, 1, Math.max(sheet.getLastRow(), 2), headers.length);
    if (!sheet.getFilter()) {
      filterRange.createFilter();
    }
  } catch (e) {
    Logger.log('Filter already exists or could not be created: ' + e.message);
  }

  // Apply default sort: newest jobs first (by Created Date descending)
  sortJobsNewestFirst(sheet);

  Logger.log('Jobs sheet ' + (isNew ? 'created' : 'updated'));
}

/**
 * Sort Jobs sheet by Created Date (newest first)
 * This ensures newest jobs always appear at the top
 */
function sortJobsNewestFirst(sheet) {
  if (!sheet) {
    const ss = getSpreadsheet();
    sheet = ss.getSheetByName(SHEETS.JOBS);
  }
  if (!sheet) return;

  const lastRow = sheet.getLastRow();
  if (lastRow <= 1) return; // No data to sort

  // Get Created Date column index from COLUMN_CONFIG (already 1-based)
  const createdDateCol = getColIndex('JOBS', 'Created Date');

  if (createdDateCol === -1) {
    Logger.log('Created Date column not found for sorting');
    return;
  }

  // Sort data rows (excluding header) by Created Date descending
  const dataRange = sheet.getRange(2, 1, lastRow - 1, sheet.getLastColumn());
  dataRange.sort({ column: createdDateCol, ascending: false });

  Logger.log('Jobs sorted by Created Date (newest first)');
}

/**
 * Add conditional formatting for SLA status column
 */
function addSLAConditionalFormatting(sheet) {
  const slaColumn = 18; // SLA Status column
  const numRows = getDynamicRowCount(sheet);
  const range = sheet.getRange(2, slaColumn, numRows, 1);

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
  const numRows = getDynamicRowCount(sheet);
  const range = sheet.getRange(2, statusColumn, numRows, 1);

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
  const numRows = getDynamicRowCount(sheet);
  const range = sheet.getRange(2, paymentColumn, numRows, 1);

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
    // Clear all data validation before migration to prevent conflicts
    try {
      const fullRange = sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns());
      fullRange.clearDataValidations();
      Logger.log('Cleared data validations before Invoices migration');
    } catch (e) {
      Logger.log('Could not clear validations: ' + e.message);
    }

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
  sheet.setRowHeight(1, SHEET_FONTS.headerRowHeight);

  // Apply alternating row colors
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataRange = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataRange.setFontFamily(SHEET_FONTS.primary);
  dataRange.setFontSize(SHEET_FONTS.sizeMD);
  dataRange.setFontColor(SHEET_COLORS.inkBlack);
  dataRange.setVerticalAlignment('middle');
  applyLightBorders(dataRange);

  sheet.setFrozenRows(1);
  sheet.setTabColor('#b8860b');

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'INVOICES');

  // Use dynamic row count instead of hardcoded 500 for scalability
  const numRows = getDynamicRowCount(sheet);

  // Clean up invalid Status values before applying validation
  // This handles cases where old Actions column data (☰) ended up in Status column
  const statusCol = getColIndex('INVOICES', 'Status');
  const validStatuses = ['Draft', 'Sent', 'Paid', 'Paid?', 'Overdue', 'Cancelled'];
  const lastDataRow = sheet.getLastRow();
  if (lastDataRow > 1) {
    const statusRange = sheet.getRange(2, statusCol, lastDataRow - 1, 1);
    const statusValues = statusRange.getValues();
    let fixed = 0;
    for (let i = 0; i < statusValues.length; i++) {
      const val = statusValues[i][0];
      if (val && !validStatuses.includes(val)) {
        statusValues[i][0] = 'Draft';
        fixed++;
      }
    }
    if (fixed > 0) {
      statusRange.setValues(statusValues);
      Logger.log('Fixed ' + fixed + ' invalid Status values in Invoices');
    }
  }

  // Apply data validation from config (Status, Invoice Type dropdowns)
  applyConfigValidation(sheet, 'INVOICES', 2, numRows);

  // Apply conditional formatting from config (Status colors)
  applyConfigConditionalFormatting(sheet, 'INVOICES', 2, numRows);

  // Apply number formats from config
  applyConfigNumberFormats(sheet, 'INVOICES', 2, numRows);

  // Apply font weights from config (bold key identifier columns)
  applyConfigFontWeights(sheet, 'INVOICES', 2, numRows);

  // Enable filtering for all columns
  try {
    const filterRange = sheet.getRange(1, 1, Math.max(sheet.getLastRow(), 2), headers.length);
    if (!sheet.getFilter()) {
      filterRange.createFilter();
    }
  } catch (e) {
    Logger.log('Filter already exists or could not be created: ' + e.message);
  }

  Logger.log('Invoice Log sheet ' + (isNew ? 'created' : 'updated'));
}

/**
 * Sets up the Clients sheet with proper formatting and structure.
 * Clients are tracked by email (primary key) and populated from existing jobs on first setup.
 * @param {Spreadsheet} ss - The spreadsheet object
 * @param {boolean} clearData - Whether to clear existing data
 */
function setupClientsSheet(ss, clearData) {
  let sheet = ss.getSheetByName(SHEETS.CLIENTS);
  const isNew = !sheet;

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.CLIENTS);
  }

  // Get headers from config (single source of truth)
  const headers = getColHeaders('CLIENTS');

  // Migrate existing data if column order has changed
  if (!isNew && sheet.getLastColumn() > 0) {
    // Clear all data validation before migration to prevent conflicts
    try {
      const fullRange = sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns());
      fullRange.clearDataValidations();
      Logger.log('Cleared data validations before Clients migration');
    } catch (e) {
      Logger.log('Could not clear validations: ' + e.message);
    }

    const migration = migrateSheetColumns(sheet, 'CLIENTS');
    if (migration.migrated) {
      Logger.log('Clients migration: ' + migration.message);
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
  sheet.setRowHeight(1, SHEET_FONTS.headerRowHeight);

  // Apply alternating row colors
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataRange = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataRange.setFontFamily(SHEET_FONTS.primary);
  dataRange.setFontSize(SHEET_FONTS.sizeMD);
  dataRange.setFontColor(SHEET_COLORS.inkBlack);
  dataRange.setVerticalAlignment('middle');
  applyLightBorders(dataRange);

  sheet.setFrozenRows(1);
  sheet.setTabColor('#7b1fa2');

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'CLIENTS');

  // Apply data validation from config (Client Status dropdown)
  const numRows = getDynamicRowCount(sheet);
  applyConfigValidation(sheet, 'CLIENTS', 2, numRows);

  // Apply conditional formatting from config (Status colors)
  applyConfigConditionalFormatting(sheet, 'CLIENTS', 2, numRows);

  // Apply number formats from config
  applyConfigNumberFormats(sheet, 'CLIENTS', 2, numRows);

  // Apply text wrapping for Notes column
  applyConfigWrapText(sheet, 'CLIENTS', 2, numRows);

  // Apply font weights from config (bold key identifier columns)
  applyConfigFontWeights(sheet, 'CLIENTS', 2, numRows);

  // Enable filtering for all columns
  try {
    const filterRange = sheet.getRange(1, 1, Math.max(sheet.getLastRow(), 2), headers.length);
    if (!sheet.getFilter()) {
      filterRange.createFilter();
    }
  } catch (e) {
    Logger.log('Filter already exists or could not be created: ' + e.message);
  }

  // If this is a new sheet, populate from existing jobs
  if (isNew && !clearData) {
    populateClientsFromExistingJobs();
  }

  Logger.log('Clients sheet ' + (isNew ? 'created' : 'updated'));
}

/**
 * Add conditional formatting for Invoice Status column
 */
function addInvoiceStatusConditionalFormatting(sheet) {
  const statusColumn = 11; // Status column
  const numRows = getDynamicRowCount(sheet);
  const range = sheet.getRange(2, statusColumn, numRows, 1);

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
    ['Next Invoice Number', '1', 'Auto-incremented invoice number counter'],
    ['Confirm Selection Dialog', 'No', 'Show confirmation when job/invoice auto-detected (Yes/No)'],
    ['Header Row Protection', 'No', 'Show warning when editing header rows (Yes/No)'],
    ['Column Protection', 'Yes', 'Prevent editing system-managed columns (Yes/No)'],
    ['Archive Jobs After Days', '90', 'Days after completion to archive jobs (0 = never archive)'],
    ['Archive Activity After Days', '365', 'Days to keep in Activity Log before archiving (0 = never)']
  ];

  if (!sheet) {
    sheet = ss.insertSheet(SHEETS.SETTINGS);
    if (!clearData) {
      // Repair mode - try to restore from PropertiesService safety net
      try {
        const propBackup = PropertiesService.getScriptProperties().getProperty('SETTINGS_BACKUP');
        if (propBackup) {
          const backedUpValues = JSON.parse(propBackup);
          const mergedSettings = defaultSettings.map((row, index) => {
            if (index === 0) return row; // Header row
            if (backedUpValues.hasOwnProperty(row[0]) && backedUpValues[row[0]] !== '') {
              return [row[0], backedUpValues[row[0]], row[2]];
            }
            return row;
          });
          sheet.getRange(1, 1, mergedSettings.length, 3).setValues(mergedSettings);
          Logger.log('Settings restored from PropertiesService backup');
        } else {
          sheet.getRange(1, 1, defaultSettings.length, 3).setValues(defaultSettings);
        }
      } catch (e) {
        Logger.log('Could not restore from PropertiesService: ' + e.message);
        sheet.getRange(1, 1, defaultSettings.length, 3).setValues(defaultSettings);
      }
    } else {
      // Hard reset - use defaults
      sheet.getRange(1, 1, defaultSettings.length, 3).setValues(defaultSettings);
    }
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

  // === STANDARD PAPER STYLING (matches other sheets) ===
  const numCols = 3;
  const numRows = defaultSettings.length;

  // Apply paper-like background to entire sheet
  applyPaperBackground(sheet);

  // Format header row with brand styling
  const headerRange = sheet.getRange(1, 1, 1, numCols);
  applyHeaderStyle(headerRange);
  applyBorders(headerRange, true, false);
  sheet.setRowHeight(1, SHEET_FONTS.headerRowHeight);

  // Apply alternating row colors for settings rows
  applyAlternatingRows(sheet, 2, numRows - 1, numCols);

  // Set default text styling for data area
  const dataRange = sheet.getRange(2, 1, numRows - 1, numCols);
  dataRange.setFontFamily(SHEET_FONTS.primary);
  dataRange.setFontSize(SHEET_FONTS.sizeMD);
  dataRange.setFontColor(SHEET_COLORS.inkBlack);
  dataRange.setVerticalAlignment('middle');

  // Format setting names (first column) - bold
  const settingNamesRange = sheet.getRange(2, 1, numRows - 1, 1);
  settingNamesRange.setFontWeight('bold');

  // Format value column - brand green, bold, centered
  const valueRange = sheet.getRange(2, 2, numRows - 1, 1);
  valueRange.setFontColor(SHEET_COLORS.brandGreen);
  valueRange.setFontWeight('bold');
  valueRange.setHorizontalAlignment('center');

  // Format description column - gray italic
  const descRange = sheet.getRange(2, 3, numRows - 1, 1);
  descRange.setFontSize(SHEET_FONTS.sizeSM);
  descRange.setFontColor(SHEET_COLORS.inkGray);
  descRange.setFontStyle('italic');

  // Set column widths
  sheet.setColumnWidth(1, 200);  // Setting Name
  sheet.setColumnWidth(2, 180);  // Value
  sheet.setColumnWidth(3, 320);  // Description

  sheet.setFrozenRows(1);
  sheet.setTabColor(SHEET_COLORS.inkLight);

  // Add dropdown validation for GST Registered (row 3, column 2)
  const gstRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(['Yes', 'No'], true)
    .setAllowInvalid(false)
    .build();
  sheet.getRange(3, 2).setDataValidation(gstRule);

  // Add dropdown validation for Yes/No settings
  const yesNoRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(['Yes', 'No'], true)
    .setAllowInvalid(false)
    .build();
  // Confirm Selection Dialog (row 12)
  sheet.getRange(12, 2).setDataValidation(yesNoRule);
  // Header Row Protection (row 13)
  sheet.getRange(13, 2).setDataValidation(yesNoRule);

  Logger.log('Settings sheet ' + (isNew ? 'created' : (clearData ? 'reset' : 'updated')));
}

/**
 * Create the Dashboard sheet with brand styling
 * @param {Spreadsheet} ss - Optional spreadsheet object (for backwards compatibility)
 */
function createDashboardSheet(ss) {
  if (!ss) {
    ss = getSpreadsheet();
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
  sheet.setTabColor(SHEET_COLORS.brandGreen);

  // Dashboard header with brand styling
  sheet.getRange('A1').setValue('📊 CartCure Dashboard');
  sheet.getRange('A1')
    .setFontSize(SHEET_FONTS.sizeXXL)
    .setFontWeight('bold')
    .setFontColor(SHEET_COLORS.brandGreen)
    .setFontFamily(SHEET_FONTS.primary);

  sheet.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));
  sheet.getRange('A2')
    .setFontColor(SHEET_COLORS.inkLight)
    .setFontStyle('italic')
    .setFontSize(SHEET_FONTS.sizeSM)
    .setFontFamily(SHEET_FONTS.primary);

  // Refresh checkbox (triggers refresh when checked)
  sheet.getRange('G1').setValue('🔄 Refresh →');
  sheet.getRange('G1')
    .setFontWeight('bold')
    .setFontSize(SHEET_FONTS.sizeMD)
    .setFontColor(SHEET_COLORS.inkGray)
    .setHorizontalAlignment('right')
    .setVerticalAlignment('middle')
    .setFontFamily(SHEET_FONTS.primary);

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

  // Style data area text (uniform background, no alternating on compact dashboard tables)
  sheet.getRange(10, 1, 6, 5)
    .setBackground(SHEET_COLORS.paperWhite)
    .setFontFamily(SHEET_FONTS.primary)
    .setFontSize(SHEET_FONTS.sizeSM)
    .setFontColor(SHEET_COLORS.inkBlack)
    .setVerticalAlignment('middle');

  // Add outer border + horizontal row separators to submissions table
  applyLightBorders(sheet.getRange(9, 1, 7, 5));

  // === RIGHT COLUMN: Active Jobs + Pending Quotes ===

  // Active Jobs Section
  sheet.getRange('I4').setValue('🔥 Active Jobs (by urgency)');
  applySectionHeaderStyle(sheet.getRange('I4'));

  const activeJobsHeaders = ['Job #', 'Client', 'Description', 'Amount', 'Days Left', 'SLA', 'Status'];
  sheet.getRange(5, 9, 1, 7).setValues([activeJobsHeaders]);
  applyTableHeaderStyle(sheet.getRange(5, 9, 1, 7));

  // Style data area (uniform background, no alternating on compact dashboard tables)
  sheet.getRange(6, 9, 10, 7)
    .setBackground(SHEET_COLORS.paperWhite)
    .setFontFamily(SHEET_FONTS.primary)
    .setFontSize(SHEET_FONTS.sizeSM)
    .setFontColor(SHEET_COLORS.inkBlack)
    .setVerticalAlignment('middle');

  // Add outer border + horizontal row separators to active jobs table
  applyLightBorders(sheet.getRange(5, 9, 11, 7));

  // Pending Quotes Section
  sheet.getRange('I17').setValue('⏳ Pending Quotes');
  applySectionHeaderStyle(sheet.getRange('I17'));

  const pendingQuotesHeaders = ['Job #', 'Client', 'Amount', 'Waiting', 'Valid Until', 'Action'];
  sheet.getRange(18, 9, 1, 6).setValues([pendingQuotesHeaders]);
  applyTableHeaderStyle(sheet.getRange(18, 9, 1, 6));

  // Style data area (uniform background, no alternating on compact dashboard tables)
  sheet.getRange(19, 9, 6, 6)
    .setBackground(SHEET_COLORS.paperWhite)
    .setFontFamily(SHEET_FONTS.primary)
    .setFontSize(SHEET_FONTS.sizeSM)
    .setFontColor(SHEET_COLORS.inkBlack)
    .setVerticalAlignment('middle');

  // Add outer border + horizontal row separators to pending quotes table
  applyLightBorders(sheet.getRange(18, 9, 7, 6));

  // Set fixed column widths for Dashboard
  // Left section (columns 1-7): Metrics + New Submissions
  sheet.setColumnWidth(1, 110);  // Submission # / OVERDUE
  sheet.setColumnWidth(2, 90);   // Date / AT RISK
  sheet.setColumnWidth(3, 110);  // Name / In Progress
  sheet.setColumnWidth(4, 110);  // Email / Pending Quote
  sheet.setColumnWidth(5, 110);  // Message / Quoted
  sheet.setColumnWidth(6, 90);   // Unpaid $
  sheet.setColumnWidth(7, 110);  // Revenue MTD
  sheet.setColumnWidth(8, 10);   // Spacer column
  // Right section (columns 9-15): Active Jobs + Pending Quotes
  sheet.setColumnWidth(9, 90);   // Job #
  sheet.setColumnWidth(10, 110); // Client
  sheet.setColumnWidth(11, 220); // Description
  sheet.setColumnWidth(12, 90);  // Amount
  sheet.setColumnWidth(13, 70);  // Days Left / Waiting
  sheet.setColumnWidth(14, 90);  // SLA / Valid Until
  sheet.setColumnWidth(15, 80);  // Status / Action

  // Set row heights for compactness
  for (let i = 1; i <= 30; i++) {
    sheet.setRowHeight(i, SHEET_FONTS.dashboardRowHeight);
  }
  sheet.setRowHeight(1, SHEET_FONTS.titleRowHeight); // Title row slightly taller
  sheet.setRowHeight(4, SHEET_FONTS.sectionHeaderHeight); // Section headers
  sheet.setRowHeight(5, SHEET_FONTS.dashboardRowHeight);       // Metric labels - compact
  sheet.setRowHeight(6, SHEET_FONTS.headerRowHeight);           // Metric values - taller for impact
  sheet.setRowHeight(8, SHEET_FONTS.sectionHeaderHeight);
  sheet.setRowHeight(17, SHEET_FONTS.sectionHeaderHeight);

  Logger.log('Dashboard sheet formatted successfully');
}

/**
 * Create the Analytics sheet with visual data displays
 * @param {Spreadsheet} ss - Optional spreadsheet object (for backwards compatibility)
 */
function createAnalyticsSheet(ss) {
  if (!ss) {
    ss = getSpreadsheet();
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
  sheet.setTabColor(SHEET_COLORS.brandGreen);

  // Title with brand styling
  sheet.getRange('A1').setValue('📈 CartCure Analytics');
  sheet.getRange('A1')
    .setFontSize(SHEET_FONTS.sizeXXL)
    .setFontWeight('bold')
    .setFontColor(SHEET_COLORS.brandGreen)
    .setFontFamily(SHEET_FONTS.primary);

  sheet.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));
  sheet.getRange('A2')
    .setFontColor(SHEET_COLORS.inkLight)
    .setFontStyle('italic')
    .setFontSize(SHEET_FONTS.sizeSM)
    .setFontFamily(SHEET_FONTS.primary);

  // Refresh checkbox
  sheet.getRange('G1').setValue('🔄 Refresh →');
  sheet.getRange('G1')
    .setFontWeight('bold')
    .setFontSize(SHEET_FONTS.sizeMD)
    .setFontColor(SHEET_COLORS.inkGray)
    .setHorizontalAlignment('right')
    .setFontFamily(SHEET_FONTS.primary);
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
  sheet.getRange(11, 1, 8, 3).setFontFamily(SHEET_FONTS.primary).setFontSize(SHEET_FONTS.sizeMD).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(10, 1, 9, 3), true, false);

  // === SECTION 3: PAYMENT STATUS (Row 9-18, Right) ===
  sheet.getRange('E9').setValue('💰 Payment Status');
  applySectionHeaderStyle(sheet.getRange('E9'));

  const paymentHeaders = ['Status', 'Count', 'Amount'];
  sheet.getRange(10, 5, 1, 3).setValues([paymentHeaders]);
  applyTableHeaderStyle(sheet.getRange(10, 5, 1, 3));
  applyAlternatingRows(sheet, 11, 5, 3, 5);
  sheet.getRange(11, 5, 5, 3).setFontFamily(SHEET_FONTS.primary).setFontSize(SHEET_FONTS.sizeMD).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(10, 5, 6, 3), true, false);

  // === SECTION 4: SLA PERFORMANCE (Row 9-18, Far Right) ===
  sheet.getRange('I9').setValue('⏱️ SLA Performance');
  applySectionHeaderStyle(sheet.getRange('I9'));

  const slaHeaders = ['Status', 'Count', '%'];
  sheet.getRange(10, 9, 1, 3).setValues([slaHeaders]);
  applyTableHeaderStyle(sheet.getRange(10, 9, 1, 3));
  applyAlternatingRows(sheet, 11, 3, 3, 9);
  sheet.getRange(11, 9, 3, 3).setFontFamily(SHEET_FONTS.primary).setFontSize(SHEET_FONTS.sizeMD).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(10, 9, 4, 3), true, false);

  // === SECTION 5: MONTHLY REVENUE (Row 20-32) ===
  sheet.getRange('A20').setValue('📅 Monthly Performance (Last 6 Months)');
  applySectionHeaderStyle(sheet.getRange('A20'));

  const monthlyHeaders = ['Month', 'Jobs Created', 'Jobs Completed', 'Revenue', 'Avg Value'];
  sheet.getRange(21, 1, 1, 5).setValues([monthlyHeaders]);
  applyTableHeaderStyle(sheet.getRange(21, 1, 1, 5));
  applyAlternatingRows(sheet, 22, 6, 5, 1);
  sheet.getRange(22, 1, 6, 5).setFontFamily(SHEET_FONTS.primary).setFontSize(SHEET_FONTS.sizeMD).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
  applyBorders(sheet.getRange(21, 1, 7, 5), true, false);

  // === SECTION 6: TOP CATEGORIES (Row 20-32, Right) ===
  sheet.getRange('G20').setValue('🏷️ Jobs by Category');
  applySectionHeaderStyle(sheet.getRange('G20'));

  const categoryHeaders = ['Category', 'Count', 'Revenue'];
  sheet.getRange(21, 7, 1, 3).setValues([categoryHeaders]);
  applyTableHeaderStyle(sheet.getRange(21, 7, 1, 3));
  applyAlternatingRows(sheet, 22, 6, 3, 7);
  sheet.getRange(22, 7, 6, 3).setFontFamily(SHEET_FONTS.primary).setFontSize(SHEET_FONTS.sizeMD).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
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
    .setFontFamily(SHEET_FONTS.primary)
    .setFontSize(SHEET_FONTS.sizeSM)
    .setHorizontalAlignment('center');
  applyAlternatingRows(sheet, 22, 6, 4, 11);
  sheet.getRange(22, 11, 6, 4).setFontFamily(SHEET_FONTS.primary).setFontSize(SHEET_FONTS.sizeMD).setFontColor(SHEET_COLORS.inkBlack).setVerticalAlignment('middle');
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
    sheet.setRowHeight(i, SHEET_FONTS.dashboardRowHeight);
  }
  sheet.setRowHeight(1, SHEET_FONTS.titleRowHeight);  // Title row
  sheet.setRowHeight(4, SHEET_FONTS.sectionHeaderHeight);  // Section headers
  sheet.setRowHeight(9, SHEET_FONTS.sectionHeaderHeight);
  sheet.setRowHeight(20, SHEET_FONTS.sectionHeaderHeight);
  sheet.setRowHeight(30, SHEET_FONTS.sectionHeaderHeight); // Charts section header

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
  sheet.setRowHeight(30, SHEET_FONTS.sectionHeaderHeight);

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
 * PERFORMANCE OPTIMIZED: Uses cached spreadsheet
 */
function refreshAnalytics() {
  // PERFORMANCE: Use cached sheet references
  const analytics = getSheet(SHEETS.ANALYTICS);
  const jobsSheet = getSheet(SHEETS.JOBS);
  const submissionsSheet = getSheet(SHEETS.SUBMISSIONS);

  if (!analytics) {
    SpreadsheetApp.getUi().alert('Error', 'Analytics sheet not found. Please run Setup first.', SpreadsheetApp.getUi().ButtonSet.OK);
    return;
  }

  // Update timestamp
  analytics.getRange('A2').setValue('Last refreshed: ' + new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }));

  // Get jobs data
  const jobsData = jobsSheet ? jobsSheet.getDataRange().getValues() : [[]];
  const jobHeaders = jobsData[0] || [];

  // Use actual sheet headers for column lookup (handles any column order)
  const cols = {
    jobNum: jobHeaders.indexOf('Job #'),
    status: jobHeaders.indexOf('Status'),
    paymentStatus: jobHeaders.indexOf('Payment Status'),
    totalInclGst: jobHeaders.indexOf('Total (incl GST)'),
    slaStatus: jobHeaders.indexOf('SLA Status'),
    category: jobHeaders.indexOf('Category'),
    clientName: jobHeaders.indexOf('Client Name'),
    daysRemaining: jobHeaders.indexOf('Days Remaining'),
    createdDate: jobHeaders.indexOf('Created Date'),
    completionDate: jobHeaders.indexOf('Actual Completion Date'),
    paymentDate: jobHeaders.indexOf('Payment Date')
  };

  const jobs = jobsData.slice(1).filter(row => row[cols.jobNum >= 0 ? cols.jobNum : 0]); // Filter out empty rows

  // Get submissions data
  const subData = submissionsSheet ? submissionsSheet.getDataRange().getValues() : [[]];
  const subHeaders = subData[0] || [];
  // Use actual sheet headers for submissions too
  const subNumCol = subHeaders.indexOf('Submission #');
  const submissions = subData.slice(1).filter(row => row[subNumCol >= 0 ? subNumCol : 0]);

  // === CALCULATE ALL METRICS IN A SINGLE LOOP ===
  // PERFORMANCE: Consolidated from 5+ separate loops into 1
  const metrics = {
    totalRevenue: 0,
    paidJobCount: 0,
    completedJobs: 0,
    onTimeJobs: 0,
    statusCounts: {},
    paymentCounts: {},
    paymentAmounts: {},
    slaCounts: { 'On Track': 0, 'AT RISK': 0, 'OVERDUE': 0 },
    categoryCounts: {},
    categoryRevenue: {}
  };

  // Initialize status and payment counts
  Object.values(JOB_STATUS).forEach(status => metrics.statusCounts[status] = 0);
  Object.values(PAYMENT_STATUS).forEach(status => {
    metrics.paymentCounts[status] = 0;
    metrics.paymentAmounts[status] = 0;
  });

  // Single loop to calculate all metrics
  jobs.forEach(row => {
    const status = row[cols.status];
    const paymentStatus = row[cols.paymentStatus];
    const amount = parseFloat(row[cols.totalInclGst]) || 0;
    const sla = row[cols.slaStatus];
    const category = row[cols.category] || 'Uncategorized';

    // Revenue (only from paid jobs)
    if (paymentStatus === PAYMENT_STATUS.PAID) {
      metrics.totalRevenue += amount;
      metrics.paidJobCount++;
    }

    // Completed and on-time counts
    if (status === JOB_STATUS.COMPLETED) {
      metrics.completedJobs++;
      if (sla !== 'OVERDUE') {
        metrics.onTimeJobs++;
      }
    }

    // Status counts
    if (status && metrics.statusCounts.hasOwnProperty(status)) {
      metrics.statusCounts[status]++;
    }

    // Payment counts and amounts
    if (paymentStatus && metrics.paymentCounts.hasOwnProperty(paymentStatus)) {
      metrics.paymentCounts[paymentStatus]++;
      metrics.paymentAmounts[paymentStatus] += amount;
    }

    // SLA counts (only active jobs)
    if (status === JOB_STATUS.ACCEPTED || status === JOB_STATUS.IN_PROGRESS) {
      if (sla === 'OVERDUE') metrics.slaCounts['OVERDUE']++;
      else if (sla === 'AT RISK') metrics.slaCounts['AT RISK']++;
      else metrics.slaCounts['On Track']++;
    }

    // Category counts
    if (!metrics.categoryCounts[category]) {
      metrics.categoryCounts[category] = 0;
      metrics.categoryRevenue[category] = 0;
    }
    metrics.categoryCounts[category]++;
    if (paymentStatus === PAYMENT_STATUS.PAID) {
      metrics.categoryRevenue[category] += amount;
    }
  });

  // Calculate derived metrics
  const totalJobs = jobs.length;
  const avgJobValue = metrics.paidJobCount > 0 ? metrics.totalRevenue / metrics.paidJobCount : 0;
  const conversionRate = submissions.length > 0 ? (totalJobs / submissions.length * 100) : 0;
  const completionRate = totalJobs > 0 ? (metrics.completedJobs / totalJobs * 100) : 0;
  const onTimeRate = metrics.completedJobs > 0 ? (metrics.onTimeJobs / metrics.completedJobs * 100) : 0;

  // Populate key metrics row
  analytics.getRange(6, 1, 1, 6).setValues([[
    totalJobs,
    formatCurrency(metrics.totalRevenue),
    isNaN(avgJobValue) || !isFinite(avgJobValue) ? formatCurrency(0) : formatCurrency(avgJobValue),
    conversionRate.toFixed(1) + '%',
    completionRate.toFixed(1) + '%',
    onTimeRate.toFixed(1) + '%'
  ]]);
  analytics.getRange(6, 1, 1, 6).setFontSize(SHEET_FONTS.sizeXL - 2).setFontWeight('bold').setHorizontalAlignment('center');

  // === JOB STATUS BREAKDOWN ===
  analytics.getRange(11, 1, 8, 3).clearContent();
  let statusRow = 11;
  Object.entries(metrics.statusCounts).forEach(([status, count]) => {
    const pct = totalJobs > 0 ? (count / totalJobs * 100).toFixed(1) + '%' : '0%';
    analytics.getRange(statusRow, 1, 1, 3).setValues([[status, count, pct]]);
    statusRow++;
  });

  // === PAYMENT STATUS ===
  analytics.getRange(11, 5, 4, 3).clearContent();
  let paymentRow = 11;
  Object.entries(metrics.paymentCounts).forEach(([status, count]) => {
    analytics.getRange(paymentRow, 5, 1, 3).setValues([[status, count, formatCurrency(metrics.paymentAmounts[status])]]);
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
  const activeSlaTotal = metrics.slaCounts['On Track'] + metrics.slaCounts['AT RISK'] + metrics.slaCounts['OVERDUE'];

  analytics.getRange(11, 9, 3, 3).clearContent();
  let slaRow = 11;
  // Use brand colors for SLA status
  const slaColorMap = [
    ['On Track', SHEET_COLORS.slaOnTrack, SHEET_COLORS.slaOnTrackText],
    ['AT RISK', SHEET_COLORS.slaAtRisk, SHEET_COLORS.slaAtRiskText],
    ['OVERDUE', SHEET_COLORS.slaOverdue, SHEET_COLORS.slaOverdueText]
  ];
  slaColorMap.forEach(([status, bgColor, textColor]) => {
    const count = metrics.slaCounts[status];
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
  // Note: This still requires a separate loop per month since we're grouping by date ranges
  const now = new Date();
  const monthlyData = [];
  for (let i = 5; i >= 0; i--) {
    const monthDate = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() - i + 1, 0);
    const monthName = monthDate.toLocaleString('en-NZ', { month: 'short', year: '2-digit' });

    let created = 0, completed = 0, revenue = 0;
    // PERFORMANCE: Uses cached column indices instead of indexOf calls in loop
    jobs.forEach(row => {
      const createdDate = row[cols.createdDate];
      const completionDate = row[cols.completionDate];
      const paymentDate = row[cols.paymentDate];
      const paymentStatus = row[cols.paymentStatus];
      const total = parseFloat(row[cols.totalInclGst]) || 0;

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
  // PERFORMANCE: Already calculated in the single metrics loop above
  // Sort by count descending
  const sortedCategories = Object.entries(metrics.categoryCounts).sort((a, b) => b[1] - a[1]);

  analytics.getRange(22, 7, 10, 3).clearContent();
  let catRow = 22;
  sortedCategories.slice(0, 10).forEach(([category, count]) => {
    analytics.getRange(catRow, 7, 1, 3).setValues([[category, count, formatCurrency(metrics.categoryRevenue[category])]]);
    catRow++;
  });

  // === ATTENTION REQUIRED (Overdue & At Risk jobs) ===
  // PERFORMANCE: Uses cached column indices
  const attentionJobs = jobs.filter(row => {
    const status = row[cols.status];
    const sla = row[cols.slaStatus];
    return (status === JOB_STATUS.ACCEPTED || status === JOB_STATUS.IN_PROGRESS) &&
           (sla === 'OVERDUE' || sla === 'AT RISK');
  }).map(row => ({
    jobNum: row[cols.jobNum],
    client: row[cols.clientName],
    sla: row[cols.slaStatus],
    daysRemaining: row[cols.daysRemaining]
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

// ============================================================================
// FINANCIAL REPORTS (P2 FIX)
// ============================================================================

/**
 * Show dialog to generate monthly financial report
 */
function showMonthlyReportDialog() {
  const ui = SpreadsheetApp.getUi();
  const now = new Date();

  // Default to previous month
  const defaultMonth = now.getMonth() === 0 ? 12 : now.getMonth();
  const defaultYear = now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear();

  const response = ui.prompt(
    '📊 Generate Monthly Report',
    'Enter month and year (MM/YYYY format):\n\n' +
    'Example: ' + String(defaultMonth).padStart(2, '0') + '/' + defaultYear,
    ui.ButtonSet.OK_CANCEL
  );

  if (response.getSelectedButton() !== ui.Button.OK) return;

  const input = response.getResponseText().trim();
  const match = input.match(/^(\d{1,2})\/(\d{4})$/);

  if (!match) {
    ui.alert('Invalid Format', 'Please enter date in MM/YYYY format (e.g., 01/2026)', ui.ButtonSet.OK);
    return;
  }

  const month = parseInt(match[1]);
  const year = parseInt(match[2]);

  if (month < 1 || month > 12) {
    ui.alert('Invalid Month', 'Month must be between 1 and 12', ui.ButtonSet.OK);
    return;
  }

  generateMonthlyReport(month, year);
}

/**
 * Generate a monthly financial report
 * @param {number} month - Month (1-12)
 * @param {number} year - Year (e.g., 2026)
 */
function generateMonthlyReport(month, year) {
  const ui = SpreadsheetApp.getUi();
  const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                      'July', 'August', 'September', 'October', 'November', 'December'];
  const monthName = monthNames[month - 1];

  // Calculate date range
  const startDate = new Date(year, month - 1, 1);
  const endDate = new Date(year, month, 0); // Last day of month

  // Get all jobs and invoices
  const jobs = getAllJobs();
  const invoices = getAllInvoicesRaw();

  // Filter data for the month
  let jobsCreated = 0;
  let jobsCompleted = 0;
  let totalQuoted = 0;
  let quotesAccepted = 0;
  let quotesDeclined = 0;

  jobs.forEach(job => {
    const createdDate = job['Created Date'] ? new Date(job['Created Date']) : null;
    const completedDate = job['Actual Completion Date'] ? new Date(job['Actual Completion Date']) : null;

    if (createdDate && createdDate >= startDate && createdDate <= endDate) {
      jobsCreated++;
      totalQuoted += parseFloat(job['Quote Amount (excl GST)']) || 0;
    }

    if (completedDate && completedDate >= startDate && completedDate <= endDate) {
      jobsCompleted++;
    }

    // Count quote outcomes for jobs created this month
    if (createdDate && createdDate >= startDate && createdDate <= endDate) {
      const status = job['Status'];
      if (status === JOB_STATUS.DECLINED) quotesDeclined++;
      else if (status !== JOB_STATUS.PENDING_QUOTE && status !== JOB_STATUS.QUOTED) quotesAccepted++;
    }
  });

  // Invoice analysis
  let invoicesSent = 0;
  let invoicesPaid = 0;
  let totalInvoiced = 0;
  let totalCollected = 0;
  let totalGSTCollected = 0;

  invoices.forEach(inv => {
    const sentDate = inv['Sent Date'] ? new Date(inv['Sent Date']) : null;
    const paidDate = inv['Paid Date'] ? new Date(inv['Paid Date']) : null;
    const amount = parseFloat(inv['Amount (excl GST)']) || 0;
    const gst = parseFloat(inv['GST']) || 0;
    const total = parseFloat(inv['Total']) || 0;

    if (sentDate && sentDate >= startDate && sentDate <= endDate) {
      invoicesSent++;
      totalInvoiced += total;
    }

    if (paidDate && paidDate >= startDate && paidDate <= endDate && inv['Status'] === 'Paid') {
      invoicesPaid++;
      totalCollected += total;
      totalGSTCollected += gst;
    }
  });

  // Build report
  const businessName = getSetting('Business Name') || 'CartCure';
  const report = [
    '═══════════════════════════════════════════════════════════════',
    '  ' + businessName.toUpperCase() + ' - MONTHLY FINANCIAL REPORT',
    '  ' + monthName + ' ' + year,
    '  Generated: ' + new Date().toLocaleString('en-NZ'),
    '═══════════════════════════════════════════════════════════════',
    '',
    '📋 JOB ACTIVITY',
    '───────────────────────────────────────────────────────────────',
    '  New Jobs Created:     ' + jobsCreated,
    '  Jobs Completed:       ' + jobsCompleted,
    '  Total Quoted:         ' + formatCurrency(totalQuoted),
    '  Quotes Accepted:      ' + quotesAccepted,
    '  Quotes Declined:      ' + quotesDeclined,
    '',
    '🧾 INVOICING',
    '───────────────────────────────────────────────────────────────',
    '  Invoices Sent:        ' + invoicesSent,
    '  Total Invoiced:       ' + formatCurrency(totalInvoiced),
    '  Invoices Paid:        ' + invoicesPaid,
    '',
    '💰 REVENUE',
    '───────────────────────────────────────────────────────────────',
    '  Total Collected:      ' + formatCurrency(totalCollected),
    '  GST Collected:        ' + formatCurrency(totalGSTCollected),
    '  Net Revenue:          ' + formatCurrency(totalCollected - totalGSTCollected),
    '',
    '═══════════════════════════════════════════════════════════════'
  ].join('\n');

  // Show report in dialog
  const htmlOutput = HtmlService.createHtmlOutput(
    '<pre style="font-family: Consolas, monospace; font-size: 12px; padding: 10px; background: #f5f5f5; white-space: pre-wrap;">' +
    report +
    '</pre>'
  ).setWidth(500).setHeight(500);

  ui.showModalDialog(htmlOutput, '📊 Monthly Report - ' + monthName + ' ' + year);
}

/**
 * Generate aging report for outstanding invoices
 */
function generateAgingReport() {
  const ui = SpreadsheetApp.getUi();
  const now = new Date();
  const invoices = getAllInvoicesRaw();

  // Filter to unpaid/overdue invoices
  const outstandingInvoices = invoices.filter(inv => {
    const status = inv['Status'];
    return status === 'Sent' || status === 'Overdue' || status === 'Paid?';
  });

  if (outstandingInvoices.length === 0) {
    ui.alert('✅ No Outstanding Invoices', 'All invoices have been paid!', ui.ButtonSet.OK);
    return;
  }

  // Age buckets
  const buckets = {
    current: { label: 'Current (0-30 days)', invoices: [], total: 0 },
    days30: { label: '31-60 days', invoices: [], total: 0 },
    days60: { label: '61-90 days', invoices: [], total: 0 },
    days90: { label: '90+ days', invoices: [], total: 0 }
  };

  outstandingInvoices.forEach(inv => {
    const dueDate = inv['Due Date'] ? new Date(inv['Due Date']) : now;
    const daysOverdue = Math.floor((now - dueDate) / (1000 * 60 * 60 * 24));
    const total = parseFloat(inv['Total']) || parseFloat(inv['Amount (excl GST)']) || 0;

    const entry = {
      invoice: inv['Invoice #'],
      client: inv['Client Name'],
      amount: total,
      dueDate: inv['Due Date'],
      daysOverdue: Math.max(0, daysOverdue)
    };

    if (daysOverdue <= 30) {
      buckets.current.invoices.push(entry);
      buckets.current.total += total;
    } else if (daysOverdue <= 60) {
      buckets.days30.invoices.push(entry);
      buckets.days30.total += total;
    } else if (daysOverdue <= 90) {
      buckets.days60.invoices.push(entry);
      buckets.days60.total += total;
    } else {
      buckets.days90.invoices.push(entry);
      buckets.days90.total += total;
    }
  });

  const grandTotal = buckets.current.total + buckets.days30.total + buckets.days60.total + buckets.days90.total;

  // Build report
  const businessName = getSetting('Business Name') || 'CartCure';
  let report = [
    '═══════════════════════════════════════════════════════════════',
    '  ' + businessName.toUpperCase() + ' - AGING REPORT',
    '  As of: ' + now.toLocaleDateString('en-NZ'),
    '═══════════════════════════════════════════════════════════════',
    '',
    '📊 SUMMARY',
    '───────────────────────────────────────────────────────────────',
    '  Total Outstanding:    ' + formatCurrency(grandTotal),
    '  Number of Invoices:   ' + outstandingInvoices.length,
    ''
  ];

  Object.values(buckets).forEach(bucket => {
    report.push('');
    report.push('📁 ' + bucket.label + ' - ' + formatCurrency(bucket.total));
    report.push('───────────────────────────────────────────────────────────────');
    if (bucket.invoices.length === 0) {
      report.push('  (none)');
    } else {
      bucket.invoices.forEach(inv => {
        report.push('  ' + inv.invoice + ' | ' + inv.client.substring(0, 20).padEnd(20) +
                    ' | ' + formatCurrency(inv.amount).padStart(12) +
                    ' | ' + (inv.daysOverdue > 0 ? inv.daysOverdue + ' days overdue' : 'Due: ' + inv.dueDate));
      });
    }
  });

  report.push('');
  report.push('═══════════════════════════════════════════════════════════════');

  // Show report
  const htmlOutput = HtmlService.createHtmlOutput(
    '<pre style="font-family: Consolas, monospace; font-size: 11px; padding: 10px; background: #f5f5f5; white-space: pre-wrap;">' +
    report.join('\n') +
    '</pre>'
  ).setWidth(650).setHeight(550);

  ui.showModalDialog(htmlOutput, '📊 Aging Report - Outstanding Invoices');
}

/**
 * Run automated reconciliation check between invoices and client revenue
 * Flags any discrepancies for review
 */
function runReconciliationCheck() {
  const ui = SpreadsheetApp.getUi();
  const issues = [];

  // Get all paid invoices
  const invoices = getAllInvoicesRaw();
  const paidInvoices = invoices.filter(inv => inv['Status'] === 'Paid');

  // Calculate total from paid invoices
  let invoiceTotal = 0;
  const invoicesByClient = {};
  paidInvoices.forEach(inv => {
    const total = parseFloat(inv['Total']) || parseFloat(inv['Amount (excl GST)']) || 0;
    invoiceTotal += total;

    const clientEmail = (inv['Client Email'] || '').toLowerCase().trim();
    if (clientEmail) {
      if (!invoicesByClient[clientEmail]) {
        invoicesByClient[clientEmail] = { total: 0, invoices: [] };
      }
      invoicesByClient[clientEmail].total += total;
      invoicesByClient[clientEmail].invoices.push(inv);
    }

    // Check for payment date before sent date
    const sentDate = inv['Sent Date'] ? new Date(inv['Sent Date']) : null;
    const paidDate = inv['Paid Date'] ? new Date(inv['Paid Date']) : null;
    if (sentDate && paidDate && paidDate < sentDate) {
      issues.push({
        type: 'DATE_ANOMALY',
        severity: 'Warning',
        description: 'Invoice ' + inv['Invoice #'] + ' has Paid Date (' +
          formatNZDate(paidDate) + ') before Sent Date (' + formatNZDate(sentDate) + ')'
      });
    }
  });

  // Get all client revenue totals
  const clientsSheet = getSheet(SHEETS.CLIENTS);
  if (clientsSheet && clientsSheet.getLastRow() > 1) {
    const clientData = clientsSheet.getDataRange().getValues();
    const headers = clientData[0];
    const emailCol = headers.indexOf('Client Email');
    const revenueCol = headers.indexOf('Total Revenue');

    let clientRevenueTotal = 0;
    for (let i = 1; i < clientData.length; i++) {
      const row = clientData[i];
      const clientEmail = (row[emailCol] || '').toLowerCase().trim();
      const clientRevenue = parseFloat(row[revenueCol]) || 0;
      clientRevenueTotal += clientRevenue;

      // Compare client revenue with their paid invoices
      if (clientEmail && invoicesByClient[clientEmail]) {
        const invoiceRevenue = invoicesByClient[clientEmail].total;
        const diff = Math.abs(clientRevenue - invoiceRevenue);

        // Allow $0.01 tolerance for rounding
        if (diff > 0.01) {
          issues.push({
            type: 'REVENUE_MISMATCH',
            severity: 'Error',
            description: 'Client ' + clientEmail + ': Revenue ($' + clientRevenue.toFixed(2) +
              ') does not match paid invoices ($' + invoiceRevenue.toFixed(2) +
              '). Difference: $' + diff.toFixed(2)
          });
        }
      } else if (clientEmail && clientRevenue > 0 && !invoicesByClient[clientEmail]) {
        issues.push({
          type: 'REVENUE_NO_INVOICES',
          severity: 'Warning',
          description: 'Client ' + clientEmail + ' has revenue ($' + clientRevenue.toFixed(2) +
            ') but no paid invoices found'
        });
      }
    }

    // Check for paid invoices with no matching client record
    for (const [clientEmail, data] of Object.entries(invoicesByClient)) {
      const clientExists = clientData.some((row, idx) =>
        idx > 0 && (row[emailCol] || '').toLowerCase().trim() === clientEmail
      );
      if (!clientExists) {
        issues.push({
          type: 'INVOICE_NO_CLIENT',
          severity: 'Warning',
          description: 'Paid invoices for ' + clientEmail + ' ($' + data.total.toFixed(2) +
            ') but no client record found'
        });
      }
    }
  }

  // Build report
  const report = [];
  report.push('═══════════════════════════════════════════════════════════════');
  report.push('       RECONCILIATION CHECK - ' + formatNZDate(new Date()));
  report.push('═══════════════════════════════════════════════════════════════');
  report.push('');
  report.push('SUMMARY');
  report.push('───────────────────────────────────────────────────────────────');
  report.push('Total Paid Invoices:     ' + paidInvoices.length);
  report.push('Total Invoice Amount:    $' + invoiceTotal.toFixed(2));
  report.push('');

  if (issues.length === 0) {
    report.push('✅ NO ISSUES FOUND');
    report.push('');
    report.push('All paid invoices reconcile with client revenue records.');
  } else {
    const errors = issues.filter(i => i.severity === 'Error');
    const warnings = issues.filter(i => i.severity === 'Warning');

    report.push('⚠️ ISSUES FOUND: ' + issues.length);
    report.push('   Errors: ' + errors.length + '  |  Warnings: ' + warnings.length);
    report.push('');

    if (errors.length > 0) {
      report.push('ERRORS (require attention)');
      report.push('───────────────────────────────────────────────────────────────');
      errors.forEach(issue => {
        report.push('❌ ' + issue.description);
      });
      report.push('');
    }

    if (warnings.length > 0) {
      report.push('WARNINGS (review recommended)');
      report.push('───────────────────────────────────────────────────────────────');
      warnings.forEach(issue => {
        report.push('⚠️ ' + issue.description);
      });
      report.push('');
    }

    report.push('───────────────────────────────────────────────────────────────');
    report.push('RECOMMENDED ACTIONS:');
    if (errors.length > 0) {
      report.push('• Run "Clients > Recalculate All Stats" to fix revenue mismatches');
    }
    if (warnings.some(w => w.type === 'DATE_ANOMALY')) {
      report.push('• Review date anomalies in Invoice Log manually');
    }
    if (warnings.some(w => w.type === 'INVOICE_NO_CLIENT')) {
      report.push('• Run "Clients > Sync Clients from Jobs" to create missing client records');
    }
  }

  const htmlOutput = HtmlService.createHtmlOutput(
    '<pre style="font-family: Consolas, monospace; font-size: 11px; padding: 10px; background: #f5f5f5; white-space: pre-wrap;">' +
    report.join('\n') +
    '</pre>'
  ).setWidth(700).setHeight(500);

  ui.showModalDialog(htmlOutput, '🔍 Reconciliation Check');
}

/**
 * Show dialog to generate GST summary
 */
function showGSTSummaryDialog() {
  const ui = SpreadsheetApp.getUi();

  // Check if GST registered
  const isGSTRegistered = getSetting('GST Registered') === 'Yes';
  if (!isGSTRegistered) {
    ui.alert('Not GST Registered',
      'GST Summary is not available because the business is not marked as GST Registered.\n\n' +
      'To enable: Go to Settings and set "GST Registered" to "Yes".',
      ui.ButtonSet.OK);
    return;
  }

  const now = new Date();
  const currentYear = now.getFullYear();

  const response = ui.prompt(
    '🧾 Generate GST Summary',
    'Enter period (Q1/Q2/Q3/Q4 YYYY or MM/YYYY for monthly):\n\n' +
    'Examples:\n' +
    '  Q1 ' + currentYear + ' (Jan-Mar)\n' +
    '  Q2 ' + currentYear + ' (Apr-Jun)\n' +
    '  01/' + currentYear + ' (January only)',
    ui.ButtonSet.OK_CANCEL
  );

  if (response.getSelectedButton() !== ui.Button.OK) return;

  const input = response.getResponseText().trim().toUpperCase();

  // Parse quarter format (Q1 2026)
  const quarterMatch = input.match(/^Q([1-4])\s*(\d{4})$/);
  if (quarterMatch) {
    const quarter = parseInt(quarterMatch[1]);
    const year = parseInt(quarterMatch[2]);
    generateGSTSummary('Q' + quarter, year);
    return;
  }

  // Parse month format (01/2026)
  const monthMatch = input.match(/^(\d{1,2})\/(\d{4})$/);
  if (monthMatch) {
    const month = parseInt(monthMatch[1]);
    const year = parseInt(monthMatch[2]);
    if (month < 1 || month > 12) {
      ui.alert('Invalid Month', 'Month must be between 1 and 12', ui.ButtonSet.OK);
      return;
    }
    generateGSTSummary(month, year);
    return;
  }

  ui.alert('Invalid Format', 'Please use Q1/Q2/Q3/Q4 YYYY or MM/YYYY format', ui.ButtonSet.OK);
}

/**
 * Generate GST summary for a period
 * @param {string|number} period - Quarter ('Q1'-'Q4') or month (1-12)
 * @param {number} year - Year
 */
function generateGSTSummary(period, year) {
  const ui = SpreadsheetApp.getUi();
  const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                      'July', 'August', 'September', 'October', 'November', 'December'];

  let startDate, endDate, periodLabel;

  if (typeof period === 'string' && period.startsWith('Q')) {
    // Quarterly
    const quarter = parseInt(period.substring(1));
    const startMonth = (quarter - 1) * 3;
    startDate = new Date(year, startMonth, 1);
    endDate = new Date(year, startMonth + 3, 0);
    periodLabel = period + ' ' + year + ' (' + monthNames[startMonth] + ' - ' + monthNames[startMonth + 2] + ')';
  } else {
    // Monthly
    const month = parseInt(period);
    startDate = new Date(year, month - 1, 1);
    endDate = new Date(year, month, 0);
    periodLabel = monthNames[month - 1] + ' ' + year;
  }

  // Get all paid invoices in period
  const invoices = getAllInvoicesRaw();

  let totalSales = 0;
  let totalGSTCollected = 0;
  let invoiceCount = 0;
  const invoiceDetails = [];

  invoices.forEach(inv => {
    if (inv['Status'] !== 'Paid') return;

    const paidDate = inv['Paid Date'] ? new Date(inv['Paid Date']) : null;
    if (!paidDate || paidDate < startDate || paidDate > endDate) return;

    const amount = parseFloat(inv['Amount (excl GST)']) || 0;
    const gst = parseFloat(inv['GST']) || 0;
    const total = parseFloat(inv['Total']) || 0;

    totalSales += amount;
    totalGSTCollected += gst;
    invoiceCount++;

    invoiceDetails.push({
      date: inv['Paid Date'],
      invoice: inv['Invoice #'],
      client: inv['Client Name'],
      amount: amount,
      gst: gst,
      total: total
    });
  });

  // Sort by date
  invoiceDetails.sort((a, b) => new Date(a.date) - new Date(b.date));

  // Build report
  const businessName = getSetting('Business Name') || 'CartCure';
  const gstNumber = getSetting('GST Number') || 'Not Set';

  let report = [
    '═══════════════════════════════════════════════════════════════',
    '  ' + businessName.toUpperCase() + ' - GST SUMMARY',
    '  Period: ' + periodLabel,
    '  GST Number: ' + gstNumber,
    '  Generated: ' + new Date().toLocaleString('en-NZ'),
    '═══════════════════════════════════════════════════════════════',
    '',
    '📊 GST SUMMARY',
    '───────────────────────────────────────────────────────────────',
    '  Total Sales (excl GST):   ' + formatCurrency(totalSales),
    '  GST Collected (15%):      ' + formatCurrency(totalGSTCollected),
    '  Total (incl GST):         ' + formatCurrency(totalSales + totalGSTCollected),
    '  Number of Invoices:       ' + invoiceCount,
    '',
    '📝 INVOICE DETAILS',
    '───────────────────────────────────────────────────────────────'
  ];

  if (invoiceDetails.length === 0) {
    report.push('  (No paid invoices in this period)');
  } else {
    report.push('  Date       | Invoice #      | Amount      | GST         | Total');
    report.push('  -----------|----------------|-------------|-------------|------------');
    invoiceDetails.forEach(inv => {
      report.push('  ' + (inv.date || '').substring(0, 10).padEnd(10) + ' | ' +
                  inv.invoice.padEnd(14) + ' | ' +
                  formatCurrency(inv.amount).padStart(11) + ' | ' +
                  formatCurrency(inv.gst).padStart(11) + ' | ' +
                  formatCurrency(inv.total).padStart(11));
    });
  }

  report.push('');
  report.push('═══════════════════════════════════════════════════════════════');
  report.push('');
  report.push('Note: This summary is for reference only. Please verify');
  report.push('against your accounting records before filing GST returns.');

  // Show report
  const htmlOutput = HtmlService.createHtmlOutput(
    '<pre style="font-family: Consolas, monospace; font-size: 11px; padding: 10px; background: #f5f5f5; white-space: pre-wrap;">' +
    report.join('\n') +
    '</pre>'
  ).setWidth(650).setHeight(550);

  ui.showModalDialog(htmlOutput, '🧾 GST Summary - ' + periodLabel);
}

/**
 * Get all invoices from Invoice Log sheet
 * @returns {Array<Object>} Array of invoice objects
 */
function getAllInvoicesRaw() {
  const sheet = getSheet(SHEETS.INVOICES);
  if (!sheet || sheet.getLastRow() < 2) return [];

  const data = sheet.getDataRange().getValues();
  const headers = data[0];

  return data.slice(1).map(row => {
    const obj = {};
    headers.forEach((header, i) => {
      obj[header] = row[i];
    });
    return obj;
  }).filter(inv => inv['Invoice #']); // Filter out empty rows
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
    // Clear all data validation before migration to prevent conflicts
    try {
      const fullRange = sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns());
      fullRange.clearDataValidations();
      Logger.log('Cleared data validations before migration');
    } catch (e) {
      Logger.log('Could not clear validations: ' + e.message);
    }

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
  sheet.setRowHeight(1, SHEET_FONTS.headerRowHeight);

  // Apply alternating row colors for existing data
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataArea = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataArea.setFontFamily(SHEET_FONTS.primary);
  dataArea.setFontSize(SHEET_FONTS.sizeMD);
  dataArea.setFontColor(SHEET_COLORS.inkBlack);
  dataArea.setVerticalAlignment('middle');
  applyLightBorders(dataArea);

  // Freeze header row
  sheet.setFrozenRows(1);
  sheet.setTabColor('#e65100');

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'SUBMISSIONS');

  // Apply wrap text from config (Message column)
  // Use dynamic row count instead of hardcoded 1000 for scalability
  const numRows = getDynamicRowCount(sheet);
  applyConfigWrapText(sheet, 'SUBMISSIONS', 2, numRows);

  // Clean up invalid Status values before applying validation
  // This handles cases where old Actions column data (☰) ended up in Status column
  const statusCol = getColIndex('SUBMISSIONS', 'Status');
  const validStatuses = ['New', 'In Review', 'Job Created', 'Declined', 'Spam'];
  const lastDataRow = sheet.getLastRow();
  if (lastDataRow > 1) {
    const statusRange = sheet.getRange(2, statusCol, lastDataRow - 1, 1);
    const statusValues = statusRange.getValues();
    let fixed = 0;
    for (let i = 0; i < statusValues.length; i++) {
      const val = statusValues[i][0];
      if (val && !validStatuses.includes(val)) {
        statusValues[i][0] = 'New';
        fixed++;
      }
    }
    if (fixed > 0) {
      statusRange.setValues(statusValues);
      Logger.log('Fixed ' + fixed + ' invalid Status values in Submissions');
    }
  }

  // Apply data validation from config (Status dropdown)
  applyConfigValidation(sheet, 'SUBMISSIONS', 2, numRows);

  // Apply conditional formatting from config (Status colors)
  applyConfigConditionalFormatting(sheet, 'SUBMISSIONS', 2, numRows);

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

  Logger.log('Submissions sheet setup completed successfully');
}

/**
 * Add conditional formatting for Submission Status column with brand colors
 */
function addSubmissionStatusFormatting(sheet) {
  const statusColumn = getColIndex('SUBMISSIONS', 'Status');
  const numRows = getDynamicRowCount(sheet);
  const range = sheet.getRange(2, statusColumn, numRows, 1);

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
  sheet.setRowHeight(1, SHEET_FONTS.headerRowHeight);

  // Apply alternating row colors for existing data
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataArea = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataArea.setFontFamily(SHEET_FONTS.primary);
  dataArea.setFontSize(SHEET_FONTS.sizeMD);
  dataArea.setFontColor(SHEET_COLORS.inkBlack);
  dataArea.setVerticalAlignment('middle');
  applyLightBorders(dataArea);

  // Freeze header row
  sheet.setFrozenRows(1);
  sheet.setTabColor('#2e7d32');

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
  const testimonialsNumRows = getDynamicRowCount(sheet);
  const approvedRange = sheet.getRange(2, 1, testimonialsNumRows, headers.length);

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

  Logger.log('Testimonials sheet setup completed successfully');
}

/**
 * Apply validation (checkbox and rating) to a specific testimonial row
 * Called when a new testimonial is added to ensure proper formatting
 * @param {Sheet} sheet - The Testimonials sheet
 * @param {number} row - The row number to apply validation to
 */
function applyTestimonialRowValidation(sheet, row) {
  // Get column indices from config for maintainability
  const showOnWebsiteCol = getColIndex('TESTIMONIALS', 'Show on Website');
  const ratingCol = getColIndex('TESTIMONIALS', 'Rating');
  const testimonialCol = getColIndex('TESTIMONIALS', 'Testimonial');

  // Add checkbox for "Show on Website" column
  // Using insertCheckboxes() which is the proper way to create a checkbox
  const checkboxCell = sheet.getRange(row, showOnWebsiteCol);
  checkboxCell.insertCheckboxes();

  // Add rating validation (1-5)
  const ratingRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(['1', '2', '3', '4', '5'], true)
    .setAllowInvalid(false)
    .build();
  sheet.getRange(row, ratingCol).setDataValidation(ratingRule);

  // Enable wrap text for testimonial column
  sheet.getRange(row, testimonialCol).setWrap(true);
}

/**
 * Clean up the Testimonials sheet by removing pre-populated checkboxes/validation from empty rows
 * Run this once via: CartCure Menu > Setup > Clean Up Testimonials Sheet
 * This fixes the issue where appendRow() was adding data at the bottom due to pre-populated checkboxes
 */
function repairTestimonialsValidation() {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(SHEETS.TESTIMONIALS);

  if (!sheet) {
    SpreadsheetApp.getUi().alert('Testimonials sheet not found.');
    return;
  }

  // Find the actual last row with data by checking Submitted timestamp column
  const submittedColLetter = getColLetter('TESTIMONIALS', 'Submitted');
  const submittedCol = sheet.getRange(submittedColLetter + ':' + submittedColLetter).getValues();
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

// ============================================================================
// DATA ARCHIVAL FUNCTIONS
// ============================================================================
// These functions help manage data growth by moving old completed/cancelled
// jobs and old activity log entries to separate archive sheets.

/**
 * Setup or get the Jobs Archive sheet with same structure as Jobs
 * @param {Spreadsheet} ss - The spreadsheet
 * @returns {Sheet} The archive sheet
 */
function setupJobsArchiveSheet(ss) {
  if (!ss) {
    ss = getSpreadsheet();
  }

  let sheet = ss.getSheetByName('Jobs Archive');

  if (!sheet) {
    sheet = ss.insertSheet('Jobs Archive');

    // Copy headers from COLUMN_CONFIG
    const headers = getColHeaders('JOBS');
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);

    // Apply same styling as Jobs sheet
    applyPaperBackground(sheet);
    const headerRange = sheet.getRange(1, 1, 1, headers.length);
    applyHeaderStyle(headerRange);
    sheet.setFrozenRows(1);
    applyConfigColumnWidths(sheet, 'JOBS');

    Logger.log('Created Jobs Archive sheet');
  }

  return sheet;
}

/**
 * Setup or get the Activity Log Archive sheet
 * @param {Spreadsheet} ss - The spreadsheet
 * @returns {Sheet} The archive sheet
 */
function setupActivityLogArchiveSheet(ss) {
  if (!ss) {
    ss = getSpreadsheet();
  }

  let sheet = ss.getSheetByName('Activity Log Archive');

  if (!sheet) {
    sheet = ss.insertSheet('Activity Log Archive');

    // Copy headers from COLUMN_CONFIG
    const headers = getColHeaders('ACTIVITY_LOG');
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);

    // Apply same styling
    applyPaperBackground(sheet);
    const headerRange = sheet.getRange(1, 1, 1, headers.length);
    applyHeaderStyle(headerRange);
    sheet.setFrozenRows(1);
    applyConfigColumnWidths(sheet, 'ACTIVITY_LOG');

    Logger.log('Created Activity Log Archive sheet');
  }

  return sheet;
}

/**
 * Archive completed/cancelled jobs older than threshold
 * Called from menu: CartCure > Setup > Maintenance > Archive Old Jobs
 */
function archiveOldJobs() {
  const ui = SpreadsheetApp.getUi();
  const ss = getSpreadsheet();

  // Get threshold from settings
  const daysThreshold = parseInt(getSetting('Archive Jobs After Days')) || 90;
  if (daysThreshold <= 0) {
    ui.alert('Archiving Disabled', 'Archive threshold is set to 0. Change "Archive Jobs After Days" in Settings to enable.', ui.ButtonSet.OK);
    return;
  }

  const jobsSheet = getSheet(SHEETS.JOBS);
  if (!jobsSheet) {
    ui.alert('Error', 'Jobs sheet not found.', ui.ButtonSet.OK);
    return;
  }

  const jobsData = jobsSheet.getDataRange().getValues();
  if (jobsData.length <= 1) {
    ui.alert('No Jobs', 'No jobs found to archive.', ui.ButtonSet.OK);
    return;
  }

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const statusCol = getColIndex('JOBS', 'Status') - 1;
  const completedDateCol = getColIndex('JOBS', 'Actual Completion Date') - 1;
  const createdDateCol = getColIndex('JOBS', 'Created Date') - 1;

  if (statusCol === -1) {
    ui.alert('Error', 'Status column not found in Jobs sheet.', ui.ButtonSet.OK);
    return;
  }

  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - daysThreshold);

  const archivableStatuses = [JOB_STATUS.COMPLETED, JOB_STATUS.CANCELLED, JOB_STATUS.DECLINED];
  const rowsToArchive = [];

  // Find rows to archive (iterate from bottom to avoid index shifting issues when deleting)
  for (let i = jobsData.length - 1; i >= 1; i--) {
    const status = jobsData[i][statusCol];
    if (!archivableStatuses.includes(status)) continue;

    // Check date - prefer Completed Date, fall back to Created Date
    const dateValue = jobsData[i][completedDateCol] || jobsData[i][createdDateCol];
    if (!dateValue) continue;

    const rowDate = new Date(dateValue);
    if (isNaN(rowDate.getTime())) continue; // Skip invalid dates

    if (rowDate < cutoffDate) {
      rowsToArchive.push({
        rowIndex: i + 1, // 1-indexed for sheet operations
        data: jobsData[i]
      });
    }
  }

  if (rowsToArchive.length === 0) {
    ui.alert('No Jobs to Archive', 'No completed/cancelled jobs found older than ' + daysThreshold + ' days.', ui.ButtonSet.OK);
    return;
  }

  // Confirm with user
  const response = ui.alert(
    'Archive ' + rowsToArchive.length + ' Jobs?',
    'This will move ' + rowsToArchive.length + ' completed/cancelled/declined jobs older than ' + daysThreshold + ' days to the Jobs Archive sheet.\n\nThis action cannot be undone.',
    ui.ButtonSet.YES_NO
  );

  if (response !== ui.Button.YES) return;

  // Setup archive sheet
  const archiveSheet = setupJobsArchiveSheet(ss);

  // Archive rows (already sorted bottom-to-top for safe deletion)
  let archivedCount = 0;
  for (const row of rowsToArchive) {
    // Add to archive at top (row 2)
    insertAtTopSafe(archiveSheet, row.data, false);
    // Delete from Jobs
    jobsSheet.deleteRow(row.rowIndex);
    archivedCount++;
  }

  // Clear cache since we modified sheets
  _cache.sheets = {};

  ui.alert('Archive Complete', 'Archived ' + archivedCount + ' jobs to Jobs Archive sheet.', ui.ButtonSet.OK);
  Logger.log('Archived ' + archivedCount + ' jobs');
}

/**
 * Archive old activity log entries
 * Called from menu: CartCure > Setup > Maintenance > Archive Old Activity
 */
function archiveOldActivity() {
  const ui = SpreadsheetApp.getUi();
  const ss = getSpreadsheet();

  const daysThreshold = parseInt(getSetting('Archive Activity After Days')) || 365;
  if (daysThreshold <= 0) {
    ui.alert('Archiving Disabled', 'Activity archive threshold is set to 0. Change "Archive Activity After Days" in Settings to enable.', ui.ButtonSet.OK);
    return;
  }

  const activitySheet = getSheet(SHEETS.ACTIVITY_LOG);
  if (!activitySheet) {
    ui.alert('Error', 'Activity Log sheet not found.', ui.ButtonSet.OK);
    return;
  }

  const data = activitySheet.getDataRange().getValues();
  if (data.length <= 1) {
    ui.alert('No Activity', 'No activity entries found to archive.', ui.ButtonSet.OK);
    return;
  }

  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const timestampCol = getColIndex('ACTIVITY_LOG', 'Timestamp') - 1;

  if (timestampCol === -1) {
    ui.alert('Error', 'Timestamp column not found in Activity Log sheet.', ui.ButtonSet.OK);
    return;
  }

  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - daysThreshold);

  const rowsToArchive = [];

  // Find rows to archive (iterate from bottom to avoid index shifting)
  for (let i = data.length - 1; i >= 1; i--) {
    const timestamp = data[i][timestampCol];
    if (!timestamp) continue;

    const rowDate = new Date(timestamp);
    if (isNaN(rowDate.getTime())) continue; // Skip invalid dates

    if (rowDate < cutoffDate) {
      rowsToArchive.push({
        rowIndex: i + 1,
        data: data[i]
      });
    }
  }

  if (rowsToArchive.length === 0) {
    ui.alert('No Activity to Archive', 'No activity entries older than ' + daysThreshold + ' days.', ui.ButtonSet.OK);
    return;
  }

  const response = ui.alert(
    'Archive ' + rowsToArchive.length + ' Entries?',
    'Move ' + rowsToArchive.length + ' activity entries older than ' + daysThreshold + ' days to archive?\n\nThis action cannot be undone.',
    ui.ButtonSet.YES_NO
  );

  if (response !== ui.Button.YES) return;

  // Setup archive sheet
  const archiveSheet = setupActivityLogArchiveSheet(ss);

  let archivedCount = 0;
  for (const row of rowsToArchive) {
    insertAtTopSafe(archiveSheet, row.data, false);
    activitySheet.deleteRow(row.rowIndex);
    archivedCount++;
  }

  // Clear cache
  _cache.sheets = {};

  ui.alert('Archive Complete', 'Archived ' + archivedCount + ' activity entries to Activity Log Archive sheet.', ui.ButtonSet.OK);
  Logger.log('Archived ' + archivedCount + ' activity entries');
}

/**
 * Manually extend validation/formatting ranges for all sheets
 * Useful when sheets have grown significantly and need more dropdown rows
 * Called from menu: CartCure > Setup > Maintenance > Extend Validation Ranges
 */
function repairValidationRanges() {
  const ui = SpreadsheetApp.getUi();

  const sheets = [
    { sheet: getSheet(SHEETS.JOBS), key: 'JOBS', name: 'Jobs' },
    { sheet: getSheet(SHEETS.INVOICES), key: 'INVOICES', name: 'Invoices' },
    { sheet: getSheet(SHEETS.SUBMISSIONS), key: 'SUBMISSIONS', name: 'Submissions' }
  ];

  let updatedCount = 0;

  for (const s of sheets) {
    if (!s.sheet) continue;
    const numRows = getDynamicRowCount(s.sheet);

    // Apply validation
    applyConfigValidation(s.sheet, s.key, 2, numRows);
    applyConfigConditionalFormatting(s.sheet, s.key, 2, numRows);

    Logger.log('Extended validation for ' + s.name + ' to ' + numRows + ' rows');
    updatedCount++;
  }

  ui.alert('Validation Extended',
    'Validation and formatting ranges have been extended for ' + updatedCount + ' sheets.\n\n' +
    'Dropdown menus should now work for all existing and new rows.',
    ui.ButtonSet.OK);
}

/**
 * Show statistics about active and archived data
 * Called from menu: CartCure > Setup > Maintenance > View Archive Stats
 */
function showArchiveStats() {
  const ui = SpreadsheetApp.getUi();
  const ss = getSpreadsheet();

  // Get active sheet counts
  const jobsSheet = getSheet(SHEETS.JOBS);
  const submissionsSheet = getSheet(SHEETS.SUBMISSIONS);
  const invoicesSheet = getSheet(SHEETS.INVOICES);
  const activitySheet = getSheet(SHEETS.ACTIVITY_LOG);

  const activeJobs = jobsSheet ? Math.max(0, jobsSheet.getLastRow() - 1) : 0;
  const activeSubmissions = submissionsSheet ? Math.max(0, submissionsSheet.getLastRow() - 1) : 0;
  const activeInvoices = invoicesSheet ? Math.max(0, invoicesSheet.getLastRow() - 1) : 0;
  const activeActivity = activitySheet ? Math.max(0, activitySheet.getLastRow() - 1) : 0;

  // Get archive sheet counts
  const jobsArchive = ss.getSheetByName('Jobs Archive');
  const activityArchive = ss.getSheetByName('Activity Log Archive');

  const archivedJobs = jobsArchive ? Math.max(0, jobsArchive.getLastRow() - 1) : 0;
  const archivedActivity = activityArchive ? Math.max(0, activityArchive.getLastRow() - 1) : 0;

  // Get archive settings
  const jobsArchiveDays = getSetting('Archive Jobs After Days') || '90';
  const activityArchiveDays = getSetting('Archive Activity After Days') || '365';

  ui.alert('Data Statistics',
    '=== Active Data ===\n' +
    'Jobs: ' + activeJobs + '\n' +
    'Submissions: ' + activeSubmissions + '\n' +
    'Invoices: ' + activeInvoices + '\n' +
    'Activity Log Entries: ' + activeActivity + '\n\n' +
    '=== Archived Data ===\n' +
    'Jobs: ' + archivedJobs + '\n' +
    'Activity Log: ' + archivedActivity + '\n\n' +
    '=== Archive Settings ===\n' +
    'Archive jobs after: ' + jobsArchiveDays + ' days\n' +
    'Archive activity after: ' + activityArchiveDays + ' days',
    ui.ButtonSet.OK
  );
}

/**
 * Setup the Activity Log sheet for tracking all job-related activities
 * This sheet stores emails sent, status changes, and other audit trail items
 */
function setupActivityLogSheet(ss, clearData) {
  if (!ss) {
    ss = getSpreadsheet();
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
  sheet.setRowHeight(1, SHEET_FONTS.headerRowHeight);

  // Apply alternating row colors for existing data
  const lastRow = Math.max(sheet.getLastRow(), 50);
  applyAlternatingRows(sheet, 2, lastRow - 1, headers.length);

  // Set default text styling for data area
  const dataArea = sheet.getRange(2, 1, lastRow - 1, headers.length);
  dataArea.setFontFamily(SHEET_FONTS.primary);
  dataArea.setFontSize(SHEET_FONTS.sizeMD);
  dataArea.setFontColor(SHEET_COLORS.inkBlack);
  dataArea.setVerticalAlignment('middle');
  applyLightBorders(dataArea);

  // Freeze header row
  sheet.setFrozenRows(1);
  sheet.setTabColor(SHEET_COLORS.inkGray);

  // Set column widths from config
  applyConfigColumnWidths(sheet, 'ACTIVITY_LOG');

  // Apply wrap text from config (Details column)
  // Use dynamic row count instead of hardcoded 1000 for scalability
  const numRows = getDynamicRowCount(sheet);
  applyConfigWrapText(sheet, 'ACTIVITY_LOG', 2, numRows);

  // Enable filtering for all columns
  try {
    const filterRange = sheet.getRange(1, 1, Math.max(sheet.getLastRow(), 2), headers.length);
    if (!sheet.getFilter()) {
      filterRange.createFilter();
    }
  } catch (e) {
    Logger.log('Filter already exists or could not be created: ' + e.message);
  }

  // Add refresh checkbox for manual email scan (column H+1)
  const extraCol = headers.length + 1; // Column after main headers
  const refreshLabelCell = sheet.getRange(1, extraCol);
  refreshLabelCell.setValue('Scan Emails →');
  refreshLabelCell.setFontWeight('bold');
  refreshLabelCell.setFontSize(SHEET_FONTS.sizeSM);
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
 * P2 FIX: Now captures actual user email for audit trail when loggedBy is "Manual"
 *
 * @param {string} jobNumber - The job number (e.g., "J-001")
 * @param {string} activityType - Type of activity (e.g., "Email Sent", "Status Change")
 * @param {string} summary - Brief description or email subject
 * @param {string} details - Full details (optional)
 * @param {string} fromTo - Email addresses or parties involved (optional)
 * @param {string} loggedBy - "Auto", "Manual", or specific identifier (defaults to "Auto")
 */
function logJobActivity(jobNumber, activityType, summary, details, fromTo, loggedBy) {
  try {
    // PERFORMANCE: Use cached sheet reference
    let sheet = getSheet(SHEETS.ACTIVITY_LOG);

    // Create sheet if it doesn't exist
    if (!sheet) {
      setupActivityLogSheet(getSpreadsheet(), false);
      sheet = getSheet(SHEETS.ACTIVITY_LOG);
    }

    const timestamp = new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' });

    // P2 FIX: Capture actual user identity for audit trail
    let actualLoggedBy = loggedBy || 'Auto';
    if (loggedBy === 'Manual' || !loggedBy) {
      try {
        const userEmail = Session.getActiveUser().getEmail();
        if (userEmail) {
          actualLoggedBy = userEmail;
        }
      } catch (e) {
        // Session.getActiveUser() may not work in some trigger contexts
        // Fall back to provided value or 'Auto'
        actualLoggedBy = loggedBy || 'Auto';
      }
    }

    const rowData = [
      timestamp,
      jobNumber || '',
      activityType || '',
      summary || '',
      details || '',
      fromTo || '',
      actualLoggedBy
    ];

    // Insert at top (row 2) so newest activity appears first
    insertAtTopSafe(sheet, rowData, false); // false = no toast (secondary operation)

    Logger.log('Activity logged for job ' + jobNumber + ': ' + activityType + ' by ' + actualLoggedBy);
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
    const ss = getSpreadsheet();
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
  const ss = getSpreadsheet();
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
 * Show dialog to view activity log for a job
 * Auto-detects job number from selected row, or shows dropdown with all jobs
 */
function viewJobActivityLog() {
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([]); // Get all jobs
  showContextAwareDialog(
    'View Activity Log',
    jobs,
    'Job',
    'displayActivityLogForJob',
    selectedJob
  );
}

/**
 * Display the activity log for a specific job in a formatted HTML dialog
 * Called by showContextAwareDialog callback
 */
function displayActivityLogForJob(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const ss = getSpreadsheet();
  const activitySheet = ss.getSheetByName(SHEETS.ACTIVITY_LOG);

  if (!activitySheet || activitySheet.getLastRow() <= 1) {
    ui.alert('No Activity Found', 'No activity log entries exist yet.', ui.ButtonSet.OK);
    return;
  }

  // Find all activities for this job
  const data = activitySheet.getDataRange().getValues();
  // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
  const jobNumColIndex = getColIndex('ACTIVITY_LOG', 'Job #') - 1;
  const timestampColIndex = getColIndex('ACTIVITY_LOG', 'Timestamp') - 1;
  const typeColIndex = getColIndex('ACTIVITY_LOG', 'Activity Type') - 1;
  const summaryColIndex = getColIndex('ACTIVITY_LOG', 'Subject/Summary') - 1;
  const detailsColIndex = getColIndex('ACTIVITY_LOG', 'Details') - 1;
  const fromToColIndex = getColIndex('ACTIVITY_LOG', 'From/To') - 1;
  const loggedByColIndex = getColIndex('ACTIVITY_LOG', 'Logged By') - 1;
  const activities = [];

  for (let i = 1; i < data.length; i++) {
    if (String(data[i][jobNumColIndex]).trim().toUpperCase() === jobNumber.toUpperCase()) {
      activities.push({
        timestamp: timestampColIndex >= 0 ? data[i][timestampColIndex] : '',
        type: typeColIndex >= 0 ? data[i][typeColIndex] : '',
        summary: summaryColIndex >= 0 ? data[i][summaryColIndex] : '',
        details: detailsColIndex >= 0 ? data[i][detailsColIndex] : '',
        fromTo: fromToColIndex >= 0 ? data[i][fromToColIndex] : '',
        loggedBy: loggedByColIndex >= 0 ? data[i][loggedByColIndex] : ''
      });
    }
  }

  if (activities.length === 0) {
    ui.alert('No Activity Found', 'No activity log entries found for ' + jobNumber + '.', ui.ButtonSet.OK);
    return;
  }

  // Sort by timestamp descending (newest first)
  activities.sort((a, b) => {
    const dateA = a.timestamp instanceof Date ? a.timestamp : new Date(a.timestamp);
    const dateB = b.timestamp instanceof Date ? b.timestamp : new Date(b.timestamp);
    return dateB - dateA;
  });

  // Build HTML for each activity
  let activitiesHtml = '';
  activities.forEach((activity, index) => {
    const timestamp = activity.timestamp instanceof Date
      ? formatNZDateTime(activity.timestamp)
      : activity.timestamp;

    // Determine icon and color based on activity type
    let icon = '📝';
    let color = '#666';
    const type = (activity.type || '').toLowerCase();
    if (type.includes('email')) {
      icon = '📧';
      color = '#1a73e8';
    } else if (type.includes('status')) {
      icon = '🔄';
      color = '#ea8600';
    } else if (type.includes('payment') || type.includes('invoice')) {
      icon = '💰';
      color = '#34a853';
    } else if (type.includes('note')) {
      icon = '📝';
      color = '#9334e6';
    } else if (type.includes('quote')) {
      icon = '📋';
      color = '#ff6d01';
    }

    const details = activity.details ? '<div class="details">' + formatActivityDetails(activity.details) + '</div>' : '';
    const fromTo = activity.fromTo ? '<div class="from-to">' + escapeHtml(activity.fromTo) + '</div>' : '';
    const loggedBy = activity.loggedBy ? '<span class="logged-by">by ' + escapeHtml(activity.loggedBy) + '</span>' : '';

    activitiesHtml += `
      <div class="activity-item">
        <div class="activity-header">
          <span class="activity-icon">${icon}</span>
          <span class="activity-type" style="color: ${color};">${escapeHtml(activity.type || 'Activity')}</span>
          <span class="activity-time">${escapeHtml(timestamp)} ${loggedBy}</span>
        </div>
        <div class="activity-summary">${escapeHtml(activity.summary || '')}</div>
        ${fromTo}
        ${details}
      </div>
    `;
  });

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
            background: linear-gradient(135deg, #1a73e8 0%, #174ea6 100%);
            color: white;
            padding: 20px;
            margin: -20px -20px 20px -20px;
            border-radius: 0;
          }
          .header h2 {
            margin: 0 0 5px 0;
            font-size: 20px;
            font-weight: 500;
          }
          .header .count {
            opacity: 0.9;
            font-size: 14px;
          }
          .activity-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
          }
          .activity-item {
            background: white;
            border-radius: 8px;
            padding: 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid #1a73e8;
          }
          .activity-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
            flex-wrap: wrap;
          }
          .activity-icon {
            font-size: 16px;
          }
          .activity-type {
            font-weight: 600;
            font-size: 14px;
          }
          .activity-time {
            color: #5f6368;
            font-size: 12px;
            margin-left: auto;
          }
          .logged-by {
            color: #80868b;
            font-style: italic;
          }
          .activity-summary {
            color: #202124;
            font-size: 14px;
            line-height: 1.5;
          }
          .from-to {
            color: #5f6368;
            font-size: 13px;
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid #e8eaed;
          }
          .details {
            color: #5f6368;
            font-size: 12px;
            margin-top: 8px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
            white-space: pre-wrap;
            word-break: break-word;
          }
          .button-row-top {
            margin-bottom: 15px;
          }
          .button-row-bottom {
            margin-top: 20px;
            text-align: center;
          }
          .btn-add-note {
            width: 100%;
            padding: 12px;
            background: #34a853;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 500;
          }
          .btn-add-note:hover {
            background: #2d8a47;
          }
          .btn-close {
            padding: 10px 40px;
            background: #5f6368;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 500;
          }
          .btn-close:hover {
            background: #4a4e51;
          }
          .note-input-area {
            display: none;
            margin-top: 15px;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          }
          .note-input-area.show {
            display: block;
          }
          .note-textarea {
            width: 100%;
            height: 80px;
            padding: 10px;
            border: 1px solid #dadce0;
            border-radius: 4px;
            resize: vertical;
            font-family: inherit;
            font-size: 14px;
          }
          .note-textarea:focus {
            outline: none;
            border-color: #1a73e8;
          }
          .note-buttons {
            margin-top: 10px;
            display: flex;
            gap: 10px;
            justify-content: flex-end;
          }
          .btn-cancel {
            padding: 8px 16px;
            background: #f1f3f4;
            color: #5f6368;
            border: 1px solid #dadce0;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
          }
          .btn-cancel:hover {
            background: #e8eaed;
          }
          .btn-save {
            padding: 8px 16px;
            background: #34a853;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
          }
          .btn-save:hover {
            background: #2d8a47;
          }
          .btn-save:disabled {
            background: #a8dab5;
            cursor: not-allowed;
          }
          .empty-state {
            text-align: center;
            padding: 40px;
            color: #5f6368;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2>📜 Activity Log</h2>
            <div class="count">${jobNumber} • ${activities.length} ${activities.length === 1 ? 'entry' : 'entries'}</div>
          </div>
          <div class="button-row-top">
            <button class="btn-add-note" onclick="showNoteInput()">📝 Add Note</button>
          </div>
          <div id="noteInputArea" class="note-input-area">
            <textarea id="noteText" class="note-textarea" placeholder="Enter your note here..."></textarea>
            <div class="note-buttons">
              <button class="btn-cancel" onclick="hideNoteInput()">Cancel</button>
              <button id="saveBtn" class="btn-save" onclick="saveNote()">Save Note</button>
            </div>
          </div>
          <div id="activityList" class="activity-list">
            ${activitiesHtml}
          </div>
          <div class="button-row-bottom">
            <button class="btn-close" onclick="google.script.host.close()">Close</button>
          </div>
        </div>
        <script>
          const jobNumber = '${escapeHtml(jobNumber)}';

          function showNoteInput() {
            document.getElementById('noteInputArea').classList.add('show');
            document.getElementById('noteText').focus();
          }

          function hideNoteInput() {
            document.getElementById('noteInputArea').classList.remove('show');
            document.getElementById('noteText').value = '';
          }

          function saveNote() {
            const noteText = document.getElementById('noteText').value.trim();

            if (!noteText) {
              alert('Please enter a note.');
              return;
            }

            // Disable button while saving
            const saveBtn = document.getElementById('saveBtn');
            saveBtn.disabled = true;
            saveBtn.textContent = 'Saving...';

            google.script.run
              .withSuccessHandler(function(result) {
                if (result && result.success) {
                  // Refresh the dialog to show the new note
                  google.script.run
                    .withSuccessHandler(function(newHtml) {
                      if (newHtml) {
                        document.getElementById('activityList').innerHTML = newHtml;
                        // Update count in header
                        const countEl = document.querySelector('.count');
                        if (countEl && result.newCount) {
                          countEl.textContent = jobNumber + ' • ' + result.newCount + (result.newCount === 1 ? ' entry' : ' entries');
                        }
                      }
                      hideNoteInput();
                      saveBtn.disabled = false;
                      saveBtn.textContent = 'Save Note';
                    })
                    .withFailureHandler(function() {
                      // Even if refresh fails, note was saved - just close and reopen
                      alert('Note saved! Please reopen the Activity Log to see it.');
                      google.script.host.close();
                    })
                    .getActivityListHtml(jobNumber);
                } else {
                  alert('Error saving note: ' + (result ? result.error : 'Unknown error'));
                  saveBtn.disabled = false;
                  saveBtn.textContent = 'Save Note';
                }
              })
              .withFailureHandler(function(error) {
                alert('Error: ' + error.message);
                saveBtn.disabled = false;
                saveBtn.textContent = 'Save Note';
              })
              .addActivityNoteFromDialog(jobNumber, noteText);
          }
        </script>
      </body>
    </html>
  `;

  const htmlOutput = HtmlService.createHtmlOutput(htmlContent)
    .setWidth(500)
    .setHeight(550);

  ui.showModalDialog(htmlOutput, 'Activity Log - ' + jobNumber);
}

/**
 * Add an activity note from the Activity Log dialog
 * Called via google.script.run from the dialog
 * @param {string} jobNumber - The job number
 * @param {string} noteText - The note content
 * @returns {Object} Result object with success boolean and newCount
 */
function addActivityNoteFromDialog(jobNumber, noteText) {
  try {
    if (!jobNumber || !noteText) {
      return { success: false, error: 'Job number and note text are required' };
    }

    // Use existing logJobActivity function
    const result = logJobActivity(jobNumber, 'Manual Note', noteText, '', '', 'Manual');

    if (result) {
      // Get the new count of activities
      const ss = getSpreadsheet();
      const activitySheet = ss.getSheetByName(SHEETS.ACTIVITY_LOG);
      let newCount = 0;

      if (activitySheet && activitySheet.getLastRow() > 1) {
        const data = activitySheet.getDataRange().getValues();
        const jobNumColIndex = getColIndex('ACTIVITY_LOG', 'Job #') - 1;

        for (let i = 1; i < data.length; i++) {
          if (String(data[i][jobNumColIndex]).trim().toUpperCase() === jobNumber.toUpperCase()) {
            newCount++;
          }
        }
      }

      return { success: true, newCount: newCount };
    } else {
      return { success: false, error: 'Failed to log activity' };
    }
  } catch (error) {
    Logger.log('Error adding note from dialog: ' + error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Get the activity list HTML for refreshing the dialog
 * Called via google.script.run from the Activity Log dialog
 * @param {string} jobNumber - The job number
 * @returns {string} HTML content for the activity list
 */
function getActivityListHtml(jobNumber) {
  try {
    const ss = getSpreadsheet();
    const activitySheet = ss.getSheetByName(SHEETS.ACTIVITY_LOG);

    if (!activitySheet || activitySheet.getLastRow() <= 1) {
      return '<div class="empty-state">No activities found.</div>';
    }

    // Find all activities for this job
    const data = activitySheet.getDataRange().getValues();
    const jobNumColIndex = getColIndex('ACTIVITY_LOG', 'Job #') - 1;
    const timestampColIndex = getColIndex('ACTIVITY_LOG', 'Timestamp') - 1;
    const typeColIndex = getColIndex('ACTIVITY_LOG', 'Activity Type') - 1;
    const summaryColIndex = getColIndex('ACTIVITY_LOG', 'Subject/Summary') - 1;
    const detailsColIndex = getColIndex('ACTIVITY_LOG', 'Details') - 1;
    const fromToColIndex = getColIndex('ACTIVITY_LOG', 'From/To') - 1;
    const loggedByColIndex = getColIndex('ACTIVITY_LOG', 'Logged By') - 1;
    const activities = [];

    for (let i = 1; i < data.length; i++) {
      if (String(data[i][jobNumColIndex]).trim().toUpperCase() === jobNumber.toUpperCase()) {
        activities.push({
          timestamp: timestampColIndex >= 0 ? data[i][timestampColIndex] : '',
          type: typeColIndex >= 0 ? data[i][typeColIndex] : '',
          summary: summaryColIndex >= 0 ? data[i][summaryColIndex] : '',
          details: detailsColIndex >= 0 ? data[i][detailsColIndex] : '',
          fromTo: fromToColIndex >= 0 ? data[i][fromToColIndex] : '',
          loggedBy: loggedByColIndex >= 0 ? data[i][loggedByColIndex] : ''
        });
      }
    }

    if (activities.length === 0) {
      return '<div class="empty-state">No activities found for this job.</div>';
    }

    // Sort by timestamp descending (newest first)
    activities.sort((a, b) => {
      const dateA = a.timestamp instanceof Date ? a.timestamp : new Date(a.timestamp);
      const dateB = b.timestamp instanceof Date ? b.timestamp : new Date(b.timestamp);
      return dateB - dateA;
    });

    // Build HTML for each activity
    let activitiesHtml = '';
    activities.forEach((activity) => {
      const timestamp = activity.timestamp instanceof Date
        ? formatNZDateTime(activity.timestamp)
        : activity.timestamp;

      // Determine icon and color based on activity type
      let icon = '📝';
      let color = '#666';
      const type = (activity.type || '').toLowerCase();
      if (type.includes('email')) {
        icon = '📧';
        color = '#1a73e8';
      } else if (type.includes('status')) {
        icon = '🔄';
        color = '#ea8600';
      } else if (type.includes('payment') || type.includes('invoice')) {
        icon = '💰';
        color = '#34a853';
      } else if (type.includes('note')) {
        icon = '📝';
        color = '#9334e6';
      } else if (type.includes('quote')) {
        icon = '📋';
        color = '#ff6d01';
      }

      const details = activity.details ? '<div class="details">' + formatActivityDetails(activity.details) + '</div>' : '';
      const fromTo = activity.fromTo ? '<div class="from-to">' + escapeHtml(activity.fromTo) + '</div>' : '';
      const loggedBy = activity.loggedBy ? '<span class="logged-by">by ' + escapeHtml(activity.loggedBy) + '</span>' : '';

      activitiesHtml += `
        <div class="activity-item">
          <div class="activity-header">
            <span class="activity-icon">${icon}</span>
            <span class="activity-type" style="color: ${color};">${escapeHtml(activity.type || 'Activity')}</span>
            <span class="activity-time">${escapeHtml(timestamp)} ${loggedBy}</span>
          </div>
          <div class="activity-summary">${escapeHtml(activity.summary || '')}</div>
          ${fromTo}
          ${details}
        </div>
      `;
    });

    return activitiesHtml;
  } catch (error) {
    Logger.log('Error getting activity list HTML: ' + error.message);
    return '<div class="empty-state">Error loading activities.</div>';
  }
}

/**
 * Format date/time for NZ timezone display
 */
function formatNZDateTime(date) {
  if (!date) return '';
  if (!(date instanceof Date)) {
    date = new Date(date);
  }
  if (isNaN(date.getTime())) return '';

  const options = {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
    timeZone: 'Pacific/Auckland'
  };

  return date.toLocaleString('en-NZ', options);
}

/**
 * Show dialog to add an activity note for a job
 * Auto-detects job number from selected row, or shows dropdown with all jobs
 */
function addManualActivityNote() {
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([]); // Get all jobs
  showContextAwareDialog(
    'Add Activity Note',
    jobs,
    'Job',
    'promptForActivityNote',
    selectedJob
  );
}

/**
 * Prompt for activity note text after job is selected
 * Called by showContextAwareDialog callback
 */
function promptForActivityNote(jobNumber) {
  const ui = SpreadsheetApp.getUi();

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

/**
 * Show dialog to request a testimonial from a completed job's client
 * Auto-detects job number from selected row, or shows dropdown with completed jobs
 */
function showRequestTestimonialDialog() {
  const selectedJob = getSelectedJobNumber();
  const jobs = getJobsByStatus([JOB_STATUS.COMPLETED]);
  showContextAwareDialog(
    'Request Testimonial',
    jobs,
    'Job',
    'sendTestimonialRequest',
    selectedJob
  );
}

/**
 * Send testimonial request email to client
 * Called by showContextAwareDialog callback
 * @param {string} jobNumber - The job number to request testimonial for
 */
function sendTestimonialRequest(jobNumber) {
  const ui = SpreadsheetApp.getUi();
  const job = getJobByNumber(jobNumber);

  if (!job) {
    ui.alert('Not Found', 'Job ' + jobNumber + ' not found.', ui.ButtonSet.OK);
    return;
  }

  const status = job['Status'];
  if (status !== JOB_STATUS.COMPLETED) {
    ui.alert('Invalid Status',
      'Testimonial requests can only be sent for completed jobs.\n\n' +
      'Current status: ' + status,
      ui.ButtonSet.OK);
    return;
  }

  const clientName = job['Client Name'];
  const clientEmail = job['Client Email'];

  if (!clientEmail) {
    ui.alert('Error', 'No email address found for this job.', ui.ButtonSet.OK);
    return;
  }

  // Check if testimonial already exists
  const ss = getSpreadsheet();
  const testimonialsSheet = ss.getSheetByName(SHEETS.TESTIMONIALS);
  if (testimonialsSheet && testimonialsSheet.getLastRow() > 1) {
    const testimonialData = testimonialsSheet.getDataRange().getValues();
    // Use COLUMN_CONFIG as source of truth (getColIndex returns 1-based, subtract 1 for array indexing)
    const jobColIndex = getColIndex('TESTIMONIALS', 'Job Number') - 1;
    if (jobColIndex >= 0) {
      const alreadySubmitted = testimonialData.slice(1).some(row =>
        row[jobColIndex] && row[jobColIndex].toString().trim() === jobNumber.trim()
      );
      if (alreadySubmitted) {
        const response = ui.alert(
          'Testimonial Already Exists',
          'A testimonial has already been submitted for this job.\n\nSend request anyway?',
          ui.ButtonSet.YES_NO
        );
        if (response !== ui.Button.YES) {
          return;
        }
      }
    }
  }

  const businessName = getSetting('Business Name') || 'CartCure';
  const adminEmail = getSetting('Admin Email') || CONFIG.ADMIN_EMAIL;
  const feedbackUrl = 'https://cartcure.co.nz/feedback.html?job=' + encodeURIComponent(jobNumber);

  const subject = 'How was your experience with CartCure?';

  const bodyContent = `
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: ${EMAIL_COLORS.paperCream};">
      <tr>
        <td align="center" style="padding: 40px 20px;">
          <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width: 600px; background-color: #ffffff; border: 3px solid ${EMAIL_COLORS.paperBorder}; box-shadow: 4px 4px 0 rgba(0,0,0,0.08);">

            <!-- Header with Logo -->
            <tr>
              <td align="center" style="padding: 30px 40px 20px 40px; border-bottom: 2px solid ${EMAIL_COLORS.paperBorder};">
                <img src="https://cartcure.co.nz/CartCure_fullLogo.png" alt="CartCure" width="180" style="display: block; max-width: 180px; height: auto;">
              </td>
            </tr>

            <!-- Main Heading -->
            <tr>
              <td style="padding: 0;">
                <div style="background-color: ${EMAIL_COLORS.brandGreen}; padding: 25px 40px; text-align: center;">
                  <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold; font-family: Georgia, 'Times New Roman', serif;">
                    We'd Love Your Feedback!
                  </h1>
                </div>
              </td>
            </tr>

            <!-- Greeting -->
            <tr>
              <td style="padding: 25px 40px 20px 40px;">
                <p style="margin: 0 0 15px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 16px; line-height: 1.7;">
                  Hi ${escapeHtml(clientName)},
                </p>
                <p style="margin: 0 0 15px 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 16px; line-height: 1.7;">
                  Thank you for choosing CartCure for your recent Shopify work. We hope everything went smoothly!
                </p>
                <p style="margin: 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 16px; line-height: 1.7;">
                  If you have a moment, we'd really appreciate hearing about your experience. Your feedback helps us improve and helps other store owners find reliable Shopify help.
                </p>
              </td>
            </tr>

            <!-- CTA Button -->
            <tr>
              <td style="padding: 10px 40px 30px 40px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                  <tr>
                    <td align="center">
                      <a href="${feedbackUrl}"
                         style="display: inline-block; background-color: ${EMAIL_COLORS.brandGreen}; color: #ffffff; padding: 18px 50px; text-decoration: none; font-size: 18px; font-weight: bold; border: 3px solid ${EMAIL_COLORS.inkBlack}; box-shadow: 3px 3px 0 rgba(0,0,0,0.2);">
                        Leave a Review
                      </a>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- Closing -->
            <tr>
              <td style="padding: 0 40px 30px 40px;">
                <p style="margin: 0 0 15px 0; color: ${EMAIL_COLORS.inkGray}; font-size: 14px; line-height: 1.7;">
                  It only takes a minute, and your kind words mean a lot to us.
                </p>
                <p style="margin: 0; color: ${EMAIL_COLORS.inkBlack}; font-size: 16px;">
                  Thanks again!<br><br>
                  <strong style="color: ${EMAIL_COLORS.brandGreen};">The CartCure Team</strong>
                </p>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="padding: 25px 40px; background-color: ${EMAIL_COLORS.paperCream}; border-top: 2px solid ${EMAIL_COLORS.paperBorder};">
                <p style="margin: 0; color: ${EMAIL_COLORS.inkLight}; font-size: 12px; text-align: center;">
                  ${businessName} | Quick Shopify Fixes for NZ Businesses<br>
                  <a href="https://cartcure.co.nz" style="color: ${EMAIL_COLORS.brandGreen};">cartcure.co.nz</a>
                </p>
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  `;

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
      'Testimonial Request',
      'Feedback link sent to client',
      'To: ' + clientEmail,
      'Manual'
    );

    ui.alert('Testimonial Request Sent',
      'A testimonial request has been sent to:\n\n' +
      clientEmail + '\n\n' +
      'The client can submit their feedback at:\n' + feedbackUrl,
      ui.ButtonSet.OK);

    Logger.log('Testimonial request sent to ' + clientEmail + ' for job ' + jobNumber);
  } catch (error) {
    ui.alert('Error', 'Failed to send testimonial request: ' + error.message, ui.ButtonSet.OK);
    Logger.log('Error sending testimonial request: ' + error.message);
  }
}

