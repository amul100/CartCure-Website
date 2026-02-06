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
    let value;
    // Use provided value if exists
    if (data.hasOwnProperty(col.name)) {
      value = data[col.name];
    }
    // Use default value if defined
    else if (col.hasOwnProperty('defaultValue')) {
      value = col.defaultValue;
    }
    // Otherwise empty string
    else {
      value = '';
    }

    // Preserve leading zeros for text-formatted columns (like phone numbers)
    // Prefix with apostrophe to force Google Sheets to treat as text
    if (col.format && col.format.numberFormat === '@' && value) {
      const strValue = String(value).trim();
      if (strValue.startsWith('0')) {
        return "'" + strValue;
      }
    }

    return value;
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
// FILTER-SAFE ROW INSERTION HELPERS
// ============================================================================

/**
 * Safely appends a row to a sheet, handling active filters.
 * When filters are active, they are temporarily removed and recreated
 * to ensure the new row is visible and the filter range includes it.
 *
 * @param {Sheet} sheet - The Google Sheet to append to
 * @param {Array} rowData - Array of values for the new row
 * @param {boolean} [showToast=false] - Whether to show a toast notification if filters were cleared
 * @returns {number} The row number where data was inserted
 */
function appendRowSafe(sheet, rowData, showToast) {
  const filter = sheet.getFilter();
  let hadFilter = false;
  let filterRange = null;

  // If filter exists, capture its range and remove it
  if (filter) {
    hadFilter = true;
    filterRange = filter.getRange();
    filter.remove();
  }

  // Use appendRow to add the data
  sheet.appendRow(rowData);
  const newRowNum = sheet.getLastRow();

  // Recreate filter if one existed, expanding range to include new row
  if (hadFilter) {
    try {
      // Create new filter range that includes all data (header to new row)
      const numCols = filterRange.getNumColumns();
      const newFilterRange = sheet.getRange(1, 1, newRowNum, numCols);
      newFilterRange.createFilter();

      // Optionally notify user that filter was reset
      if (showToast) {
        try {
          SpreadsheetApp.getActiveSpreadsheet().toast(
            'Filter was reset to show all rows. New data added at row ' + newRowNum + '.',
            'Filter Reset',
            5
          );
        } catch (e) {
          // Toast may fail if no UI context (e.g., from doPost)
        }
      }
    } catch (e) {
      Logger.log('Warning: Could not recreate filter after row insert: ' + e.message);
    }
  }

  return newRowNum;
}

/**
 * Safely inserts a row at a specific position, handling active filters.
 * When filters are active, they are temporarily removed and recreated
 * to ensure the new row is visible and the filter range includes it.
 *
 * @param {Sheet} sheet - The Google Sheet to insert into
 * @param {number} rowNum - The row number to insert at
 * @param {Array} rowData - Array of values for the new row
 * @param {boolean} [showToast=false] - Whether to show a toast notification if filters were cleared
 * @returns {number} The row number where data was inserted
 */
function insertRowSafe(sheet, rowNum, rowData, showToast) {
  const filter = sheet.getFilter();
  let hadFilter = false;
  let filterRange = null;

  // If filter exists, capture its range and remove it
  if (filter) {
    hadFilter = true;
    filterRange = filter.getRange();
    filter.remove();
  }

  // Insert the data at the specified row
  sheet.getRange(rowNum, 1, 1, rowData.length).setValues([rowData]);
  const lastRow = sheet.getLastRow();

  // Recreate filter if one existed, expanding range to include all data
  if (hadFilter) {
    try {
      // Create new filter range that includes all data (header to last row)
      const numCols = filterRange.getNumColumns();
      const newFilterRange = sheet.getRange(1, 1, Math.max(lastRow, rowNum), numCols);
      newFilterRange.createFilter();

      // Optionally notify user that filter was reset
      if (showToast) {
        try {
          SpreadsheetApp.getActiveSpreadsheet().toast(
            'Filter was reset to show all rows. New data added at row ' + rowNum + '.',
            'Filter Reset',
            5
          );
        } catch (e) {
          // Toast may fail if no UI context (e.g., from doPost)
        }
      }
    } catch (e) {
      Logger.log('Warning: Could not recreate filter after row insert: ' + e.message);
    }
  }

  return rowNum;
}

/**
 * Finds the actual last row with data by checking a specific column.
 * Useful when sheets have pre-formatted empty rows that confuse getLastRow().
 *
 * @param {Sheet} sheet - The Google Sheet
 * @param {string} sheetKey - Key in COLUMN_CONFIG (e.g., 'JOBS')
 * @param {string} columnName - Column to check for data (e.g., 'Job #')
 * @returns {number} The last row number with data in the specified column
 */
function findActualLastRow(sheet, sheetKey, columnName) {
  const colLetter = getColLetter(sheetKey, columnName);
  const columnData = sheet.getRange(colLetter + ':' + colLetter).getValues();

  let actualLastRow = 1; // Start at 1 (header row)
  for (let i = columnData.length - 1; i >= 0; i--) {
    if (columnData[i][0] !== '' && columnData[i][0] !== null) {
      actualLastRow = i + 1; // Convert to 1-indexed
      break;
    }
  }
  return actualLastRow;
}

/**
 * Calculate dynamic validation row count based on current data + buffer.
 * Used to replace hardcoded row limits (500, 1000) in setup functions.
 *
 * @param {Sheet} sheet - The sheet to check
 * @param {number} [buffer] - Additional rows beyond data (default: VALIDATION_CONFIG.BUFFER_ROWS)
 * @param {number} [minRows] - Minimum rows to return (default: VALIDATION_CONFIG.MIN_ROWS)
 * @returns {number} Number of rows to apply validation/formatting to
 */
function getDynamicRowCount(sheet, buffer, minRows) {
  buffer = buffer || VALIDATION_CONFIG.BUFFER_ROWS;
  minRows = minRows || VALIDATION_CONFIG.MIN_ROWS;

  const lastRow = sheet.getLastRow();
  // Subtract 1 because lastRow includes header, we want data rows only
  const dynamicCount = Math.max(lastRow - 1 + buffer, minRows);

  return Math.min(dynamicCount, VALIDATION_CONFIG.MAX_ROWS);
}

/**
 * Safely inserts a row at the TOP of the data area (row 2), shifting existing data down.
 * Handles active filters by temporarily removing and recreating them.
 * Used for Jobs, Submissions, Invoices, Activity Log so newest items appear first.
 *
 * @param {Sheet} sheet - The Google Sheet
 * @param {Array} rowData - Array of values for the new row
 * @param {boolean} [showToast=false] - Whether to show toast notification
 * @returns {number} Always returns 2 (the inserted row)
 */
function insertAtTopSafe(sheet, rowData, showToast) {
  const filter = sheet.getFilter();
  let hadFilter = false;
  let filterRange = null;

  // Capture and remove filter if exists
  if (filter) {
    hadFilter = true;
    filterRange = filter.getRange();
    filter.remove();
  }

  // Insert a new row at position 2 (shifts existing data down)
  sheet.insertRowBefore(2);

  // Write data to the new row 2
  sheet.getRange(2, 1, 1, rowData.length).setValues([rowData]);

  // Recreate filter if one existed
  if (hadFilter) {
    try {
      const lastRow = sheet.getLastRow();
      const numCols = filterRange.getNumColumns();
      const newFilterRange = sheet.getRange(1, 1, lastRow, numCols);
      newFilterRange.createFilter();

      if (showToast) {
        try {
          SpreadsheetApp.getActiveSpreadsheet().toast(
            'New data added at top (row 2). Filter reset to show all rows.',
            'Data Added',
            5
          );
        } catch (e) {
          // Toast may fail in doPost context
        }
      }
    } catch (e) {
      Logger.log('Warning: Could not recreate filter after top insert: ' + e.message);
    }
  }

  return 2;
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
  const maxCol = sheet.getMaxColumns();
  // Only set widths for columns that exist in the sheet
  const colsToSet = Math.min(widths.length, maxCol);
  for (let col = 1; col <= colsToSet; col++) {
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
 * Applies font weights from COLUMN_CONFIG (bold key identifier columns).
 * @param {Sheet} sheet - The Google Sheet object
 * @param {string} sheetKey - Key in COLUMN_CONFIG
 * @param {number} startRow - First data row
 * @param {number} numRows - Number of rows
 */
function applyConfigFontWeights(sheet, sheetKey, startRow, numRows) {
  const config = COLUMN_CONFIG[sheetKey];
  if (!config) return;

  config.forEach((col, index) => {
    if (col.format && col.format.fontWeight) {
      const colIndex = index + 1;
      sheet.getRange(startRow, colIndex, numRows, 1).setFontWeight(col.format.fontWeight);
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
    return expectedHeaders.map((expectedCol, colIndex) => {
      const currentIndex = currentHeaders.indexOf(expectedCol);
      if (currentIndex >= 0) {
        return row[currentIndex];
      }
      // Column is new - use defaultValue from config if available
      const colConfig = config[colIndex];
      if (colConfig && colConfig.hasOwnProperty('defaultValue')) {
        return colConfig.defaultValue;
      }
      return '';
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

