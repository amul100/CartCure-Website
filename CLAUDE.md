# CartCure Website

## Project Info
- **Repository**: https://github.com/amul100/CartCure-Website
- **Local Path**: c:\Users\andre\OneDrive\Documents\CartCure\Cartcure-website
- **Main Branch**: main

## Apps Script File Structure
The Job Management System is split across multiple `.gs` files in `apps-script/`. All files share the same global namespace (Apps Script natively supports this). Cross-file constants use `var` instead of `const` for global visibility.

| File | Contents |
|------|----------|
| **Code.gs** | Config constants (`IS_PRODUCTION`, `CONFIG`, `VALIDATION_CONFIG`, `REGEX`), `doPost()`, `doGet()`, testimonials, quote acceptance, payment confirmation, `respondJson()` helper |
| **BackgroundTasks.gs** | Background task queue, processing, retry logic, diagnostics, signatures folder |
| **Security.gs** | Validation, rate limiting, input sanitization, `escapeHtml()`, `saveToSheet()`, debug helpers (`saveDebugLog()`, `throwValidationError()`) |
| **Email.gs** | `EMAIL_COLORS`, `renderEmailTemplate()`, `wrapEmailHtml()`, deferred email queue, all notification email functions |
| **Config.gs** | `JOB_CONFIG`, `SHEETS`, `COLUMN_CONFIG`, `EDITABLE_COLUMNS`, status/payment constants, colors, typography, cache system, settings dialog |
| **Columns.gs** | Column helpers (`getColIndex`, `getColLetter`, `buildRowFromConfig`), row insertion, sheet setup/formatting, migration utilities |
| **Menu.gs** | `onOpen()`, `buildMenu()`, `onEdit()`, actions dialogs, multi-row batch support, silent batch helpers, status menu functions, trigger helpers |
| **Setup.gs** | Setup functions, sheet styling, financial reports, data archival |
| **Operations.gs** | Helper functions, dropdowns, selection helpers, job management, refund processing, client management, quote functions, invoice functions, PDF generation |
| **Tests.gs** | Dashboard/reporting, hard reset, test data generation, test jobs, test emails |

## Job Management System Documentation Rule
**IMPORTANT**: Whenever changes are made to the Job Management System (`apps-script/*.gs` files), you MUST update the CartCure_Job_Management_Guide.html file to reflect the new functionality, features, or workflow changes.

This includes:
- New features or menu items
- Modified workflows or processes
- New sheets or columns
- Changed functionality
- New settings or configuration options

The guide must stay synchronized with the actual implementation to ensure users have accurate documentation.

## Email Template System
**IMPORTANT**: Email templates are stored as separate `.html` files in the `apps-script/` folder. **NEVER write inline HTML in `.gs` files** - always create or use separate template files.

### How Templates Work
1. Templates are `.html` files stored in `apps-script/` (e.g., `email-invoice.html`, `email-balance-invoice.html`)
2. Google Apps Script bundles all files in the same folder - templates are referenced by filename (without extension)
3. Email.gs loads templates using `renderEmailTemplate('template-name', data)` which calls `HtmlService.createTemplateFromFile()`
4. Template syntax:
   - `<?= variable ?>` - Escaped output (safe for user input)
   - `<?!= htmlVariable ?>` - Unescaped HTML output (use for pre-built HTML snippets)
   - `<?= colors.brandGreen ?>` - Access to `EMAIL_COLORS` object (defined in Email.gs, always available)

### Creating New Email Templates
When adding a new email type:
1. Create a new `.html` file in `apps-script/` folder
2. Use existing templates as reference for structure and styling
3. Call from any `.gs` file with: `renderEmailTemplate('email-new-type', { data })` - the template name matches the filename without `.html`
4. Update the template mapping table below

### Current Template Files
| Template File | Used By | Description |
|--------------|---------|-------------|
| email-admin-notification.html | sendEmailNotification() | Admin notification for new submissions |
| email-user-confirmation.html | sendUserConfirmationEmail() | User confirmation after submission |
| email-quote.html | sendQuoteEmail() | Quote emails |
| email-invoice.html | sendInvoiceEmail(), sendInvoiceEmailSilent() | Standard and deposit invoices |
| email-balance-invoice.html | sendInvoiceEmailSilent() | Balance invoice (final payment after deposit) |
| email-status-update.html | sendStatusUpdateEmail() | Job status update emails |
| email-payment-receipt.html | sendPaymentReceiptEmail() | Payment confirmation |
| email-invoice-reminder.html | sendInvoiceReminder() | Pre-due date reminder with "I Have Paid" button |
| email-overdue-invoice.html | sendOverdueInvoice() | Overdue invoice with late fees and "I Have Paid" button |
| email-quote-accepted.html | handleQuoteAcceptance() | Client confirmation after accepting quote |
| email-quote-reminder.html | sendQuoteReminder() | Quote reminder with Accept Quote button |
| email-client-paid-notification.html | sendPaymentClaimedNotification() | Admin notification when client clicks "I Have Paid" |
| invoice-pdf.html | generateInvoicePDF(), renderInvoicePDFHtml() | Print-optimized invoice PDF template |
| receipt-pdf.html | generateReceiptPDF(), renderReceiptPDFHtml() | Print-optimized payment receipt PDF template |

## Column Configuration System
**IMPORTANT**: All sheet columns are defined in a single `COLUMN_CONFIG` object in `apps-script/Config.gs`. To reorder columns or add new ones, ONLY modify this config - no other code changes needed.

### How to Reorder Columns
1. Find `COLUMN_CONFIG` in Config.gs
2. Move the column object to its new position in the array
3. Run Setup from the CartCure menu - migration happens automatically

### How to Add a New Column
Add a new object to the appropriate sheet's array in `COLUMN_CONFIG`:
```javascript
{
  name: 'Column Name',           // Header text (required)
  width: 100,                    // Width in pixels (required)
  validation: {                  // Optional: dropdown or checkbox
    type: 'list',                // 'list' or 'checkbox'
    values: ['Option1', 'Option2'],
    allowInvalid: false
  },
  format: {                      // Optional: formatting
    numberFormat: '$#,##0.00',   // Number format
    wrapText: true,              // Enable text wrap
    conditionalRules: [...]      // Conditional formatting
  },
  formula: '=...',               // Optional: cell formula with {{row}} placeholder
  defaultValue: 'Default'        // Optional: default value for new rows
}
```

### Helper Functions (in Columns.gs)
- `getColIndex('JOBS', 'Column Name')` - Returns 1-based column number
- `getColLetter('JOBS', 'Column Name')` - Returns column letter (A, B, ... AA)
- `buildRowFromConfig('JOBS', { 'Column': value })` - Builds row array in correct order
- `migrateSheetColumns(sheet, 'JOBS')` - Migrates existing data to new column order

### Available Sheet Keys
- `JOBS` - Jobs sheet (31 columns)
- `INVOICES` - Invoice Log sheet (19 columns)
- `SUBMISSIONS` - Submissions sheet (10 columns)
- `TESTIMONIALS` - Testimonials sheet (9 columns)
- `ACTIVITY_LOG` - Activity Log sheet (7 columns)

## CartCure Menu - Dual Action Access
The `🛒 CartCure` menu offers two ways to perform actions:

| Method | Location | Use Case |
|--------|----------|----------|
| **Actions Dialog** | `⚡ Actions` | Shows only valid actions for current row status. Supports batch selection. Best for new users. |
| **Submenu Items** | `📥 Submissions`, `📋 Jobs`, `💰 Quotes`, `🧾 Invoices`, `👥 Clients` | Direct access to specific actions (e.g., `▶️ Start Work`, `📤 Send Quote`). Best for power users. |

### Sync Requirement
**Both systems must stay identical.** When modifying actions, update in **Menu.gs**:
- **Actions Dialog:** `getValidJobActions()`, `getValidSubmissionActions()`, `getValidInvoiceActions()`, `getValidClientActions()`
- **Submenus:** `onOpen()` menu builder

Both call the same underlying `show...Dialog()` functions.

## Apps Script Debugging
**IMPORTANT**: The only way to see debug output from `.gs` files is to write to a text file in Google Drive. `Logger.log()` is NOT visible to the user.

### How to add debug logging:
Use the `saveDebugLog()` helper (defined in Security.gs). It automatically handles timestamps, `IS_PRODUCTION` checks, and error fallback:

```javascript
// Simple string debug
saveDebugLog('MY_FUNCTION', 'Variable: ' + someValue);

// Array of debug messages (joined with newlines)
const debugLog = [];
debugLog.push('=== Debug Title ===');
debugLog.push('Variable: ' + someValue);
debugLog.push('Data: ' + JSON.stringify(data));
saveDebugLog('MY_FUNCTION', debugLog);
```

**Key points:**
- `saveDebugLog(prefix, content)` - prefix becomes the filename prefix, content can be a string or array
- Automatically skipped when `IS_PRODUCTION = true` (set in Code.gs)
- Auto-generates timestamps in filenames
- Falls back to Drive root if debug folder creation fails
- Debug files are saved to **"CartCure Debug Logs"** folder in Google Drive

**Remember**: After updating any `.gs` file, push changes with git (clasp is linked and runs automatically).

### Helper Functions (in Security.gs)
- `saveDebugLog(prefix, content)` - Write debug file with auto-timestamp and IS_PRODUCTION guard
- `throwValidationError(internalMsg, userMsg)` - Create and throw error with `.userMessage` property
- `getOrCreateDebugFolder()` - Get/create the "CartCure Debug Logs" Drive folder

### JSON Response Helper (in Code.gs)
- `respondJson(data)` - Wraps `ContentService.createTextOutput(JSON.stringify(data)).setMimeType(ContentService.MimeType.JSON)`

## Background Task System & Diagnostics
Quote acceptance, deposit invoices, and other async operations use a background task queue processed every minute by a time-based trigger.

### Diagnosing Background Task Issues
If async operations (like deposit invoices after quote acceptance) aren't working:

1. **Run diagnostics**: `CartCure > ⚙️ Settings > 🔍 Diagnose Background Tasks`
   - Shows if trigger is installed
   - Shows pending tasks in queue
   - Provides instructions for checking execution logs

2. **If trigger is missing**: `CartCure > ⚙️ Settings > ⏱️ Setup Background Tasks`

3. **If tasks are stuck**: `CartCure > ⚙️ Settings > ▶️ Manually Process Tasks`

4. **Check execution logs**: Extensions > Apps Script > Executions sidebar
   - Look for `processBackgroundTasks` entries
   - Check for errors in recent executions

### Key Functions
- `queueBackgroundTask(taskData)` - Adds task to queue
- `processBackgroundTasks()` - Processes queue (runs every 1 min via trigger)
- `processQuoteAcceptanceTask(task)` - Handles quote acceptance subtasks
- `diagnoseBackgroundTasks()` - Shows diagnostic info
- `manuallyProcessBackgroundTasks()` - Force processes stuck tasks

### Debug Logging Added
The quote acceptance flow logs:
- `Quote acceptance taskData - Total: X, requiresDeposit: true/false`
- `Deposit invoice required/NOT required for JOB-XXX (total: $X)`

These appear in Apps Script execution logs.

## Apps Script Deployment
**IMPORTANT**: After making changes to any `.gs` file in `apps-script/`:

1. **For menu functions, triggers, and spreadsheet UI code**: Just git push. Clasp is linked and runs automatically. Changes take effect immediately.

2. **For the web app endpoint (`doPost()` or `doGet()` in Code.gs)**: After git push, you MUST also deploy a new version using clasp:
   ```bash
   cd apps-script && npx @google/clasp deploy -i AKfycbyBjf9TKEogrSWp5cLxs4tZWuGbIdWUYGn5oDGIBVWvVQWggNDjxZzgugrgo0s8LZ4stg -d "Description of changes"
   ```
   **AUTOMATICALLY run this command** whenever `doPost()` or `doGet()` functions are modified. Do not wait to be asked.

**DO NOT say "redeploy"** - this is incorrect terminology. The correct process is to deploy a new version which updates the existing deployment.

## Puppeteer Testing Configuration
**IMPORTANT**: When using Puppeteer to test Google Sheets with the CartCure system, Google blocks automated browser logins by default. Use these launch options to allow manual login:

```javascript
// Launch Puppeteer with these options to bypass automation detection:
puppeteer_navigate({
  url: "https://docs.google.com/spreadsheets/d/1Yy77rtMl8wJ2n-w9MF5qDUOKAK6iXM1Ym2Oiqbd7r_0/edit",
  launchOptions: {
    headless: false,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-blink-features=AutomationControlled"]
  },
  allowDangerous: true
})
```

**Key points:**
- `headless: false` - Required to see the browser and manually log in
- `--disable-blink-features=AutomationControlled` - Prevents Google from detecting automation
- `allowDangerous: true` - Required to use --no-sandbox args
- User must manually log in once after browser launches (Google still requires human authentication)
- After login, Puppeteer can automate clicking menus, taking screenshots, etc.

### Google Sheets Interaction Patterns
**Clicking sheet tabs** - Standard CSS selectors don't work. Use this pattern:
```javascript
puppeteer_evaluate({
  script: `(function() {
    const tabs = Array.from(document.querySelectorAll('*')).filter(el =>
      el.textContent === 'SHEET_NAME' &&
      el.offsetParent !== null &&
      el.getBoundingClientRect().bottom > 800
    );
    if (tabs.length > 0) {
      const tab = tabs[0];
      const rect = tab.getBoundingClientRect();
      ['mousedown', 'mouseup', 'click'].forEach(eventType => {
        tab.dispatchEvent(new MouseEvent(eventType, {
          bubbles: true, cancelable: true, view: window,
          clientX: rect.left + rect.width/2,
          clientY: rect.top + rect.height/2
        }));
      });
      return 'Clicked';
    }
    return 'Not found';
  })();`
})
```

**Clicking cells** - Click by cell address (e.g., A10):
```javascript
puppeteer_evaluate({
  script: `(function() {
    // Use the name box to navigate to cell
    const nameBox = document.querySelector('input.jfk-textinput');
    if (nameBox) {
      nameBox.focus();
      nameBox.value = 'A10';
      nameBox.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', keyCode: 13, bubbles: true}));
      return 'Navigated to cell';
    }
    return 'Name box not found';
  })();`
})
```

**Opening menus** - Click menu items by text:
```javascript
puppeteer_evaluate({
  script: `(function() {
    const menuItems = document.querySelectorAll('.menu-button, [role="menuitem"]');
    for (const item of menuItems) {
      if (item.textContent.includes('CartCure')) {
        item.click();
        return 'Clicked menu';
      }
    }
    return 'Menu not found';
  })();`
})

## Google Apps Script Dialog Styling
**IMPORTANT**: When creating modal dialogs with `HtmlService.createHtmlOutput()`, follow these rules to ensure consistent sizing:

### Dialog Width Issues
1. **Long titles expand dialogs** - Google Apps Script dialogs automatically expand width to fit the title. Keep dialog titles SHORT (under ~40 characters). Avoid including emails or long IDs in titles.
   ```javascript
   // BAD - title too long, dialog expands
   ui.showModalDialog(html, 'Actions - John Smith (john.smith@example.com)');

   // GOOD - short title, dialog stays at setWidth() size
   ui.showModalDialog(html, 'Actions - John Smith');
   ```

2. **Use CSS Grid for full-width layouts** - Flexbox with `flex-direction: column` can shrink-wrap to content width. CSS Grid with `1fr` forces full width:
   ```css
   /* BAD - can shrink to content width */
   .actions-list {
     display: flex;
     flex-direction: column;
   }

   /* GOOD - always fills container width */
   .actions-list {
     display: grid;
     grid-template-columns: 1fr;
     gap: 10px;
     width: 100%;
   }
   ```

3. **Ensure body and container fill the dialog**:
   ```css
   html, body {
     margin: 0;
     padding: 0;
     min-width: 100%;
   }
   .container {
     width: 100%;
     box-sizing: border-box;
     padding: 16px;
   }
   ```

4. **Make buttons explicitly stretch**:
   ```css
   .action-btn {
     width: 100%;
     min-width: 100%;
     justify-self: stretch;  /* For grid items */
   }
   ```

### Why Content-Based Shrinking Happens
- Short button labels (e.g., "Set VIP") cause flex containers to shrink
- Longer labels (e.g., "Send Quote Reminder") naturally fill more width
- CSS Grid with `1fr` prevents this by forcing full-width regardless of content

## Git Commands
```bash
# Stage, commit, and push in one command:
git add . && git commit -m "Your commit message" && git push origin main
```
