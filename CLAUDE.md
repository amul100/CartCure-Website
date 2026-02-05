# CartCure Website

## Project Info
- **Repository**: https://github.com/amul100/CartCure-Website
- **Local Path**: c:\Users\andre\OneDrive\Documents\CartCure\Cartcure-website
- **Main Branch**: main

## Job Management System Documentation Rule
**IMPORTANT**: Whenever changes are made to the Job Management System (apps-script/Code.gs), you MUST update the CartCure_Job_Management_Guide.html file to reflect the new functionality, features, or workflow changes.

This includes:
- New features or menu items
- Modified workflows or processes
- New sheets or columns
- Changed functionality
- New settings or configuration options

The guide must stay synchronized with the actual implementation to ensure users have accurate documentation.

## Email Template System
**IMPORTANT**: Email templates are stored as separate `.html` files in the `apps-script/` folder (same folder as Code.gs). **NEVER write inline HTML in Code.gs** - always create or use separate template files.

### How Templates Work
1. Templates are `.html` files stored alongside Code.gs in `apps-script/` (e.g., `email-invoice.html`, `email-balance-invoice.html`)
2. Google Apps Script bundles all files in the same folder - Code.gs references templates by filename (without extension)
3. Code.gs loads templates using `renderEmailTemplate('template-name', data)` which calls `HtmlService.createTemplateFromFile()`
4. Template syntax:
   - `<?= variable ?>` - Escaped output (safe for user input)
   - `<?!= htmlVariable ?>` - Unescaped HTML output (use for pre-built HTML snippets)
   - `<?= colors.brandGreen ?>` - Access to EMAIL_COLORS object (always available)

### Creating New Email Templates
When adding a new email type:
1. Create a new `.html` file in `apps-script/` folder (same folder as Code.gs)
2. Use existing templates as reference for structure and styling
3. Call it from Code.gs with: `renderEmailTemplate('email-new-type', { data })` - the template name matches the filename without `.html`
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

## Column Configuration System
**IMPORTANT**: All sheet columns are defined in a single `COLUMN_CONFIG` object at the top of Code.gs. To reorder columns or add new ones, ONLY modify this config - no other code changes needed.

### How to Reorder Columns
1. Find `COLUMN_CONFIG` in Code.gs (around line 2300)
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

### Helper Functions
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
**Both systems must stay identical.** When modifying actions, update:
- **Actions Dialog:** `getValidJobActions()`, `getValidSubmissionActions()`, `getValidInvoiceActions()`, `getValidClientActions()` (~line 4542-4677)
- **Submenus:** `onOpen()` menu builder (~line 4315)

Both call the same underlying `show...Dialog()` functions.

## Apps Script Debugging
**IMPORTANT**: The only way to see debug output from Code.gs is to write to a text file in Google Drive. `Logger.log()` is NOT visible to the user.

### How to add debug logging:
1. Create a debug log array to collect messages:
   ```javascript
   const debugLog = [];
   debugLog.push('=== Debug Title ===');
   debugLog.push('Variable: ' + someValue);
   ```

2. Save the debug file using the helper function:
   ```javascript
   if (!IS_PRODUCTION) {
     saveTestimonialDebugFile(identifier, debugLog);
   }
   ```

3. Or use the generic pattern:
   ```javascript
   const folder = getOrCreateDebugFolder();
   const fileName = 'DEBUG_' + timestamp + '.txt';
   folder.createFile(fileName, debugLog.join('\n'));
   ```

4. Debug files are saved to **"CartCure Debug Logs"** folder in Google Drive

5. The `IS_PRODUCTION` flag (set at top of Code.gs) controls whether debug files are created

**Remember**: After updating Code.gs, push changes with git (clasp is linked and runs automatically).

### Error logging pattern:
When debugging functions that might fail early, add debug file creation at the VERY START of the function, before any other code:

```javascript
function someFunction(data) {
  // Create debug file FIRST before anything else can fail
  try {
    const debugFolder = getOrCreateDebugFolder();
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const earlyDebug = [
      '=== Function Name Early Debug ===',
      'Timestamp: ' + ts,
      'Data received: ' + JSON.stringify(data),
      'Key variable: ' + someVar
    ];
    debugFolder.createFile('FUNCTION_EARLY_' + ts + '.txt', earlyDebug.join('\n'));
  } catch (earlyDebugError) {
    // If even this fails, try writing to Drive root
    try {
      DriveApp.createFile('ERROR_' + new Date().getTime() + '.txt', 'Debug failed: ' + earlyDebugError.toString());
    } catch (e) { /* ignore */ }
  }

  // Rest of function...
}
```

This ensures you get a debug file even if the function fails immediately.

## Apps Script Deployment
**IMPORTANT**: After making changes to Code.gs:

1. **For menu functions, triggers, and spreadsheet UI code**: Just git push. Clasp is linked and runs automatically. Changes take effect immediately.

2. **For the web app endpoint (`doPost()` or `doGet()`)**: After git push, you MUST also deploy a new version using clasp:
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
