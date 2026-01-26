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
| email-invoice-reminder.html | sendInvoiceReminder() | Pre-due date reminder |
| email-overdue-invoice.html | sendOverdueInvoice() | Overdue invoice with late fees |

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

2. **For the web app endpoint (`doPost()`)**: After git push, you also need to create a new version via "Manage Deployments" in Apps Script. Select the deployment and create a new version.

**DO NOT say "redeploy"** - this is incorrect terminology. The correct process is to manage deployments and create a new version if needed for web app changes.

## Git Commands
```bash
# Stage, commit, and push in one command:
git add . && git commit -m "Your commit message" && git push origin main
```
