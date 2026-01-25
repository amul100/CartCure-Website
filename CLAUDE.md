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

## Email Template Previews
**IMPORTANT**: The `email-previews/` folder contains the exact HTML email templates as they appear in Code.gs. These files and Code.gs must always stay in sync:

- **When updating emails in Code.gs**: Also update the corresponding preview HTML file in `email-previews/`
- **When updating preview HTML files**: Also update the corresponding email template in Code.gs

This bidirectional sync ensures:
1. Preview files accurately reflect what customers receive
2. Changes made in either location are not lost
3. Email formatting can be tested locally before deployment

### Email Template Cross-References in Code.gs
Each email function in Code.gs includes a comment referencing its corresponding preview file(s):
```javascript
/**
 * Send a professional quote email
 *
 * EMAIL TEMPLATE: See email-previews/03-quote.html for preview
 */
function sendQuoteEmail(jobNumber) {
```

The email template mapping is:
| Preview File | Code.gs Function | Description |
|-------------|------------------|-------------|
| 01-admin-notification.html | sendEmailNotification() | Admin notification for new form submissions |
| 02-user-confirmation.html | sendUserConfirmationEmail() | User confirmation after form submission |
| 03-quote.html | sendQuoteEmail() / generateQuoteEmailHtml() | Standard quote email |
| 04-quote-with-deposit.html | sendQuoteEmail() / generateQuoteEmailHtml() | Quote for $200+ jobs requiring deposit |
| 05-quote-reminder.html | sendQuoteReminder() | Quote follow-up reminder |
| 06-status-in-progress.html | sendStatusUpdateEmail() | Job status: In Progress |
| 07-status-on-hold.html | sendStatusUpdateEmail() | Job status: On Hold |
| 08-status-completed.html | sendStatusUpdateEmail() | Job status: Completed |
| 09-invoice.html | sendInvoiceEmail() | Standard invoice |
| 10-deposit-invoice.html | sendInvoiceEmailSilent() | Deposit invoice (50% for $200+ jobs) |
| 11-invoice-reminder.html | sendInvoiceReminder() | Pre-due date payment reminder |
| 12-overdue-invoice.html | sendOverdueInvoice() | Overdue invoice with late fees |
| 13-payment-receipt.html | sendPaymentReceiptEmail() | Payment confirmation receipt |

### Email Template Sync Script
A Python script (`sync-email-templates.py`) is available to sync HTML preview files to Code.gs:

```bash
# Preview changes without modifying files
python sync-email-templates.py --dry-run

# Sync all configured templates
python sync-email-templates.py

# Sync a specific template
python sync-email-templates.py --template 05-quote-reminder
```

The script:
1. Reads the HTML preview file
2. Converts static placeholders (e.g., "Sarah", "JOB-0042") to JavaScript template variables (e.g., `${clientName}`, `${jobNumber}`)
3. Finds the corresponding function in Code.gs
4. Replaces the `htmlBody` template literal with the updated HTML

**Note**: Not all templates are configured in the script yet. Add new template configurations to the `EMAIL_TEMPLATES` dict in the script as needed.

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
