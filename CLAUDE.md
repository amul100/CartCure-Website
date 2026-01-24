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

**Remember**: After updating Code.gs, you must redeploy the Apps Script web app for changes to take effect.

## Git Commands
```bash
# Stage, commit, and push in one command:
git add . && git commit -m "Your commit message" && git push origin main
```
