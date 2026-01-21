The user is requesting to toggle rate limiting, if off, turn on, if on turn off.


## Overview

Rate limiting prevents spam by restricting users to 5 form submissions per hour per email address. There are two layers:
- **Client-side**: JavaScript checks in browser localStorage
- **Server-side**: Google Apps Script checks in Script Properties

## Disable Rate Limiting (for testing)

### 1. Client-Side (script.js)

Comment out the rate limit check around line 367:

```javascript
// TEMPORARILY DISABLED FOR TESTING
// if (!checkRateLimit()) {
//     showError(SecurityConfig.ERRORS.RATE_LIMIT);
//     return;
// }
```

Comment out the recording around line 522:

```javascript
// TEMPORARILY DISABLED FOR TESTING
// recordSubmission();
```

### 2. Server-Side (apps-script/Code.gs)

Comment out the check around line 142:

```javascript
// TEMPORARILY DISABLED FOR TESTING
// checkServerRateLimit(emailForRateLimit);
```

Comment out the recording around line 160:

```javascript
// TEMPORARILY DISABLED FOR TESTING
// recordServerSubmission(emailForRateLimit);
```


## Enable/disable Rate Limiting

### 1. Uncomment/comment All Four Sections

Add/remove the `//` comment markers from all four locations above:
- script.js: checkRateLimit() call
- script.js: recordSubmission() call
- Code.gs: checkServerRateLimit() call
- Code.gs: recordServerSubmission() call

## Files Affected

- **Client-side**: `/script.js` (lines ~367, ~522)
- **Server-side**: `/apps-script/Code.gs` (lines ~142, ~160)
- **Config**: `/security-config.js` (defines limits, don't modify)

Push changes to git (code.gs will be automatically updated after git push)

After disabling client-side checks, users need to clear localStorage
