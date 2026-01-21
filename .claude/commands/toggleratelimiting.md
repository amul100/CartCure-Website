# Toggle Rate Limiting

Quick reference for enabling/disabling rate limiting in the CartCure form submission system.

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

### 3. Clear Browser Cache

After disabling client-side checks, users need to clear localStorage:

```javascript
// In browser console (F12):
localStorage.clear();
```

## Enable Rate Limiting (restore protection)

### 1. Uncomment All Four Sections

Remove the `//` comment markers from all four locations above:
- script.js: checkRateLimit() call
- script.js: recordSubmission() call
- Code.gs: checkServerRateLimit() call
- Code.gs: recordServerSubmission() call

### 2. Deploy Changes

```bash
git add .
git commit -m "Re-enable rate limiting"
git push origin main
```

Clasp will auto-deploy the server-side changes.

## Files Affected

- **Client-side**: `/script.js` (lines ~367, ~522)
- **Server-side**: `/apps-script/Code.gs` (lines ~142, ~160)
- **Config**: `/security-config.js` (defines limits, don't modify)

## Rate Limit Settings

Current limits (defined in security-config.js and Code.gs):
- **Max submissions**: 5 per hour
- **Window**: 3,600,000 ms (1 hour)
- **Tracking**: Per email address

## Notes

- Always re-enable rate limiting before production deployment
- Client-side checks can be bypassed, server-side is the real protection
- Users who hit the limit see: "Too many requests! You can only submit 5 times per hour. Please try again later."
