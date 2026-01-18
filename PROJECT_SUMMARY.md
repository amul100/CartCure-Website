# CartCure Website - Complete Summary

## What It Is
**CartCure** is a NZ-based Shopify® store fix/maintenance service website. Target audience: NZ small business owners who need quick, affordable Shopify fixes without long-term commitments.

**Value Props:** 1-3 day turnaround, $50-200 per fix, NZ-based, pay-per-fix (no contracts)

---

## Tech Stack
| Layer | Technology |
|-------|------------|
| Frontend | HTML5, CSS3, Vanilla JS (IIFE-wrapped) |
| Sanitization | DOMPurify v3.0.6 (CDN) |
| Backend | Google Apps Script (serverless) |
| Database | Google Sheets |
| File Storage | Google Drive (audio files) |
| Notifications | Gmail (via MailApp) |

---

## File Structure
| File | Lines | Purpose |
|------|-------|---------|
| `index.html` | 365 | Main landing page with contact form, CSP header |
| `styles.css` | 1,148 | "Paperlike" retro design theme |
| `script.js` | 638 | Client-side logic: form, voice recording, validation |
| `security-config.js` | 144 | Centralized security constants (frozen object) |
| `google_apps_script.js` | 689 | Backend: validation, rate limiting, email/sheet storage |
| `privacy-policy.html` | — | GDPR/CCPA/NZ Privacy Act compliant |
| `start-server.bat` | — | Local dev server launcher |
| `CartCure_Favicon.png` | — | Favicon image |
| `CartCure_fullLogo.png` | — | Full brand logo |
| `old_versions/` | — | Previous version archive |

---

## Key Features

### Contact Form
- **Fields:** Name (required), Email (required), Store URL (optional), Message (optional)
- **Privacy consent checkbox** (required)
- **Validation:** HTML5 + client-side JS + server-side

### Voice Recording
- MediaRecorder API → WebM audio → Base64
- **Limits:** 3 min max (warning at 2:30), 10MB max
- UI: Record → Stop → Preview → Delete

### Browser APIs Used
- MediaRecorder (voice recording)
- Fetch (form submission)
- localStorage (rate limiting)
- IntersectionObserver (scroll animations)

### Page Sections
Hero → Services → How It Works → Testimonials → Benefits → Pricing → Footer

---

## Form Submission Flow
```
Client: Validate → Sanitize (DOMPurify) → URLSearchParams → POST to Google Apps Script
   ↓
Server: Rate limit check → Validate inputs → Save to Sheet → Save audio to Drive → Send email
   ↓
Response: { success: true/false, message: "..." }
```

---

## Security Features

### Implemented
- **CSP Header** - Strict content security policy in meta tag
- **DOMPurify** - Strips ALL HTML tags
- **Rate Limiting** - 5 submissions/hour (client localStorage + server Cache Service)
- **Input Validation** - Regex for email/URL, max lengths, blocked patterns
- **URL Protocol Blocking** - Blocks javascript:, data:, file:, localhost, private IPs
- **HTML Entity Escaping** - Server-side XSS prevention
- **IIFE Wrapper** - No global namespace pollution
- **Memory Leak Prevention** - URL.revokeObjectURL cleanup

### Removed (was causing issues)
- CSRF tokens - Not needed for stateless Google Apps Script

---

## Configuration

### Client (script.js)
```javascript
const SCRIPT_URL = 'https://script.google.com/macros/s/[DEPLOYMENT_ID]/exec'
const IS_PRODUCTION = false  // Set true in production
```

### Server (Google Apps Script Properties)
```
ADMIN_EMAIL: your-email@domain.com
SHEET_ID: [Google Sheet ID]
SHARED_SECRET: [32+ char random string - for future HMAC]
```

### Limits (security-config.js)
| Setting | Value |
|---------|-------|
| MAX_SUBMISSIONS_PER_HOUR | 5 |
| MAX_AUDIO_DURATION | 180 seconds |
| MAX_AUDIO_SIZE | 10MB |
| NAME_MAX_LENGTH | 100 |
| EMAIL_MAX_LENGTH | 254 |
| MESSAGE_MAX_LENGTH | 5000 |

---

## Google Sheet Columns
Timestamp | Name | Email | Store URL | Message | Has Voice Note | Voice Note Link | IP Address

---

## Recent Fixes Applied
1. **CSP updated** - Added `https://script.googleusercontent.com` to connect-src (Google Apps Script redirects there)
2. **CSRF removed** - Was causing form submission failures; unnecessary for stateless API
3. **Store URL fix** - Changed from sending "Not provided" to empty string when blank

---

## Deployment Checklist
1. Create Google Apps Script project, paste `google_apps_script.js`
2. Set Script Properties (ADMIN_EMAIL, SHEET_ID)
3. Deploy as Web App (Execute as: Me, Who has access: Anyone)
4. Update SCRIPT_URL in `script.js` with deployment URL
5. Set `IS_PRODUCTION = true`
6. Upload all files to web host with HTTPS
7. Test end-to-end

---

## Local Development
```bash
# Run from project folder
start-server.bat
# Opens http://localhost:8000
```

---

## Status
**Version:** 1.0.0 | **Status:** Production-ready | **Total Lines:** ~2,900
