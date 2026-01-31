# CartCure Automated Test Results

**Date:** 2026-01-28
**Total:** 81/88 tests passed (92%)

## Summary by Suite

| Suite | Passed | Total | Pass Rate |
|-------|--------|-------|-----------|
| Email Validation | 10 | 10 | 100% |
| Phone Validation | 10 | 11 | 91% |
| URL Validation | 8 | 8 | 100% |
| Text Sanitization | 8 | 9 | 89% |
| Format Validators | 15 | 15 | 100% |
| Utility Functions | 23 | 23 | 100% |
| Column Config | 7 | 12 | 58% |

## Failed Tests

### VAL-28: Phone Validation - Too Short
- **Input:** `021 123`
- **Expected:** Should throw error (too short)
- **Actual:** Accepted as valid
- **Severity:** Low - edge case
- **Action:** Consider enforcing minimum 8 digits for phone numbers

### VAL-65: Text Sanitization - Single Quotes
- **Input:** `It's fine`
- **Expected:** `It&#x27;s fine`
- **Actual:** `It&#039;s fine`
- **Severity:** None - both are valid HTML entities
- **Action:** Update test expectation (both encodings work correctly)

### COL-01 to COL-21: Column Config Tests
- **Issue:** Tests assume Job # is at column index 1, but current config has it at index 2
- **Cause:** Column structure changed (possibly added a new first column)
- **Affected Tests:**
  - COL-01: Expected index 1, got 2
  - COL-04: Expected index 1, got 2
  - COL-06: Expected letter "A", got "B"
  - COL-11: Built row position mismatch
  - COL-21: rowToObject key mapping off by one
- **Action:** Update test expectations to match current COLUMN_CONFIG

## Detailed Results

### Email Validation (10/10)
- [x] VAL-01: Valid email
- [x] VAL-02: Valid with subdomain
- [x] VAL-03: Valid with plus
- [x] VAL-04: Missing @ (correctly rejected)
- [x] VAL-05: Missing domain (correctly rejected)
- [x] VAL-06: Missing local part (correctly rejected)
- [x] VAL-07: Multiple @ (correctly rejected)
- [x] VAL-08: Empty string (correctly rejected)
- [x] VAL-09: Spaces in email (correctly rejected)
- [x] VAL-10: NZ domain

### Phone Validation (10/11)
- [x] VAL-20: NZ mobile (021)
- [x] VAL-21: NZ mobile (022)
- [x] VAL-22: NZ mobile (027)
- [x] VAL-23: NZ mobile no spaces
- [x] VAL-24: NZ mobile with dashes
- [x] VAL-25: NZ landline
- [x] VAL-26: International format
- [x] VAL-27: Invalid prefix (accepted - valid digit format)
- [ ] **VAL-28: Too short** - Failed
- [x] VAL-29: Too long (within limit)
- [x] VAL-30: Letters (correctly rejected)

### URL Validation (8/8)
- [x] VAL-40: Shopify URL
- [x] VAL-41: Custom domain
- [x] VAL-42: HTTP (not HTTPS)
- [x] VAL-43: Missing protocol (auto-adds https)
- [x] VAL-44: With path
- [x] VAL-45: Invalid URL (correctly rejected)
- [x] VAL-46: JavaScript URL (correctly rejected)
- [x] VAL-47: Empty (correctly rejected)

### Text Sanitization (8/9)
- [x] VAL-60: Normal text
- [x] VAL-61: HTML tags escaped
- [x] VAL-62: Script tags escaped
- [x] VAL-63: Ampersand escaped
- [x] VAL-64: Quotes escaped
- [ ] **VAL-65: Single quotes escaped** - Minor encoding difference
- [x] VAL-66: Empty string
- [x] VAL-67: Null input
- [x] VAL-68: Unicode preserved

### Format Validators (15/15)
- [x] VAL-80: Valid submission # (new format)
- [x] VAL-81: Invalid submission #
- [x] VAL-81b: Valid submission # (legacy)
- [x] VAL-82: Valid job #
- [x] VAL-83: Job # with suffix
- [x] VAL-84: Invalid job #
- [x] VAL-84b: Valid job # (legacy)
- [x] VAL-85: Valid invoice #
- [x] VAL-85b: Valid invoice # with suffix
- [x] VAL-86: Invalid invoice #
- [x] VAL-86b: Valid invoice # (legacy)
- [x] VAL-86c: Valid invoice # (old)
- [x] VAL-87: Null job number
- [x] VAL-88: Empty submission number
- [x] VAL-89: Whitespace invoice number

### Utility Functions (23/23)
- [x] UTIL-01: Format $100
- [x] UTIL-02: Format $1234.56
- [x] UTIL-03: Format $0
- [x] UTIL-04: Format $99.999 rounded
- [x] UTIL-05: Format negative
- [x] UTIL-20: Format date Jan 15
- [x] UTIL-21: Format date Dec 31
- [x] UTIL-22: Format null date
- [x] UTIL-30: Days Jan 1 to Jan 5
- [x] UTIL-31: Days Jan 5 to Jan 1 (negative)
- [x] UTIL-32: Same date
- [x] UTIL-40: No late fee on due date
- [x] UTIL-41: Late fee at 7 days (2%/day)
- [x] UTIL-42: Late fee at 14 days
- [x] UTIL-60: Small project (<$200)
- [x] UTIL-61: Medium project ($200-$500)
- [x] UTIL-61b: Medium project upper bound
- [x] UTIL-62: Large project (>$500)
- [x] UTIL-70: Column 1 = A
- [x] UTIL-71: Column 26 = Z
- [x] UTIL-72: Column 27 = AA
- [x] UTIL-73: Column 52 = AZ
- [x] UTIL-74: Column 53 = BA

### Column Config (7/12)
- [ ] **COL-01: JOBS Job # column index** - Expected 1, got 2
- [x] COL-02: JOBS Status exists
- [x] COL-03: Invalid column returns -1
- [ ] **COL-04: INVOICES Invoice # column** - Expected 1, got 2
- [x] COL-05: SUBMISSIONS Submission # column
- [ ] **COL-06: Job # letter is A** - Expected "A", got "B"
- [x] COL-07: Invalid column returns empty
- [x] COL-10: Built row is array
- [ ] **COL-11: Built row has correct Job #** - Position mismatch
- [x] COL-12: Unknown fields handled
- [x] COL-20: rowToObject returns object
- [ ] **COL-21: rowToObject has Job # key** - Key mapping issue

## Recommendations

1. **Fix Column Config Tests** - Update test expectations to match current column positions
2. **Consider Phone Length Validation** - Optionally enforce minimum digit count
3. **Keep Single Quote Test** - Current encoding is functionally correct

## Next Steps

- [ ] Update column config test expectations
- [ ] Review phone validation requirements
- [ ] Run tests again after fixes

---

# Puppeteer Workflow Tests

**Test Date:** 2026-01-29
**Tester:** Claude (Puppeteer automation)

## Environment
- Google Sheet: CartCure Enquires
- Puppeteer Config: headless=false, --disable-blink-features=AutomationControlled

---

## PHASE 1: Submission & Job Creation - PASS

### Test 1.1: Create Job from Submission
- **Action:** Selected "New" submission CC-CREST-630, CartCure > Jobs > Create Job from Submission
- **Result:** Job J-CREST-630 created successfully. Submission status changed to "Job Created".
- **Status:** PASS

### Test 1.2: Job Appears in Jobs Sheet
- **Result:** Job J-CREST-630 visible in row 7 with Status "Pending Quote"
- **Status:** PASS

---

## PHASE 2: Quoting (>= $200 Deposit Path) - PASS

### Test 2.1: Set Category
- **Action:** Selected "Integration" from Category dropdown for J-CREST-630
- **Status:** PASS

### Test 2.2: Set Quote Amount
- **Action:** Set Quote Amount to $500 (>= $200 triggers deposit requirement)
- **Note:** Used name box + formula bar approach (direct cell editing unreliable)
- **Status:** PASS

### Test 2.3: Send Quote
- **Action:** CartCure > Quotes > Send Quote
- **Result:** "Quote Sent - Quote sent successfully to tom@samplestore.com! Amount: $500.00, Valid until: 12/02/2026"
- **Status changed:** "Pending Quote" → "Quoted"
- **Status:** PASS

---

## PHASE 3: Quote Acceptance - PARTIAL PASS

### Test 3.1: Mark Quote Accepted
- **Action:** Selected J-CREST-630 row, CartCure > Jobs > Mark Quote Accepted
- **Result:** Deposit Invoice Required dialog appeared correctly
- **Status:** PASS

### Test 3.2: Deposit Invoice Generation
- **Action:** Clicked Yes to proceed with deposit invoice
- **Result:** Quote accepted, status changed to "Accepted", SLA clock started (Due Date: 05/02/2026, Days Remaining: 7)
- **Bug:** "Deposit Invoice Error: Invoice created but email failed: Invoice not found"
- **Invoice Status:** Created in Draft status (INV-CREST-630, $250)
- **Status:** PARTIAL PASS

---

## PHASE 4: Deposit Payment - CROSS-ORIGIN LIMITATION

### Test 4.1: Mark as Paid Dialog
- **Action:** CartCure > Invoices > Mark as Paid
- **Result:** Dialog opens with Select Invoice dropdown, Payment Method, Payment Reference fields
- **Limitation:** Cannot interact with dropdown (cross-origin iframe)
- **Status:** DIALOG WORKS, CANNOT COMPLETE

---

## PHASE 5: Start Work - PASS

### Test 5.1: Backup Reminder
- **Action:** Selected J-CREST-630 (Accepted), CartCure > Jobs > Start Work on Job
- **Result:** Backup Reminder dialog appeared:
  - "IMPORTANT: Before starting work, ensure the client has a backup of their store"
  - "Per our Terms of Service, clients are responsible for maintaining their own backups"
- **Status:** PASS

### Test 5.2: Status Change
- **Action:** Clicked Yes to confirm
- **Result:** "Work Started - Job J-CREST-630 is now In Progress. Client has been notified."
- **Status changed:** "Accepted" → "In Progress"
- **Status:** PASS

---

## PHASE 6: On Hold - CROSS-ORIGIN LIMITATION

### Test 6.1: Put Job On Hold
- **Action:** Selected J-CREST-630 (In Progress), CartCure > Jobs > Put Job On Hold
- **Result:** Confirmation dialog "Put job J-CREST-630 on hold?" appeared
- **Status:** PASS

### Test 6.2: On Hold Explanation
- **Action:** Clicked Yes
- **Result:** "On Hold Explanation" dialog appeared requesting reason
- **Limitation:** Cannot enter text in cross-origin iframe
- **Status:** DIALOG WORKS, CANNOT COMPLETE

---

## PHASE 7: Job Completion - PASS

### Test 7.1: Mark Job Complete
- **Action:** Selected J-BIRCH-177 (In Progress, $500), CartCure > Jobs > Mark Job Complete
- **Result:** Security Reminder dialog appeared:
  - "Job J-BIRCH-177 marked as Complete!"
  - "Client has been notified."
  - ⚠️ IMPORTANT - Per TOS requirements:
    - Delete/revoke any store access credentials within 24 hours
    - Remove any saved passwords
    - Log out of all client accounts
    - Remind client to change their passwords
- **Status changed:** "In Progress" → "Completed"
- **Status:** PASS

---

## PHASE 8: Final/Balance Invoice - PARTIAL PASS

### Test 8.1: Generate Invoice Prompt
- **Action:** After job completion, "Generate Invoice?" dialog appeared
- **Status:** PASS

### Test 8.2: Deposit Check
- **Action:** Clicked Yes
- **Result:** "Deposit Not Paid" warning - deposit invoice not marked as paid
- **Status:** PASS (correct validation)

### Test 8.3: Balance Invoice Creation
- **Action:** Clicked Yes to proceed anyway
- **Result:** Balance invoice INV-BIRCH-177-2 created ($250, 50% balance)
- **Bug:** Same "Invoice not found" error when trying to auto-send
- **Invoice Status:** Created in Draft status
- **Status:** PARTIAL PASS

---

## PHASE 9: Final Payment - CROSS-ORIGIN LIMITATION

- Same limitation as Phase 4 (Mark as Paid dialog has cross-origin dropdown)
- **Status:** CANNOT TEST VIA PUPPETEER

---

## PHASE 10: Testimonial Flow - NOT FOUND

- No "Request Testimonial" menu option found in CartCure menu
- Testimonials may be triggered differently (after payment, or via separate process)
- **Status:** MENU OPTION NOT AVAILABLE

---

## Bugs Found

### BUG-01: Invoice Auto-Send Fails
- **Severity:** Medium
- **Description:** When deposit/balance invoices are auto-generated, the email send fails with "Invoice not found"
- **Affected:** Phase 3 (deposit invoice), Phase 8 (balance invoice)
- **Workaround:** Manually send invoice via CartCure > Invoices > Send Invoice
- **Root Cause:** Timing issue - invoice may not be committed to sheet before send is attempted

---

## Puppeteer Technical Notes

### Successful Patterns
```javascript
// Navigate to cell: use name box + formula bar
puppeteer_fill('.waffle-name-box', 'K7');
puppeteer_fill('#t-formula-bar-input', '500');

// Click sheet tabs: dispatch full mouse events
['mousedown', 'mouseup', 'click'].forEach(e => el.dispatchEvent(new MouseEvent(e, {...})));

// Open submenus: use mouseenter/mouseover events
item.dispatchEvent(new MouseEvent('mouseenter', {...}));

// Select entire row: use row notation in name box
box.value = '7:7'; // Selects entire row 7
```

### Limitations
- Google blocks automated login (manual login required)
- Apps Script dialog iframes are cross-origin (cannot interact with form fields)
- Direct cell keyboard input unreliable
- Cannot test functions that require dropdown selection in dialogs

---

## Workflow Test Summary

| Phase | Test | Status |
|-------|------|--------|
| 1 | Submission & Job Creation | ✅ PASS |
| 2 | Quoting (≥$200 deposit path) | ✅ PASS |
| 3 | Quote Acceptance | ⚠️ PARTIAL (invoice send bug) |
| 4 | Deposit Payment | 🔒 Dialog works, cross-origin limit |
| 5 | Start Work + Backup Reminder | ✅ PASS |
| 6 | On Hold Workflow | 🔒 Dialog works, cross-origin limit |
| 7 | Job Completion + Security Reminder | ✅ PASS |
| 8 | Balance Invoice | ⚠️ PARTIAL (invoice send bug) |
| 9 | Final Payment | 🔒 Cross-origin limit |
| 10 | Testimonial Flow | ❓ Menu option not found |

**Completed:** 10 phases | **Passed:** 4 | **Partial:** 2 | **Cross-origin Limited:** 3 | **Not Found:** 1

---

## Recommendations

1. **Fix Invoice Auto-Send Bug** - Add delay or refresh after invoice creation before attempting send
2. **Add Testimonial Menu Option** - Add "Request Testimonial" to Jobs submenu for completed jobs
3. **Consider Row-Based Operations** - For dialogs with dropdowns, consider detecting selected row instead of using dropdown selection
