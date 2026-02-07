# CartCure Job Management System - Comprehensive Test Specification

## Overview

This document lists all tests needed to verify the CartCure job management system functions correctly. Tests are organized by category with expected inputs, outputs, and edge cases.

**Total Test Cases: ~180+**

| Category | Count |
|----------|-------|
| Web Endpoint Tests | 57 |
| Input Validation Tests | 48 |
| Utility Function Tests | 33 |
| Column Config Tests | 12 |
| Job Workflow Tests | 40 |
| Invoice Workflow Tests | 25 |
| Email Template Tests | 15 |
| Automated Trigger Tests | 10 |
| Edge Cases | 12 |

---

## 1. WEB ENDPOINT TESTS (doPost / doGet)

### 1.1 doGet - Health Check
| Test ID | Description | Input | Expected Output |
|---------|-------------|-------|-----------------|
| GET-01 | Health check returns OK | No params | `{"status":"ok","message":"CartCure Form Handler is running","timestamp":"..."}` |

### 1.2 doGet - Testimonials API
| Test ID | Description | Input | Expected Output |
|---------|-------------|-------|-----------------|
| GET-02 | Get all approved testimonials | `?action=getTestimonials` | `{"success":true,"testimonials":[...]}` with approved items only |
| GET-03 | Get 5-star only testimonials | `?action=getTestimonials&fiveStarOnly=true` | Only rating=5 testimonials |
| GET-04 | Limit testimonials | `?action=getTestimonials&limit=3` | Max 3 testimonials |
| GET-05 | Combined filters | `?action=getTestimonials&fiveStarOnly=true&limit=5` | Max 5 five-star testimonials |
| GET-06 | No testimonials exist | `?action=getTestimonials` (empty sheet) | `{"success":true,"testimonials":[]}` |

### 1.3 doPost - Contact Form Submission
| Test ID | Description | Input | Expected Output |
|---------|-------------|-------|-----------------|
| POST-01 | Valid submission | `{name, email, phone, storeUrl, message}` | `{"success":true,"message":"Form submitted successfully"}` |
| POST-02 | Submission saved to sheet | Valid form data | New row in Submissions sheet with status "New" |
| POST-03 | Admin email sent | Valid form data | Email to admin with submission details |
| POST-04 | User confirmation email sent | Valid form data | Confirmation email to user's email |
| POST-05 | Submission number generated | Valid form data | Format: `CC-[WORD]-[XXX]` |

### 1.4 doPost - Contact Form Validation
| Test ID | Description | Input | Expected Output |
|---------|-------------|-------|-----------------|
| POST-10 | Missing name | `{email, phone, storeUrl, message}` | Error: name required |
| POST-11 | Missing email | `{name, phone, storeUrl, message}` | Error: email required |
| POST-12 | Invalid email format | `{email: "notanemail"}` | Error: invalid email |
| POST-13 | Invalid phone format | `{phone: "abc123"}` | Error: invalid phone |
| POST-14 | XSS in message | `{message: "<script>alert('xss')</script>"}` | Script tags escaped/removed |
| POST-15 | SQL injection attempt | `{name: "'; DROP TABLE--"}` | Input sanitized, no errors |
| POST-16 | Very long message | `{message: "a".repeat(10000)}` | Truncated or rejected |
| POST-17 | Empty message | `{message: ""}` | Error: message required |
| POST-18 | Invalid URL format | `{storeUrl: "not-a-url"}` | Error or sanitized |

### 1.5 doPost - Rate Limiting
| Test ID | Description | Input | Expected Output |
|---------|-------------|-------|-----------------|
| POST-20 | First submission | Valid data | Success |
| POST-21 | 5th submission (same email, <1hr) | Same email, 5th time | Success |
| POST-22 | 6th submission (same email, <1hr) | Same email, 6th time | `{"success":false}` with rate limit message |
| POST-23 | Submission after 1hr cooldown | Same email after 1hr | Success |
| POST-24 | Different email not affected | Different email | Success (own limit) |

### 1.6 doPost - Quote Acceptance
| Test ID | Description | Input | Expected Output |
|---------|-------------|-------|-----------------|
| POST-30 | Valid quote acceptance | `{action:"acceptQuote", jobNumber, fullName, signature, termsAccepted:"Yes"}` | `{"success":true,"message":"Quote accepted..."}` |
| POST-31 | Job status updated | Valid acceptance | Job status = "Accepted" |
| POST-32 | Quote Accepted Date set | Valid acceptance | Current date in Quote Accepted Date field |
| POST-33 | Due Date calculated | Valid acceptance | Due Date = Quote Accepted Date + Turnaround |
| POST-34 | Signature saved to Drive | Valid acceptance with signature | PNG file in Signatures folder |
| POST-35 | Confirmation email to client | Valid acceptance | Email with acceptance confirmation |
| POST-36 | Notification to admin | Valid acceptance | Email notifying admin |
| POST-37 | Deposit invoice auto-generated (>=200) | Job total >= $200 | Deposit invoice created & emailed |
| POST-38 | No deposit invoice (<200) | Job total < $200 | No invoice created |
| POST-39 | Missing job number | `{action:"acceptQuote", fullName, signature}` | Error: job number required |
| POST-40 | Invalid job number | `{jobNumber: "INVALID-123"}` | Error: job not found |
| POST-41 | Missing signature | `{jobNumber, fullName, termsAccepted}` | Error: signature required |
| POST-42 | Terms not accepted | `{termsAccepted: "No"}` | Error: must accept terms |
| POST-43 | Already accepted job | Job already in "Accepted" status | Error or warning |

### 1.7 doPost - Testimonial Submission
| Test ID | Description | Input | Expected Output |
|---------|-------------|-------|-----------------|
| POST-50 | Valid testimonial | `{action:"submitTestimonial", jobNumber, name, businessName, location, rating, testimonial}` | `{"success":true}` |
| POST-51 | Saved to sheet | Valid testimonial | Row in Testimonials sheet |
| POST-52 | Status = Pending Review | Valid testimonial | Default status |
| POST-53 | Optional email saved | Include email field | Saved in Email column |
| POST-54 | Missing job number | No jobNumber | Error |
| POST-55 | Invalid rating | `{rating: "6"}` or `{rating: "0"}` | Error: rating 1-5 |
| POST-56 | Empty testimonial | `{testimonial: ""}` | Error: testimonial required |
| POST-57 | Job doesn't exist | Invalid jobNumber | Error or warning |

---

## 2. INPUT VALIDATION TESTS

### 2.1 validateEmail()
| Test ID | Description | Input | Expected |
|---------|-------------|-------|----------|
| VAL-01 | Valid email | `test@example.com` | true |
| VAL-02 | Valid with subdomain | `test@mail.example.com` | true |
| VAL-03 | Valid with plus | `test+tag@example.com` | true |
| VAL-04 | Missing @ | `testexample.com` | false |
| VAL-05 | Missing domain | `test@` | false |
| VAL-06 | Missing local part | `@example.com` | false |
| VAL-07 | Multiple @ | `test@@example.com` | false |
| VAL-08 | Empty string | `` | false |
| VAL-09 | Spaces in email | `test @example.com` | false |
| VAL-10 | NZ domain | `test@business.co.nz` | true |

### 2.2 validatePhone()
| Test ID | Description | Input | Expected |
|---------|-------------|-------|----------|
| VAL-20 | NZ mobile (021) | `021 123 4567` | true |
| VAL-21 | NZ mobile (022) | `022 123 4567` | true |
| VAL-22 | NZ mobile (027) | `027 123 4567` | true |
| VAL-23 | NZ mobile no spaces | `0211234567` | true |
| VAL-24 | NZ mobile with dashes | `021-123-4567` | true |
| VAL-25 | NZ landline | `09 123 4567` | true |
| VAL-26 | International format | `+64 21 123 4567` | true |
| VAL-27 | Invalid prefix | `099 123 4567` | false |
| VAL-28 | Too short | `021 123` | false |
| VAL-29 | Too long | `021 123 456 789` | false |
| VAL-30 | Letters | `021 ABC DEFG` | false |

### 2.3 validateURL()
| Test ID | Description | Input | Expected |
|---------|-------------|-------|----------|
| VAL-40 | Shopify URL | `https://store.myshopify.com` | true |
| VAL-41 | Custom domain | `https://www.mystore.co.nz` | true |
| VAL-42 | HTTP (not HTTPS) | `http://store.com` | true (or convert) |
| VAL-43 | Missing protocol | `store.myshopify.com` | true (add https) |
| VAL-44 | With path | `https://store.com/products` | true |
| VAL-45 | Invalid URL | `not a url` | false |
| VAL-46 | JavaScript URL | `javascript:alert(1)` | false |
| VAL-47 | Empty | `` | false |

### 2.4 validateAndSanitizeText()
| Test ID | Description | Input | Expected |
|---------|-------------|-------|----------|
| VAL-60 | Normal text | `Hello world` | `Hello world` |
| VAL-61 | HTML tags escaped | `<b>bold</b>` | `&lt;b&gt;bold&lt;/b&gt;` |
| VAL-62 | Script tags removed | `<script>alert(1)</script>` | Sanitized |
| VAL-63 | Special chars kept | `$100 & 50%` | `$100 &amp; 50%` |
| VAL-64 | Newlines preserved | `Line1\nLine2` | Preserved |
| VAL-65 | Leading/trailing whitespace | `  text  ` | `text` |
| VAL-66 | Multiple spaces | `word    word` | `word word` or preserved |
| VAL-67 | Unicode characters | `Maori words` | Preserved |
| VAL-68 | Max length enforced | Very long text | Truncated |

### 2.5 Format Validators
| Test ID | Description | Input | Expected |
|---------|-------------|-------|----------|
| VAL-80 | Valid submission # | `CC-APPLE-123` | true |
| VAL-81 | Invalid submission # | `CC-123` | false |
| VAL-82 | Valid job # | `J-APPLE-123` | true |
| VAL-83 | Job # with suffix | `J-APPLE-123-2` | true |
| VAL-84 | Invalid job # | `JOB-123` | false |
| VAL-85 | Valid invoice # | `INV-001` | true |
| VAL-86 | Invalid invoice # | `INVOICE-1` | false |

---

## 3. UTILITY FUNCTION TESTS

### 3.1 formatCurrency()
| Test ID | Input | Expected |
|---------|-------|----------|
| UTIL-01 | `100` | `$100.00` |
| UTIL-02 | `1234.56` | `$1,234.56` |
| UTIL-03 | `0` | `$0.00` |
| UTIL-04 | `99.999` | `$100.00` (rounded) |
| UTIL-05 | `-50` | `-$50.00` |

### 3.2 calculateGST()
| Test ID | Input (excl GST) | Expected GST (15%) |
|---------|------------------|-------------------|
| UTIL-10 | `100` | `15.00` |
| UTIL-11 | `1000` | `150.00` |
| UTIL-12 | `0` | `0.00` |
| UTIL-13 | `33.33` | `5.00` (rounded) |

### 3.3 formatNZDate() / formatDueDate()
| Test ID | Input | Expected Format |
|---------|-------|-----------------|
| UTIL-20 | `new Date(2025, 0, 15)` | `15/01/2025` |
| UTIL-21 | `new Date(2025, 11, 31)` | `31/12/2025` |

### 3.4 daysBetween()
| Test ID | Date1 | Date2 | Expected |
|---------|-------|-------|----------|
| UTIL-30 | Jan 1 | Jan 5 | 4 |
| UTIL-31 | Jan 5 | Jan 1 | -4 |
| UTIL-32 | Same date | Same date | 0 |

### 3.5 calculateLateFee()
| Test ID | Original | Days Overdue | Expected Fee |
|---------|----------|--------------|--------------|
| UTIL-40 | $100 | 0 | $0 |
| UTIL-41 | $100 | 7 | Based on LATE_FEE_CONFIG |
| UTIL-42 | $100 | 14 | Higher tier |
| UTIL-43 | $100 | 30 | Maximum tier |

### 3.6 calculateSLAStatus()
| Test ID | Accepted Date | Turnaround | Current Date | Expected |
|---------|---------------|------------|--------------|----------|
| UTIL-50 | 5 days ago | 10 days | Today | "On Track" |
| UTIL-51 | 9 days ago | 10 days | Today | "At Risk" |
| UTIL-52 | 12 days ago | 10 days | Today | "Overdue" |

### 3.7 getProjectSize()
| Test ID | Total Amount | Expected |
|---------|--------------|----------|
| UTIL-60 | $50 | "Small" |
| UTIL-61 | $200 | "Medium" |
| UTIL-62 | $1000 | "Large" |

### 3.8 colIndexToLetter()
| Test ID | Index | Expected |
|---------|-------|----------|
| UTIL-70 | 1 | "A" |
| UTIL-71 | 26 | "Z" |
| UTIL-72 | 27 | "AA" |
| UTIL-73 | 52 | "AZ" |

---

## 4. COLUMN CONFIG TESTS

### 4.1 getColIndex()
| Test ID | Sheet | Column | Expected |
|---------|-------|--------|----------|
| COL-01 | JOBS | "Job #" | 1 |
| COL-02 | JOBS | "Status" | (check config) |
| COL-03 | JOBS | "Invalid Column" | Error |
| COL-04 | INVOICES | "Invoice #" | 1 |
| COL-05 | SUBMISSIONS | "Submission #" | 2 |

### 4.2 buildRowFromConfig()
| Test ID | Description | Expected |
|---------|-------------|----------|
| COL-10 | Builds row in correct order | Array matches COLUMN_CONFIG order |
| COL-11 | Missing fields get defaults | Default values used |
| COL-12 | Unknown fields ignored | No error, extra fields dropped |

### 4.3 rowToObject()
| Test ID | Description | Expected |
|---------|-------------|----------|
| COL-20 | Converts array to object | Object with column names as keys |
| COL-21 | Empty cells | Empty string values |

---

## 5. JOB WORKFLOW TESTS

### 5.1 createJobFromSubmission()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| JOB-01 | Creates job from submission | Valid submission selected | New job in Jobs sheet |
| JOB-02 | Job number generated | Submission = CC-APPLE-123 | Job = J-APPLE-123 |
| JOB-03 | Client info copied | Submission has client data | Job has same data |
| JOB-04 | Initial status | New job | "Pending Quote" |
| JOB-05 | Submission status updated | After job creation | "Job Created" |
| JOB-06 | Activity log entry | Job created | Entry in Activity Log |
| JOB-07 | Duplicate warning | Job already exists for submission | Warning dialog, option to create J-XXX-2 |
| JOB-08 | No submission selected | Nothing selected | Error dialog |

### 5.2 sendQuoteEmail()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| JOB-10 | Sends quote email | Job with Quote Amount filled | Email sent |
| JOB-11 | Status updated | After sending | "Quoted" |
| JOB-12 | Quote Sent Date set | After sending | Current date |
| JOB-13 | GST calculated | Quote Amount = $100 | GST = $15, Total = $115 |
| JOB-14 | Deposit shown (>=200) | Total >= $200 | Email mentions 50% deposit |
| JOB-15 | No deposit (<200) | Total < $200 | No deposit mentioned |
| JOB-16 | Accept Quote link | In email | Valid link with job number |
| JOB-17 | Missing Quote Amount | No amount set | Error dialog |

### 5.3 sendQuoteReminder()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| JOB-20 | Sends reminder | Job in "Quoted" status | Reminder email sent |
| JOB-21 | Status updated | After sending | "Quote Reminded" |
| JOB-22 | Accept button in email | Reminder email | Valid Accept Quote link |

### 5.4 markQuoteDeclined()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| JOB-25 | Updates status | Job selected | Status = "Declined" |

### 5.5 startWorkOnJob()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| JOB-30 | Starts work | Job in "Accepted" status, deposit paid (if required) | Status = "In Progress" |
| JOB-31 | Backup reminder shown | Fresh start (not from On Hold) | Reminder dialog |
| JOB-32 | No backup reminder | Resuming from "On Hold" | No reminder |
| JOB-33 | Blocked - deposit unpaid | Deposit invoice unpaid | Error: deposit must be paid |
| JOB-34 | Actual Start Date set | After starting | Current date |
| JOB-35 | Status email sent | After starting | "In Progress" email to client |

### 5.6 putJobOnHold()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| JOB-40 | Puts job on hold | Job "In Progress" | Status = "On Hold" |
| JOB-41 | Requires explanation | Called without explanation | Prompt for explanation |
| JOB-42 | Email with reason | Explanation provided | Email includes reason |

### 5.7 markJobComplete()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| JOB-50 | Completes job | Job "In Progress" | Status = "Completed" |
| JOB-51 | Credential cleanup reminder | After completion | Reminder dialog shown |
| JOB-52 | Completion email sent | After completion | Email to client |
| JOB-53 | Actual Completion Date set | After completion | Current date |
| JOB-54 | Prompt for invoice | After completion | "Generate Invoice?" dialog |

---

## 6. INVOICE WORKFLOW TESTS

### 6.1 generateAndSendDepositInvoice()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| INV-01 | Creates deposit invoice | Job >=200, just accepted | Invoice with 50% of total |
| INV-02 | Invoice type = "Deposit" | Deposit invoice | Type field = "Deposit" |
| INV-03 | Due date = TODAY | Deposit invoice | Due immediately |
| INV-04 | Invoice number generated | New invoice | INV-XXX format |
| INV-05 | Email sent automatically | After creation | Invoice email to client |
| INV-06 | Linked to job | Invoice created | Job # in invoice record |

### 6.2 generateInvoiceForJob()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| INV-10 | Creates balance invoice | Job completed, deposit paid | 50% of total |
| INV-11 | Creates final invoice | Job completed, no deposit | 100% of total |
| INV-12 | Invoice type correct | Balance vs Final | Type = "Balance" or "Final" |
| INV-13 | Job Payment Status updated | Invoice generated | "Invoiced" |

### 6.3 sendInvoiceEmail()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| INV-20 | Sends invoice | Valid invoice | Email with invoice details |
| INV-21 | Bank details included | Email sent | Bank name, account number |
| INV-22 | GST shown (if registered) | GST registered = Yes | GST number in email |
| INV-23 | Due date shown | Email sent | Clear due date |

### 6.4 sendInvoiceReminder()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| INV-30 | Sends friendly reminder | Invoice unpaid, approaching due | Reminder email |
| INV-31 | No late fee mentioned | Pre-due reminder | Friendly tone, no fees |

### 6.5 sendOverdueInvoice()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| INV-40 | Sends overdue notice | Invoice past due | Overdue email |
| INV-41 | Late fee calculated | Overdue invoice | Fee added to total |
| INV-42 | New total shown | With late fee | Original + late fee |

### 6.6 markInvoicePaid()
| Test ID | Description | Precondition | Expected |
|---------|-------------|--------------|----------|
| INV-50 | Updates invoice status | Invoice paid | Status = "Paid" |
| INV-51 | Payment date recorded | Mark paid | Current date |
| INV-52 | Payment method saved | Method selected | Method field updated |
| INV-53 | Payment reference saved | Reference entered | Reference field updated |
| INV-54 | Receipt email sent | Payment recorded | Receipt to client |
| INV-55 | Job Payment Status updated | All invoices paid | Job status = "Paid" |

---

## 7. EMAIL TEMPLATE TESTS

### 7.1 Template Rendering
| Test ID | Template | Description | Verify |
|---------|----------|-------------|--------|
| EMAIL-01 | email-admin-notification | Admin notification | Submission details correct |
| EMAIL-02 | email-user-confirmation | User confirmation | Submission number, message shown |
| EMAIL-03 | email-quote | Quote email | Amounts, Accept button link works |
| EMAIL-04 | email-invoice | Standard invoice | Bank details, amounts correct |
| EMAIL-05 | email-balance-invoice | Balance invoice | Shows 50%, "Balance Due" |
| EMAIL-06 | email-status-update | Status update | Status shown, appropriate message |
| EMAIL-07 | email-payment-receipt | Payment receipt | Payment method, reference shown |
| EMAIL-08 | email-invoice-reminder | Pre-due reminder | Friendly tone, due date |
| EMAIL-09 | email-overdue-invoice | Overdue notice | Late fees shown correctly |
| EMAIL-10 | email-quote-accepted | Acceptance confirmation | Job details, next steps |
| EMAIL-11 | email-quote-reminder | Quote reminder | Accept button works |

### 7.2 Email Styling
| Test ID | Description | Verify |
|---------|-------------|--------|
| EMAIL-20 | Colors from EMAIL_COLORS | Brand green, ink gray used |
| EMAIL-21 | Mobile responsive | Readable on mobile |
| EMAIL-22 | No broken images | All images load |
| EMAIL-23 | Links work | All buttons/links functional |

---

## 8. AUTOMATED TRIGGER TESTS

### 8.1 autoSendQuoteReminders()
| Test ID | Description | Condition | Expected |
|---------|-------------|-----------|----------|
| AUTO-01 | Sends reminder | Job "Quoted" > 7 days ago | Reminder sent |
| AUTO-02 | Doesn't send early | Job "Quoted" < 7 days | No reminder |
| AUTO-03 | Doesn't resend | Already "Quote Reminded" | No duplicate |

### 8.2 autoSendInvoiceReminders()
| Test ID | Description | Condition | Expected |
|---------|-------------|-----------|----------|
| AUTO-10 | Sends reminder | Invoice due in 3 days | Reminder sent |
| AUTO-11 | Doesn't send for paid | Invoice already paid | No reminder |

### 8.3 autoSendOverdueInvoices()
| Test ID | Description | Condition | Expected |
|---------|-------------|-----------|----------|
| AUTO-20 | Sends overdue | Invoice past due | Overdue notice sent |
| AUTO-21 | Late fee applied | Overdue invoice | Fee calculated |

### 8.4 updateAllLateFees()
| Test ID | Description | Expected |
|---------|-------------|----------|
| AUTO-30 | Updates all overdue invoices | Late fees recalculated |

---

## 9. EDGE CASES & ERROR HANDLING

### 9.1 Concurrent Operations
| Test ID | Description | Expected |
|---------|-------------|----------|
| EDGE-01 | Two users edit same job | No data corruption |
| EDGE-02 | Invoice generated twice | Warning or prevention |

### 9.2 Missing Data
| Test ID | Description | Expected |
|---------|-------------|----------|
| EDGE-10 | Job without email | Graceful handling, no email sent |
| EDGE-11 | Settings sheet missing | Error message, prompt setup |
| EDGE-12 | Jobs sheet missing | Error message, prompt setup |

### 9.3 Invalid States
| Test ID | Description | Expected |
|---------|-------------|----------|
| EDGE-20 | Start work on "Pending Quote" | Error: must be accepted first |
| EDGE-21 | Complete already completed job | Warning or prevention |
| EDGE-22 | Accept already accepted quote | Warning |

### 9.4 Data Integrity
| Test ID | Description | Expected |
|---------|-------------|----------|
| EDGE-30 | Delete job with invoices | Warning about linked data |
| EDGE-31 | Invoice total != job total | Warning or auto-correct |

---

## 10. CURL TEST SCRIPTS

### Setup
```bash
# Set the deployed web app URL
WEBAPP_URL="https://script.google.com/macros/s/AKfycbyBjf9TKEogrSWp5cLxs4tZWuGbIdWUYGn5oDGIBVWvVQWggNDjxZzgugrgo0s8LZ4stg/exec"
```

### 10.1 Health Check
```bash
curl -s "$WEBAPP_URL" | jq
# Expected: {"status":"ok",...}
```

### 10.2 Get Testimonials
```bash
# All approved
curl -s "$WEBAPP_URL?action=getTestimonials" | jq

# 5-star only, limit 3
curl -s "$WEBAPP_URL?action=getTestimonials&fiveStarOnly=true&limit=3" | jq
```

### 10.3 Contact Form Submission
```bash
curl -X POST "$WEBAPP_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "phone": "021 123 4567",
    "storeUrl": "https://test-store.myshopify.com",
    "message": "Test submission via curl"
  }' | jq
```

### 10.4 Quote Acceptance
```bash
curl -X POST "$WEBAPP_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "acceptQuote",
    "jobNumber": "J-TEST-123",
    "fullName": "Test Customer",
    "signature": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    "termsAccepted": "Yes"
  }' | jq
```

### 10.5 Testimonial Submission
```bash
curl -X POST "$WEBAPP_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "submitTestimonial",
    "jobNumber": "J-TEST-123",
    "name": "Test Customer",
    "businessName": "Test Store",
    "location": "Auckland",
    "rating": "5",
    "testimonial": "Great service! Test submission via curl.",
    "email": "test@example.com"
  }' | jq
```

### 10.6 Rate Limit Test
```bash
# Submit 6 times rapidly (should fail on 6th)
for i in {1..6}; do
  echo "Submission $i:"
  curl -s -X POST "$WEBAPP_URL" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"Rate Test\",
      \"email\": \"ratetest@example.com\",
      \"phone\": \"021 000 000$i\",
      \"storeUrl\": \"https://test.myshopify.com\",
      \"message\": \"Rate limit test $i\"
    }" | jq -r '.success'
done
```

### 10.7 Validation Tests
```bash
# Invalid email
curl -s -X POST "$WEBAPP_URL" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"notanemail","phone":"021123456","storeUrl":"https://test.com","message":"Test"}' | jq

# XSS attempt
curl -s -X POST "$WEBAPP_URL" \
  -H "Content-Type: application/json" \
  -d '{"name":"<script>alert(1)</script>","email":"test@test.com","phone":"021123456","storeUrl":"https://test.com","message":"XSS test"}' | jq

# Missing required field
curl -s -X POST "$WEBAPP_URL" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","phone":"021123456","storeUrl":"https://test.com","message":"Missing name"}' | jq
```

---

## Implementation Priority

1. **Web endpoint tests (curl scripts)** - Critical for deployed system
2. **Input validation tests** - Security critical
3. **Job workflow tests** - Core functionality
4. **Invoice workflow tests** - Financial accuracy
5. **Email templates** - Customer-facing
6. **Automated triggers** - Background reliability
7. **Edge cases** - Robustness

---

## Existing Test Functions in Tests.gs

The following test functions already exist and can be run from the CartCure menu:

| Function | Menu Location | Description |
|----------|---------------|-------------|
| `runAllTests()` | Script Editor | Basic tests for drive, debug files, form submission |
| `createTestSubmissions()` | CartCure > Setup | Creates 10 test submissions |
| `createTestTestimonials()` | CartCure > Setup | Creates 20 test testimonials |
| `createTestJobForTestimonials()` | CartCure > Setup | Creates completed job for testing |
| `sendAllTestEmails()` | CartCure > Setup | Sends all email types to info@cartcure.co.nz |

---

*Generated: 2025-01-28, Updated: 2026-02-07*
*Source: apps-script/*.gs analysis + JOB_FLOW_CHART.txt*
