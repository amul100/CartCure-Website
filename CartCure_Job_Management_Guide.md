# CartCure Job Management System
## Deployment & User Guide

---

# Part 1: Deployment Instructions

## Prerequisites
- Access to your Google Apps Script project
- The CartCure Google Sheet (already configured)
- Clasp CLI installed (for deployment)

---

## Step 1: Deploy the Updated Code

Open a terminal in the `apps-script` folder and run:

```
clasp push
```

This uploads the new Code.gs to your Google Apps Script project.

---

## Step 2: Run Initial Setup

1. Open your CartCure Google Sheet
2. Refresh the page (F5 or Ctrl+R)
3. Wait for the custom menu to appear (may take a few seconds)
4. Click: **CartCure > Setup Sheets**
5. Authorize the script when prompted
6. Wait for "Setup Complete" confirmation

This creates four new sheets:
- **Dashboard** - Your daily workflow view
- **Jobs** - All job tracking data
- **Invoice Log** - Invoice records
- **Settings** - Your business configuration

---

## Step 3: Configure Your Settings

Go to the **Settings** sheet and fill in:

| Setting | What to Enter |
|---------|---------------|
| Business Name | CartCure (or your business name) |
| GST Registered | Yes or No |
| GST Number | Your GST number (if registered) |
| Bank Account | Your bank account number |
| Bank Name | Your bank name (ANZ, ASB, etc.) |
| Admin Email | Your email for notifications |

Leave the other settings at their defaults unless you want to change them.

---

## Step 4: Verify Deployment

Test that everything works:

1. Click **CartCure > Dashboard > Refresh Dashboard**
2. Check that no errors appear
3. The Dashboard should show "Last refreshed: [current time]"

---

# Part 2: Daily Workflow

## Your Morning Routine

1. **Open the Dashboard sheet**
   - This is your command center
   - Shows all active jobs sorted by urgency

2. **Check the Summary Metrics**
   - Jobs OVERDUE (red) - Handle these first!
   - Jobs AT RISK (yellow) - Due within 2 days
   - Jobs In Progress - Currently being worked on

3. **Click "Refresh Dashboard"** to update all calculations

---

## Processing a New Submission

When a customer submits a request via your website:

### Step 1: Create a Job
1. Go to **CartCure > Jobs > Create Job from Submission**
2. Enter the Submission # (e.g., CC-20260121-12345)
3. Click OK

### Step 2: Prepare the Quote
1. Go to the **Jobs** sheet
2. Find your new job (JOB-001, JOB-002, etc.)
3. Fill in:
   - **Category**: Design, Content, Bug Fix, Improvement, App Setup, or Other
   - **Quote Amount (excl GST)**: Your price (e.g., 100)
   - **Job Description**: Refine the description if needed
   - **Estimated Turnaround**: Days to complete (default: 7)

### Step 3: Send the Quote
1. Go to **CartCure > Quotes > Send Quote**
2. Enter the Job # (e.g., JOB-001)
3. Click OK

The client receives a professional quote email with:
- Scope of work
- Pricing (with GST breakdown if registered)
- Turnaround time
- "Accept Quote" button
- Your bank details

---

## When Client Accepts a Quote

1. Go to **CartCure > Jobs > Mark Quote Accepted**
2. Enter the Job #
3. Click OK

**Important**: This starts the 7-day SLA clock!

The system now tracks:
- Days Since Accepted
- Days Remaining
- SLA Status (On Track / AT RISK / OVERDUE)

---

## Working on a Job

### Start Work
1. Go to **CartCure > Jobs > Start Work on Job**
2. Enter the Job #
3. Status changes to "In Progress"

### Complete the Job
1. Go to **CartCure > Jobs > Mark Job Complete**
2. Enter the Job #
3. You'll be asked if you want to generate an invoice

### Put on Hold (if needed)
1. Go to **CartCure > Jobs > Put Job On Hold**
2. Enter the Job #
3. Use this when waiting for client info

---

## Invoicing & Payments

### Generate an Invoice
1. Go to **CartCure > Invoices > Generate Invoice**
2. Enter the Job #
3. Invoice number is auto-generated (INV-2026-001)

### Send the Invoice
1. Go to **CartCure > Invoices > Send Invoice**
2. Enter the Invoice # (e.g., INV-2026-001)
3. Client receives professional invoice email

### Record Payment
1. Go to **CartCure > Invoices > Mark as Paid**
2. Enter the Invoice #
3. Enter payment method (Bank Transfer, Stripe, etc.)
4. Enter reference number (optional)

---

# Part 3: Understanding the Dashboard

## Summary Metrics Section

| Metric | What It Means |
|--------|---------------|
| Jobs OVERDUE | Past their due date - handle immediately |
| Jobs AT RISK | Due within 2 days - prioritize these |
| Jobs In Progress | Currently being worked on |
| Jobs Awaiting Quote | Need quotes prepared |
| Pending Quotes (sent) | Waiting for client response |
| Unpaid Invoices | Total $ outstanding |
| Revenue This Month | Paid invoices this month |

## Active Jobs Section

Shows jobs sorted by urgency:
- **OVERDUE** (red) - Negative days remaining
- **AT RISK** (yellow) - 1-2 days remaining
- **On Track** (green) - 3+ days remaining

Oldest/most urgent jobs appear first.

## Pending Quotes Section

Shows quotes awaiting client response:
- Sorted by how long they've been waiting
- "Follow up!" appears after 5 days

---

# Part 4: SLA Tracking

## The 7-Day Promise

Your SLA clock starts when you click "Mark Quote Accepted".

| Days Remaining | Status | Color | Action |
|----------------|--------|-------|--------|
| 3+ days | On Track | Green | Normal priority |
| 1-2 days | AT RISK | Yellow | Prioritize this job |
| 0 or less | OVERDUE | Red | Complete immediately |

## Keeping on Track

1. **Refresh Dashboard daily** - Updates all SLA calculations
2. **Work OVERDUE jobs first** - They're past due
3. **Then AT RISK jobs** - Due within 2 days
4. **Then On Track jobs** - In order of due date

---

# Part 5: Reports

## Overdue Jobs Report
**CartCure > Reports > Overdue Jobs**

Lists all jobs that are past their due date.

## Outstanding Payments Report
**CartCure > Reports > Outstanding Payments**

Shows:
- Total amount outstanding
- List of unpaid jobs with amounts

## Monthly Summary
**CartCure > Reports > Monthly Summary**

Shows for current month:
- Jobs Started
- Jobs Completed
- Revenue Collected

---

# Part 6: GST Handling

## If You're GST Registered

1. Go to Settings sheet
2. Set "GST Registered" to "Yes"
3. Enter your GST Number

Quotes and invoices will show:
- Subtotal (excl GST)
- GST (15%)
- Total (incl GST)
- Your GST number in footer

## If You're NOT GST Registered

1. Go to Settings sheet
2. Set "GST Registered" to "No"

Quotes and invoices will show:
- Total amount only (no GST breakdown)

---

# Part 7: Quick Reference

## Menu Locations

| Action | Menu Path |
|--------|-----------|
| Refresh Dashboard | CartCure > Dashboard > Refresh Dashboard |
| Create Job | CartCure > Jobs > Create Job from Submission |
| Accept Quote | CartCure > Jobs > Mark Quote Accepted |
| Start Work | CartCure > Jobs > Start Work on Job |
| Complete Job | CartCure > Jobs > Mark Job Complete |
| Send Quote | CartCure > Quotes > Send Quote |
| Send Reminder | CartCure > Quotes > Send Quote Reminder |
| Generate Invoice | CartCure > Invoices > Generate Invoice |
| Send Invoice | CartCure > Invoices > Send Invoice |
| Mark Paid | CartCure > Invoices > Mark as Paid |

## Job Status Flow

```
Pending Quote → Quoted → Accepted → In Progress → Completed
                  ↓                      ↓
              Declined              On Hold
```

## Payment Status Flow

```
Unpaid → Invoiced → Paid
```

---

# Part 8: Troubleshooting

## Menu Not Appearing
- Refresh the page
- Wait 5-10 seconds for scripts to load
- Try closing and reopening the spreadsheet

## "Sheet Not Found" Error
- Run **CartCure > Setup Sheets** again
- Check that all sheets exist (Dashboard, Jobs, Invoice Log, Settings)

## Quote Email Not Sending
- Check that Quote Amount is filled in
- Verify client email is correct in Jobs sheet
- Check Apps Script execution log for errors

## SLA Not Calculating
- Click **Refresh Dashboard** to update calculations
- Ensure "Quote Accepted Date" is set
- Check that status is "Accepted" or "In Progress"

---

# Part 9: Tips for Success

1. **Start each day with Dashboard** - Know your priorities

2. **Refresh Dashboard often** - Keeps SLA calculations current

3. **Update status promptly** - Keeps tracking accurate

4. **Send quotes same day** - Fast response wins jobs

5. **Follow up on old quotes** - Dashboard highlights 5+ day old quotes

6. **Complete jobs before OVERDUE** - Maintain your reputation

7. **Invoice immediately after completion** - Faster payment

8. **Record payments when received** - Accurate financial tracking

---

# Support

For issues with this system:
- Check the troubleshooting section above
- Review Google Apps Script execution logs
- Contact your developer for assistance

---

*CartCure Job Management System v1.0*
*Built for CartCure - Quick Shopify Fixes for NZ Businesses*
