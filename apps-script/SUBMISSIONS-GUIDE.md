# Submissions Sheet Guide

## Overview
The Submissions sheet is now fully integrated into the CartCure Job Management System with professional styling, status tracking, and seamless workflow integration.

## Features

### 1. Professional Formatting
- **CartCure Green Headers** (#2d5d3f): Matches the branding across all sheets
- **Frozen Header Row**: Headers stay visible when scrolling
- **Optimized Column Widths**: All columns are sized for easy reading
- **Protected Headers**: Header row is protected with warning (prevents accidental edits)
- **Sortable & Filterable**: Built-in filters for all columns

### 2. Status Tracking
Every submission now has a **Status** column with 5 possible values:

| Status | Color | Meaning |
|--------|-------|---------|
| **New** | Blue | Fresh submission that needs review |
| **In Review** | Yellow | Being evaluated/processed |
| **Job Created** | Green | Successfully converted to a job |
| **Declined** | Gray | Quote declined or not pursuing |
| **Spam** | Red | Spam or invalid submission |

#### Status Colors
- **New**: Blue background (#cfe2ff) with dark blue text - stands out for attention
- **In Review**: Yellow background (#fff3cd) - indicates work in progress
- **Job Created**: Green background (#d4edda) - success state
- **Declined**: Gray background (#e9ecef) - closed/archived
- **Spam**: Red background (#ffcccc) - rejected

### 3. Automatic Status Updates
- **New Submissions**: Automatically set to "New" when form is submitted
- **Job Creation**: Status automatically updates to "Job Created" when you use "Create Job from Submission"
- **Manual Updates**: You can manually change status via dropdown

### 4. Data Validation
- Status column has dropdown validation (can only select valid statuses)
- Prevents typos and ensures consistency

## Setup Instructions

### First Time Setup
1. Open your Google Sheet
2. Go to **🛒 CartCure > ⚙️ Setup Sheets**
3. The Submissions sheet will be automatically created/updated with:
   - Professional formatting
   - Status column
   - Conditional formatting
   - Data validation
   - Filters

### Updating Existing Submissions Sheet
If you already have a Submissions sheet with data:
1. Run **🛒 CartCure > ⚙️ Setup Sheets**
2. The script will:
   - Preserve all existing submission data
   - Add the Status column
   - Set all existing submissions to "New" status
   - Apply formatting and validation

## Workflow Integration

### Complete Workflow
1. **Form Submitted** → New row added with Status = "New"
2. **Review Submission** → Change status to "In Review"
3. **Create Job** → Use "🛒 CartCure > 📋 Jobs > Create Job from Submission"
   - Status automatically changes to "Job Created"
   - New job created in Jobs sheet
4. **Alternative Actions**:
   - Mark as "Declined" if quote is rejected
   - Mark as "Spam" if submission is invalid

### Using the Status Column

#### To Filter by Status:
1. Click the filter icon in the Status column header
2. Select which statuses to show
3. Example: Filter to show only "New" submissions to see what needs attention

#### To Update Status Manually:
1. Click any cell in the Status column
2. Use the dropdown to select new status
3. Status formatting will update automatically

## Column Reference

| Column | Description |
|--------|-------------|
| **Submission #** | Unique ID (CC-YYYYMMDD-XXXXX) |
| **Timestamp** | When form was submitted |
| **Name** | Client name |
| **Email** | Client email address |
| **Store URL** | Shopify store URL |
| **Message** | Text message from client |
| **Has Voice Note** | Yes/No indicator |
| **Voice Note Link** | Link to audio file in Drive |
| **Status** | Submission status (New/In Review/etc.) |

## Tips & Best Practices

### 1. Daily Workflow
- Filter Status = "New" to see submissions needing attention
- Review new submissions and change to "In Review"
- Create jobs for valid requests
- Mark spam/invalid submissions appropriately

### 2. Tracking Conversions
- Filter Status = "Job Created" to see successful conversions
- Filter Status = "Declined" to track rejection rate
- Use Status column to measure submission quality

### 3. Keeping It Clean
- Regularly update statuses to keep the sheet organized
- Use "Spam" status to identify and learn from invalid submissions
- Archive old submissions by hiding/moving them

### 4. Integration with Jobs Sheet
- When creating a job, the Submission # is automatically linked
- You can always reference the original submission from the Jobs sheet
- Status update is automatic - no manual tracking needed

## Troubleshooting

### Status Column Missing?
Run **🛒 CartCure > ⚙️ Setup Sheets** to add it.

### Statuses Not Updating Automatically?
Make sure you're using the "Create Job from Submission" function from the CartCure menu, not manually copying data.

### Colors Not Showing?
The conditional formatting is applied automatically. Try refreshing the sheet or re-running Setup Sheets.

### Can't Edit Status?
Click directly on a cell in the Status column and use the dropdown arrow that appears.

## Future Enhancements (Coming Soon)
- Dashboard widget showing submission statistics
- Email notifications for new submissions
- Bulk status updates
- Submission aging alerts (submissions older than X days with no action)

---

**Questions or Issues?** Check the main CartCure Job Management documentation or contact support.
