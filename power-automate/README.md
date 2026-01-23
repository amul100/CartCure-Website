# CartCure Email Organization - Power Automate Flow

This folder contains the Power Automate flow configuration for automatically organizing CartCure emails into structured folders in your Microsoft 365 Outlook account (info@cartcure.co.nz).

## 📁 Folder Structure Created

```
Inbox/
└── Clients/
    ├── [Client Name 1]/
    │   ├── J-TIGER-042/
    │   │   ├── Invoices/
    │   │   │   └── Invoice emails here
    │   │   └── Other job emails (quotes, status updates)
    │   └── J-MAPLE-015/
    │       └── Job emails here
    └── [Client Name 2]/
        └── J-EAGLE-088/
            ├── Invoices/
            └── Other job emails
```

## 🚀 Quick Start

### Prerequisites
- Microsoft 365 Business account with info@cartcure.co.nz
- Access to Power Automate (included with MS 365)
- CartCure Google Sheets with Apps Script deployed as Web App

### Setup Steps (20 minutes)

#### Step 1: Deploy Apps Script Web App (5 minutes)

The `doGet()` function is already included in your Code.gs file (it auto-deploys with Git push). You just need to deploy it as a Web App:

1. Open your CartCure Google Sheet
2. Go to **Extensions > Apps Script**
3. The `doGet()` function should already be at the bottom of Code.gs (added automatically)
4. Click **Deploy > New deployment**
5. Click the gear icon ⚙️ next to "Select type"
6. Choose **Web app**
7. Configure:

8. Configure:
   - **Execute as:** Me (your Google account)
   - **Who has access:** Anyone
   - **Description:** Power Automate email organization endpoint
9. Click **Deploy**
10. ⚠️ **IMPORTANT:** Copy the **Web app URL** (looks like: `https://script.google.com/macros/s/AKfy...xyz/exec`)
11. Save this URL - you'll need it in Step 2

**Security Note:** The "Anyone" access is safe. This endpoint only returns client names for valid job numbers - no sensitive financial data is exposed.

#### Step 2: Import the Power Automate Flow (15 minutes)

1. Go to https://make.powerautomate.com
2. Sign in with your **info@cartcure.co.nz** account
3. Click **My flows** in the left sidebar
4. Click **Import** at the top
5. Click **Upload** and select `cartcure-email-organizer-flow.json` from this folder
6. Click **Import**
7. When prompted for connections:
   - Click **Select during import** next to "Office 365 Outlook"
   - Choose **Create new** connection
   - Sign in with info@cartcure.co.nz
   - Grant permissions
8. Click **Import** to finalize

#### Step 3: Configure Apps Script URL (5 minutes)

1. After importing, click on the flow name to open it
2. Click **Edit** at the top
3. Find the action called **Get_client_name_from_Google_Sheets**
4. Click on it to expand
5. Find the **uri** field (should show a placeholder URL)
6. Replace the URL with your Apps Script Web App URL from Step 1
7. The final URL should look like:
   ```
   https://script.google.com/macros/s/YOUR_ID_HERE/exec?action=getClientName&jobNumber=@{outputs('Build_full_job_number')}
   ```
   Keep the `?action=getClientName&jobNumber=...` part - only replace the base URL
8. Click **Save** at the top

#### Step 4: Test the Flow (5 minutes)

1. Click **Test** in the top-right corner
2. Select **Manually**
3. Click **Test** button
4. Send yourself a test email to info@cartcure.co.nz with subject:
   ```
   Test Email (J-TIGER-042)
   ```
5. Wait 1-2 minutes
6. Check your Outlook inbox - the email should be moved
7. You should see a new folder structure:
   ```
   Clients/[Client Name]/J-TIGER-042/
   ```
8. If successful, you'll see green checkmarks in the flow run history
9. If failed, click on the failed step to see error details

**Common Test Issues:**
- **404 error on HTTP call:** Apps Script URL is incorrect or not deployed
- **Folder not created:** Outlook permissions not granted - reconnect Office 365
- **Email not moved:** Job number not found in subject line - check format (J-WORD-XXX)

#### Step 5: Enable the Flow

1. If test was successful, click **Turn on** at the top
2. The flow will now run automatically on every new email
3. Monitor the first few emails to ensure everything works

## 📊 Monitoring & Maintenance

### Check Flow Runs
1. Go to https://make.powerautomate.com
2. Click **My flows**
3. Click on **CartCure Email Organizer**
4. Click **Run history** to see all executions
5. Green = success, Red = failed
6. Click any run to see details

### Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| Emails not moving | Flow is turned OFF | Turn flow ON in Power Automate |
| Emails not moving | No job number in subject | Ensure subject contains (J-WORD-XXX) format |
| 404 HTTP error | Apps Script not deployed | Redeploy Apps Script as Web App |
| 401 HTTP error | Apps Script permissions changed | Redeploy with "Anyone" access |
| Folder creation failed | Outlook permissions expired | Reconnect Office 365 connection |
| Client name shows "Unknown" | Job not found in Google Sheets | Verify job number exists in Jobs sheet |

### Flow Usage Limits

**Office 365 Business Plans:**
- Basic: 750 runs/month (sufficient for ~25 emails/day)
- Premium: Unlimited runs

**Check your usage:**
1. Go to https://make.powerautomate.com
2. Click gear icon ⚙️ (Settings)
3. View **My licenses**

**Current email volume estimate:** 50-100 emails/month = Well within free limits

## 🔧 Customization Options

### Change Folder Structure

The default structure is: `Clients/[Client Name]/[Job Number]/Invoices`

**To organize by Job Number instead of Client Name:**

1. Edit the flow
2. Find action **Build_client_folder_path**
3. Change the formula from:
   ```
   Clients/@{body('Parse_client_name_response')?['clientName']}
   ```
   To:
   ```
   Clients
   ```
4. Find action **Build_job_folder_path**
5. Change from:
   ```
   @{outputs('Build_client_folder_path')}/@{outputs('Build_full_job_number')}
   ```
   To:
   ```
   Clients/@{outputs('Build_full_job_number')}
   ```
6. Save

**Result:** `Clients/J-TIGER-042/Invoices`

### Add More Subfolder Types

To create separate folders for Quotes, Payments, etc.:

1. Edit the flow
2. Find the action **Check_if_invoice_email**
3. Duplicate this entire condition block
4. Change the condition to check for different keywords:
   - For Quotes: `contains(toLower(triggerBody()?['subject']), 'quote')`
   - For Payments: `contains(toLower(triggerBody()?['subject']), 'paid')`
5. Update folder path to `@{outputs('Build_job_folder_path')}/Quotes`
6. Save

### Disable Auto-Read

By default, organized emails are marked as read. To keep them unread:

1. Edit the flow
2. Find action **Mark_email_as_read**
3. Click the **...** (three dots) on the action
4. Click **Delete**
5. Save

## 📝 Git Workflow

### Committing Changes

After making changes in Power Automate's visual editor:

1. Go to https://make.powerautomate.com
2. Click **My flows**
3. Click **...** (three dots) next to your flow
4. Click **Export > Package (.zip)**
5. Choose "Update" (not "Create as new")
6. Click **Export**
7. Download the ZIP file
8. Extract it and find the JSON file
9. Replace `cartcure-email-organizer-flow.json` with the new version
10. Commit and push to Git:
   ```bash
   git add power-automate/
   git commit -m "Update Power Automate flow configuration"
   git push origin main
   ```

### Deploying Changes from Git

When you pull changes from Git:

1. Go to https://make.powerautomate.com
2. Turn OFF the old flow (don't delete yet - as backup)
3. Import the updated JSON file (see Step 2 above)
4. Test the new flow
5. If successful, delete the old flow
6. If failed, turn the old flow back ON and troubleshoot

## 🧪 Testing Scenarios

### Test Case 1: New Job Email
**Send:** Email with subject `Test Job Started (J-NEWTEST-001)`
**Expected:**
- Creates `Clients/[Client]/J-NEWTEST-001/`
- Moves email to this folder
- Email marked as read

### Test Case 2: Invoice Email
**Send:** Email with subject `Invoice INV-TIGER-042 (J-TIGER-042)`
**Expected:**
- Creates `Clients/[Client]/J-TIGER-042/Invoices/` (if not exists)
- Moves email to Invoices subfolder
- Email marked as read

### Test Case 3: Non-Job Email
**Send:** Email with subject `Random email no job number`
**Expected:**
- Email stays in Inbox
- No folders created
- Flow terminates early (shows as "Succeeded" in run history)

### Test Case 4: Multiple Emails Same Job
**Send:** 3 emails with subject containing `(J-TIGER-042)`
**Expected:**
- All 3 go to same folder
- Folder only created once (subsequent emails reuse it)

## 🔐 Security & Privacy

### What Data is Shared?
- **Apps Script endpoint:** Only exposes client names for valid job numbers
- **Power Automate:** Only accesses your info@cartcure.co.nz mailbox
- **No external services:** Data stays between Google Sheets and Microsoft 365

### Permissions Granted
- **Apps Script:** Read access to Jobs sheet (client names only)
- **Power Automate:** Read/write access to Outlook folders and emails
- **No third parties:** No data sent outside Microsoft/Google ecosystems

### Revoking Access
To stop the automation:
1. Turn OFF the flow in Power Automate
2. Delete the Office 365 connection
3. (Optional) Undeploy the Apps Script Web App

## 📚 Additional Resources

- [Power Automate Documentation](https://docs.microsoft.com/en-us/power-automate/)
- [Office 365 Outlook Connector Reference](https://docs.microsoft.com/en-us/connectors/office365/)
- [Apps Script Web Apps Guide](https://developers.google.com/apps-script/guides/web)

## 🐛 Troubleshooting Deep Dive

### Flow Shows "Failed" in Run History

1. Click on the failed run
2. Look for the red X icon on a specific action
3. Common failures:

**Action: Get_client_name_from_Google_Sheets**
- Error: `404 Not Found`
  - **Fix:** Apps Script URL is wrong or not deployed
  - **Check:** Can you access the URL in a browser? It should return JSON.

- Error: `401 Unauthorized`
  - **Fix:** Apps Script deployment access changed to "Only myself"
  - **Check:** Redeploy with "Anyone" access

**Action: Move_email_to_job_folder**
- Error: `Folder not found`
  - **Fix:** Previous folder creation action failed
  - **Check:** Look at earlier actions in the run to find which folder creation failed

- Error: `Insufficient permissions`
  - **Fix:** Office 365 connection expired
  - **Solution:** Edit flow > Reconnect Office 365 Outlook

### Emails Going to Wrong Folders

**Symptom:** All emails going to "Unknown Client" folder

**Cause:** Apps Script can't find the job in Google Sheets

**Fix:**
1. Check if job number exists in Jobs sheet
2. Verify job number format in email matches exactly (J-WORD-XXX)
3. Test Apps Script endpoint directly:
   - Open browser
   - Paste URL: `https://script.google.com/.../exec?action=getClientName&jobNumber=J-TIGER-042`
   - Should return: `{"success":true,"jobNumber":"J-TIGER-042","clientName":"John Smith"}`

### Flow Not Triggering

**Symptom:** New emails arrive but flow doesn't run

**Causes & Fixes:**
1. **Flow is OFF:** Turn it ON in Power Automate
2. **Email going to different folder:** Trigger only monitors Inbox
3. **Subject doesn't contain (J-XXX):** Flow skips emails without job numbers
4. **Office 365 webhook expired:** Edit flow, save without changes (refreshes webhook)

## 🎯 Success Metrics

After 1 week, you should see:
- ✅ All job-related emails automatically organized
- ✅ Easy to find all emails for a specific client/job
- ✅ info@cartcure.co.nz inbox stays clean
- ✅ Audit trail maintained (all CC'd emails in organized folders)

## 💡 Tips & Best Practices

1. **Include job number in ALL client emails:** Ensure your email templates always include the job number in the subject line for automatic organization

2. **Standardize subject format:** Keep the format consistent:
   - Good: `"Your Job is Complete (J-TIGER-042)"`
   - Good: `"Invoice INV-TIGER-042 (J-TIGER-042)"`
   - Bad: `"Job J-TIGER-042 update"` (job number not in parentheses)

3. **Check run history weekly:** Catch any issues early by reviewing failed runs

4. **Keep Apps Script deployed:** Don't undeploy the Web App or the folder organization will break

5. **Backup your flow:** Export the flow JSON monthly and commit to Git

## 📞 Support

If you encounter issues not covered here:
1. Check Power Automate run history for error details
2. Test Apps Script endpoint directly in browser
3. Verify job exists in Google Sheets
4. Check Office 365 connection is active

---

**Last Updated:** January 2026
**Version:** 1.0
**Maintained by:** CartCure Team
