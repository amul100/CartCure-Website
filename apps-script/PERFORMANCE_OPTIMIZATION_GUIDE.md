# CartCure Performance Optimization Guide

## PROMPT FOR NEW CONTEXT - COPY THIS:

```
Continue implementing performance optimizations in the apps-script/*.gs files.

Read apps-script/PERFORMANCE_OPTIMIZATION_GUIDE.md for full details.

COMPLETED:
- Settings caching (already worked)
- Column index caching in refreshDashboard() (Tests.gs)
- Column index caching in refreshAnalytics() with consolidated single metrics loop (Setup.gs)
- Column index caching in showOverdueJobs(), showOutstandingPayments(), showMonthlySummary() (Setup.gs)
- autoSendQuoteReminders(), autoSendInvoiceReminders(), autoSendOverdueInvoices() already had proper caching (Operations.gs)

TODO (if needed):
- Batch setValue operations in updateAllSLAStatus() (more complex, low priority)
- TextFinder for invoice lookups (if performance issues persist)

Pattern to follow: See refreshDashboard() in Tests.gs or refreshAnalytics() in Setup.gs for examples of column caching.
```

---

## Purpose
This document describes caching optimizations implemented across the `apps-script/*.gs` files to make operations run faster. Use this as a prompt for Claude to continue implementation.

---

## What is Caching (Quick Recap)
Instead of loading the same data multiple times during one operation, load it once and reuse it. The cache automatically clears when the operation ends (Google Apps Script behavior).

---

## Existing Cache Infrastructure

The code ALREADY has a caching system in Config.gs:

```javascript
// Cache object (in Config.gs)
var _cache = {
  spreadsheet: null,
  sheets: {},
  settings: null,
  settingsLoaded: false
};

// getAllSettings() - loads settings once, caches them (in Config.gs)
function getAllSettings() {
  if (_cache.settingsLoaded) {
    return _cache.settings;
  }
  // ... loads from sheet, caches result
}

// getSettingCached() - uses the cache (in Config.gs)
function getSettingCached(settingName) {
  const settings = getAllSettings();
  return settings.hasOwnProperty(settingName) ? settings[settingName] : null;
}
```

**Problem:** Many functions use `getSetting()` instead of `getSettingCached()`, bypassing the cache.

---

## OPTIMIZATION 1: Settings Caching - ALREADY DONE ✓

**Status:** Already implemented! `getSetting()` already calls `getSettingCached()` which uses the cache.

```javascript
// getSetting already uses cache (in Operations.gs)
function getSetting(settingName) {
  return getSettingCached(settingName);
}
```

No changes needed for settings caching.

---

## OPTIMIZATION 2: Replace getSetting() with getSettingCached()

### Files to Search
- All `apps-script/*.gs` files (primarily Operations.gs, Email.gs, Setup.gs)

### How to Find
Search for: `getSetting('` (with single quote)
Replace with: `getSettingCached('`

### Exceptions - Do NOT replace these:
- Inside `getAllSettings()` function itself
- Inside `updateSetting()` function
- Any function that WRITES to settings

### Expected locations (approximate line numbers may have shifted):
- `sendQuoteEmail()` - multiple getSetting calls
- `sendInvoiceEmail()` - multiple getSetting calls
- `sendQuoteReminderAuto()` - ~6 getSetting calls
- `sendInvoiceReminderAuto()` - ~6 getSetting calls
- `sendOverdueInvoiceAuto()` - ~6 getSetting calls
- `generateInvoice()` - multiple getSetting calls
- `createQuotePage()` - multiple getSetting calls
- `handleQuoteAcceptance()` - multiple getSetting calls
- Various other email/document generation functions

---

## OPTIMIZATION 2: Cache Column Indices in Loops

### Problem
Functions like `refreshDashboard()` call `headers.indexOf('Column Name')` inside loops, doing the same lookup 30+ times.

### Pattern - Before:
```javascript
const headers = data[0];
for (let i = 1; i < data.length; i++) {
  const row = data[i];
  const status = row[headers.indexOf('Status')];  // Called every iteration!
  const client = row[headers.indexOf('Client Name')];  // Called every iteration!
}
```

### Pattern - After:
```javascript
const headers = data[0];
// Cache indices ONCE before loop
const cols = {
  status: headers.indexOf('Status'),
  client: headers.indexOf('Client Name'),
  // ... all needed columns
};

for (let i = 1; i < data.length; i++) {
  const row = data[i];
  const status = row[cols.status];  // Direct array access - instant
  const client = row[cols.client];  // Direct array access - instant
}
```

### Functions to Update:
1. `refreshDashboard()` (Tests.gs) - DONE
2. `refreshAnalytics()` (Setup.gs) - DONE
3. `autoSendQuoteReminders()` (Operations.gs) - already had caching
4. `autoSendInvoiceReminders()` (Operations.gs) - already had caching
5. `autoSendOverdueInvoices()` (Operations.gs) - already had caching
6. `archiveOldJobs()` (Setup.gs)
7. `archiveOldActivity()` (Setup.gs)
8. Any function that loops through sheet data with indexOf inside

---

## OPTIMIZATION 3: Consolidate Analytics Loops

### Problem
`refreshAnalytics()` (in Setup.gs) loops through jobs data 5 separate times to calculate different metrics.

### Current Pattern (Setup.gs - now consolidated):
```javascript
// Loop 1: Calculate revenue
jobs.forEach(row => { if (paid) totalRevenue += amount; });

// Loop 2: Count completed
const completedJobs = jobs.filter(row => status === 'Completed').length;

// Loop 3: Count on-time
const onTimeJobs = jobs.filter(row => status === 'Completed' && sla !== 'OVERDUE').length;

// Loop 4: Count by status
jobs.forEach(row => { statusCounts[status]++; });

// Loop 5: Count by payment
jobs.forEach(row => { paymentCounts[payment]++; });
```

### Optimized Pattern:
```javascript
// Single loop calculates everything
const metrics = {
  totalRevenue: 0,
  completedJobs: 0,
  onTimeJobs: 0,
  statusCounts: {},
  paymentCounts: {}
};

jobs.forEach(row => {
  const status = row[cols.status];
  const payment = row[cols.payment];
  const amount = parseFloat(row[cols.amount]) || 0;
  const sla = row[cols.sla];

  // Revenue
  if (payment === PAYMENT_STATUS.PAID) {
    metrics.totalRevenue += amount;
  }

  // Completed count
  if (status === JOB_STATUS.COMPLETED) {
    metrics.completedJobs++;
    if (sla !== 'OVERDUE') metrics.onTimeJobs++;
  }

  // Status counts
  metrics.statusCounts[status] = (metrics.statusCounts[status] || 0) + 1;

  // Payment counts
  metrics.paymentCounts[payment] = (metrics.paymentCounts[payment] || 0) + 1;
});
```

---

## OPTIMIZATION 4: Batch setValue Operations

### Problem
`updateAllSLAStatus()` (in Tests.gs) calls individual `setValue()` inside a loop.

### Current Pattern (Tests.gs):
```javascript
for (let i = 0; i < updates.length; i++) {
  sheet.getRange(row, col1).setValue(updates[i].daysSince);
  sheet.getRange(row, col2).setValue(updates[i].daysRemaining);
  sheet.getRange(row, col3).setValue(updates[i].slaStatus);
}
// 3 API calls per job = 90 calls for 30 jobs
```

### Optimized Pattern:
```javascript
// Build all values first
const daysSinceValues = updates.map(u => [u.daysSince]);
const daysRemainingValues = updates.map(u => [u.daysRemaining]);
const slaStatusValues = updates.map(u => [u.slaStatus]);

// Use RangeList for batch update (3 API calls total, regardless of job count)
if (updates.length > 0) {
  const daysSinceRanges = updates.map(u => `${daysSinceCol}${u.row}`);
  sheet.getRangeList(daysSinceRanges).setValues(daysSinceValues);
  // ... repeat for other columns
}
```

---

## OPTIMIZATION 5: Use TextFinder for Invoice Lookups

### Problem
`getInvoicesByJobNumber()` (in Operations.gs) loads ALL invoices then loops through them.

### Current Pattern (Operations.gs):
```javascript
const allData = sheet.getDataRange().getValues();  // Load ALL invoices
for (let i = 1; i < allData.length; i++) {
  if (row[jobNumCol] === jobNumber) {
    // Found match
  }
}
```

### Optimized Pattern:
```javascript
// Use TextFinder (Google's server-side search - much faster)
const jobNumCol = getColIndex('INVOICES', 'Job #');
const finder = sheet.getRange(1, jobNumCol, sheet.getLastRow(), 1)
  .createTextFinder(jobNumber)
  .matchEntireCell(true);

const matches = finder.findAll();
const invoices = [];
const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];

for (const match of matches) {
  const rowNum = match.getRow();
  const rowData = sheet.getRange(rowNum, 1, 1, headers.length).getValues()[0];
  // Build invoice object from rowData
}
```

---

## Implementation Order (Priority)

1. ✅ **getSetting → getSettingCached** - Already implemented (getSetting calls getSettingCached)
2. ✅ **Column index caching in loops** - Done in refreshDashboard, refreshAnalytics, showOverdueJobs, showOutstandingPayments, showMonthlySummary
3. ✅ **Consolidate analytics loops** - Done in refreshAnalytics (5 loops → 1 single metrics loop)
4. ⏳ **TextFinder for invoice lookups** (if time permits)
5. ⏳ **Batch setValue operations** (more complex, do last)

---

## Testing After Changes

1. Run **Setup/Repair Sheets** - should complete without errors
2. **Send a test quote** - verify all fields populate correctly
3. **Refresh Dashboard** - should be noticeably faster
4. **Create a job from submission** - verify it works
5. Check **Activity Log** - verify entries are created

---

## Notes

- The cache clears automatically between operations (safe)
- Don't cache data that changes DURING an operation (rare)
- Changes may be in any `apps-script/*.gs` file depending on the function location
- After changes, run `git push` (clasp auto-deploys for menu functions)
- If doPost functions are modified (Code.gs), also run clasp deploy

---

## File Locations
- **Cache system**: `apps-script/Config.gs` (`_cache` object, `getAllSettings()`, `getSettingCached()`)
- **Dashboard**: `apps-script/Tests.gs` (`refreshDashboard()`, `updateAllSLAStatus()`)
- **Analytics/Reports**: `apps-script/Setup.gs` (`refreshAnalytics()`, `showOverdueJobs()`, etc.)
- **Auto-reminders**: `apps-script/Operations.gs` (`autoSendQuoteReminders()`, etc.)
- **Invoice lookups**: `apps-script/Operations.gs` (`getInvoicesByJobNumber()`)
