// Email Template Preview Configuration
// This file provides sample data for local browser preview of Apps Script templates
// The previewer parses <?= ?> and <?!= ?> syntax and replaces with these values

const PREVIEW_CONFIG = {
  // Colors (must match EMAIL_COLORS in Code.gs)
  colors: {
    brandGreen: '#2d5d3f',
    brandGreenLight: '#3a7a52',
    paperWhite: '#f9f7f3',
    paperCream: '#faf8f4',
    paperBorder: '#d4cfc3',
    inkBlack: '#2b2b2b',
    inkGray: '#5a5a5a',
    inkLight: '#8a8a8a',
    alertBg: '#fff8e6',
    alertBorder: '#f5d76e',
    alertRed: '#c62828',
    alertRedBg: '#ffebee',
    depositBlue: '#1565c0',
    depositBlueDark: '#0d47a1',
    depositBlueBg: '#e3f2fd',
    depositBlueBorder: '#1976d2'
  },

  // Business settings (editable in UI)
  businessName: 'CartCure',
  isGSTRegistered: true,
  gstNumber: '123-456-789',
  gstRate: 0.15,
  bankName: 'ANZ',
  bankAccount: '01-0123-0123456-00',
  baseAmount: 150
};

// Sample data for each template type
const SAMPLE_DATA = {
  // Admin notification
  submissionNumber: 'CC-MAPLE-042',
  timestamp: new Date().toLocaleString('en-NZ', { timeZone: 'Pacific/Auckland' }),
  clientName: 'Sarah Thompson',
  clientEmail: 'sarah@example.com',
  clientPhone: '021 123 4567',
  storeUrl: 'https://sarahs-boutique.myshopify.com',
  messageHtml: 'I need help adding a size guide popup to my product pages and some mobile responsive fixes for the cart page.',
  voiceNoteHtml: '',
  sheetsUrl: 'https://docs.google.com/spreadsheets/d/example/edit',

  // Quote
  jobNumber: 'JOB-0042',
  jobDescription: 'Add size guide popup to product pages\nCustomize product image gallery layout\nMobile responsive adjustments for cart and checkout',
  turnaround: '7',
  validUntil: formatDate(addDays(new Date(), 14)),

  // Invoice
  invoiceNumber: 'INV-0042',
  headingTitle: 'Invoice',
  greetingText: 'Thank you for choosing CartCure! Please find your invoice below for the completed work.',
  invoiceDate: formatDate(new Date()),
  dueDate: formatDate(addDays(new Date(), 7)),

  // Status update
  status: 'In Progress',

  // Payment receipt
  paidDate: formatDate(new Date()),
  paymentMethod: 'Bank Transfer',
  feedbackUrl: 'https://cartcure.co.nz/feedback.html?job=JOB-0042',

  // Invoice reminder
  dueDateText: '<strong>tomorrow</strong>',

  // Overdue invoice
  daysOverdue: 14
};

// Helper functions
function formatDate(date) {
  return date.toLocaleDateString('en-NZ', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric'
  });
}

function addDays(date, days) {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
}

function formatCurrency(amount) {
  return '$' + parseFloat(amount).toFixed(2);
}

// Calculate pricing based on current settings
function calculatePricing() {
  const subtotal = PREVIEW_CONFIG.baseAmount;
  const gst = PREVIEW_CONFIG.isGSTRegistered ? subtotal * PREVIEW_CONFIG.gstRate : 0;
  const total = subtotal + gst;
  const deposit = total / 2;
  const requiresDeposit = total >= 200;

  return {
    subtotal: formatCurrency(subtotal),
    gst: formatCurrency(gst),
    total: formatCurrency(total),
    displayTotal: PREVIEW_CONFIG.isGSTRegistered ? formatCurrency(total) : formatCurrency(subtotal),
    depositAmount: formatCurrency(deposit),
    requiresDeposit: requiresDeposit,
    lateFee: formatCurrency(total * 0.02 * 14), // 2% per day for 14 days
    totalWithFees: formatCurrency(total * 1.28) // total + 28% late fees
  };
}

// Build dynamic HTML snippets that depend on settings
function buildDynamicHtml() {
  const pricing = calculatePricing();
  const c = PREVIEW_CONFIG.colors;

  // Pricing rows for invoice
  let pricingRowsHtml = '';
  if (PREVIEW_CONFIG.isGSTRegistered) {
    pricingRowsHtml = `
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${c.paperBorder};">
          <span style="color: ${c.inkGray};">Subtotal (excl. GST)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${c.paperBorder};">
          <span style="color: ${c.inkBlack}; font-weight: bold;">${pricing.subtotal}</span>
        </td>
      </tr>
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${c.paperBorder};">
          <span style="color: ${c.inkGray};">GST (15%)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${c.paperBorder};">
          <span style="color: ${c.inkBlack};">${pricing.gst}</span>
        </td>
      </tr>
      <tr style="background-color: ${c.brandGreen};">
        <td style="padding: 15px;"><span style="color: #ffffff; font-weight: bold;">TOTAL DUE (incl. GST)</span></td>
        <td align="right" style="padding: 15px;"><span style="color: #ffffff; font-size: 20px; font-weight: bold;">${pricing.total}</span></td>
      </tr>
    `;
  } else {
    pricingRowsHtml = `
      <tr style="background-color: ${c.brandGreen};">
        <td style="padding: 15px;"><span style="color: #ffffff; font-weight: bold;">TOTAL DUE</span></td>
        <td align="right" style="padding: 15px;"><span style="color: #ffffff; font-size: 20px; font-weight: bold;">${pricing.subtotal}</span></td>
      </tr>
    `;
  }

  // Deposit notice for quotes/invoices over $200
  let depositNoticeHtml = '';
  if (pricing.requiresDeposit) {
    depositNoticeHtml = `
      <tr>
        <td style="padding: 25px 40px 20px 40px;">
          <div style="background-color: ${c.depositBlueBg}; border: 3px solid ${c.depositBlue}; padding: 15px; border-radius: 4px;">
            <p style="margin: 0; color: ${c.depositBlueDark}; font-size: 16px; font-weight: bold;">50% Deposit Required</p>
            <p style="margin: 10px 0 0 0; color: ${c.inkBlack}; font-size: 13px; line-height: 1.6;">
              For jobs $200+, we require a 50% deposit (${pricing.depositAmount}) before work begins.<br>
              The remaining balance will be invoiced upon completion.
            </p>
          </div>
        </td>
      </tr>
    `;
  }

  // Bank section for quotes
  const bankSectionHtml = PREVIEW_CONFIG.bankAccount ? `
    <tr>
      <td style="padding: 0 40px 25px 40px;">
        <div style="background-color: ${c.alertBg}; border: 2px solid ${c.alertBorder}; padding: 15px;">
          <p style="margin: 0 0 10px 0; color: ${c.inkBlack}; font-weight: bold;">Payment Details (for your reference):</p>
          <p style="margin: 0; color: ${c.inkGray}; font-size: 14px; line-height: 1.6;">
            Bank: ${PREVIEW_CONFIG.bankName}<br>
            Account: ${PREVIEW_CONFIG.bankAccount}<br>
            Reference: ${SAMPLE_DATA.jobNumber}
          </p>
        </div>
      </td>
    </tr>
  ` : '';

  // Bank details for invoice
  const bankDetailsHtml = PREVIEW_CONFIG.bankAccount
    ? `Bank: ${PREVIEW_CONFIG.bankName}<br>Account: ${PREVIEW_CONFIG.bankAccount}<br>`
    : '';

  // Payment details for reminder/overdue
  const paymentDetailsHtml = PREVIEW_CONFIG.bankAccount ? `
    <tr>
      <td style="padding: 0 40px 25px 40px;">
        <div style="background-color: #e8f5e9; border: 2px solid #4caf50; padding: 15px;">
          <p style="margin: 0 0 10px 0; color: ${c.inkBlack}; font-weight: bold;">Payment Details:</p>
          <p style="margin: 0; color: ${c.inkGray}; font-size: 14px; line-height: 1.6;">
            Bank: ${PREVIEW_CONFIG.bankName}<br>
            Account: ${PREVIEW_CONFIG.bankAccount}<br>
            Reference: ${SAMPLE_DATA.invoiceNumber}
          </p>
        </div>
      </td>
    </tr>
  ` : '';

  // GST footer
  const gstFooterLine = PREVIEW_CONFIG.isGSTRegistered && PREVIEW_CONFIG.gstNumber
    ? `GST: ${PREVIEW_CONFIG.gstNumber}<br>`
    : '';

  // Status content for status update email
  let statusContentHtml = '';
  switch (SAMPLE_DATA.status) {
    case 'In Progress':
      statusContentHtml = `<p>Great news! We've started work on your job and are actively working on it.</p>`;
      break;
    case 'On Hold':
      statusContentHtml = `
        <p>We need to pause work on your job temporarily.</p>
        <div style="background-color: ${c.paperCream}; border-left: 4px solid ${c.brandGreen}; padding: 15px 20px; margin: 15px 0;">
          <p style="margin: 0; color: ${c.inkBlack}; font-size: 15px; line-height: 1.7;">
            <strong>Reason:</strong> Waiting for client to provide product images.
          </p>
        </div>
        <p><strong>Note:</strong> The 7-day SLA timer is also paused while your job is on hold.</p>
      `;
      break;
    case 'Completed':
      statusContentHtml = `
        <p>Excellent news! We've completed the work on your job.</p>
        <p>We'll be in touch shortly with the final details and invoice.</p>
        <div style="background-color: ${c.paperCream}; border: 2px solid ${c.paperBorder}; padding: 25px; margin: 20px 0; text-align: center;">
          <p style="margin: 0 0 10px 0; color: ${c.inkBlack}; font-size: 18px; font-weight: bold;">How was your experience?</p>
          <p style="margin: 0 0 20px 0; color: ${c.inkGray}; font-size: 14px;">We'd love to hear your feedback!</p>
          <a href="${SAMPLE_DATA.feedbackUrl}" style="display: inline-block; background-color: ${c.brandGreen}; color: #ffffff; padding: 15px 40px; text-decoration: none; font-size: 16px; font-weight: bold; border: 3px solid ${c.inkBlack}; box-shadow: 3px 3px 0 rgba(0,0,0,0.2);">Share Your Feedback</a>
        </div>
      `;
      break;
  }

  // Pricing HTML for payment receipt
  let pricingHtml = '';
  if (PREVIEW_CONFIG.isGSTRegistered) {
    pricingHtml = `
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${c.paperBorder};">
          <span style="color: ${c.inkGray};">Subtotal (excl. GST)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${c.paperBorder};">
          <span style="color: ${c.inkBlack};">${pricing.subtotal}</span>
        </td>
      </tr>
      <tr>
        <td style="padding: 12px 15px; border-bottom: 1px solid ${c.paperBorder};">
          <span style="color: ${c.inkGray};">GST (15%)</span>
        </td>
        <td align="right" style="padding: 12px 15px; border-bottom: 1px solid ${c.paperBorder};">
          <span style="color: ${c.inkBlack};">${pricing.gst}</span>
        </td>
      </tr>
      <tr style="background-color: ${c.brandGreen};">
        <td style="padding: 15px; color: #ffffff; font-size: 16px; font-weight: bold;">Total Paid</td>
        <td style="padding: 15px; color: #ffffff; font-size: 18px; font-weight: bold; text-align: right;">${pricing.total}</td>
      </tr>
    `;
  } else {
    pricingHtml = `
      <tr style="background-color: ${c.brandGreen};">
        <td style="padding: 15px; color: #ffffff; font-size: 16px; font-weight: bold;">Total Paid</td>
        <td style="padding: 15px; color: #ffffff; font-size: 18px; font-weight: bold; text-align: right;">${pricing.subtotal}</td>
      </tr>
    `;
  }

  return {
    pricingRowsHtml,
    depositNoticeHtml,
    bankSectionHtml,
    bankDetailsHtml,
    paymentDetailsHtml,
    gstFooterLine,
    statusContentHtml,
    pricingHtml,
    displayTotal: pricing.displayTotal,
    lateFee: pricing.lateFee,
    totalWithFees: pricing.totalWithFees
  };
}

// Get all template variables for rendering
function getTemplateVariables() {
  const dynamic = buildDynamicHtml();

  return {
    // Config values
    colors: PREVIEW_CONFIG.colors,
    businessName: PREVIEW_CONFIG.businessName,

    // Sample data
    ...SAMPLE_DATA,

    // Dynamic HTML
    ...dynamic
  };
}
