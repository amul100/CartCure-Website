#!/usr/bin/env python3
"""
Email Template Sync Script

This script reads email preview HTML files and updates the corresponding
email templates in Code.gs. It converts static HTML placeholders to
JavaScript template literals with dynamic variables.

Usage:
    python sync-email-templates.py [--dry-run] [--template <name>]

Options:
    --dry-run       Show what would be changed without modifying files
    --template      Only sync a specific template (e.g., "05-quote-reminder")
"""

import re
import os
import sys
import argparse
from pathlib import Path

# Common color placeholders used across all templates
COMMON_COLORS = {
    '#2d5d3f': '${colors.brandGreen}',
    '#faf8f4': '${colors.paperCream}',
    '#f9f7f3': '${colors.paperWhite}',
    '#d4cfc3': '${colors.paperBorder}',
    '#2b2b2b': '${colors.inkBlack}',
    '#5a5a5a': '${colors.inkGray}',
    '#8a8a8a': '${colors.inkLight}',
    '#fff8e6': '${colors.alertBg}',
    '#f5d76e': '${colors.alertBorder}',
    '#856404': '${colors.alertText}',
    '#e8f5e9': '${colors.successBg}',
    '#4caf50': '${colors.successBorder}',
    '#c62828': '${colors.alertRed}',
    '#ffebee': '${colors.alertRedBg}',
}

# Configuration: Maps preview files to Code.gs function patterns
EMAIL_TEMPLATES = {
    '01-admin-notification.html': {
        'function': 'sendEmailNotification',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'SUB-0042': '${submissionNumber}',
            'Sarah Smith': '${data.name}',
            'sarah@example.com': '${data.email}',
            'www.sarahsstore.myshopify.com': '${data.store}',
            '+64 21 123 4567': '${data.phone}',
            'Add size guide popup to product pages...': '${data.message}',
            '25/01/2025 2:30 PM': '${timestamp}',
        }
    },
    '02-user-confirmation.html': {
        'function': 'sendUserConfirmationEmail',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'SUB-0042': '${submissionNumber}',
            'Sarah': '${firstName}',
        }
    },
    '03-quote.html': {
        'function': 'generateStandardQuoteEmailHtml',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'JOB-0042': '${data.jobNumber}',
            'Sarah': '${data.clientName}',
            'Add size guide popup to product pages\nCustomize product image gallery layout\nMobile responsive adjustments': '${data.jobDescription}',
            '$130.00': '${data.subtotal}',
            '$19.50': '${data.gst}',
            '$149.50': '${data.total}',
            '7 days': '${data.turnaround} days',
            '10/02/2025': '${data.validUntil}',
            'GST: 123-456-789': 'GST: ${data.gstNumber}',
            'Bank: ANZ': 'Bank: ${data.bankName}',
            'Account: 01-0123-0123456-00': 'Account: ${data.bankAccount}',
            'Reference: JOB-0042': 'Reference: ${data.jobNumber}',
        }
    },
    '04-quote-with-deposit.html': {
        'function': 'generateQuoteWithDepositEmailHtml',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            '#1565c0': '${colors.depositBlue}',
            '#e3f2fd': '${colors.depositBlueBg}',
            'JOB-0043': '${data.jobNumber}',
            'Mike': '${data.clientName}',
            'Custom checkout flow modifications\nAdd gift wrapping option with preview\nImplement subscription product functionality\nCustom email notification templates': '${data.jobDescription}',
            '$350.00': '${data.subtotal}',
            '$52.50': '${data.gst}',
            '$402.50': '${data.total}',
            '$201.25': '${data.depositAmount}',
            '7 days': '${data.turnaround} days',
            '10/02/2025': '${data.validUntil}',
            'GST: 123-456-789': 'GST: ${data.gstNumber}',
            'Bank: ANZ': 'Bank: ${data.bankName}',
            'Account: 01-0123-0123456-00': 'Account: ${data.bankAccount}',
            'Reference: JOB-0043': 'Reference: ${data.jobNumber}',
        }
    },
    '05-quote-reminder.html': {
        'function': 'sendQuoteReminder',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'JOB-0042': '${jobNumber}',
            'Sarah': '${clientName}',
            '$149.50': '$${total}',
            '10/02/2025': '${validUntil}',
        }
    },
    '06-status-in-progress.html': {
        'function': 'generateStatusInProgressEmailHtml',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'JOB-0042': '${data.jobNumber}',
            'Sarah': '${data.clientName}',
        }
    },
    '07-status-on-hold.html': {
        'function': 'generateStatusOnHoldEmailHtml',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'JOB-0042': '${data.jobNumber}',
            'Sarah': '${data.clientName}',
            'Waiting for client to provide product images and updated content.': '${data.explanation}',
        }
    },
    '08-status-completed.html': {
        'function': 'generateStatusCompletedEmailHtml',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'JOB-0042': '${data.jobNumber}',
            'Sarah': '${data.clientName}',
            'feedback.html?job=JOB-0042': 'feedback.html?job=${encodeURIComponent(data.jobNumber)}',
        }
    },
    '09-invoice.html': {
        'function': 'sendInvoiceEmail',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'INV-0042': '${invoiceNumber}',
            'JOB-0042': '${jobNumber}',
            'Sarah': '${clientName}',
            '$130.00': '$${amount}',
            '$19.50': '$${gst}',
            '$149.50': '$${total}',
            '01/02/2025': '${dueDate}',
            'Bank: ANZ<br>\n                  Account: 01-0123-0123456-00<br>\n                  Reference: INV-0042': '${bankName ? "Bank: " + bankName + "<br>" : ""}${bankAccount ? "Account: " + bankAccount + "<br>" : ""}Reference: ${invoiceNumber}',
        }
    },
    '10-deposit-invoice.html': {
        'function': 'sendInvoiceEmailSilent',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'INV-0043-DEP': '${invoiceNumber}',
            'JOB-0043': '${jobNumber}',
            'Mike': '${clientName}',
            '$402.50': '${fullJobTotal}',
            '$175.00': '$${amount}',
            '$26.25': '$${gst}',
            '$201.25': '$${total}',
            '25/01/2025': '${formatNZDate(new Date())}',
            '01/02/2025': '${dueDate}',
            'Bank: ANZ<br>\n                  Account: 01-0123-0123456-00<br>\n                  Reference: INV-0043-DEP<br>\n                  GST Number: 123-456-789': '${bankName ? "Bank: " + bankName + "<br>" : ""}${bankAccount ? "Account: " + bankAccount + "<br>" : ""}Reference: ${invoiceNumber}${isGSTRegistered && gstNumber ? "<br>GST Number: " + gstNumber : ""}',
        }
    },
    '11-invoice-reminder.html': {
        'function': 'sendInvoiceReminder',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'INV-0042': '${invoiceNumber}',
            'JOB-0042': '${jobNumber}',
            'Sarah': '${clientName}',
            '$149.50': '${formatCurrency(displayTotal)}',
            '01/02/2025': '${dueDate}',
            '<strong>tomorrow</strong>': '${daysUntilDue === 1 ? "<strong>tomorrow</strong>" : "<strong>" + dueDate + "</strong>"}',
            'Pay by 01/02/2025': 'Pay by ${dueDate}',
            'Bank: ANZ<br>\n                  Account: 01-0123-0123456-00<br>\n                  Reference: INV-0042': 'Bank: ${bankName}<br>\n                  Account: ${bankAccount}<br>\n                  Reference: ${invoiceNumber}',
        }
    },
    '12-overdue-invoice.html': {
        'function': 'sendOverdueInvoice',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'INV-0042': '${invoiceNumber}',
            'JOB-0042': '${jobNumber}',
            'Sarah': '${clientName}',
            '14 days overdue': '${feeCalc.daysOverdue} days overdue',
            '<strong>14 days overdue</strong>': '<strong>${feeCalc.daysOverdue} days overdue</strong>',
            '<strong>INV-0042</strong> is now <strong>14 days overdue</strong>': '<strong>${invoiceNumber}</strong> is now <strong>${feeCalc.daysOverdue} days overdue</strong>',
            '$130.00': '${formatCurrency(originalAmount)}',
            '$19.50': '${formatCurrency(originalGst)}',
            '$149.50': '${formatCurrency(originalTotal)}',
            '$41.86': '${formatCurrency(feeCalc.lateFee)}',
            '$191.36': '${formatCurrency(feeCalc.totalWithFees)}',
            '2% x 14 days': '2% x ${feeCalc.daysOverdue} days',
            '25/01/2025': '${invoiceDate}',
            '01/02/2025': '${dueDate}',
            'Bank: ANZ<br>\n                  Account: 01-0123-0123456-00<br>\n                  Reference: INV-0042': 'Bank: ${bankName}<br>\n                  Account: ${bankAccount}<br>\n                  Reference: ${invoiceNumber}',
        }
    },
    '13-payment-receipt.html': {
        'function': 'sendPaymentReceiptEmail',
        'html_var': 'htmlBody',
        'placeholders': {
            **COMMON_COLORS,
            'INV-0042': '${invoiceNumber}',
            'JOB-0042': '${jobNumber}',
            'Sarah': '${clientName}',
            '$130.00': '$${amount}',
            '$19.50': '$${gst}',
            '$149.50': '$${total}',
            '25/01/2025': '${paidDate}',
            'Bank Transfer': '${method}',
            'TXN-123456': '${reference}',
            'feedback.html?job=JOB-0042': 'feedback.html?job=${encodeURIComponent(jobNumber)}',
        }
    },
}


def read_file(filepath):
    """Read file contents."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


def write_file(filepath, content):
    """Write content to file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)


def extract_body_content(html_content):
    """Extract the content inside <body> tags."""
    match = re.search(r'<body[^>]*>(.*?)</body>', html_content, re.DOTALL)
    if match:
        return match.group(1).strip()
    return html_content


def convert_to_template_literal(html, placeholders):
    """Convert HTML with placeholders to JavaScript template literal."""
    result = html

    # Sort placeholders by length (longest first) to avoid partial replacements
    sorted_placeholders = sorted(placeholders.items(), key=lambda x: len(x[0]), reverse=True)

    # Apply placeholder replacements
    for placeholder, variable in sorted_placeholders:
        result = result.replace(placeholder, variable)

    return result


def find_function_and_template(code, function_name, html_var):
    """
    Find the htmlBody template literal assignment in a function.
    Returns (start_pos, end_pos) of the template literal content, or None if not found.
    """
    # Find the function
    func_pattern = rf'function\s+{re.escape(function_name)}\s*\([^)]*\)\s*\{{'
    func_match = re.search(func_pattern, code)

    if not func_match:
        return None, f"Could not find function {function_name}"

    func_start = func_match.end()

    # Find the next function to limit our search scope
    next_func = re.search(r'\n(?:function\s+\w+|/\*\*)', code[func_start:])
    func_end = func_start + next_func.start() if next_func else len(code)

    func_body = code[func_start:func_end]

    # Find the htmlBody assignment within the function
    # Look for: const htmlBody = ` or let htmlBody = ` or htmlBody = `
    if html_var == 'return':
        # For functions that return HTML directly, look for return `
        assignment_pattern = r'return\s*`'
    else:
        assignment_pattern = rf'(?:const|let|var)?\s*{re.escape(html_var)}\s*=\s*`'

    assignment_match = re.search(assignment_pattern, func_body)

    if not assignment_match:
        return None, f"Could not find {html_var} assignment in {function_name}"

    # Calculate absolute position
    template_start = func_start + assignment_match.end()

    # Find the closing backtick
    pos = template_start
    depth = 1
    in_expression = False
    expr_depth = 0

    while pos < len(code) and depth > 0:
        char = code[pos]

        if char == '\\' and pos + 1 < len(code):
            pos += 2  # Skip escaped character
            continue

        if char == '`' and not in_expression:
            depth -= 1
            if depth == 0:
                break
        elif char == '$' and pos + 1 < len(code) and code[pos + 1] == '{':
            in_expression = True
            expr_depth = 1
            pos += 1
        elif in_expression:
            if char == '{':
                expr_depth += 1
            elif char == '}':
                expr_depth -= 1
                if expr_depth == 0:
                    in_expression = False

        pos += 1

    if depth != 0:
        return None, f"Could not find closing backtick for template in {function_name}"

    template_end = pos

    return (template_start, template_end), None


def format_as_template_literal(html_content):
    """Format HTML content for use in a JavaScript template literal."""
    # Escape backticks that aren't part of template expressions
    # But we need to be careful not to escape ${} expressions

    # First, preserve ${} expressions
    expressions = []
    def save_expression(match):
        expressions.append(match.group(0))
        return f'__EXPR_{len(expressions)-1}__'

    result = re.sub(r'\$\{[^}]+\}', save_expression, html_content)

    # Escape any remaining backticks
    result = result.replace('`', '\\`')

    # Restore expressions
    for i, expr in enumerate(expressions):
        result = result.replace(f'__EXPR_{i}__', expr)

    return result


def update_code_gs(code_gs_path, template_name, html_content, config, dry_run=False):
    """Update the Code.gs file with new HTML template."""
    if config.get('skip'):
        print(f"\nSkipping {template_name} - {config.get('note', 'marked as skip')}")
        return False

    code = read_file(code_gs_path)

    function_name = config['function']
    html_var = config['html_var']
    placeholders = config.get('placeholders', {})

    print(f"\nProcessing {template_name}...")
    print(f"  Function: {function_name}")

    # Extract body from HTML
    body_html = extract_body_content(html_content)

    # Convert to template literal with variables
    template_content = convert_to_template_literal(body_html, placeholders)

    # Format for JavaScript
    template_content = format_as_template_literal(template_content)

    # Add proper indentation (4 spaces for consistency)
    lines = template_content.split('\n')
    indented_lines = []
    for line in lines:
        if line.strip():
            indented_lines.append('    ' + line)
        else:
            indented_lines.append('')
    template_content = '\n'.join(indented_lines)

    # Find the position to replace
    result, error = find_function_and_template(code, function_name, html_var)

    if error:
        print(f"  SKIPPED: {error}")
        return False

    start, end = result

    # Get the old content for comparison
    old_content = code[start:end]

    if dry_run:
        print(f"  DRY RUN: Would replace {len(old_content)} chars with {len(template_content)} chars")
        print(f"  Preview of new content (first 200 chars):")
        preview = template_content[:200].replace('\n', '\\n')
        print(f"    {preview}...")
        return True

    # Replace the template content
    new_code = code[:start] + '\n' + template_content + '\n  ' + code[end:]

    # Write the updated code
    write_file(code_gs_path, new_code)
    print(f"  SUCCESS: Updated {function_name} ({len(template_content)} chars)")

    return True


def list_templates():
    """List all configured templates."""
    print("\nConfigured Email Templates:")
    print("-" * 60)
    for name, config in EMAIL_TEMPLATES.items():
        status = "SKIP" if config.get('skip') else "OK"
        func = config['function']
        note = config.get('note', '')
        print(f"  [{status}] {name}")
        print(f"        Function: {func}")
        if note:
            print(f"        Note: {note}")
    print()


def main():
    parser = argparse.ArgumentParser(description='Sync email templates from HTML previews to Code.gs')
    parser.add_argument('--dry-run', action='store_true', help='Show what would change without modifying files')
    parser.add_argument('--template', type=str, help='Only sync a specific template (e.g., "05-quote-reminder")')
    parser.add_argument('--list', action='store_true', help='List all configured templates')
    args = parser.parse_args()

    # Paths
    script_dir = Path(__file__).parent
    email_previews_dir = script_dir / 'email-previews'
    code_gs_path = script_dir / 'apps-script' / 'Code.gs'

    if args.list:
        list_templates()
        return

    # Validate paths
    if not email_previews_dir.exists():
        print(f"Error: Email previews directory not found: {email_previews_dir}")
        sys.exit(1)

    if not code_gs_path.exists():
        print(f"Error: Code.gs not found: {code_gs_path}")
        sys.exit(1)

    print("=" * 60)
    print("Email Template Sync Script")
    print("=" * 60)

    if args.dry_run:
        print("DRY RUN MODE - No files will be modified")

    print(f"\nEmail previews: {email_previews_dir}")
    print(f"Code.gs: {code_gs_path}")

    # Filter templates if specific one requested
    templates_to_process = EMAIL_TEMPLATES
    if args.template:
        matching = {k: v for k, v in EMAIL_TEMPLATES.items() if args.template in k}
        if not matching:
            print(f"\nError: No template matching '{args.template}' found")
            print(f"Available templates: {', '.join(EMAIL_TEMPLATES.keys())}")
            sys.exit(1)
        templates_to_process = matching

    # Process each template
    updated_count = 0
    skipped_count = 0
    error_count = 0

    for template_file, config in templates_to_process.items():
        template_path = email_previews_dir / template_file

        if not template_path.exists():
            print(f"\nWarning: Template file not found: {template_file}")
            error_count += 1
            continue

        if config.get('skip'):
            print(f"\nSkipping {template_file}: {config.get('note', 'marked as skip')}")
            skipped_count += 1
            continue

        html_content = read_file(template_path)

        try:
            if update_code_gs(code_gs_path, template_file, html_content, config, args.dry_run):
                updated_count += 1
            else:
                skipped_count += 1
        except Exception as e:
            print(f"\n  ERROR processing {template_file}: {e}")
            error_count += 1

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Templates configured: {len(templates_to_process)}")
    print(f"Updated: {updated_count}")
    print(f"Skipped: {skipped_count}")
    print(f"Errors: {error_count}")

    if args.dry_run and updated_count > 0:
        print("\nRun without --dry-run to apply changes")


if __name__ == '__main__':
    main()
