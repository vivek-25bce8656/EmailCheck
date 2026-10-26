"""
EmailCheck - Advanced Email Intelligence & DNS Verification Platform
Production-grade Flask Web Application.
"""
import io
import csv
import re
import time
from datetime import datetime, timezone
from typing import List
from flask import Flask, request, render_template, Response, make_response, jsonify
from email_checker import (
    assess_email,
    assess_batch,
    aggregate_domain_insights,
    sanitize_csv_value,
    clear_dns_cache,
    validate_email_syntax,
    resolve_domain_mail_config,
    CATEGORY_LIKELY_DELIVERED,
    CATEGORY_LIKELY_TO_BOUNCE,
    CATEGORY_UNKNOWN,
    DNS_STATUS_ACTIVE_MX,
    DNS_STATUS_FALLBACK,
    DNS_STATUS_NULL_MX,
    DNS_STATUS_NO_ROUTING,
    DNS_STATUS_NXDOMAIN,
    DNS_STATUS_TIMEOUT,
    DNS_STATUS_ERROR,
    STATUS_MAIL_CONFIG,
    STATUS_NO_MX,
    STATUS_NULL_MX,
    STATUS_DOMAIN_NOT_FOUND,
    STATUS_INVALID_FORMAT,
    STATUS_UNABLE_TO_VERIFY,
    STATUS_UNKNOWN,
    MAX_EMAIL_LENGTH,
    MAX_LOCAL_LENGTH,
    MAX_DOMAIN_LENGTH,
    LOCAL_PART_PATTERN,
    DEFAULT_BATCH_LIMIT,
    MAX_BATCH_LIMIT,
    ALLOWED_BATCH_LIMITS,
)
import dns.resolver
import dns.exception

app = Flask(__name__, template_folder="templates", static_folder="static")

# Production Limits & Config (Upgraded for high-throughput batching)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024  # 512 KB upload ceiling
MAX_INPUT_LENGTH = 150000  # Allows up to 500 RFC-sized addresses + whitespace
DEFAULT_MAX_EMAILS = DEFAULT_BATCH_LIMIT  # 100 addresses
ABSOLUTE_MAX_EMAILS = MAX_BATCH_LIMIT  # 500 addresses
MAX_EMAILS = DEFAULT_MAX_EMAILS  # Backward-compatible default limit alias

# Export regex pattern for backward compatibility
EMAIL_PATTERN = LOCAL_PART_PATTERN


def parse_email_input(input_text: str) -> List[str]:
    """
    Parse email addresses from text input.
    Accepts addresses separated by newlines, commas, or semicolons.
    Trims surrounding whitespace and removes empty items.
    """
    if not input_text or not isinstance(input_text, str):
        return []
    tokens = re.split(r"[\r\n,;]+", input_text)
    return [t.strip() for t in tokens if t.strip()]


def check_email(email: str):
    """
    Backward-compatible wrapper for email assessment.
    Returns: (classification, css, reason)
    """
    res = assess_email(email)
    return res["classification"], res["css"], res["reason"]


@app.after_request
def apply_security_headers(response):
    """
    Attach standard enterprise security headers to all HTTP responses.
    """
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )
    # Content Security Policy allowing self, Google Fonts, and inline styling
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return response


@app.route("/", methods=["GET", "POST"])
def home():
    input_text = ""
    results = []
    domain_insights = []
    notice = ""
    total_submitted = 0
    unique_count = 0
    duplicate_count = 0
    execution_time = "0ms"

    # Default batch limit is 100, with optional advanced 500 limit
    selected_limit = DEFAULT_BATCH_LIMIT

    if request.method == "POST":
        # Extract and validate selected batch limit
        batch_limit_raw = request.form.get("batch_limit", str(DEFAULT_BATCH_LIMIT))
        try:
            parsed_limit = int(batch_limit_raw)
            if parsed_limit in ALLOWED_BATCH_LIMITS:
                selected_limit = parsed_limit
            elif parsed_limit >= MAX_BATCH_LIMIT:
                selected_limit = MAX_BATCH_LIMIT
            else:
                selected_limit = DEFAULT_BATCH_LIMIT
        except (ValueError, TypeError):
            selected_limit = DEFAULT_BATCH_LIMIT

        input_text = request.form.get("emails", "")

        if len(input_text) > MAX_INPUT_LENGTH:
            notice = "Input is too long. Please shorten your list."
        else:
            raw_tokens = parse_email_input(input_text)
            total_submitted = len(raw_tokens)

            # Deduplicate while strictly preserving insertion order
            seen = set()
            unique_emails = []
            for email in raw_tokens:
                if email not in seen:
                    seen.add(email)
                    unique_emails.append(email)

            unique_count = len(unique_emails)
            duplicate_count = total_submitted - unique_count

            if not unique_emails:
                notice = "Please enter at least one email address."
            elif unique_count > selected_limit:
                notice = (
                    f"Please submit no more than {selected_limit} unique "
                    "email addresses at a time."
                )
            else:
                # Benchmark high-throughput bounded assessment
                t_start = time.perf_counter()
                results = assess_batch(unique_emails)
                t_duration = time.perf_counter() - t_start

                ms = t_duration * 1000.0
                if t_duration <= 0:
                    execution_time = "0ms"
                elif ms < 1.0:
                    execution_time = "< 1ms"
                elif t_duration < 1.0:
                    execution_time = f"{int(ms)}ms"
                else:
                    execution_time = f"{t_duration:.2f}s"

                domain_insights = aggregate_domain_insights(results)

    # Compute category metrics for the 3 user-facing classifications
    likely_delivered_count = sum(
        r["classification"] == CATEGORY_LIKELY_DELIVERED for r in results
    )
    likely_to_bounce_count = sum(
        r["classification"] == CATEGORY_LIKELY_TO_BOUNCE for r in results
    )
    unknown_count = sum(
        r["classification"] == CATEGORY_UNKNOWN for r in results
    )

    # Granular evidence-based diagnostic metrics
    mail_config_count = likely_delivered_count
    no_mx_count = sum(
        r.get("dns_status") == DNS_STATUS_NO_ROUTING for r in results
    )
    null_mx_count = sum(
        r.get("dns_status") == DNS_STATUS_NULL_MX for r in results
    )
    domain_not_found_count = sum(
        r.get("dns_status") == DNS_STATUS_NXDOMAIN for r in results
    )
    invalid_format_count = sum(
        "Invalid syntax" in r.get("syntax_status", "") for r in results
    )
    unverified_count = unknown_count

    # Check for client-side progressive enhancement (AJAX / JSON requested)
    is_ajax = (
        request.headers.get("Accept") == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.form.get("ajax") == "1"
        or request.args.get("format") == "json"
    )
    if is_ajax and request.method == "POST":
        return jsonify({
            "status": "error" if notice else "success",
            "notice": notice,
            "total_submitted": total_submitted,
            "unique_count": unique_count,
            "duplicate_count": duplicate_count,
            "batch_limit": selected_limit,
            "execution_time": execution_time,
            "metrics": {
                "likely_delivered_count": likely_delivered_count,
                "likely_to_bounce_count": likely_to_bounce_count,
                "unknown_count": unknown_count,
                "mail_config_count": mail_config_count,
                "no_mx_count": no_mx_count,
                "null_mx_count": null_mx_count,
                "domain_not_found_count": domain_not_found_count,
                "invalid_format_count": invalid_format_count,
                "unverified_count": unverified_count,
            },
            "results": results,
            "domain_insights": domain_insights,
        })

    return render_template(
        "index.html",
        input_text=input_text,
        results=results,
        domain_insights=domain_insights,
        notice=notice,
        total_submitted=total_submitted,
        unique_count=unique_count,
        duplicate_count=duplicate_count,
        batch_limit=selected_limit,
        default_batch_limit=DEFAULT_BATCH_LIMIT,
        max_batch_limit=MAX_BATCH_LIMIT,
        likely_delivered_count=likely_delivered_count,
        likely_to_bounce_count=likely_to_bounce_count,
        unknown_count=unknown_count,
        mail_config_count=mail_config_count,
        no_mx_count=no_mx_count,
        null_mx_count=null_mx_count,
        domain_not_found_count=domain_not_found_count,
        invalid_format_count=invalid_format_count,
        unverified_count=unverified_count,
        execution_time=execution_time,
    )


@app.route("/export-csv", methods=["POST"])
def export_csv():
    """
    Generate and serve a CSV export with formula injection protection.
    Accepts email addresses separated by newlines, commas, or semicolons.
    Respects selected batch limit up to MAX_BATCH_LIMIT (500).
    """
    input_text = request.form.get("emails", "")
    raw_tokens = parse_email_input(input_text)

    batch_limit_raw = request.form.get("batch_limit", str(DEFAULT_BATCH_LIMIT))
    try:
        selected_limit = int(batch_limit_raw)
        if selected_limit > MAX_BATCH_LIMIT:
            selected_limit = MAX_BATCH_LIMIT
        elif selected_limit < 1:
            selected_limit = DEFAULT_BATCH_LIMIT
    except (ValueError, TypeError):
        selected_limit = DEFAULT_BATCH_LIMIT

    seen = set()
    unique_emails = []
    for email in raw_tokens:
        if email not in seen:
            seen.add(email)
            unique_emails.append(email)

    if len(unique_emails) > selected_limit:
        unique_emails = unique_emails[:selected_limit]

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header Row with evidence-based assessment fields
    writer.writerow([
        "Email Address",
        "Classification",
        "Short Explanation",
        "Syntax Validation",
        "DNS Mail-Routing Assessment",
        "Limitations & Uncertainty",
        "Domain",
        "Primary Mail Server",
    ])

    results = assess_batch(unique_emails)
    for res in results:
        writer.writerow([
            sanitize_csv_value(res["email"]),
            sanitize_csv_value(res["classification"]),
            sanitize_csv_value(res["reason"]),
            sanitize_csv_value(res.get("syntax_status", "")),
            sanitize_csv_value(res.get("dns_status", "")),
            sanitize_csv_value(res.get("limitation", "")),
            sanitize_csv_value(res["domain"]),
            sanitize_csv_value(res["primary_mx"]),
        ])

    csv_data = "\ufeff" + output.getvalue()
    filename = f"emailcheck_results_{datetime.now().strftime('%Y-%m-%d')}.csv"

    response = Response(csv_data, mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route("/health", methods=["GET"])
def health_check():
    """Application health endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "EmailCheck",
        "version": "3.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200


@app.errorhandler(413)
def request_entity_too_large(_error):
    return "Input is too large. Please submit a smaller list.", 413


@app.errorhandler(400)
def bad_request(_error):
    return "Bad Request. The server could not understand your submission.", 400


@app.errorhandler(404)
def not_found(_error):
    return "The requested page or resource could not be found.", 404


@app.errorhandler(500)
def internal_server_error(_error):
    return "An internal server error occurred. Please try again later.", 500


if __name__ == "__main__":
    app.run(debug=False)
