"""
EmailCheck - Advanced Email Intelligence & DNS Verification Platform
Production-grade Flask Web Application.
"""
import io
import csv
import time
from datetime import datetime, timezone
from flask import Flask, request, render_template, Response, make_response, jsonify
from email_checker import (
    assess_email,
    aggregate_domain_insights,
    sanitize_csv_value,
    clear_dns_cache,
    validate_email_syntax,
    resolve_domain_mail_config,
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
)
import dns.resolver
import dns.exception

app = Flask(__name__, template_folder="templates", static_folder="static")

# Production Limits & Config
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024  # 32 KB max upload
MAX_EMAILS = 20
MAX_INPUT_LENGTH = 12000

# Export regex pattern for backward compatibility
EMAIL_PATTERN = LOCAL_PART_PATTERN


def check_email(email: str):
    """
    Backward-compatible wrapper for email assessment.
    Returns: (status, css, reason)
    """
    res = assess_email(email)
    return res["status"], res["css"], res["reason"]


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
    execution_time = "0ms"

    if request.method == "POST":
        input_text = request.form.get("emails", "")

        if len(input_text) > MAX_INPUT_LENGTH:
            notice = "Input is too long. Please shorten your list."
        else:
            raw_lines = [
                line.strip()
                for line in input_text.splitlines()
                if line.strip()
            ]
            total_submitted = len(raw_lines)

            # Deduplicate while strictly preserving insertion order
            seen = set()
            unique_emails = []
            for email in raw_lines:
                if email not in seen:
                    seen.add(email)
                    unique_emails.append(email)

            unique_count = len(unique_emails)

            if not unique_emails:
                notice = "Please enter at least one email address."
            elif unique_count > MAX_EMAILS:
                notice = (
                    f"Please submit no more than {MAX_EMAILS} unique "
                    "email addresses at a time."
                )
            else:
                # Benchmark assessment performance
                t_start = time.perf_counter()

                for email in unique_emails:
                    assessment = assess_email(email)
                    results.append(assessment)

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

    # Compute category metrics
    mail_config_count = sum(r["status"] == STATUS_MAIL_CONFIG for r in results)
    no_mx_count = sum(r["status"] in (STATUS_NO_MX, STATUS_NULL_MX) for r in results)
    domain_not_found_count = sum(r["status"] == STATUS_DOMAIN_NOT_FOUND for r in results)
    invalid_format_count = sum(r["status"] == STATUS_INVALID_FORMAT for r in results)
    unverified_count = sum(
        r["status"] in (STATUS_UNABLE_TO_VERIFY, STATUS_UNKNOWN)
        for r in results
    )

    return render_template(
        "index.html",
        input_text=input_text,
        results=results,
        domain_insights=domain_insights,
        notice=notice,
        total_submitted=total_submitted,
        unique_count=unique_count,
        mail_config_count=mail_config_count,
        no_mx_count=no_mx_count,
        domain_not_found_count=domain_not_found_count,
        invalid_format_count=invalid_format_count,
        unverified_count=unverified_count,
        execution_time=execution_time,
    )


@app.route("/export-csv", methods=["POST"])
def export_csv():
    """
    Generate and serve a CSV export with formula injection protection.
    """
    input_text = request.form.get("emails", "")
    raw_lines = [line.strip() for line in input_text.splitlines() if line.strip()]

    seen = set()
    unique_emails = []
    for email in raw_lines:
        if email not in seen:
            seen.add(email)
            unique_emails.append(email)

    if len(unique_emails) > MAX_EMAILS:
        unique_emails = unique_emails[:MAX_EMAILS]

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header Row
    writer.writerow([
        "Email Address",
        "Assessment Status",
        "Domain",
        "Reason / Evidence",
        "Mail Servers",
    ])

    for email in unique_emails:
        res = assess_email(email)
        writer.writerow([
            sanitize_csv_value(res["email"]),
            sanitize_csv_value(res["status"]),
            sanitize_csv_value(res["domain"]),
            sanitize_csv_value(res["reason"]),
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
        "version": "2.0.0",
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
