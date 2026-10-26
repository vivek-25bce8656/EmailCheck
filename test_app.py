"""
EmailCheck - Comprehensive Automated Test Suite
Covers unit tests, RFC validation, mocked DNS, security headers,
CSV injection shielding, IPv6 AAAA fallbacks, RFC 7505 Null MX,
3-tier classification (Likely delivered, Likely to bounce, Unknown),
comma/newline input parsing, caching, and error handlers.
"""
import unittest
from unittest.mock import patch, MagicMock
import time
import dns.resolver
import dns.exception
import dns.name
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, InternalServerError

from app import app, check_email, parse_email_input
import email_checker
from email_checker import (
    validate_email_syntax,
    resolve_domain_mail_config,
    assess_email,
    assess_batch,
    aggregate_domain_insights,
    sanitize_csv_value,
    clear_dns_cache,
    get_dns_cache_size,
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
    DEFAULT_BATCH_LIMIT,
    MAX_BATCH_LIMIT,
    ALLOWED_BATCH_LIMITS,
    _DNS_CACHE,
    _DNS_CACHE_MAX_SIZE,
)


class EmailCheckComprehensiveTests(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        clear_dns_cache()

    def tearDown(self):
        clear_dns_cache()

    # 1. Web Page & Navigation
    def test_homepage_loads_successfully(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"EmailCheck", response.data)
        self.assertIn(b"Advanced Email Intelligence", response.data)
        self.assertIn(b"Assess Addresses", response.data)
        self.assertIn(b"Load Sample", response.data)
        self.assertIn(b"Likely delivered", response.data)
        self.assertIn(b"Likely to bounce", response.data)
        self.assertIn(b"Unknown", response.data)

    # 2. Security Headers
    def test_security_headers_present(self):
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy"))

    # 3. Valid Syntax Tests
    def test_valid_email_syntax(self):
        valid_emails = [
            "user@example.com",
            "first.last@company.org",
            "developer+tag@github.com",
            "test_user123@sub.domain.co.uk",
        ]
        for email in valid_emails:
            is_valid, local, domain, reason = validate_email_syntax(email)
            self.assertTrue(is_valid, f"Expected {email} to be valid: {reason}")
            self.assertEqual(reason, "")

    # 4. Invalid Syntax Tests & Edge Cases
    def test_invalid_email_syntax_variations(self):
        invalid_cases = [
            ("missing-at-sign.com", "missing the '@' delimiter"),
            ("user@sub@domain.com", "invalid"),
            (".leadingdot@example.com", "cannot start or end with a period"),
            ("trailingdot.@example.com", "cannot start or end with a period"),
            ("consecutive..dots@example.com", "consecutive periods"),
            ("@nodomain.com", "missing the local user portion"),
            ("user@", "missing the domain portion"),
            ("user@singlelabel", "Domain must contain at least a name and a top-level domain"),
            ("user@-hyphenstart.com", "contains invalid characters or starts/ends with a hyphen"),
            ("user@hyphenend-.com", "contains invalid characters or starts/ends with a hyphen"),
            ("user@domain.123", "Top-level domain (TLD) is invalid or purely numeric"),
            ("", "Empty or null address provided."),
            ("user@[192.168.1.1]", "Domain literals (IP addresses in brackets) are not supported"),
            ("bücher@domain.com", "Local mailbox portion contains non-ASCII characters"),
        ]
        for email, expected_reason_substr in invalid_cases:
            is_valid, local, domain, reason = validate_email_syntax(email)
            self.assertFalse(is_valid, f"Expected {email} to be invalid")
            self.assertIn(expected_reason_substr.lower(), reason.lower())

            status, css, explanation = check_email(email)
            self.assertEqual(status, CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(css, "status-danger")
            self.assertIn(expected_reason_substr.lower(), explanation.lower())

    def test_validate_syntax_non_string_types(self):
        self.assertFalse(validate_email_syntax(None)[0])
        self.assertFalse(validate_email_syntax(123)[0])
        self.assertFalse(validate_email_syntax([])[0])

    # 5. Length Constraints
    def test_maximum_email_and_local_part_lengths(self):
        # Local part > 64 chars
        long_local = "a" * 65 + "@example.com"
        is_valid, _, _, reason = validate_email_syntax(long_local)
        self.assertFalse(is_valid)
        self.assertIn("exceeds maximum length of 64", reason)

        # Local part == 64 chars (valid syntax)
        valid_local = "a" * 64 + "@example.com"
        is_valid, _, _, _ = validate_email_syntax(valid_local)
        self.assertTrue(is_valid)

        # Total email > 254 chars
        domain = "sub." + ("b" * 50) + "." + ("c" * 50) + "." + ("d" * 50) + "." + ("e" * 50) + ".com"
        long_email = ("a" * 60) + "@" + domain
        if len(long_email) > 254:
            is_valid, _, _, reason = validate_email_syntax(long_email)
            self.assertFalse(is_valid)
            self.assertIn("exceeds maximum rfc length of 254", reason.lower())

    # 6. IDN / Internationalized Domain Names (Punycode conversion)
    def test_idn_punycode_domain_handling(self):
        is_valid, local, domain, reason = validate_email_syntax("user@münchen.de")
        self.assertTrue(is_valid, f"IDN conversion failed: {reason}")
        self.assertEqual(domain, "xn--mnchen-3ya.de")

    # 7. Duplicates & Whitespace
    def test_duplicate_removal_preserving_order(self):
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.example.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            response = self.client.post("/", data={
                "emails": "first@example.com\nsecond@example.com\nfirst@example.com\n  second@example.com  "
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"first@example.com", response.data)
            self.assertIn(b"second@example.com", response.data)
            self.assertIn(b"From 4 submitted lines", response.data)
            self.assertIn(b"Showing 2 of 2", response.data)

    def test_empty_and_whitespace_submissions(self):
        response = self.client.post("/", data={"emails": "   \n\n   \t  \n"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Please enter at least one email address.", response.data)

    # 8. Max Limits & Configured Batch Guardrails (100 Default / 500 Advanced)
    def test_default_100_unique_addresses_accepted_and_101_rejected(self):
        """Default maximum is 100 unique addresses: accepts 100, rejects 101."""
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.example.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            # 100 addresses should succeed
            emails_100 = "\n".join(f"user{i}@example.com" for i in range(100))
            resp_100 = self.client.post("/", data={"emails": emails_100})
            self.assertEqual(resp_100.status_code, 200)
            self.assertNotIn(b"Please submit no more than", resp_100.data)
            self.assertIn(b"user99@example.com", resp_100.data)

            # 101 addresses should be rejected under default 100 limit
            emails_101 = "\n".join(f"user{i}@example.com" for i in range(101))
            resp_101 = self.client.post("/", data={"emails": emails_101})
            self.assertEqual(resp_101.status_code, 200)
            self.assertIn(b"Please submit no more than 100 unique email addresses at a time.", resp_101.data)

    def test_optional_500_unique_addresses_accepted_and_501_rejected(self):
        """Optional advanced maximum is 500 unique addresses: accepts 500, rejects 501."""
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.example.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            # 500 addresses with batch_limit=500 should succeed
            emails_500 = "\n".join(f"user{i}@example.com" for i in range(500))
            resp_500 = self.client.post("/", data={
                "emails": emails_500,
                "batch_limit": "500",
            })
            self.assertEqual(resp_500.status_code, 200)
            self.assertNotIn(b"Please submit no more than", resp_500.data)
            self.assertIn(b"user499@example.com", resp_500.data)

            # 501 addresses should be rejected even with batch_limit=500
            emails_501 = "\n".join(f"user{i}@example.com" for i in range(501))
            resp_501 = self.client.post("/", data={
                "emails": emails_501,
                "batch_limit": "500",
            })
            self.assertEqual(resp_501.status_code, 200)
            self.assertIn(b"Please submit no more than 500 unique email addresses at a time.", resp_501.data)

    def test_batch_limit_tampering_capped_at_max(self):
        """Users tampering with batch_limit beyond 500 are capped at 500."""
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.example.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            emails_501 = "\n".join(f"user{i}@example.com" for i in range(501))
            resp = self.client.post("/", data={
                "emails": emails_501,
                "batch_limit": "99999",  # Tampered parameter
            })
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Please submit no more than 500 unique email addresses at a time.", resp.data)

    def test_oversized_text_rejected(self):
        huge_input = "a@b.com\n" * 25000  # 200,000 characters > 150,000 limit
        response = self.client.post("/", data={"emails": huge_input})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Input is too long. Please shorten your list.", response.data)

    # 9. DNS MX Checks (Mocked)
    def test_domain_with_valid_mx_records(self):
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.example.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            status, css, reason = check_email("user@example.com")
            self.assertEqual(status, CATEGORY_LIKELY_DELIVERED)
            self.assertEqual(css, "status-success")
            self.assertIn("active mail exchange", reason)

    # 10. Fallback: A records & AAAA records (RFC 5321)
    def test_domain_no_mx_fallback_to_a_record(self):
        """RFC 5321 Fallback test: No MX, but IPv4 A record exists."""
        def mock_dns_resolve(qname, rdtype, **kwargs):
            if rdtype == "MX":
                raise dns.resolver.NoAnswer()
            elif rdtype == "A":
                a_mock = MagicMock()
                a_mock.__str__ = lambda x: "93.184.216.34"
                return [a_mock]
            raise dns.resolver.NXDOMAIN()

        with patch("email_checker.dns.resolver.resolve", side_effect=mock_dns_resolve):
            status, css, reason = check_email("fallback@example.com")
            self.assertEqual(status, CATEGORY_LIKELY_DELIVERED)
            self.assertEqual(css, "status-success")
            self.assertIn("Implicit mail routing fallback", reason)
            self.assertIn("93.184.216.34", reason)

    def test_domain_no_mx_fallback_to_aaaa_record(self):
        """RFC 5321 Fallback test: No MX, No A record, but IPv6 AAAA record exists."""
        def mock_dns_resolve(qname, rdtype, **kwargs):
            if rdtype in ("MX", "A"):
                raise dns.resolver.NoAnswer()
            elif rdtype == "AAAA":
                aaaa_mock = MagicMock()
                aaaa_mock.__str__ = lambda x: "2001:db8::1"
                return [aaaa_mock]
            raise dns.resolver.NXDOMAIN()

        with patch("email_checker.dns.resolver.resolve", side_effect=mock_dns_resolve):
            status, css, reason = check_email("ipv6@example.com")
            self.assertEqual(status, CATEGORY_LIKELY_DELIVERED)
            self.assertEqual(css, "status-success")
            self.assertIn("Implicit mail routing fallback", reason)
            self.assertIn("2001:db8::1", reason)

    def test_domain_no_mx_and_no_a_or_aaaa_record(self):
        def mock_dns_resolve(qname, rdtype, **kwargs):
            raise dns.resolver.NoAnswer()

        with patch("email_checker.dns.resolver.resolve", side_effect=mock_dns_resolve):
            status, css, reason = check_email("user@no-mx-no-a.com")
            self.assertEqual(status, CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(css, "status-danger")
            self.assertIn("has no MX or fallback host records", reason)

    def test_fallback_timeout_handling(self):
        def mock_dns_resolve_a_timeout(qname, rdtype, **kwargs):
            if rdtype == "MX":
                raise dns.resolver.NoAnswer()
            raise dns.exception.Timeout()

        with patch("email_checker.dns.resolver.resolve", side_effect=mock_dns_resolve_a_timeout):
            res = resolve_domain_mail_config("timeout-host.com")
            self.assertEqual(res["classification"], CATEGORY_UNKNOWN)
            self.assertEqual(res["status"], CATEGORY_UNKNOWN)
            self.assertIn("timed out", res["reason"].lower())

    def test_nonexistent_domain_nxdomain(self):
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            status, css, reason = check_email("user@nonexistent-domain.xyz")
            self.assertEqual(status, CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(css, "status-danger")
            self.assertIn("does not exist in DNS", reason)

    def test_dns_timeout_and_exceptions(self):
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.exception.Timeout()):
            status, css, reason = check_email("user@timeout-domain.com")
            self.assertEqual(status, CATEGORY_UNKNOWN)
            self.assertEqual(css, "status-neutral")
            self.assertIn("timed out", reason.lower())

        with patch("email_checker.dns.resolver.resolve", side_effect=dns.exception.DNSException()):
            status, css, reason = check_email("user@error-domain.com")
            self.assertEqual(status, CATEGORY_UNKNOWN)
            self.assertEqual(css, "status-neutral")
            self.assertIn("failed", reason.lower())

    # 11. Bounded DNS Cache & Cache Eviction
    def test_dns_caching_and_cache_eviction(self):
        mx_mock = MagicMock()
        mx_mock.preference = 5
        mx_mock.exchange = "mx.cached.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]) as mock_resolve:
            res1 = assess_email("first@cached.com")
            res2 = assess_email("second@cached.com")
            self.assertEqual(mock_resolve.call_count, 1)
            self.assertEqual(res1["classification"], CATEGORY_LIKELY_DELIVERED)
            self.assertEqual(res2["classification"], CATEGORY_LIKELY_DELIVERED)

        self.assertGreaterEqual(get_dns_cache_size(), 1)

        # Fill cache to test bounded size eviction
        for i in range(_DNS_CACHE_MAX_SIZE + 5):
            _DNS_CACHE[f"domain{i}.com"] = (time.time(), {"classification": CATEGORY_LIKELY_DELIVERED})

        # Adding one more via resolver triggers eviction of oldest
        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            resolve_domain_mail_config("trigger-eviction.com")
        self.assertLessEqual(get_dns_cache_size(), _DNS_CACHE_MAX_SIZE)

    # 12. CSV Sanitization & Formula Injection Shield
    def test_csv_formula_injection_protection(self):
        malicious_inputs = [
            "=SUM(A1:A10)",
            "+cmd|' /C calc'!A0",
            "-2+3",
            "@evil.com",
            "\tTAB_INJECT",
            "\rCR_INJECT",
            "  =whitespace_prefixed",
            "   +tab_after_spaces",
            None,
        ]
        for val in malicious_inputs:
            sanitized = sanitize_csv_value(val)
            if val is None:
                self.assertEqual(sanitized, "")
            else:
                self.assertTrue(
                    sanitized.startswith("'"),
                    f"Expected {val} to be escaped with leading quote, got: {sanitized}"
                )

        safe_input = "regular_user@example.com"
        self.assertEqual(sanitize_csv_value(safe_input), safe_input)

    # 13. CSV Export Endpoint
    def test_csv_export_endpoint(self):
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            # Test with data
            response = self.client.post("/export-csv", data={
                "emails": "test@nonexistent.org\n=danger@injection.com"
            })
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, "text/csv")
            self.assertIn("attachment; filename=", response.headers.get("Content-Disposition", ""))

            csv_content = response.data.decode("utf-8")
            self.assertIn("Email Address", csv_content)
            self.assertIn("Classification", csv_content)
            self.assertIn("Domain", csv_content)
            self.assertIn("Primary Mail Server", csv_content)
            self.assertIn("test@nonexistent.org", csv_content)
            self.assertIn("Likely to bounce", csv_content)
            self.assertIn("'=danger@injection.com", csv_content)

            # Test empty submission
            empty_resp = self.client.post("/export-csv", data={"emails": ""})
            self.assertEqual(empty_resp.status_code, 200)
            self.assertIn("Email Address", empty_resp.data.decode("utf-8"))

            # Test submission exceeding default batch limit (truncated at 100)
            many_emails = "\n".join(f"user{i}@test.com" for i in range(120))
            many_resp = self.client.post("/export-csv", data={"emails": many_emails})
            self.assertEqual(many_resp.status_code, 200)
            lines = many_resp.data.decode("utf-8").strip().splitlines()
            # 1 header line + 100 data lines = 101 lines
            self.assertEqual(len(lines), 101)

            # Test submission with batch_limit=500 (accepts up to 500)
            resp_500 = self.client.post("/export-csv", data={
                "emails": many_emails,
                "batch_limit": "500",
            })
            self.assertEqual(resp_500.status_code, 200)
            lines_500 = resp_500.data.decode("utf-8").strip().splitlines()
            # 1 header line + 120 data lines = 121 lines
            self.assertEqual(len(lines_500), 121)

    # 14. Accurate Summary Counts & Execution Benchmark
    def test_accurate_summary_counts_and_benchmark(self):
        xss_email = "<script>alert(1)</script>@invalid..domain"
        with patch("time.perf_counter", side_effect=[100.0, 101.5]):
            response = self.client.post("/", data={
                "emails": f"{xss_email}\nvalid@syntax.org"
            })
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(b"<script>alert(1)</script>", response.data)
            self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", response.data)
            self.assertIn(b"1.50s", response.data)

    # 15. Domain Insights Aggregation
    def test_domain_insights_aggregation(self):
        sample_results = [
            {
                "email": "a@domain1.com",
                "domain": "domain1.com",
                "classification": CATEGORY_LIKELY_DELIVERED,
                "status": CATEGORY_LIKELY_DELIVERED,
                "css": "status-success",
                "badge": "Likely delivered",
                "primary_mx": "mx1.domain1.com",
                "mx_records": ["mx1.domain1.com"],
            },
            {
                "email": "b@domain1.com",
                "domain": "domain1.com",
                "classification": CATEGORY_LIKELY_DELIVERED,
                "status": CATEGORY_LIKELY_DELIVERED,
                "css": "status-success",
                "badge": "Likely delivered",
                "primary_mx": "mx1.domain1.com",
                "mx_records": ["mx1.domain1.com"],
            },
            {
                "email": "c@invalid",
                "domain": "N/A",
                "classification": CATEGORY_LIKELY_TO_BOUNCE,
                "status": CATEGORY_LIKELY_TO_BOUNCE,
                "css": "status-danger",
                "badge": "Likely to bounce",
                "primary_mx": "None",
                "mx_records": [],
            }
        ]
        insights = aggregate_domain_insights(sample_results)
        self.assertEqual(len(insights), 1)
        self.assertEqual(insights[0]["address_count"], 2)
        self.assertEqual(insights[0]["primary_mx"], "mx1.domain1.com")
        self.assertEqual(aggregate_domain_insights([]), [])

    # 16. Health Check Endpoint
    def test_health_check(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("service"), "EmailCheck")

    # 17. HTTP Error Handlers
    def test_http_error_handlers(self):
        # 404 handler via client
        resp_404 = self.client.get("/nonexistent-page-url-xyz")
        self.assertEqual(resp_404.status_code, 404)
        self.assertIn(b"could not be found", resp_404.data)

        # 413 handler
        msg_413, code_413 = app.error_handler_spec[None][413][RequestEntityTooLarge](RequestEntityTooLarge())
        self.assertEqual(code_413, 413)
        self.assertIn("too large", msg_413.lower())

        # 400 handler
        msg_400, code_400 = app.error_handler_spec[None][400][BadRequest](BadRequest())
        self.assertEqual(code_400, 400)

        # 500 handler
        msg_500, code_500 = app.error_handler_spec[None][500][InternalServerError](InternalServerError())
        self.assertEqual(code_500, 500)

    # 18. RFC 7505 Null MX Handling
    def test_null_mx_record_handling(self):
        """A DNS MX record with exchange '.' explicitly indicates the domain does not accept email."""
        null_mx_mock = MagicMock()
        null_mx_mock.preference = 0
        null_mx_mock.exchange = dns.name.from_text(".")

        with patch("email_checker.dns.resolver.resolve", return_value=[null_mx_mock]):
            res = resolve_domain_mail_config("null-mx-domain.example")
            self.assertEqual(res["classification"], CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(res["status"], CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(res["primary_mx"], ". (priority 0)")
            self.assertFalse(res["has_mx"])
            self.assertFalse(res["has_fallback"])
            self.assertIn("Null MX record (RFC 7505)", res["reason"])
            self.assertIn("does not accept email", res["reason"])

            # Also check assess_email output
            email_res = assess_email("test@null-mx-domain.example")
            self.assertEqual(email_res["classification"], CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(email_res["status"], CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(email_res["primary_mx"], ". (priority 0)")

    def test_null_mx_distinction_from_missing_mx(self):
        """Ensure Null MX does not fall back to A/AAAA records even if host records exist."""
        null_mx_mock = MagicMock()
        null_mx_mock.preference = 0
        null_mx_mock.exchange = "."

        mock_resolve = MagicMock()
        mock_resolve.return_value = [null_mx_mock]

        with patch("email_checker.dns.resolver.resolve", mock_resolve):
            res = resolve_domain_mail_config("explicit-null-mx.org")
            self.assertEqual(res["classification"], CATEGORY_LIKELY_TO_BOUNCE)
            # Resolver should only have been queried for MX, not A or AAAA
            for call in mock_resolve.call_args_list:
                self.assertEqual(call[0][1], "MX")

    # 19. Mixed Valid & Invalid Addresses with Same Domain
    def test_mixed_valid_and_invalid_addresses_domain_summary_independence(self):
        """
        Confirmed defect regression test:
        When a batch contains invalid syntax addresses and valid syntax addresses
        sharing the same domain, and an invalid address appears first,
        the domain summary must still accurately reflect the domain's DNS status.
        """
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.example.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            response = self.client.post("/", data={
                "emails": "malformed..address@example.com\nuser+tag@example.com"
            })
            self.assertEqual(response.status_code, 200)

            assess_invalid = assess_email("malformed..address@example.com")
            assess_valid = assess_email("user+tag@example.com")
            self.assertEqual(assess_invalid["classification"], CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(assess_valid["classification"], CATEGORY_LIKELY_DELIVERED)

            insights = aggregate_domain_insights([assess_invalid, assess_valid])
            self.assertEqual(len(insights), 1)
            self.assertEqual(insights[0]["domain"], "example.com")
            self.assertEqual(insights[0]["classification"], CATEGORY_LIKELY_DELIVERED)
            self.assertEqual(insights[0]["address_count"], 2)
            self.assertIn("mail.example.com", insights[0]["primary_mx"])

    # 20. Domain Summary When All Addresses Have Syntax Errors
    def test_domain_summary_all_addresses_invalid_syntax(self):
        """
        When all addresses for a domain have syntax errors, the domain summary
        should independently assess the domain DNS and report mail routing if valid.
        """
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.example.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            assess1 = assess_email("bad..user1@example.com")
            assess2 = assess_email("bad..user2@example.com")
            self.assertEqual(assess1["classification"], CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(assess2["classification"], CATEGORY_LIKELY_TO_BOUNCE)

            insights = aggregate_domain_insights([assess1, assess2])
            self.assertEqual(len(insights), 1)
            self.assertEqual(insights[0]["domain"], "example.com")
            self.assertEqual(insights[0]["classification"], CATEGORY_LIKELY_DELIVERED)
            self.assertEqual(insights[0]["address_count"], 2)

    # 21. Valid Plus-Addressing Syntax
    def test_valid_plus_addressing_syntax(self):
        emails = [
            "developer+testing@github.com",
            "support+ticket-1234@company.co.uk",
            "first.last+newsletter@domain.org",
        ]
        for em in emails:
            is_valid, local, domain, reason = validate_email_syntax(em)
            self.assertTrue(is_valid, f"Expected {em} to be valid, got reason: {reason}")
            self.assertIn("+", local)

    # 22. Assessment Time Precision (< 1ms vs 0ms)
    def test_execution_time_formatting_precision(self):
        with patch("time.perf_counter", side_effect=[100.0, 100.0003]):
            response = self.client.post("/", data={"emails": "user@example.com"})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"&lt; 1ms", response.data)
            self.assertNotIn(b">0ms<", response.data)

    # 23. Comma-Separated Input Parsing (ShieldNex Requirement 3)
    def test_comma_and_semicolon_separated_input_parsing(self):
        """Users can paste comma- or semicolon-separated email lists."""
        raw_input = "first@example.com, second@example.com; third@example.com"
        tokens = parse_email_input(raw_input)
        self.assertEqual(tokens, ["first@example.com", "second@example.com", "third@example.com"])

        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.example.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            response = self.client.post("/", data={"emails": raw_input})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"first@example.com", response.data)
            self.assertIn(b"second@example.com", response.data)
            self.assertIn(b"third@example.com", response.data)
            self.assertIn(b"From 3 submitted lines", response.data)

    # 24. Exact Three-Tier Classification Mapping (ShieldNex Requirement 1 & 2)
    def test_three_tier_classification_exact_categories(self):
        """Every assessed address must map to one of: Likely delivered, Likely to bounce, Unknown."""
        mx_mock = MagicMock()
        mx_mock.preference = 5
        mx_mock.exchange = "mail.domain.com."

        # Case A: Valid syntax + MX -> Likely delivered
        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            res_delivered = assess_email("valid.user@domain.com")
            self.assertEqual(res_delivered["classification"], "Likely delivered")
            self.assertEqual(res_delivered["status"], "Likely delivered")
            self.assertEqual(res_delivered["css"], "status-success")

        # Case B: Malformed syntax -> Likely to bounce
        res_syntax_err = assess_email("bad..syntax@domain.com")
        self.assertEqual(res_syntax_err["classification"], "Likely to bounce")
        self.assertEqual(res_syntax_err["status"], "Likely to bounce")
        self.assertEqual(res_syntax_err["css"], "status-danger")

        # Case C: Nonexistent domain -> Likely to bounce
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            res_nx = assess_email("user@nonexistent.domain")
            self.assertEqual(res_nx["classification"], "Likely to bounce")
            self.assertEqual(res_nx["status"], "Likely to bounce")

        # Case D: Null MX -> Likely to bounce
        null_mock = MagicMock()
        null_mock.preference = 0
        null_mock.exchange = "."
        with patch("email_checker.dns.resolver.resolve", return_value=[null_mock]):
            res_null = assess_email("user@nullmx.domain")
            self.assertEqual(res_null["classification"], "Likely to bounce")

        # Case E: No MX & No A/AAAA -> Likely to bounce
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
            res_no_routing = assess_email("user@norouting.domain")
            self.assertEqual(res_no_routing["classification"], "Likely to bounce")

        # Case F: DNS Timeout -> Unknown (NOT bounce)
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.exception.Timeout()):
            res_timeout = assess_email("user@timeout.domain")
            self.assertEqual(res_timeout["classification"], "Unknown")
            self.assertEqual(res_timeout["status"], "Unknown")
            self.assertEqual(res_timeout["css"], "status-neutral")

        # Case G: DNS Exception -> Unknown (NOT bounce)
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.exception.DNSException()):
            res_err = assess_email("user@dnserror.domain")
            self.assertEqual(res_err["classification"], "Unknown")
            self.assertEqual(res_err["status"], "Unknown")

    # 25. Batch Processing with Mixed Classifications (ShieldNex Requirement 2.D & 6)
    def test_batch_processing_mixed_three_categories(self):
        """Ensure batch contains all three categories and template shows them."""
        def mock_dns_resolve(qname, rdtype, **kwargs):
            q_str = str(qname).lower()
            if "deliverable" in q_str:
                mx_mock = MagicMock()
                mx_mock.preference = 10
                mx_mock.exchange = "mail.deliverable.com."
                return [mx_mock]
            elif "timeout" in q_str:
                raise dns.exception.Timeout()
            raise dns.resolver.NXDOMAIN()

        with patch("email_checker.dns.resolver.resolve", side_effect=mock_dns_resolve):
            batch_input = (
                "user@deliverable.com\n"
                "user@timeout.com\n"
                "invalid..syntax@test.com\n"
                "user@nxdomain.com"
            )
            response = self.client.post("/", data={"emails": batch_input})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Likely delivered", response.data)
            self.assertIn(b"Likely to bounce", response.data)
            self.assertIn(b"Unknown", response.data)

    # 26. Uncertainty Must Never Be Classified As Bounce (ShieldNex Requirement 2.B)
    def test_uncertainty_is_never_classified_as_bounce(self):
        """DNS timeouts or connection errors must be Unknown, never Likely to bounce."""
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.exception.Timeout()):
            res = assess_email("user@uncertain-network.org")
            self.assertNotEqual(res["classification"], CATEGORY_LIKELY_TO_BOUNCE)
            self.assertEqual(res["classification"], CATEGORY_UNKNOWN)
            self.assertIn("timed out", res["reason"].lower())

    # 27. Individual Mailbox Claims Strictly Disclaimed (ShieldNex Requirement 2.C)
    def test_mailbox_existence_disclaimed_and_limitation_present(self):
        """DNS assessment must have is_deliverable_claim=False and explicit limitation text."""
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.company.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            res = assess_email("ceo@company.com")
            self.assertFalse(res["is_deliverable_claim"])
            self.assertIn("limitation", res)
            self.assertIn("mailbox existence cannot be confirmed", res["limitation"].lower())

    # 28. CSV Export with Comma-Separated Submissions
    def test_csv_export_with_comma_separated_submission(self):
        """CSV export handles comma-separated email input list properly."""
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            response = self.client.post("/export-csv", data={
                "emails": "alpha@test.com, beta@test.com, gamma@test.com"
            })
            self.assertEqual(response.status_code, 200)
            csv_content = response.data.decode("utf-8")
            self.assertIn("alpha@test.com", csv_content)
            self.assertIn("beta@test.com", csv_content)
            self.assertIn("gamma@test.com", csv_content)

    # 29. Batch Domain Resolution Avoids Repeated Lookups
    def test_batch_resolution_avoids_repeated_domain_lookups(self):
        """Within a batch, multiple email addresses sharing a domain trigger at most one DNS lookup."""
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.company.com."

        mock_resolve = MagicMock(return_value=[mx_mock])
        with patch("email_checker.dns.resolver.resolve", mock_resolve):
            batch = [f"employee{i}@company.com" for i in range(25)]
            results = assess_batch(batch)
            self.assertEqual(len(results), 25)
            # Exactly 1 DNS MX resolution call for company.com across all 25 addresses
            self.assertEqual(mock_resolve.call_count, 1)
            for res in results:
                self.assertEqual(res["classification"], CATEGORY_LIKELY_DELIVERED)
                self.assertEqual(res["domain"], "company.com")

    # 30. Assess Batch Bounded Concurrency & Strict Order Preservation
    def test_assess_batch_concurrent_processing_and_order_preservation(self):
        """assess_batch correctly evaluates mixed scenarios and strictly preserves input ordering."""
        def mock_dns_resolve(qname, rdtype, **kwargs):
            q = str(qname).lower().rstrip(".")
            if "valid-mx" in q:
                mx_mock = MagicMock()
                mx_mock.preference = 5
                mx_mock.exchange = f"mx.{q}."
                return [mx_mock]
            elif "null-mx" in q:
                null_mock = MagicMock()
                null_mock.preference = 0
                null_mock.exchange = "."
                return [null_mock]
            elif "fallback-host" in q:
                if rdtype == "MX":
                    raise dns.resolver.NoAnswer()
                elif rdtype == "A":
                    a_mock = MagicMock()
                    a_mock.__str__ = lambda x: "1.2.3.4"
                    return [a_mock]
            elif "nxdomain" in q:
                raise dns.resolver.NXDOMAIN()
            elif "timeout" in q:
                raise dns.exception.Timeout()
            raise dns.resolver.NXDOMAIN()

        with patch("email_checker.dns.resolver.resolve", side_effect=mock_dns_resolve):
            input_list = [
                "alpha@valid-mx-1.com",
                "malformed..dots@invalid.syntax",
                "beta@null-mx.org",
                "gamma@fallback-host.net",
                "delta@nxdomain-test.xyz",
                "epsilon@timeout-domain.io",
                "zeta@valid-mx-1.com",  # Repeated domain
            ]
            results = assess_batch(input_list)
            self.assertEqual(len(results), len(input_list))

            # Verify order preservation and exact classifications
            self.assertEqual(results[0]["email"], "alpha@valid-mx-1.com")
            self.assertEqual(results[0]["classification"], CATEGORY_LIKELY_DELIVERED)

            self.assertEqual(results[1]["email"], "malformed..dots@invalid.syntax")
            self.assertEqual(results[1]["classification"], CATEGORY_LIKELY_TO_BOUNCE)
            self.assertIn("Invalid email syntax", results[1]["reason"])

            self.assertEqual(results[2]["email"], "beta@null-mx.org")
            self.assertEqual(results[2]["classification"], CATEGORY_LIKELY_TO_BOUNCE)
            self.assertIn("Null MX", results[2]["reason"])

            self.assertEqual(results[3]["email"], "gamma@fallback-host.net")
            self.assertEqual(results[3]["classification"], CATEGORY_LIKELY_DELIVERED)
            self.assertIn("Implicit mail routing fallback", results[3]["reason"])

            self.assertEqual(results[4]["email"], "delta@nxdomain-test.xyz")
            self.assertEqual(results[4]["classification"], CATEGORY_LIKELY_TO_BOUNCE)

            self.assertEqual(results[5]["email"], "epsilon@timeout-domain.io")
            self.assertEqual(results[5]["classification"], CATEGORY_UNKNOWN)

            self.assertEqual(results[6]["email"], "zeta@valid-mx-1.com")
            self.assertEqual(results[6]["classification"], CATEGORY_LIKELY_DELIVERED)

    # 31. 500-Address Batch Stress & Accounting Test
    def test_assess_batch_500_addresses_stress_and_accounting(self):
        """Verify that a full 500-address batch processes deterministically without omissions."""
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.large-scale-test.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            # 500 addresses across 10 shared domains + invalid syntax addresses
            large_batch = []
            for i in range(500):
                if i % 50 == 0:
                    large_batch.append(f"invalid..user{i}@badformat.com")
                else:
                    dom_id = i % 10
                    large_batch.append(f"user{i}@cluster{dom_id}.domain.com")

            self.assertEqual(len(large_batch), 500)
            t_start = time.perf_counter()
            results = assess_batch(large_batch, max_workers=16)
            elapsed = time.perf_counter() - t_start

            # Complete accounting: exactly 500 results returned
            self.assertEqual(len(results), 500)
            self.assertLess(elapsed, 5.0, "500-address assessment must complete within 5 seconds")

            delivered = sum(r["classification"] == CATEGORY_LIKELY_DELIVERED for r in results)
            bounces = sum(r["classification"] == CATEGORY_LIKELY_TO_BOUNCE for r in results)
            # 10 invalid syntax addresses
            self.assertEqual(bounces, 10)
            self.assertEqual(delivered, 490)

    # 32. JSON / AJAX API Endpoint Progressive Enhancement
    def test_json_ajax_endpoint_response(self):
        """The application returns structured JSON when requested via Accept: application/json."""
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.api-test.com."

        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            resp = self.client.post(
                "/",
                data={"emails": "api.user1@api-test.com\napi.user2@api-test.com", "batch_limit": "100"},
                headers={"Accept": "application/json"}
            )
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.mimetype, "application/json")
            data = resp.get_json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["unique_count"], 2)
            self.assertEqual(len(data["results"]), 2)
            self.assertIn("metrics", data)
            self.assertEqual(data["metrics"]["likely_delivered_count"], 2)

    # 33. Inconclusive Retry Workflow
    def test_inconclusive_retry_flow(self):
        """Simulate re-evaluating inconclusive (Unknown) addresses after network stabilizes."""
        # Phase 1: DNS times out
        with patch("email_checker.dns.resolver.resolve", side_effect=dns.exception.Timeout()):
            res1 = assess_batch(["user@retry-test.com"])
            self.assertEqual(res1[0]["classification"], CATEGORY_UNKNOWN)

        # Clear cache to simulate re-query
        clear_dns_cache()

        # Phase 2: DNS recovers and resolves active MX
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = "mail.recovered.com."
        with patch("email_checker.dns.resolver.resolve", return_value=[mx_mock]):
            res2 = assess_batch(["user@retry-test.com"])
            self.assertEqual(res2[0]["classification"], CATEGORY_LIKELY_DELIVERED)


if __name__ == "__main__":
    unittest.main()

