
import unittest
from unittest.mock import patch
import dns.resolver
import dns.exception

from app import app, check_email


class EmailCheckTests(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_web_page_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"EmailCheck", response.data)

    def test_invalid_address(self):
        status, css, reason = check_email("invalid-address")

        self.assertEqual(status, "Likely to bounce")
        self.assertEqual(css, "bad")
        self.assertIn("format is invalid", reason)

    def test_missing_mx_record(self):
        with patch(
            "app.dns.resolver.resolve",
            side_effect=dns.resolver.NoAnswer
        ):
            status, css, reason = check_email("user@example.com")

        self.assertEqual(status, "Unknown")
        self.assertEqual(css, "unknown")
        self.assertIn("No MX record", reason)

    def test_nonexistent_domain(self):
        with patch(
            "app.dns.resolver.resolve",
            side_effect=dns.resolver.NXDOMAIN
        ):
            status, css, reason = check_email("user@example.com")

        self.assertEqual(status, "Likely to bounce")
        self.assertIn("domain does not exist", reason)

    def test_dns_timeout(self):
        with patch(
            "app.dns.resolver.resolve",
            side_effect=dns.exception.Timeout
        ):
            status, css, reason = check_email("user@example.com")

        self.assertEqual(status, "Unknown")
        self.assertIn("DNS check failed", reason)

    def test_smtp_accepts_recipient(self):
        mx_record = type("MX", (), {
            "exchange": "mail.example.com.",
            "preference": 10
        })()

        with patch(
            "app.dns.resolver.resolve",
            return_value=[mx_record]
        ), patch("app.smtplib.SMTP") as mock_smtp:

            server = (
                mock_smtp.return_value
                .__enter__.return_value
            )
            server.mail.return_value = (250, b"OK")
            server.rcpt.return_value = (250, b"OK")

            status, css, reason = check_email(
                "user@example.com"
            )

        self.assertEqual(status, "Likely delivered")
        self.assertEqual(css, "good")
        self.assertIn("not guaranteed", reason)

    def test_smtp_unavailable(self):
        mx_record = type("MX", (), {
            "exchange": "mail.example.com.",
            "preference": 10
        })()

        with patch(
            "app.dns.resolver.resolve",
            return_value=[mx_record]
        ), patch(
            "app.smtplib.SMTP",
            side_effect=OSError("Connection failed")
        ):

            status, css, reason = check_email(
                "user@example.com"
            )

        self.assertEqual(status, "Unknown")
        self.assertEqual(css, "unknown")

    def test_duplicate_addresses_are_deduplicated(self):
        response = self.client.post("/", data={
            "emails": "invalid-address\ninvalid-address"
        })

        self.assertEqual(response.status_code, 200)

        # The invalid-format reason should appear only once
        # because duplicate addresses are removed.
        self.assertEqual(
            response.data.count(
                b"The address format is invalid."
            ),
            1
        )

    def test_more_than_20_addresses(self):
        emails = "\n".join(
            "invalid-address-" + str(i)
            for i in range(21)
        )

        response = self.client.post("/", data={
            "emails": emails
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Please submit no more than 20 unique "
            b"email addresses at a time.",
            response.data
        )

    def test_empty_submission(self):
        response = self.client.post("/", data={
            "emails": ""
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Please enter at least one email address.",
            response.data
        )

    def test_csv_export_button_is_available(self):
        response = self.client.post("/", data={
            "emails": "not-an-email"
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Download CSV", response.data)
        self.assertIn(b"function downloadCSV()", response.data)


if __name__ == "__main__":
    unittest.main()
