# EmailCheck PRO | Email Validation & DNS Routing Assessment Platform

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-31%20passing%20%7C%2095%25%20coverage-brightgreen.svg)]()
[![Deployment](https://img.shields.io/badge/deployment-Render-46E3B7.svg)](https://emailcheck-5n2a.onrender.com/)

> **Recommended GitHub Repository Description:**
> *Email syntax validation and DNS-based mail-routing assessment with MX lookup, A/AAAA fallback, safe CSV export, and privacy-conscious processing. No SMTP mailbox probing.*

**EmailCheck PRO** is a reliable, high-precision, production-ready email syntax and DNS mail-routing assessment platform. Built with Python, Flask, and `dnspython`, it delivers deterministic, evidence-based assessments of RFC-oriented email syntax compliance, domain existence, authoritative Mail Exchange (MX) routing, RFC 5321 host fallback, and explicit RFC 7505 Null MX declarations.

- **Live Application:** [https://emailcheck-5n2a.onrender.com/](https://emailcheck-5n2a.onrender.com/)
- **Source Repository:** [https://github.com/vivek-25bce8656/EmailCheck](https://github.com/vivek-25bce8656/EmailCheck)

---

## Key Features

- **RFC-Oriented Syntax Validation**: Enforces full address length constraints (<= 254 chars), local-part constraints (<= 64 chars, no consecutive periods, no leading/trailing periods, whitespace detection), Internationalized Domain Names (IDN/Punycode), and valid plus-addressing (`user+tag@example.com`).
- **Active Mail Exchange (MX) Analysis**: Resolves authoritative MX records, ranks mail exchangers by preference, and reports primary mail gateways.
- **RFC 7505 Null MX Detection**: Explicitly identifies domains that publish a Null MX record (`.` with priority 0), declaring that the domain does not accept email. Ensures that ordinary fallback routing is not erroneously applied.
- **RFC 5321 Section 5.1 Fallback Routing**: If a domain lacks dedicated MX records and does not publish a Null MX record, EmailCheck automatically inspects IPv4 (A) and IPv6 (AAAA) records for implicit fallback mail routing.
- **Independent Domain-Level Intelligence Aggregation**: Decouples domain DNS evaluation from individual address syntax results. Syntax errors in individual addresses never distort the domain's actual DNS routing status.
- **Fast Bounded In-Memory DNS Caching**: Thread-safe cache with TTL windows speeds up multi-address batch assessments while preventing redundant DNS lookups.
- **Spreadsheet Formula Injection Defense**: CSV exports automatically neutralize executable spreadsheet triggers (`=`, `+`, `-`, `@`, `\t`, `\r`) with leading apostrophe shielding.
- **Enterprise UI/UX Design**:
  - Dark and Light mode with persistent state (`localStorage`).
  - Live client-side input analysis (live unique count, duplicate detection, and visual capacity meter).
  - One-click sample dataset loader.
  - Interactive results table with instant search, status filtering, sortable columns, and one-click copy to clipboard.
  - Aggregated domain-level intelligence summary cards.
- **Comprehensive Security Headers**: Pre-configured HTTP response headers including Content Security Policy (CSP), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy`.
- **Privacy-Conscious Processing**: No application-level address storage, zero email delivery attempts, and zero invasive SMTP mailbox handshakes.

---

## Technical Architecture

```
EmailCheck/
|-- app.py                 # Application controller, routes, error handlers, and security headers
|-- email_checker.py       # Core assessment engine, RFC parsing, Null MX, DNS fallback, and cache
|-- templates/
|   `-- index.html         # Accessible semantic HTML5 interface
|-- static/
|   |-- css/
|   |   `-- style.css      # SaaS design system, CSS variables, and light/dark theme
|   `-- js/
|       `-- app.js         # Reactive UI, live input statistics, filtering, sorting, and CSV export
|-- test_app.py            # Comprehensive 31-test test suite with 100% mocked DNS
|-- requirements.txt       # Production dependencies
|-- .gitignore             # Git exclusion rules
`-- README.md              # Platform documentation
```

---

## Assessment Categories & Evidence

EmailCheck delivers technically honest assessments based on observable network evidence:

| Status Label | Badge Indicator | Technical Meaning |
| :--- | :---: | :--- |
| **Mail configuration detected** | `Green` | Domain has active MX records or valid RFC 5321 fallback host records (A/AAAA) configured to route mail. |
| **No MX record detected** | `Amber` | Domain exists in DNS, but has neither MX records nor fallback host records for mail delivery. |
| **Null MX** | `Amber` | Domain publishes an RFC 7505 Null MX record (`.`), explicitly declaring that it does not accept email. Fallback does not apply. |
| **Domain not found** | `Red` | Domain does not exist in DNS (`NXDOMAIN`). |
| **Invalid format** | `Red` | Address violates RFC syntax specifications. |
| **Unable to verify** | `Neutral` | DNS query timed out or encountered a temporary resolver error. Not treated as proof of nonexistence. |

> **Important Notice on Mailbox Deliverability:**
> DNS and MX records verify mail-routing infrastructure configuration, not individual mailbox existence or guaranteed delivery. EmailCheck does not send emails or perform invasive SMTP mailbox probing.

---

## Technology Stack

- **Backend:** Python 3.10+ / Flask
- **DNS Resolution:** `dnspython`
- **WSGI Server:** Gunicorn (Production)
- **Frontend:** Vanilla HTML5, Modern CSS3 with CSS Custom Properties, Vanilla JavaScript (Zero bloated external frontend dependencies)
- **Deployment Target:** Render (Web Service)

---

## Local Development & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/vivek-25bce8656/EmailCheck.git
cd EmailCheck
```

### 2. Create and Activate a Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**On macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

The application will start on `http://127.0.0.1:5000`.

---

## Running Automated Tests

The test suite runs with 100% mocked DNS responses, ensuring fast, deterministic execution without internet dependencies or network flakiness.

```bash
python -m unittest test_app.py -v
```

### Test Coverage Highlights:
- Homepage rendering and security headers (`X-Frame-Options`, `nosniff`, `CSP`)
- RFC-oriented syntax parsing (missing `@`, multiple `@`, spaces, consecutive periods, label constraints)
- Boundary checks for local-part (64 chars) and total email length (254 chars)
- Server-side deduplication preserving insertion order
- Input capacity limits (20 unique addresses, 12,000 char maximum length)
- Active MX record resolution and primary gateway reporting
- RFC 7505 Null MX detection and disallowing improper fallback routing
- RFC 5321 Section 5.1 host fallback routing (both IPv4 A and IPv6 AAAA records)
- Nonexistent domains (`NXDOMAIN`), timeouts, and DNS exceptions (distinguishing timeouts from NXDOMAIN)
- Independent domain-level summary aggregation for mixed valid/invalid batches
- Thread-safe bounded DNS caching with failure TTL handling
- Spreadsheet formula injection protection in CSV outputs
- Assessment duration formatting precision (< 1ms vs 0ms)
- HTML escaping preventing cross-site scripting (XSS)
- Health check endpoint verification (`/health`)
- HTTP error handling (400, 404, 413, 500)

---

## Production Deployment (Render)

EmailCheck is configured for deployment on Render:

1. Connect your GitHub repository to Render as a **Web Service**.
2. Set the **Environment** to `Python 3`.
3. Set the **Build Command**:
   ```bash
   pip install -r requirements.txt
   ```
4. Set the **Start Command**:
   ```bash
   gunicorn app:app
   ```
5. Deploy service.

---

## Security, Privacy & Responsible Use

- **Input Restrictions:** Maximum of 20 unique email addresses per submission; maximum payload size of 32 KB.
- **Safe CSV Handling:** All user-controlled fields exported to CSV are prepended with an apostrophe if they begin with arithmetic operators or formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`).
- **No Application-Level Address Storage:** EmailCheck processes addresses in memory and does not persist address queries to any database or internal storage. Standard hosting provider network transit logs remain outside application control.
- **Usage Policy:** Only submit email addresses and domains you are authorized to assess.

---

## License

This project is open-source under the [MIT License](LICENSE).
