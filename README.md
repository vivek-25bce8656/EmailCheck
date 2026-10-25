# EmailCheck | Advanced Email Intelligence & DNS Verification Platform

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-25%20passing%20%7C%2095%25%20coverage-brightgreen.svg)]()
[![Deployment](https://img.shields.io/badge/deployment-Render-46E3B7.svg)](https://emailcheck-5n2a.onrender.com/)

**EmailCheck** is a modern, high-precision, production-grade email intelligence and routing verification platform. Built with Python, Flask, and `dnspython`, it provides deterministic, evidence-based assessments of RFC syntax compliance, domain existence, active Mail Exchange (MX) routing, and implicit RFC 5321 fallback configurations.

- **Live Application:** [https://emailcheck-5n2a.onrender.com/](https://emailcheck-5n2a.onrender.com/)
- **Source Repository:** [https://github.com/vivek-25bce8656/EmailCheck](https://github.com/vivek-25bce8656/EmailCheck)

---

## Key Features

- **Strict RFC 5321 & 5322 Syntax Validation**: Enforces full address length constraints (<= 254 chars), local-part constraints (<= 64 chars, no consecutive periods, no leading/trailing periods), and RFC-compliant domain label structures.
- **Active Mail Exchange (MX) Analysis**: Resolves authoritative MX records, ranks mail exchangers by preference, and reports primary mail gateways.
- **RFC 5321 Section 5.1 Fallback Routing**: If a domain has no designated MX records, EmailCheck automatically inspects host A and AAAA records for implicit fallback mail routing.
- **Fast Bounded In-Memory Caching**: Caches domain lookup results within a bounded TTL window, dramatically speeding up multi-address batch assessments while preventing redundant DNS queries.
- **Enterprise UI/UX Design**:
  - Dark and Light mode with persistent state (`localStorage`).
  - Live client-side input analysis (live unique count, duplicate detection, and visual capacity meter).
  - One-click sample dataset loader.
  - Interactive results table with instant search, status filtering, sortable columns, and one-click copy to clipboard.
  - Aggregated domain-level intelligence summary cards.
- **Spreadsheet Formula Injection Defense**: CSV exports automatically neutralize executable spreadsheet triggers (`=`, `+`, `-`, `@`, `\t`, `\r`).
- **Comprehensive Security Headers**: Pre-configured HTTP response headers including Content Security Policy (CSP), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy`.
- **Privacy & Safety First**: Zero email delivery attempts, zero invasive SMTP mailbox handshakes (avoiding IP blacklisting and port 25 cloud blocks), and zero query data retention.

---

## Technical Architecture

```
EmailCheck/
|-- app.py                 # Application controller, routes, error handlers, and security headers
|-- email_checker.py       # Core assessment engine, RFC parsing, DNS fallback logic, and cache
|-- templates/
|   `-- index.html         # Accessible semantic HTML5 interface
|-- static/
|   |-- css/
|   |   `-- style.css      # SaaS design system, CSS variables, and light/dark theme
|   `-- js/
|       `-- app.js         # Reactive UI, live input statistics, filtering, sorting, and CSV export
|-- test_app.py            # Comprehensive 25-test test suite with 100% mocked DNS
|-- requirements.txt       # Production dependencies
|-- .gitignore             # Git exclusion rules
`-- README.md              # Platform documentation
```

---

## Assessment Categories & Evidence

EmailCheck delivers technically honest assessments based on observable network evidence:

| Status Label | Indicator | Technical Meaning |
| :--- | :---: | :--- |
| **Mail configuration detected** | `Green` | Domain has active MX records or valid RFC 5321 fallback host records (A/AAAA) configured to route mail. |
| **No MX record detected** | `Amber` | Domain exists in DNS, but has neither MX records nor fallback host records for mail delivery. |
| **Domain not found** | `Red` | Domain does not exist in DNS (`NXDOMAIN`). |
| **Invalid format** | `Red` | Address violates RFC 5321/5322 syntax specifications. |
| **Unable to verify** | `Neutral` | DNS query timed out or encountered a temporary network resolution failure. |

> **Important Notice on Mailbox Deliverability:**
> DNS and MX records prove that mail infrastructure is configured for a domain. They do **not** guarantee that an individual recipient mailbox exists or that an inbox will accept an incoming message. EmailCheck explicitly avoids claiming delivery guarantees because truthful verification without intrusive SMTP spamming cannot be performed.

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

The test suite runs with 100% mocked DNS responses, ensuring fast, reproducible execution without internet dependencies or network flakiness.

```bash
python -m unittest test_app.py -v
```

To run with coverage measurement:
```bash
coverage run -m unittest test_app.py
coverage report -m
```

### Test Coverage Highlights:
- Homepage rendering and security headers (`X-Frame-Options`, `nosniff`, `CSP`)
- RFC 5321 & 5322 syntax parsing (missing `@`, leading/trailing periods, consecutive periods, label constraints)
- Boundary checks for local-part (64 chars) and total email length (254 chars)
- Server-side deduplication preserving insertion order
- Input capacity limits (20 unique addresses, 12,000 char maximum length)
- Active MX record resolution and primary gateway reporting
- RFC 5321 Section 5.1 host fallback routing (both IPv4 A and IPv6 AAAA records)
- Nonexistent domains (`NXDOMAIN`), timeouts, and DNS exceptions
- Thread-safe bounded DNS caching with failure TTL handling
- Spreadsheet formula injection protection in CSV outputs
- HTML escaping preventing cross-site scripting (XSS)
- Health check endpoint verification
- HTTP error handling (400, 404, 413, 500)

---

## Production Deployment (Render)

EmailCheck is configured for zero-friction deployment on Render:

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

## Security & Responsible Use

- **Input Restrictions:** Maximum of 20 unique email addresses per submission; maximum payload size of 32 KB.
- **Safe CSV Handling:** All user-controlled fields exported to CSV are prepended with an apostrophe if they begin with arithmetic operators or formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`).
- **Privacy:** EmailCheck processes addresses in memory and does not persist address queries to any database or external logging service.
- **Usage Policy:** Only submit email addresses and domains you are authorized to assess.

---

## License

This project is open-source under the [MIT License](LICENSE).
