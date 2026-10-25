
from flask import Flask, request, render_template_string
import re
import smtplib
import dns.resolver
import dns.exception

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
MAX_EMAILS = 20
MAX_INPUT_LENGTH = 12000

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?)+$"
)

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EmailCheck | Email Assessment</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0; font-family: Arial, sans-serif;
    background: #f1f5f9; color: #172033;
}
header {
    background: #172554; color: white;
    padding: 28px 16px; text-align: center;
}
header p { color: #dbeafe; }
main { max-width: 1000px; margin: 28px auto; padding: 0 16px; }
.panel {
    background: white; padding: 22px; border-radius: 12px;
    box-shadow: 0 3px 14px #0000000c; margin-bottom: 20px;
}
textarea {
    width: 100%; min-height: 150px; padding: 12px;
    border: 1px solid #cbd5e1; border-radius: 8px;
    font: 15px Arial; resize: vertical;
}
button {
    border: 0; border-radius: 8px; padding: 12px 18px;
    cursor: pointer; font-size: 15px; margin: 8px 6px 0 0;
}
.primary { background: #2563eb; color: white; }
.secondary { background: #e2e8f0; color: #172033; }
button:disabled { opacity: .6; cursor: wait; }
.notice { color: #475569; line-height: 1.6; font-size: 14px; }
.stats { display: flex; gap: 12px; flex-wrap: wrap; }
.stat {
    flex: 1; min-width: 140px; padding: 16px;
    border-radius: 8px; background: #eff6ff;
}
.stat strong { display: block; font-size: 26px; margin-top: 8px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td {
    text-align: left; padding: 12px 8px;
    border-bottom: 1px solid #e2e8f0; overflow-wrap: anywhere;
}
th { background: #f8fafc; }
.good { color: #166534; }
.bad { color: #b91c1c; }
.unknown { color: #92400e; }
.status { font-weight: bold; }
footer { text-align: center; color: #64748b; padding: 20px; }
</style>
</head>
<body>
<header>
    <h1>EmailCheck</h1>
    <p>Understand email address checks with transparent results.</p>
</header>
<main>
    <section class="panel">
        <h2>Check email addresses</h2>
        <p>Enter up to 20 unique addresses, one per line.</p>
        <form method="post" id="checkForm">
            <textarea name="emails" required maxlength="12000"
                placeholder="person@example.com&#10;another@example.org"
            >{{ input_text }}</textarea>
            <br>
            <button class="primary" id="checkButton" type="submit">
                Check addresses
            </button>
            <button class="secondary" type="button"
                onclick="window.location.href='/'">Reset</button>
            <span id="loading" role="status" aria-live="polite"></span>
        </form>
        <p class="notice">
            Results are estimates, not delivery guarantees.
            This tool does not send email messages. Use only addresses
            you are authorized to assess.
        </p>
    </section>

    {% if notice %}
    <section class="panel notice" role="alert">{{ notice }}</section>
    {% endif %}

    {% if results %}
    <section class="panel">
        <h2>Assessment summary</h2>
        <div class="stats">
            <div class="stat">Unique addresses
                <strong>{{ results|length }}</strong></div>
            <div class="stat">Likely delivered
                <strong>{{ good_count }}</strong></div>
            <div class="stat">Likely to bounce
                <strong>{{ bad_count }}</strong></div>
            <div class="stat">Unknown
                <strong>{{ unknown_count }}</strong></div>
        </div>
        <button class="primary" type="button" onclick="downloadCSV()">
            Download CSV
        </button>
    </section>

    <section class="panel">
        <h2>Individual results</h2>
        <div class="table-wrap">
        <table id="resultsTable">
            <thead><tr>
                <th>Email address</th><th>Result</th><th>Reason</th>
            </tr></thead>
            <tbody>
            {% for item in results %}
            <tr>
                <td>{{ item.email }}</td>
                <td class="status {{ item.css }}">{{ item.status }}</td>
                <td>{{ item.reason }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        </div>
    </section>
    {% endif %}
</main>
<footer>EmailCheck | Transparent email assessment</footer>
<script>
const form = document.getElementById("checkForm");
if (form) {
    form.addEventListener("submit", function () {
        document.getElementById("checkButton").disabled = true;
        document.getElementById("loading").textContent =
            " Checking addresses... Please wait.";
    });
}

function downloadCSV() {
    const table = document.getElementById("resultsTable");
    if (!table) return;

    const rows = Array.from(table.querySelectorAll("tr"));
    const csv = rows.map(row =>
        Array.from(row.querySelectorAll("th,td")).map(cell => {
            let value = cell.innerText.replace(/"/g, '""');
            if (/^[=+@\\-\\t\\r]/.test(value)) {
                value = "'" + value;
            }
            return '"' + value + '"';
        }).join(",")
    ).join("\\r\\n");

    const blob = new Blob(["\\ufeff" + csv], {
        type: "text/csv;charset=utf-8;"
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "emailcheck-results.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
</script>
</body>
</html>
"""


def check_email(email):
    if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
        return ("Likely to bounce", "bad",
                "The address format is invalid.")

    local, domain = email.rsplit("@", 1)

    if (len(local) > 64 or ".." in local
            or local.startswith(".") or local.endswith(".")):
        return ("Likely to bounce", "bad",
                "The address format is invalid.")

    try:
        records = dns.resolver.resolve(domain, "MX", lifetime=2)
        servers = sorted(records, key=lambda r: r.preference)

    except dns.resolver.NXDOMAIN:
        return ("Likely to bounce", "bad",
                "The email domain does not exist.")

    except dns.resolver.NoAnswer:
        return ("Unknown", "unknown",
                "No MX record was found; delivery is unconfirmed.")

    except (dns.exception.DNSException, OSError, ValueError):
        return ("Unknown", "unknown",
                "The DNS check failed or timed out.")

    for record in servers[:2]:
        server = str(record.exchange).rstrip(".")

        try:
            with smtplib.SMTP(server, 25, timeout=2) as smtp:
                smtp.ehlo()
                code, _ = smtp.mail("")

                if code != 250:
                    continue

                code, reply = smtp.rcpt(email)
                message = reply.decode(
                    "utf-8", errors="replace"
                ).lower()

                if code in (250, 251):
                    return (
                        "Likely delivered", "good",
                        "The server accepted the recipient check; "
                        "actual delivery is not guaranteed."
                    )

                if code == 550 and any(term in message for term in (
                    "5.1.1", "user unknown", "mailbox unavailable"
                )):
                    return (
                        "Likely to bounce", "bad",
                        "The server reported that the mailbox "
                        "may not exist."
                    )

        except (smtplib.SMTPException, OSError, TimeoutError):
            continue

    return (
        "Unknown", "unknown",
        "The server gave no conclusive result or the connection "
        "was unavailable."
    )


@app.route("/", methods=["GET", "POST"])
def home():
    input_text = ""
    results = []
    notice = ""

    if request.method == "POST":
        input_text = request.form.get("emails", "")

        if len(input_text) > MAX_INPUT_LENGTH:
            notice = "Input is too long. Please shorten your list."
        else:
            raw_emails = [
                line.strip()
                for line in input_text.splitlines()
                if line.strip()
            ]

            emails = list(dict.fromkeys(raw_emails))

            if not emails:
                notice = "Please enter at least one email address."

            elif len(emails) > MAX_EMAILS:
                notice = (
                    "Please submit no more than 20 unique "
                    "email addresses at a time."
                )

            else:
                for email in emails:
                    status, css, reason = check_email(email)
                    results.append({
                        "email": email,
                        "status": status,
                        "css": css,
                        "reason": reason
                    })

    return render_template_string(
        PAGE,
        input_text=input_text,
        results=results,
        notice=notice,
        good_count=sum(
            r["status"] == "Likely delivered" for r in results
        ),
        bad_count=sum(
            r["status"] == "Likely to bounce" for r in results
        ),
        unknown_count=sum(
            r["status"] == "Unknown" for r in results
        )
    )


@app.errorhandler(413)
def too_large(_error):
    return "Input is too large. Please submit a smaller list.", 413


if __name__ == "__main__":
    app.run(debug=False)
