
from flask import Flask, request, render_template_string
import re
import dns.resolver
import dns.exception
import smtplib

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
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
    background: #f4f7fb; color: #172033;
}
header {
    background: #172554; color: white;
    padding: 24px; text-align: center;
}
header p { color: #dbeafe; }
main { max-width: 900px; margin: 28px auto; padding: 0 16px; }
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
    background: #2563eb; color: white; border: 0;
    border-radius: 8px; padding: 12px 20px;
    cursor: pointer; font-size: 15px; margin-top: 12px;
}
button:hover { background: #1d4ed8; }
.notice { color: #475569; line-height: 1.5; font-size: 14px; }
.stats { display: flex; gap: 12px; flex-wrap: wrap; }
.stat {
    flex: 1; min-width: 150px; padding: 16px;
    border-radius: 8px; background: #eff6ff;
}
.stat strong { display: block; font-size: 25px; margin-top: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td {
    text-align: left; padding: 12px 8px;
    border-bottom: 1px solid #e2e8f0; overflow-wrap: anywhere;
}
th { background: #f8fafc; }
.status { font-weight: bold; }
.good { color: #166534; }
.bad { color: #b91c1c; }
.unknown { color: #92400e; }
.table-wrap { overflow-x: auto; }
footer { text-align: center; color: #64748b; padding: 20px; }
</style>
</head>
<body>
<header>
    <h1>EmailCheck</h1>
    <p>Assess email addresses with clear, honest results.</p>
</header>
<main>
    <section class="panel">
        <h2>Check email addresses</h2>
        <p>Paste one address per line.</p>
        <form method="post">
            <textarea name="emails" required
                placeholder="person@example.com&#10;another@example.org"
            >{{ input_text }}</textarea>
            <br>
            <button type="submit">Check addresses</button>
        </form>
        <p class="notice">
            Results are estimates, not guarantees of inbox delivery.
            Do not use this tool to send messages to addresses you do not own.
        </p>
    </section>
    {% if notice %}
    <section class="panel notice">
        {{ notice }}
    </section>
    {% endif %}
    {% if results %}
    <section class="panel">
        <h2>Assessment summary</h2>
        <div class="stats">
            <div class="stat">Total checked<strong>{{ results|length }}</strong></div>
            <div class="stat">Likely delivered<strong>{{ good_count }}</strong></div>
            <div class="stat">Likely to bounce<strong>{{ bad_count }}</strong></div>
            <div class="stat">Unknown<strong>{{ unknown_count }}</strong></div>
        </div>
    </section>
    <section class="panel">
        <h2>Individual results</h2>
        <div class="table-wrap">
        <table>
            <thead><tr><th>Email address</th><th>Result</th><th>Reason</th></tr></thead>
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
<footer>EmailCheck &middot; Transparent email assessment</footer>
</body>
</html>
"""



def check_email(email):
    pattern = r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

    if not re.fullmatch(pattern, email):
        return ("Likely to bounce", "bad",
                "The address format is invalid.")

    domain = email.rsplit("@", 1)[1].lower()

    try:
        mx_records = dns.resolver.resolve(
            domain, "MX", lifetime=3
        )
        servers = sorted(
            mx_records, key=lambda record: record.preference
        )

    except dns.resolver.NXDOMAIN:
        return ("Likely to bounce", "bad",
                "The email domain does not exist.")

    except dns.resolver.NoAnswer:
        return ("Unknown", "unknown",
                "No MX record was found; mailbox delivery "
                "could not be verified.")

    except (dns.exception.DNSException, OSError):
        return ("Unknown", "unknown",
                "The domain check failed or timed out.")

    for record in servers[:2]:
        server = str(record.exchange).rstrip(".")

        try:
            with smtplib.SMTP(server, 25, timeout=3) as smtp:
                smtp.ehlo()

                # Use an empty reverse-path; send no message.
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
                        "The mail server accepted the recipient "
                        "check, but delivery is not guaranteed."
                    )

                if code == 550 and (
                    "5.1.1" in message
                    or "user unknown" in message
                    or "mailbox unavailable" in message
                ):
                    return (
                        "Likely to bounce", "bad",
                        "The server reported that the mailbox "
                        "may not exist."
                    )

        except (smtplib.SMTPException, OSError, TimeoutError):
            continue

    return (
        "Unknown", "unknown",
        "The mail server did not provide a conclusive result "
        "or the connection was unavailable."
    )


@app.route("/", methods=["GET", "POST"])
def home():
    input_text = ""
    results = []
    notice = ""

    if request.method == "POST":
        input_text = request.form.get("emails", "")

        emails = list(dict.fromkeys(
            line.strip()
            for line in input_text.splitlines()
            if line.strip()
        ))

        if len(emails) > 20:
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


if __name__ == "__main__":
    app.run(debug=False)