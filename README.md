\# EmailCheck



EmailCheck is a lightweight web application that assesses multiple email addresses and classifies them as \*\*Likely delivered\*\*, \*\*Likely to bounce\*\*, or \*\*Unknown\*\*.



\## Features



\- Checks multiple email addresses in one submission.

\- Validates basic email-address syntax.

\- Checks DNS records for email routing.

\- Attempts a limited SMTP recipient check without sending an email message.

\- Displays a result, explanation, and summary counts for each assessment.

\- Uses \*\*Unknown\*\* when the available evidence is inconclusive.



\## Technologies Used



\- Python

\- Flask

\- dnspython

\- HTML and CSS



\## Requirements



\- Python 3.12 or a compatible Python 3 version

\- Internet access for DNS and SMTP checks



\## Run Locally



1\. Clone or download this repository.

2\. Open a terminal in the project directory.

3\. Create a virtual environment:



&#x20;  `python -m venv .venv`



4\. Install dependencies:



&#x20;  `python -m pip install -r requirements.txt`



5\. Start the application:



&#x20;  `python app.py`



6\. Open `http://127.0.0.1:5000` in your browser.



\## How It Works



EmailCheck first checks the address format, then looks for DNS mail-routing information. Where possible, it attempts a limited SMTP recipient check. It uses the server's response to provide an estimate, not a guarantee.



\## Limitations



\- A valid address format does not prove that a mailbox exists.

\- Some mail servers block SMTP recipient checks or intentionally conceal mailbox information.

\- Some servers accept recipient checks even when eventual delivery is not possible.

\- Hosting providers may block outbound SMTP connections, causing results to remain Unknown.

\- A successful SMTP response does not guarantee inbox delivery.

\- The application does not send email messages.



\## Privacy and Responsible Use



Only assess email addresses you are authorized to check. Do not use this tool to send messages to addresses you do not own.



\## Project Status



Developed as a software development internship task.



