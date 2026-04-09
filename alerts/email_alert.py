import smtplib
from email.mime.text import MIMEText
from typing import List, Dict


def get_high_critical_findings(findings: List[Dict]) -> List[Dict]:
    return [
        f for f in findings
        if f.get("severity", "").upper() in {"HIGH", "CRITICAL"}
    ]


def build_email_body(findings: List[Dict]) -> str:
    lines = []
    lines.append("Security Alert: High/Critical Findings Detected\n")
    lines.append(f"Total High/Critical Findings: {len(findings)}\n")

    for finding in findings:
        lines.append(
            f"[{finding.get('severity', 'UNKNOWN')}] "
            f"{finding.get('service', 'Unknown')} | "
            f"{finding.get('resource', 'Unknown')} | "
            f"{finding.get('issue', 'No issue provided')}"
        )

    return "\n".join(lines)


def send_email_alert(
    findings: List[Dict],
    smtp_server: str,
    smtp_port: int,
    sender_email: str,
    sender_password: str,
    recipient_email: str
) -> None:
    risky_findings = get_high_critical_findings(findings)

    if not risky_findings:
        print("No HIGH or CRITICAL findings. Email not sent.")
        return

    subject = f"Security Alert: {len(risky_findings)} High/Critical Findings"
    body = build_email_body(risky_findings)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())

        print(f"Alert email sent to {recipient_email}")

    except Exception as e:
        print(f"Failed to send email alert: {e}")