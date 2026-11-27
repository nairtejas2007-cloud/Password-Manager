import json
import smtplib
from html import escape
from email.message import EmailMessage
from urllib.request import Request, urlopen

from app.config import (
    BREVO_API_KEY,
    EMAIL_FROM,
    SMTP_APP_PASSWORD,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
)


def is_email_configured() -> bool:
    return bool(BREVO_API_KEY or (SMTP_USERNAME and SMTP_APP_PASSWORD))


def send_otp_email(to_email: str, full_name: str, otp: str, purpose: str) -> None:
    if not is_email_configured():
        raise RuntimeError(
            "Email delivery is not configured. Set BREVO_API_KEY or configure "
            "SMTP_USERNAME and SMTP_APP_PASSWORD."
        )

    title = "Verify your email" if purpose == "verify" else "Password vault verification"
    subject = f"{title} - Secure Password Manager"
    text_content = (
        f"Hello {full_name},\n\nYour verification code is: {otp}\n"
        "This code expires in 5 minutes.\n\n"
        "If you did not request this, ignore this email."
    )
    html_content = f"""<!doctype html><html><body style="margin:0;background:#ffffff;font-family:Arial,sans-serif;color:#171717">
        <div style="max-width:520px;margin:40px auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;padding:32px">
          <h1 style="color:#4d7c0f;margin-top:0">Secure Password Manager</h1>
          <p>Hello {escape(full_name)},</p>
          <p>Use this verification code:</p>
          <div style="font-size:32px;letter-spacing:8px;text-align:center;background:#f7f9f7;border-radius:12px;padding:18px;color:#365314;font-weight:bold">{otp}</div>
          <p style="color:#737373;font-size:13px">This code expires in 5 minutes. Never share it with anyone.</p>
        </div></body></html>"""

    if BREVO_API_KEY:
        if not EMAIL_FROM:
            raise RuntimeError("EMAIL_FROM must be set when using the Brevo API.")
        payload = {
            "sender": {"email": EMAIL_FROM, "name": "Secure Password Manager"},
            "to": [{"email": to_email, "name": full_name}],
            "subject": subject,
            "textContent": text_content,
            "htmlContent": html_content,
        }
        request = Request(
            "https://api.brevo.com/v3/smtp/email",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "api-key": BREVO_API_KEY,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(request, timeout=15) as response:
            response.read()
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = EMAIL_FROM or SMTP_USERNAME
    message["To"] = to_email
    message.set_content(text_content)
    message.add_alternative(html_content, subtype="html")

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USERNAME, SMTP_APP_PASSWORD)
        smtp.send_message(message)
