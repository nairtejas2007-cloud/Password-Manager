import smtplib
from html import escape
from email.message import EmailMessage

from app.config import EMAIL_FROM, SMTP_APP_PASSWORD, SMTP_HOST, SMTP_PORT, SMTP_USERNAME


def is_smtp_configured() -> bool:
    return bool(SMTP_USERNAME and SMTP_APP_PASSWORD)


def send_otp_email(to_email: str, full_name: str, otp: str, purpose: str) -> None:
    if not is_smtp_configured():
        raise RuntimeError(
            "Gmail SMTP is not configured. Set SMTP_USERNAME and SMTP_APP_PASSWORD."
        )

    title = "Verify your email" if purpose == "verify" else "Password vault verification"
    message = EmailMessage()
    message["Subject"] = f"{title} - Secure Password Manager"
    message["From"] = EMAIL_FROM or SMTP_USERNAME
    message["To"] = to_email
    message.set_content(
        f"Hello {full_name},\n\nYour verification code is: {otp}\n"
        f"This code expires in 5 minutes.\n\nIf you did not request this, ignore this email."
    )
    message.add_alternative(
        f"""<!doctype html><html><body style="margin:0;background:#ffffff;font-family:Arial,sans-serif;color:#171717">
        <div style="max-width:520px;margin:40px auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;padding:32px">
          <h1 style="color:#4d7c0f;margin-top:0">Secure Password Manager</h1>
          <p>Hello {escape(full_name)},</p>
          <p>Use this verification code:</p>
          <div style="font-size:32px;letter-spacing:8px;text-align:center;background:#f7f9f7;border-radius:12px;padding:18px;color:#365314;font-weight:bold">{otp}</div>
          <p style="color:#737373;font-size:13px">This code expires in 5 minutes. Never share it with anyone.</p>
        </div></body></html>""",
        subtype="html",
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USERNAME, SMTP_APP_PASSWORD)
        smtp.send_message(message)
