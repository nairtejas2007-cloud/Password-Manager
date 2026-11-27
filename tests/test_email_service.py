import io
import json

from app import email_service


def test_brevo_api_sends_otp_email_over_https(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return io.BytesIO(b"{}")

    monkeypatch.setattr(email_service, "BREVO_API_KEY", "test-brevo-key")
    monkeypatch.setattr(email_service, "EMAIL_FROM", "sender@example.net")
    monkeypatch.setattr(email_service, "urlopen", fake_urlopen)

    email_service.send_otp_email(
        "recipient@example.net", "Ada <Admin>", "123456", "verify"
    )

    request = captured["request"]
    headers = {key.lower(): value for key, value in request.header_items()}
    payload = json.loads(request.data)
    assert request.full_url == "https://api.brevo.com/v3/smtp/email"
    assert request.get_method() == "POST"
    assert headers["api-key"] == "test-brevo-key"
    assert headers["content-type"] == "application/json"
    assert captured["timeout"] == 15
    assert payload["sender"]["email"] == "sender@example.net"
    assert payload["to"] == [{"email": "recipient@example.net", "name": "Ada <Admin>"}]
    assert payload["subject"] == "Verify your email - Secure Password Manager"
    assert "123456" in payload["textContent"]
    assert "Ada &lt;Admin&gt;" in payload["htmlContent"]


def test_gmail_smtp_is_used_when_brevo_key_is_empty(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def starttls(self):
            sent["starttls"] = True

        def login(self, username, password):
            sent["login"] = (username, password)

        def send_message(self, message):
            sent["message"] = message

    monkeypatch.setattr(email_service, "BREVO_API_KEY", "")
    monkeypatch.setattr(email_service, "EMAIL_FROM", "sender@example.net")
    monkeypatch.setattr(email_service, "SMTP_USERNAME", "smtp-user")
    monkeypatch.setattr(email_service, "SMTP_APP_PASSWORD", "smtp-password")
    monkeypatch.setattr(email_service.smtplib, "SMTP", lambda *args, **kwargs: FakeSMTP())

    def fail_urlopen(*args, **kwargs):
        raise AssertionError("Brevo must not be used")

    monkeypatch.setattr(email_service, "urlopen", fail_urlopen)

    email_service.send_otp_email("recipient@example.net", "Test User", "654321", "login")

    assert sent["starttls"]
    assert sent["login"] == ("smtp-user", "smtp-password")
    assert sent["message"]["To"] == "recipient@example.net"
    assert "654321" in sent["message"].get_body(preferencelist=("plain",)).get_content()
