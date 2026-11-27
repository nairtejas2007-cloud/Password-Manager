import pytest

from app.config import _validate_production_environment


def _production_environment(ca_path):
    return {
        "APP_ENV": "production",
        "DB_HOST": "db.example.net",
        "DB_USER": "password_manager_app",
        "DB_PASSWORD": "test-db-password",
        "DB_NAME": "password_manager",
        "EMAIL_FROM": "mailer@example.net",
        "SMTP_USERNAME": "mailer@example.net",
        "SMTP_APP_PASSWORD": "test-smtp-password",
        "OTP_PEPPER": "a" * 64,
        "ALLOWED_HOSTS": "vault.example.net",
        "DB_SSL_CA": str(ca_path),
        "SESSION_COOKIE_SECURE": "true",
        "CORS_ORIGINS": "",
    }


def test_production_configuration_accepts_secure_database_and_host_settings(tmp_path):
    ca_path = tmp_path / "database-ca.pem"
    ca_path.write_text("test certificate", encoding="ascii")

    _validate_production_environment(_production_environment(ca_path))


def test_production_configuration_accepts_brevo_without_smtp_credentials(tmp_path):
    ca_path = tmp_path / "database-ca.pem"
    ca_path.write_text("test certificate", encoding="ascii")
    environment = _production_environment(ca_path)
    environment.pop("SMTP_USERNAME")
    environment.pop("SMTP_APP_PASSWORD")
    environment["BREVO_API_KEY"] = "test-brevo-api-key"

    _validate_production_environment(environment)


def test_production_configuration_requires_smtp_when_brevo_is_not_configured(tmp_path):
    ca_path = tmp_path / "database-ca.pem"
    ca_path.write_text("test certificate", encoding="ascii")
    environment = _production_environment(ca_path)
    environment.pop("SMTP_USERNAME")
    environment.pop("SMTP_APP_PASSWORD")

    with pytest.raises(RuntimeError, match="SMTP_USERNAME, SMTP_APP_PASSWORD"):
        _validate_production_environment(environment)


def test_production_configuration_requires_sender_address_for_brevo(tmp_path):
    ca_path = tmp_path / "database-ca.pem"
    ca_path.write_text("test certificate", encoding="ascii")
    environment = _production_environment(ca_path)
    environment.pop("EMAIL_FROM")
    environment.pop("SMTP_USERNAME")
    environment["BREVO_API_KEY"] = "test-brevo-api-key"

    with pytest.raises(RuntimeError, match="EMAIL_FROM"):
        _validate_production_environment(environment)


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        ("SESSION_COOKIE_SECURE", "false", "SESSION_COOKIE_SECURE"),
        ("ALLOWED_HOSTS", "*", "ALLOWED_HOSTS"),
        ("CORS_ORIGINS", "http://vault.example.net", "CORS_ORIGINS"),
        ("OTP_PEPPER", "not-a-hex-secret", "OTP_PEPPER"),
    ],
)
def test_production_configuration_rejects_insecure_values(
    tmp_path, setting, value, message
):
    ca_path = tmp_path / "database-ca.pem"
    ca_path.write_text("test certificate", encoding="ascii")
    environment = _production_environment(ca_path)
    environment[setting] = value

    with pytest.raises(RuntimeError, match=message):
        _validate_production_environment(environment)


def test_production_configuration_requires_database_ca_certificate(tmp_path):
    environment = _production_environment(tmp_path / "missing-ca.pem")

    with pytest.raises(RuntimeError, match="DB_SSL_CA"):
        _validate_production_environment(environment)
