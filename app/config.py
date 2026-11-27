import os
import re
import secrets
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "pm_user"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "password_manager"),
    "connection_timeout": int(os.getenv("DB_CONNECTION_TIMEOUT", "10")),
}
DB_SSL_CA = os.getenv("DB_SSL_CA", "").strip()
if DB_SSL_CA:
    DB_CONFIG.update(
        ssl_ca=DB_SSL_CA,
        ssl_verify_cert=True,
        ssl_verify_identity=True,
    )

SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "15"))
MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_ATTEMPTS", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "5"))
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))
OTP_MAX_SENDS_PER_15_MINUTES = 5 if IS_PRODUCTION else None
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_APP_PASSWORD = os.getenv("SMTP_APP_PASSWORD", "")
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", SMTP_USERNAME).strip()
SESSION_COOKIE_SECURE = os.getenv(
    "SESSION_COOKIE_SECURE", "true" if IS_PRODUCTION else "false"
).strip().lower() == "true"
OTP_PEPPER = os.getenv("OTP_PEPPER", "").strip()
if not OTP_PEPPER and not IS_PRODUCTION:
    OTP_PEPPER = secrets.token_hex(32)
ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv(
        "ALLOWED_HOSTS", "localhost,127.0.0.1,testserver"
    ).split(",")
    if host.strip()
]
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "" if IS_PRODUCTION else "http://127.0.0.1:5000,http://localhost:5000",
    ).split(",")
    if origin.strip()
]
RUN_MIGRATIONS = os.getenv(
    "RUN_MIGRATIONS", "false" if IS_PRODUCTION else "true"
).strip().lower() == "true"


def _validate_production_environment(env):
    if env.get("APP_ENV", "development").strip().lower() != "production":
        return

    required = [
        "DB_HOST",
        "DB_USER",
        "DB_PASSWORD",
        "DB_NAME",
        "OTP_PEPPER",
        "ALLOWED_HOSTS",
        "DB_SSL_CA",
    ]
    missing = [name for name in required if not env.get(name, "").strip()]
    if env.get("BREVO_API_KEY", "").strip():
        if not env.get("EMAIL_FROM", env.get("SMTP_USERNAME", "")).strip():
            missing.append("EMAIL_FROM")
    else:
        missing.extend(
            name
            for name in ("SMTP_USERNAME", "SMTP_APP_PASSWORD")
            if not env.get(name, "").strip()
        )
    if missing:
        raise RuntimeError(
            "Production configuration is missing required settings: "
            + ", ".join(missing)
        )

    if env["DB_HOST"].strip().lower() in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError("Production DB_HOST must point to a remote database.")
    if env["DB_USER"].strip().lower() in {"root", "admin"}:
        raise RuntimeError("Production must use a dedicated database user.")
    try:
        with Path(env["DB_SSL_CA"]).open("rb") as ca_file:
            if not ca_file.read(1):
                raise RuntimeError(
                    "DB_SSL_CA must point to a readable CA certificate file."
                )
    except OSError as exc:
        raise RuntimeError(
            "DB_SSL_CA must point to a readable CA certificate file."
        ) from exc
    if not re.fullmatch(r"[0-9a-fA-F]{64}", env["OTP_PEPPER"].strip()):
        raise RuntimeError("Production OTP_PEPPER must be 64 hexadecimal characters.")
    if env.get("SESSION_COOKIE_SECURE", "true").strip().lower() != "true":
        raise RuntimeError("SESSION_COOKIE_SECURE must be true in production.")

    hosts = [host.strip() for host in env["ALLOWED_HOSTS"].split(",")]
    if not hosts or any(not host or "*" in host for host in hosts):
        raise RuntimeError("Production ALLOWED_HOSTS must contain explicit hostnames.")
    origins = [
        origin.strip()
        for origin in env.get("CORS_ORIGINS", "").split(",")
        if origin.strip()
    ]
    if any(not origin.startswith("https://") for origin in origins):
        raise RuntimeError("Production CORS_ORIGINS must use HTTPS.")


if APP_ENV not in {"development", "production"}:
    raise RuntimeError("APP_ENV must be either 'development' or 'production'.")

_validate_production_environment(os.environ)
