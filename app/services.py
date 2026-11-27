import hashlib

import pyotp
import requests

HIBP_URL = "https://api.pwnedpasswords.com/range/"


# ---------- TOTP (2FA) ----------

def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str, issuer: str = "SecurePasswordManager") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# ---------- breach checker (Have I Been Pwned, k-anonymity) ----------

def pwned_count(password: str) -> int:
    """Number of times the password appears in known breaches.
    Only the first 5 chars of the SHA-1 hash are sent to the API."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(
        HIBP_URL + prefix, headers={"Add-Padding": "true"}, timeout=10
    )
    resp.raise_for_status()
    for line in resp.text.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            return int(count)
    return 0
