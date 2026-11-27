import hashlib

import pyotp

from app import services


def test_totp_roundtrip():
    secret = services.new_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert services.verify_totp(secret, code)
    assert not services.verify_totp(secret, "000000" if code != "000000" else "111111")


def test_totp_uri_contains_user():
    uri = services.totp_uri(services.new_totp_secret(), "tejas")
    assert uri.startswith("otpauth://totp/")
    assert "tejas" in uri


class _FakeResp:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_pwned_count_found(monkeypatch):
    sha1 = hashlib.sha1(b"password").hexdigest().upper()
    body = f"0000000000000000000000000000000000A:3\r\n{sha1[5:]}:9999\r\n"
    monkeypatch.setattr(
        services.requests, "get", lambda *a, **k: _FakeResp(body)
    )
    assert services.pwned_count("password") == 9999


def test_pwned_count_not_found(monkeypatch):
    monkeypatch.setattr(
        services.requests,
        "get",
        lambda *a, **k: _FakeResp("0000000000000000000000000000000000A:3\r\n"),
    )
    assert services.pwned_count("a-very-unique-password-xyz") == 0


def test_only_hash_prefix_is_sent(monkeypatch):
    seen = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        return _FakeResp("")

    monkeypatch.setattr(services.requests, "get", fake_get)
    services.pwned_count("password")
    prefix = hashlib.sha1(b"password").hexdigest().upper()[:5]
    assert seen["url"].endswith("/range/" + prefix)
