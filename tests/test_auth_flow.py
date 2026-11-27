from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from pydantic import ValidationError
from starlette.requests import Request

from app import main, sessions
from app.schemas import LoginIn, LoginResendIn, LoginVerifyIn, RegisterIn


class FakeRequest:
    client = SimpleNamespace(host="testclient")


def test_registration_model_rejects_blank_name_and_invalid_email():
    base = {
        "full_name": "Test User",
        "email": "test@example.com",
        "master_password": "StrongPassword123",
        "confirm_password": "StrongPassword123",
    }

    for changes in ({"full_name": "   "}, {"email": "not-an-email"}):
        with pytest.raises(ValidationError):
            RegisterIn(**{**base, **changes})


def test_registration_rejects_mismatched_and_weak_passwords_before_database_access():
    with pytest.raises(HTTPException) as mismatch:
        main.register(
            RegisterIn(
                full_name="Test User",
                email="test@example.com",
                master_password="StrongPassword123",
                confirm_password="OtherPassword123",
            ),
            FakeRequest(),
        )
    assert mismatch.value.status_code == 422
    assert mismatch.value.detail == "Passwords do not match"

    with pytest.raises(HTTPException) as weak:
        main.register(
            RegisterIn(
                full_name="Test User",
                email="test@example.com",
                master_password="weakpassword",
                confirm_password="weakpassword",
            ),
            FakeRequest(),
        )
    assert weak.value.status_code == 422
    assert "12 characters" in weak.value.detail


def test_otp_challenge_uses_inserted_verification_record_id(monkeypatch):
    executed = []

    def fake_execute(sql, params=()):
        executed.append((sql, params))
        return (39, 1) if "INSERT INTO email_verifications" in sql else (0, 1)

    monkeypatch.setattr(main, "query_one", lambda *args: None)
    monkeypatch.setattr(main, "execute", fake_execute)
    monkeypatch.setattr(main, "send_otp_email", lambda *args: None)
    monkeypatch.setattr(main, "is_email_configured", lambda: True)

    otp_id = main.issue_otp(7, "test@example.com", "Test User", "login")
    assert otp_id == 39
    assert any("INSERT INTO email_verifications" in sql for sql, _ in executed)


def test_otp_can_be_resent_without_consuming_the_previous_code(monkeypatch):
    executed = []
    monkeypatch.setattr(main, "execute", lambda sql, params=(): executed.append((sql, params)) or (39, 1))
    monkeypatch.setattr(main, "send_otp_email", lambda *args: None)
    monkeypatch.setattr(main, "is_email_configured", lambda: True)

    main.issue_otp(
        7,
        "test@example.com",
        "Test User",
        "login",
        invalidate_previous=False,
    )

    assert not any("UPDATE email_verifications" in sql for sql, _ in executed)
    assert any("INSERT INTO email_verifications" in sql for sql, _ in executed)


def test_production_otp_send_limit_stops_before_creating_another_code(monkeypatch):
    executed = []
    monkeypatch.setattr(main, "OTP_MAX_SENDS_PER_15_MINUTES", 5)
    monkeypatch.setattr(main, "query_one", lambda *args: {"send_count": 5})
    monkeypatch.setattr(main, "execute", lambda *args: executed.append(args))
    monkeypatch.setattr(main, "send_otp_email", lambda *args: pytest.fail("Must not send"))
    monkeypatch.setattr(main, "is_email_configured", lambda: True)

    with pytest.raises(HTTPException) as limited:
        main.issue_otp(7, "test@example.com", "Test User", "login")

    assert limited.value.status_code == 429
    assert not executed


def test_registration_saves_account_without_sending_otp_and_returns_login_message(monkeypatch):
    transactions = []
    monkeypatch.setattr(main, "is_email_configured", lambda: False)
    monkeypatch.setattr(
        main,
        "execute_transaction",
        lambda statements: (transactions.append(statements) or [(41, 1), (None, 1)]),
    )
    monkeypatch.setattr(main, "issue_otp", lambda *args, **kwargs: pytest.fail("OTP must wait until login"))

    result = main.register(
        RegisterIn(
            full_name="Test User",
            email="test@example.com",
            master_password="StrongPassword123",
            confirm_password="StrongPassword123",
        ),
        FakeRequest(),
    )

    assert result["email"] == "test@example.com"
    assert "Log in" in result["message"]
    assert len(transactions) == 1
    assert len(transactions[0]) == 2
    assert "INSERT INTO users" in transactions[0][0][0]
    assert "INSERT INTO activity_log" in transactions[0][1][0]


def test_registration_reports_existing_account_as_login_path(monkeypatch):
    def raise_duplicate(_statements):
        raise main.IntegrityError("duplicate email")

    monkeypatch.setattr(main, "execute_transaction", raise_duplicate)

    with pytest.raises(HTTPException) as duplicate:
        main.register(
            RegisterIn(
                full_name="Test User",
                email="test@example.com",
                master_password="StrongPassword123",
                confirm_password="StrongPassword123",
            ),
            FakeRequest(),
        )

    assert duplicate.value.status_code == 409
    assert duplicate.value.detail["code"] == "account_exists"


def _request_with_cookies(method, cookies, csrf=""):
    headers = [(b"cookie", cookies.encode("ascii"))]
    if csrf:
        headers.append((b"x-csrf-token", csrf.encode("ascii")))
    return Request({"type": "http", "method": method, "headers": headers})


def test_login_is_two_stage_and_cookie_session_requires_csrf(monkeypatch):
    password = "StrongMasterPassword123"
    user = {
        "id": 7,
        "full_name": "Test User",
        "email": "test@example.com",
        "password_hash": main.security.hash_master_password(password),
        "kdf_salt": b"0123456789abcdef",
        "email_verified": 1,
        "locked_until": None,
        "failed_attempts": 0,
        "auto_lock_minutes": 15,
    }
    otp_record = {
        "id": 51,
        "user_id": 7,
        "purpose": "login",
        "otp_hash": main.otp_hash("123456"),
        "expires_at": datetime.utcnow() + timedelta(minutes=5),
        "attempts": 0,
        "consumed_at": None,
    }
    resent_otp_record = {
        **otp_record,
        "id": 52,
        "otp_hash": main.otp_hash("654321"),
    }

    def fake_query_one(sql, params=()):
        if "SELECT * FROM users" in sql:
            return user
        if "SELECT id, full_name FROM users" in sql:
            return user
        if "SELECT auto_lock_minutes" in sql:
            return {"auto_lock_minutes": 15}
        raise AssertionError(f"Unexpected query: {sql}")

    def fake_query_all(sql, params=()):
        if "FROM email_verifications" in sql:
            return [resent_otp_record, otp_record]
        raise AssertionError(f"Unexpected query: {sql}")

    issued_ids = iter([otp_record["id"], resent_otp_record["id"]])
    monkeypatch.setattr(main, "query_one", fake_query_one)
    monkeypatch.setattr(main, "query_all", fake_query_all)
    monkeypatch.setattr(main, "issue_otp", lambda *args, **kwargs: next(issued_ids))
    monkeypatch.setattr(main, "execute", lambda *args: (None, 1))
    monkeypatch.setattr(main, "log", lambda *args, **kwargs: None)
    monkeypatch.setattr(main, "client_ip", lambda request: "testclient")
    sessions._sessions.clear()

    stage_one = main.login(
        LoginIn(email="test@example.com", master_password=password), FakeRequest()
    )
    challenge_id = stage_one["challenge_id"]
    assert stage_one["masked_email"] == "t***@example.com"
    assert "token" not in stage_one
    assert not sessions._sessions

    resend = main.resend_login_otp(
        LoginResendIn(challenge_id=challenge_id), FakeRequest()
    )
    assert "new verification code" in resend["message"]

    with pytest.raises(HTTPException) as incorrect:
        main.verify_login(
            LoginVerifyIn(challenge_id=challenge_id, code="000000"),
            FakeRequest(),
            Response(),
        )
    assert incorrect.value.status_code == 400
    assert not sessions._sessions

    response = Response()
    verified = main.verify_login(
        LoginVerifyIn(challenge_id=challenge_id, code="123456"),
        FakeRequest(),
        response,
    )
    assert verified["message"] == "Vault unlocked."
    assert sessions._sessions

    cookie_jar = SimpleCookie()
    for name, value in response.raw_headers:
        if name.lower() == b"set-cookie":
            cookie_jar.load(value.decode("latin-1"))
    session_cookie = cookie_jar["pm_session"].value
    csrf_cookie = cookie_jar["pm_csrf"].value
    assert cookie_jar["pm_session"]["httponly"]

    unsafe_request = _request_with_cookies(
        "POST", f"pm_session={session_cookie}; pm_csrf={csrf_cookie}"
    )
    with pytest.raises(HTTPException) as csrf_failure:
        sessions.current_session(unsafe_request, authorization="")
    assert csrf_failure.value.status_code == 403

    protected_session = sessions.current_session(
        _request_with_cookies(
            "GET", f"pm_session={session_cookie}; pm_csrf={csrf_cookie}"
        ),
        authorization="",
    )
    logout_response = Response()
    main.logout(FakeRequest(), logout_response, protected_session)
    with pytest.raises(HTTPException) as logged_out:
        sessions.current_session(
            _request_with_cookies(
                "GET", f"pm_session={session_cookie}; pm_csrf={csrf_cookie}"
            ),
            authorization="",
        )
    assert logged_out.value.status_code == 401
