import hashlib
import hmac
import secrets
import smtplib
import threading
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from mysql.connector.errors import IntegrityError

from app import security, services, sessions
from app.config import (
    LOCKOUT_MINUTES,
    MAX_FAILED_ATTEMPTS,
    OTP_EXPIRY_MINUTES,
    OTP_MAX_ATTEMPTS,
    OTP_PEPPER,
    SESSION_COOKIE_SECURE,
    SESSION_TTL_MINUTES,
)
from app.db import execute, execute_transaction, query_all, query_one
from app.email_service import is_smtp_configured, send_otp_email
from app.migrations import migrate_existing_schema
from app.schemas import (
    ChangePasswordIn,
    CodeIn,
    EntryEditAuthIn,
    EntryIn,
    LoginIn,
    LoginResendIn,
    LoginVerifyIn,
    PasswordIn,
    RegisterIn,
)
from app.sessions import create_session, current_session, delete_session

BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(application: FastAPI):
    migrate_existing_schema()
    yield


app = FastAPI(
    title="Secure Password Manager",
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5000", "http://localhost:5000"],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

if (BASE_DIR / "static").exists():
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

_DUMMY_HASH = security.hash_master_password("dummy-password-for-timing")
_login_challenges = {}
_challenge_lock = threading.Lock()
_login_attempts = defaultdict(deque)
_attempt_lock = threading.Lock()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def client_ip(request: Request):
    return request.client.host if request.client else None


def log(user_id, action, success=True, ip=None, detail=None):
    execute(
        "INSERT INTO activity_log (user_id, action, success, ip_address, detail) "
        "VALUES (%s, %s, %s, %s, %s)",
        (user_id, action, int(success), ip, detail),
    )


def otp_hash(code: str) -> str:
    return hmac.new(OTP_PEPPER.encode("utf-8"), code.encode("utf-8"), hashlib.sha256).hexdigest()


def enforce_login_rate_limit(ip: str | None):
    now = utcnow()
    key = ip or "unknown"
    with _attempt_lock:
        attempts = _login_attempts[key]
        while attempts and attempts[0] < now - timedelta(minutes=15):
            attempts.popleft()
        if len(attempts) >= 20:
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
        attempts.append(now)


def masked_email(email: str) -> str:
    local, domain = email.split("@", 1)
    visible = local[:1]
    return f"{visible}{'*' * max(2, len(local) - 1)}@{domain}"


def issue_otp(
    user_id: int,
    email: str,
    full_name: str,
    purpose: str,
    account_created: bool = False,
    invalidate_previous: bool = True,
):
    if not is_smtp_configured():
        raise HTTPException(
            status_code=503,
            detail={
                "code": "smtp_not_configured",
                "message": (
                    "Email OTP is not configured. Set SMTP_USERNAME and "
                    "SMTP_APP_PASSWORD in your local .env file, then try again."
                ),
                "account_created": account_created,
            },
        )

    code = f"{secrets.randbelow(1_000_000):06d}"
    if invalidate_previous:
        execute(
            "UPDATE email_verifications SET consumed_at = COALESCE(consumed_at, %s) "
            "WHERE user_id = %s AND purpose = %s AND consumed_at IS NULL",
            (utcnow(), user_id, purpose),
        )
    otp_id, _ = execute(
        "INSERT INTO email_verifications "
        "(user_id, otp_hash, purpose, expires_at) VALUES (%s, %s, %s, %s)",
        (user_id, otp_hash(code), purpose, utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)),
    )
    try:
        send_otp_email(email, full_name, code, purpose)
    except (OSError, RuntimeError, smtplib.SMTPException) as exc:
        execute(
            "UPDATE email_verifications SET consumed_at = %s WHERE id = %s",
            (utcnow(), otp_id),
        )
        raise HTTPException(
            status_code=503,
            detail={
                "code": "otp_delivery_failed",
                "message": (
                    "The verification email could not be sent. Check the Gmail "
                    "SMTP settings and try again."
                ),
                "account_created": account_created,
            },
        ) from exc
    return otp_id


@app.get("/", response_class=HTMLResponse)
def landing():
    index = BASE_DIR / "static" / "index.html"
    return index.read_text(encoding="utf-8") if index.exists() else "<h1>Secure Password Manager</h1>"


@app.post("/register", status_code=201)
def register(body: RegisterIn, request: Request):
    full_name = body.full_name.strip()
    if not full_name:
        raise HTTPException(status_code=422, detail="Full name cannot be blank")
    if body.master_password != body.confirm_password:
        raise HTTPException(status_code=422, detail="Passwords do not match")
    if (
        len(body.master_password) < 12
        or not any(char.isalpha() for char in body.master_password)
        or not any(char.isdigit() for char in body.master_password)
    ):
        raise HTTPException(
            status_code=422,
            detail="Use at least 12 characters with at least one letter and one number.",
        )
    email = body.email.strip().lower()
    pw_hash = security.hash_master_password(body.master_password)
    salt = security.new_kdf_salt()
    try:
        execute_transaction(
            [
                (
                    "INSERT INTO users (full_name, email, password_hash, kdf_salt) "
                    "VALUES (%s, %s, %s, %s)",
                    (full_name, email, pw_hash, salt),
                ),
                (
                    "INSERT INTO activity_log "
                    "(user_id, action, success, ip_address, detail) "
                    "SELECT id, %s, %s, %s, %s FROM users WHERE email = %s",
                    ("register", 1, client_ip(request), None, email),
                ),
            ]
        )
    except IntegrityError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "account_exists",
                "message": "An account with this email already exists. Log in instead.",
            },
        )
    return {
        "message": "Account created. Log in with your master password to receive an email verification code.",
        "email": email,
    }


@app.post("/register/resend")
def resend_registration_otp(body: dict, request: Request):
    email = str(body.get("email", "")).strip().lower()
    user = query_one(
        "SELECT id, full_name, email_verified FROM users WHERE email = %s", (email,)
    )
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    if user["email_verified"]:
        raise HTTPException(status_code=409, detail="Email already verified")
    issue_otp(
        user["id"], email, user["full_name"], "verify", account_created=True
    )
    log(user["id"], "otp_resend", True, client_ip(request), "verify")
    return {"message": "A new OTP has been sent.", "expires_in": OTP_EXPIRY_MINUTES * 60}


@app.post("/register/verify")
def verify_registration(body: CodeIn, request: Request, email: str):
    email = email.strip().lower()
    user = query_one("SELECT id, full_name, email_verified FROM users WHERE email = %s", (email,))
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    otp = query_one(
        "SELECT * FROM email_verifications WHERE user_id = %s AND purpose = 'verify' "
        "AND consumed_at IS NULL ORDER BY id DESC LIMIT 1",
        (user["id"],),
    )
    if not otp or otp["expires_at"] < utcnow():
        raise HTTPException(status_code=400, detail="OTP expired")
    if otp["attempts"] >= OTP_MAX_ATTEMPTS:
        raise HTTPException(status_code=423, detail="Too many OTP attempts")
    if not secrets.compare_digest(otp["otp_hash"], otp_hash(body.code)):
        execute("UPDATE email_verifications SET attempts = attempts + 1 WHERE id = %s", (otp["id"],))
        log(user["id"], "otp_verify", False, client_ip(request), "verify")
        raise HTTPException(status_code=400, detail="Invalid OTP")
    execute("UPDATE users SET email_verified = 1 WHERE id = %s", (user["id"],))
    execute("UPDATE email_verifications SET consumed_at = %s WHERE id = %s", (utcnow(), otp["id"]))
    log(user["id"], "otp_verify", True, client_ip(request), "verify")
    return {"message": "Email verified. You can now log in."}


@app.post("/login")
def login(body: LoginIn, request: Request):
    ip = client_ip(request)
    enforce_login_rate_limit(ip)
    email = body.email.strip().lower()
    user = query_one("SELECT * FROM users WHERE email = %s", (email,))
    if not user:
        security.verify_master_password(_DUMMY_HASH, body.master_password)
        log(None, "login", False, ip, "unknown user")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user["locked_until"] and user["locked_until"] > utcnow():
        raise HTTPException(status_code=423, detail="Account temporarily locked")
    if not security.verify_master_password(user["password_hash"], body.master_password):
        attempts = user["failed_attempts"] + 1
        if attempts >= MAX_FAILED_ATTEMPTS:
            execute(
                "UPDATE users SET failed_attempts = 0, locked_until = %s WHERE id = %s",
                (utcnow() + timedelta(minutes=LOCKOUT_MINUTES), user["id"]),
            )
        else:
            execute("UPDATE users SET failed_attempts = %s WHERE id = %s", (attempts, user["id"]))
        log(user["id"], "login", False, ip, "wrong password")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    key = security.derive_vault_key(body.master_password, bytes(user["kdf_salt"]))
    challenge_id = secrets.token_urlsafe(32)
    try:
        otp_id = issue_otp(user["id"], email, user["full_name"], "login")
    except HTTPException:
        raise
    with _challenge_lock:
        now = utcnow()
        for stale_id in [
            challenge for challenge, data in _login_challenges.items()
            if data["expires"] < now
        ]:
            _login_challenges.pop(stale_id, None)
        _login_challenges[challenge_id] = {
            "user_id": user["id"],
            "full_name": user["full_name"],
            "email": email,
            "key": key,
            "otp_id": otp_id,
            "otp_ids": [otp_id],
            "ip": ip,
            "expires": now + timedelta(minutes=OTP_EXPIRY_MINUTES),
        }
    return {
        "challenge_id": challenge_id,
        "masked_email": masked_email(email),
        "expires_in": OTP_EXPIRY_MINUTES * 60,
        "message": "Verification code sent to your registered email address.",
    }


@app.post("/login/resend")
def resend_login_otp(body: LoginResendIn, request: Request):
    with _challenge_lock:
        challenge = _login_challenges.get(body.challenge_id)
        if not challenge or challenge["expires"] < utcnow():
            _login_challenges.pop(body.challenge_id, None)
            raise HTTPException(status_code=400, detail="Login challenge expired. Start again.")
        if challenge["ip"] != client_ip(request):
            raise HTTPException(status_code=403, detail="Login challenge is not valid for this connection.")
    user = query_one(
        "SELECT id, full_name FROM users WHERE id = %s", (challenge["user_id"],)
    )
    otp_id = issue_otp(
        user["id"],
        challenge["email"],
        user["full_name"],
        "login",
        invalidate_previous=False,
    )
    with _challenge_lock:
        challenge["otp_id"] = otp_id
        challenge.setdefault("otp_ids", []).append(otp_id)
        challenge["expires"] = utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    return {"message": "A new verification code was sent.", "expires_in": OTP_EXPIRY_MINUTES * 60}


@app.post("/login/verify")
def verify_login(body: LoginVerifyIn, request: Request, response: Response):
    with _challenge_lock:
        challenge = _login_challenges.get(body.challenge_id)
        if not challenge or challenge["expires"] < utcnow():
            _login_challenges.pop(body.challenge_id, None)
            raise HTTPException(status_code=400, detail="Verification code expired. Start login again.")
        if challenge["ip"] != client_ip(request):
            raise HTTPException(status_code=403, detail="Login challenge is not valid for this connection.")
    otp_ids = challenge.get("otp_ids") or [challenge["otp_id"]]
    placeholders = ", ".join(["%s"] * len(otp_ids))
    records = query_all(
        "SELECT * FROM email_verifications "
        f"WHERE id IN ({placeholders}) AND user_id = %s "
        "AND purpose = 'login' AND consumed_at IS NULL ORDER BY id DESC",
        (*otp_ids, challenge["user_id"]),
    )
    active_records = [
        record for record in records if record["expires_at"] >= utcnow()
    ]
    if not active_records:
        raise HTTPException(status_code=400, detail="Verification code expired. Request a new one.")
    available_records = [
        record for record in active_records if record["attempts"] < OTP_MAX_ATTEMPTS
    ]
    if not available_records:
        raise HTTPException(status_code=423, detail="Too many code attempts. Start login again.")
    matching_record = next(
        (
            record
            for record in available_records
            if secrets.compare_digest(record["otp_hash"], otp_hash(body.code))
        ),
        None,
    )
    if not matching_record:
        active_ids = [record["id"] for record in available_records]
        active_placeholders = ", ".join(["%s"] * len(active_ids))
        execute(
            "UPDATE email_verifications SET attempts = attempts + 1 "
            f"WHERE id IN ({active_placeholders})",
            tuple(active_ids),
        )
        raise HTTPException(status_code=400, detail="Incorrect verification code.")
    execute(
        "UPDATE email_verifications SET consumed_at = %s "
        f"WHERE id IN ({placeholders}) AND user_id = %s AND consumed_at IS NULL",
        (utcnow(), *otp_ids, challenge["user_id"]),
    )
    execute(
        "UPDATE users SET email_verified = 1, failed_attempts = 0, locked_until = NULL WHERE id = %s",
        (challenge["user_id"],),
    )
    session = query_one(
        "SELECT auto_lock_minutes FROM users WHERE id = %s", (challenge["user_id"],)
    )
    token = create_session(
        challenge["user_id"],
        challenge["full_name"],
        challenge["key"],
        ttl_minutes=session["auto_lock_minutes"] or SESSION_TTL_MINUTES,
    )
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        "pm_session", token, httponly=True, secure=SESSION_COOKIE_SECURE,
        samesite="strict", path="/",
    )
    response.set_cookie(
        "pm_csrf", csrf_token, httponly=False, secure=SESSION_COOKIE_SECURE,
        samesite="strict", path="/",
    )
    log(challenge["user_id"], "login", True, client_ip(request))
    with _challenge_lock:
        _login_challenges.pop(body.challenge_id, None)
    return {"message": "Vault unlocked."}


@app.get("/auth/me")
def auth_me(sess: dict = Depends(current_session)):
    return {"full_name": sess["username"]}


@app.post("/logout")
def logout(request: Request, response: Response, sess: dict = Depends(current_session)):
    delete_session(sess["token"])
    log(sess["user_id"], "logout", True, client_ip(request))
    response.delete_cookie(
        "pm_session", path="/", httponly=True, secure=SESSION_COOKIE_SECURE, samesite="strict"
    )
    response.delete_cookie(
        "pm_csrf", path="/", secure=SESSION_COOKIE_SECURE, samesite="strict"
    )
    return {"message": "Logged out"}


@app.post("/account/change-password")
def change_password(
    body: ChangePasswordIn,
    request: Request,
    response: Response,
    sess: dict = Depends(current_session),
):
    if body.new_password != body.confirm_password:
        raise HTTPException(status_code=422, detail="Passwords do not match")
    user = query_one("SELECT * FROM users WHERE id = %s", (sess["user_id"],))
    if not security.verify_master_password(user["password_hash"], body.current_password):
        raise HTTPException(status_code=401, detail="Current master password is incorrect")

    old_key = sess["key"]
    new_salt = security.new_kdf_salt()
    new_key = security.derive_vault_key(body.new_password, new_salt)
    entries = query_all(
        "SELECT * FROM vault_entries WHERE user_id = %s", (sess["user_id"],)
    )
    fields = query_all(
        "SELECT vf.id, vf.value_enc FROM vault_fields vf "
        "JOIN vault_entries ve ON ve.id = vf.entry_id WHERE ve.user_id = %s",
        (sess["user_id"],),
    )
    statements = []
    for row in entries:
        username = security.decrypt(old_key, row["username_enc"])
        password = security.decrypt(old_key, row["password_enc"])
        notes = security.decrypt(old_key, row["notes_enc"]) if row["notes_enc"] else None
        statements.append(
            (
                "UPDATE vault_entries SET username_enc=%s, password_enc=%s, notes_enc=%s "
                "WHERE id=%s AND user_id=%s",
                (security.encrypt(new_key, username), security.encrypt(new_key, password),
                 security.encrypt(new_key, notes) if notes is not None else None,
                 row["id"], sess["user_id"]),
            )
        )
    for row in fields:
        value = security.decrypt(old_key, row["value_enc"])
        statements.append(
            (
                "UPDATE vault_fields SET value_enc=%s WHERE id=%s",
                (security.encrypt(new_key, value), row["id"]),
            )
        )
    statements.append(
        (
            "UPDATE users SET password_hash=%s, kdf_salt=%s WHERE id=%s",
            (security.hash_master_password(body.new_password), new_salt, sess["user_id"]),
        )
    )
    execute_transaction(statements)
    delete_session(sess["token"])
    response.delete_cookie(
        "pm_session", path="/", httponly=True, secure=SESSION_COOKIE_SECURE, samesite="strict"
    )
    response.delete_cookie(
        "pm_csrf", path="/", secure=SESSION_COOKIE_SECURE, samesite="strict"
    )
    log(sess["user_id"], "password_change", True, client_ip(request))
    return {"message": "Master password changed. Log in again to unlock the vault."}


def _entry_out(row, key, include_password=False, include_username=True):
    out = {
        "id": row["id"], "title": row["site_name"], "site_name": row["site_name"],
        "site_url": row["site_url"],
        "username": security.decrypt(key, row["username_enc"]) if include_username else "",
        "category": row["category"], "favourite": bool(row["favourite"]),
        "created_at": row["created_at"], "updated_at": row["updated_at"],
    }
    if include_password:
        out["password"] = security.decrypt(key, row["password_enc"])
        out["notes"] = security.decrypt(key, row["notes_enc"]) if row["notes_enc"] else None
        stored_fields = query_all(
            "SELECT id, field_label, field_type, is_sensitive, field_order, value_enc "
            "FROM vault_fields WHERE entry_id = %s ORDER BY field_order, id",
            (row["id"],),
        )
        if stored_fields:
            out["fields"] = [
                {
                    "id": field["id"],
                    "label": field["field_label"],
                    "type": field["field_type"],
                    "sensitive": bool(
                        field["is_sensitive"] or field["field_type"] == "password"
                    ),
                    "position": field["field_order"],
                    "value": security.decrypt(key, field["value_enc"]),
                }
                for field in stored_fields
            ]
        else:
            legacy_fields = [
                ("Username or email", "text", False, out["username"]),
                ("Password", "password", True, out["password"]),
            ]
            if out["notes"]:
                legacy_fields.append(("Notes", "multiline", False, out["notes"]))
            out["fields"] = [
                {
                    "id": None,
                    "label": label,
                    "type": field_type,
                    "sensitive": sensitive,
                    "position": position,
                    "value": value,
                }
                for position, (label, field_type, sensitive, value) in enumerate(legacy_fields)
            ]
    return out


def _get_entry(entry_id, user_id):
    row = query_one("SELECT * FROM vault_entries WHERE id = %s AND user_id = %s", (entry_id, user_id))
    if not row:
        raise HTTPException(status_code=404, detail="Entry not found")
    return row


def _require_entry_edit_authorization(entry_id, sess):
    if not sessions.consume_entry_edit_authorization(sess["token"], entry_id):
        raise HTTPException(
            status_code=403,
            detail="Enter your master password before changing this saved entry.",
        )


@app.post("/vault", status_code=201)
def add_entry(body: EntryIn, request: Request, sess: dict = Depends(current_session)):
    fields = _prepare_entry_fields(body.fields or [])
    username, password, notes = _legacy_entry_values(body, fields)
    statements = [
        (
            "INSERT INTO vault_entries "
            "(user_id, site_name, site_url, username_enc, password_enc, category, notes_enc, favourite) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (sess["user_id"], body.title, body.site_url,
             _legacy_ciphertext(sess["key"], username, 1024),
             _legacy_ciphertext(sess["key"], password, 2048),
             body.category, _legacy_ciphertext(sess["key"], notes if notes else None, 4096),
             int(body.favourite)),
        )
    ]
    statements.extend(
        lambda results, field=field: _field_insert_statement(
            results[0][0], field, sess["key"]
        )
        for field in fields
    )
    results = execute_transaction(statements)
    entry_id = results[0][0]
    log(sess["user_id"], "vault_add", True, client_ip(request), f"entry {entry_id}")
    return {"id": entry_id}


def _prepare_entry_fields(fields):
    return [
        {
            "label": field.label.strip(),
            "value": field.value,
            "type": field.type,
            "sensitive": bool(field.sensitive or field.type == "password"),
            "position": position,
        }
        for position, field in enumerate(fields)
    ]


def _legacy_entry_values(body, fields):
    username = body.username or next(
        (
            field["value"]
            for field in fields
            if field["label"].casefold() in _USERNAME_FIELD_LABELS
        ),
        "",
    )
    password = body.password or next(
        (
            field["value"]
            for field in fields
            if field["type"] == "password" or "password" in field["label"].casefold()
        ),
        "",
    )
    notes = body.notes or next(
        (field["value"] for field in fields if field["label"].casefold() == "notes"),
        None,
    )
    return username, password, notes


_USERNAME_FIELD_LABELS = {
    "username",
    "username or email",
    "email",
    "email address",
    "user id",
}


def _field_insert_statement(entry_id, field, key):
    return (
        "INSERT INTO vault_fields "
        "(entry_id, field_label, field_type, is_sensitive, field_order, value_enc) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (
            entry_id,
            field["label"],
            field["type"],
            int(field["sensitive"]),
            field["position"],
            security.encrypt(key, field["value"]),
        ),
    )


def _legacy_ciphertext(key, value, column_capacity):
    if value is None:
        return None
    encrypted = security.encrypt(key, value)
    if len(encrypted) > column_capacity:
        return security.encrypt(key, "")
    return encrypted


@app.get("/vault")
def list_entries(search: str = "", category: str = "", favourite: bool = False,
                 sess: dict = Depends(current_session)):
    sql = "SELECT * FROM vault_entries WHERE user_id = %s"
    params = [sess["user_id"]]
    if category:
        sql += " AND category = %s"; params.append(category)
    if favourite:
        sql += " AND favourite = 1"
    sql += " ORDER BY updated_at DESC"
    rows = query_all(sql, tuple(params))
    sensitive_usernames = set()
    if rows:
        placeholders = ", ".join(["%s"] * len(rows))
        field_metadata = query_all(
            "SELECT entry_id, field_label, field_type, is_sensitive FROM vault_fields "
            f"WHERE entry_id IN ({placeholders})",
            tuple(row["id"] for row in rows),
        )
        sensitive_usernames = {
            field["entry_id"]
            for field in field_metadata
            if (field["is_sensitive"] or field["field_type"] == "password")
            and field["field_label"].casefold() in _USERNAME_FIELD_LABELS
        }
    output = [
        _entry_out(
            row,
            sess["key"],
            include_username=row["id"] not in sensitive_usernames,
        )
        for row in rows
    ]
    if search:
        needle = search.lower()
        output = [row for row in output if needle in row["title"].lower()
                  or needle in row["username"].lower()]
    return output


@app.post("/vault/{entry_id}/edit-authorize")
def authorize_entry_edit(
    entry_id: int,
    body: EntryEditAuthIn,
    request: Request,
    sess: dict = Depends(current_session),
):
    _get_entry(entry_id, sess["user_id"])
    user = query_one(
        "SELECT password_hash FROM users WHERE id = %s", (sess["user_id"],)
    )
    if not user or not security.verify_master_password(
        user["password_hash"], body.master_password
    ):
        raise HTTPException(status_code=401, detail="Master password is incorrect.")
    sessions.authorize_entry_edit(sess["token"], entry_id)
    log(sess["user_id"], "vault_edit_authorize", True, client_ip(request), f"entry {entry_id}")
    return {"message": "Master password verified."}


@app.get("/vault/{entry_id}")
def get_entry(entry_id: int, request: Request, sess: dict = Depends(current_session)):
    row = _get_entry(entry_id, sess["user_id"])
    log(sess["user_id"], "vault_view", True, client_ip(request), f"entry {entry_id}")
    return _entry_out(row, sess["key"], include_password=True)


@app.put("/vault/{entry_id}")
def update_entry(entry_id: int, body: EntryIn, request: Request, sess: dict = Depends(current_session)):
    current_entry = _get_entry(entry_id, sess["user_id"])
    _require_entry_edit_authorization(entry_id, sess)
    fields = _prepare_entry_fields(body.fields or [])
    username, password, notes = _legacy_entry_values(body, fields)
    if body.fields is None:
        if "username" not in body.model_fields_set:
            username = security.decrypt(sess["key"], current_entry["username_enc"])
        if "password" not in body.model_fields_set:
            password = security.decrypt(sess["key"], current_entry["password_enc"])
        if "notes" not in body.model_fields_set:
            notes = (
                security.decrypt(sess["key"], current_entry["notes_enc"])
                if current_entry["notes_enc"]
                else None
            )
    statements = [
        (
            "UPDATE vault_entries SET site_name=%s, site_url=%s, username_enc=%s, password_enc=%s, "
            "category=%s, notes_enc=%s, favourite=%s WHERE id=%s AND user_id=%s",
            (body.title, body.site_url, _legacy_ciphertext(sess["key"], username, 1024),
             _legacy_ciphertext(sess["key"], password, 2048), body.category,
             _legacy_ciphertext(sess["key"], notes if notes else None, 4096), int(body.favourite),
             entry_id, sess["user_id"]),
        )
    ]
    if body.fields is not None:
        statements.append(("DELETE FROM vault_fields WHERE entry_id=%s", (entry_id,)))
        statements.extend(
            _field_insert_statement(entry_id, field, sess["key"])
            for field in fields
        )
    execute_transaction(statements)
    log(sess["user_id"], "vault_update", True, client_ip(request), f"entry {entry_id}")
    return {"message": "Updated"}


@app.patch("/vault/{entry_id}/favourite")
def toggle_favourite(entry_id: int, favourite: bool = True, sess: dict = Depends(current_session)):
    _get_entry(entry_id, sess["user_id"])
    _require_entry_edit_authorization(entry_id, sess)
    execute("UPDATE vault_entries SET favourite=%s WHERE id=%s AND user_id=%s",
            (int(favourite), entry_id, sess["user_id"]))
    return {"message": "Favourite updated"}


@app.delete("/vault/{entry_id}")
def delete_entry(entry_id: int, request: Request, sess: dict = Depends(current_session)):
    _get_entry(entry_id, sess["user_id"])
    _require_entry_edit_authorization(entry_id, sess)
    execute("DELETE FROM vault_entries WHERE id=%s AND user_id=%s", (entry_id, sess["user_id"]))
    log(sess["user_id"], "vault_delete", True, client_ip(request), f"entry {entry_id}")
    return {"message": "Deleted"}


@app.get("/categories")
def categories(sess: dict = Depends(current_session)):
    return query_all(
        "SELECT name FROM categories WHERE user_id IS NULL OR user_id=%s "
        "ORDER BY is_builtin DESC, name",
        (sess["user_id"],),
    )


@app.post("/categories", status_code=201)
def add_category(body: dict, sess: dict = Depends(current_session)):
    name = str(body.get("name", "")).strip()
    if not (1 <= len(name) <= 100):
        raise HTTPException(status_code=422, detail="Invalid category name")
    try:
        execute("INSERT INTO categories (user_id, name) VALUES (%s, %s)", (sess["user_id"], name))
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Category already exists")
    return {"name": name}


@app.get("/dashboard")
def dashboard(sess: dict = Depends(current_session)):
    rows = query_all(
        "SELECT id, site_name, site_name AS title, category, favourite, created_at FROM vault_entries "
        "WHERE user_id=%s ORDER BY created_at DESC", (sess["user_id"],),
    )
    category_count = len(set(row["category"] for row in rows))
    return {
        "full_name": sess["username"], "total": len(rows),
        "category_count": category_count,
        "favourites": sum(bool(row["favourite"]) for row in rows),
        "recent": rows[:5],
    }


@app.post("/breach/check")
def check_password(body: PasswordIn, request: Request, sess: dict = Depends(current_session)):
    try:
        count = services.pwned_count(body.password)
    except services.requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="Breach service unavailable") from exc
    log(sess["user_id"], "breach_check", True, client_ip(request))
    return {"breached": count > 0, "times_seen": count}


@app.get("/generate")
def generate(length: int = 20, symbols: bool = True, uppercase: bool = True,
             lowercase: bool = True, numbers: bool = True, ambiguous: bool = True,
             sess: dict = Depends(current_session)):
    length = max(8, min(length, 64))
    return {"password": security.generate_password(length, symbols, uppercase, lowercase, numbers, ambiguous)}
