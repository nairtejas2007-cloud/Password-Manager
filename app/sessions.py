import secrets
import threading
from datetime import datetime, timedelta, timezone

import hmac

from fastapi import Header, HTTPException, Request

from app.config import SESSION_TTL_MINUTES

# token -> {"user_id", "username", "key", "expires"}
# The vault key lives only in memory and is gone on logout, expiry or restart.
_sessions = {}
_entry_edit_authorizations = {}
_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc)


def create_session(
    user_id: int, username: str, key: bytes, ttl_minutes: int = SESSION_TTL_MINUTES
) -> str:
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = {
            "user_id": user_id,
            "username": username,
            "key": key,
            "ttl_minutes": ttl_minutes,
            "expires": _now() + timedelta(minutes=ttl_minutes),
        }
    return token



def delete_session(token: str) -> None:
    with _lock:
        _sessions.pop(token, None)
        _clear_entry_edit_authorizations(token)


def _clear_entry_edit_authorizations(token: str) -> None:
    for authorization in [
        key for key in _entry_edit_authorizations if key[0] == token
    ]:
        del _entry_edit_authorizations[authorization]


def authorize_entry_edit(token: str, entry_id: int) -> None:
    now = _now()
    with _lock:
        for authorization, expires in list(_entry_edit_authorizations.items()):
            if expires < now:
                del _entry_edit_authorizations[authorization]
        _entry_edit_authorizations[(token, entry_id)] = now + timedelta(minutes=5)


def consume_entry_edit_authorization(token: str, entry_id: int) -> bool:
    with _lock:
        expires = _entry_edit_authorizations.pop((token, entry_id), None)
        return expires is not None and expires >= _now()


def current_session(
    request: Request, authorization: str = Header(default="")
) -> dict:
    cookie_token = request.cookies.get("pm_session")
    bearer_token = authorization[7:] if authorization.startswith("Bearer ") else None
    token = cookie_token or bearer_token
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    if cookie_token and request.method not in {"GET", "HEAD", "OPTIONS"}:
        csrf_cookie = request.cookies.get("pm_csrf", "")
        csrf_header = request.headers.get("x-csrf-token", "")
        if not csrf_cookie or not hmac.compare_digest(csrf_cookie, csrf_header):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
    with _lock:
        sess = _sessions.get(token)
        if not sess or sess["expires"] < _now():
            _sessions.pop(token, None)
            _clear_entry_edit_authorizations(token)
            raise HTTPException(status_code=401, detail="Session expired")
        sess["expires"] = _now() + timedelta(minutes=sess["ttl_minutes"])
        return {**sess, "token": token}
