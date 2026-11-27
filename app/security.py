import os
import secrets
import string
import re

from argon2 import PasswordHasher
from argon2.low_level import Type, hash_secret_raw
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_hasher = PasswordHasher()  # Argon2id defaults

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
NONCE_SIZE = 12


# ---------- master password hashing (Argon2id) ----------

def hash_master_password(password: str) -> str:
    return _hasher.hash(password)


def verify_master_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


# ---------- vault key derivation (PBKDF2-HMAC-SHA256) ----------

def new_kdf_salt() -> bytes:
    return os.urandom(16)


def derive_vault_key(master_password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )


# ---------- AES-256-GCM ----------

def encrypt(key: bytes, plaintext: str) -> bytes:
    """Returns nonce || ciphertext || tag."""
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct


def decrypt(key: bytes, blob: bytes) -> str:
    """Raises ValueError if the key is wrong or the data was tampered with."""
    blob = bytes(blob)
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except InvalidTag as exc:
        raise ValueError("Decryption failed") from exc


# ---------- password generator ----------

def generate_password(
    length: int = 20,
    symbols: bool = True,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    ambiguous: bool = True,
) -> str:
    alphabet = ""
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    special = "!@#$%^&*()-_=+[]{}"
    if ambiguous:
        upper += ""; lower += ""; digits += ""
    else:
        upper = "".join(c for c in upper if c not in "IO")
        lower = "".join(c for c in lower if c not in "lo")
        digits = "".join(c for c in digits if c not in "01")
    pools = []
    if uppercase:
        alphabet += upper; pools.append(upper)
    if lowercase:
        alphabet += lower; pools.append(lower)
    if numbers:
        alphabet += digits; pools.append(digits)
    if symbols:
        alphabet += special; pools.append(special)
    if not pools:
        pools = [lower]; alphabet = lower
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in pool for c in pw) for pool in pools):
            return pw
