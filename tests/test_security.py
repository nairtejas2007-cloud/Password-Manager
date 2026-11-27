import pytest

from app import security


def test_argon2_hash_and_verify():
    h = security.hash_master_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert security.verify_master_password(h, "correct horse battery staple")
    assert not security.verify_master_password(h, "wrong password")


def test_kdf_is_deterministic_and_salted():
    salt = security.new_kdf_salt()
    k1 = security.derive_vault_key("master-password-123", salt)
    k2 = security.derive_vault_key("master-password-123", salt)
    k3 = security.derive_vault_key("master-password-123", security.new_kdf_salt())
    assert len(k1) == 32
    assert k1 == k2
    assert k1 != k3


def test_encrypt_decrypt_roundtrip():
    key = security.derive_vault_key("master-password-123", security.new_kdf_salt())
    blob = security.encrypt(key, "hunter2")
    assert b"hunter2" not in blob
    assert security.decrypt(key, blob) == "hunter2"


def test_encryption_uses_fresh_nonce():
    key = security.derive_vault_key("master-password-123", security.new_kdf_salt())
    assert security.encrypt(key, "same") != security.encrypt(key, "same")


def test_wrong_key_fails():
    salt = security.new_kdf_salt()
    k1 = security.derive_vault_key("master-password-123", salt)
    k2 = security.derive_vault_key("different-password-1", salt)
    blob = security.encrypt(k1, "secret")
    with pytest.raises(ValueError):
        security.decrypt(k2, blob)


def test_tampered_ciphertext_fails():
    key = security.derive_vault_key("master-password-123", security.new_kdf_salt())
    blob = bytearray(security.encrypt(key, "secret"))
    blob[-1] ^= 1
    with pytest.raises(ValueError):
        security.decrypt(key, bytes(blob))


def test_generate_password():
    pw = security.generate_password(24)
    assert len(pw) == 24
    assert any(c.isdigit() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
