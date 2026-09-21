"""Cryptographic helpers: password hashing, opaque tokens and at-rest secret encryption."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from netguard.config import get_settings

# scrypt parameters (OWASP-recommended minimum: N=2^17 r=8 p=1 is the ideal; 2^15 keeps login
# latency reasonable). Parameters are stored in the hash so they can be raised later.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128


class PasswordPolicyError(ValueError):
    pass


def validate_password_strength(password: str, email: str = "") -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
    if len(set(password)) < 5:
        raise PasswordPolicyError("Password is too repetitive")
    local = email.split("@")[0].lower()
    if local and len(local) >= 4 and local in password.lower():
        raise PasswordPolicyError("Password must not contain your email name")


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=_SCRYPT_DKLEN,
        maxmem=256 * 1024 * 1024,
    )


def hash_password(password: str, *, n: int | None = None) -> str:
    n = n or _SCRYPT_N
    salt = os.urandom(16)
    digest = _scrypt(password, salt, n, _SCRYPT_R, _SCRYPT_P)
    return "$".join(
        [
            "scrypt",
            str(n),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        ]
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest_b64)
        actual = _scrypt(password, base64.b64decode(salt_b64), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, actual)


# A fixed dummy hash so that logins for unknown users cost the same as real ones (timing).
_DUMMY_HASH: str | None = None


def dummy_verify(password: str) -> None:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("netguard-dummy-password")
    verify_password(password, _DUMMY_HASH)


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Tokens are high-entropy random values, so a plain SHA-256 is sufficient for lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _fernet() -> Fernet:
    secret = get_settings().resolved_secret_key().encode("utf-8")
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"netguard-secret-encryption"
    ).derive(secret)
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a provider token / credential for storage."""
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Stored secret could not be decrypted (was the secret key changed?)"
        ) from exc
