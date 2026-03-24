"""
Security helpers live here.

This file keeps the auth and encryption pieces in one place so the Worker
entry file can stay focused on routing. If we expand the site later, this is
the file that should keep low-level security utilities, not request handlers
"""

import base64
import hashlib
import hmac as _hmac
import json
import os


def new_id() -> str:
    """Generate a random UUID v4 using os.urandom."""
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def _derive_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt(plaintext: str, secret: str) -> str:
    """XOR stream-cipher placeholder used for demo data storage."""
    if not plaintext:
        return ""
    key = _derive_key(secret)
    data = plaintext.encode("utf-8")
    ks = (key * (len(data) // len(key) + 1))[: len(data)]
    return base64.b64encode(bytes(a ^ b for a, b in zip(data, ks))).decode("ascii")


def decrypt(ciphertext: str, secret: str) -> str:
    """Reverse of encrypt(). XOR is self-inverse."""
    if not ciphertext:
        return ""
    try:
        key = _derive_key(secret)
        raw = base64.b64decode(ciphertext)
        ks = (key * (len(raw) // len(key) + 1))[: len(raw)]
        return bytes(a ^ b for a, b in zip(raw, ks)).decode("utf-8")
    except Exception:
        return "[decryption error]"


def blind_index(value: str, secret: str) -> str:
    """Deterministic HMAC-SHA256 blind index used for case-insensitive lookup."""
    return _hmac.new(
        secret.encode("utf-8"), value.lower().encode("utf-8"), hashlib.sha256
    ).hexdigest()


_PEPPER = b"edu-platform-cf-pepper-2024"
_PBKDF2_IT = 100_000


def _user_salt(username: str) -> bytes:
    return hashlib.sha256(_PEPPER + username.encode("utf-8")).digest()


def hash_password(password: str, username: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), _user_salt(username), _PBKDF2_IT
    )
    return base64.b64encode(dk).decode("ascii")


def verify_password(password: str, stored: str, username: str) -> bool:
    return hash_password(password, username) == stored


def create_token(uid: str, username: str, role: str, secret: str) -> str:
    payload = base64.b64encode(
        json.dumps({"id": uid, "username": username, "role": role}).encode()
    ).decode("ascii")
    sig = _hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{sig}"


def verify_token(raw: str, secret: str):
    """Return decoded payload dict or None if invalid or missing."""
    if not raw:
        return None
    try:
        token = raw.removeprefix("Bearer ").strip()
        dot = token.rfind(".")
        if dot == -1:
            return None
        payload, sig = token[:dot], token[dot + 1 :]
        expected = _hmac.new(
            secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return None
        padding = (4 - len(payload) % 4) % 4
        return json.loads(base64.b64decode(payload + "=" * padding).decode("utf-8"))
    except Exception:
        return None
