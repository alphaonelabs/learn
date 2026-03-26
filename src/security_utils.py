import base64
import hashlib
import hmac as _hmac
import json
import os

def new_id() -> str:
    """Generate a random UUID v4 using os.urandom."""
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40   # version 4
    b[8] = (b[8] & 0x3F) | 0x80   # RFC 4122 variant
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _derive_key(secret: str) -> bytes:
    """Derive a 32-byte key from an arbitrary secret string via SHA-256."""
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt(plaintext: str, secret: str) -> str:
    """
    XOR stream-cipher encryption.

    Key is SHA-256 of secret, XOR'd byte-by-byte against plaintext.
    Result is Base64-encoded for safe TEXT storage in D1.

    XOR stream cipher - demonstration only. Replace with AES-GCM for production.
    """
    if not plaintext:
        return ""
    key  = _derive_key(secret)
    data = plaintext.encode("utf-8")
    ks   = (key * (len(data) // len(key) + 1))[: len(data)]
    return base64.b64encode(bytes(a ^ b for a, b in zip(data, ks))).decode("ascii")


def decrypt(ciphertext: str, secret: str) -> str:
    """Reverse of encrypt(). XOR is self-inverse."""
    if not ciphertext:
        return ""
    try:
        key = _derive_key(secret)
        raw = base64.b64decode(ciphertext)
        ks  = (key * (len(raw) // len(key) + 1))[: len(raw)]
        return bytes(a ^ b for a, b in zip(raw, ks)).decode("utf-8")
    except Exception:
        return "[decryption error]"


def blind_index(value: str, secret: str) -> str:
    """
    HMAC-SHA256 deterministic hash of value used as a blind index.

    Allows finding a row by plaintext value without decrypting every row.
    The value is lower-cased before hashing so lookups are case-insensitive.
    """
    return _hmac.new(
        secret.encode("utf-8"), value.lower().encode("utf-8"), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

# ⚠️  For production, derive the pepper from a secret stored via
#     `wrangler secret put PEPPER` and pass it to _user_salt() at runtime.
#     Rotating the pepper requires re-hashing all stored passwords.
_PEPPER    = b"edu-platform-cf-pepper-2024"
_PBKDF2_IT = 100_000


def _user_salt(username: str) -> bytes:
    """Per-user PBKDF2 salt = SHA-256(pepper || username)."""
    return hashlib.sha256(_PEPPER + username.encode("utf-8")).digest()


def hash_password(password: str, username: str) -> str:
    """PBKDF2-SHA256 with per-user derived salt."""
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), _user_salt(username), _PBKDF2_IT
    )
    return base64.b64encode(dk).decode("ascii")


def verify_password(password: str, stored: str, username: str) -> bool:
    return hash_password(password, username) == stored


# ---------------------------------------------------------------------------
# Auth tokens (HMAC-SHA256 signed, stateless JWT-lite)
# ---------------------------------------------------------------------------

def create_token(uid: str, username: str, role: str, secret: str) -> str:
    payload = base64.b64encode(
        json.dumps({"id": uid, "username": username, "role": role}).encode()
    ).decode("ascii")
    sig = _hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{sig}"


def verify_token(raw: str, secret: str):
    """Return decoded payload dict or None if invalid/missing."""
    if not raw:
        return None
    try:
        token = raw.removeprefix("Bearer ").strip()
        dot   = token.rfind(".")
        if dot == -1:
            return None
        p, sig = token[:dot], token[dot + 1:]
        exp = _hmac.new(
            secret.encode("utf-8"), p.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not _hmac.compare_digest(sig, exp):
            return None
        padding = (4 - len(p) % 4) % 4
        return json.loads(base64.b64decode(p + "=" * padding).decode("utf-8"))
    except Exception:
        return None
