"""
security.py — Core cryptographic and validation utilities for SecureChat.

Provides:
  • Password hashing / verification via bcrypt
  • AES-256-GCM authenticated message encryption / decryption
  • JWT creation and verification
  • Input sanitisation to prevent SQL-injection and XSS
  • In-memory brute-force tracker and rate-limiter
"""

import base64
import html
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from threading import Lock

import bcrypt
import jwt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import config
import logger as sec_log


# ─── Password Hashing ─────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain* (work factor 12)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode(), salt).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time compare of *plain* against *hashed*."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ─── AES-256-GCM Message Encryption ──────────────────────────────────────────
# GCM provides both confidentiality AND integrity (authenticated encryption).
# Format stored/transmitted:  base64( nonce[12] + ciphertext + tag[16] )

_AES_KEY = bytes.fromhex(config.AES_MESSAGE_KEY)   # 32-byte key → AES-256


def encrypt_message(plaintext: str) -> str:
    """
    Encrypt *plaintext* with AES-256-GCM.
    Returns a URL-safe base-64 string: nonce ‖ ciphertext ‖ tag.
    """
    nonce  = get_random_bytes(12)                   # 96-bit nonce (GCM standard)
    cipher = AES.new(_AES_KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    blob = nonce + ciphertext + tag                 # 12 + n + 16 bytes
    return base64.urlsafe_b64encode(blob).decode()


def decrypt_message(token: str) -> str:
    """
    Decrypt an AES-256-GCM token produced by *encrypt_message*.
    Raises ValueError on tampering or bad key.
    """
    blob       = base64.urlsafe_b64decode(token.encode())
    nonce      = blob[:12]
    tag        = blob[-16:]
    ciphertext = blob[12:-16]
    cipher     = AES.new(_AES_KEY, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
    except (ValueError, KeyError) as exc:
        raise ValueError("Message authentication failed — data may be tampered.") from exc


# ─── JWT ──────────────────────────────────────────────────────────────────────

def create_jwt(user_id: int, username: str) -> str:
    """Issue a signed JWT valid for JWT_EXPIRY_MINUTES minutes."""
    payload = {
        "sub":      str(user_id),   # PyJWT 2.x requires sub to be a string
        "uid":      user_id,        # Keep int version for easy access
        "username": username,
        "iat":      datetime.now(timezone.utc),
        "exp":      datetime.now(timezone.utc) + timedelta(minutes=config.JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def decode_jwt(token: str) -> dict:
    """
    Decode and validate a JWT.
    Raises jwt.ExpiredSignatureError / jwt.InvalidTokenError on failure.
    """
    payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    # Normalise: always expose user_id as int via 'sub'
    payload["sub"] = int(payload.get("uid") or payload["sub"])
    return payload


# ─── Input Validation & Sanitisation ─────────────────────────────────────────

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,32}$")
_EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Characters that hint at SQL injection attempts
_SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND|--)\b",
    re.IGNORECASE,
)


def validate_username(username: str) -> tuple[bool, str]:
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(username) > 32:
        return False, "Username must be at most 32 characters."
    if not _USERNAME_RE.match(username):
        return False, "Username may only contain letters, digits, _ and -."
    if _SQL_KEYWORDS.search(username):
        return False, "Username contains reserved keywords."
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if len(password) > 128:
        return False, "Password is too long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    return True, ""


def sanitise_message(text: str) -> str:
    """
    HTML-escape the message to neutralise XSS payloads.
    The encrypted ciphertext is stored; this is applied to plaintext before
    display on the client.
    """
    if len(text) > 4096:
        raise ValueError("Message too long (max 4096 chars).")
    return html.escape(text, quote=True)


# ─── Brute-Force / Rate-Limit Tracker ────────────────────────────────────────
# Uses two in-memory dicts protected by a threading.Lock.
# For multi-process deployments, replace with Redis.

_lock            = Lock()
_login_attempts: dict[str, list[float]] = defaultdict(list)  # ip → [timestamps]
_rate_windows:   dict[str, list[float]] = defaultdict(list)  # ip → [timestamps]


def record_login_attempt(ip: str) -> int:
    """
    Record a failed login attempt for *ip*.
    Returns the number of recent failed attempts (within LOCKOUT window).
    """
    now = time.monotonic()
    with _lock:
        attempts = _login_attempts[ip]
        # Keep only attempts within the lockout window
        attempts = [t for t in attempts if now - t < config.LOCKOUT_SECONDS]
        attempts.append(now)
        _login_attempts[ip] = attempts
        count = len(attempts)
    if count >= config.MAX_LOGIN_ATTEMPTS:
        sec_log.log_brute_force(ip, "?", count)
    return count


def is_locked_out(ip: str) -> bool:
    """Return True if *ip* has exceeded the failed-login threshold."""
    now = time.monotonic()
    with _lock:
        attempts = [
            t for t in _login_attempts.get(ip, [])
            if now - t < config.LOCKOUT_SECONDS
        ]
        return len(attempts) >= config.MAX_LOGIN_ATTEMPTS


def clear_login_attempts(ip: str) -> None:
    """Reset failed-login counter after a successful login."""
    with _lock:
        _login_attempts.pop(ip, None)


def check_rate_limit(ip: str) -> bool:
    """
    Return True if the request should be allowed.
    Implements a sliding-window counter per IP.
    """
    now = time.monotonic()
    with _lock:
        window = _rate_windows[ip]
        window = [t for t in window if now - t < config.RATE_LIMIT_WINDOW]
        if len(window) >= config.RATE_LIMIT_MAX_REQS:
            _rate_windows[ip] = window
            return False
        window.append(now)
        _rate_windows[ip] = window
        return True