"""
logger.py — Structured security-event logging for SecureChat.

All authentication, authorisation, and anomaly events are written here so
operators can audit the system without touching application logs.
"""

import logging
import os
from datetime import datetime, timezone

import config

# ─── Setup ────────────────────────────────────────────────────────────────────

log_dir = os.path.dirname(os.path.abspath(config.LOG_FILE))
os.makedirs(log_dir, exist_ok=True)

_logger = logging.getLogger("securechat.security")
_logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

# File handler — append mode so logs survive restarts
_fh = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
_fh.setFormatter(
    logging.Formatter("%(asctime)s  [%(levelname)-8s]  %(message)s",
                      datefmt="%Y-%m-%dT%H:%M:%S%z")
)
_logger.addHandler(_fh)

# Console handler (useful during development)
_ch = logging.StreamHandler()
_ch.setFormatter(logging.Formatter("[SECURITY] %(message)s"))
_logger.addHandler(_ch)


# ─── Public helpers ───────────────────────────────────────────────────────────

def _fmt(event: str, ip: str, user: str | None, detail: str) -> str:
    u = user or "anonymous"
    return f"event={event!r:30s} ip={ip!r:20s} user={u!r:20s} detail={detail!r}"


def log_signup(ip: str, username: str, success: bool, reason: str = ""):
    if success:
        _logger.info(_fmt("USER_SIGNUP_OK", ip, username, reason or "account created"))
    else:
        _logger.warning(_fmt("USER_SIGNUP_FAIL", ip, username, reason))


def log_login(ip: str, username: str, success: bool, reason: str = ""):
    if success:
        _logger.info(_fmt("USER_LOGIN_OK", ip, username, reason or "authenticated"))
    else:
        _logger.warning(_fmt("USER_LOGIN_FAIL", ip, username, reason))


def log_logout(ip: str, username: str):
    _logger.info(_fmt("USER_LOGOUT", ip, username, "session terminated"))


def log_jwt_error(ip: str, user: str | None, reason: str):
    _logger.warning(_fmt("JWT_ERROR", ip, user, reason))


def log_brute_force(ip: str, username: str, attempt: int):
    _logger.error(
        _fmt("BRUTE_FORCE_DETECTED", ip, username,
             f"attempt #{attempt} — lockout active")
    )


def log_rate_limit(ip: str):
    _logger.warning(_fmt("RATE_LIMIT_HIT", ip, None, "too many requests"))


def log_validation_fail(ip: str, user: str | None, field: str, reason: str):
    _logger.warning(
        _fmt("INPUT_VALIDATION_FAIL", ip, user, f"{field}: {reason}")
    )


def log_message_sent(ip: str, sender: str, recipient: str):
    _logger.info(_fmt("MSG_SENT", ip, sender, f"→ {recipient}"))


def log_suspicious(ip: str, user: str | None, detail: str):
    _logger.error(_fmt("SUSPICIOUS_ACTIVITY", ip, user, detail))
