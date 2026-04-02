"""
config.py — Central configuration for SecureChat backend
"""

import os
import secrets

# ─── Flask ────────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DEBUG       = os.environ.get("DEBUG", "false").lower() == "true"

# ─── Database ─────────────────────────────────────────────────────────────────
DATABASE_PATH = os.environ.get("DATABASE_PATH", "securechat.db")

# ─── JWT ──────────────────────────────────────────────────────────────────────
JWT_SECRET          = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM       = "HS256"
JWT_EXPIRY_MINUTES  = 480         # 8 hours — comfortable session length
JWT_REFRESH_DAYS    = 7

# ─── AES Message Encryption ───────────────────────────────────────────────────
# Key is PERSISTED to .aes_key so messages survive server restarts.
# Without persistence every restart generates a new random key and all
# previously encrypted messages become unreadable — [decryption error].

def _load_or_create_aes_key() -> str:
    env_key = os.environ.get("AES_MESSAGE_KEY")
    if env_key:
        return env_key
    key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".aes_key")
    if os.path.exists(key_file):
        with open(key_file, "r") as fh:
            return fh.read().strip()
    new_key = secrets.token_hex(32)
    with open(key_file, "w") as fh:
        fh.write(new_key)
    print(f"[INFO] New AES-256 key generated and saved to {key_file}")
    return new_key

AES_MESSAGE_KEY = _load_or_create_aes_key()

# ─── Brute-Force / Rate-Limiting ──────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS   = 5
LOCKOUT_SECONDS      = 300
RATE_LIMIT_WINDOW    = 60
RATE_LIMIT_MAX_REQS  = 120        # raised to support chat polling

# ─── Session / CORS ───────────────────────────────────────────────────────────
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE   = False   # Set True when HTTPS is active
CORS_ORIGINS = ["http://localhost:5000", "http://192.168.1.3:5000",
                "https://yourdomain.com"]

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE  = os.environ.get("LOG_FILE", "../logs/security.log")
LOG_LEVEL = "INFO"