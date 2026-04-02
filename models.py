"""
models.py — SQLite database layer for SecureChat.

Tables:
  • users    — accounts with bcrypt-hashed passwords
  • messages — AES-256-GCM encrypted content, per-conversation

All queries use parameterised statements to prevent SQL injection.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

import config


# ─── Connection Helper ────────────────────────────────────────────────────────

@contextmanager
def get_db():
    """Yield a configured SQLite connection and auto-commit / rollback."""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row           # Dict-like rows
    conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
    conn.execute("PRAGMA foreign_keys=ON")   # Enforce FK constraints
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── Schema Initialisation ────────────────────────────────────────────────────

def init_db():
    """Create tables if they do not already exist."""
    with get_db() as db:
        db.executescript("""
            -- ── Users ──────────────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                created_at    TEXT    NOT NULL,
                last_login    TEXT,
                is_online     INTEGER NOT NULL DEFAULT 0  -- 0=offline, 1=online
            );

            -- ── Messages ────────────────────────────────────────────────────
            -- content is stored as AES-256-GCM ciphertext (base64)
            CREATE TABLE IF NOT EXISTS messages (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id    INTEGER NOT NULL REFERENCES users(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                content      TEXT    NOT NULL,   -- encrypted
                sent_at      TEXT    NOT NULL,
                is_read      INTEGER NOT NULL DEFAULT 0
            );

            -- ── Indexes ─────────────────────────────────────────────────────
            CREATE INDEX IF NOT EXISTS idx_messages_conv
                ON messages(sender_id, recipient_id, sent_at);
            CREATE INDEX IF NOT EXISTS idx_users_username
                ON users(username);
        """)


# ─── User CRUD ────────────────────────────────────────────────────────────────

def create_user(username: str, password_hash: str) -> int:
    """Insert a new user; return the new row id."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, now),
        )
        return cur.lastrowid


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with get_db() as db:
        return db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    with get_db() as db:
        return db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def get_all_users_except(user_id: int) -> list[sqlite3.Row]:
    """Return all users visible in the contact list."""
    with get_db() as db:
        return db.execute(
            "SELECT id, username, is_online, last_login FROM users WHERE id != ?",
            (user_id,),
        ).fetchall()


def set_online_status(user_id: int, online: bool):
    with get_db() as db:
        db.execute(
            "UPDATE users SET is_online = ? WHERE id = ?",
            (1 if online else 0, user_id),
        )


def update_last_login(user_id: int):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "UPDATE users SET last_login = ? WHERE id = ?", (now, user_id)
        )


# ─── Message CRUD ─────────────────────────────────────────────────────────────

def save_message(sender_id: int, recipient_id: int, encrypted_content: str) -> int:
    """Persist an encrypted message; return its id."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO messages (sender_id, recipient_id, content, sent_at)
               VALUES (?, ?, ?, ?)""",
            (sender_id, recipient_id, encrypted_content, now),
        )
        return cur.lastrowid


def get_conversation(user_a: int, user_b: int, limit: int = 100) -> list[sqlite3.Row]:
    """
    Return the last *limit* messages exchanged between two users,
    oldest-first.
    """
    with get_db() as db:
        return db.execute(
            """SELECT m.id, m.sender_id, m.recipient_id, m.content,
                      m.sent_at, m.is_read,
                      u.username AS sender_name
               FROM   messages m
               JOIN   users    u ON u.id = m.sender_id
               WHERE  (m.sender_id = ? AND m.recipient_id = ?)
                   OR (m.sender_id = ? AND m.recipient_id = ?)
               ORDER  BY m.sent_at ASC
               LIMIT  ?""",
            (user_a, user_b, user_b, user_a, limit),
        ).fetchall()


def mark_conversation_read(reader_id: int, sender_id: int):
    """Mark all messages FROM sender TO reader as read."""
    with get_db() as db:
        db.execute(
            """UPDATE messages SET is_read = 1
               WHERE sender_id = ? AND recipient_id = ? AND is_read = 0""",
            (sender_id, reader_id),
        )
