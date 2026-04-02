"""
auth.py — Authentication Blueprint for SecureChat.

Routes:
  POST /api/auth/signup  → Register a new account
  POST /api/auth/login   → Authenticate and receive JWT
  POST /api/auth/logout  → Invalidate session (set offline)
  GET  /api/auth/me      → Return current user info (JWT required)
"""

from functools import wraps

import jwt as pyjwt
from flask import Blueprint, g, jsonify, request

import logger as sec_log
import models
import security

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# ─── JWT Middleware / Decorator ───────────────────────────────────────────────

def jwt_required(f):
    """
    Decorator that validates the Bearer token in the Authorization header.
    Sets g.user_id and g.username on success.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip    = request.remote_addr or "unknown"
        token = None

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

        if not token:
            sec_log.log_jwt_error(ip, None, "missing token")
            return jsonify({"error": "Authentication required."}), 401

        try:
            payload   = security.decode_jwt(token)
            g.user_id = payload["sub"]
            g.username = payload["username"]
        except pyjwt.ExpiredSignatureError:
            sec_log.log_jwt_error(ip, None, "token expired")
            return jsonify({"error": "Session expired. Please log in again."}), 401
        except pyjwt.InvalidTokenError as exc:
            sec_log.log_jwt_error(ip, None, str(exc))
            return jsonify({"error": "Invalid token."}), 401

        return f(*args, **kwargs)
    return wrapper


# ─── Rate-Limit Decorator ─────────────────────────────────────────────────────

def rate_limited(f):
    """Reject requests from IPs that exceed the sliding-window threshold."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        if not security.check_rate_limit(ip):
            sec_log.log_rate_limit(ip)
            return jsonify({"error": "Too many requests. Slow down."}), 429
        return f(*args, **kwargs)
    return wrapper


# ─── Routes ───────────────────────────────────────────────────────────────────

@auth_bp.route("/signup", methods=["POST"])
@rate_limited
def signup():
    ip   = request.remote_addr or "unknown"
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    # ── Validate inputs ──
    ok, reason = security.validate_username(username)
    if not ok:
        sec_log.log_validation_fail(ip, username, "username", reason)
        return jsonify({"error": reason}), 400

    ok, reason = security.validate_password(password)
    if not ok:
        sec_log.log_validation_fail(ip, username, "password", reason)
        return jsonify({"error": reason}), 400

    # ── Check uniqueness ──
    if models.get_user_by_username(username):
        sec_log.log_signup(ip, username, False, "username already taken")
        return jsonify({"error": "Username already taken."}), 409

    # ── Persist ──
    password_hash = security.hash_password(password)
    user_id       = models.create_user(username, password_hash)
    token         = security.create_jwt(user_id, username)

    sec_log.log_signup(ip, username, True)
    return jsonify({"token": token, "username": username, "user_id": user_id}), 201


@auth_bp.route("/login", methods=["POST"])
@rate_limited
def login():
    ip   = request.remote_addr or "unknown"
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    # ── Brute-force check ──
    if security.is_locked_out(ip):
        return jsonify({
            "error": f"Account locked after too many failed attempts. "
                     f"Try again in {security.config.LOCKOUT_SECONDS // 60} minutes."
        }), 429

    # ── Basic input checks ──
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    # ── Lookup user ──
    user = models.get_user_by_username(username)

    # Constant-time check even when user doesn't exist (prevents enumeration).
    # This is a real bcrypt hash of "dummy" so checkpw() doesn't raise on invalid salt.
    dummy_hash = "$2b$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Vb3zMwyBRX/xLyi"
    check_hash = user["password_hash"] if user else dummy_hash

    if not security.verify_password(password, check_hash) or not user:
        count = security.record_login_attempt(ip)
        remaining = max(0, security.config.MAX_LOGIN_ATTEMPTS - count)
        sec_log.log_login(ip, username, False,
                          f"bad credentials (attempt {count})")
        msg = "Invalid username or password."
        if remaining <= 2 and remaining > 0:
            msg += f" {remaining} attempt(s) remaining before lockout."
        return jsonify({"error": msg}), 401

    # ── Success ──
    security.clear_login_attempts(ip)
    models.update_last_login(user["id"])
    models.set_online_status(user["id"], True)

    token = security.create_jwt(user["id"], user["username"])
    sec_log.log_login(ip, username, True)

    return jsonify({
        "token":    token,
        "username": user["username"],
        "user_id":  user["id"],
    }), 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required
def logout():
    ip = request.remote_addr or "unknown"
    models.set_online_status(g.user_id, False)
    sec_log.log_logout(ip, g.username)
    return jsonify({"message": "Logged out successfully."}), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required
def me():
    user = models.get_user_by_id(g.user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    return jsonify({
        "user_id":    user["id"],
        "username":   user["username"],
        "created_at": user["created_at"],
        "last_login": user["last_login"],
    }), 200