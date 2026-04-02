"""
chat.py — Chat Blueprint + SocketIO event handlers for SecureChat.

REST Routes:
  GET  /api/chat/users              → List all users with online status
  GET  /api/chat/messages/<user_id> → Fetch conversation (decrypted + raw)
  GET  /api/chat/messages/<id>/poll → Long-poll for new messages since ?after=<id>
  POST /api/chat/messages           → Send a new encrypted message
"""

import jwt as pyjwt
from flask import Blueprint, g, jsonify, request
from flask_socketio import SocketIO, emit, join_room as sio_join

import logger as sec_log
import models
import security
from auth import jwt_required, rate_limited
from datetime import datetime, timezone

chat_bp = Blueprint("chat", __name__, url_prefix="/api/chat")

socketio: SocketIO | None = None


def init_socketio(sio: SocketIO):
    global socketio
    socketio = sio
    _register_socket_events(sio)


# ─── REST Routes ──────────────────────────────────────────────────────────────

@chat_bp.route("/users", methods=["GET"])
@jwt_required
def list_users():
    users = models.get_all_users_except(g.user_id)
    return jsonify([
        {
            "user_id":    u["id"],
            "username":   u["username"],
            "is_online":  bool(u["is_online"]),
            "last_login": u["last_login"],
        }
        for u in users
    ]), 200


def _format_message(row, my_id: int) -> dict:
    """Decrypt a DB row and return both plaintext and raw ciphertext."""
    ip = request.remote_addr or "unknown"
    try:
        plaintext = security.decrypt_message(row["content"])
    except ValueError:
        sec_log.log_suspicious(ip, str(my_id), f"decryption failed for msg {row['id']}")
        plaintext = None  # signal failure — client decides display

    return {
        "id":            row["id"],
        "sender_id":     row["sender_id"],
        "sender_name":   row["sender_name"],
        "content":       plaintext,           # None if decryption failed
        "encrypted_raw": row["content"],      # raw base64 ciphertext for toggle
        "sent_at":       row["sent_at"],
        "is_read":       bool(row["is_read"]),
        "is_mine":       row["sender_id"] == my_id,
    }


@chat_bp.route("/messages/<int:peer_id>", methods=["GET"])
@jwt_required
def get_messages(peer_id: int):
    peer = models.get_user_by_id(peer_id)
    if not peer:
        return jsonify({"error": "User not found."}), 404

    rows = models.get_conversation(g.user_id, peer_id)
    models.mark_conversation_read(g.user_id, peer_id)

    return jsonify([_format_message(r, g.user_id) for r in rows]), 200


@chat_bp.route("/messages/<int:peer_id>/poll", methods=["GET"])
@jwt_required
def poll_messages(peer_id: int):
    """Return messages with id > after_id (for auto-refresh polling)."""
    after_id = int(request.args.get("after", 0))
    rows     = models.get_conversation(g.user_id, peer_id)
    new_rows = [r for r in rows if r["id"] > after_id]

    if new_rows:
        models.mark_conversation_read(g.user_id, peer_id)

    return jsonify([_format_message(r, g.user_id) for r in new_rows]), 200


@chat_bp.route("/messages", methods=["POST"])
@jwt_required
@rate_limited
def send_message():
    ip   = request.remote_addr or "unknown"
    data = request.get_json(silent=True) or {}

    recipient_id = data.get("recipient_id")
    content      = data.get("content", "").strip()

    if not recipient_id or not content:
        return jsonify({"error": "recipient_id and content are required."}), 400

    try:
        safe_content = security.sanitise_message(content)
    except ValueError as exc:
        sec_log.log_validation_fail(ip, g.username, "content", str(exc))
        return jsonify({"error": str(exc)}), 400

    recipient = models.get_user_by_id(recipient_id)
    if not recipient:
        return jsonify({"error": "Recipient not found."}), 404

    if recipient_id == g.user_id:
        return jsonify({"error": "You cannot message yourself."}), 400

    encrypted = security.encrypt_message(safe_content)
    msg_id    = models.save_message(g.user_id, recipient_id, encrypted)
    sec_log.log_message_sent(ip, g.username, recipient["username"])

    now = datetime.now(timezone.utc).isoformat()

    if socketio:
        room = _room_name(g.user_id, recipient_id)
        socketio.emit("new_message", {
            "id":            msg_id,
            "sender_id":     g.user_id,
            "sender_name":   g.username,
            "content":       safe_content,
            "encrypted_raw": encrypted,
            "sent_at":       now,
            "is_mine":       False,
            "is_read":       False,
        }, to=room)

    return jsonify({
        "message_id":    msg_id,
        "encrypted_raw": encrypted,
        "sent_at":       now,
        "status":        "sent",
    }), 201


# ─── WebSocket ────────────────────────────────────────────────────────────────

def _room_name(a: int, b: int) -> str:
    lo, hi = sorted([a, b])
    return f"room_{lo}_{hi}"


def _register_socket_events(sio: SocketIO):

    @sio.on("connect")
    def on_connect(auth):
        token = (auth or {}).get("token")
        if not token:
            return False
        try:
            payload    = security.decode_jwt(token)
            g.user_id  = payload["sub"]
            g.username = payload["username"]
        except pyjwt.InvalidTokenError:
            return False

        models.set_online_status(g.user_id, True)
        emit("status", {"message": f"Connected as {g.username}"})

    @sio.on("disconnect")
    def on_disconnect():
        if hasattr(g, "user_id"):
            models.set_online_status(g.user_id, False)

    @sio.on("join_room")
    def on_join_room(data):
        peer_id = data.get("peer_id")
        if not peer_id or not hasattr(g, "user_id"):
            return
        room = _room_name(g.user_id, int(peer_id))
        sio_join(room)

    @sio.on("send_msg")
    def on_send_msg(data):
        if not hasattr(g, "user_id"):
            return

        peer_id = data.get("peer_id")
        content = (data.get("content") or "").strip()

        if not peer_id or not content:
            return

        ip = request.remote_addr or "ws"
        try:
            safe_content = security.sanitise_message(content)
        except ValueError as exc:
            emit("error", {"message": str(exc)})
            return

        encrypted = security.encrypt_message(safe_content)
        msg_id    = models.save_message(g.user_id, int(peer_id), encrypted)
        now       = datetime.now(timezone.utc).isoformat()
        sec_log.log_message_sent(ip, g.username, str(peer_id))

        room    = _room_name(g.user_id, int(peer_id))
        payload = {
            "id":            msg_id,
            "sender_id":     g.user_id,
            "sender_name":   g.username,
            "content":       safe_content,
            "encrypted_raw": encrypted,
            "sent_at":       now,
            "is_read":       False,
        }
        sio.emit("new_message", {**payload, "is_mine": False}, to=room)