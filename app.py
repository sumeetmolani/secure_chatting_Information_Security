"""
app.py — SecureChat Flask Application Entry Point

Wires up:
  • Flask application factory
  • CORS headers
  • Flask-SocketIO (WebSocket support)
  • Auth and Chat blueprints
  • Security headers (HSTS, CSP, X-Frame-Options, …)
  • SQLite initialisation
  • Global error handlers
"""

import os
import sys

from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO

import config
import models
from auth import auth_bp
from chat import chat_bp, init_socketio


# ─── Application Factory ──────────────────────────────────────────────────────

def create_app() -> tuple[Flask, SocketIO]:
    # Resolve the frontend folder relative to this file
    base_dir     = os.path.dirname(os.path.abspath(__file__))
    frontend_dir = os.path.join(base_dir, "..", "frontend")

    app = Flask(
        __name__,
        template_folder=os.path.join(frontend_dir, "templates"),
        static_folder=os.path.join(frontend_dir, "static"),
    )

    app.secret_key = config.SECRET_KEY

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS(app, resources={r"/api/*": {"origins": config.CORS_ORIGINS}},
         supports_credentials=True)

    # ── SocketIO ──────────────────────────────────────────────────────────────
    # async_mode="threading" works without an event loop — fine for SQLite.
    sio = SocketIO(
        app,
        cors_allowed_origins=config.CORS_ORIGINS,
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )

    # ── Blueprints ────────────────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    init_socketio(sio)

    # ── Database ──────────────────────────────────────────────────────────────
    models.init_db()

    # ── Security Headers ──────────────────────────────────────────────────────
    @app.after_request
    def set_security_headers(response):
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # Block MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Basic XSS filter (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Content Security Policy — tighten in production
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' ws: wss:; "
            "img-src 'self' data:;"
        )
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # HSTS — enable only when HTTPS is active
        # response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    # ── Page Routes ───────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/chat")
    def chat_page():
        return render_template("chat.html")

    # ── Health Check ──────────────────────────────────────────────────────────
    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "SecureChat"}), 200

    # ── Global Error Handlers ─────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Endpoint not found."}), 404
        return render_template("index.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(500)
    def server_error(exc):
        app.logger.error("Unhandled exception: %s", exc)
        return jsonify({"error": "Internal server error."}), 500

    return app, sio


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app, sio = create_app()

    # Use SSL in production:
    #   ssl_context = ("cert.pem", "key.pem")
    #   sio.run(app, host="0.0.0.0", port=5000, ssl_context=ssl_context)
    ssl_context = None
    host        = os.environ.get("HOST", "0.0.0.0")
    port        = int(os.environ.get("PORT", 5000))

    print(f"""
╔══════════════════════════════════════════╗
║         SecureChat Server Starting       ║
╠══════════════════════════════════════════╣
║  URL : http://{host}:{port}              ║
║  DB  : {config.DATABASE_PATH:<32}║
║  LOG : {config.LOG_FILE:<32}║
╚══════════════════════════════════════════╝
    """)

    sio.run(app, host=host, port=port, debug=config.DEBUG,
            use_reloader=False, ssl_context=ssl_context)
