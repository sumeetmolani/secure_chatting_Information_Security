# 🔒 SecureChat — End-to-End Encrypted Chat Application

A production-grade secure chat application demonstrating real-world information
security practices: AES-256-GCM encryption, JWT authentication, bcrypt password
hashing, brute-force protection, input validation, and WebSocket real-time messaging.

---

## 📁 Project Structure

```
secure_chat/
├── backend/
│   ├── app.py              # Flask application factory + security headers
│   ├── auth.py             # Login, signup, logout routes + JWT middleware
│   ├── chat.py             # REST chat routes + SocketIO WebSocket events
│   ├── models.py           # SQLite database layer (parameterised queries)
│   ├── security.py         # bcrypt, AES-256-GCM, JWT, rate-limiting, validation
│   ├── logger.py           # Structured security-event audit log
│   ├── config.py           # Central configuration (env-aware)
│   ├── bruteforce_sim.py   # Attack simulation script (demo only)
│   └── requirements.txt
├── frontend/
│   ├── templates/
│   │   ├── index.html      # Login / Signup page
│   │   └── chat.html       # Chat interface with WebSocket
│   └── static/
│       ├── css/style.css   # Full dark-theme UI
│       └── js/
│           ├── auth.js     # Login/signup logic + client-side validation
│           └── chat.js     # Real-time chat, session timer, XSS-safe rendering
└── logs/
    └── security.log        # Auto-created on first run
```

---

## ⚡ Quick Setup (5 steps)

### 1. Clone / Extract the project

```bash
cd secure_chat
```

### 2. Create a Python virtual environment

```bash
python -m venv venv

# Activate:
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows PowerShell
```

### 3. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 4. (Optional) Configure environment variables

The app works with secure random defaults, but for production set:

```bash
export SECRET_KEY="your-flask-secret-key-64-chars-hex"
export JWT_SECRET="your-jwt-secret-key-64-chars-hex"
export AES_MESSAGE_KEY="your-aes-key-must-be-exactly-64-hex-chars"
export DATABASE_PATH="/path/to/production.db"
export LOG_FILE="/var/log/securechat/security.log"
```

Or create a `.env` file in `backend/`:
```
SECRET_KEY=...
JWT_SECRET=...
AES_MESSAGE_KEY=...
```

### 5. Start the server

```bash
cd backend
python app.py
```

Open **http://localhost:5000** in your browser.

---

## 🧪 Testing the Application

### Basic flow
1. Open http://localhost:5000 → Sign up as **alice**
2. Open a second browser (or incognito) → Sign up as **bob**
3. Click each other's name → send encrypted messages
4. Watch them appear in real-time via WebSocket

### Run the security simulations

```bash
# First create test users via the UI, then:
cd backend

# Brute-force attack demo (dictionary attack)
python bruteforce_sim.py --target alice

# All simulations (brute-force + rate-limit + injection)
python bruteforce_sim.py --target alice --all

# Watch the security log in real time
tail -f ../logs/security.log
```

---

## 🛡️ Security Features — Deep Dive

### 1. Password Hashing (bcrypt)

**File:** `backend/security.py` — `hash_password()`, `verify_password()`

- Uses bcrypt with **work factor 12** (≈250ms per hash on modern hardware)
- Automatically salted — identical passwords produce different hashes
- Comparison is constant-time (`bcrypt.checkpw`) to prevent timing attacks
- Plaintext passwords are **never** stored, logged, or transmitted after hashing

```python
# How it works
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# Output: $2b$12$<22-char-salt><31-char-hash>
```

### 2. AES-256-GCM Message Encryption

**File:** `backend/security.py` — `encrypt_message()`, `decrypt_message()`

- **AES-256-GCM** (Galois/Counter Mode) provides:
  - **Confidentiality** — 256-bit key renders brute-force infeasible
  - **Integrity** — 128-bit authentication tag detects tampering
  - **Authenticity** — modified ciphertext raises `ValueError`
- A fresh **96-bit nonce** is generated per message (never reused)
- Storage format: `base64url(nonce[12] ‖ ciphertext[n] ‖ tag[16])`
- Messages are encrypted **before** being written to the database

```
┌──────────┬─────────────────┬──────────┐
│ nonce    │   ciphertext    │   tag    │
│ 12 bytes │   n bytes       │ 16 bytes │
└──────────┴─────────────────┴──────────┘
       → base64url encoded → stored in DB
```

### 3. JWT Authentication

**File:** `backend/auth.py` — `jwt_required` decorator  
**File:** `backend/security.py` — `create_jwt()`, `decode_jwt()`

- Tokens signed with **HS256** + a 256-bit random secret
- Claims: `sub` (user_id), `username`, `iat`, `exp`
- Expiry: **60 minutes** (configurable via `JWT_EXPIRY_MINUTES`)
- Sent via `Authorization: Bearer <token>` header (never in URL/cookie)
- WebSocket auth via SocketIO `auth` object (never in query string)
- Client-side countdown timer forces logout before expiry

### 4. Brute-Force Protection

**File:** `backend/security.py` — `record_login_attempt()`, `is_locked_out()`

- Sliding-window counter per **IP address**
- Default: **5 failed attempts** triggers a **5-minute lockout**
- Counter resets on successful login
- Remaining attempts warned to legitimate users
- All events logged as `BRUTE_FORCE_DETECTED`
- Counters stored in-memory (swap for Redis in multi-process deployments)

### 5. Rate Limiting

**File:** `backend/security.py` — `check_rate_limit()`  
**File:** `backend/auth.py` — `rate_limited` decorator

- Sliding window: **30 requests / 60 seconds** per IP
- Applied to all write endpoints (login, signup, send message)
- Returns **HTTP 429** with Retry-After semantics
- Logged as `RATE_LIMIT_HIT`

### 6. SQL Injection Prevention

**File:** `backend/models.py`

All database queries use **parameterised statements** exclusively:

```python
# ✅ Safe — never concatenates user input into SQL
db.execute("SELECT * FROM users WHERE username = ?", (username,))

# ❌ Never done — vulnerable to injection
# db.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

Additionally, `security.validate_username()` rejects SQL keywords and
enforces a strict allowlist regex before queries even run.

### 7. XSS Prevention

**File:** `backend/security.py` — `sanitise_message()`  
**File:** `frontend/static/js/chat.js`

- Server-side: `html.escape()` applied to all message content before storage
- Client-side: **`textContent`** used exclusively for rendering (never `innerHTML`)
- Content Security Policy header restricts script sources
- Result: `<script>alert(1)</script>` is stored and displayed as literal text

### 8. Security HTTP Headers

**File:** `backend/app.py` — `set_security_headers()`

| Header | Value | Purpose |
|---|---|---|
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `X-Content-Type-Options` | `nosniff` | Stops MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter |
| `Content-Security-Policy` | Restricted | Limits script/style sources |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer leakage |

### 9. Session Timeout

- JWT expiry enforced **server-side** (PyJWT validates `exp` claim)
- Client-side countdown timer counts down visually in the sidebar
- Timer turns amber at 5 min, red at 1 min, flashing below 1 min
- Automatic redirect to login on expiry or 401 response
- Logout sets user offline in DB and clears all `localStorage`

### 10. Audit Logging

**File:** `backend/logger.py`

Every security-relevant event is written to `logs/security.log`:

```
2025-01-15T14:32:01+00:00  [INFO    ]  event='USER_LOGIN_OK'      ip='127.0.0.1'  user='alice'   detail='authenticated'
2025-01-15T14:32:45+00:00  [WARNING ]  event='USER_LOGIN_FAIL'    ip='192.168.1.5' user='alice'  detail='bad credentials (attempt 3)'
2025-01-15T14:32:47+00:00  [ERROR   ]  event='BRUTE_FORCE_DETECTED' ip='192.168.1.5' user='alice' detail='attempt #5 — lockout active'
2025-01-15T14:33:01+00:00  [WARNING ]  event='RATE_LIMIT_HIT'     ip='10.0.0.2'   user='anonymous' detail='too many requests'
```

---

## 🔐 HTTPS / Production Setup

To enable HTTPS, obtain a TLS certificate (e.g., Let's Encrypt) and update `app.py`:

```python
# In app.py, change the sio.run() call:
sio.run(app, host="0.0.0.0", port=443,
        ssl_context=("cert.pem", "key.pem"))
```

Also uncomment the HSTS header in `set_security_headers()`:
```python
response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
```

For production, use **Gunicorn + Nginx**:

```bash
pip install gunicorn gevent gevent-websocket

gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
         --workers 1 \
         --bind 0.0.0.0:5000 \
         "app:create_app()[0]"
```

---

## 🧩 API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/signup` | None | Create account |
| `POST` | `/api/auth/login` | None | Get JWT token |
| `POST` | `/api/auth/logout` | JWT | Mark offline |
| `GET` | `/api/auth/me` | JWT | Current user info |
| `GET` | `/api/chat/users` | JWT | List all users |
| `GET` | `/api/chat/messages/<id>` | JWT | Conversation history |
| `POST` | `/api/chat/messages` | JWT | Send message |
| `GET` | `/api/health` | None | Health check |

---

## ⚠️ Known Limitations & Future Work

- **True E2E encryption** would require key exchange on the client (e.g., ECDH)
  and messages decrypted only in the browser — the current implementation
  decrypts server-side for simplicity.
- **Token revocation** — JWTs can't be invalidated before expiry without a
  server-side blocklist (e.g., Redis set of revoked JTIs).
- **Multi-process deployments** need Redis for brute-force counters and
  SocketIO pub/sub.
- **File attachments** and group chats are not implemented.
