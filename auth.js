/**
 * auth.js — Login / Signup page logic for SecureChat
 *
 * Security measures implemented:
 *  • Client-side input validation (mirrors server-side checks)
 *  • No passwords stored in localStorage — only the JWT token
 *  • XSS-safe DOM manipulation (textContent only)
 *  • Rate-limit feedback from server surfaced to user
 *  • Brute-force lockout messaging
 */

"use strict";

const API = "";   // Same origin — Flask serves both API and HTML

// ── Utility ──────────────────────────────────────────────────────────────────

function showBanner(msg, type = "error") {
  const el = document.getElementById("banner");
  el.textContent = msg;
  el.className   = `banner ${type}`;
  el.classList.remove("hidden");
  // Auto-hide success banners after 3s
  if (type === "success") setTimeout(() => el.classList.add("hidden"), 3000);
}

function setLoading(btnId, loading) {
  const btn     = document.getElementById(btnId);
  const text    = btn.querySelector(".btn-text");
  const spinner = btn.querySelector(".btn-spinner");
  btn.disabled        = loading;
  text.classList.toggle("hidden", loading);
  spinner.classList.toggle("hidden", !loading);
}

// ── Tab Switcher ─────────────────────────────────────────────────────────────

function switchTab(tab) {
  document.getElementById("panel-login").classList.toggle("hidden", tab !== "login");
  document.getElementById("panel-signup").classList.toggle("hidden", tab !== "signup");
  document.getElementById("tab-login").classList.toggle("active", tab === "login");
  document.getElementById("tab-signup").classList.toggle("active", tab === "signup");
  document.getElementById("tab-login").setAttribute("aria-selected", tab === "login");
  document.getElementById("tab-signup").setAttribute("aria-selected", tab === "signup");
  document.getElementById("banner").classList.add("hidden");
}

// ── Password Visibility Toggle ────────────────────────────────────────────────

function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  const shown = input.type === "text";
  input.type  = shown ? "password" : "text";
  btn.setAttribute("aria-label", shown ? "Show password" : "Hide password");
  btn.textContent = shown ? "👁" : "🙈";
}

// ── Client-Side Validation ────────────────────────────────────────────────────

const USERNAME_RE = /^[A-Za-z0-9_\-]{3,32}$/;

function validateUsernameField(input) {
  const val = input.value.trim();
  const hint = document.getElementById("hint-username");
  if (!USERNAME_RE.test(val)) {
    input.classList.add("error");
    input.classList.remove("valid");
    hint.className = "field-hint error";
    hint.textContent = "3–32 chars. Letters, digits, _ and - only.";
  } else {
    input.classList.remove("error");
    input.classList.add("valid");
    hint.className = "field-hint valid";
    hint.textContent = "✓ Looks good";
  }
}

function validatePassword(pw) {
  if (pw.length < 8)         return { ok: false, msg: "At least 8 characters required." };
  if (pw.length > 128)       return { ok: false, msg: "Password too long." };
  if (!/[A-Z]/.test(pw))    return { ok: false, msg: "Needs at least one uppercase letter." };
  if (!/[0-9]/.test(pw))    return { ok: false, msg: "Needs at least one digit." };
  return { ok: true, msg: "" };
}

/**
 * updateStrengthMeter — visual password strength indicator
 * Scoring: length, uppercase, digit, special char, length bonus
 */
function updateStrengthMeter(pw) {
  let score = 0;
  if (pw.length >= 8)    score++;
  if (pw.length >= 12)   score++;
  if (/[A-Z]/.test(pw))  score++;
  if (/[0-9]/.test(pw))  score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  const bar    = document.getElementById("strength-bar");
  const hint   = document.getElementById("hint-password");
  const pct    = (score / 5) * 100;
  const colors = ["#ef4444", "#f59e0b", "#f59e0b", "#10b981", "#10b981"];
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

  bar.style.width      = pct + "%";
  bar.style.background = colors[Math.max(0, score - 1)] || "#ef4444";
  hint.textContent     = pw ? labels[Math.max(0, score - 1)] : "Min 8 chars · 1 uppercase · 1 digit";
  hint.className       = score >= 4 ? "field-hint valid" : "field-hint";
}

// ── API Calls ─────────────────────────────────────────────────────────────────

async function apiPost(endpoint, body) {
  const res = await fetch(`${API}${endpoint}`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

// ── Login ─────────────────────────────────────────────────────────────────────

async function doLogin() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;

  if (!username || !password) {
    showBanner("Please enter your username and password.");
    return;
  }

  setLoading("btn-login", true);

  try {
    const { ok, status, data } = await apiPost("/api/auth/login", { username, password });

    if (ok && data.token) {
      // Store JWT (never store plain passwords)
      localStorage.setItem("jwt_token",   data.token);
      localStorage.setItem("username",    data.username);
      localStorage.setItem("user_id",     String(data.user_id));
      localStorage.setItem("login_time",  String(Date.now()));

      showBanner("Login successful! Redirecting…", "success");
      setTimeout(() => { window.location.href = "/chat"; }, 600);
    } else {
      showBanner(data.error || "Login failed. Please try again.");
    }
  } catch {
    showBanner("Network error. Please check your connection.");
  } finally {
    setLoading("btn-login", false);
  }
}

// ── Signup ────────────────────────────────────────────────────────────────────

async function doSignup() {
  const username = document.getElementById("signup-username").value.trim();
  const password = document.getElementById("signup-password").value;

  // Client-side validation
  if (!USERNAME_RE.test(username)) {
    showBanner("Invalid username. Use 3–32 chars: letters, digits, _ or -.");
    return;
  }
  const { ok: pwOk, msg: pwMsg } = validatePassword(password);
  if (!pwOk) { showBanner(pwMsg); return; }

  setLoading("btn-signup", true);

  try {
    const { ok, status, data } = await apiPost("/api/auth/signup", { username, password });

    if (ok && data.token) {
      localStorage.setItem("jwt_token",  data.token);
      localStorage.setItem("username",   data.username);
      localStorage.setItem("user_id",    String(data.user_id));
      localStorage.setItem("login_time", String(Date.now()));

      showBanner("Account created! Redirecting…", "success");
      setTimeout(() => { window.location.href = "/chat"; }, 600);
    } else {
      showBanner(data.error || "Signup failed. Please try again.");
    }
  } catch {
    showBanner("Network error. Please check your connection.");
  } finally {
    setLoading("btn-signup", false);
  }
}

// ── Enter key support ─────────────────────────────────────────────────────────

document.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const active = document.activeElement;
  if (active && active.closest("#panel-login"))  doLogin();
  if (active && active.closest("#panel-signup")) doSignup();
});

// ── Redirect if already logged in ────────────────────────────────────────────

(function checkExistingSession() {
  const token     = localStorage.getItem("jwt_token");
  const loginTime = Number(localStorage.getItem("login_time") || 0);
  const TOKEN_TTL = 60 * 60 * 1000;   // 60 minutes in ms — matches JWT_EXPIRY_MINUTES

  if (token && (Date.now() - loginTime) < TOKEN_TTL) {
    window.location.href = "/chat";
  } else if (token) {
    // Stale token — clear it
    localStorage.clear();
  }
})();
