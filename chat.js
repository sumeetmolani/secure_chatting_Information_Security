/**
 * chat.js — SecureChat real-time chat page
 *
 * Features:
 *  • Auto-refresh: polls /poll endpoint every 3 seconds for new messages
 *  • Decrypt toggle: switch between plaintext and raw AES-256-GCM ciphertext
 *  • WebSocket for instant delivery when connected
 *  • XSS-safe rendering (textContent only)
 *  • JWT in Authorization header — never in URLs
 */

"use strict";

// ─── Auth State ───────────────────────────────────────────────────────────────
const TOKEN   = localStorage.getItem("jwt_token");
const ME_ID   = Number(localStorage.getItem("user_id"));
const ME_NAME = localStorage.getItem("username");

if (!TOKEN || !ME_ID || !ME_NAME) {
  window.location.href = "/";
}

// ─── App State ────────────────────────────────────────────────────────────────
let currentPeer    = null;
let allContacts    = [];
let socket         = null;
let pollInterval   = null;
let contactInterval= null;
let lastMessageId  = 0;          // highest message id seen in current convo
let showEncrypted  = false;      // decrypt toggle state
let messageStore   = [];         // full message objects (both content + encrypted_raw)

// ─── DOM ──────────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function setText(id, txt) { $(id).textContent = txt; }

function formatTime(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatDate(iso) {
  const d  = new Date(iso);
  const td = new Date();
  const yd = new Date(td); yd.setDate(td.getDate() - 1);
  if (d.toDateString() === td.toDateString()) return "Today";
  if (d.toDateString() === yd.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
}

function avatarChar(name) { return (name || "?")[0].toUpperCase(); }

// ─── Authenticated fetch ──────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${TOKEN}`,
      ...(opts.headers || {}),
    },
  });
  if (res.status === 401) { doLogout(); return null; }
  return res.ok ? res.json() : null;
}

// ─── Logout ───────────────────────────────────────────────────────────────────
async function doLogout() {
  await fetch("/api/auth/logout", {
    method: "POST",
    headers: { "Authorization": `Bearer ${TOKEN}` },
  }).catch(() => {});
  if (socket) socket.disconnect();
  clearInterval(pollInterval);
  clearInterval(contactInterval);
  localStorage.clear();
  window.location.href = "/";
}

// ─── Contacts ─────────────────────────────────────────────────────────────────
async function loadContacts() {
  const users = await apiFetch("/api/chat/users");
  if (!users) return;
  allContacts = users;
  renderContacts(users);
}

function renderContacts(users) {
  const list = $("contact-list");
  if (!users.length) {
    list.innerHTML = `<li class="contact-loading">No other users yet.</li>`;
    return;
  }
  list.innerHTML = "";
  users.forEach(u => {
    const li = document.createElement("li");
    li.className = "contact-item" + (currentPeer?.user_id === u.user_id ? " active" : "");
    li.setAttribute("role", "option");
    li.onclick = () => openChat(u);

    const avWrap = document.createElement("div");
    avWrap.className = "contact-avatar";
    const av  = document.createElement("div");
    av.className = "avatar";
    av.textContent = avatarChar(u.username);
    const dot = document.createElement("div");
    dot.className = "online-dot" + (u.is_online ? " online" : "");
    avWrap.appendChild(av);
    avWrap.appendChild(dot);

    const info = document.createElement("div");
    const nm   = document.createElement("div");
    nm.className = "contact-name";
    nm.textContent = u.username;
    const mt = document.createElement("div");
    mt.className = "contact-meta";
    mt.textContent = u.is_online ? "● Online" : "Offline";
    info.appendChild(nm);
    info.appendChild(mt);

    li.appendChild(avWrap);
    li.appendChild(info);
    list.appendChild(li);

    // Sync peer status if this is the active chat
    if (currentPeer && currentPeer.user_id === u.user_id) {
      currentPeer.is_online = u.is_online;
      const ps = $("peer-status");
      ps.textContent = u.is_online ? "● Online" : "Offline";
      ps.className   = "peer-status" + (u.is_online ? " online" : "");
    }
  });
}

function filterUsers(q) {
  renderContacts(q
    ? allContacts.filter(u => u.username.toLowerCase().includes(q.toLowerCase()))
    : allContacts);
}

// ─── Open chat ────────────────────────────────────────────────────────────────
async function openChat(peer) {
  currentPeer   = peer;
  lastMessageId = 0;
  messageStore  = [];

  // Sidebar active state
  document.querySelectorAll(".contact-item").forEach(l => l.classList.remove("active"));
  // Re-render to apply active class
  renderContacts(allContacts);

  setText("peer-name", peer.username);
  $("peer-avatar").textContent = avatarChar(peer.username);
  const ps = $("peer-status");
  ps.textContent = peer.is_online ? "● Online" : "Offline";
  ps.className   = "peer-status" + (peer.is_online ? " online" : "");

  $("empty-state").classList.add("hidden");
  $("chat-area").classList.remove("hidden");

  if (socket?.connected) {
    socket.emit("join_room", { peer_id: peer.user_id });
  }

  // Stop any previous poll, start fresh
  clearInterval(pollInterval);
  await loadMessages(peer.user_id);

  // Auto-refresh every 3 seconds
  pollInterval = setInterval(() => pollNewMessages(peer.user_id), 3000);

  $("sidebar").classList.add("hidden-mobile");
  $("msg-input").focus();
}

function showSidebar() {
  $("sidebar").classList.remove("hidden-mobile");
}

// ─── Load full conversation ───────────────────────────────────────────────────
async function loadMessages(peerId) {
  const container = $("messages-container");
  container.innerHTML = `<div class="contact-loading">Loading…</div>`;

  const msgs = await apiFetch(`/api/chat/messages/${peerId}`);
  container.innerHTML = "";

  if (!msgs || !msgs.length) {
    const h = document.createElement("div");
    h.className = "contact-loading";
    h.textContent = "No messages yet. Say hello!";
    container.appendChild(h);
    return;
  }

  messageStore = msgs;
  lastMessageId = Math.max(...msgs.map(m => m.id));

  let lastDate = null;
  msgs.forEach(msg => {
    const dl = formatDate(msg.sent_at);
    if (dl !== lastDate) { appendDateSeparator(dl); lastDate = dl; }
    appendMessage(msg);
  });
  scrollToBottom();
}

// ─── Poll for new messages (auto-refresh) ────────────────────────────────────
async function pollNewMessages(peerId) {
  if (!currentPeer || currentPeer.user_id !== peerId) return;

  const msgs = await apiFetch(`/api/chat/messages/${peerId}/poll?after=${lastMessageId}`);
  if (!msgs || !msgs.length) return;

  msgs.forEach(msg => {
    // Skip if already rendered (e.g., sent via WebSocket)
    if (document.querySelector(`[data-msg-id="${msg.id}"]`)) return;

    messageStore.push(msg);
    if (msg.id > lastMessageId) lastMessageId = msg.id;

    // Check if we need a new date separator
    const container = $("messages-container");
    const lastSep   = container.querySelector(".day-separator:last-of-type");
    const newDate   = formatDate(msg.sent_at);
    if (!lastSep || lastSep.textContent !== newDate) {
      appendDateSeparator(newDate);
    }
    appendMessage(msg);
  });
  scrollToBottom();
}

// ─── Decrypt Toggle ───────────────────────────────────────────────────────────
function toggleDecryption() {
  showEncrypted = !showEncrypted;
  const btn   = $("decrypt-toggle");
  const label = $("dt-label");
  const icon  = btn.querySelector(".dt-icon");

  if (showEncrypted) {
    icon.textContent  = "🔓";
    label.textContent = "Encrypted";
    btn.classList.add("toggled");
  } else {
    icon.textContent  = "🔒";
    label.textContent = "Decrypted";
    btn.classList.remove("toggled");
  }

  // Re-render all visible message bubbles
  document.querySelectorAll(".message[data-msg-id]").forEach(el => {
    const id  = Number(el.dataset.msgId);
    const msg = messageStore.find(m => m.id === id);
    if (!msg) return;

    const bubble = el.querySelector(".bubble");
    if (showEncrypted) {
      bubble.textContent = msg.encrypted_raw || "[no ciphertext]";
      bubble.classList.add("encrypted-view");
    } else {
      bubble.textContent = msg.content || "[decryption error]";
      bubble.classList.remove("encrypted-view");
    }
  });
}

// ─── Render helpers ───────────────────────────────────────────────────────────
function appendDateSeparator(label) {
  const div = document.createElement("div");
  div.className = "day-separator";
  div.textContent = label;
  $("messages-container").appendChild(div);
}

function appendMessage(msg) {
  const isMine = msg.sender_id === ME_ID || msg.is_mine;

  const wrap = document.createElement("div");
  wrap.className  = `message ${isMine ? "mine" : "theirs"}`;
  wrap.dataset.msgId = msg.id;

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  if (showEncrypted) {
    bubble.textContent = msg.encrypted_raw || "[no ciphertext]";
    bubble.classList.add("encrypted-view");
  } else {
    bubble.textContent = msg.content !== null ? msg.content : "[decryption error]";
    if (msg.content === null) bubble.classList.add("decrypt-error");
  }

  const meta = document.createElement("div");
  meta.className = "msg-meta";

  if (!isMine) {
    const nm = document.createElement("span");
    nm.textContent = msg.sender_name + " · ";
    meta.appendChild(nm);
  }

  const ts = document.createElement("span");
  ts.textContent = formatTime(msg.sent_at);
  meta.appendChild(ts);

  if (isMine && msg.is_read) {
    const rd = document.createElement("span");
    rd.className   = "msg-read";
    rd.textContent = " ✓✓";
    meta.appendChild(rd);
  }

  wrap.appendChild(bubble);
  wrap.appendChild(meta);
  $("messages-container").appendChild(wrap);
}

function scrollToBottom() {
  const c = $("messages-container");
  c.scrollTop = c.scrollHeight;
}

// ─── Send ─────────────────────────────────────────────────────────────────────
async function sendMessage() {
  if (!currentPeer) return;
  const input   = $("msg-input");
  const content = input.value.trim();
  if (!content) return;

  input.value        = "";
  input.style.height = "";
  updateCharCount("");

  if (socket?.connected) {
    socket.emit("send_msg", { peer_id: currentPeer.user_id, content });
  } else {
    const result = await apiFetch("/api/chat/messages", {
      method: "POST",
      body:   JSON.stringify({ recipient_id: currentPeer.user_id, content }),
    });
    // Optimistically render with the returned encrypted_raw
    if (result) {
      const optimistic = {
        id:            result.message_id,
        sender_id:     ME_ID,
        sender_name:   ME_NAME,
        content:       content,
        encrypted_raw: result.encrypted_raw,
        sent_at:       result.sent_at || new Date().toISOString(),
        is_read:       false,
        is_mine:       true,
      };
      messageStore.push(optimistic);
      if (optimistic.id > lastMessageId) lastMessageId = optimistic.id;
      appendMessage(optimistic);
      scrollToBottom();
    }
  }
}

function handleMsgKey(e) {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function autoResize(el) {
  el.style.height = "auto";
  el.style.height = Math.min(el.scrollHeight, 140) + "px";
  updateCharCount(el.value);
}

function updateCharCount(val) {
  const c = $("char-count");
  c.textContent = `${val.length}/4096`;
  c.className   = val.length > 3500 ? "char-count warn" : "char-count";
}

// ─── WebSocket ────────────────────────────────────────────────────────────────
function initSocket() {
  socket = io({ auth: { token: TOKEN } });

  socket.on("connect", () => {
    if (currentPeer) socket.emit("join_room", { peer_id: currentPeer.user_id });
  });

  socket.on("new_message", msg => {
    const relevant =
      msg.sender_id === currentPeer?.user_id ||
      (msg.sender_id === ME_ID && msg.recipient_id === currentPeer?.user_id);

    if (!relevant) return;
    if (document.querySelector(`[data-msg-id="${msg.id}"]`)) return;

    messageStore.push(msg);
    if (msg.id > lastMessageId) lastMessageId = msg.id;
    appendMessage(msg);
    scrollToBottom();
  });
}

// ─── Init ─────────────────────────────────────────────────────────────────────
(function init() {
  setText("me-name", ME_NAME);
  $("me-avatar").textContent = avatarChar(ME_NAME);

  loadContacts();
  // Refresh contacts list every 10s for online status
  contactInterval = setInterval(loadContacts, 10000);

  initSocket();
})();