/**
 * app.js — SecureChat Client
 * Session-ID mode only. True E2EE: ECDH P-256 + AES-256-GCM.
 * Server never sees plaintext. Keys destroyed on disconnect.
 */
"use strict";

// ── Crypto ─────────────────────────────────────────────────────────────────
const Crypto = {
  async genKeyPair() {
    return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
  },
  async exportPub(pub) {
    const raw = await crypto.subtle.exportKey("raw", pub);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  },
  async importPub(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  },
  async deriveKey(priv, theirPub) {
    return crypto.subtle.deriveKey(
      { name: "ECDH", public: theirPub },
      priv,
      { name: "AES-GCM", length: 256 },
      false, ["encrypt", "decrypt"]
    );
  },
  async encrypt(key, text) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
    return {
      payload: btoa(String.fromCharCode(...new Uint8Array(enc))),
      iv:      btoa(String.fromCharCode(...iv)),
    };
  },
  async decrypt(key, p, iv) {
    const ct  = Uint8Array.from(atob(p),  c => c.charCodeAt(0));
    const ivb = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
    const pt  = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivb }, key, ct);
    return new TextDecoder().decode(pt);
  },
};

// ── State ───────────────────────────────────────────────────────────────────
const S = {
  ws: null, username: null, sessionId: null, partnerName: null,
  kp: null, aes: null, ready: false,
  isTyping: false, typingTimer: null,
};

function destroyKeys() {
  S.kp = null; S.aes = null; S.ready = false;
}

// ── UI helpers ──────────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }

function setStatus(variant, text) {
  const b = el('statusBadge'), l = el('statusLed'), t = el('statusText');
  if (!b) return;
  b.className = `status-badge ${variant}`;
  l.className = `status-led${variant === 'searching' ? ' pulse' : ''}`;
  t.textContent = text;
}

function showPartnerBar(show, name) {
  const bar = el('partnerBar'); if (!bar) return;
  bar.classList.toggle('show', show);
  if (name) {
    el('partnerLabel').textContent = name;
    el('partnerAv').textContent     = name.charAt(0).toUpperCase();
    el('partnerAv').style.background = nameColor(name);
  }
}

function showKeyAnim(show) {
  const ka = el('keyAnim'), ps = el('partnerSecure');
  if (ka) ka.classList.toggle('show', show);
  if (ps) ps.classList.toggle('show', !show && S.ready);
}

function showEncBadge(show) {
  const ps = el('partnerSecure'), ka = el('keyAnim');
  if (ps) ps.classList.toggle('show', show);
  if (ka) ka.classList.remove('show');
}

function showWaiting(show) {
  const wp = el('waitingPane'), mp = el('messagesPane');
  if (wp) wp.classList.toggle('hidden', !show);
  if (mp) mp.classList.toggle('hidden', show);
}

function enableInput(on) {
  const t = el('chatInput'), b = el('sendBtn');
  if (t) t.disabled = !on;
  if (b) b.disabled = !on;
}

function addMsg(text, type, sender, ts) {
  const pane = el('messagesPane'); if (!pane) return;
  const wrap = document.createElement('div');
  wrap.className = `msg ${type}`;
  const bub = document.createElement('div');
  bub.className = 'msg-bubble';
  bub.textContent = text;
  wrap.appendChild(bub);
  if (type !== 'sys') {
    const meta = document.createElement('div');
    meta.className = 'msg-meta';
    const t = ts || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    meta.textContent = type === 'out' ? `You · ${t}` : `${sender || S.partnerName || 'Partner'} · ${t}`;
    wrap.appendChild(meta);
  }
  pane.appendChild(wrap);
  pane.scrollTop = pane.scrollHeight;
}

function showTyping(show) {
  const row = el('typingRow'), nm = el('typingName');
  if (row) row.classList.toggle('show', show);
  if (nm && S.partnerName) nm.textContent = `${S.partnerName} is typing...`;
}

// Deterministic avatar color from name
const NAME_COLORS = ['#4F46E5','#0891B2','#059669','#D97706','#DC2626','#7C3AED','#DB2777','#0369A1'];
function nameColor(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return NAME_COLORS[h % NAME_COLORS.length];
}

// ── Chat ────────────────────────────────────────────────────────────────────
const Chat = {
  connect(username, sessionId) {
    S.username  = username;
    S.sessionId = sessionId;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    S.ws = new WebSocket(`${proto}://${location.host}/ws`);
    S.ws.onopen    = ()  => Chat._open();
    S.ws.onmessage = e   => Chat._msg(e);
    S.ws.onclose   = ()  => Chat._close();
    S.ws.onerror   = ()  => addMsg('Connection error — please refresh.', 'sys');
  },

  _open() {
    setStatus('searching', 'Connecting');
    S.ws.send(JSON.stringify({ type: 'init', username: S.username, mode: 'session', sessionId: S.sessionId }));
  },

  async _msg(e) {
    let d; try { d = JSON.parse(e.data); } catch { return; }

    switch (d.type) {
      case 'connected':
        setStatus('searching', 'Waiting');
        break;

      case 'waiting':
        showWaiting(true);
        setStatus('searching', 'Waiting for contact');
        break;

      case 'matched':
        S.partnerName = d.partnerName || 'Anonymous';
        showWaiting(false);
        showPartnerBar(true, S.partnerName);
        setStatus('securing', 'Securing');
        showKeyAnim(true);
        addMsg(`${S.partnerName} joined. Establishing encrypted channel...`, 'sys');
        try {
          S.kp = await Crypto.genKeyPair();
          const pub = await Crypto.exportPub(S.kp.publicKey);
          S.ws.send(JSON.stringify({ type: 'public_key', publicKey: pub }));
        } catch { addMsg('Encryption setup failed.', 'sys'); }
        break;

      case 'partner_public_key':
        try {
          const theirPub = await Crypto.importPub(d.publicKey);
          S.aes   = await Crypto.deriveKey(S.kp.privateKey, theirPub);
          S.ready = true;
          showKeyAnim(false);
          showEncBadge(true);
          setStatus('live', 'Encrypted');
          enableInput(true);
          addMsg('Secure channel active. Messages are end-to-end encrypted.', 'sys');
        } catch { addMsg('Key exchange failed. Please reconnect.', 'sys'); }
        break;

      case 'message':
        if (!S.aes) return;
        try {
          const plain = await Crypto.decrypt(S.aes, d.payload, d.iv);
          showTyping(false);
          addMsg(plain, 'in', d.from, d.timestamp);
        } catch { addMsg('A message could not be decrypted.', 'sys'); }
        break;

      case 'typing':
        showTyping(true);
        clearTimeout(S.typingTimer);
        S.typingTimer = setTimeout(() => showTyping(false), 2500);
        break;

      case 'partner_disconnected':
        destroyKeys();
        showTyping(false);
        showPartnerBar(false);
        showEncBadge(false);
        enableInput(false);
        setStatus('gone', 'Disconnected');
        addMsg('Your contact disconnected. This session has been erased.', 'sys');
        S.partnerName = null;
        break;

      case 'error':
        addMsg(`Error: ${d.message}`, 'sys');
        break;
    }
  },

  _close() {
    destroyKeys();
    setStatus('gone', 'Disconnected');
    enableInput(false);
  },

  async send(text) {
    if (!text.trim() || !S.ws || S.ws.readyState !== WebSocket.OPEN) return;
    if (!S.ready || !S.aes) { addMsg('Encryption not ready yet.', 'sys'); return; }
    try {
      const { payload, iv } = await Crypto.encrypt(S.aes, text.trim());
      const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      S.ws.send(JSON.stringify({ type: 'message', payload, iv, timestamp: ts }));
      addMsg(text.trim(), 'out', '', ts);
    } catch { addMsg('Failed to send.', 'sys'); }
  },

  sendTyping() {
    if (!S.ready || !S.ws || S.ws.readyState !== WebSocket.OPEN) return;
    if (!S.isTyping) {
      S.isTyping = true;
      S.ws.send(JSON.stringify({ type: 'typing' }));
      setTimeout(() => { S.isTyping = false; }, 2000);
    }
  },

  leave() {
    destroyKeys();
    if (S.ws) { S.ws.close(); S.ws = null; }
    window.location.href = '/';
  },
};

// ── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const chatInput = el('chatInput');
  if (!chatInput) return;

  const username  = sessionStorage.getItem('sc_username');
  const sessionId = sessionStorage.getItem('sc_sessionId');
  if (!username) { window.location.href = '/'; return; }

  // Fill UI identities
  const youName   = el('youName'),   youAv = el('youAvatar');
  const sidPill   = el('sessionPill'), sidText = el('sessionPillText');
  if (youName) youName.textContent   = username;
  if (youAv)   { youAv.textContent = username.charAt(0).toUpperCase(); youAv.style.background = nameColor(username); }
  if (sidText && sessionId) {
    sidText.textContent = sessionId;
    sidPill.classList.remove('hidden');
  }

  // Show session ID in waiting pane
  const wsi = el('waitSessionId');
  if (wsi && sessionId) { wsi.textContent = `Session: ${sessionId}`; wsi.classList.remove('hidden'); }

  showWaiting(true);
  enableInput(false);
  setStatus('idle', 'Connecting');

  Chat.connect(username, sessionId);

  // Send
  el('sendBtn').addEventListener('click', () => {
    const v = chatInput.value;
    if (v.trim()) { Chat.send(v); chatInput.value = ''; chatInput.style.height = 'auto'; }
  });

  chatInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const v = chatInput.value;
      if (v.trim()) { Chat.send(v); chatInput.value = ''; chatInput.style.height = 'auto'; }
    }
  });

  chatInput.addEventListener('input', () => {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 120) + 'px';
    Chat.sendTyping();
  });

  el('leaveBtn').addEventListener('click', () => {
    if (confirm('Leave this session?')) Chat.leave();
  });
});