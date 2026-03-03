/**
 * group.js — SecureChat Group Chat Client
 * Admin-controlled rooms. E2EE: ECDH P-256 + AES-256-GCM per-session key.
 * NOTE: In group E2EE, each member derives a shared key with the server acting
 * as relay. For true group E2EE, we use a shared symmetric key distributed by
 * the admin encrypted to each member — implemented here as admin-broadcast AES key.
 */
"use strict";

// ── Crypto ──────────────────────────────────────────────────────────────────
const Crypto = {
  async genKeyPair() {
    return crypto.subtle.generateKey({ name:"ECDH", namedCurve:"P-256" }, true, ["deriveKey"]);
  },
  async exportPub(pub) {
    const r = await crypto.subtle.exportKey("raw", pub);
    return btoa(String.fromCharCode(...new Uint8Array(r)));
  },
  async importPub(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey("raw", raw, { name:"ECDH", namedCurve:"P-256" }, false, []);
  },
  async deriveKey(priv, pub) {
    return crypto.subtle.deriveKey({ name:"ECDH", public:pub }, priv, { name:"AES-GCM", length:256 }, true, ["encrypt","decrypt"]);
  },
  async genAESKey() {
    return crypto.subtle.generateKey({ name:"AES-GCM", length:256 }, true, ["encrypt","decrypt"]);
  },
  async exportAES(key) {
    const r = await crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(r)));
  },
  async importAES(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey("raw", raw, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]);
  },
  async encrypt(key, text) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, new TextEncoder().encode(text));
    return { payload: btoa(String.fromCharCode(...new Uint8Array(enc))), iv: btoa(String.fromCharCode(...iv)) };
  },
  async decrypt(key, p, iv) {
    const ct  = Uint8Array.from(atob(p),  c => c.charCodeAt(0));
    const ivb = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
    return new TextDecoder().decode(await crypto.subtle.decrypt({ name:"AES-GCM", iv:ivb }, key, ct));
  },
  // Wrap AES key with ECDH-derived key (for sending group key to a member)
  async wrapKey(aesKey, wrapKey) {
    const raw = await crypto.subtle.exportKey("raw", aesKey);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, wrapKey, raw);
    return { wrapped: btoa(String.fromCharCode(...new Uint8Array(enc))), iv: btoa(String.fromCharCode(...iv)) };
  },
  async unwrapKey(wrappedB64, ivB64, unwrapKey) {
    const wrapped = Uint8Array.from(atob(wrappedB64), c => c.charCodeAt(0));
    const iv      = Uint8Array.from(atob(ivB64),      c => c.charCodeAt(0));
    const raw     = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, unwrapKey, wrapped);
    return crypto.subtle.importKey("raw", raw, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]);
  },
  destroy() { S.myKP = null; S.groupAES = null; S.memberKeys = {}; S.encReady = false; },
};

// ── State ────────────────────────────────────────────────────────────────────
const S = {
  ws: null, username: null, action: null,
  groupId: null, groupName: null, isAdmin: false,
  myKP: null,          // ECDH key pair
  groupAES: null,      // shared AES-GCM key for group messages
  memberKeys: {},      // connId -> derived ECDH key (for key wrapping)
  encReady: false,
  typingTimer: null, isTyping: false,
  connId: null,
};

// ── Helpers ──────────────────────────────────────────────────────────────────
const NAME_COLORS = ['#4F46E5','#0891B2','#059669','#D97706','#DC2626','#7C3AED','#DB2777','#0369A1'];
function nameColor(n) { let h=0; for(let i=0;i<n.length;i++) h=(h*31+n.charCodeAt(i))>>>0; return NAME_COLORS[h%NAME_COLORS.length]; }
function el(id) { return document.getElementById(id); }

function setStatus(v, t) {
  const b=el('statusBadge'), l=el('statusLed'), tx=el('statusText');
  if (!b) return;
  b.className=`status-badge ${v}`;
  l.className=`status-led${v==='searching'?' pulse':''}`;
  tx.textContent=t;
}

function showWaiting(show) {
  el('waitingPane').classList.toggle('hidden', !show);
  el('messagesPane').classList.toggle('hidden', show);
}

function enableInput(on) {
  el('chatInput').disabled = !on;
  el('sendBtn').disabled   = !on;
}

function addMsg(text, type, sender, ts) {
  const pane = el('messagesPane');
  const wrap = document.createElement('div');
  wrap.className = `msg ${type}`;
  const bub = document.createElement('div');
  bub.className = 'msg-bubble';
  bub.textContent = text;
  wrap.appendChild(bub);
  if (type !== 'sys') {
    const meta = document.createElement('div');
    meta.className = 'msg-meta';
    const t = ts || new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
    meta.textContent = type==='out' ? `You · ${t}` : `${sender} · ${t}`;
    wrap.appendChild(meta);
  }
  pane.appendChild(wrap);
  pane.scrollTop = pane.scrollHeight;
}

function showTyping(show, from) {
  el('typingRow').classList.toggle('show', show);
  if (from) el('typingName').textContent = `${from} is typing...`;
}

function renderMembers(members) {
  const list = el('memberList');
  list.innerHTML = '';
  el('memberCount').textContent = members.length;
  el('sideGroupMeta').textContent = `${members.length} / 8 members`;
  members.forEach(m => {
    const row = document.createElement('div');
    row.className = 'member-row';
    const av  = document.createElement('div');
    av.className = 'member-av';
    av.textContent = m.username.charAt(0).toUpperCase();
    av.style.background = nameColor(m.username);
    const nm  = document.createElement('span');
    nm.className = 'member-name';
    nm.textContent = m.username;
    row.appendChild(av);
    row.appendChild(nm);
    if (m.isAdmin) {
      const tag = document.createElement('span');
      tag.className = 'admin-tag';
      tag.textContent = 'Admin';
      row.appendChild(tag);
    }
    // Kick button (admin only, not for self)
    if (S.isAdmin && !m.isAdmin) {
      const kb = document.createElement('button');
      kb.className = 'kick-btn';
      kb.title = 'Remove member';
      kb.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
      kb.addEventListener('click', () => {
        if (confirm(`Remove ${m.username} from the group?`)) {
          // We need connId — store it
          kb.dataset.username = m.username;
          // Send kick by username (admin knows connId via pendingList entries; for members we track separately)
          S.ws.send(JSON.stringify({ type:'kick_by_username', username: m.username }));
        }
      });
      row.appendChild(kb);
    }
    list.appendChild(row);
  });
}

function renderPending(pending) {
  const list = el('pendingList');
  const empty = el('emptyPending');
  list.querySelectorAll('.pending-row').forEach(e => e.remove());
  if (!pending || pending.length === 0) {
    empty.style.display = '';
    return;
  }
  empty.style.display = 'none';
  pending.forEach(p => {
    const row = document.createElement('div');
    row.className = 'pending-row';
    row.dataset.connId = p.connId;
    const av = document.createElement('div');
    av.className = 'pending-av';
    av.textContent = p.username.charAt(0).toUpperCase();
    av.style.background = nameColor(p.username);
    const nm = document.createElement('span');
    nm.className = 'pending-name';
    nm.textContent = p.username;
    const actions = document.createElement('div');
    actions.className = 'pending-actions';
    const ap = document.createElement('button');
    ap.className = 'pend-approve';
    ap.textContent = 'Approve';
    ap.addEventListener('click', () => {
      S.ws.send(JSON.stringify({ type:'approve_member', connId: p.connId }));
      row.remove();
      if (!list.querySelector('.pending-row')) empty.style.display = '';
    });
    const dn = document.createElement('button');
    dn.className = 'pend-deny';
    dn.textContent = 'Deny';
    dn.addEventListener('click', () => {
      S.ws.send(JSON.stringify({ type:'deny_member', connId: p.connId }));
      row.remove();
      if (!list.querySelector('.pending-row')) empty.style.display = '';
    });
    actions.appendChild(ap); actions.appendChild(dn);
    row.appendChild(av); row.appendChild(nm); row.appendChild(actions);
    list.appendChild(row);
  });
}

// ── WebSocket ────────────────────────────────────────────────────────────────
function connect() {
  const proto = location.protocol==='https:'?'wss':'ws';
  S.ws = new WebSocket(`${proto}://${location.host}/ws/group`);
  S.ws.onopen    = () => init();
  S.ws.onmessage = e  => handleMsg(e);
  S.ws.onclose   = () => { setStatus('gone','Disconnected'); enableInput(false); };
  S.ws.onerror   = () => addMsg('Connection error.','sys');
}

function init() {
  setStatus('searching','Connecting');
  S.ws.send(JSON.stringify({
    type: 'init', username: S.username,
    action: S.action,
    groupName: sessionStorage.getItem('sc_grpName') || '',
    groupId:   sessionStorage.getItem('sc_grpId')   || '',
  }));
}

async function handleMsg(e) {
  let d; try { d = JSON.parse(e.data); } catch { return; }

  switch (d.type) {
    case 'connected':
      S.connId = d.connectionId;
      setStatus('searching', S.action==='create' ? 'Creating group...' : 'Requesting to join...');
      break;

    case 'group_created':
      S.groupId   = d.groupId;
      S.groupName = d.groupName;
      S.isAdmin   = true;
      // Generate group AES key (admin owns it)
      S.groupAES  = await Crypto.genAESKey();
      S.encReady  = true;
      el('sideGroupName').textContent = d.groupName;
      el('sideGroupMeta').textContent = `1 / ${d.maxSize} members`;
      el('groupIdText').textContent   = d.groupId;
      el('groupIdPill').classList.remove('hidden');
      el('adminPanel').classList.remove('hidden');
      setStatus('live', 'Encrypted · Admin');
      showWaiting(false);
      enableInput(true);
      renderMembers(d.members);
      renderPending([]);
      addMsg(`Group "${d.groupName}" created. Share the Group ID: ${d.groupId}`, 'sys');
      addMsg('As admin you can approve/deny requests and remove members from the sidebar.', 'sys');
      break;

    case 'join_requested':
      S.groupId = d.groupId;
      el('waitTitle').textContent = 'Waiting for admin approval';
      el('waitSub').textContent   = 'The admin will approve your request shortly';
      el('waitGroupId').textContent = `Group ID: ${d.groupId}`;
      el('waitGroupId').classList.remove('hidden');
      setStatus('searching', 'Awaiting approval');
      break;

    case 'approved':
      S.groupId   = d.groupId;
      S.groupName = d.groupName;
      S.isAdmin   = false;
      // Generate our ECDH key pair and send public key to admin for key exchange
      S.myKP = await Crypto.genKeyPair();
      const pub = await Crypto.exportPub(S.myKP.publicKey);
      S.ws.send(JSON.stringify({ type:'member_pub_key', publicKey: pub }));
      el('sideGroupName').textContent = d.groupName;
      el('groupIdText').textContent   = d.groupId;
      el('groupIdPill').classList.remove('hidden');
      setStatus('securing', 'Securing...');
      showWaiting(false);
      renderMembers(d.members);
      addMsg(`Joined "${d.groupName}". Establishing encrypted channel...`, 'sys');
      break;

    case 'member_pub_key':
      // Admin receives a member's public key → derive ECDH shared key → wrap group AES key → send back
      if (S.isAdmin && S.groupAES) {
        try {
          if (!S.myKP) { S.myKP = await Crypto.genKeyPair(); }
          const theirPub  = await Crypto.importPub(d.publicKey);
          const sharedKey = await Crypto.deriveKey(S.myKP.privateKey, theirPub);
          const { wrapped, iv } = await Crypto.wrapKey(S.groupAES, sharedKey);
          const myPub = await Crypto.exportPub(S.myKP.publicKey);
          S.ws.send(JSON.stringify({
            type:       'group_key_for_member',
            targetId:   d.fromId,
            wrappedKey: wrapped,
            keyIv:      iv,
            adminPub:   myPub,
          }));
        } catch(err) { console.error('Key wrap failed', err); }
      }
      break;

    case 'group_key_for_member':
      // Member receives wrapped group AES key from admin
      if (!S.isAdmin && S.myKP) {
        try {
          const adminPub  = await Crypto.importPub(d.adminPub);
          const sharedKey = await Crypto.deriveKey(S.myKP.privateKey, adminPub);
          S.groupAES  = await Crypto.unwrapKey(d.wrappedKey, d.keyIv, sharedKey);
          S.encReady  = true;
          setStatus('live', 'Encrypted');
          enableInput(true);
          addMsg('Secure channel established. Messages are end-to-end encrypted.', 'sys');
        } catch(err) { console.error('Key unwrap failed', err); addMsg('Encryption failed. Please rejoin.','sys'); }
      }
      break;

    case 'join_request':
      if (S.isAdmin) renderPending(d.pending);
      break;

    case 'admin_update':
      renderMembers(d.members);
      renderPending(d.pending);
      break;

    case 'member_joined':
      renderMembers(d.members);
      addMsg(`${d.username} joined the group.`, 'sys');
      // Admin sends group key to new member
      if (S.isAdmin) {
        // Wait for their pub key via member_pub_key event (handled above)
      }
      break;

    case 'member_left':
      renderMembers(d.members);
      addMsg(`${d.username} left the group.`, 'sys');
      break;

    case 'group_message':
      if (!S.groupAES) return;
      try {
        const plain = await Crypto.decrypt(S.groupAES, d.payload, d.iv);
        showTyping(false);
        addMsg(plain, 'in', d.from, d.timestamp);
      } catch { addMsg('A message could not be decrypted.', 'sys'); }
      break;

    case 'group_typing':
      showTyping(true, d.from);
      clearTimeout(S.typingTimer);
      S.typingTimer = setTimeout(() => showTyping(false), 2500);
      break;

    case 'kicked':
      Crypto.destroy();
      enableInput(false);
      setStatus('gone', 'Removed');
      addMsg(d.message, 'sys');
      showWaiting(true);
      el('waitTitle').textContent = 'You were removed';
      el('waitSub').textContent   = 'The admin removed you from this group.';
      break;

    case 'denied':
      setStatus('gone', 'Denied');
      showWaiting(true);
      el('waitTitle').textContent = 'Request declined';
      el('waitSub').textContent   = 'The admin did not approve your join request.';
      break;

    case 'group_dissolved':
      Crypto.destroy();
      enableInput(false);
      setStatus('gone', 'Closed');
      showWaiting(true);
      el('waitTitle').textContent = 'Group dissolved';
      el('waitSub').textContent   = d.message;
      addMsg(d.message, 'sys');
      break;

    case 'error':
      addMsg(`Error: ${d.message}`, 'sys');
      break;
  }
}

// ── Send message ─────────────────────────────────────────────────────────────
async function sendMessage(text) {
  if (!text.trim() || !S.ws || S.ws.readyState !== WebSocket.OPEN) return;
  if (!S.encReady || !S.groupAES) { addMsg('Encryption not ready.', 'sys'); return; }
  try {
    const { payload, iv } = await Crypto.encrypt(S.groupAES, text.trim());
    const ts = new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
    S.ws.send(JSON.stringify({ type:'group_message', payload, iv, timestamp: ts }));
    addMsg(text.trim(), 'out', '', ts);
  } catch { addMsg('Failed to send.', 'sys'); }
}

function sendTyping() {
  if (!S.encReady || !S.ws || S.ws.readyState !== WebSocket.OPEN) return;
  if (!S.isTyping) {
    S.isTyping = true;
    S.ws.send(JSON.stringify({ type:'group_typing' }));
    setTimeout(() => { S.isTyping = false; }, 2000);
  }
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const username = sessionStorage.getItem('sc_username');
  const action   = sessionStorage.getItem('sc_grpAction');
  if (!username || !action) { window.location.href='/'; return; }

  S.username = username;
  S.action   = action;

  // Set your chip
  el('youName').textContent  = username;
  const av = el('youAvatar');
  av.textContent  = username.charAt(0).toUpperCase();
  av.style.background = nameColor(username);

  setStatus('idle', 'Connecting');

  connect();

  // Copy group ID
  el('copyGroupId').addEventListener('click', () => {
    navigator.clipboard.writeText(S.groupId || '').then(() => {
      el('copyGroupId').style.color = '#059669';
      setTimeout(() => { el('copyGroupId').style.color = ''; }, 1500);
    });
  });

  // Send
  el('sendBtn').addEventListener('click', () => {
    const v = el('chatInput').value;
    if (v.trim()) { sendMessage(v); el('chatInput').value=''; el('chatInput').style.height='auto'; }
  });

  el('chatInput').addEventListener('keydown', e => {
    if (e.key==='Enter' && !e.shiftKey) {
      e.preventDefault();
      const v = el('chatInput').value;
      if (v.trim()) { sendMessage(v); el('chatInput').value=''; el('chatInput').style.height='auto'; }
    }
  });

  el('chatInput').addEventListener('input', () => {
    el('chatInput').style.height = 'auto';
    el('chatInput').style.height = Math.min(el('chatInput').scrollHeight,120)+'px';
    sendTyping();
  });

  el('dissolveBtn').addEventListener('click', () => {
    if (confirm('Dissolve this group? All members will be disconnected.')) {
      S.ws.send(JSON.stringify({ type:'dissolve_group' }));
    }
  });

  el('leaveBtn').addEventListener('click', () => {
    if (confirm('Leave this group?')) {
      Crypto.destroy();
      if (S.ws) { S.ws.close(); S.ws=null; }
      window.location.href='/';
    }
  });
});