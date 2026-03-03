/**
 * group.js - SecureChat Group Chat
 * E2EE: Admin generates AES-256-GCM group key, wraps it per-member via ECDH.
 * Server only relays encrypted blobs - never sees plaintext.
 * Written with Promise chains (no async/await in if-else) to avoid JS syntax bugs.
 */
(function () {
  "use strict";

  // ── Crypto helpers ────────────────────────────────────────────────────────
  var C = {
    genECDH: function () {
      return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
    },
    exportPub: function (k) {
      return crypto.subtle.exportKey("raw", k).then(function (b) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(b)));
      });
    },
    importPub: function (b64) {
      var buf = Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); });
      return crypto.subtle.importKey("raw", buf, { name: "ECDH", namedCurve: "P-256" }, false, []);
    },
    deriveAES: function (priv, pub) {
      return crypto.subtle.deriveKey(
        { name: "ECDH", public: pub }, priv,
        { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
      );
    },
    genAES: function () {
      return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    },
    exportAESraw: function (k) {
      return crypto.subtle.exportKey("raw", k).then(function (b) { return new Uint8Array(b); });
    },
    importAESraw: function (buf) {
      return crypto.subtle.importKey("raw", buf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    },
    encrypt: function (k, data) {
      var iv = crypto.getRandomValues(new Uint8Array(12));
      return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, k, data).then(function (e) {
        return {
          ct: btoa(String.fromCharCode.apply(null, new Uint8Array(e))),
          iv: btoa(String.fromCharCode.apply(null, iv))
        };
      });
    },
    decrypt: function (k, ctB64, ivB64) {
      var ct = Uint8Array.from(atob(ctB64), function (c) { return c.charCodeAt(0); });
      var iv = Uint8Array.from(atob(ivB64), function (c) { return c.charCodeAt(0); });
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, k, ct);
    },
    encryptText: function (k, text) {
      return C.encrypt(k, new TextEncoder().encode(text));
    },
    decryptText: function (k, ctB64, ivB64) {
      return C.decrypt(k, ctB64, ivB64).then(function (buf) {
        return new TextDecoder().decode(buf);
      });
    }
  };

  // ── State ──────────────────────────────────────────────────────────────────
  var S = {
    ws: null, username: null, action: null,
    connId: null, groupId: null, groupName: null, isAdmin: false,
    ecdhKP: null, groupKey: null, ready: false,
    typingTimer: null, isTyping: false
  };

  // ── DOM helpers ───────────────────────────────────────────────────────────
  function g(id) { return document.getElementById(id); }
  var COLORS = ['#4F46E5', '#0891B2', '#059669', '#D97706', '#DC2626', '#7C3AED', '#DB2777', '#0369A1'];
  function nameColor(n) {
    var h = 0;
    for (var i = 0; i < n.length; i++) h = (h * 31 + n.charCodeAt(i)) >>> 0;
    return COLORS[h % COLORS.length];
  }
  function setStatus(cls, text) {
    var b = g('statusBadge'), l = g('statusLed'), t = g('statusText');
    if (!b) return;
    b.className = 'status-badge ' + cls;
    l.className = 'status-led' + (cls === 'searching' ? ' pulse' : '');
    t.textContent = text;
  }
  function showWaiting(show) {
    g('waitingPane').classList.toggle('hidden', !show);
    g('messagesPane').classList.toggle('hidden', show);
  }
  function enableChat(on) {
    g('chatInput').disabled = !on;
    g('sendBtn').disabled = !on;
    if (on) setTimeout(function () { g('chatInput').focus(); }, 50);
  }
  function wsSend(obj) {
    if (S.ws && S.ws.readyState === WebSocket.OPEN)
      S.ws.send(JSON.stringify(obj));
  }
  function addMsg(text, type, sender, ts) {
    var pane = g('messagesPane');
    var wrap = document.createElement('div'); wrap.className = 'msg ' + type;
    var bub = document.createElement('div'); bub.className = 'msg-bubble'; bub.textContent = text;
    wrap.appendChild(bub);
    if (type !== 'sys') {
      var meta = document.createElement('div'); meta.className = 'msg-meta';
      var t = ts || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      meta.textContent = (type === 'out') ? 'You \u00b7 ' + t : sender + ' \u00b7 ' + t;
      wrap.appendChild(meta);
    }
    pane.appendChild(wrap);
    pane.scrollTop = pane.scrollHeight;
  }
  function showTyping(show, from) {
    g('typingRow').classList.toggle('show', show);
    if (from) g('typingName').textContent = from + ' is typing...';
  }
  function renderMembers(members) {
    var list = g('memberList');
    list.innerHTML = '';
    g('memberCount').textContent = members.length;
    g('sideGroupMeta').textContent = members.length + ' / 8 members';
    for (var i = 0; i < members.length; i++) {
      (function (m) {
        var row = document.createElement('div'); row.className = 'member-row';
        var av = document.createElement('div'); av.className = 'member-av';
        av.textContent = m.username[0].toUpperCase(); av.style.background = nameColor(m.username);
        var nm = document.createElement('span'); nm.className = 'member-name'; nm.textContent = m.username;
        row.appendChild(av); row.appendChild(nm);
        if (m.isAdmin) {
          var tag = document.createElement('span'); tag.className = 'admin-tag'; tag.textContent = 'Admin';
          row.appendChild(tag);
        }
        if (S.isAdmin && !m.isAdmin) {
          var kb = document.createElement('button'); kb.className = 'kick-btn'; kb.title = 'Remove';
          kb.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
          kb.onclick = (function (un) {
            return function () { if (confirm('Remove ' + un + '?')) wsSend({ type: 'kick_by_username', username: un }); };
          })(m.username);
          row.appendChild(kb);
        }
        list.appendChild(row);
      })(members[i]);
    }
  }
  function renderPending(pending) {
    var list = g('pendingList'), empty = g('emptyPending');
    var rows = list.querySelectorAll('.pending-row');
    for (var i = 0; i < rows.length; i++) rows[i].remove();
    if (!pending || !pending.length) { empty.style.display = ''; return; }
    empty.style.display = 'none';
    for (var j = 0; j < pending.length; j++) {
      (function (p) {
        var row = document.createElement('div'); row.className = 'pending-row';
        var av = document.createElement('div'); av.className = 'pending-av';
        av.textContent = p.username[0].toUpperCase(); av.style.background = nameColor(p.username);
        var nm = document.createElement('span'); nm.className = 'pending-name'; nm.textContent = p.username;
        var actions = document.createElement('div'); actions.className = 'pending-actions';
        var ap = document.createElement('button'); ap.className = 'pend-approve'; ap.textContent = 'Approve';
        ap.onclick = function () {
          wsSend({ type: 'approve_member', connId: p.connId });
          row.remove();
          if (!list.querySelector('.pending-row')) empty.style.display = '';
        };
        var dn = document.createElement('button'); dn.className = 'pend-deny'; dn.textContent = 'Deny';
        dn.onclick = function () {
          wsSend({ type: 'deny_member', connId: p.connId });
          row.remove();
          if (!list.querySelector('.pending-row')) empty.style.display = '';
        };
        actions.appendChild(ap); actions.appendChild(dn);
        row.appendChild(av); row.appendChild(nm); row.appendChild(actions);
        list.appendChild(row);
      })(pending[j]);
    }
  }

  // ── WebSocket ─────────────────────────────────────────────────────────────
  function connect() {
    var proto = location.protocol === 'https:' ? 'wss' : 'ws';
    var url = proto + '://' + location.host + '/ws/group';
    console.log('[WS] connecting to', url);
    try { S.ws = new WebSocket(url); } catch (e) {
      setStatus('gone', 'Connection failed'); return;
    }
    S.ws.onopen = function () {
      console.log('[WS] open — action=' + S.action);
      setStatus('searching', S.action === 'create' ? 'Creating group...' : 'Requesting to join...');
      wsSend({
        type: 'init',
        username: S.username,
        action: S.action,
        groupName: sessionStorage.getItem('sc_grpName') || '',
        groupId: sessionStorage.getItem('sc_grpId') || ''
      });
    };
    S.ws.onmessage = function (e) {
      handleMsg(e).catch(function (err) { console.error('[WS] error:', err); });
    };
    S.ws.onclose = function (e) {
      console.log('[WS] closed', e.code);
      setStatus('gone', 'Disconnected'); enableChat(false);
    };
    S.ws.onerror = function (e) {
      console.error('[WS] onerror', e);
      setStatus('gone', 'Connection error');
    };
  }

  // ── Message handler ───────────────────────────────────────────────────────
  function handleMsg(e) {
    return Promise.resolve().then(function () {
      var d;
      try { d = JSON.parse(e.data); } catch (x) { return; }
      console.log('[RX]', d.type, d);

      if (d.type === 'connected') {
        S.connId = d.connectionId;
        setStatus('searching', S.action === 'create' ? 'Creating group...' : 'Requesting to join...');
        return;
      }

      if (d.type === 'group_created') {
        S.groupId = d.groupId; S.groupName = d.groupName; S.isAdmin = true;
        return C.genAES().then(function (aesKey) {
          S.groupKey = aesKey;
          return C.genECDH();
        }).then(function (kp) {
          S.ecdhKP = kp;
          S.ready = true;
          g('sideGroupName').textContent = d.groupName;
          g('sideGroupMeta').textContent = '1 / ' + d.maxSize + ' members';
          g('groupIdText').textContent = d.groupId;
          g('groupIdPill').classList.remove('hidden');
          g('adminPanel').classList.remove('hidden');
          setStatus('live', 'Encrypted \u00b7 Admin');
          showWaiting(false);
          enableChat(true);
          renderMembers(d.members);
          renderPending([]);
          addMsg('Group "' + d.groupName + '" created. Share ID: ' + d.groupId, 'sys');
          addMsg('Approve join requests from the left sidebar.', 'sys');
        });
      }

      if (d.type === 'join_requested') {
        S.groupId = d.groupId;
        g('waitTitle').textContent = 'Waiting for admin approval';
        g('waitSub').textContent = 'The admin will see your request shortly...';
        g('waitGroupId').textContent = 'Group ID: ' + d.groupId;
        g('waitGroupId').classList.remove('hidden');
        setStatus('searching', 'Awaiting approval...');
        return;
      }

      if (d.type === 'approved') {
        S.groupId = d.groupId; S.groupName = d.groupName; S.isAdmin = false; S.ready = false;
        return C.genECDH().then(function (kp) {
          S.ecdhKP = kp;
          return C.exportPub(kp.publicKey);
        }).then(function (pubB64) {
          wsSend({ type: 'member_pub_key', publicKey: pubB64 });
          g('sideGroupName').textContent = d.groupName;
          g('groupIdText').textContent = d.groupId;
          g('groupIdPill').classList.remove('hidden');
          setStatus('securing', 'Securing channel...');
          showWaiting(false);
          renderMembers(d.members);
          addMsg('Joined "' + d.groupName + '". Exchanging encryption keys...', 'sys');
        });
      }

      // Admin receives member's ECDH public key → wrap group AES key → send back
      if (d.type === 'member_pub_key') {
        if (!S.isAdmin || !S.groupKey || !S.ecdhKP) {
          console.error('[KEY] admin not ready'); return;
        }
        console.log('[KEY] wrapping for', d.username, 'fromId=', d.fromId);
        var savedFromId = d.fromId;
        return C.importPub(d.publicKey).then(function (memberPub) {
          return C.deriveAES(S.ecdhKP.privateKey, memberPub);
        }).then(function (sharedKey) {
          return C.exportAESraw(S.groupKey).then(function (rawKey) {
            return C.encrypt(sharedKey, rawKey);
          });
        }).then(function (enc) {
          return C.exportPub(S.ecdhKP.publicKey).then(function (adminPubB64) {
            wsSend({
              type: 'group_key_for_member',
              targetId: savedFromId,
              wrappedKey: enc.ct,
              keyIv: enc.iv,
              adminPub: adminPubB64
            });
            console.log('[KEY] sent wrapped key to', savedFromId);
          });
        }).catch(function (err) { console.error('[KEY] wrap failed:', err); });
      }

      // Member receives wrapped group AES key from admin → unwrap → chat enabled
      if (d.type === 'group_key_for_member') {
        if (S.isAdmin || !S.ecdhKP) { console.error('[KEY] unexpected'); return; }
        console.log('[KEY] unwrapping group key...');
        return C.importPub(d.adminPub).then(function (adminPub) {
          return C.deriveAES(S.ecdhKP.privateKey, adminPub);
        }).then(function (sharedKey) {
          return C.decrypt(sharedKey, d.wrappedKey, d.keyIv);
        }).then(function (rawBuf) {
          return C.importAESraw(new Uint8Array(rawBuf));
        }).then(function (aesKey) {
          S.groupKey = aesKey;
          S.ready = true;
          console.log('[KEY] group key ready!');
          setStatus('live', 'Encrypted');
          enableChat(true);
          addMsg('Secure channel ready. Messages are end-to-end encrypted.', 'sys');
        }).catch(function (err) {
          console.error('[KEY] unwrap failed:', err);
          addMsg('Encryption setup failed - please leave and rejoin.', 'sys');
        });
      }

      if (d.type === 'join_request')  { if (S.isAdmin) renderPending(d.pending); return; }
      if (d.type === 'admin_update')  { renderMembers(d.members); renderPending(d.pending); return; }
      if (d.type === 'member_joined') { renderMembers(d.members); addMsg(d.username + ' joined.', 'sys'); return; }
      if (d.type === 'member_left')   { renderMembers(d.members); addMsg(d.username + ' left.', 'sys'); return; }

      if (d.type === 'group_message') {
        if (!S.ready || !S.groupKey) { addMsg('(Message received - encryption setting up)', 'sys'); return; }
        return C.decryptText(S.groupKey, d.payload, d.iv).then(function (plain) {
          showTyping(false); addMsg(plain, 'in', d.from, d.timestamp);
        }).catch(function (err) { console.error('[DECRYPT]', err); addMsg('Could not decrypt.', 'sys'); });
      }

      if (d.type === 'group_typing') {
        showTyping(true, d.from);
        clearTimeout(S.typingTimer);
        S.typingTimer = setTimeout(function () { showTyping(false); }, 2500);
        return;
      }

      if (d.type === 'kicked') {
        S.ready = false; S.groupKey = null; S.ecdhKP = null;
        enableChat(false); setStatus('gone', 'Removed'); showWaiting(true);
        g('waitTitle').textContent = 'You were removed';
        g('waitSub').textContent = 'The admin removed you from this group.';
        addMsg(d.message, 'sys'); return;
      }

      if (d.type === 'denied') {
        setStatus('gone', 'Denied'); showWaiting(true);
        g('waitTitle').textContent = 'Request declined';
        g('waitSub').textContent = 'The admin did not approve your request.';
        return;
      }

      if (d.type === 'group_dissolved') {
        S.ready = false; S.groupKey = null; S.ecdhKP = null;
        enableChat(false); setStatus('gone', 'Closed'); showWaiting(true);
        g('waitTitle').textContent = 'Group dissolved';
        g('waitSub').textContent = d.message;
        addMsg(d.message, 'sys'); return;
      }

      if (d.type === 'error') { addMsg('Error: ' + d.message, 'sys'); return; }

      console.warn('[WS] unhandled:', d.type);
    });
  }

  // ── Send ──────────────────────────────────────────────────────────────────
  function sendMessage(text) {
    text = text.trim();
    if (!text) return;
    if (!S.ready || !S.groupKey) { addMsg('Encryption not ready - please wait.', 'sys'); return; }
    var ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    C.encryptText(S.groupKey, text).then(function (enc) {
      wsSend({ type: 'group_message', payload: enc.ct, iv: enc.iv, timestamp: ts });
      addMsg(text, 'out', '', ts);
    }).catch(function (err) { console.error('[SEND]', err); addMsg('Failed to send.', 'sys'); });
  }

  function notifyTyping() {
    if (!S.ready) return;
    if (!S.isTyping) {
      S.isTyping = true;
      wsSend({ type: 'group_typing' });
      setTimeout(function () { S.isTyping = false; }, 2000);
    }
  }

  // ── Init ─────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    var username = sessionStorage.getItem('sc_username');
    var action = sessionStorage.getItem('sc_grpAction');
    console.log('[INIT] username=' + username + ' action=' + action);
    if (!username || !action) { location.href = '/'; return; }
    S.username = username; S.action = action;
    g('youName').textContent = username;
    var av = g('youAvatar');
    av.textContent = username[0].toUpperCase();
    av.style.background = nameColor(username);
    setStatus('idle', 'Connecting');
    connect();

    g('copyGroupId').onclick = function () {
      navigator.clipboard.writeText(S.groupId || '').then(function () {
        g('copyGroupId').style.color = '#059669';
        setTimeout(function () { g('copyGroupId').style.color = ''; }, 1500);
      }).catch(function () { });
    };

    g('sendBtn').onclick = function () {
      var v = g('chatInput').value;
      if (v.trim()) { sendMessage(v); g('chatInput').value = ''; g('chatInput').style.height = 'auto'; }
    };

    g('chatInput').addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        var v = g('chatInput').value;
        if (v.trim()) { sendMessage(v); g('chatInput').value = ''; g('chatInput').style.height = 'auto'; }
      }
    });

    g('chatInput').addEventListener('input', function () {
      g('chatInput').style.height = 'auto';
      g('chatInput').style.height = Math.min(g('chatInput').scrollHeight, 120) + 'px';
      notifyTyping();
    });

    g('dissolveBtn').onclick = function () {
      if (confirm('Dissolve group? All members will be disconnected.'))
        wsSend({ type: 'dissolve_group' });
    };

    g('leaveBtn').onclick = function () {
      if (confirm('Leave this group?')) {
        S.ready = false; S.groupKey = null; S.ecdhKP = null;
        if (S.ws) { S.ws.close(); S.ws = null; }
        location.href = '/';
      }
    };
  });

})();
