/**
 * group.js — SecureChat Group Chat Client v2
 * Bulletproof group key exchange:
 * 1. Admin creates group → AES-256-GCM group key + ECDH key pair
 * 2. Member approved → member generates ECDH KP → sends pubkey to admin
 * 3. Admin derives ECDH shared secret → encrypts group key → sends to member
 * 4. Member derives same shared secret → decrypts group key → chat enabled
 */
"use strict";

const C = {
  genECDH: () => crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveKey"]),
  exportPub: async (k) => { const b=await crypto.subtle.exportKey("raw",k); return btoa(String.fromCharCode(...new Uint8Array(b))); },
  importPub: (b64) => { const b=Uint8Array.from(atob(b64),c=>c.charCodeAt(0)); return crypto.subtle.importKey("raw",b,{name:"ECDH",namedCurve:"P-256"},false,[]); },
  deriveAES: (priv,pub) => crypto.subtle.deriveKey({name:"ECDH",public:pub},priv,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]),
  genAES: () => crypto.subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"]),
  exportAESraw: async (k) => { const b=await crypto.subtle.exportKey("raw",k); return new Uint8Array(b); },
  importAESraw: (buf) => crypto.subtle.importKey("raw",buf,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]),
  aesEnc: async (k,data) => { const iv=crypto.getRandomValues(new Uint8Array(12)); const e=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,data); return {ct:btoa(String.fromCharCode(...new Uint8Array(e))),iv:btoa(String.fromCharCode(...iv))}; },
  aesDec: (k,ct,iv) => { const c=Uint8Array.from(atob(ct),x=>x.charCodeAt(0)); const i=Uint8Array.from(atob(iv),x=>x.charCodeAt(0)); return crypto.subtle.decrypt({name:"AES-GCM",iv:i},k,c); },
  encText: async (k,t) => C.aesEnc(k,new TextEncoder().encode(t)),
  decText: async (k,ct,iv) => new TextDecoder().decode(await C.aesDec(k,ct,iv)),
};

const S = {ws:null,username:null,action:null,connId:null,groupId:null,groupName:null,isAdmin:false,ecdhKP:null,groupKey:null,ready:false,typingTimer:null,isTyping:false};
const $=id=>document.getElementById(id);
const NAME_COLORS=['#4F46E5','#0891B2','#059669','#D97706','#DC2626','#7C3AED','#DB2777','#0369A1'];
function nameColor(n){let h=0;for(let i=0;i<n.length;i++)h=(h*31+n.charCodeAt(i))>>>0;return NAME_COLORS[h%NAME_COLORS.length];}
function setStatus(cls,text){const b=$('statusBadge'),l=$('statusLed'),t=$('statusText');if(!b)return;b.className=`status-badge ${cls}`;l.className=`status-led${cls==='searching'?' pulse':''}`;t.textContent=text;}
function showWaiting(show){$('waitingPane').classList.toggle('hidden',!show);$('messagesPane').classList.toggle('hidden',show);}
function enableChat(on){$('chatInput').disabled=!on;$('sendBtn').disabled=!on;if(on)$('chatInput').focus();}
function send(obj){if(S.ws&&S.ws.readyState===WebSocket.OPEN)S.ws.send(JSON.stringify(obj));}

function addMsg(text,type,sender,ts){
  const pane=$('messagesPane'),wrap=document.createElement('div');
  wrap.className=`msg ${type}`;
  const bub=document.createElement('div');bub.className='msg-bubble';bub.textContent=text;wrap.appendChild(bub);
  if(type!=='sys'){const meta=document.createElement('div');meta.className='msg-meta';const t=ts||new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});meta.textContent=type==='out'?`You · ${t}`:`${sender} · ${t}`;wrap.appendChild(meta);}
  pane.appendChild(wrap);pane.scrollTop=pane.scrollHeight;
}
function showTyping(show,from){$('typingRow').classList.toggle('show',show);if(from)$('typingName').textContent=`${from} is typing...`;}

function renderMembers(members){
  const list=$('memberList');list.innerHTML='';
  $('memberCount').textContent=members.length;
  $('sideGroupMeta').textContent=members.length+' / 8 members';
  members.forEach(function(m){
    const row=document.createElement('div');row.className='member-row';
    const av=document.createElement('div');av.className='member-av';av.textContent=m.username[0].toUpperCase();av.style.background=nameColor(m.username);
    const nm=document.createElement('span');nm.className='member-name';nm.textContent=m.username;
    row.appendChild(av);row.appendChild(nm);
    if(m.isAdmin){const tag=document.createElement('span');tag.className='admin-tag';tag.textContent='Admin';row.appendChild(tag);}
    if(S.isAdmin&&!m.isAdmin){
      const kb=document.createElement('button');kb.className='kick-btn';kb.title='Remove';
      kb.innerHTML='<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
      kb.onclick=function(){if(confirm('Remove '+m.username+'?'))send({type:'kick_by_username',username:m.username});};
      row.appendChild(kb);
    }
    list.appendChild(row);
  });
}

function renderPending(pending){
  const list=$('pendingList'),empty=$('emptyPending');
  list.querySelectorAll('.pending-row').forEach(function(e){e.remove();});
  if(!pending||!pending.length){empty.style.display='';return;}
  empty.style.display='none';
  pending.forEach(function(p){
    const row=document.createElement('div');row.className='pending-row';
    const av=document.createElement('div');av.className='pending-av';av.textContent=p.username[0].toUpperCase();av.style.background=nameColor(p.username);
    const nm=document.createElement('span');nm.className='pending-name';nm.textContent=p.username;
    const actions=document.createElement('div');actions.className='pending-actions';
    const ap=document.createElement('button');ap.className='pend-approve';ap.textContent='Approve';
    ap.onclick=function(){send({type:'approve_member',connId:p.connId});row.remove();if(!list.querySelector('.pending-row'))empty.style.display='';};
    const dn=document.createElement('button');dn.className='pend-deny';dn.textContent='Deny';
    dn.onclick=function(){send({type:'deny_member',connId:p.connId});row.remove();if(!list.querySelector('.pending-row'))empty.style.display='';};
    actions.appendChild(ap);actions.appendChild(dn);row.appendChild(av);row.appendChild(nm);row.appendChild(actions);list.appendChild(row);
  });
}

function connect(){
  var proto=location.protocol==='https:'?'wss':'ws';
  S.ws=new WebSocket(proto+'://'+location.host+'/ws/group');
  S.ws.onopen=function(){
    setStatus('searching','Connecting...');
    send({type:'init',username:S.username,action:S.action,
      groupName:sessionStorage.getItem('sc_grpName')||'',
      groupId:sessionStorage.getItem('sc_grpId')||''});
  };
  S.ws.onmessage=function(e){onMessage(e).catch(function(err){console.error('Handler:',err);addMsg('Internal error.','sys');});};
  S.ws.onclose=function(){setStatus('gone','Disconnected');enableChat(false);};
  S.ws.onerror=function(){addMsg('WebSocket error.','sys');};
}

async function onMessage(e){
  var d;
  try{d=JSON.parse(e.data);}catch(x){return;}
  console.log('[WS]',d.type,d);

  if(d.type==='connected'){
    S.connId=d.connectionId;
    setStatus('searching',S.action==='create'?'Creating...':'Requesting to join...');

  }else if(d.type==='group_created'){
    S.groupId=d.groupId; S.groupName=d.groupName; S.isAdmin=true;
    S.groupKey=await C.genAES();
    S.ecdhKP=await C.genECDH();
    S.ready=true;
    $('sideGroupName').textContent=d.groupName;
    $('sideGroupMeta').textContent='1 / '+d.maxSize+' members';
    $('groupIdText').textContent=d.groupId;
    $('groupIdPill').classList.remove('hidden');
    $('adminPanel').classList.remove('hidden');
    setStatus('live','Encrypted - Admin');
    showWaiting(false); enableChat(true);
    renderMembers(d.members); renderPending([]);
    addMsg('Group "'+d.groupName+'" created. Share ID: '+d.groupId,'sys');
    addMsg('Approve join requests from the sidebar.','sys');

  }else if(d.type==='join_requested'){
    S.groupId=d.groupId;
    $('waitTitle').textContent='Waiting for admin approval';
    $('waitSub').textContent='The admin will see your request shortly...';
    $('waitGroupId').textContent='Group ID: '+d.groupId;
    $('waitGroupId').classList.remove('hidden');
    setStatus('searching','Awaiting approval...');

  }else if(d.type==='approved'){
    S.groupId=d.groupId; S.groupName=d.groupName; S.isAdmin=false; S.ready=false;
    S.ecdhKP=await C.genECDH();
    var myPub=await C.exportPub(S.ecdhKP.publicKey);
    send({type:'member_pub_key',publicKey:myPub});
    $('sideGroupName').textContent=d.groupName;
    $('groupIdText').textContent=d.groupId;
    $('groupIdPill').classList.remove('hidden');
    setStatus('securing','Securing channel...');
    showWaiting(false); renderMembers(d.members);
    addMsg('Joined "'+d.groupName+'". Exchanging encryption keys...','sys');

  }else if(d.type==='member_pub_key'){
    if(!S.isAdmin||!S.groupKey||!S.ecdhKP){console.error('Admin keys not ready');break_out:break;}
    try{
      console.log('[KEY-EXCHANGE] Wrapping for',d.username,'fromId:',d.fromId);
      var memberPub=await C.importPub(d.publicKey);
      var sharedKey=await C.deriveAES(S.ecdhKP.privateKey,memberPub);
      var rawGroupKey=await C.exportAESraw(S.groupKey);
      var enc=await C.aesEnc(sharedKey,rawGroupKey);
      var adminPub=await C.exportPub(S.ecdhKP.publicKey);
      send({type:'group_key_for_member',targetId:d.fromId,wrappedKey:enc.ct,keyIv:enc.iv,adminPub:adminPub});
      console.log('[KEY-EXCHANGE] Sent wrapped key to',d.fromId);
    }catch(err){console.error('[KEY-EXCHANGE] wrap failed:',err);}

  }else if(d.type==='group_key_for_member'){
    if(S.isAdmin||!S.ecdhKP){console.error('Not member or no ecdhKP');return;}
    try{
      console.log('[KEY-EXCHANGE] Unwrapping group key...');
      var adminPub=await C.importPub(d.adminPub);
      var sharedKey=await C.deriveAES(S.ecdhKP.privateKey,adminPub);
      var rawBuf=await C.aesDec(sharedKey,d.wrappedKey,d.keyIv);
      S.groupKey=await C.importAESraw(new Uint8Array(rawBuf));
      S.ready=true;
      console.log('[KEY-EXCHANGE] Group key ready!');
      setStatus('live','Encrypted');
      enableChat(true);
      addMsg('Secure channel ready. Messages are end-to-end encrypted.','sys');
    }catch(err){
      console.error('[KEY-EXCHANGE] unwrap failed:',err);
      addMsg('Encryption setup failed - please leave and rejoin.','sys');
    }

  }else if(d.type==='join_request'){
    if(S.isAdmin)renderPending(d.pending);
  }else if(d.type==='admin_update'){
    renderMembers(d.members);renderPending(d.pending);
  }else if(d.type==='member_joined'){
    renderMembers(d.members);addMsg(d.username+' joined the group.','sys');
  }else if(d.type==='member_left'){
    renderMembers(d.members);addMsg(d.username+' left the group.','sys');
  }else if(d.type==='group_message'){
    if(!S.ready||!S.groupKey){addMsg('(Message received - encryption still setting up)','sys');return;}
    try{var plain=await C.decText(S.groupKey,d.payload,d.iv);showTyping(false);addMsg(plain,'in',d.from,d.timestamp);}
    catch(err){console.error('Decrypt:',err);addMsg('Could not decrypt a message.','sys');}
  }else if(d.type==='group_typing'){
    showTyping(true,d.from);clearTimeout(S.typingTimer);S.typingTimer=setTimeout(function(){showTyping(false);},2500);
  }else if(d.type==='kicked'){
    S.ready=false;S.groupKey=null;S.ecdhKP=null;enableChat(false);
    setStatus('gone','Removed');showWaiting(true);
    $('waitTitle').textContent='You were removed';$('waitSub').textContent='The admin removed you.';
    addMsg(d.message,'sys');
  }else if(d.type==='denied'){
    setStatus('gone','Denied');showWaiting(true);
    $('waitTitle').textContent='Request declined';$('waitSub').textContent='The admin did not approve your request.';
  }else if(d.type==='group_dissolved'){
    S.ready=false;S.groupKey=null;S.ecdhKP=null;enableChat(false);
    setStatus('gone','Closed');showWaiting(true);
    $('waitTitle').textContent='Group dissolved';$('waitSub').textContent=d.message;
    addMsg(d.message,'sys');
  }else if(d.type==='error'){
    addMsg('Error: '+d.message,'sys');
  }
}

async function sendMessage(text){
  text=text.trim();
  if(!text)return;
  if(!S.ready||!S.groupKey){addMsg('Encryption not ready yet - please wait.','sys');return;}
  try{
    var ts=new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
    var enc=await C.encText(S.groupKey,text);
    send({type:'group_message',payload:enc.ct,iv:enc.iv,timestamp:ts});
    addMsg(text,'out','',ts);
  }catch(err){console.error('Send:',err);addMsg('Failed to send.','sys');}
}

function notifyTyping(){
  if(!S.ready)return;
  if(!S.isTyping){S.isTyping=true;send({type:'group_typing'});setTimeout(function(){S.isTyping=false;},2000);}
}

document.addEventListener('DOMContentLoaded',function(){
  var username=sessionStorage.getItem('sc_username');
  var action=sessionStorage.getItem('sc_grpAction');
  if(!username||!action){location.href='/';return;}
  S.username=username;S.action=action;
  $('youName').textContent=username;
  var av=$('youAvatar');av.textContent=username[0].toUpperCase();av.style.background=nameColor(username);
  setStatus('idle','Connecting');
  connect();
  $('copyGroupId').onclick=function(){navigator.clipboard.writeText(S.groupId||'').then(function(){$('copyGroupId').style.color='#059669';setTimeout(function(){$('copyGroupId').style.color='';},1500);});};
  $('sendBtn').onclick=function(){var v=$('chatInput').value;if(v.trim()){sendMessage(v);$('chatInput').value='';$('chatInput').style.height='auto';}};
  $('chatInput').addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();var v=$('chatInput').value;if(v.trim()){sendMessage(v);$('chatInput').value='';$('chatInput').style.height='auto';}}});
  $('chatInput').addEventListener('input',function(){$('chatInput').style.height='auto';$('chatInput').style.height=Math.min($('chatInput').scrollHeight,120)+'px';notifyTyping();});
  $('dissolveBtn').onclick=function(){if(confirm('Dissolve group? All members will be disconnected.'))send({type:'dissolve_group'});};
  $('leaveBtn').onclick=function(){if(confirm('Leave this group?')){S.ready=false;S.groupKey=null;S.ecdhKP=null;if(S.ws){S.ws.close();S.ws=null;}location.href='/';}};
});
