"""
main.py - FastAPI app. Handles 1-on-1 session chat AND group chat.
Server only relays encrypted blobs — never reads plaintext.
"""

import asyncio, json, logging, os, sys, uuid
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.connection_manager import Connection, manager as conn_manager
from app.room_manager import room_manager
from app.group_manager import group_manager, MAX_GROUP_SIZE
from app.security import rate_limiter, ip_throttle, validate_username, validate_session_id, validate_payload_length

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("chat.main")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = FastAPI(title="SecureChat", version="2.0.0")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


# ── HTTP ──────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/chat", response_class=HTMLResponse)
async def chat(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})

@app.get("/group", response_class=HTMLResponse)
async def group_page(request: Request):
    return templates.TemplateResponse("group.html", {"request": request})

@app.get("/health")
async def health():
    return {"status": "ok", "connections": await conn_manager.count()}


# ── Lobby WebSocket ───────────────────────────────────────────────────────────
@app.websocket("/ws/lobby")
async def lobby_ws(websocket: WebSocket):
    await websocket.accept()
    await conn_manager.add_lobby(websocket)
    try:
        while True:
            await asyncio.sleep(30)
    except Exception:
        pass
    finally:
        await conn_manager.remove_lobby(websocket)


# ── 1-on-1 Chat WebSocket ─────────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_private(websocket: WebSocket):
    await websocket.accept()
    client_ip = websocket.client.host if websocket.client else "unknown"

    if not await ip_throttle.is_allowed(client_ip):
        await websocket.send_text(json.dumps({"type":"error","message":"Too many connections."}))
        await websocket.close(); return

    connection_id = uuid.uuid4().hex
    conn = None; session_id_used = None

    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=15.0)
        data = json.loads(raw)
        if data.get("type") != "init":
            await websocket.send_text(json.dumps({"type":"error","message":"Expected init."}))
            await websocket.close(); return

        username   = str(data.get("username","")).strip()
        session_id = str(data.get("sessionId","")).strip()

        ok, err = validate_username(username)
        if not ok:
            await websocket.send_text(json.dumps({"type":"error","message":err}))
            await websocket.close(); return

        ok, err = validate_session_id(session_id)
        if not ok:
            await websocket.send_text(json.dumps({"type":"error","message":err}))
            await websocket.close(); return

        session_id_used = session_id
        conn = Connection(websocket, connection_id, username, client_ip)
        await conn_manager.register(conn)

        await conn.send_json({"type":"connected","connectionId":connection_id})

        room = await room_manager.join_session(session_id, conn)
        if room is None:
            await conn.send_json({"type":"waiting","message":"Waiting for your contact..."})
        else:
            await _notify_matched(room, conn)

        while True:
            raw = await websocket.receive_text()
            if not await rate_limiter.is_allowed(connection_id):
                await conn.send_json({"type":"error","message":"Slow down."}); continue

            try: data = json.loads(raw)
            except: continue

            t = data.get("type","")

            if t == "public_key":
                pk = data.get("publicKey","")
                if pk and len(pk) <= 500:
                    await room_manager.relay_to_partner(connection_id, {"type":"partner_public_key","publicKey":pk,"username":username})

            elif t == "message":
                payload, iv = data.get("payload",""), data.get("iv","")
                if payload and iv and validate_payload_length(payload):
                    await room_manager.relay_to_partner(connection_id, {"type":"message","payload":payload,"iv":iv,"from":username,"timestamp":data.get("timestamp","")})

            elif t == "typing":
                await room_manager.relay_to_partner(connection_id, {"type":"typing","from":username})

    except WebSocketDisconnect: pass
    except asyncio.TimeoutError: pass
    except Exception as e: logger.exception("Private WS error: %s", e)
    finally:
        if conn:
            room = await room_manager.get_room_for_connection(connection_id)
            if room:
                partner = room.partner_of(connection_id)
                if partner:
                    await partner.send_json({"type":"partner_disconnected","message":"Contact disconnected. Session erased."})
                await room_manager.destroy_room(room.room_id)
            await room_manager.leave_random_queue(conn)
            if session_id_used:
                await room_manager.leave_session_queue(session_id_used, conn)
        await conn_manager.unregister(connection_id)
        await rate_limiter.remove(connection_id)


# ── Group Chat WebSocket ──────────────────────────────────────────────────────
@app.websocket("/ws/group")
async def ws_group(websocket: WebSocket):
    await websocket.accept()
    client_ip = websocket.client.host if websocket.client else "unknown"

    if not await ip_throttle.is_allowed(client_ip):
        await websocket.send_text(json.dumps({"type":"error","message":"Too many connections."}))
        await websocket.close(); return

    connection_id = uuid.uuid4().hex
    conn = None

    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=15.0)
        data = json.loads(raw)
        if data.get("type") != "init":
            await websocket.close(); return

        username = str(data.get("username","")).strip()
        action   = str(data.get("action","")).strip()   # "create" | "join"

        ok, err = validate_username(username)
        if not ok:
            await websocket.send_text(json.dumps({"type":"error","message":err}))
            await websocket.close(); return

        conn = Connection(websocket, connection_id, username, client_ip)
        await conn_manager.register(conn)
        await conn.send_json({"type":"connected","connectionId":connection_id})

        # ── CREATE group ──────────────────────────────────────────────────────
        if action == "create":
            group_name = str(data.get("groupName","")).strip()[:40] or f"{username}'s Group"
            group = await group_manager.create_group(group_name, conn)
            await conn.send_json({
                "type":       "group_created",
                "groupId":    group.group_id,
                "groupName":  group.group_name,
                "adminToken": group.admin_token,
                "members":    group.member_list(),
                "maxSize":    MAX_GROUP_SIZE,
            })

        # ── JOIN group ────────────────────────────────────────────────────────
        elif action == "join":
            group_id = str(data.get("groupId","")).strip().upper()
            ok, err = await group_manager.request_join(group_id, conn)
            if not ok:
                await conn.send_json({"type":"error","message":err})
            else:
                await conn.send_json({"type":"join_requested","groupId":group_id})
                # Notify admin
                group = await group_manager.get_group(group_id)
                if group:
                    admin_conn = group.members.get(group.admin_id)
                    if admin_conn:
                        await admin_conn.send_json({
                            "type":     "join_request",
                            "connId":   connection_id,
                            "username": username,
                            "pending":  group.pending_list(),
                        })
        else:
            await conn.send_json({"type":"error","message":"Unknown action."})

        # ── Message loop ──────────────────────────────────────────────────────
        while True:
            raw = await websocket.receive_text()
            if not await rate_limiter.is_allowed(connection_id):
                await conn.send_json({"type":"error","message":"Slow down."}); continue

            try: data = json.loads(raw)
            except: continue

            t = data.get("type","")

            # Admin: approve join request
            if t == "approve_member":
                target = data.get("connId","")
                group  = await group_manager.get_group_for_conn(connection_id)
                if group:
                    ok, err = await group_manager.approve_member(group.group_id, connection_id, target)
                    if ok:
                        group = await group_manager.get_group(group.group_id)
                        new_member = group.members.get(target) if group else None
                        if new_member:
                            # Tell new member they're approved + send member list
                            await new_member.send_json({
                                "type":      "approved",
                                "groupId":   group.group_id,
                                "groupName": group.group_name,
                                "members":   group.member_list(),
                                "maxSize":   MAX_GROUP_SIZE,
                                "isAdmin":   False,
                            })
                            # Tell all existing members
                            await group_manager.broadcast(group.group_id, {
                                "type":     "member_joined",
                                "username": new_member.username,
                                "members":  group.member_list(),
                            }, exclude_id=target)
                            # Update admin panel
                            await conn.send_json({"type":"admin_update","members":group.member_list(),"pending":group.pending_list()})
                    else:
                        await conn.send_json({"type":"error","message":err})

            # Admin: deny join request
            elif t == "deny_member":
                target = data.get("connId","")
                group  = await group_manager.get_group_for_conn(connection_id)
                if group:
                    ok, err = await group_manager.deny_member(group.group_id, connection_id, target)
                    if ok:
                        # Notify denied user
                        denied_conn = await conn_manager.get(target)
                        if denied_conn:
                            await denied_conn.send_json({"type":"denied","message":"Your join request was declined."})
                        group = await group_manager.get_group(group.group_id)
                        if group:
                            await conn.send_json({"type":"admin_update","members":group.member_list(),"pending":group.pending_list()})

            # Admin: kick by username (from member list UI)
            elif t == "kick_by_username":
                target_username = data.get("username","")
                group  = await group_manager.get_group_for_conn(connection_id)
                if group and group.is_admin(connection_id):
                    target_conn_id = next((cid for cid,c in group.members.items() if c.username==target_username and cid!=connection_id), None)
                    if target_conn_id:
                        ok, err, kicked = await group_manager.kick_member(group.group_id, connection_id, target_conn_id)
                        if ok and kicked:
                            await kicked.send_json({"type":"kicked","message":"You were removed from the group by the admin."})
                            group = await group_manager.get_group(group.group_id)
                            if group:
                                await group_manager.broadcast_all(group.group_id,{"type":"member_left","username":kicked.username,"members":group.member_list()})
                                await conn.send_json({"type":"admin_update","members":group.member_list(),"pending":group.pending_list()})

            # Admin: kick member
            elif t == "kick_member":
                target = data.get("connId","")
                group  = await group_manager.get_group_for_conn(connection_id)
                if group:
                    ok, err, kicked = await group_manager.kick_member(group.group_id, connection_id, target)
                    if ok and kicked:
                        await kicked.send_json({"type":"kicked","message":"You were removed from the group by the admin."})
                        group = await group_manager.get_group(group.group_id)
                        if group:
                            await group_manager.broadcast_all(group.group_id, {"type":"member_left","username":kicked.username,"members":group.member_list()})
                            await conn.send_json({"type":"admin_update","members":group.member_list(),"pending":group.pending_list()})

            # Admin: dissolve group
            elif t == "dissolve_group":
                group = await group_manager.get_group_for_conn(connection_id)
                if group:
                    ok, all_conns = await group_manager.dissolve_group(group.group_id, connection_id)
                    if ok:
                        for c in all_conns:
                            if c.id != connection_id:
                                await c.send_json({"type":"group_dissolved","message":"The admin has dissolved this group."})
                        await conn.send_json({"type":"group_dissolved","message":"You dissolved the group."})

            # Member sends their ECDH public key to admin for key exchange
            elif t == "member_pub_key":
                group = await group_manager.get_group_for_conn(connection_id)
                if group and group.is_member(connection_id):
                    admin_conn = group.members.get(group.admin_id)
                    if admin_conn:
                        await admin_conn.send_json({
                            "type":      "member_pub_key",
                            "publicKey": data.get("publicKey", ""),
                            "fromId":    connection_id,
                            "username":  username,
                        })

            # Admin sends wrapped group AES key to a specific member
            elif t == "group_key_for_member":
                target_id = data.get("targetId", "")
                group = await group_manager.get_group_for_conn(connection_id)
                if group and group.is_admin(connection_id):
                    target_conn = group.members.get(target_id)
                    if target_conn:
                        await target_conn.send_json({
                            "type":       "group_key_for_member",
                            "wrappedKey": data.get("wrappedKey", ""),
                            "keyIv":      data.get("keyIv", ""),
                            "adminPub":   data.get("adminPub", ""),
                        })

            # Encrypted group message — relay to all members
            elif t == "group_message":
                payload = data.get("payload","")
                iv      = data.get("iv","")
                if not payload or not iv or not validate_payload_length(payload):
                    continue
                group = await group_manager.get_group_for_conn(connection_id)
                if group and group.is_member(connection_id):
                    await group_manager.broadcast(group.group_id, {
                        "type":      "group_message",
                        "payload":   payload,
                        "iv":        iv,
                        "from":      username,
                        "fromId":    connection_id,
                        "timestamp": data.get("timestamp",""),
                    }, exclude_id=connection_id)

            # Typing indicator
            elif t == "group_typing":
                group = await group_manager.get_group_for_conn(connection_id)
                if group and group.is_member(connection_id):
                    await group_manager.broadcast(group.group_id, {"type":"group_typing","from":username}, exclude_id=connection_id)

    except WebSocketDisconnect: pass
    except asyncio.TimeoutError: pass
    except Exception as e: logger.exception("Group WS error: %s", e)
    finally:
        if conn:
            group_id, affected, was_admin = await group_manager.leave_group(connection_id)
            if group_id:
                if was_admin:
                    for c in affected:
                        await c.send_json({"type":"group_dissolved","message":"Admin disconnected. Group has been closed."})
                else:
                    group = await group_manager.get_group(group_id)
                    members = group.member_list() if group else []
                    for c in affected:
                        await c.send_json({"type":"member_left","username":username,"members":members})
        await conn_manager.unregister(connection_id)
        await rate_limiter.remove(connection_id)


async def _notify_matched(room, new_conn):
    partner = room.partner_of(new_conn.id)
    await new_conn.send_json({"type":"matched","partnerName":partner.username})
    await partner.send_json({"type":"matched","partnerName":new_conn.username})
