"""
connection_manager.py — Manages individual WebSocket connections.
Tracks active sockets and provides safe send helpers.
Also manages lobby subscribers for the online-users panel.
"""

import asyncio
import json
import logging
from fastapi import WebSocket

logger = logging.getLogger("chat.connection")


class Connection:
    """Wraps a single WebSocket with metadata."""

    def __init__(self, websocket: WebSocket, connection_id: str, username: str, client_ip: str):
        self.ws            = websocket
        self.id            = connection_id
        self.username      = username
        self.client_ip     = client_ip
        self.partner_id    = None
        self.room_id       = None
        self._send_lock    = asyncio.Lock()

    async def send_json(self, data: dict) -> bool:
        async with self._send_lock:
            try:
                await self.ws.send_text(json.dumps(data))
                return True
            except Exception as exc:
                logger.debug("Send failed for %s: %s", self.id, exc)
                return False

    async def close(self) -> None:
        try:
            await self.ws.close()
        except Exception:
            pass


class ConnectionManager:
    """Registry of all active chat connections + lobby subscribers."""

    def __init__(self):
        self._connections: dict[str, Connection] = {}
        self._lobby_sockets: list[WebSocket] = []   # landing page listeners
        self._lock = asyncio.Lock()

    async def register(self, connection: Connection) -> None:
        async with self._lock:
            self._connections[connection.id] = connection
        await self._broadcast_online_list()

    async def unregister(self, connection_id: str):
        async with self._lock:
            self._connections.pop(connection_id, None)
        await self._broadcast_online_list()

    async def get(self, connection_id: str):
        async with self._lock:
            return self._connections.get(connection_id)

    async def count(self) -> int:
        async with self._lock:
            return len(self._connections)

    async def get_usernames(self) -> list[str]:
        """Return list of connected usernames (for lobby display)."""
        async with self._lock:
            return [c.username for c in self._connections.values()]

    async def send_to(self, connection_id: str, data: dict) -> bool:
        conn = await self.get(connection_id)
        if conn:
            return await conn.send_json(data)
        return False

    # ── Lobby (landing page live presence) ───────────────────────────────────

    async def add_lobby(self, ws: WebSocket) -> None:
        async with self._lock:
            self._lobby_sockets.append(ws)
        # Send current list immediately to this new subscriber
        usernames = await self.get_usernames()
        try:
            await ws.send_text(json.dumps({"type": "online_users", "users": usernames}))
        except Exception:
            pass

    async def remove_lobby(self, ws: WebSocket) -> None:
        async with self._lock:
            try:
                self._lobby_sockets.remove(ws)
            except ValueError:
                pass

    async def _broadcast_online_list(self) -> None:
        """Push updated user list to all lobby subscribers."""
        usernames = await self.get_usernames()
        payload = json.dumps({"type": "online_users", "users": usernames})
        async with self._lock:
            dead = []
            for ws in self._lobby_sockets:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                try:
                    self._lobby_sockets.remove(ws)
                except ValueError:
                    pass


manager = ConnectionManager()