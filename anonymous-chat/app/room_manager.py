"""
room_manager.py - Manages chat rooms, random matching queue, and session ID rooms.
All data is in-memory only. Server never sees plaintext.
"""

import asyncio
import logging
import uuid
from app.connection_manager import Connection, manager as conn_manager

logger = logging.getLogger("chat.room")


class Room:
    """Represents a two-person encrypted chat room."""

    def __init__(self, room_id, conn_a, conn_b):
        self.room_id = room_id
        self.conn_a  = conn_a
        self.conn_b  = conn_b

    def partner_of(self, connection_id):
        if self.conn_a.id == connection_id:
            return self.conn_b
        if self.conn_b.id == connection_id:
            return self.conn_a
        return None

    def both_ids(self):
        return (self.conn_a.id, self.conn_b.id)


class RoomManager:
    """Manages random queue, session waiting rooms, and active rooms."""

    def __init__(self):
        self._rooms           = {}   # room_id -> Room
        self._session_waiting = {}   # session_id -> Connection
        self._random_queue    = []   # list[Connection]
        self._lock = asyncio.Lock()

    # --- Random Matching ---

    async def join_random_queue(self, conn):
        async with self._lock:
            # Prune stale entries
            alive = []
            for c in self._random_queue:
                if await self._is_alive(c):
                    alive.append(c)
            self._random_queue = alive

            # Find partner (avoid same connection)
            for waiting in self._random_queue:
                if waiting.id != conn.id:
                    self._random_queue.remove(waiting)
                    room = await self._create_room(waiting, conn)
                    return room

            self._random_queue.append(conn)
            return None

    async def leave_random_queue(self, conn):
        async with self._lock:
            self._random_queue = [c for c in self._random_queue if c.id != conn.id]

    # --- Session ID Matching ---

    async def join_session(self, session_id, conn):
        async with self._lock:
            waiting = self._session_waiting.get(session_id)
            if waiting and waiting.id != conn.id and await self._is_alive(waiting):
                del self._session_waiting[session_id]
                room = await self._create_room(waiting, conn)
                return room
            self._session_waiting[session_id] = conn
            return None

    async def leave_session_queue(self, session_id, conn):
        async with self._lock:
            existing = self._session_waiting.get(session_id)
            if existing and existing.id == conn.id:
                del self._session_waiting[session_id]

    # --- Room Lifecycle ---

    async def get_room_for_connection(self, connection_id):
        async with self._lock:
            for room in self._rooms.values():
                if connection_id in room.both_ids():
                    return room
            return None

    async def destroy_room(self, room_id):
        async with self._lock:
            room = self._rooms.pop(room_id, None)
            if room:
                room.conn_a.partner_id = None
                room.conn_a.room_id    = None
                room.conn_b.partner_id = None
                room.conn_b.room_id    = None
                logger.info("Room %s destroyed - ephemeral data erased.", room_id)

    # --- Relay ---

    async def relay_to_partner(self, sender_id, data):
        """Relay encrypted payload to partner. Server never reads content."""
        room = await self.get_room_for_connection(sender_id)
        if not room:
            return False
        partner = room.partner_of(sender_id)
        if not partner:
            return False
        return await partner.send_json(data)

    # --- Internal ---

    async def _create_room(self, conn_a, conn_b):
        room_id = uuid.uuid4().hex
        room = Room(room_id, conn_a, conn_b)
        self._rooms[room_id] = room
        conn_a.partner_id = conn_b.id
        conn_a.room_id    = room_id
        conn_b.partner_id = conn_a.id
        conn_b.room_id    = room_id
        logger.info("Room %s: %s <-> %s", room_id, conn_a.username, conn_b.username)
        return room

    async def _is_alive(self, conn):
        return await conn_manager.get(conn.id) is not None


room_manager = RoomManager()
