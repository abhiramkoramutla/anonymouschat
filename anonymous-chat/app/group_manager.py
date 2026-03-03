"""
group_manager.py - In-memory group chat management.

Rules:
- Admin creates group, gets group_id + admin_token
- Max 8 members (including admin)
- Members submit join requests; admin approves/denies
- Admin can kick any member
- Admin can dissolve the entire group
- Group auto-destroys when admin disconnects
- Server only relays encrypted blobs; never reads plaintext
"""

import asyncio
import logging
import uuid

logger = logging.getLogger("chat.group")

MAX_GROUP_SIZE = 8


class GroupRoom:
    def __init__(self, group_id: str, group_name: str, admin_conn):
        self.group_id    = group_id
        self.group_name  = group_name
        self.admin_id    = admin_conn.id
        self.admin_token = uuid.uuid4().hex          # secret token only admin holds
        self.members     = {admin_conn.id: admin_conn}  # conn_id -> Connection
        self.pending     = {}                        # conn_id -> Connection (awaiting approval)

    def is_admin(self, connection_id: str) -> bool:
        return connection_id == self.admin_id

    def is_member(self, connection_id: str) -> bool:
        return connection_id in self.members

    def is_pending(self, connection_id: str) -> bool:
        return connection_id in self.pending

    def member_count(self) -> int:
        return len(self.members)

    def member_list(self) -> list[dict]:
        return [
            {"username": c.username, "isAdmin": c.id == self.admin_id}
            for c in self.members.values()
        ]

    def pending_list(self) -> list[dict]:
        return [{"connId": c.id, "username": c.username} for c in self.pending.values()]


class GroupManager:
    def __init__(self):
        self._groups: dict[str, GroupRoom] = {}   # group_id -> GroupRoom
        self._conn_to_group: dict[str, str] = {}   # conn_id  -> group_id
        self._lock = asyncio.Lock()

    # ── Create ────────────────────────────────────────────────────────────────

    async def create_group(self, group_name: str, admin_conn) -> GroupRoom:
        async with self._lock:
            group_id = uuid.uuid4().hex[:10].upper()
            group = GroupRoom(group_id, group_name, admin_conn)
            self._groups[group_id] = group
            self._conn_to_group[admin_conn.id] = group_id
            admin_conn.room_id = group_id
            logger.info("Group %s created by %s", group_id, admin_conn.username)
            return group

    # ── Join request ──────────────────────────────────────────────────────────

    async def request_join(self, group_id: str, conn) -> tuple[bool, str]:
        """Returns (ok, error_message)."""
        async with self._lock:
            group = self._groups.get(group_id)
            if not group:
                return False, "Group not found. Check the Group ID."
            if group.is_member(conn.id):
                return False, "Already a member."
            if group.is_pending(conn.id):
                return False, "Join request already pending."
            if group.member_count() >= MAX_GROUP_SIZE:
                return False, f"Group is full (max {MAX_GROUP_SIZE} members)."
            group.pending[conn.id] = conn
            logger.info("%s requested to join group %s", conn.username, group_id)
            return True, ""

    # ── Admin: approve ────────────────────────────────────────────────────────

    async def approve_member(self, group_id: str, admin_conn_id: str, target_conn_id: str) -> tuple[bool, str]:
        async with self._lock:
            group = self._groups.get(group_id)
            if not group or not group.is_admin(admin_conn_id):
                return False, "Not authorized."
            if target_conn_id not in group.pending:
                return False, "Request not found."
            if group.member_count() >= MAX_GROUP_SIZE:
                return False, f"Group is full."
            conn = group.pending.pop(target_conn_id)
            group.members[target_conn_id] = conn
            self._conn_to_group[target_conn_id] = group_id
            conn.room_id = group_id
            logger.info("%s approved into group %s", conn.username, group_id)
            return True, ""

    # ── Admin: deny ───────────────────────────────────────────────────────────

    async def deny_member(self, group_id: str, admin_conn_id: str, target_conn_id: str) -> tuple[bool, str]:
        async with self._lock:
            group = self._groups.get(group_id)
            if not group or not group.is_admin(admin_conn_id):
                return False, "Not authorized."
            conn = group.pending.pop(target_conn_id, None)
            return (True, "") if conn else (False, "Request not found.")

    # ── Admin: kick ───────────────────────────────────────────────────────────

    async def kick_member(self, group_id: str, admin_conn_id: str, target_conn_id: str) -> tuple[bool, str, object]:
        async with self._lock:
            group = self._groups.get(group_id)
            if not group or not group.is_admin(admin_conn_id):
                return False, "Not authorized.", None
            if target_conn_id == admin_conn_id:
                return False, "Cannot kick yourself.", None
            conn = group.members.pop(target_conn_id, None)
            if conn:
                self._conn_to_group.pop(target_conn_id, None)
                conn.room_id = None
                return True, "", conn
            return False, "Member not found.", None

    # ── Admin: dissolve ───────────────────────────────────────────────────────

    async def dissolve_group(self, group_id: str, admin_conn_id: str) -> tuple[bool, list]:
        async with self._lock:
            group = self._groups.get(group_id)
            if not group or not group.is_admin(admin_conn_id):
                return False, []
            all_conns = list(group.members.values()) + list(group.pending.values())
            for c in all_conns:
                self._conn_to_group.pop(c.id, None)
                c.room_id = None
            del self._groups[group_id]
            logger.info("Group %s dissolved by admin", group_id)
            return True, all_conns

    # ── Member leave ──────────────────────────────────────────────────────────

    async def leave_group(self, conn_id: str) -> tuple[str | None, list, bool]:
        """Returns (group_id, remaining_members, was_admin)."""
        async with self._lock:
            group_id = self._conn_to_group.pop(conn_id, None)
            if not group_id:
                # Check pending
                for gid, group in list(self._groups.items()):
                    if conn_id in group.pending:
                        del group.pending[conn_id]
                return None, [], False

            group = self._groups.get(group_id)
            if not group:
                return group_id, [], False

            was_admin = group.is_admin(conn_id)
            group.members.pop(conn_id, None)

            if was_admin:
                # Auto-dissolve — notify all
                all_conns = list(group.members.values()) + list(group.pending.values())
                for c in all_conns:
                    self._conn_to_group.pop(c.id, None)
                    c.room_id = None
                del self._groups[group_id]
                logger.info("Group %s auto-dissolved (admin left)", group_id)
                return group_id, all_conns, True

            remaining = list(group.members.values())
            return group_id, remaining, False

    # ── Lookup ────────────────────────────────────────────────────────────────

    async def get_group(self, group_id: str) -> GroupRoom | None:
        async with self._lock:
            return self._groups.get(group_id)

    async def get_group_for_conn(self, conn_id: str) -> GroupRoom | None:
        async with self._lock:
            gid = self._conn_to_group.get(conn_id)
            return self._groups.get(gid) if gid else None

    # ── Broadcast helpers ─────────────────────────────────────────────────────

    async def broadcast(self, group_id: str, data: dict, exclude_id: str = None):
        """Send to all members. Server never reads message content."""
        async with self._lock:
            group = self._groups.get(group_id)
            if not group:
                return
            targets = [c for cid, c in group.members.items() if cid != exclude_id]
        for conn in targets:
            await conn.send_json(data)

    async def broadcast_all(self, group_id: str, data: dict):
        await self.broadcast(group_id, data, exclude_id=None)


group_manager = GroupManager()