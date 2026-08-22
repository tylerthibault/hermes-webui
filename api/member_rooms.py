"""Durable, owner-scoped member chat rooms."""
from __future__ import annotations

import copy
import fcntl
import json
import os
import tempfile
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api import config

_VERSION = 1
_MAX_MESSAGE = 20_000
_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
_lock = threading.RLock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _safe(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or any(c not in _ID_CHARS for c in value):
        raise ValueError(f"{field} is invalid")
    return value


def _path() -> Path:
    return Path(config.STATE_DIR) / ".member_rooms.json"


@contextmanager
def _locked():
    with _lock:
        root = Path(config.STATE_DIR)
        root.mkdir(parents=True, exist_ok=True)
        lock_path = root / ".member_rooms.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _empty() -> dict[str, Any]:
    return {"version": _VERSION, "rooms": [], "participants": [], "messages": []}


def _read() -> dict[str, Any]:
    path = _path()
    if not path.exists():
        return _empty()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("member room store could not be read") from exc
    if not isinstance(data, dict) or data.get("version") != _VERSION:
        raise RuntimeError("member room store has an invalid version")
    for key in ("rooms", "participants", "messages"):
        if not isinstance(data.get(key), list):
            raise RuntimeError("member room store has an invalid shape")
    return data


def _write(data: dict[str, Any]) -> None:
    path = _path()
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".member_rooms.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _room(data, room_id):
    return next((r for r in data["rooms"] if r["id"] == room_id), None)


def user_is_member(room_id: str, user_id: str) -> bool:
    _safe(room_id, "room id"); _safe(user_id, "user id")
    with _locked():
        return any(p["room_id"] == room_id and p["participant_type"] == "user" and p["participant_id"] == user_id and p.get("active", True) for p in _read()["participants"])


def create_room(owner_user_id: str, *, kind: str, name: str, participant_user_ids: list[str], orchestrator_enabled: bool = False) -> dict[str, Any]:
    _safe(owner_user_id, "owner user id")
    if kind not in {"direct", "room"}:
        raise ValueError("room kind is invalid")
    if kind == "direct":
        orchestrator_enabled = False
    if not isinstance(name, str) or len(name) > 128:
        raise ValueError("room name is invalid")
    users = list(dict.fromkeys([owner_user_id, *participant_user_ids]))
    for user_id in users:
        _safe(user_id, "participant user id")
    if kind == "direct" and len(users) != 2:
        raise ValueError("direct rooms require exactly two users")
    with _locked():
        data = _read()
        room_id = uuid.uuid4().hex
        now = _now()
        room = {"id": room_id, "kind": kind, "name": name.strip(), "created_by": owner_user_id, "created_at": now, "updated_at": now, "archived": False, "orchestrator_enabled": bool(orchestrator_enabled), "orchestrator_disabled_at": None}
        data["rooms"].append(room)
        for user_id in users:
            data["participants"].append({"room_id": room_id, "participant_type": "user", "participant_id": user_id, "role": "owner" if user_id == owner_user_id else "member", "active": True, "joined_at": now})
        _write(data)
        return copy.deepcopy(room)


def get_room(room_id: str) -> dict[str, Any] | None:
    _safe(room_id, "room id")
    with _locked():
        room = _room(_read(), room_id)
        return copy.deepcopy(room) if room else None


def list_rooms(user_id: str) -> list[dict[str, Any]]:
    _safe(user_id, "user id")
    with _locked():
        data = _read()
        ids = {p["room_id"] for p in data["participants"] if p["participant_type"] == "user" and p["participant_id"] == user_id and p.get("active", True)}
        return [copy.deepcopy(r) for r in data["rooms"] if r["id"] in ids and not r.get("archived")]


def list_participants(room_id: str, user_id: str | None = None) -> list[dict[str, Any]]:
    _safe(room_id, "room id")
    with _locked():
        data = _read()
        if user_id is not None and not any(p["room_id"] == room_id and p["participant_type"] == "user" and p["participant_id"] == user_id and p.get("active", True) for p in data["participants"]):
            return []
        result = [copy.deepcopy(p) for p in data["participants"] if p["room_id"] == room_id and p.get("active", True)]
        room = _room(data, room_id)
        if room and room.get("orchestrator_enabled"):
            result.append({"room_id": room_id, "participant_type": "orchestrator", "participant_id": "room-orchestrator", "role": "orchestrator", "active": True, "joined_at": room["created_at"]})
        return result


def set_orchestrator(room_id: str, enabled: bool) -> dict[str, Any]:
    _safe(room_id, "room id")
    with _locked():
        data = _read(); room = _room(data, room_id)
        if room is None: raise KeyError(room_id)
        room["orchestrator_enabled"] = bool(enabled)
        room["orchestrator_disabled_at"] = None if enabled else _now()
        room["updated_at"] = _now(); _write(data)
        return copy.deepcopy(room)


def add_message(room_id: str, sender_id: str, body: str, *, sender_type: str = "user") -> dict[str, Any]:
    _safe(room_id, "room id"); _safe(sender_id, "sender id")
    if sender_type not in {"user", "bot", "orchestrator"} or not isinstance(body, str) or not body.strip() or len(body) > _MAX_MESSAGE:
        raise ValueError("message is invalid")
    with _locked():
        data = _read()
        if not any(p["room_id"] == room_id and p["participant_id"] == sender_id and p["participant_type"] == ("user" if sender_type == "user" else "bot") and p.get("active", True) for p in data["participants"]):
            raise KeyError(room_id)
        message = {"id": uuid.uuid4().hex, "room_id": room_id, "sender_type": sender_type, "sender_id": sender_id, "body": body.strip(), "created_at": _now()}
        data["messages"].append(message); room = _room(data, room_id); room["updated_at"] = message["created_at"]; _write(data)
        return copy.deepcopy(message)


def list_messages(room_id: str, user_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    _safe(room_id, "room id"); _safe(user_id, "user id")
    with _locked():
        data = _read()
        if not any(p["room_id"] == room_id and p["participant_type"] == "user" and p["participant_id"] == user_id and p.get("active", True) for p in data["participants"]):
            return []
        return [copy.deepcopy(m) for m in data["messages"] if m["room_id"] == room_id][-max(1, min(limit, 200)):]
