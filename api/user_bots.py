"""Durable owner-scoped registry and private homes for user bots."""
from __future__ import annotations

import copy
import fcntl
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api import config

_STORE_VERSION = 1
_BOT_FIELDS = frozenset({"id", "owner_user_id", "name", "home", "status", "created_at", "updated_at"})
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_MAX_BYTES = 4 * 1024 * 1024
_SOUL_MAX_BYTES = 128 * 1024
_DEFAULT_SOUL = "# Soul\n\nYou are a helpful, thoughtful assistant.\n\n## Focus\nDescribe this bot's focus and boundaries here.\n"
_lock = threading.RLock()


def _path() -> Path:
    return Path(config.STATE_DIR) / ".user_bots.json"


def _lock_path() -> Path:
    return Path(config.STATE_DIR) / ".user_bots.lock"


def _homes_root() -> Path:
    return (Path(config.STATE_DIR) / "user_bots").resolve()


@contextmanager
def _locked():
    with _lock:
        Path(config.STATE_DIR).mkdir(parents=True, exist_ok=True)
        fd = os.open(_lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _empty() -> dict[str, Any]:
    return {"version": _STORE_VERSION, "bots": []}


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _validate_home(bot: dict[str, Any]) -> Path:
    root = _homes_root()
    home = Path(bot["home"]).expanduser().resolve()
    expected = (root / bot["owner_user_id"] / bot["id"]).resolve()
    if home != expected or not home.is_relative_to(root):
        raise ValueError("bot home is outside the managed bot root")
    return home


def _validate_bot(bot: Any) -> None:
    if not isinstance(bot, dict) or set(bot) != _BOT_FIELDS:
        raise ValueError("bot has invalid fields")
    _safe_id(bot["id"], "bot id")
    _safe_id(bot["owner_user_id"], "owner user id")
    if not isinstance(bot["name"], str) or not _NAME_RE.fullmatch(bot["name"]):
        raise ValueError("bot name is invalid")
    for field in ("home", "created_at", "updated_at"):
        if not isinstance(bot[field], str) or not bot[field].strip():
            raise ValueError(f"bot {field} must be a non-empty string")
    if bot["status"] not in {"stopped", "running", "error"}:
        raise ValueError("bot status is invalid")
    _validate_home(bot)


def _read_unlocked() -> dict[str, Any]:
    path = _path()
    if not path.exists():
        return _empty()
    try:
        with path.open("r", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            if os.fstat(handle.fileno()).st_size > _MAX_BYTES:
                raise RuntimeError("bot registry is too large")
            payload = json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("bot registry could not be read") from exc
    if not isinstance(payload, dict) or payload.get("version") != _STORE_VERSION or not isinstance(payload.get("bots"), list):
        raise RuntimeError("bot registry has an invalid shape")
    ids: set[str] = set()
    for bot in payload["bots"]:
        try:
            _validate_bot(bot)
        except ValueError as exc:
            raise RuntimeError(f"bot registry is invalid: {exc}") from exc
        if bot["id"] in ids:
            raise RuntimeError("bot registry contains duplicate IDs")
        ids.add(bot["id"])
    return payload


def _write_unlocked(payload: dict[str, Any]) -> None:
    for bot in payload["bots"]:
        _validate_bot(bot)
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if len(serialized.encode()) > _MAX_BYTES:
        raise RuntimeError("bot registry is too large")
    path = _path()
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f"{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def list_bots(owner_user_id: str) -> list[dict[str, Any]]:
    _safe_id(owner_user_id, "owner user id")
    with _locked():
        return [copy.deepcopy(bot) for bot in _read_unlocked()["bots"] if bot["owner_user_id"] == owner_user_id]


def get_bot(bot_id: str, owner_user_id: str) -> dict[str, Any] | None:
    _safe_id(bot_id, "bot id")
    _safe_id(owner_user_id, "owner user id")
    with _locked():
        return next((copy.deepcopy(bot) for bot in _read_unlocked()["bots"] if bot["id"] == bot_id and bot["owner_user_id"] == owner_user_id), None)


def create_bot(owner_user_id: str, name: str) -> dict[str, Any]:
    _safe_id(owner_user_id, "owner user id")
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name.strip()):
        raise ValueError("bot name is invalid")
    name = name.strip()
    with _locked():
        payload = _read_unlocked()
        if any(bot["owner_user_id"] == owner_user_id and bot["name"].casefold() == name.casefold() for bot in payload["bots"]):
            raise ValueError("bot name already exists")
        bot_id = str(uuid.uuid4())
        home = _homes_root() / owner_user_id / bot_id
        home.parent.mkdir(parents=True, exist_ok=True)
        home.mkdir(exist_ok=False)
        os.chmod(home, 0o700)
        (home / "SOUL.md").write_text(_DEFAULT_SOUL, encoding="utf-8")
        os.chmod(home / "SOUL.md", 0o600)
        now = _now()
        bot = {"id": bot_id, "owner_user_id": owner_user_id, "name": name, "home": str(home), "status": "stopped", "created_at": now, "updated_at": now}
        try:
            payload["bots"].append(bot)
            _write_unlocked(payload)
        except Exception:
            payload["bots"].pop()
            shutil.rmtree(home, ignore_errors=True)
            raise
        return copy.deepcopy(bot)


def rename_bot(bot_id: str, owner_user_id: str, name: str) -> dict[str, Any]:
    _safe_id(bot_id, "bot id"); _safe_id(owner_user_id, "owner user id")
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name.strip()):
        raise ValueError("bot name is invalid")
    name = name.strip()
    with _locked():
        payload = _read_unlocked()
        bot = next((item for item in payload["bots"] if item["id"] == bot_id and item["owner_user_id"] == owner_user_id), None)
        if bot is None: raise KeyError(bot_id)
        if any(item["owner_user_id"] == owner_user_id and item["id"] != bot_id and item["name"].casefold() == name.casefold() for item in payload["bots"]):
            raise ValueError("bot name already exists")
        bot["name"] = name; bot["updated_at"] = _now(); _write_unlocked(payload)
        return copy.deepcopy(bot)


def delete_bot(bot_id: str, owner_user_id: str) -> dict[str, Any]:
    _safe_id(bot_id, "bot id"); _safe_id(owner_user_id, "owner user id")
    with _locked():
        payload = _read_unlocked()
        index = next((i for i, item in enumerate(payload["bots"]) if item["id"] == bot_id and item["owner_user_id"] == owner_user_id), None)
        if index is None: raise KeyError(bot_id)
        bot = payload["bots"][index]; home = _validate_home(bot)
        payload["bots"].pop(index)
        _write_unlocked(payload)
        shutil.rmtree(home, ignore_errors=True)
        return copy.deepcopy(bot)


def read_soul(bot_id: str, owner_user_id: str) -> str:
    bot = get_bot(bot_id, owner_user_id)
    if bot is None:
        raise KeyError(bot_id)
    path = _validate_home(bot) / "SOUL.md"
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _SOUL_MAX_BYTES:
            raise RuntimeError("SOUL.md is invalid")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            return os.fdopen(fd, "r", encoding="utf-8").read()
        except Exception:
            os.close(fd)
            raise
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise RuntimeError("SOUL.md is invalid") from exc


def write_soul(bot_id: str, owner_user_id: str, content: str) -> str:
    if not isinstance(content, str):
        raise ValueError("SOUL.md must be text")
    if len(content.encode("utf-8")) > _SOUL_MAX_BYTES:
        raise ValueError("SOUL.md is too large")
    bot = get_bot(bot_id, owner_user_id)
    if bot is None:
        raise KeyError(bot_id)
    home = _validate_home(bot)
    temporary = home / ".SOUL.md.tmp"
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, home / "SOUL.md")
    return content


def update_bot_status(bot_id: str, owner_user_id: str, status: str) -> dict[str, Any]:
    if status not in {"stopped", "running", "error"}: raise ValueError("bot status is invalid")
    _safe_id(bot_id, "bot id"); _safe_id(owner_user_id, "owner user id")
    with _locked():
        payload = _read_unlocked()
        for bot in payload["bots"]:
            if bot["id"] == bot_id and bot["owner_user_id"] == owner_user_id:
                bot["status"] = status; bot["updated_at"] = _now(); _write_unlocked(payload); return copy.deepcopy(bot)
    raise KeyError(bot_id)
