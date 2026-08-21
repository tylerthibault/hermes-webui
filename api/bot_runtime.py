"""Dedicated subprocess runtime for one private Hermes bot."""
from __future__ import annotations
import atexit
import json
import os
import shlex
import threading
from pathlib import Path
from typing import Sequence
from api.bot_worker import BotWorker
from api.user_bots import get_bot, update_bot_status

_lock = threading.RLock()
_workers: dict[object, BotWorker] = {}


def configured_command() -> list[str]:
    raw = os.getenv("HERMES_WEBUI_BOT_COMMAND", "hermes").strip()
    try: value = json.loads(raw) if raw.startswith("[") else shlex.split(raw)
    except (TypeError, ValueError) as exc: raise RuntimeError("bot runtime command is invalid") from exc
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise RuntimeError("bot runtime command is invalid")
    if Path(value[0]).name.casefold() not in {"hermes", "hermes-agent"} and not os.getenv("HERMES_WEBUI_ALLOW_CUSTOM_BOT_COMMAND"):
        raise RuntimeError("bot runtime command must be the Hermes executable")
    return value


def _key(owner: str, bot: str) -> tuple[str, str]: return owner, bot


def start_bot(owner_user_id: str, bot_id: str, *, command: Sequence[str] | None = None) -> dict:
    bot = get_bot(bot_id, owner_user_id)
    if bot is None: raise KeyError(bot_id)
    key = _key(owner_user_id, bot_id)
    with _lock:
        worker = _workers.get(key)
        if worker is not None and worker.alive():
            return update_bot_status(bot_id, owner_user_id, "running")
        if worker is not None and worker.process is not None:
            update_bot_status(bot_id, owner_user_id, "error" if worker.process.returncode else "stopped")
        worker = BotWorker(bot, list(command) if command is not None else configured_command())
        try: worker.start()
        except Exception:
            update_bot_status(bot_id, owner_user_id, "error")
            raise
        _workers[key] = worker
        _workers[bot_id] = worker  # legacy in-process compatibility alias
        return update_bot_status(bot_id, owner_user_id, "running")


def stop_bot(owner_user_id: str, bot_id: str) -> dict:
    if get_bot(bot_id, owner_user_id) is None: raise KeyError(bot_id)
    key = _key(owner_user_id, bot_id)
    with _lock:
        worker = _workers.get(key)
        if worker is not None:
            worker.stop()
            _workers.pop(key, None)
            if _workers.get(bot_id) is worker: _workers.pop(bot_id, None)
        return update_bot_status(bot_id, owner_user_id, "stopped")


def reconcile_workers() -> None:
    with _lock:
        for key, worker in list(_workers.items()):
            if not isinstance(key, tuple) or worker.process is None or worker.process.poll() is None: continue
            owner, bot_id = key
            try: update_bot_status(bot_id, owner, "error" if worker.process.returncode else "stopped")
            except Exception: pass
            _workers.pop(key, None)
            if _workers.get(bot_id) is worker: _workers.pop(bot_id, None)


def shutdown_workers() -> None:
    with _lock:
        seen: set[int] = set()
        for worker in list(_workers.values()):
            if id(worker) in seen: continue
            seen.add(id(worker))
            try: worker.stop()
            except Exception: pass
        _workers.clear()

atexit.register(shutdown_workers)
