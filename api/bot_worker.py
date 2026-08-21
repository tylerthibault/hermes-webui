"""Subprocess boundary for one private Hermes bot runtime."""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from typing import Sequence

_REQUIRED_DIRS = ("sessions", "memories", "skills", "cron", "workspace", "credentials")


class BotWorker:
    """Own one bot subprocess and give it an isolated Hermes home."""

    def __init__(self, bot: dict, command: Sequence[str]) -> None:
        if not isinstance(bot, dict):
            raise ValueError("bot must be a mapping")
        if not isinstance(command, (list, tuple)) or not command or not all(isinstance(item, str) and item for item in command):
            raise ValueError("worker command must be a non-empty argument list")
        home = Path(str(bot.get("home") or "")).expanduser().resolve()
        owner_id = str(bot.get("owner_user_id") or "").strip()
        bot_id = str(bot.get("id") or "").strip()
        if not owner_id or not bot_id or not str(bot.get("home") or "").strip():
            raise ValueError("bot identity and home are required")
        self.bot = dict(bot)
        self.command = list(command)
        self.home = str(home)
        self.process: subprocess.Popen | None = None

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def _prepare_home(self) -> None:
        home = Path(self.home)
        home.mkdir(parents=True, exist_ok=True)
        if home.is_symlink():
            raise ValueError("bot home may not be a symlink")
        for name in _REQUIRED_DIRS:
            child = home / name
            if child.exists() and child.is_symlink():
                raise ValueError("bot runtime directories may not be symlinks")
            child.mkdir(exist_ok=True)
        os.chmod(home, 0o700)
        for name in _REQUIRED_DIRS:
            os.chmod(home / name, 0o700)

    def start(self) -> subprocess.Popen:
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("bot worker is already running")
        self._prepare_home()
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"}
        }
        env["HERMES_HOME"] = self.home
        env["HOME"] = self.home
        env["TMPDIR"] = str(Path(self.home) / "tmp")
        Path(env["TMPDIR"]).mkdir(exist_ok=True)
        env["HERMES_BOT_ID"] = str(self.bot["id"])
        env["HERMES_BOT_OWNER_ID"] = str(self.bot["owner_user_id"])
        self.process = subprocess.Popen(
            self.command,
            cwd=self.home,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
            close_fds=True,
        )
        return self.process

    def stop(self, timeout: float = 5.0) -> None:
        process = self.process
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=timeout)
        finally:
            self.process = None
