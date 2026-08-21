from __future__ import annotations

import os
import sys
import time

import pytest


@pytest.fixture
def worker(tmp_path):
    import api.bot_worker as bot_worker
    bot = {
        "id": "bot-1",
        "owner_user_id": "user-1",
        "home": str(tmp_path / "user-1" / "bot-1"),
    }
    return bot_worker, bot


def test_worker_uses_private_home_and_does_not_mutate_parent_environment(worker, monkeypatch):
    bot_worker, bot = worker
    before = os.environ.get("HERMES_HOME")
    monkeypatch.setenv("WEBUI_TEST_SECRET", "must-not-inherit")
    command = [sys.executable, "-c", "import os,time; open('env-check','w').write(os.getenv('WEBUI_TEST_SECRET','')); time.sleep(30)"]

    instance = bot_worker.BotWorker(bot, command)
    instance.start()
    try:
        assert instance.process is not None
        assert instance.home == os.path.realpath(bot["home"])
        assert instance.process.poll() is None
        assert os.environ.get("HERMES_HOME") == before
        assert os.path.isdir(instance.home)
        assert os.path.isdir(os.path.join(instance.home, "sessions"))
        assert os.path.isdir(os.path.join(instance.home, "memories"))
        assert os.path.isdir(os.path.join(instance.home, "workspace"))
        assert os.path.isdir(os.path.join(instance.home, "credentials"))
    finally:
        instance.stop()


def test_workers_for_different_bots_have_distinct_homes(tmp_path):
    from api.bot_worker import BotWorker

    bots = [
        {"id": "bot-a", "owner_user_id": "user-a", "home": str(tmp_path / "a")},
        {"id": "bot-b", "owner_user_id": "user-b", "home": str(tmp_path / "b")},
    ]
    workers = [BotWorker(bot, [sys.executable, "-c", "import time; time.sleep(30)"]) for bot in bots]
    for item in workers:
        item.start()
    try:
        assert workers[0].home != workers[1].home
        assert workers[0].process.pid != workers[1].process.pid
    finally:
        for item in workers:
            item.stop()
