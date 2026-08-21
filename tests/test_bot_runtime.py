from __future__ import annotations

import sys


def test_start_and_stop_are_owner_scoped(tmp_path, monkeypatch):
    import api.bot_runtime as runtime
    import api.user_bots as bots

    monkeypatch.setattr(bots.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(runtime, "get_bot", bots.get_bot)
    monkeypatch.setattr(runtime, "_workers", {})
    created = bots.create_bot("owner-a", "Alpha")
    other = bots.create_bot("owner-b", "Beta")

    running = runtime.start_bot(
        "owner-a", created["id"],
        command=[sys.executable, "-c", "import time; time.sleep(30)"],
    )
    assert running["status"] == "running"
    assert runtime._workers[created["id"]].process.poll() is None

    try:
        try:
            runtime.stop_bot("owner-b", created["id"])
        except KeyError:
            pass
        else:
            raise AssertionError("cross-owner stop was accepted")
        stopped = runtime.stop_bot("owner-a", created["id"])
        assert stopped["status"] == "stopped"
    finally:
        runtime.stop_bot("owner-a", created["id"])
        assert other["owner_user_id"] == "owner-b"
