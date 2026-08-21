from __future__ import annotations

import pytest


@pytest.fixture
def bots(tmp_path, monkeypatch):
    import api.user_bots as user_bots
    monkeypatch.setattr(user_bots.config, "STATE_DIR", tmp_path)
    return user_bots


def test_bots_are_owner_scoped_and_have_private_homes(bots):
    first = bots.create_bot("user-a", "Research")
    second = bots.create_bot("user-b", "Research")

    assert bots.list_bots("user-a") == [first]
    assert bots.list_bots("user-b") == [second]
    assert first["home"] != second["home"]
    assert first["owner_user_id"] == "user-a"
    assert bots.get_bot(second["id"], "user-a") is None


def test_duplicate_names_are_only_rejected_within_owner(bots):
    bots.create_bot("user-a", "Research")
    with pytest.raises(ValueError, match="already exists"):
        bots.create_bot("user-a", " research ")
    assert bots.create_bot("user-b", "Research")["name"] == "Research"


def test_status_updates_cannot_cross_owner_boundary(bots):
    bot = bots.create_bot("user-a", "Writer")
    with pytest.raises(KeyError):
        bots.update_bot_status(bot["id"], "user-b", "running")
    assert bots.update_bot_status(bot["id"], "user-a", "running")["status"] == "running"
