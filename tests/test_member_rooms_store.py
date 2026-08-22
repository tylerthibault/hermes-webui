import json
from pathlib import Path

import pytest

from api import member_rooms


def test_direct_room_defaults_to_orchestrator_off(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", tmp_path)
    room = member_rooms.create_room("u1", kind="direct", name="", participant_user_ids=["u2"])
    assert room["orchestrator_enabled"] is False
    assert {p["participant_id"] for p in member_rooms.list_participants(room["id"])} == {"u1", "u2"}


def test_shared_room_can_enable_orchestrator_and_owner_can_disable(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", tmp_path)
    room = member_rooms.create_room("u1", kind="room", name="Family", participant_user_ids=["u2"], orchestrator_enabled=True)
    assert room["orchestrator_enabled"] is True
    member_rooms.set_orchestrator(room["id"], False)
    assert member_rooms.get_room(room["id"])["orchestrator_enabled"] is False


def test_non_member_cannot_read_or_write_room(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", tmp_path)
    room = member_rooms.create_room("u1", kind="room", name="Private", participant_user_ids=[])
    assert member_rooms.user_is_member(room["id"], "u2") is False
    with pytest.raises(KeyError):
        member_rooms.add_message(room["id"], "u2", "no")
    assert member_rooms.list_messages(room["id"], "u2") == []


def test_message_persists(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", tmp_path)
    room = member_rooms.create_room("u1", kind="direct", name="", participant_user_ids=["u2"])
    message = member_rooms.add_message(room["id"], "u1", "Hello")
    assert member_rooms.list_messages(room["id"], "u2")[0]["id"] == message["id"]
    payload = json.loads((tmp_path / ".member_rooms.json").read_text())
    assert payload["rooms"][0]["id"] == room["id"]
