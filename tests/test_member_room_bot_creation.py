from api import member_rooms, user_bots
import pytest


def test_create_shared_room_with_owned_bot_adds_bot_participant(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(user_bots.config, "STATE_DIR", str(tmp_path))
    bot = user_bots.create_bot("owner_1", "Alex")
    room = member_rooms.create_room("owner_1", kind="room", name="Chat with Alex", participant_user_ids=[], bot_ids=[bot["id"]])
    participants = member_rooms.list_participants(room["id"], "owner_1")
    assert any(p["participant_type"] == "bot" and p["participant_id"] == bot["id"] for p in participants)
    direct = member_rooms.create_room("owner_1", kind="direct", name="DM", participant_user_ids=["member_1"])
    with pytest.raises(ValueError):
        member_rooms.invite_bot(direct["id"], "owner_1", bot["id"])


def test_direct_room_rejects_bots_and_unowned_bot_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(user_bots.config, "STATE_DIR", str(tmp_path))
    bot = user_bots.create_bot("owner_1", "Alex")
    try:
        member_rooms.create_room("owner_1", kind="direct", name="No bot", participant_user_ids=["member_1"], bot_ids=[bot["id"]])
    except ValueError:
        pass
    else:
        raise AssertionError("direct room accepted a bot")
    try:
        member_rooms.create_room("owner_2", kind="room", name="No access", participant_user_ids=[], bot_ids=[bot["id"]])
    except KeyError:
        pass
    else:
        raise AssertionError("room accepted another user's bot")


def test_create_room_rejects_non_list_participants(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", str(tmp_path))
    try:
        member_rooms.create_room("owner_1", kind="room", name="Bad", participant_user_ids="member_1", bot_ids=[])
    except ValueError:
        pass
    else:
        raise AssertionError("string participant list was accepted")
