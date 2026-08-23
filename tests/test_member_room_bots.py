from api import member_rooms, user_bots


def test_owner_can_invite_owned_bot_and_adjust_participation(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(user_bots.config, "STATE_DIR", str(tmp_path))
    room = member_rooms.create_room("owner_1", kind="room", name="Family", participant_user_ids=["member_1"])
    bot = user_bots.create_bot("owner_1", "Finance")
    invited = member_rooms.invite_bot(room["id"], "owner_1", bot["id"], 70)
    assert invited["participant_type"] == "bot"
    assert invited["participation_level"] == 70
    updated = member_rooms.set_bot_participation(room["id"], "owner_1", bot["id"], participation_level=18)
    assert updated["participation_level"] == 18
    assert updated["active"] is True


def test_other_member_cannot_invite_owner_bot(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(user_bots.config, "STATE_DIR", str(tmp_path))
    room = member_rooms.create_room("owner_1", kind="room", name="Family", participant_user_ids=["member_1"])
    bot = user_bots.create_bot("owner_1", "Finance")
    try:
        member_rooms.invite_bot(room["id"], "member_1", bot["id"])
    except PermissionError:
        return
    raise AssertionError("non-owner invited a bot")
