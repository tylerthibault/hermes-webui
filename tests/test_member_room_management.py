from api import member_rooms


def test_owner_can_manage_room_members_and_rename(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", str(tmp_path))
    direct = member_rooms.create_room("owner_1", kind="direct", name="Member", participant_user_ids=["member_1"])
    direct_again = member_rooms.create_room("member_1", kind="direct", name="Other", participant_user_ids=["owner_1"])
    assert direct_again["id"] == direct["id"]
    for operation in (
        lambda: member_rooms.add_member(direct["id"], "owner_1", "member_2"),
        lambda: member_rooms.remove_member(direct["id"], "owner_1", "member_1"),
        lambda: member_rooms.rename_room(direct["id"], "owner_1", "Renamed"),
    ):
        try:
            operation()
        except ValueError:
            pass
        else:
            raise AssertionError("direct room accepted shared-room management")
    room = member_rooms.create_room("owner_1", kind="room", name="Family", participant_user_ids=["member_1"])
    added = member_rooms.add_member(room["id"], "owner_1", "member_2")
    assert added["participant_id"] == "member_2"
    renamed = member_rooms.rename_room(room["id"], "owner_1", "Family planning")
    assert renamed["name"] == "Family planning"
    member_rooms.remove_member(room["id"], "owner_1", "member_1")
    assert not member_rooms.user_is_member(room["id"], "member_1")


def test_non_owner_cannot_manage_members_and_owner_cannot_leave(tmp_path, monkeypatch):
    monkeypatch.setattr(member_rooms.config, "STATE_DIR", str(tmp_path))
    room = member_rooms.create_room("owner_1", kind="room", name="Family", participant_user_ids=["member_1"])
    try:
        member_rooms.add_member(room["id"], "member_1", "member_2")
    except PermissionError:
        pass
    else:
        raise AssertionError("non-owner managed members")
    try:
        member_rooms.leave_room(room["id"], "owner_1")
    except ValueError:
        pass
    else:
        raise AssertionError("owner left room")
