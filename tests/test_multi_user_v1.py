from __future__ import annotations

import json
import pytest


def test_bot_crud_is_owner_scoped_and_delete_cleans_home(tmp_path, monkeypatch):
    import api.user_bots as bots
    monkeypatch.setattr(bots.config, "STATE_DIR", tmp_path)
    first = bots.create_bot("owner-a", "Alpha")
    assert bots.get_bot(first["id"], "owner-b") is None
    renamed = bots.rename_bot(first["id"], "owner-a", "Renamed")
    assert renamed["name"] == "Renamed"
    with pytest.raises(KeyError): bots.rename_bot(first["id"], "owner-b", "Nope")
    home = tmp_path / "user_bots" / "owner-a" / first["id"]
    assert home.exists()
    bots.delete_bot(first["id"], "owner-a")
    assert not home.exists()
    assert bots.list_bots("owner-a") == []


def test_bot_store_rejects_traversal(tmp_path, monkeypatch):
    import api.user_bots as bots
    monkeypatch.setattr(bots.config, "STATE_DIR", tmp_path)
    with pytest.raises(ValueError): bots.create_bot("../outside", "Bad")


def test_bootstrap_local_admin_is_atomic_and_one_shot(tmp_path, monkeypatch):
    import api.auth_users as users
    monkeypatch.setattr(users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(users, "_validate_existing_profiles", lambda profiles, subject="": None)
    admin = users.bootstrap_local_admin_if_empty(username="Admin", display_name="Admin", password_hash=users.hash_password("a" * 12), profiles=["default"])
    assert admin["role"] == "admin"
    assert admin["username"] == "admin"
    assert users.bootstrap_local_admin_if_empty(username="other", display_name="Other", password_hash=users.hash_password("b" * 12), profiles=["default"]) is None
    stored = json.loads((tmp_path / ".auth_users.json").read_text())
    serialized = json.dumps(stored)
    assert "a" * 12 not in serialized
    assert "b" * 12 not in serialized
