from __future__ import annotations

import json

import pytest


@pytest.fixture
def users(tmp_path, monkeypatch):
    import api.auth_users as auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(
        auth_users.profiles_api, "profiles_exist_uncached", lambda _profile_ids: True
    )
    return auth_users


def test_create_local_user_normalizes_username_and_stores_no_plaintext(users):
    user = users.create_local_user(
        username="  Ada.Example  ",
        display_name="Ada",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$hash",
    )

    assert user["username"] == "ada.example"
    assert user["display_name"] == "Ada"
    assert user["password_hash"].startswith("$argon2id$")
    assert user["enabled"] is True
    assert user["failed_login_count"] == 0
    assert user["session_revocation_version"] == 0

    payload = json.loads((users.config.STATE_DIR / ".auth_users.json").read_text())
    assert payload["users"][0]["username"] == "ada.example"
    assert "password_hash" in payload["users"][0]
    assert "  Ada.Example  " not in json.dumps(payload)


def test_local_user_lookup_is_case_and_whitespace_insensitive(users):
    created = users.create_local_user(
        username="Grace.Hopper",
        display_name="Grace",
        password_hash="hash",
    )

    found = users.find_user_by_username("  GRACE.HOPPER  ")

    assert found["id"] == created["id"]


def test_duplicate_local_username_is_rejected(users):
    users.create_local_user(username="ada", display_name="Ada", password_hash="hash")

    with pytest.raises(ValueError, match="username"):
        users.create_local_user(username=" ADA ", display_name="Other", password_hash="hash2")


def test_local_user_login_state_can_be_updated(users):
    created = users.create_local_user(username="ada", display_name="Ada", password_hash="hash")

    failed = users.record_login_failure(created["id"])
    succeeded = users.record_login_success(created["id"])
    revoked = users.increment_session_revocation(created["id"])

    assert failed["failed_login_count"] == 1
    assert succeeded["failed_login_count"] == 0
    assert succeeded["last_login_at"] is not None
    assert revoked["session_revocation_version"] == 1


def test_admin_password_reset_replaces_hash_and_revokes_sessions(users):
    created = users.create_local_user(
        username="ada",
        display_name="Ada",
        password_hash=users.hash_password("old-secret-123"),
    )

    updated = users.reset_local_password(
        created["id"], users.hash_password("new-secret-456")
    )

    assert updated["password_hash"] != created["password_hash"]
    assert updated["session_revocation_version"] == 1
    assert users.verify_password("new-secret-456", updated["password_hash"])
    assert not users.verify_password("old-secret-123", updated["password_hash"])


def test_local_password_adapter_uses_persisted_hash(users):
    password_hash = users.hash_password("correct-password-123")
    assert users.verify_local_password("correct-password-123", password_hash)
    assert not users.verify_local_password("wrong-password-123", password_hash)


def test_external_users_receive_empty_local_credential_fields(users):
    created = users.upsert_external_user(
        provider="oidc",
        issuer="https://issuer.example",
        subject="subject-1",
        display_name="Ada",
        email="ada@example.com",
        allow_create=True,
    )

    assert created["username"] is None
    assert created["password_hash"] is None
    assert created["failed_login_count"] == 0
    assert created["session_revocation_version"] == 0
