from __future__ import annotations

import json
import stat
from datetime import timedelta

import pytest


@pytest.fixture
def users(tmp_path, monkeypatch):
    import api.auth_users as auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(
        auth_users.profiles_api, "profiles_exist_uncached", lambda _profile_ids: True
    )
    return auth_users


def _create(users, subject="subject-1", **overrides):
    values = {
        "provider": "oidc",
        "issuer": "https://issuer.example",
        "subject": subject,
        "display_name": "Ada",
        "email": "ada@example.com",
        "allow_create": True,
    }
    values.update(overrides)
    return users.upsert_external_user(**values)


def test_external_identity_is_canonical_and_email_is_not_identity(users):
    ada = _create(users)
    same = users.upsert_external_user(
        provider="oidc",
        issuer="https://issuer.example",
        subject="subject-1",
        display_name="Ada Lovelace",
        email="new-address@example.com",
        allow_create=False,
    )
    other = _create(users, subject="subject-2", email="new-address@example.com")

    assert same["id"] == ada["id"]
    assert same["display_name"] == "Ada Lovelace"
    assert same["email"] == "new-address@example.com"
    assert other["id"] != ada["id"]
    assert users.find_user_by_identity("oidc", "https://issuer.example", "subject-1")["id"] == ada["id"]
    assert users.find_user_by_identity("other", "https://issuer.example", "subject-1") is None


def test_update_canonicalizes_identity_like_upsert_and_whitespace_cannot_duplicate_user(users):
    first = _create(users)
    second = _create(users, subject="subject-2")

    updated = users.update_user(
        second["id"],
        {
            "display_name": "  Grace Hopper  ",
            "identities": [
                {
                    "provider": "  oidc  ",
                    "issuer": "  https://issuer.example  ",
                    "subject": "  subject-2  ",
                }
            ],
        },
    )

    assert updated["display_name"] == "Grace Hopper"
    assert updated["identities"] == [
        {
            "provider": "oidc",
            "issuer": "https://issuer.example",
            "subject": "subject-2",
        }
    ]
    same = users.upsert_external_user(
        provider=" oidc ",
        issuer=" https://issuer.example ",
        subject=" subject-2 ",
        display_name="  Grace  ",
        allow_create=True,
    )
    assert same["id"] == second["id"]
    assert same["display_name"] == "Grace"
    assert len(users.list_users()) == 2
    with pytest.raises(ValueError, match="Duplicate identity"):
        users.update_user(
            second["id"],
            {
                "identities": [
                    {
                        "provider": " oidc ",
                        "issuer": " https://issuer.example ",
                        "subject": " subject-1 ",
                    }
                ]
            },
        )
    assert users.find_user_by_identity(" oidc ", " https://issuer.example ", " subject-1 ")["id"] == first["id"]


def test_external_user_is_only_auto_created_when_explicitly_allowed(users):
    assert users.upsert_external_user(
        provider="oidc",
        issuer="https://issuer.example",
        subject="unknown",
        display_name="Unknown",
        email="same@example.com",
        allow_create=False,
    ) is None
    assert users.list_users() == []

    created = _create(users)
    assert created["role"] == "member"
    assert created["enabled"] is True
    assert created["profiles"] == []
    assert created["last_login_at"] is not None


def test_store_is_versioned_private_atomic_shape_without_secrets(users):
    created = _create(users)
    path = users.config.STATE_DIR / ".auth_users.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["version"] == 3
    assert payload["users"] == [created]
    assert payload["invitations"] == []
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(users.config.STATE_DIR.glob(".auth_users.json.*.tmp"))
    forbidden = {"token", "secret", "password", "access_token", "refresh_token", "id_token"}
    assert forbidden.isdisjoint(payload["users"][0])
    assert forbidden.isdisjoint(payload["users"][0]["identities"][0])


def test_existing_store_permissions_are_corrected_on_read(users):
    created = _create(users)
    path = users.config.STATE_DIR / ".auth_users.json"
    path.chmod(0o644)

    assert users.list_users() == [created]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_existing_store_fails_closed_when_permissions_cannot_be_corrected(users, monkeypatch):
    _create(users)
    path = users.config.STATE_DIR / ".auth_users.json"
    path.chmod(0o644)

    def fail_fchmod(fd, mode):
        raise OSError("injected chmod failure")

    monkeypatch.setattr(users.os, "fchmod", fail_fchmod)
    with pytest.raises(users.AuthUserStoreError, match="injected chmod failure"):
        users.list_users()


def test_atomic_replace_failure_preserves_old_store_and_removes_temporary_file(users, monkeypatch):
    created = _create(users)
    path = users.config.STATE_DIR / ".auth_users.json"
    original_bytes = path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("injected replace failure")

    monkeypatch.setattr(users.os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected replace failure"):
        users.update_user(created["id"], {"display_name": "not persisted"})

    assert path.read_bytes() == original_bytes
    assert not list(users.config.STATE_DIR.glob(".auth_users.json.*.tmp"))


def test_user_ids_and_created_time_are_stable_across_updates_and_reload(users):
    created = _create(users)
    updated = users.update_user(created["id"], {"display_name": "Updated", "profiles": ["alpha"]})

    assert updated["id"] == created["id"]
    assert updated["created_at"] == created["created_at"]
    assert updated["updated_at"] >= created["updated_at"]
    assert users.get_user(created["id"]) == updated
    assert users.list_users() == [updated]


def test_update_rejects_unknown_fields_roles_bad_profiles_and_duplicate_identities(users):
    first = _create(users)
    second = _create(users, subject="subject-2")

    with pytest.raises(ValueError, match="Unknown update field"):
        users.update_user(first["id"], {"token": "do-not-store"})
    with pytest.raises(ValueError, match="role"):
        users.update_user(first["id"], {"role": "owner"})
    with pytest.raises(ValueError, match="profile"):
        users.update_user(first["id"], {"profiles": ["../escape"]})
    with pytest.raises(ValueError, match="Duplicate identity"):
        users.update_user(
            second["id"],
            {"identities": [{"provider": "oidc", "issuer": "https://issuer.example", "subject": "subject-1"}]},
        )


def test_cannot_disable_or_demote_last_enabled_admin(users):
    first = _create(users)
    # Bootstrap promotion is allowed while there are no enabled admins.
    admin = users.update_user(first["id"], {"role": "admin"})

    with pytest.raises(ValueError, match="last enabled admin"):
        users.update_user(admin["id"], {"enabled": False})
    with pytest.raises(ValueError, match="last enabled admin"):
        users.update_user(admin["id"], {"role": "member"})

    second = _create(users, subject="subject-2")
    users.update_user(second["id"], {"role": "admin"})
    demoted = users.update_user(admin["id"], {"role": "member", "enabled": False})
    assert demoted["role"] == "member"
    assert demoted["enabled"] is False


def test_cannot_remove_every_identity_from_last_enabled_admin(users):
    first = _create(users)
    admin = users.update_user(first["id"], {"role": "admin"})

    with pytest.raises(ValueError, match="last enabled admin"):
        users.update_user(admin["id"], {"identities": []})

    assert users.get_user(admin["id"])["identities"] == admin["identities"]

    second = _create(users, subject="subject-2")
    identityless_member = users.update_user(second["id"], {"identities": []})
    assert identityless_member["identities"] == []


@pytest.mark.parametrize(
    "updates",
    [
        {"identities": []},
        {"enabled": False},
        {"role": "member"},
    ],
    ids=["remove-identities", "disable", "demote"],
)
def test_identityless_admin_is_not_a_viable_backup_for_last_admin(users, updates):
    usable_admin = users.update_user(_create(users)["id"], {"role": "admin"})
    identityless_member = users.update_user(
        _create(users, subject="subject-2")["id"],
        {"identities": []},
    )

    identityless_admin = users.update_user(identityless_member["id"], {"role": "admin"})
    assert identityless_admin["enabled"] is True
    assert identityless_admin["identities"] == []

    with pytest.raises(ValueError, match="last enabled admin"):
        users.update_user(usable_admin["id"], updates)

    assert users.get_user(usable_admin["id"]) == usable_admin


def test_corrupt_or_invalid_existing_store_fails_closed(users):
    path = users.config.STATE_DIR / ".auth_users.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(users.AuthUserStoreError):
        users.list_users()
    with pytest.raises(users.AuthUserStoreError):
        _create(users)
    assert path.read_text(encoding="utf-8") == "not json"

    path.write_text(json.dumps({"version": 999, "users": []}), encoding="utf-8")
    with pytest.raises(users.AuthUserStoreError):
        users.list_users()


def test_store_rejects_boolean_version_and_malformed_ids_or_timestamps(users):
    created = _create(users)
    path = users.config.STATE_DIR / ".auth_users.json"
    path.write_text(
        json.dumps({"version": True, "users": [], "invitations": []}),
        encoding="utf-8",
    )
    with pytest.raises(users.AuthUserStoreError, match="version"):
        users.list_users()

    payload = {"version": 1, "users": [created]}
    payload["users"][0]["id"] = "not-a-uuid"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(users.AuthUserStoreError, match="user id"):
        users.list_users()

    payload["users"][0]["id"] = "f7cf4706-bb1b-4ff5-bd66-3fcb93586a80"
    payload["users"][0]["created_at"] = "yesterday"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(users.AuthUserStoreError, match="created_at"):
        users.list_users()


def test_permissions_and_profile_access_honor_enabled_role_assignments_and_root_alias(users, monkeypatch):
    member = _create(users)
    member = users.update_user(member["id"], {"profiles": ["default", "project_a"]})

    monkeypatch.setattr(users, "_profiles_match", lambda left, right: {left, right} == {"default", "renamed-root"} or left == right)
    assert users.user_allows_profile(member, "renamed-root") is True
    assert users.user_allows_profile(member, "project_a") is True
    assert users.user_allows_profile(member, "other") is False
    assert users.permissions_for_role("admin") > users.permissions_for_role("member")
    assert users.permissions_for_role("member")
    with pytest.raises(ValueError, match="role"):
        users.permissions_for_role("owner")

    disabled = users.update_user(member["id"], {"enabled": False})
    assert users.user_allows_profile(disabled, "default") is False


def test_remove_profile_assignments_updates_users_and_active_invitations_atomically(users):
    admin = users.update_user(_create(users)["id"], {"role": "admin", "profiles": ["alpha", "beta"]})
    member = users.update_user(_create(users, subject="subject-2")["id"], {"profiles": ["beta"]})
    users.create_invitation(
        "google",
        "invitee@example.com",
        profiles=["alpha", "beta"],
        created_by=admin["id"],
        expires_at=users._now_datetime() + timedelta(days=1),
    )

    users.remove_profile_assignments("alpha")

    assert users.get_user(admin["id"])["profiles"] == ["beta"]
    assert users.get_user(member["id"])["profiles"] == ["beta"]
    assert users.list_invitations()[0]["profiles"] == ["beta"]


def test_profile_assignment_cleanup_token_restores_only_exact_still_existing_records(users):
    admin = users.update_user(
        _create(users)["id"],
        {"role": "admin", "profiles": ["alpha", "beta"]},
    )
    unrelated = users.update_user(
        _create(users, subject="subject-2")["id"],
        {"profiles": ["beta"]},
    )
    invitation = users.create_invitation(
        "google",
        "invitee@example.com",
        profiles=["alpha", "beta"],
        created_by=admin["id"],
        expires_at=users._now_datetime() + timedelta(days=1),
    )

    token = users.remove_profile_assignments("alpha")
    assert token == {
        "profile_id": "alpha",
        "user_ids": [admin["id"]],
        "invitation_ids": [invitation["id"]],
    }

    # Simulate unrelated concurrent mutations after cleanup and before rollback.
    users.update_user(admin["id"], {"display_name": "Concurrent rename"})
    users.update_user(unrelated["id"], {"email": "concurrent@example.com"})
    users.restore_profile_assignments(token)

    restored = users.get_user(admin["id"])
    assert restored["display_name"] == "Concurrent rename"
    assert restored["profiles"] == ["beta", "alpha"]
    assert users.get_user(unrelated["id"])["email"] == "concurrent@example.com"
    assert users.get_user(unrelated["id"])["profiles"] == ["beta"]
    assert users.list_invitations()[0]["profiles"] == ["beta", "alpha"]


def test_profile_assignment_restore_requires_profile_to_exist(users, monkeypatch):
    admin = users.update_user(
        _create(users)["id"],
        {"role": "admin", "profiles": ["alpha"]},
    )
    token = users.remove_profile_assignments("alpha")
    monkeypatch.setattr(
        users.profiles_api,
        "profiles_exist_uncached",
        lambda _profile_ids: False,
    )

    with pytest.raises(ValueError, match="unavailable"):
        users.restore_profile_assignments(token)
    assert users.get_user(admin["id"])["profiles"] == []


def test_return_values_are_detached_from_persisted_state(users):
    created = _create(users)
    created["display_name"] = "tampered"
    created["identities"][0]["subject"] = "tampered"

    stored = users.list_users()[0]
    assert stored["display_name"] == "Ada"
    assert stored["identities"][0]["subject"] == "subject-1"
