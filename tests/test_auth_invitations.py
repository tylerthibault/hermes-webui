from __future__ import annotations

import json
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest


GOOGLE_ISSUER = "https://accounts.google.com"
GITHUB_ISSUER = "https://github.com"


@pytest.fixture
def invitation_users(tmp_path, monkeypatch):
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    inventory = {"default", "team-one"}
    monkeypatch.setattr(
        auth_users.profiles_api,
        "list_profiles_api",
        lambda: [{"name": name} for name in sorted(inventory)],
    )
    monkeypatch.setattr(
        auth_users.profiles_api,
        "profiles_exist_uncached",
        lambda profile_ids: all(profile_id in inventory for profile_id in profile_ids),
    )
    auth_users._test_profile_inventory = inventory
    return auth_users


def _future(days=1):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat().replace(
        "+00:00", "Z"
    )


def _admin(users, *, enabled=True):
    user = users.upsert_external_user(
        "oidc",
        "https://admin.example",
        "admin-subject",
        "Admin",
        "admin@example.com",
        allow_create=True,
    )
    user = users.update_user(user["id"], role="admin")
    if not enabled:
        # A second viable admin is needed before disabling the creator.
        backup = users.upsert_external_user(
            "oidc", "https://admin.example", "backup", allow_create=True
        )
        users.update_user(backup["id"], role="admin")
        user = users.update_user(user["id"], enabled=False)
    return user


def _invite(users, admin, provider="google", target="person@example.com", **overrides):
    values = {
        "provider": provider,
        "target": target,
        "profiles": ["default", "team-one"],
        "created_by": admin["id"],
        "expires_at": _future(),
    }
    values.update(overrides)
    return users.create_invitation(**values)


def test_profile_existence_bypasses_stale_list_cache(tmp_path, monkeypatch):
    from api import profiles

    profile_dir = tmp_path / "profiles" / "team-one"
    profile_dir.mkdir(parents=True)
    monkeypatch.setattr(profiles, "_DEFAULT_HERMES_HOME", tmp_path)
    monkeypatch.setattr(profiles, "_is_isolated_profile_mode", lambda: False)
    monkeypatch.setattr(
        profiles,
        "list_profiles_api",
        lambda *, force_refresh=False: [{
            "name": "team-one", "path": str(profile_dir), "is_default": False,
        }],
    )

    assert profiles.profiles_exist_uncached(["team-one"]) is True
    profile_dir.rmdir()
    assert profiles.profiles_exist_uncached(["team-one"]) is False


def test_profile_existence_preserves_fresh_root_alias(tmp_path, monkeypatch):
    from api import profiles

    monkeypatch.setattr(profiles, "_DEFAULT_HERMES_HOME", tmp_path)
    monkeypatch.setattr(profiles, "_is_isolated_profile_mode", lambda: False)
    monkeypatch.setattr(
        profiles,
        "list_profiles_api",
        lambda *, force_refresh=False: [{
            "name": "renamed-root", "path": str(tmp_path), "is_default": True,
        }],
    )

    assert profiles.profiles_exist_uncached(["default", "renamed-root"]) is True


def test_v1_store_migrates_atomically_to_private_v3(invitation_users):
    users = invitation_users
    created = users.upsert_external_user(
        "oidc", "https://issuer.example", "known", allow_create=True
    )
    path = users.config.STATE_DIR / ".auth_users.json"
    path.write_text(json.dumps({"version": 1, "users": [created]}), encoding="utf-8")
    path.chmod(0o644)

    assert users.list_users() == [created]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload == {"version": 3, "users": [created], "invitations": []}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "payload",
    [
        {"version": 1, "users": [], "extra": []},
        {"version": 2, "users": []},
        {"version": 3, "users": [], "invitations": [{"id": "bad"}]},
        {"version": 2, "users": [], "invitations": [{"id": "bad"}]},
    ],
)
def test_unknown_or_malformed_store_shapes_fail_closed(invitation_users, payload):
    users = invitation_users
    path = users.config.STATE_DIR / ".auth_users.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(users.AuthUserStoreError):
        users.list_users()
    assert json.loads(path.read_text(encoding="utf-8")) == payload


def test_create_invitation_is_admin_member_only_validated_and_secret_free(invitation_users):
    users = invitation_users
    admin = _admin(users)

    invite = _invite(
        users,
        admin,
        target=" Person@Example.COM ",
    )

    assert invite["provider"] == "google"
    assert invite["target"] == "person@example.com"
    assert invite["profiles"] == ["default", "team-one"]
    assert invite["created_by"] == admin["id"]
    assert "role" not in invite
    assert invite == users.list_invitations()[0]
    payload = json.loads((users.config.STATE_DIR / ".auth_users.json").read_text())
    assert payload["version"] == 3
    assert payload["invitations"] == [invite]
    assert not ({"token", "secret", "client_secret", "role"} & set(invite))

    member = users.upsert_external_user(
        "oidc", "https://member.example", "member", allow_create=True
    )
    with pytest.raises(ValueError, match="admin"):
        _invite(users, member, target="other@example.com")
    with pytest.raises(ValueError, match="profile"):
        _invite(users, admin, target="other@example.com", profiles=["missing"])
    assert users.list_invitations() == [invite]


def test_create_rejects_bad_targets_expiry_duplicate_and_disabled_admin(invitation_users):
    users = invitation_users
    admin = _admin(users)
    _invite(users, admin)

    with pytest.raises(ValueError, match="duplicate|already"):
        _invite(users, admin, target="PERSON@example.COM")
    for target in ("", "not-email", "a @example.com"):
        with pytest.raises(ValueError, match="target|email"):
            _invite(users, admin, target=target)
    for target in ("0", "01", "-1", "abc", 123):
        with pytest.raises(ValueError, match="target|GitHub"):
            _invite(users, admin, provider="github", target=target)
    with pytest.raises(ValueError, match="30 days"):
        _invite(users, admin, target="later@example.com", expires_at=_future(31))
    with pytest.raises(ValueError, match="future"):
        _invite(users, admin, target="past@example.com", expires_at=_future(-1))

    disabled = _admin(users, enabled=False)
    with pytest.raises(ValueError, match="enabled admin"):
        _invite(users, disabled, target="disabled-admin@example.com")


def test_list_expiry_and_revoke_durably_garbage_collect_expired_records(invitation_users):
    users = invitation_users
    admin = _admin(users)
    active = _invite(users, admin)

    path = users.config.STATE_DIR / ".auth_users.json"
    payload = json.loads(path.read_text())
    expired = dict(active)
    expired["id"] = "expired-invitation-id"
    expired["created_at"] = (
        datetime.now(timezone.utc) - timedelta(days=2)
    ).isoformat().replace("+00:00", "Z")
    expired["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(days=1)
    ).isoformat().replace("+00:00", "Z")
    expired["target"] = "expired@example.com"
    payload["invitations"].append(expired)
    path.write_text(json.dumps(payload), encoding="utf-8")

    # Expired invitations are operational records, not audit history. Even an
    # include_expired listing may collect them rather than preserve history.
    assert users.list_invitations(include_expired=True) == [active]
    assert json.loads(path.read_text())["invitations"] == [active]
    revoked = users.revoke_invitation(active["id"])
    assert revoked == active
    assert users.revoke_invitation(active["id"]) is False
    assert users.list_invitations() == []


def test_failed_gc_write_preserves_prior_store(invitation_users, monkeypatch):
    users = invitation_users
    admin = _admin(users)
    active = _invite(users, admin)
    path = users.config.STATE_DIR / ".auth_users.json"
    payload = json.loads(path.read_text())
    expired = dict(active)
    expired.update({
        "id": "expired-invitation-id",
        "target": "expired@example.com",
        "created_at": _future(-2),
        "expires_at": _future(-1),
    })
    payload["invitations"].append(expired)
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = path.read_bytes()

    monkeypatch.setattr(
        users.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("gc write failed")),
    )
    with pytest.raises(OSError, match="gc write failed"):
        users.list_invitations()

    assert path.read_bytes() == before


def test_google_consumption_normalizes_email_and_creates_member(invitation_users):
    users = invitation_users
    admin = _admin(users)
    invite = _invite(users, admin, target="Person@Example.com")

    user = users.consume_invitation_and_create_user(
        "google",
        "person@example.COM",
        GOOGLE_ISSUER,
        "google-subject",
        "Person",
        "PERSON@example.com",
    )

    assert user["role"] == "member"
    assert user["enabled"] is True
    assert user["profiles"] == invite["profiles"]
    assert user["email"] == "person@example.com"
    assert user["identities"] == [
        {"provider": "google", "issuer": GOOGLE_ISSUER, "subject": "google-subject"}
    ]
    assert users.list_invitations(include_expired=True) == []


def test_deleted_profile_blocks_consumption_and_preserves_invitation(invitation_users):
    users = invitation_users
    admin = _admin(users)
    invite = _invite(users, admin, profiles=["team-one"])
    users._test_profile_inventory.remove("team-one")

    with pytest.raises(ValueError, match="profile"):
        users.consume_invitation_and_create_user(
            "google", "person@example.com", GOOGLE_ISSUER, "subject",
            "Person", "person@example.com",
        )

    assert users.list_invitations() == [invite]
    assert users.find_user_by_identity("google", GOOGLE_ISSUER, "subject") is None


def test_active_invitation_cap_rejects_without_dropping_active_records(
    invitation_users, monkeypatch
):
    users = invitation_users
    monkeypatch.setattr(users, "MAX_ACTIVE_INVITATIONS", 2)
    admin = _admin(users)
    first = _invite(users, admin, target="first@example.com")
    second = _invite(users, admin, target="second@example.com")

    with pytest.raises(ValueError, match="active invitation"):
        _invite(users, admin, target="third@example.com")

    assert users.list_invitations() == [first, second]


def test_expired_pruning_frees_cap_and_persists(invitation_users, monkeypatch):
    users = invitation_users
    monkeypatch.setattr(users, "MAX_ACTIVE_INVITATIONS", 1)
    admin = _admin(users)
    old = _invite(users, admin, target="old@example.com")
    path = users.config.STATE_DIR / ".auth_users.json"
    payload = json.loads(path.read_text())
    payload["invitations"][0]["created_at"] = _future(-2)
    payload["invitations"][0]["expires_at"] = _future(-1)
    path.write_text(json.dumps(payload))

    replacement = _invite(users, admin, target="new@example.com")

    assert replacement["target"] == "new@example.com"
    persisted = json.loads(path.read_text())["invitations"]
    assert persisted == [replacement]
    assert old["id"] not in {item["id"] for item in persisted}


def test_oversized_store_fails_before_json_parse(invitation_users, monkeypatch):
    users = invitation_users
    path = users.config.STATE_DIR / ".auth_users.json"
    path.write_bytes(b" " * (users.MAX_AUTH_STORE_BYTES + 1))
    called = False

    def unexpected_parse(_handle):
        nonlocal called
        called = True
        raise AssertionError("oversized auth store must not be parsed")

    monkeypatch.setattr(users.json, "load", unexpected_parse)
    with pytest.raises(users.AuthUserStoreError, match="too large"):
        users.list_users()
    assert called is False


@pytest.mark.parametrize(
    "issuer,subject,email",
    [
        ("https://evil.example", "sub", "person@example.com"),
        (GOOGLE_ISSUER, "", "person@example.com"),
        (GOOGLE_ISSUER, "sub", "other@example.com"),
    ],
)
def test_google_invalid_consumption_does_not_consume(invitation_users, issuer, subject, email):
    users = invitation_users
    admin = _admin(users)
    invite = _invite(users, admin)

    with pytest.raises(ValueError):
        users.consume_invitation_and_create_user(
            "google", "person@example.com", issuer, subject, "Person", email
        )
    assert users.list_invitations() == [invite]
    assert len(users.list_users()) == 1


def test_github_consumption_uses_exact_numeric_id_not_email(invitation_users):
    users = invitation_users
    admin = _admin(users)
    _invite(users, admin, provider="github", target="123")

    user = users.consume_invitation_and_create_user(
        "github", "123", GITHUB_ISSUER, "123", "Octocat", "optional@example.com"
    )
    assert user["role"] == "member"
    assert user["email"] == "optional@example.com"
    assert user["identities"] == [
        {"provider": "github", "issuer": GITHUB_ISSUER, "subject": "123"}
    ]


@pytest.mark.parametrize("issuer,subject", [("https://evil.example", "123"), (GITHUB_ISSUER, "0123"), (GITHUB_ISSUER, "124")])
def test_github_invalid_consumption_does_not_consume(invitation_users, issuer, subject):
    users = invitation_users
    admin = _admin(users)
    invite = _invite(users, admin, provider="github", target="123")

    with pytest.raises(ValueError):
        users.consume_invitation_and_create_user(
            "github", "123", issuer, subject, "Octocat", ""
        )
    assert users.list_invitations() == [invite]


def test_invitation_is_single_use_across_threads(invitation_users):
    users = invitation_users
    admin = _admin(users)
    _invite(users, admin)

    def consume(index):
        return users.consume_invitation_and_create_user(
            "google",
            "person@example.com",
            GOOGLE_ISSUER,
            f"subject-{index}",
            "Person",
            "person@example.com",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(consume, range(8)))

    created = [result for result in results if result is not None]
    assert len(created) == 1
    assert len(users.list_users()) == 2
    assert users.list_invitations(include_expired=True) == []


def test_failed_consume_write_preserves_invitation_and_users(invitation_users, monkeypatch):
    users = invitation_users
    admin = _admin(users)
    invite = _invite(users, admin)
    before = (users.config.STATE_DIR / ".auth_users.json").read_bytes()

    monkeypatch.setattr(users.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("write failed")))
    with pytest.raises(OSError, match="write failed"):
        users.consume_invitation_and_create_user(
            "google",
            "person@example.com",
            GOOGLE_ISSUER,
            "subject",
            "Person",
            "person@example.com",
        )

    path = users.config.STATE_DIR / ".auth_users.json"
    assert path.read_bytes() == before
    assert users.list_invitations() == [invite]
    assert users.find_user_by_identity("google", GOOGLE_ISSUER, "subject") is None


def test_invitation_is_single_use_across_processes(invitation_users):
    users = invitation_users
    if users.fcntl is None:
        pytest.skip("interprocess file locking is POSIX-only")
    admin = _admin(users)
    _invite(users, admin)
    code = """
import json, sys
from api import auth_users
auth_users.config.STATE_DIR = sys.argv[1]
auth_users.profiles_api.profiles_exist_uncached = lambda _ids: True
result = auth_users.consume_invitation_and_create_user(
    'google', 'person@example.com', auth_users.GOOGLE_ISSUER,
    sys.argv[2], 'Person', 'person@example.com')
print(json.dumps(result))
"""
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                code,
                str(users.config.STATE_DIR),
                f"process-{index}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(4)
    ]
    outputs = [process.communicate(timeout=30) for process in processes]
    assert all(process.returncode == 0 for process in processes), outputs
    results = [json.loads(stdout) for stdout, _stderr in outputs]
    assert sum(result is not None for result in results) == 1
    assert len(users.list_users()) == 2


def test_google_provider_admits_invited_verified_email_before_legacy_allowlist(
    invitation_users,
):
    from api import auth_oidc

    users = invitation_users
    admin = _admin(users)
    _invite(users, admin, target="Invited@Example.com", profiles=["team-one"])

    user = auth_oidc._admit_google_identity(
        {
            "sub": "invited-google-subject",
            "email": "INVITED@example.com",
            "email_verified": True,
            "name": "Invited Person",
        },
        {"auto_provision": False, "allow_emails": [], "allow_domains": []},
    )
    assert user["profiles"] == ["team-one"]
    assert user["role"] == "member"
    assert users.list_invitations() == []


def test_github_provider_admits_invited_numeric_id_before_legacy_allowlist(
    invitation_users,
):
    from api import auth_github

    users = invitation_users
    admin = _admin(users)
    _invite(users, admin, provider="github", target="987", profiles=["default"])

    user = auth_github._admit_github_identity(
        {"id": 987, "login": "invited-octocat", "email": "optional@example.com"},
        {
            "auto_provision": False,
            "allow_user_ids": [],
            "default_profiles": [],
        },
    )
    assert user["profiles"] == ["default"]
    assert user["role"] == "member"
    assert users.list_invitations() == []
