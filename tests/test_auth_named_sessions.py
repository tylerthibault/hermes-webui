from __future__ import annotations

import io
import json
import time
from types import SimpleNamespace

import pytest

import api.auth as auth
import api.auth_users as auth_users
import api.profiles as profiles

OIDC_ISSUER = "https://issuer.example"
OIDC_SUBJECT = "subject-1"


class _Handler:
    def __init__(self, cookie: str | None = None):
        self.headers = {"Cookie": f"hermes_session={cookie}"} if cookie else {}
        self.request = SimpleNamespace()
        self.wfile = io.BytesIO()
        self.status = None
        self.sent_headers: list[tuple[str, str]] = []

    def send_response(self, status):
        self.status = status

    def send_header(self, name, value):
        self.sent_headers.append((name, value))

    def end_headers(self):
        pass


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(auth, "STATE_DIR", tmp_path)
    monkeypatch.setattr(auth, "_SESSIONS_FILE", tmp_path / ".sessions.json")
    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setenv("HERMES_WEBUI_OIDC_ISSUER", OIDC_ISSUER)
    monkeypatch.setattr(auth_users, "get_user", lambda _id: _user())
    monkeypatch.setattr(profiles, "profiles_exist_uncached", lambda _ids: True)
    monkeypatch.setattr(
        auth_users,
        "find_user_by_identity",
        lambda provider, issuer, subject: auth_users.get_user("user-1")
        if (provider, issuer, subject) == ("oidc", OIDC_ISSUER, OIDC_SUBJECT)
        else None,
    )
    auth._sessions.clear()
    profiles.clear_request_profile()
    yield
    auth._sessions.clear()
    profiles.clear_request_profile()


def _user(*, user_id="user-1", role="member", enabled=True, assigned=None, identities=None):
    return {
        "id": user_id,
        "display_name": "Alice",
        "email": "alice@example.test",
        "role": role,
        "enabled": enabled,
        "profiles": list(assigned or []),
        "identities": list(identities if identities is not None else [{
            "provider": "oidc", "issuer": OIDC_ISSUER, "subject": OIDC_SUBJECT,
        }]),
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "last_login_at": None,
    }


def _named_cookie(**kwargs):
    return auth.create_session(
        user_id="user-1", provider="oidc", auth_type="oidc",
        external_issuer=OIDC_ISSUER, external_subject=OIDC_SUBJECT, **kwargs
    )


def _request(cookie, path="/api/sessions"):
    handler = _Handler(cookie)
    result = auth.check_auth(handler, SimpleNamespace(path=path, query=""))
    return handler, result


def test_named_session_persists_only_identity_metadata_and_exposes_defaults():
    cookie = auth.create_session(
        user_id="user-1", provider="oidc",
        external_issuer=OIDC_ISSUER, external_subject=OIDC_SUBJECT,
    )
    token = cookie.split(".", 1)[0]

    stored = json.loads(auth._SESSIONS_FILE.read_text())[token]
    assert stored["user_id"] == "user-1"
    assert stored["provider"] == "oidc"
    assert "role" not in stored
    assert "profiles" not in stored
    assert auth.get_session_info(cookie) == {
        "token": token,
        "expiry": stored["expiry"],
        "user_id": "user-1",
        "provider": "oidc",
        "external_issuer": OIDC_ISSUER,
        "external_subject": OIDC_SUBJECT,
        "auth_type": None,
        "username": None,
        "bound_profile": None,
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"provider": "oidc"}, id="missing-user-id"),
        pytest.param({"provider": "oidc", "user_id": None}, id="null-user-id"),
        pytest.param({"provider": "oidc", "user_id": ""}, id="empty-user-id"),
        pytest.param({"provider": "oidc", "user_id": "   "}, id="blank-user-id"),
        pytest.param({"provider": "oidc", "user_id": 123}, id="non-string-user-id"),
        pytest.param({"user_id": "user-1"}, id="missing-provider"),
        pytest.param({"user_id": "user-1", "provider": "   "}, id="blank-provider"),
        pytest.param({"user_id": "user-1", "provider": 123}, id="non-string-provider"),
        pytest.param(
            {
                "user_id": "user-1",
                "provider": "oidc",
                "external_subject": OIDC_SUBJECT,
            },
            id="missing-external-issuer",
        ),
        pytest.param(
            {
                "user_id": "user-1",
                "provider": "oidc",
                "external_issuer": OIDC_ISSUER,
            },
            id="missing-external-subject",
        ),
        pytest.param(
            {
                "user_id": "user-1",
                "provider": "oidc",
                "external_issuer": "   ",
                "external_subject": OIDC_SUBJECT,
            },
            id="blank-external-issuer",
        ),
        pytest.param(
            {
                "user_id": "user-1",
                "provider": "oidc",
                "external_issuer": OIDC_ISSUER,
                "external_subject": 123,
            },
            id="non-string-external-subject",
        ),
    ],
)
def test_create_session_rejects_partial_or_malformed_named_identity(kwargs):
    with pytest.raises(ValueError, match="user_id, provider"):
        auth.create_session(**kwargs)

    assert auth._sessions == {}
    assert not auth._SESSIONS_FILE.exists()


def test_create_session_trims_named_identity_before_persisting():
    cookie = auth.create_session(
        user_id="  user-1  ", provider="  oidc  ",
        external_issuer=f"  {OIDC_ISSUER}  ", external_subject=f"  {OIDC_SUBJECT}  ",
    )
    token = cookie.split(".", 1)[0]

    assert auth._sessions[token]["user_id"] == "user-1"
    assert auth._sessions[token]["provider"] == "oidc"
    assert auth._sessions[token]["external_issuer"] == OIDC_ISSUER
    assert auth._sessions[token]["external_subject"] == OIDC_SUBJECT
    stored = json.loads(auth._SESSIONS_FILE.read_text())[token]
    assert stored["user_id"] == "user-1"
    assert stored["provider"] == "oidc"
    assert stored["external_issuer"] == OIDC_ISSUER
    assert stored["external_subject"] == OIDC_SUBJECT


@pytest.mark.parametrize("provider,issuer,subject", [
    ("google", "https://accounts.google.com", "google-subject"),
    ("github", "https://github.com", "123"),
])
@pytest.mark.parametrize("change", ["removed", "reassigned"])
def test_provider_identity_removal_or_reassignment_invalidates_live_session(
    monkeypatch, provider, issuer, subject, change
):
    identity = {"provider": provider, "issuer": issuer, "subject": subject}
    original = _user(identities=[identity])
    replacement = _user(user_id="user-2", identities=[identity])
    state = {"owner": original}
    monkeypatch.setattr(
        auth_users, "get_user", lambda user_id: original if user_id == "user-1" else None
    )
    monkeypatch.setattr(
        auth_users, "find_user_by_identity", lambda *_args: state["owner"]
    )
    cookie = auth.create_session(
        user_id="user-1", provider=provider,
        external_issuer=issuer, external_subject=subject,
    )
    token = cookie.split(".", 1)[0]

    original["identities"] = []
    state["owner"] = None if change == "removed" else replacement
    handler, allowed = _request(cookie)

    assert allowed is False
    assert handler.status == 401
    assert token not in auth._sessions


@pytest.mark.parametrize("field,value", [
    ("external_issuer", None),
    ("external_issuer", "https://attacker.example"),
    ("external_subject", None),
    ("external_subject", "   "),
    ("external_subject", "different-subject"),
])
def test_malformed_persisted_provider_identity_claims_fail_closed(field, value):
    cookie = _named_cookie()
    token = cookie.split(".", 1)[0]
    auth._sessions[token][field] = value

    handler, allowed = _request(cookie)

    assert allowed is False
    assert handler.status == 401
    assert token not in auth._sessions


_MISSING = object()


@pytest.mark.parametrize(
    "user_id",
    [
        pytest.param(_MISSING, id="missing"),
        pytest.param(None, id="null"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="blank"),
        pytest.param(123, id="non-string"),
    ],
)
@pytest.mark.parametrize("storage", ["memory", "persisted"])
def test_provider_marked_session_with_invalid_user_id_fails_401_and_is_invalidated(user_id, storage):
    cookie = auth.create_session()
    token = cookie.split(".", 1)[0]
    record = {"expiry": time.time() + 300, "provider": "oidc", "auth_type": "oidc"}
    if user_id is not _MISSING:
        record["user_id"] = user_id

    if storage == "memory":
        auth._sessions[token] = record
    else:
        auth._SESSIONS_FILE.write_text(json.dumps({token: record}))
        auth._sessions.clear()
        auth._sessions.update(auth._load_sessions())

    handler, allowed = _request(cookie)

    assert allowed is False
    assert handler.status == 401
    assert token not in auth._sessions
    assert auth.verify_session(cookie) is False


def test_legacy_session_info_gets_named_principal_defaults():
    cookie = auth.create_session()
    info = auth.get_session_info(cookie)
    assert info["user_id"] is None
    assert info["provider"] is None
    assert auth.current_principal(_Handler(cookie)) is None


@pytest.mark.parametrize("auth_type", ["password", "passkey", "trusted"])
def test_legacy_dict_without_named_identity_remains_valid(auth_type):
    cookie = auth.create_session()
    token = cookie.split(".", 1)[0]
    auth._sessions[token] = {"expiry": time.time() + 300, "auth_type": auth_type}

    assert auth.current_principal(_Handler(cookie)) is None
    assert auth.verify_session(cookie) is True
    assert token in auth._sessions


def test_deleted_disabled_and_corrupt_named_users_fail_closed_and_invalidate(monkeypatch):
    lookups = (
        lambda _id: None,
        lambda _id: _user(enabled=False),
        lambda _id: {"id": "broken"},
    )
    cookies = [_named_cookie() for _lookup in lookups]
    for cookie, lookup in zip(cookies, lookups):
        monkeypatch.setattr("api.auth_users.get_user", lookup)
        handler, allowed = _request(cookie)
        assert allowed is False
        assert handler.status == 401
        assert auth.verify_session(cookie) is False


def test_user_store_error_fails_closed_and_invalidates(monkeypatch):
    cookie = _named_cookie()
    monkeypatch.setattr("api.auth_users.get_user", lambda _id: (_ for _ in ()).throw(RuntimeError("corrupt")))
    handler, allowed = _request(cookie)
    assert allowed is False
    assert handler.status == 401
    assert auth.verify_session(cookie) is False


def test_role_and_profile_updates_take_effect_on_next_request(monkeypatch):
    state = {"user": _user(assigned=["alpha"])}
    monkeypatch.setattr("api.auth_users.get_user", lambda _id: state["user"])
    cookie = _named_cookie()

    handler = _Handler(cookie)
    assert auth.check_auth(handler, SimpleNamespace(path="/api/sessions", query="")) is True
    assert profiles.get_active_profile_name() == "alpha"
    auth.reset_trusted_auth_request_state(handler)
    profiles.clear_request_profile()

    state["user"] = _user(assigned=["beta"])
    assert auth.check_auth(handler, SimpleNamespace(path="/api/sessions", query="")) is True
    assert profiles.get_active_profile_name() == "beta"
    auth.reset_trusted_auth_request_state(handler)
    profiles.clear_request_profile()

    state["user"] = _user(role="admin", assigned=[])
    signed_other = auth.sign_profile_cookie_value("other", cookie)
    handler.headers["Cookie"] = f"hermes_session={cookie}; hermes_profile={signed_other}"
    assert auth.check_auth(handler, SimpleNamespace(path="/api/sessions", query="")) is True
    assert auth.current_principal(handler)["role"] == "admin"
    assert profiles.get_active_profile_name() == "other"


def test_missing_profile_never_inherits_global_and_selects_first_authorized(monkeypatch):
    monkeypatch.setattr("api.auth_users.get_user", lambda _id: _user(assigned=["beta", "alpha"]))
    monkeypatch.setattr(profiles, "_active_profile", "unrelated")
    cookie = _named_cookie()

    handler, allowed = _request(cookie)

    assert allowed is True
    assert profiles.get_active_profile_name() == "beta"
    pending = getattr(handler, "_pending_set_cookies", [])
    assert any(value.startswith("hermes_profile=beta.") for value in pending)


def test_named_member_is_denied_explicit_unauthorized_profile(monkeypatch):
    monkeypatch.setattr("api.auth_users.get_user", lambda _id: _user(assigned=["alpha"]))
    cookie = _named_cookie()
    signed = auth.sign_profile_cookie_value("beta", cookie)
    handler = _Handler(cookie)
    handler.headers["Cookie"] += f"; hermes_profile={signed}"

    assert auth.check_auth(handler, SimpleNamespace(path="/api/sessions", query="")) is False
    assert handler.status == 403
    assert auth.verify_session(cookie) is True


def test_named_member_with_deleted_assignment_is_denied_without_recreating_profile(monkeypatch):
    monkeypatch.setattr("api.auth_users.get_user", lambda _id: _user(assigned=["deleted"]))
    monkeypatch.setattr(profiles, "profiles_exist_uncached", lambda _ids: False)
    cookie = _named_cookie()

    handler, allowed = _request(cookie)

    assert allowed is False
    assert handler.status == 401
    assert auth.verify_session(cookie) is False


def test_named_member_with_no_profiles_is_forbidden(monkeypatch):
    monkeypatch.setattr("api.auth_users.get_user", lambda _id: _user(assigned=[]))
    handler, allowed = _request(_named_cookie())
    assert allowed is False
    assert handler.status == 403


def test_named_admin_can_access_any_explicit_profile(monkeypatch):
    monkeypatch.setattr("api.auth_users.get_user", lambda _id: _user(role="admin"))
    cookie = _named_cookie()
    signed = auth.sign_profile_cookie_value("anything", cookie)
    handler = _Handler(cookie)
    handler.headers["Cookie"] += f"; hermes_profile={signed}"

    assert auth.check_auth(handler, SimpleNamespace(path="/api/sessions", query="")) is True
    assert profiles.get_active_profile_name() == "anything"
    assert auth.principal_has_permission(auth.current_principal(handler), "users:write") is True
    assert auth.principal_has_permission(auth.current_principal(handler), "unknown") is False


def test_legacy_generic_and_trusted_bound_profile_remain_compatible(monkeypatch):
    generic = auth.create_session(auth_type="password")
    monkeypatch.setattr(auth, "is_trusted_auth_enabled", lambda: False)
    handler, allowed = _request(generic)
    assert allowed is True
    assert handler.status is None

    trusted = auth.create_session(auth_type="trusted", username="alice", bound_profile="ops")
    info = auth.get_session_info(trusted)
    profiles.set_request_profile("other")
    assert auth.trusted_session_allows_active_profile(info) is False
