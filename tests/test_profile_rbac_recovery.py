from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

import api.auth as auth
import api.routes as routes


class _Handler:
    def __init__(self, command="GET"):
        self.command = command
        self.path = "/api/sessions"
        self.headers = {}
        self.wfile = io.BytesIO()
        self.status = None

    def send_response(self, status):
        self.status = status

    def send_header(self, _key, _value):
        pass

    def end_headers(self):
        pass


def _named_auth(monkeypatch, role="member"):
    principal = {"id": "user-1", "enabled": True, "role": role, "profiles": ["alpha"]}
    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "parse_cookie", lambda _handler: "cookie")
    monkeypatch.setattr(auth, "verify_session", lambda _cookie: True)
    monkeypatch.setattr(
        auth,
        "get_session_info",
        lambda _cookie: {
            "user_id": "user-1",
            "provider": "oidc",
            "external_issuer": "issuer",
            "external_subject": "subject",
        },
    )
    monkeypatch.setattr(auth, "current_principal", lambda _handler: principal)
    return principal


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " ON "])
def test_named_member_truthy_all_profiles_query_is_forbidden_before_profile_side_effects(monkeypatch, value):
    _named_auth(monkeypatch)
    monkeypatch.setattr(
        auth,
        "_apply_named_principal_profile",
        lambda *_args: (_ for _ in ()).throw(AssertionError("profile side effect ran")),
    )
    handler = _Handler()

    assert auth.check_auth(
        handler,
        SimpleNamespace(path="/api/sessions", query=f"all_profiles={value}"),
    ) is False
    assert handler.status == 403
    assert handler.wfile.getvalue() == b'{"error":"Forbidden"}'


def test_named_admin_and_legacy_keep_all_profiles_query(monkeypatch):
    _named_auth(monkeypatch, role="admin")
    monkeypatch.setattr(auth, "_apply_named_principal_profile", lambda *_args: True)
    assert auth.check_auth(
        _Handler(), SimpleNamespace(path="/api/sessions", query="all_profiles=yes")
    ) is True

    monkeypatch.setattr(auth, "get_session_info", lambda _cookie: {"auth_type": "password"})
    monkeypatch.setattr(auth, "ensure_trusted_auth_session", lambda _handler: {"auth_type": "password"})
    monkeypatch.setattr(auth, "trusted_session_allows_active_profile", lambda _info: True)
    assert auth.check_auth(
        _Handler(), SimpleNamespace(path="/api/sessions", query="all_profiles=yes")
    ) is True


@pytest.mark.parametrize("value", [True, 1, "1", "true", "yes", "on"])
def test_named_member_import_rejects_all_profiles_before_any_session_read(monkeypatch, value):
    monkeypatch.setattr(auth, "current_principal", lambda _handler: {"enabled": True, "role": "member"})
    monkeypatch.setattr(routes, "_get_active_profile_name", lambda: "alpha")
    monkeypatch.setattr(
        routes.Session,
        "load",
        staticmethod(lambda _sid: (_ for _ in ()).throw(AssertionError("session metadata read"))),
    )
    handler = _Handler(command="POST")

    routes._handle_session_import_cli(
        handler,
        {"session_id": "foreign-session", "all_profiles": value, "profile": "beta"},
    )

    assert handler.status == 403


def test_named_member_import_rejects_foreign_body_profile_before_existing_session_read(monkeypatch):
    monkeypatch.setattr(auth, "current_principal", lambda _handler: {"enabled": True, "role": "member"})
    monkeypatch.setattr(routes, "_get_active_profile_name", lambda: "alpha")
    monkeypatch.setattr(
        routes.Session,
        "load",
        staticmethod(lambda _sid: (_ for _ in ()).throw(AssertionError("existing session read"))),
    )
    handler = _Handler(command="POST")

    routes._handle_session_import_cli(
        handler,
        {"session_id": "already-imported", "profile": "beta"},
    )

    assert handler.status == 403
    assert b"beta" not in handler.wfile.getvalue()
    assert b"already-imported" not in handler.wfile.getvalue()


def test_profile_delete_cleanup_write_failure_never_calls_irreversible_delete(monkeypatch):
    calls = []
    monkeypatch.setattr(
        routes,
        "_stage_profile_grant_cleanup",
        lambda _name: (_ for _ in ()).throw(RuntimeError("cleanup write failed")),
        raising=False,
    )
    monkeypatch.setattr(
        routes,
        "_delete_profile_filesystem",
        lambda _name: calls.append("delete"),
        raising=False,
    )

    with pytest.raises(RuntimeError, match="cleanup write failed"):
        routes._delete_profile_with_grant_cleanup("alpha")
    assert calls == []


def test_profile_delete_failure_restores_grants_and_success_does_not_rollback(monkeypatch):
    token = {"profile_id": "alpha", "user_ids": ["u1"], "invitation_ids": ["i1"]}
    calls = []
    monkeypatch.setattr(routes, "_stage_profile_grant_cleanup", lambda _name: calls.append("cleanup") or token, raising=False)
    monkeypatch.setattr(routes, "_restore_profile_grants", lambda value: calls.append(("restore", value)), raising=False)
    monkeypatch.setattr(
        routes,
        "_delete_profile_filesystem",
        lambda _name: (_ for _ in ()).throw(RuntimeError("delete failed")),
        raising=False,
    )

    with pytest.raises(RuntimeError, match="delete failed"):
        routes._delete_profile_with_grant_cleanup("alpha")
    assert calls == ["cleanup", ("restore", token)]

    calls.clear()
    monkeypatch.setattr(routes, "_delete_profile_filesystem", lambda _name: calls.append("delete") or {"ok": True}, raising=False)
    assert routes._delete_profile_with_grant_cleanup("alpha") == {"ok": True}
    assert calls == ["cleanup", "delete"]
