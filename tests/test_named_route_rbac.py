from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

import api.auth as auth


@pytest.mark.parametrize(
    ("method", "path", "permission"),
    [
        ("GET", "/api/admin/users?offset=1", "users:manage"),
        ("DELETE", "/api/admin/", "users:manage"),
        ("GET", "/api/settings", "settings:manage"),
        ("GET", "/api/providers/oauth", "providers:manage"),
        ("POST", "/api/default-model", "models:write"),
        ("POST", "/api/profile/delete", "profiles:write"),
        ("POST", "/api/auth/passkey/register/options", "passkeys:manage"),
        ("POST", "/api/updates/clear_lock", "updates:write"),
        ("GET", "/api/onboarding/oauth/poll", "onboarding:write"),
        ("PATCH", "/api/mcp/servers/example", "mcp:manage"),
        ("POST", "/api/extensions/sidecar-proxy-consent", "extensions:manage"),
        ("POST", "/api/gateway/restart", "gateway:manage"),
    ],
)
def test_required_named_permission_matrix(method, path, permission):
    assert auth.required_named_permission(method, path) == permission


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/administer"),
        ("GET", "/api/auth/google/start"),
        ("POST", "/api/auth/passkey/login"),
        ("POST", "/api/chat/start"),
        ("POST", "/api/crons/create"),
        ("GET", "/api/mcp/tools"),
        ("GET", "/api/default-model"),
    ],
)
def test_required_named_permission_does_not_overreach(method, path):
    assert auth.required_named_permission(method, path) is None


class _Handler:
    def __init__(self, command="POST"):
        self.command = command
        self.path = "/api/settings"
        self.wfile = io.BytesIO()
        self.status = None
        self.headers_sent = []

    def send_response(self, status):
        self.status = status

    def send_header(self, key, value):
        self.headers_sent.append((key, value))

    def end_headers(self):
        pass


def _stub_authenticated(monkeypatch, principal):
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


def test_named_member_rbac_denies_before_profile_or_route_side_effects(monkeypatch):
    principal = {"enabled": True, "role": "member"}
    _stub_authenticated(monkeypatch, principal)
    monkeypatch.setattr(
        auth,
        "_apply_named_principal_profile",
        lambda *_args: (_ for _ in ()).throw(AssertionError("profile side effect ran")),
    )
    handler = _Handler()

    assert auth.check_auth(handler, SimpleNamespace(path="/api/settings", query="")) is False
    assert handler.status == 403
    assert handler.wfile.getvalue() == b'{"error":"Forbidden"}'


def test_named_admin_wildcard_and_legacy_session_remain_allowed(monkeypatch):
    admin = {"enabled": True, "role": "admin"}
    _stub_authenticated(monkeypatch, admin)
    called = []
    monkeypatch.setattr(auth, "_apply_named_principal_profile", lambda *_args: called.append(True) or True)
    assert auth.check_auth(_Handler(), SimpleNamespace(path="/api/settings", query="")) is True
    assert called == [True]

    monkeypatch.setattr(auth, "get_session_info", lambda _cookie: {"auth_type": "password"})
    monkeypatch.setattr(auth, "ensure_trusted_auth_session", lambda _handler: {"auth_type": "password"})
    monkeypatch.setattr(auth, "trusted_session_allows_active_profile", lambda _info: True)
    assert auth.check_auth(_Handler(), SimpleNamespace(path="/api/settings", query="")) is True
