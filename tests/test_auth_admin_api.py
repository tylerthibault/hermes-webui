from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

import api.auth as auth
import api.auth_users as auth_users
import api.routes as routes


class Handler:
    def __init__(
        self, body=None, *, cookie=None, origin="http://example.test",
        referer=None, sec_fetch_site=None, host="example.test",
    ):
        raw = json.dumps(body).encode() if body is not None else b""
        self.headers = {
            "Host": host,
            "Content-Length": str(len(raw)),
        }
        if origin is not None:
            self.headers["Origin"] = origin
        if referer is not None:
            self.headers["Referer"] = referer
        if sec_fetch_site is not None:
            self.headers["Sec-Fetch-Site"] = sec_fetch_site
        if cookie:
            self.headers["Cookie"] = f"hermes_session={cookie}"
        self.request = SimpleNamespace()
        self.client_address = ("203.0.113.10", 12345)
        self.rfile = io.BytesIO(raw)
        self.wfile = io.BytesIO()
        self.status = None
        self.sent_headers = []

    def send_response(self, status): self.status = status
    def send_header(self, key, value): self.sent_headers.append((key, value))
    def end_headers(self): pass

    @property
    def json(self): return json.loads(self.wfile.getvalue())


def parsed(path):
    return SimpleNamespace(path=path, query="")


def test_auth_status_adds_provider_capabilities_without_config_leak(monkeypatch):
    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "get_password_hash", lambda: "hash")
    monkeypatch.setattr("api.auth_oidc.is_google_enabled", lambda: True)
    monkeypatch.setattr("api.auth_github.is_github_enabled", lambda: False)
    monkeypatch.setattr("api.passkeys.registered_credentials", lambda: [])

    handler = Handler()
    assert routes.handle_get(handler, parsed("/api/auth/status")) is None
    assert handler.status == 200
    assert handler.json["password_auth_enabled"] is True
    assert handler.json["google_enabled"] is True
    assert handler.json["github_enabled"] is False
    serialized = json.dumps(handler.json).lower()
    assert "client_id" not in serialized and "secret" not in serialized


def _principal(role="admin"):
    return {
        "id": "user-1", "display_name": "Alice", "email": "alice@example.test",
        "role": role, "enabled": True, "profiles": ["alpha"],
        "identities": [{"provider": "google", "issuer": "secret-issuer", "subject": "secret-subject"}],
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-02T00:00:00Z",
        "last_login_at": "2026-01-02T00:00:00Z",
    }


def test_me_open_legacy_and_named_are_safe_and_live(monkeypatch):
    monkeypatch.setattr(routes, "_get_active_profile_name", lambda: "alpha")
    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    open_handler = Handler()
    routes.handle_get(open_handler, parsed("/api/auth/me"))
    assert open_handler.json == {
        "authenticated": False, "mode": "open", "user": None,
        "permissions": ["legacy-owner"], "profiles": None, "active_profile": "alpha",
    }

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "current_principal", lambda _handler: None)
    legacy = Handler()
    routes.handle_get(legacy, parsed("/api/auth/me"))
    assert legacy.json["mode"] == "legacy"
    assert legacy.json["user"] is None

    user = _principal(role="member")
    monkeypatch.setattr(auth, "current_principal", lambda _handler: user)
    monkeypatch.setattr(auth, "current_session_info", lambda _handler: {
        "provider": "google", "external_issuer": "do-not-return", "external_subject": "do-not-return"
    })
    monkeypatch.setattr("api.profiles.list_profiles_api", lambda **_kwargs: [
        {"name": "alpha"}, {"name": "deleted-live-grant"}, {"name": "hidden", "visible": False}
    ])
    monkeypatch.setattr(auth_users, "user_allows_profile", lambda principal, name: name == "alpha")
    named = Handler()
    routes.handle_get(named, parsed("/api/auth/me"))
    assert named.json["mode"] == "named"
    assert named.json["user"] == {
        "id": "user-1", "display_name": "Alice", "email": "alice@example.test",
        "role": "member", "provider": "google",
    }
    assert named.json["profiles"] == ["alpha"]
    assert named.json["permissions"] == sorted(named.json["permissions"])
    assert "issuer" not in json.dumps(named.json) and "subject" not in json.dumps(named.json)


def test_admin_user_list_is_named_admin_only_and_redacted(monkeypatch):
    monkeypatch.setattr(auth, "current_principal", lambda _handler: None)
    denied = Handler()
    routes.handle_get(denied, parsed("/api/admin/users"))
    assert denied.status == 403

    monkeypatch.setattr(auth, "current_principal", lambda _handler: _principal())
    monkeypatch.setattr(auth_users, "list_users", lambda: [_principal()])
    allowed = Handler()
    routes.handle_get(allowed, parsed("/api/admin/users"))
    assert allowed.status == 200
    assert allowed.json["users"][0]["providers"] == ["google"]
    output = json.dumps(allowed.json)
    assert "issuer" not in output and "subject" not in output and "last_login" not in output


def test_admin_can_create_local_user_without_returning_password(monkeypatch):
    monkeypatch.setattr(auth, "current_principal", lambda _handler: _principal())
    monkeypatch.setattr(routes, "_check_named_admin_origin", lambda _handler: True)
    captured = {}

    def create_local_user(**kwargs):
        captured.update(kwargs)
        return {**_principal(role="member"), "username": kwargs["username"], "password_hash": "secret-hash"}

    monkeypatch.setattr(auth_users, "create_local_user", create_local_user)
    handler = Handler({
        "username": "ada", "display_name": "Ada", "password": "long-enough-password",
        "role": "member", "email": "ada@example.test", "profiles": [],
    })
    routes.handle_post(handler, parsed("/api/admin/users"))
    assert handler.status == 201
    assert captured["username"] == "ada"
    assert captured["password_hash"].startswith("pbkdf2_sha256$")
    assert "password" not in json.dumps(handler.json).lower()


def test_admin_password_reset_requires_admin_and_returns_redacted_user(monkeypatch):
    monkeypatch.setattr(auth, "current_principal", lambda _handler: _principal())
    monkeypatch.setattr(routes, "_check_named_admin_origin", lambda _handler: True)
    captured = {}

    def reset_local_password(user_id, password_hash):
        captured.update(user_id=user_id, password_hash=password_hash)
        return {**_principal(role="member"), "id": user_id, "password_hash": password_hash}

    monkeypatch.setattr(auth_users, "reset_local_password", reset_local_password)
    handler = Handler({"password": "long-enough-password"})
    routes.handle_post(handler, parsed("/api/admin/users/user-2/password"))
    assert handler.status == 200
    assert captured["user_id"] == "user-2"
    assert captured["password_hash"].startswith("pbkdf2_sha256$")
    assert "password_hash" not in json.dumps(handler.json)


def test_member_bot_lifecycle_uses_authenticated_owner(monkeypatch):
    member = _principal(role="member")

    monkeypatch.setattr(auth, "current_principal", lambda _handler: member)
    monkeypatch.setattr(routes, "_check_csrf", lambda _handler: True)
    monkeypatch.setattr("api.bot_runtime.start_bot", lambda owner, bot_id: {"owner": owner, "id": bot_id, "status": "running"})
    monkeypatch.setattr("api.bot_runtime.stop_bot", lambda owner, bot_id: {"owner": owner, "id": bot_id, "status": "stopped"})

    start = Handler({})
    routes.handle_post(start, parsed("/api/user/bots/bot-1/start"))
    assert start.status == 200
    assert start.json["bot"] == {"owner": "user-1", "id": "bot-1", "status": "running"}

    stop = Handler({})
    routes.handle_post(stop, parsed("/api/user/bots/bot-1/stop"))
    assert stop.status == 200
    assert stop.json["bot"]["owner"] == "user-1"


def test_admin_patch_whitelist_errors_and_strict_origin(monkeypatch):
    monkeypatch.setattr(auth, "current_principal", lambda _handler: _principal())
    missing = Handler({"display_name": "Updated"}, origin=None)
    routes.handle_patch(missing, parsed("/api/admin/users/user-2"))
    assert missing.status == 403
    cross = Handler({"display_name": "Updated"}, origin="https://evil.test")
    routes.handle_patch(cross, parsed("/api/admin/users/user-2"))
    assert cross.status == 403

    forbidden = Handler({"email": "attacker@example.test"})
    routes.handle_patch(forbidden, parsed("/api/admin/users/user-2"))
    assert forbidden.status == 400
    empty = Handler({})
    routes.handle_patch(empty, parsed("/api/admin/users/user-2"))
    assert empty.status == 400

    monkeypatch.setattr(auth_users, "update_user", lambda user_id, body: {
        **_principal(role="member"), "id": user_id, **body
    })
    good = Handler({"enabled": False, "profiles": ["alpha"]})
    routes.handle_patch(good, parsed("/api/admin/users/user-2"))
    assert good.status == 200
    assert good.json["user"]["enabled"] is False


def test_admin_mutation_requires_matching_origin_or_referer(monkeypatch):
    monkeypatch.setattr(auth, "current_principal", lambda _handler: _principal())
    monkeypatch.setattr(auth_users, "update_user", lambda user_id, body: {
        **_principal(role="member"), "id": user_id, **body
    })

    no_provenance = Handler(
        {"display_name": "Updated"}, origin=None, sec_fetch_site="none"
    )
    routes.handle_patch(no_provenance, parsed("/api/admin/users/user-2"))
    assert no_provenance.status == 403

    post_without_provenance = Handler(
        {"provider": "google", "target": "person@example.test", "profiles": [],
         "expires_at": "2026-01-02T00:00:00Z"},
        origin=None, sec_fetch_site="same-origin",
    )
    routes.handle_post(post_without_provenance, parsed("/api/admin/invitations"))
    assert post_without_provenance.status == 403

    delete_without_provenance = Handler(origin=None, sec_fetch_site="none")
    routes.handle_delete(
        delete_without_provenance, parsed("/api/admin/invitations/invitation-1")
    )
    assert delete_without_provenance.status == 403

    matching_referer = Handler(
        {"display_name": "Updated"}, origin=None,
        referer="http://example.test/admin/users?tab=active",
    )
    routes.handle_patch(matching_referer, parsed("/api/admin/users/user-2"))
    assert matching_referer.status == 200

    hostile_origin = Handler(
        {"display_name": "Updated"}, origin="https://evil.test",
        referer="http://example.test/admin/users",
    )
    routes.handle_patch(hostile_origin, parsed("/api/admin/users/user-2"))
    assert hostile_origin.status == 403


@pytest.mark.parametrize("origin", [
    "https://example.test",
    "http://example.test:8080",
    "http://sub.example.test",
    "http://sibling.test",
    "http://user@example.test",
    "null",
    "http://example.test:bad",
    "http://example.test evil.test",
])
def test_admin_mutation_rejects_nonidentical_or_malformed_origins(monkeypatch, origin):
    monkeypatch.setattr(auth, "current_principal", lambda _handler: _principal())
    attempted = []
    monkeypatch.setattr(auth_users, "update_user", lambda *_args: attempted.append(True))
    handler = Handler({"display_name": "Updated"}, origin=origin)
    routes.handle_patch(handler, parsed("/api/admin/users/user-2"))
    assert handler.status == 403
    assert attempted == []


def test_admin_mutation_does_not_use_general_cors_allowlist(monkeypatch):
    monkeypatch.setenv("HERMES_WEBUI_ALLOWED_ORIGINS", "https://allowed.example")
    monkeypatch.setattr(auth, "current_principal", lambda _handler: _principal())
    handler = Handler(
        {"display_name": "Updated"}, origin="https://allowed.example"
    )
    routes.handle_patch(handler, parsed("/api/admin/users/user-2"))
    assert handler.status == 403


def test_admin_origin_normalizes_default_port_and_read_only_get_is_unaffected(monkeypatch):
    monkeypatch.setattr(auth, "current_principal", lambda _handler: _principal())
    monkeypatch.setattr(auth_users, "update_user", lambda user_id, body: {
        **_principal(role="member"), "id": user_id, **body
    })
    matching = Handler(
        {"display_name": "Updated"}, origin="http://example.test:80"
    )
    routes.handle_patch(matching, parsed("/api/admin/users/user-2"))
    assert matching.status == 200

    monkeypatch.setattr(auth_users, "list_users", lambda: [_principal()])
    read_only = Handler(origin="https://evil.test")
    routes.handle_get(read_only, parsed("/api/admin/users"))
    assert read_only.status == 200


def test_admin_origin_uses_forwarded_authority_only_from_trusted_proxy(monkeypatch):
    monkeypatch.setenv("HERMES_WEBUI_TRUST_FORWARDED_PROTO", "1")
    monkeypatch.setenv("HERMES_WEBUI_TRUST_FORWARDED_HOST", "1")
    monkeypatch.setattr(auth, "current_principal", lambda _handler: _principal())
    monkeypatch.setattr(auth_users, "update_user", lambda user_id, body: {
        **_principal(role="member"), "id": user_id, **body
    })

    trusted = Handler(
        {"display_name": "Updated"}, origin="https://public.example:8443",
        host="internal.example:8787",
    )
    trusted.client_address = ("127.0.0.1", 12345)
    trusted.headers["X-Forwarded-Proto"] = "https"
    trusted.headers["X-Forwarded-Host"] = "public.example:8443"
    routes.handle_patch(trusted, parsed("/api/admin/users/user-2"))
    assert trusted.status == 200

    untrusted = Handler(
        {"display_name": "Updated"}, origin="https://public.example:8443",
        host="internal.example:8787",
    )
    untrusted.headers["X-Forwarded-Proto"] = "https"
    untrusted.headers["X-Forwarded-Host"] = "public.example:8443"
    routes.handle_patch(untrusted, parsed("/api/admin/users/user-2"))
    assert untrusted.status == 403


def test_invitation_crud_uses_current_admin_and_safe_errors(monkeypatch):
    admin = _principal()
    monkeypatch.setattr(auth, "current_principal", lambda _handler: admin)
    captured = {}
    invitation = {
        "id": "opaque-invitation-id", "provider": "google", "target": "person@example.test",
        "profiles": ["alpha"], "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-02T00:00:00Z", "created_by": admin["id"],
    }
    def create_invitation(**kwargs):
        captured.update(kwargs)
        return invitation
    monkeypatch.setattr(auth_users, "create_invitation", create_invitation)
    created = Handler({
        "provider": "google", "target": "person@example.test", "profiles": ["alpha"],
        "expires_at": "2026-01-02T00:00:00Z",
    })
    routes.handle_post(created, parsed("/api/admin/invitations"))
    assert created.status == 201 and captured["created_by"] == admin["id"]

    bad_role = Handler({
        "provider": "google", "target": "person@example.test", "profiles": ["alpha"],
        "expires_at": "2026-01-02T00:00:00Z", "role": "admin",
    })
    routes.handle_post(bad_role, parsed("/api/admin/invitations"))
    assert bad_role.status == 400

    monkeypatch.setattr(auth_users, "list_invitations", lambda: [invitation])
    listed = Handler()
    routes.handle_get(listed, parsed("/api/admin/invitations"))
    assert listed.json == {"invitations": [invitation]}
    monkeypatch.setattr(auth_users, "revoke_invitation", lambda value: invitation if value == invitation["id"] else False)
    deleted = Handler()
    routes.handle_delete(deleted, parsed(f"/api/admin/invitations/{invitation['id']}"))
    assert deleted.status == 200 and deleted.json == {"ok": True}
    absent = Handler()
    routes.handle_delete(absent, parsed("/api/admin/invitations/absent"))
    assert absent.status == 404
