import io
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest


GOOGLE_ISSUER = "https://accounts.google.com"


@pytest.fixture
def isolated_users(monkeypatch, tmp_path):
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    return auth_users


def _google_config(**overrides):
    config = {
        "issuer": GOOGLE_ISSUER,
        "client_id": "google-client",
        "client_secret": "secret",
        "redirect_uri": "",
        "scopes": ["openid", "profile", "email"],
        "allow_emails": ["allowed@example.com"],
        "allow_domains": ["example.org"],
        "auto_provision": False,
        "default_profiles": ["default", "team-one"],
    }
    config.update(overrides)
    return config


def test_google_config_is_fixed_and_env_is_supported(monkeypatch):
    import api.auth_oidc as oidc

    monkeypatch.setattr(
        oidc,
        "get_config",
        lambda: {
            "webui_google": {
                "issuer": "https://evil.example",
                "authorization_endpoint": "https://evil.example/auth",
                "client_id": "from-file",
            }
        },
    )
    monkeypatch.setenv("HERMES_WEBUI_GOOGLE_CLIENT_ID", "from-env")

    cfg = oidc._resolve_google_config()

    assert cfg["issuer"] == GOOGLE_ISSUER
    assert cfg["client_id"] == "from-env"
    assert cfg["scopes"] == ["openid", "profile", "email"]
    assert "authorization_endpoint" not in cfg
    assert oidc.is_google_enabled() is True


def test_google_start_uses_pkce_and_provider_bound_state(monkeypatch):
    import api.auth_oidc as oidc

    monkeypatch.setattr(oidc, "_require_provider_config", lambda provider: _google_config())
    monkeypatch.setattr(
        oidc,
        "_get_discovery_document",
        lambda issuer: {
            "issuer": issuer,
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        },
    )
    oidc._pending_flows.clear()

    location = oidc.build_google_authorization_redirect("https://webui.example", "/chat")
    params = parse_qs(urlparse(location).query)
    pending = oidc._pending_flows[params["state"][0]]

    assert params["scope"] == ["openid profile email"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["redirect_uri"] == ["https://webui.example/api/auth/google/callback"]
    assert pending["provider"] == "google"
    assert pending["next_path"] == "/chat"


def test_google_callback_rejects_generic_provider_state(monkeypatch):
    import api.auth_oidc as oidc

    monkeypatch.setattr(oidc, "_require_provider_config", lambda provider: _google_config())
    oidc._pending_flows.clear()
    oidc._pending_flows["state"] = {
        "created_at": time.time(),
        "provider": "oidc",
        "nonce": "nonce",
        "code_verifier": "verifier",
        "next_path": "/",
    }

    with pytest.raises(oidc.OIDCAuthError, match="different provider"):
        oidc.complete_google_authorization_code_flow("https://webui.example", "state", "code")

    assert "state" not in oidc._pending_flows


def test_google_pending_state_is_single_use():
    import api.auth_oidc as oidc

    oidc._pending_flows.clear()
    oidc._pending_flows["single-use"] = {
        "created_at": time.time(),
        "provider": "google",
    }

    assert oidc._consume_pending_flow("single-use") is not None
    assert oidc._consume_pending_flow("single-use") is None


def test_unknown_google_identity_is_denied_by_default(isolated_users):
    import api.auth_oidc as oidc

    with pytest.raises(oidc.OIDCAuthError, match="not admitted") as exc:
        oidc._admit_google_identity(
            {"sub": "new-user", "email": "allowed@example.com", "email_verified": True},
            _google_config(),
        )

    assert exc.value.status_code == 403
    assert isolated_users.list_users() == []


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": "email-user", "email": "ALLOWED@example.com", "email_verified": True},
        {
            "sub": "domain-user",
            "email": "person@example.org",
            "email_verified": True,
            "hd": "EXAMPLE.ORG",
        },
    ],
)
def test_verified_allowlist_auto_provisions_member_with_profiles(isolated_users, claims):
    import api.auth_oidc as oidc

    user = oidc._admit_google_identity(
        claims, _google_config(auto_provision=True)
    )

    assert user["role"] == "member"
    assert user["profiles"] == ["default", "team-one"]
    assert user["identities"] == [
        {"provider": "google", "issuer": GOOGLE_ISSUER, "subject": claims["sub"]}
    ]


def test_unverified_google_identity_cannot_auto_provision(isolated_users):
    import api.auth_oidc as oidc

    with pytest.raises(oidc.OIDCAuthError, match="verified email"):
        oidc._admit_google_identity(
            {"sub": "new-user", "email": "allowed@example.com", "email_verified": False},
            _google_config(auto_provision=True),
        )
    assert isolated_users.list_users() == []


@pytest.mark.parametrize(
    "email_claims",
    [
        pytest.param({}, id="missing-email"),
        pytest.param({"email": ""}, id="empty-email"),
        pytest.param({"email": "   "}, id="blank-email"),
    ],
)
def test_hosted_domain_cannot_auto_provision_without_nonempty_email(
    isolated_users, email_claims
):
    import api.auth_oidc as oidc

    claims = {
        "sub": "domain-user-without-email",
        "email_verified": True,
        "hd": "example.org",
        **email_claims,
    }

    with pytest.raises(oidc.OIDCAuthError) as exc:
        oidc._admit_google_identity(claims, _google_config(auto_provision=True))

    assert exc.value.status_code == 403
    assert isolated_users.list_users() == []


def test_existing_enabled_identity_logs_in_without_current_allowlist(isolated_users):
    import api.auth_oidc as oidc

    existing = isolated_users.upsert_external_user(
        "google", GOOGLE_ISSUER, "known", "Old Name", "old@example.net", allow_create=True
    )
    user = oidc._admit_google_identity(
        {"sub": "known", "name": "New Name", "email": "new@example.net"},
        _google_config(),
    )

    assert user["id"] == existing["id"]
    assert user["display_name"] == "New Name"


def test_existing_disabled_identity_is_denied(isolated_users):
    import api.auth_oidc as oidc

    existing = isolated_users.upsert_external_user(
        "google", GOOGLE_ISSUER, "disabled", allow_create=True
    )
    isolated_users.update_user(existing["id"], enabled=False)

    with pytest.raises(oidc.OIDCAuthError, match="disabled"):
        oidc._admit_google_identity({"sub": "disabled"}, _google_config())


class _Handler:
    def __init__(self, *, cookie=""):
        self.headers = {"Host": "localhost:8787"}
        if cookie:
            self.headers["Cookie"] = cookie
        self.request = SimpleNamespace()
        self.wfile = io.BytesIO()
        self.status = None
        self.sent_headers = []

    def send_response(self, status):
        self.status = status

    def send_header(self, key, value):
        self.sent_headers.append((key, value))

    def end_headers(self):
        pass

    def header_values(self, name):
        needle = name.lower()
        return [value for key, value in self.sent_headers if key.lower() == needle]


def _flow_cookie(state):
    return f"hermes_google_oidc_flow={state}"


def test_google_start_sets_browser_bound_flow_cookie(monkeypatch):
    import api.routes as routes

    monkeypatch.setattr(
        "api.auth_oidc.build_google_authorization_redirect",
        lambda *_args: "https://accounts.google.com/o/oauth2/v2/auth?state=state-token",
    )

    handler = _Handler()
    routes.handle_get(
        handler,
        SimpleNamespace(path="/api/auth/google/start", query="next=%2Fchat"),
    )

    assert handler.status == 302
    assert handler.header_values("Set-Cookie") == [
        "hermes_google_oidc_flow=state-token; Path=/api/auth/google/callback; "
        "Max-Age=600; HttpOnly; SameSite=Lax"
    ]


def test_google_start_capacity_error_does_not_set_flow_cookie(monkeypatch):
    import api.auth_oidc as oidc
    import api.routes as routes

    monkeypatch.setattr(oidc, "_MAX_PENDING_FLOWS", 1)
    monkeypatch.setattr(
        oidc, "_require_provider_config", lambda _provider: _google_config()
    )
    monkeypatch.setattr(
        oidc,
        "_get_discovery_document",
        lambda _issuer: {
            "issuer": GOOGLE_ISSUER,
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        },
    )
    oidc._pending_flows.clear()
    oidc._store_pending_flow(
        "active",
        {"created_at": time.time(), "provider": "google", "nonce": "active"},
    )

    handler = _Handler()
    routes.handle_get(
        handler,
        SimpleNamespace(path="/api/auth/google/start", query="next=%2Fchat"),
    )

    assert handler.status == 429
    assert json.loads(handler.wfile.getvalue()) == {
        "error": "Too many authentication flows are already pending"
    }
    assert handler.header_values("Location") == []
    assert handler.header_values("Set-Cookie") == []
    assert oidc._consume_pending_flow("active")["nonce"] == "active"


def test_google_start_flow_cookie_is_secure_in_secure_context(monkeypatch):
    import api.routes as routes

    monkeypatch.setenv("HERMES_WEBUI_SECURE", "1")
    monkeypatch.setattr(
        "api.auth_oidc.build_google_authorization_redirect",
        lambda *_args: "https://accounts.google.com/o/oauth2/v2/auth?state=secure-state",
    )

    handler = _Handler()
    routes.handle_get(
        handler,
        SimpleNamespace(path="/api/auth/google/start", query=""),
    )

    [cookie] = handler.header_values("Set-Cookie")
    assert cookie.endswith("; HttpOnly; SameSite=Lax; Secure")


def test_google_start_in_second_tab_replaces_first_flow_cookie(monkeypatch):
    import api.auth_oidc as oidc
    import api.routes as routes

    locations = iter(
        [
            "https://accounts.google.com/o/oauth2/v2/auth?state=first-state",
            "https://accounts.google.com/o/oauth2/v2/auth?state=second-state",
        ]
    )
    monkeypatch.setattr(
        "api.auth_oidc.build_google_authorization_redirect",
        lambda *_args: next(locations),
    )

    first = _Handler()
    second = _Handler()
    parsed = SimpleNamespace(path="/api/auth/google/start", query="")
    routes.handle_get(first, parsed)
    routes.handle_get(second, parsed)

    [first_cookie] = first.header_values("Set-Cookie")
    [second_cookie] = second.header_values("Set-Cookie")
    # Both responses use the same name and path, so a browser retains the second.
    assert first_cookie.startswith(_flow_cookie("first-state") + ";")
    assert second_cookie.startswith(_flow_cookie("second-state") + ";")
    retained_cookie = second_cookie.split(";", 1)[0]
    assert oidc.google_flow_cookie_matches(retained_cookie, "second-state")
    assert not oidc.google_flow_cookie_matches(retained_cookie, "first-state")


@pytest.mark.parametrize(
    "cookie",
    [
        pytest.param("", id="missing-cookie"),
        pytest.param(_flow_cookie("different-state"), id="mismatched-cookie"),
    ],
)
def test_google_callback_rejects_unbound_state_and_clears_flow_cookie(
    monkeypatch, cookie
):
    import api.auth as auth
    import api.routes as routes

    monkeypatch.setattr(
        "api.auth_oidc.complete_google_authorization_code_flow",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("unbound callback must not exchange a provider code")
        ),
    )
    monkeypatch.setattr(
        auth,
        "create_session",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("unbound callback must not create a session")
        ),
    )

    handler = _Handler(cookie=cookie)
    routes.handle_get(
        handler,
        SimpleNamespace(
            path="/api/auth/google/callback",
            query="state=state-token&code=code-token",
        ),
    )

    assert handler.status == 401
    assert json.loads(handler.wfile.getvalue())["error"] == "Invalid Google login state"
    assert handler.header_values("Set-Cookie") == [
        "hermes_google_oidc_flow=; Path=/api/auth/google/callback; "
        "Max-Age=0; HttpOnly; SameSite=Lax"
    ]


@pytest.mark.parametrize(
    ("query", "expected_status"),
    [
        pytest.param("error=access_denied", 401, id="provider-error-query"),
        pytest.param("state=state-token", 400, id="missing-code"),
        pytest.param("code=code-token", 400, id="missing-state"),
        pytest.param("", 400, id="empty-query"),
    ],
)
def test_google_callback_early_errors_clear_flow_cookie(
    monkeypatch, query, expected_status
):
    import api.routes as routes

    monkeypatch.setattr(
        "api.auth_oidc.complete_google_authorization_code_flow",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("malformed callback must not exchange a provider code")
        ),
    )

    handler = _Handler(cookie=_flow_cookie("state-token"))
    routes.handle_get(
        handler,
        SimpleNamespace(path="/api/auth/google/callback", query=query),
    )

    assert handler.status == expected_status
    [cookie] = handler.header_values("Set-Cookie")
    assert cookie.startswith("hermes_google_oidc_flow=;")
    assert "Max-Age=0" in cookie


def test_google_callback_provider_error_clears_flow_cookie_securely(monkeypatch):
    import api.routes as routes
    from api.auth_oidc import OIDCAuthError

    monkeypatch.setenv("HERMES_WEBUI_SECURE", "1")
    monkeypatch.setattr(
        "api.auth_oidc.complete_google_authorization_code_flow",
        lambda *_args: (_ for _ in ()).throw(
            OIDCAuthError("Google identity is not admitted", status_code=403)
        ),
    )

    handler = _Handler(cookie=_flow_cookie("state-token"))
    routes.handle_get(
        handler,
        SimpleNamespace(
            path="/api/auth/google/callback",
            query="state=state-token&code=code-token",
        ),
    )

    assert handler.status == 403
    [cookie] = handler.header_values("Set-Cookie")
    assert cookie.startswith("hermes_google_oidc_flow=;")
    assert "Max-Age=0" in cookie
    assert cookie.endswith("; Secure")


def test_google_route_creates_named_session_without_claims_or_tokens(monkeypatch):
    import api.auth as auth
    import api.routes as routes

    calls = []
    monkeypatch.setattr(
        "api.auth_oidc.complete_google_authorization_code_flow",
        lambda *_args: {
            "next_path": "//evil.example",
            "claims": {"sub": "subject", "secret": "claim"},
            "external_issuer": GOOGLE_ISSUER,
            "external_subject": "subject",
            "user": {
                "id": "user-id",
                "enabled": True,
                "display_name": "Ada",
                "email": "ada@example.com",
            },
        },
    )
    monkeypatch.setattr(auth, "create_session", lambda **kwargs: calls.append(kwargs) or "cookie")

    handler = _Handler(cookie=_flow_cookie("state"))
    routes.handle_get(
        handler,
        SimpleNamespace(path="/api/auth/google/callback", query="state=state&code=code"),
    )

    assert handler.status == 302
    assert calls == [{
        "user_id": "user-id",
        "provider": "google",
        "external_issuer": GOOGLE_ISSUER,
        "external_subject": "subject",
        "auth_type": "oidc",
        "username": "Ada",
    }]
    assert ("Location", "/") in handler.sent_headers
    cookies = handler.header_values("Set-Cookie")
    assert any(cookie.startswith("hermes_session=") for cookie in cookies)
    assert any(
        cookie.startswith("hermes_google_oidc_flow=;") and "Max-Age=0" in cookie
        for cookie in cookies
    )
    persisted = json.dumps(calls)
    assert "secret" not in persisted and "code" not in persisted and "claims" not in persisted
    assert "/api/auth/google/start" in auth.PUBLIC_PATHS
    assert "/api/auth/google/callback" in auth.PUBLIC_PATHS
