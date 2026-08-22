import io
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest


ISSUER = "https://github.com"


@pytest.fixture
def isolated_users(monkeypatch, tmp_path):
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    return auth_users


def _config(**overrides):
    value = {
        "client_id": "client-id",
        "client_secret": "client-secret",
        "redirect_uri": "",
        "allow_user_ids": ["123"],
        "auto_provision": False,
        "default_profiles": ["default", "team-one"],
    }
    value.update(overrides)
    return value


def test_config_env_and_fixed_endpoints(monkeypatch):
    import api.auth_github as github

    monkeypatch.setattr(github, "get_config", lambda: {"webui_github": {
        "client_id": "file-id", "client_secret": "file-secret",
        "authorization_endpoint": "https://evil.example/auth",
        "token_endpoint": "https://evil.example/token",
        "user_endpoint": "https://evil.example/user",
    }})
    monkeypatch.setenv("HERMES_WEBUI_GITHUB_CLIENT_ID", "env-id")
    monkeypatch.setenv("HERMES_WEBUI_GITHUB_CLIENT_SECRET", "env-secret")
    monkeypatch.setenv("HERMES_WEBUI_GITHUB_ALLOW_USER_IDS", "123, 456\n789")

    cfg = github._resolve_github_config()
    assert cfg["client_id"] == "env-id"
    assert cfg["client_secret"] == "env-secret"
    assert cfg["allow_user_ids"] == ["123", "456", "789"]
    assert "authorization_endpoint" not in cfg
    assert github.AUTHORIZATION_ENDPOINT == "https://github.com/login/oauth/authorize"
    assert github.TOKEN_ENDPOINT == "https://github.com/login/oauth/access_token"
    assert github.USER_ENDPOINT == "https://api.github.com/user"
    assert github.is_github_enabled() is True


def test_both_client_credentials_are_required(monkeypatch):
    import api.auth_github as github

    monkeypatch.setattr(github, "_resolve_github_config", lambda: _config(client_secret=""))
    assert github.is_github_enabled() is False
    with pytest.raises(github.GitHubConfigError):
        github.build_authorization_redirect("https://webui.example")


def test_github_configuration_enables_overall_auth(monkeypatch):
    import api.auth as auth

    monkeypatch.setattr(auth, "is_password_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "are_passkeys_enabled", lambda: False)
    monkeypatch.setattr(auth, "is_oidc_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "is_google_auth_enabled", lambda: False)
    monkeypatch.setattr(auth, "is_github_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "is_trusted_auth_enabled", lambda: False)
    assert auth.is_auth_enabled() is True


def test_start_uses_state_pkce_safe_next(monkeypatch):
    import api.auth_github as github

    monkeypatch.setattr(github, "_require_config", lambda: _config())
    github._pending_flows.clear()
    location = github.build_authorization_redirect("https://webui.example", "/chat")
    params = parse_qs(urlparse(location).query)
    state = params["state"][0]
    pending = github._pending_flows[state]
    assert urlparse(location)._replace(query="").geturl() == github.AUTHORIZATION_ENDPOINT
    assert params["client_id"] == ["client-id"]
    assert params["redirect_uri"] == ["https://webui.example/api/auth/github/callback"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["code_challenge"][0]
    assert pending["next_path"] == "/chat"


def test_full_pending_github_capacity_rejects_new_flow_without_evicting_active_states(monkeypatch):
    import api.auth_github as github

    monkeypatch.setattr(github, "_MAX_PENDING_FLOWS", 2)
    github._pending_flows.clear()
    now = time.time()
    github._store_pending_flow("old", {"created_at": now - 2})
    github._store_pending_flow("middle", {"created_at": now - 1})

    with pytest.raises(github.GitHubAuthError) as exc:
        github._store_pending_flow("new", {"created_at": now})

    assert exc.value.status_code == 429
    assert set(github._pending_flows) == {"old", "middle"}
    assert github._consume_pending_flow("old")["created_at"] == now - 2
    assert github._consume_pending_flow("middle")["created_at"] == now - 1


def test_duplicate_github_state_cannot_replace_an_active_flow():
    import api.auth_github as github

    github._pending_flows.clear()
    created_at = time.time()
    github._store_pending_flow(
        "same", {"created_at": created_at, "code_verifier": "original"}
    )

    with pytest.raises(github.GitHubAuthError) as exc:
        github._store_pending_flow(
            "same", {"created_at": created_at + 1, "code_verifier": "replacement"}
        )

    assert exc.value.status_code == 503
    assert github._consume_pending_flow("same")["code_verifier"] == "original"


def test_consumed_pending_github_flow_frees_capacity(monkeypatch):
    import api.auth_github as github

    monkeypatch.setattr(github, "_MAX_PENDING_FLOWS", 1)
    github._pending_flows.clear()
    github._store_pending_flow(
        "first", {"created_at": time.time(), "code_verifier": "first"}
    )

    assert github._consume_pending_flow("first")["code_verifier"] == "first"
    github._store_pending_flow(
        "second", {"created_at": time.time(), "code_verifier": "second"}
    )

    assert set(github._pending_flows) == {"second"}


def test_concurrent_github_starts_never_exceed_capacity(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    import api.auth_github as github

    monkeypatch.setattr(github, "_MAX_PENDING_FLOWS", 2)
    github._pending_flows.clear()
    now = time.time()

    def reserve(index):
        try:
            github._store_pending_flow(
                f"state-{index}",
                {"created_at": now, "code_verifier": str(index)},
            )
            return True
        except github.GitHubAuthError as exc:
            assert exc.status_code == 429
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reserve, range(8)))

    assert results.count(True) == 2
    assert len(github._pending_flows) == 2


def test_expired_pending_github_flow_frees_capacity(monkeypatch):
    import api.auth_github as github

    monkeypatch.setattr(github, "_MAX_PENDING_FLOWS", 1)
    github._pending_flows.clear()
    github._pending_flows["expired"] = {
        "created_at": time.time() - github._PENDING_TTL_SECONDS - 1,
    }

    github._store_pending_flow("new", {"created_at": time.time()})

    assert set(github._pending_flows) == {"new"}


def test_pending_flow_expires_and_is_single_use(monkeypatch):
    import api.auth_github as github

    github._pending_flows.clear()
    github._pending_flows["expired"] = {
        "created_at": time.time() - github._PENDING_TTL_SECONDS - 1,
        "code_verifier": "v", "next_path": "/",
    }
    assert github._consume_pending_flow("expired") is None
    github._pending_flows["once"] = {
        "created_at": time.time(), "code_verifier": "v", "next_path": "/",
    }
    assert github._consume_pending_flow("once") is not None
    assert github._consume_pending_flow("once") is None


def test_flow_cookie_security_and_constant_time_match():
    import api.auth_github as github

    header = github.flow_cookie_header("safe_state-1", secure=True)
    assert header == (
        "hermes_github_oauth_flow=safe_state-1; Path=/api/auth/github/callback; "
        "Max-Age=600; HttpOnly; SameSite=Lax; Secure"
    )
    assert github.flow_cookie_matches("x=y; hermes_github_oauth_flow=safe_state-1", "safe_state-1")
    assert not github.flow_cookie_matches("", "safe_state-1")
    assert not github.flow_cookie_matches("hermes_github_oauth_flow=other", "safe_state-1")
    assert "Max-Age=0" in github.flow_cookie_header(secure=True, clear=True)


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def read(self, _size=-1):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return _Response(next(self.responses))


def _pending(github, state="state"):
    github._pending_flows.clear()
    github._pending_flows[state] = {
        "created_at": time.time(), "code_verifier": "pkce-verifier", "next_path": "/chat",
    }


def test_token_and_user_requests_have_required_headers_and_form(monkeypatch, isolated_users):
    import api.auth_github as github

    existing = isolated_users.upsert_external_user(
        "github", ISSUER, "123", "Old", allow_create=True, profiles=["default"]
    )
    opener = _Opener([{"access_token": "top-secret", "token_type": "bearer"},
                      {"id": 123, "name": "Ada", "login": "renamed", "email": "a@example.test"}])
    monkeypatch.setattr(github, "_require_config", lambda: _config())
    monkeypatch.setattr(github, "_github_opener", lambda: opener)
    _pending(github)

    result = github.complete_authorization_code_flow("https://webui.example", "state", "code")

    token_request, user_request = [item[0] for item in opener.requests]
    token_form = parse_qs(token_request.data.decode())
    assert token_request.full_url == github.TOKEN_ENDPOINT
    assert token_request.method == "POST"
    assert token_request.get_header("Accept") == "application/json"
    assert token_request.get_header("User-agent")
    assert token_form == {
        "client_id": ["client-id"], "client_secret": ["client-secret"], "code": ["code"],
        "redirect_uri": ["https://webui.example/api/auth/github/callback"],
        "code_verifier": ["pkce-verifier"],
    }
    assert user_request.full_url == github.USER_ENDPOINT
    assert user_request.get_header("Authorization") == "Bearer top-secret"
    assert user_request.get_header("Accept") == "application/vnd.github+json"
    assert user_request.get_header("X-github-api-version") == "2022-11-28"
    assert user_request.get_header("User-agent")
    assert result == {
        "next_path": "/chat",
        "user": result["user"],
        "external_issuer": ISSUER,
        "external_subject": "123",
    }
    assert result["user"]["id"] == existing["id"]
    assert result["user"]["display_name"] == "Ada"
    assert "top-secret" not in json.dumps(result)


@pytest.mark.parametrize("bad_id", [None, 0, -1, True, "123", 1.5])
def test_github_user_id_must_be_positive_integer(monkeypatch, isolated_users, bad_id):
    import api.auth_github as github

    opener = _Opener([{"access_token": "secret"}, {"id": bad_id, "login": "somebody"}])
    monkeypatch.setattr(github, "_require_config", lambda: _config())
    monkeypatch.setattr(github, "_github_opener", lambda: opener)
    _pending(github)
    with pytest.raises(github.GitHubAuthError, match="numeric user ID"):
        github.complete_authorization_code_flow("https://webui.example", "state", "code")
    assert isolated_users.list_users() == []


def test_numeric_identity_is_stable_across_login_rename(isolated_users):
    import api.auth_github as github

    first = github._admit_github_identity(
        {"id": 123, "login": "old-login"}, _config(auto_provision=True)
    )
    second = github._admit_github_identity(
        {"id": 123, "login": "new-login"}, _config(allow_user_ids=[])
    )
    assert first["id"] == second["id"]
    assert second["display_name"] == "new-login"
    assert second["identities"] == [{"provider": "github", "issuer": ISSUER, "subject": "123"}]


def test_display_name_order_and_fallback(isolated_users):
    import api.auth_github as github

    users = [
        github._admit_github_identity({"id": 123, "name": "Name", "login": "login"}, _config(auto_provision=True)),
        github._admit_github_identity({"id": 124, "name": "", "login": "login"}, _config(auto_provision=True, allow_user_ids=["124"])),
        github._admit_github_identity({"id": 125}, _config(auto_provision=True, allow_user_ids=["125"])),
    ]
    assert [u["display_name"] for u in users] == ["Name", "login", "GitHub user 125"]


def test_unknown_and_disabled_users_are_denied(isolated_users):
    import api.auth_github as github

    with pytest.raises(github.GitHubAuthError, match="not admitted"):
        github._admit_github_identity({"id": 123, "login": "allowed-login"}, _config())
    user = isolated_users.upsert_external_user("github", ISSUER, "123", allow_create=True)
    isolated_users.update_user(user["id"], enabled=False)
    with pytest.raises(github.GitHubAuthError, match="disabled"):
        github._admit_github_identity({"id": 123, "login": "renamed"}, _config())


def test_auto_provision_requires_explicit_exact_numeric_allowlist_and_profiles(isolated_users):
    import api.auth_github as github

    for cfg in (
        _config(auto_provision=False),
        _config(auto_provision=True, allow_user_ids=["999"]),
        _config(auto_provision=True, default_profiles=[]),
    ):
        with pytest.raises(github.GitHubAuthError):
            github._admit_github_identity({"id": 123, "login": "allowed-login"}, cfg)
    user = github._admit_github_identity(
        {"id": 123, "login": "allowed-login"}, _config(auto_provision=True)
    )
    assert user["role"] == "member"
    assert user["profiles"] == ["default", "team-one"]


def test_invalid_allow_ids_and_profiles_are_discarded(monkeypatch):
    import api.auth_github as github

    monkeypatch.setattr(github, "get_config", lambda: {"webui_github": {
        "client_id": "id", "client_secret": "secret", "auto_provision": True,
        "allow_user_ids": ["123", "0", "-1", "12x", 456],
        "default_profiles": ["default", "bad/profile", "team"],
    }})
    cfg = github._resolve_github_config()
    assert cfg["allow_user_ids"] == ["123", "456"]
    assert cfg["default_profiles"] == ["default", "team"]


class _Handler:
    def __init__(self, cookie=""):
        self.headers = {"Host": "localhost:8787"}
        if cookie:
            self.headers["Cookie"] = cookie
        self.request = SimpleNamespace()
        self.wfile = io.BytesIO()
        self.status = None
        self.sent_headers = []

    def send_response(self, status): self.status = status
    def send_header(self, key, value): self.sent_headers.append((key, value))
    def end_headers(self): pass
    def values(self, key): return [v for k, v in self.sent_headers if k.lower() == key.lower()]


def test_github_start_capacity_error_does_not_set_flow_cookie(monkeypatch):
    import api.auth_github as github
    import api.routes as routes

    monkeypatch.setattr(github, "_MAX_PENDING_FLOWS", 1)
    monkeypatch.setattr(github, "_require_config", lambda: _config())
    github._pending_flows.clear()
    github._store_pending_flow(
        "active", {"created_at": time.time(), "code_verifier": "active"}
    )

    handler = _Handler()
    routes.handle_get(
        handler,
        SimpleNamespace(path="/api/auth/github/start", query="next=%2Fchat"),
    )

    assert handler.status == 429
    assert json.loads(handler.wfile.getvalue()) == {
        "error": "Too many authentication flows are already pending"
    }
    assert handler.values("Location") == []
    assert handler.values("Set-Cookie") == []
    assert github._consume_pending_flow("active")["code_verifier"] == "active"


@pytest.mark.parametrize("cookie", ["", "hermes_github_oauth_flow=wrong"])
def test_callback_requires_bound_cookie_and_clears_it(monkeypatch, cookie):
    import api.routes as routes

    monkeypatch.setattr("api.auth_github.complete_authorization_code_flow", lambda *_: (_ for _ in ()).throw(AssertionError))
    handler = _Handler(cookie)
    routes.handle_get(handler, SimpleNamespace(path="/api/auth/github/callback", query="state=state&code=code"))
    assert handler.status == 401
    assert json.loads(handler.wfile.getvalue()) == {"error": "Invalid GitHub login state"}
    assert any(c.startswith("hermes_github_oauth_flow=;") and "Max-Age=0" in c for c in handler.values("Set-Cookie"))


@pytest.mark.parametrize("query,status", [("", 400), ("state=s", 400), ("code=c", 400), ("error=denied", 401)])
def test_all_early_callback_errors_clear_cookie(monkeypatch, query, status):
    import api.routes as routes

    handler = _Handler("hermes_github_oauth_flow=s")
    routes.handle_get(handler, SimpleNamespace(path="/api/auth/github/callback", query=query))
    assert handler.status == status
    assert any("Max-Age=0" in c for c in handler.values("Set-Cookie"))


def test_start_cookie_and_callback_named_session_nonleakage(monkeypatch):
    import api.auth as auth
    import api.routes as routes

    monkeypatch.setenv("HERMES_WEBUI_SECURE", "1")
    monkeypatch.setattr("api.auth_github.build_authorization_redirect", lambda *_: github_location("state"))
    start = _Handler()
    routes.handle_get(start, SimpleNamespace(path="/api/auth/github/start", query="next=%2Fchat"))
    assert start.status == 302
    assert start.values("Set-Cookie")[0].endswith("; Secure")

    calls = []
    monkeypatch.setattr("api.auth_github.complete_authorization_code_flow", lambda *_: {
        "next_path": "https://evil.example", "access_token": "must-not-persist",
        "external_issuer": ISSUER, "external_subject": "123",
        "user": {"id": "local-user-id", "enabled": True, "display_name": "Ada"},
    })
    monkeypatch.setattr(auth, "create_session", lambda **kw: calls.append(kw) or "session-cookie")
    callback = _Handler("hermes_github_oauth_flow=state")
    routes.handle_get(callback, SimpleNamespace(path="/api/auth/github/callback", query="state=state&code=secret-code"))
    assert callback.status == 302
    assert calls == [{
        "user_id": "local-user-id", "provider": "github",
        "external_issuer": ISSUER, "external_subject": "123",
        "auth_type": "oauth", "username": "Ada",
    }]
    assert ("Location", "/") in callback.sent_headers
    assert any(c.startswith("hermes_session=") for c in callback.values("Set-Cookie"))
    assert any(c.startswith("hermes_github_oauth_flow=;") for c in callback.values("Set-Cookie"))
    assert "secret-code" not in json.dumps(calls)
    assert "/api/auth/github/start" in auth.PUBLIC_PATHS
    assert "/api/auth/github/callback" in auth.PUBLIC_PATHS


def github_location(state):
    return f"https://github.com/login/oauth/authorize?state={state}"
