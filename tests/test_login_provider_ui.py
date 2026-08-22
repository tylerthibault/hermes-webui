import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


class _Handler:
    def __init__(self):
        self.headers = {"Host": "localhost:8787"}
        self.request = SimpleNamespace()
        self.wfile = io.BytesIO()
        self.status = None

    def send_response(self, status):
        self.status = status

    def send_header(self, _key, _value):
        pass

    def end_headers(self):
        pass


def _render_login(monkeypatch, *, password, google, github, oidc=False, passkeys=False, query=""):
    import api.auth as auth
    import api.auth_github as auth_github
    import api.auth_oidc as auth_oidc
    import api.passkeys as passkey_api
    import api.routes as routes

    captured = {}
    monkeypatch.setattr(routes, "load_settings", lambda: {"bot_name": "Hermes", "language": "en"})
    monkeypatch.setattr(auth, "get_password_hash", lambda: "hash" if password else None)
    monkeypatch.setattr(auth, "_passkey_feature_flag_enabled", lambda: passkeys)
    monkeypatch.setattr(passkey_api, "registered_credentials", lambda: [{"id": "credential"}] if passkeys else [])
    monkeypatch.setattr(auth_oidc, "is_oidc_enabled", lambda: oidc)
    monkeypatch.setattr(auth_oidc, "is_google_enabled", lambda: google)
    monkeypatch.setattr(auth_github, "is_github_enabled", lambda: github)
    monkeypatch.setattr(
        routes,
        "t",
        lambda _handler, body, *, content_type=None, **_kwargs: captured.update(
            {"body": body, "content_type": content_type}
        ) or True,
    )

    routes.handle_get(_Handler(), SimpleNamespace(path="/login", query=query))
    return captured["body"]


def _raise_capability(name):
    def raiser(*_args, **_kwargs):
        raise RuntimeError(f"{name} discovery failed")

    return raiser


@pytest.mark.parametrize(
    ("failed", "hidden_control"),
    [
        ("password", "password-login-section"),
        ("google", "google-login"),
        ("github", "github-login"),
        ("oidc", "oidc-login"),
        ("passkey_flag", "passkey-login"),
        ("passkey_credentials", "passkey-login"),
    ],
)
def test_login_page_capability_exceptions_hide_only_the_failed_control(
    monkeypatch, failed, hidden_control
):
    import api.auth as auth
    import api.auth_github as auth_github
    import api.auth_oidc as auth_oidc
    import api.passkeys as passkey_api
    import api.routes as routes

    captured = {}
    monkeypatch.setattr(routes, "load_settings", lambda: {"bot_name": "Hermes", "language": "en"})
    monkeypatch.setattr(auth, "get_password_hash", lambda: "hash")
    monkeypatch.setattr(auth, "_passkey_feature_flag_enabled", lambda: True)
    monkeypatch.setattr(passkey_api, "registered_credentials", lambda: [{"id": "credential"}])
    monkeypatch.setattr(auth_oidc, "is_oidc_enabled", lambda: True)
    monkeypatch.setattr(auth_oidc, "is_google_enabled", lambda: True)
    monkeypatch.setattr(auth_github, "is_github_enabled", lambda: True)
    targets = {
        "password": (auth, "get_password_hash"),
        "google": (auth_oidc, "is_google_enabled"),
        "github": (auth_github, "is_github_enabled"),
        "oidc": (auth_oidc, "is_oidc_enabled"),
        "passkey_flag": (auth, "_passkey_feature_flag_enabled"),
        "passkey_credentials": (passkey_api, "registered_credentials"),
    }
    monkeypatch.setattr(*targets[failed], _raise_capability(failed))
    monkeypatch.setattr(
        routes,
        "t",
        lambda _handler, body, *, content_type=None, **_kwargs: captured.update(
            {"body": body, "content_type": content_type}
        ) or True,
    )

    routes.handle_get(_Handler(), SimpleNamespace(path="/login", query=""))
    html = captured["body"]

    assert captured["content_type"] == "text/html; charset=utf-8"
    for control in (
        "password-login-section", "google-login", "github-login", "oidc-login", "passkey-login"
    ):
        start = html.index(f'id="{control}"')
        tag = html[start:html.index(">", start)]
        assert (" hidden" in tag) is (control == hidden_control)


@pytest.mark.parametrize(
    ("failed", "failed_fields"),
    [
        ("password", {"password_auth_enabled"}),
        ("google", {"google_enabled"}),
        ("github", {"github_enabled"}),
        ("oidc", {"oidc_enabled"}),
        ("passkey_flag", {"passkey_feature_flag", "passkeys_enabled"}),
        ("passkey_credentials", {"passkeys_enabled"}),
    ],
)
def test_auth_status_capability_exceptions_fail_closed_independently(
    monkeypatch, failed, failed_fields
):
    import api.auth as auth
    import api.auth_github as auth_github
    import api.auth_oidc as auth_oidc
    import api.passkeys as passkey_api
    import api.routes as routes

    monkeypatch.setattr(auth, "get_password_hash", lambda: "hash")
    monkeypatch.setattr(auth, "_passkey_feature_flag_enabled", lambda: True)
    monkeypatch.setattr(passkey_api, "registered_credentials", lambda: [{"id": "credential"}])
    monkeypatch.setattr(auth_oidc, "is_oidc_enabled", lambda: True)
    monkeypatch.setattr(auth_oidc, "is_google_enabled", lambda: True)
    monkeypatch.setattr(auth_github, "is_github_enabled", lambda: True)
    monkeypatch.setattr(auth, "is_trusted_auth_enabled", lambda: True)
    monkeypatch.setattr(
        auth,
        "ensure_trusted_auth_session",
        lambda _handler: {
            "auth_type": "trusted", "username": "alice", "bound_profile": "dev"
        },
    )
    monkeypatch.setattr(routes, "load_settings", lambda: {"auth_disabled_acknowledged": True})
    targets = {
        "password": (auth, "get_password_hash"),
        "google": (auth_oidc, "is_google_enabled"),
        "github": (auth_github, "is_github_enabled"),
        "oidc": (auth, "is_oidc_auth_enabled"),
        "passkey_flag": (auth, "_passkey_feature_flag_enabled"),
        "passkey_credentials": (passkey_api, "registered_credentials"),
    }
    monkeypatch.setattr(*targets[failed], _raise_capability(failed))

    handler = _Handler()
    routes.handle_get(handler, SimpleNamespace(path="/api/auth/status", query=""))
    payload = json.loads(handler.wfile.getvalue())

    assert handler.status == 200
    assert payload["auth_enabled"] is True
    assert payload["logged_in"] is True
    assert payload["trusted_auth_enabled"] is True
    assert payload["auth_type"] == "trusted"
    assert payload["user"] == "alice"
    assert payload["bound_profile"] == "dev"
    expected_true = {
        "oidc_enabled", "password_auth_enabled", "google_enabled", "github_enabled",
        "passkeys_enabled", "passkey_feature_flag",
    } - failed_fields
    for field in expected_true:
        assert payload[field] is True, field
    for field in failed_fields:
        assert payload[field] is False, field
    assert payload["passwordless_enabled"] is False
    assert payload["passkeys_count"] == (0 if failed.startswith("passkey") else 1)


def test_login_password_markup_is_accessible_and_keeps_localized_placeholder(monkeypatch):
    html = _render_login(
        monkeypatch, password=True, google=False, github=False, oidc=False
    )

    assert '<label class="visually-hidden" for="password">Password</label>' in html
    assert 'type="password" id="password" placeholder="Password" autocomplete="current-password"' in html
    assert '<div class="err" id="err" role="alert" aria-live="polite"></div>' in html


@pytest.mark.parametrize(
    ("password", "google", "github", "oidc", "expected_hidden"),
    [
        (True, False, False, False, {"password": False, "google": True, "github": True, "oidc": True}),
        (False, True, False, False, {"password": True, "google": False, "github": True, "oidc": True}),
        (False, False, True, True, {"password": True, "google": True, "github": False, "oidc": False}),
        (True, True, True, True, {"password": False, "google": False, "github": False, "oidc": False}),
    ],
)
def test_login_page_server_renders_each_auth_control_independently(
    monkeypatch, password, google, github, oidc, expected_hidden
):
    html = _render_login(
        monkeypatch, password=password, google=google, github=github, oidc=oidc,
        query="next=%2Fworkspace%2Fdemo%3Ftab%3Dfiles%26sort%3Dname",
    )

    assert 'id="password-login-section"' in html
    assert ('id="password-login-section" hidden' in html) is expected_hidden["password"]
    assert ('id="google-login" class="provider-login google-login" hidden' in html) is expected_hidden["google"]
    assert ('id="github-login" class="provider-login github-login" hidden' in html) is expected_hidden["github"]
    assert ('id="oidc-login" class="provider-login oidc-login" hidden' in html) is expected_hidden["oidc"]
    assert 'href="/api/auth/google/start?next=/workspace/demo%3Ftab%3Dfiles%26sort%3Dname"' in html
    assert 'href="/api/auth/github/start?next=/workspace/demo%3Ftab%3Dfiles%26sort%3Dname"' in html
    assert 'href="/api/auth/oidc/start?next=/workspace/demo%3Ftab%3Dfiles%26sort%3Dname"' in html
    assert "client_id" not in html.lower()
    assert "client_secret" not in html.lower()


@pytest.mark.parametrize(
    "query",
    [
        "next=https%3A%2F%2Fevil.example%2Fpwn",
        "next=%2F%2Fevil.example%2Fpwn",
        "next=%2Flogin%3Fnext%3D%252F%252Fevil.example",
    ],
)
def test_provider_login_hrefs_fail_closed_for_malicious_next(monkeypatch, query):
    html = _render_login(
        monkeypatch, password=False, google=True, github=True, oidc=True, query=query
    )

    assert "evil.example" not in html
    assert 'href="/api/auth/google/start"' in html
    assert 'href="/api/auth/github/start"' in html
    assert 'href="/api/auth/oidc/start"' in html


def test_passwordless_server_render_keeps_enabled_passkey_available(monkeypatch):
    html = _render_login(
        monkeypatch, password=False, google=False, github=False, passkeys=True
    )

    assert 'id="password-login-section" hidden' in html
    assert 'id="passkey-login" class="passkey-login" hidden' not in html


def test_login_js_initializes_without_password_form_and_fetches_status_once():
    source = (Path(__file__).parents[1] / "static" / "login.js").read_text()

    assert "if (!form || !input) return" not in source
    assert source.count("fetch('api/auth/status'") == 1
    assert "if (!pw)" in source
    assert "password_auth_enabled" in source
    assert "google_enabled" in source
    assert "github_enabled" in source
