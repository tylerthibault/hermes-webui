from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

import api.auth as auth
import api.auth_users as auth_users
import api.profiles as profiles
import api.routes as routes


@pytest.mark.parametrize(
    "path",
    [
        "/api/session/new",
        "/api/projects/create",
        "/api/goal",
        "/api/chat/start",
        "/api/crons/create",
    ],
)
def test_named_profile_body_tampering_is_denied_before_route_side_effects(monkeypatch, path):
    handler = SimpleNamespace(headers={})
    captured = {}
    monkeypatch.setattr(routes, "_check_csrf", lambda _handler: True)
    monkeypatch.setattr(routes, "_handle_extension_sidecar_proxy", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(routes, "read_body", lambda _handler: {"profile": "beta"})
    monkeypatch.setattr(auth, "current_principal", lambda _handler: {"role": "member", "enabled": True})
    monkeypatch.setattr(routes, "_get_active_profile_name", lambda: "alpha")
    monkeypatch.setattr(
        routes,
        "_guard_request_session_visibility",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("route preflight ran")),
    )
    monkeypatch.setattr(
        routes,
        "bad",
        lambda _handler, message, status=400, **_kwargs: captured.update(
            message=message, status=status
        )
        or True,
    )

    assert routes.handle_post(handler, urlparse(path)) is True
    assert captured == {"message": "Profile access forbidden", "status": 403}


def test_named_profile_switch_denial_precedes_switch_watcher_and_cookie(monkeypatch):
    handler = SimpleNamespace(headers={})
    captured = {}
    monkeypatch.setattr(routes, "_check_csrf", lambda _handler: True)
    monkeypatch.setattr(routes, "_handle_extension_sidecar_proxy", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(routes, "read_body", lambda _handler: {"name": "beta"})
    monkeypatch.setattr(routes, "_guard_request_session_visibility", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(auth, "current_principal", lambda _handler: {"role": "member", "enabled": True})
    monkeypatch.setattr(auth_users, "user_allows_profile", lambda _principal, _name: False)
    monkeypatch.setattr(
        profiles,
        "switch_profile",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("switch ran")),
    )
    monkeypatch.setattr(
        routes,
        "bad",
        lambda _handler, message, status=400, **_kwargs: captured.update(
            message=message, status=status
        )
        or True,
    )

    assert routes.handle_post(handler, urlparse("/api/profile/switch")) is True
    assert captured == {"message": "Profile access forbidden", "status": 403}
