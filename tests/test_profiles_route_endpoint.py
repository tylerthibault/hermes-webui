from types import SimpleNamespace
from urllib.parse import urlparse


def test_profiles_route_filters_named_member_without_mutating_cached_list(monkeypatch):
    import api.auth as auth
    import api.auth_users as auth_users
    import api.profiles as profiles
    import api.routes as routes

    cached = [{"name": "alpha"}, {"name": "beta"}]
    principal = {"role": "member", "enabled": True, "profiles": ["alpha"]}
    monkeypatch.setattr(profiles, "list_profiles_api", lambda: cached)
    monkeypatch.setattr(profiles, "get_active_profile_name", lambda: "alpha")
    monkeypatch.setattr(auth, "current_principal", lambda _handler: principal)
    monkeypatch.setattr(
        auth_users,
        "user_allows_profile",
        lambda _principal, profile: profile == "alpha",
    )
    monkeypatch.setattr(routes, "_is_isolated_profile_mode", lambda: False)
    monkeypatch.setattr(routes, "j", lambda _handler, payload, status=200: payload)

    payload = routes.handle_get(SimpleNamespace(headers={}), urlparse("/api/profiles"))

    assert payload["profiles"] == [{"name": "alpha"}]
    assert cached == [{"name": "alpha"}, {"name": "beta"}]


def test_profiles_route_returns_active_profile(monkeypatch):
    import api.profiles as profiles
    import api.routes as routes

    expected_profiles = [{"name": "default", "is_default": True}]

    monkeypatch.setattr(profiles, "list_profiles_api", lambda: expected_profiles)
    monkeypatch.setattr(profiles, "get_active_profile_name", lambda: "default")
    monkeypatch.setattr(routes, "_is_isolated_profile_mode", lambda: False)
    monkeypatch.setattr(
        routes,
        "j",
        lambda _handler, payload, status=200: {"status": status, "payload": payload},
    )

    response = routes.handle_get(SimpleNamespace(), urlparse("/api/profiles"))

    assert response == {
        "status": 200,
        "payload": {
            "profiles": expected_profiles,
            "active": "default",
            "single_profile_mode": False,
        },
    }
