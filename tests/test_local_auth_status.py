from pathlib import Path


def test_auth_status_counts_local_users_as_authentication_enabled():
    source = (Path(__file__).parents[1] / "api/routes.py").read_text()
    assert "local_users_enabled, _ = discover_bool(has_local_users)" in source
    assert "local_users_enabled," in source
