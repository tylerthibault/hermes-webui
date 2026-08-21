from pathlib import Path


def test_bootstrap_admin_page_exists():
    html = (Path(__file__).parents[1] / "static/bootstrap-admin.html").read_text()
    assert "/api/auth/bootstrap" in html
    assert "Create your administrator account" in html


def test_bootstrap_route_allows_only_empty_legacy_bootstrap_path():
    source = (Path(__file__).parents[1] / "api/routes.py").read_text()
    assert "legacy_bootstrap" in source
    assert "and not has_local_users()" in source
