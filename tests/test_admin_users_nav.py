from pathlib import Path


def test_admin_users_nav_is_present_and_role_gated():
    html = (Path(__file__).parents[1] / "static/index.html").read_text()
    ui = (Path(__file__).parents[1] / "static/ui.js").read_text()
    assert 'id="adminUsersRailBtn"' in html
    assert 'href="/admin/users"' in html
    assert "data.user.role==='admin'" in ui
    assert "data-admin-users-link" in ui
