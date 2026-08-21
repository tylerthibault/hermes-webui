from pathlib import Path


def test_admin_user_page_contains_management_controls():
    html = (Path(__file__).parents[1] / "static" / "admin-users.html").read_text()
    assert "/api/admin/users" in html
    assert "Reset password" in html
    assert "Disable" in html
    assert "Make admin" in html


def test_local_admin_login_redirects_to_access_management():
    source = (Path(__file__).parents[1] / "static" / "login.js").read_text()
    assert "data.role === 'admin' ? '/admin/users'" in source
