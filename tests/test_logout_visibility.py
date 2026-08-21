from pathlib import Path


def test_sign_out_is_not_hidden_by_auth_status():
    html = (Path(__file__).parents[1] / "static/index.html").read_text()
    js = (Path(__file__).parents[1] / "static/panels.js").read_text()
    assert 'id="btnSignOut"' in html
    assert "if(signOutBtn) signOutBtn.style.display='';" in js
    assert "/api/auth/logout" in js
