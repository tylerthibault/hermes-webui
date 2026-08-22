from pathlib import Path


def test_bootstrap_assigns_default_profile():
    html = (Path(__file__).parents[1] / "static/bootstrap-admin.html").read_text()
    assert 'profiles:["default"]' in html
    assert "profiles:[]" not in html
