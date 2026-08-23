from pathlib import Path


def test_rooms_nav_replaces_admin_users_rail_action():
    html = (Path(__file__).parents[1] / "static/index.html").read_text()
    ui = (Path(__file__).parents[1] / "static/ui.js").read_text()
    assert 'id="roomsRailBtn"' in html
    assert 'href="/rooms"' in html
    assert 'data-room-link' in html
    assert "authenticated=(await r.json()).authenticated===true" in ui
    assert "data-room-link" in ui
    assert 'id="adminUsersRailBtn"' not in html
