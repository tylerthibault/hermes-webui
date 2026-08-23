from pathlib import Path


def test_member_dashboard_has_slack_style_navigation_and_management_controls():
    html = (Path(__file__).parents[1] / "static/member-dashboard.html").read_text()
    assert 'id="dmList"' in html and 'id="roomList"' in html and 'id="botList"' in html
    assert 'id="peopleBtn"' in html and 'id="peopleModal"' in html
    assert "addMember" in html and "renameRoom" in html and "leaveRoom" in html



def test_member_dashboard_uses_text_content_for_messages():
    html = (Path(__file__).parents[1] / "static/member-dashboard.html").read_text()
    assert "text.textContent=m.body" in html
