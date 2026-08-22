from pathlib import Path


def test_member_dashboard_has_room_modes_and_orchestrator_controls():
    html = (Path(__file__).parents[1] / "static/member-dashboard.html").read_text()
    assert "Direct message" in html
    assert "Shared room" in html
    assert "Include Room Orchestrator" in html
    assert "/api/member/rooms" in html
    assert "/orchestrator" in html


def test_member_dashboard_uses_text_content_for_messages():
    html = (Path(__file__).parents[1] / "static/member-dashboard.html").read_text()
    assert "text.textContent=m.body" in html
