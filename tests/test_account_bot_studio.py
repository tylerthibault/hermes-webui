from pathlib import Path

from api import user_bots


def test_new_bot_has_private_soul_and_owner_can_update_it(tmp_path, monkeypatch):
    monkeypatch.setattr(user_bots.config, "STATE_DIR", str(tmp_path))
    bot = user_bots.create_bot("user_one", "Meal Planner")
    assert "# Soul" in user_bots.read_soul(bot["id"], "user_one")
    user_bots.write_soul(bot["id"], "user_one", "# Soul\nFocus on meal planning.")
    assert "meal planning" in user_bots.read_soul(bot["id"], "user_one")
    try:
        user_bots.read_soul(bot["id"], "user_two")
    except KeyError:
        pass
    else:
        raise AssertionError("another user read the bot soul")
    (Path(bot["home"]) / "SOUL.md").unlink()
    (Path(bot["home"]) / "SOUL.md").symlink_to("/etc/hosts")
    try:
        user_bots.read_soul(bot["id"], "user_one")
    except RuntimeError:
        pass
    else:
        raise AssertionError("symlinked SOUL.md was read")


def test_account_and_bot_studio_pages_and_navigation_exist():
    root = Path(__file__).parents[1]
    account = (root / "static/account.html").read_text()
    studio = (root / "static/bot-studio.html").read_text()
    index = (root / "static/index.html").read_text()
    assert "Administrator" in account and "/admin/users" in account
    assert "SOUL.md" in studio and "/api/user/bots/" in studio
    assert 'href="/account"' in index and 'href="/rooms"' in index
