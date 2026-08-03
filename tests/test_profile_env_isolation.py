import importlib
import os
import sys
from pathlib import Path


def test_profile_switch_clears_previous_profile_env_vars(monkeypatch, tmp_path):
    base = tmp_path / ".hermes"
    (base / "profiles" / "p1").mkdir(parents=True)
    (base / "profiles" / "p2").mkdir(parents=True)
    (base / "profiles" / "p1" / ".env").write_text(
        "OPENAI_API_KEY=secret-from-p1\nCUSTOM_TOKEN=token-from-p1\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HERMES_BASE_HOME", str(base))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CUSTOM_TOKEN", raising=False)

    # Point the module's cached base-home at our temp base via monkeypatch
    # (auto-restored at teardown) instead of deleting + re-importing api.profiles.
    # The delitem+import_module approach swapped the module object and poisoned
    # dependent modules' cached references, breaking later tests under sharding.
    import api.profiles as profiles
    monkeypatch.setattr(profiles, "_DEFAULT_HERMES_HOME", base)

    profiles.init_profile_state()
    profiles.switch_profile("p1")
    assert os.environ.get("OPENAI_API_KEY") == "secret-from-p1"
    assert os.environ.get("CUSTOM_TOKEN") == "token-from-p1"

    profiles.switch_profile("p2")
    assert os.environ.get("OPENAI_API_KEY") is None
    assert os.environ.get("CUSTOM_TOKEN") is None
    assert profiles.get_active_profile_name() == "p2"


def test_profile_switch_replaces_overlapping_keys(monkeypatch, tmp_path):
    base = tmp_path / ".hermes"
    (base / "profiles" / "p1").mkdir(parents=True)
    (base / "profiles" / "p2").mkdir(parents=True)
    (base / "profiles" / "p1" / ".env").write_text(
        "OPENAI_API_KEY=secret-from-p1\nONLY_P1=one\n",
        encoding="utf-8",
    )
    (base / "profiles" / "p2" / ".env").write_text(
        "OPENAI_API_KEY=secret-from-p2\nONLY_P2=two\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HERMES_BASE_HOME", str(base))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ONLY_P1", raising=False)
    monkeypatch.delenv("ONLY_P2", raising=False)

    # Point the module's cached base-home at our temp base via monkeypatch
    # (auto-restored at teardown) instead of deleting + re-importing api.profiles.
    # The delitem+import_module approach swapped the module object and poisoned
    # dependent modules' cached references, breaking later tests under sharding.
    import api.profiles as profiles
    monkeypatch.setattr(profiles, "_DEFAULT_HERMES_HOME", base)

    profiles.init_profile_state()
    profiles.switch_profile("p1")
    assert os.environ.get("OPENAI_API_KEY") == "secret-from-p1"
    assert os.environ.get("ONLY_P1") == "one"

    profiles.switch_profile("p2")
    assert os.environ.get("OPENAI_API_KEY") == "secret-from-p2"
    assert os.environ.get("ONLY_P1") is None
    assert os.environ.get("ONLY_P2") == "two"


def test_profile_env_cannot_override_matrix_provisioning_homeserver(
    monkeypatch, tmp_path
):
    import api.profiles as profiles

    operator_origin = "https://matrix.operator.example"
    profile_home = tmp_path / "profile"
    profile_home.mkdir()
    (profile_home / ".env").write_text(
        "HERMES_WEBUI_MATRIX_PROVISIONING_HOMESERVER=https://attacker.example\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(
        "HERMES_WEBUI_MATRIX_PROVISIONING_HOMESERVER", operator_origin
    )
    monkeypatch.setattr(profiles, "_loaded_profile_env_keys", set())

    profiles._reload_dotenv(profile_home)

    assert (
        os.environ["HERMES_WEBUI_MATRIX_PROVISIONING_HOMESERVER"]
        == operator_origin
    )
    assert "HERMES_WEBUI_MATRIX_PROVISIONING_HOMESERVER" not in profiles._loaded_profile_env_keys
