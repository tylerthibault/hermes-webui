"""Regression coverage for channel-specific WebUI tool permissions."""

import ast
import builtins
import sys
import types
from pathlib import Path
from unittest import mock


def _resolver_modules(resolver):
    hermes_cli = types.ModuleType("hermes_cli")
    tools_config = types.ModuleType("hermes_cli.tools_config")
    tools_config._get_platform_tools = resolver
    hermes_cli.tools_config = tools_config
    return {
        "hermes_cli": hermes_cli,
        "hermes_cli.tools_config": tools_config,
    }


def test_explicit_webui_is_ceiling_after_platform_resolution():
    import api.config as config

    cfg = {
        "platform_toolsets": {
            "webui": ["file", "terminal"],
            "cli": ["web"],
        },
        "toolsets": {"disabled": ["terminal"]},
        "mcp_servers": {"docs": {"enabled": True}},
    }

    def production_semantics(candidate, platform):
        assert candidate is cfg
        assert platform == "webui"
        # Hermes' platform resolver applies disabled-tool policy and auto-adds
        # enabled MCP server toolsets. The WebUI-specific list must still be the
        # capability ceiling around that production result.
        return ["file", "mcp-docs"]

    with mock.patch.dict(sys.modules, _resolver_modules(production_semantics)):
        assert config._resolve_webui_toolsets(cfg) == ["file"]


def test_explicit_empty_webui_disables_mcp_without_calling_platform_resolver():
    import api.config as config

    cfg = {
        "platform_toolsets": {"webui": [], "cli": ["terminal"]},
        "mcp_servers": {"docs": {"enabled": True}},
    }
    resolver = mock.Mock(return_value=["mcp-docs"])

    with mock.patch.dict(sys.modules, _resolver_modules(resolver)):
        assert config._resolve_webui_toolsets(cfg) == []
    resolver.assert_not_called()


def test_session_selection_can_only_narrow_webui_ceiling():
    import api.config as config

    cfg = {"platform_toolsets": {"webui": ["file", "terminal"]}}
    resolver = mock.Mock(return_value=["file", "terminal", "mcp-docs"])

    with mock.patch.dict(sys.modules, _resolver_modules(resolver)):
        assert config._resolve_webui_toolsets(
            cfg,
            selected_toolsets=["web", "terminal", "mcp-docs"],
        ) == ["terminal"]
        assert config._resolve_webui_toolsets(cfg, selected_toolsets=[]) == []


def test_webui_platform_resolver_runtime_failure_fails_closed():
    import api.config as config

    cfg = {"platform_toolsets": {"webui": ["terminal", "file"]}}

    def broken_resolver(candidate, platform):
        raise RuntimeError("disabled-tool policy could not be loaded")

    with mock.patch.dict(sys.modules, _resolver_modules(broken_resolver)):
        assert config._resolve_webui_toolsets(cfg) == []


def test_legacy_cli_fallback_resolver_runtime_failure_fails_closed_for_webui():
    import api.config as config

    cfg = {"platform_toolsets": {"cli": ["terminal", "file"]}}

    def broken_resolver(candidate, platform):
        assert platform == "cli"
        raise RuntimeError("disabled-tool policy could not be loaded")

    with mock.patch.dict(sys.modules, _resolver_modules(broken_resolver)):
        assert config._resolve_webui_toolsets(cfg) == []


def test_known_import_absence_preserves_explicit_webui_list():
    import api.config as config

    cfg = {"platform_toolsets": {"webui": ["terminal", "file"]}}
    real_import = builtins.__import__

    def without_tools_config(name, *args, **kwargs):
        if name == "hermes_cli.tools_config":
            error = ModuleNotFoundError("Hermes Agent is not installed")
            error.name = "hermes_cli"
            raise error
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=without_tools_config):
        assert config._resolve_webui_toolsets(cfg) == ["terminal", "file"]


def test_transitive_import_error_does_not_enable_raw_compatibility_fallback():
    import api.config as config

    cfg = {"platform_toolsets": {"webui": ["terminal", "file"]}}
    real_import = builtins.__import__

    def incompatible_tools_config(name, *args, **kwargs):
        if name == "hermes_cli.tools_config":
            raise ImportError("cannot import name 'new_runtime_dependency'")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=incompatible_tools_config):
        assert config._resolve_webui_toolsets(cfg) == []


def test_undetermined_profile_config_fails_closed_instead_of_using_defaults():
    import api.config as config

    with mock.patch.object(config, "get_config", return_value={
        "platform_toolsets": {"cli": ["terminal", "file"]},
    }):
        assert config._resolve_webui_toolsets(None, config_loaded=False) == []


def test_gateway_policy_constraints_force_the_local_webui_runtime():
    from api.routes import _gateway_backend_allowed_for_webui_policy

    assert not _gateway_backend_allowed_for_webui_policy(
        True,
        {"platform_toolsets": {"webui": ["file"]}},
        None,
    )
    assert not _gateway_backend_allowed_for_webui_policy(
        True,
        {"platform_toolsets": {"cli": ["file", "terminal"]}},
        ["file"],
    )
    assert not _gateway_backend_allowed_for_webui_policy(True, None, None)
    # A successfully loaded old profile remains on its configured gateway path.
    assert _gateway_backend_allowed_for_webui_policy(
        True,
        {"platform_toolsets": {"cli": ["file", "terminal"]}},
        None,
    )


def test_named_profile_config_failure_maps_to_an_explicit_no_tools_policy():
    from api.routes import _webui_tool_config_for_session

    session = types.SimpleNamespace(profile="work")
    assert _webui_tool_config_for_session(session, None) == {
        "platform_toolsets": {"webui": []}
    }


def test_synchronous_agent_scope_binds_the_session_profile():
    from contextlib import contextmanager
    from api.routes import _sync_profile_agent_scope

    entered = []

    @contextmanager
    def fake_profile_scope(profile, purpose, logger_override=None):
        entered.append((profile, purpose, logger_override))
        yield

    with mock.patch("api.profiles.profile_env_for_background_worker", fake_profile_scope):
        with _sync_profile_agent_scope(types.SimpleNamespace(profile="maverick")):
            assert entered and entered[0][0] == "maverick"


def test_synchronous_chat_constructs_agent_inside_profile_scope():
    repo = Path(__file__).resolve().parent.parent
    tree = ast.parse((repo / "api" / "routes.py").read_text(encoding="utf-8"))
    scoped_with = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.With)
        and any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Name)
            and item.context_expr.func.id == "_sync_profile_agent_scope"
            for item in node.items
        )
    ]
    assert len(scoped_with) == 1
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "AIAgent"
        for node in ast.walk(scoped_with[0])
    )


def test_session_metadata_failure_keeps_reliable_loaded_session_ceiling(tmp_path):
    import api.models as models
    import api.streaming as streaming

    session = types.SimpleNamespace(enabled_toolsets=["file"])
    (tmp_path / "session-1.json").write_text("{}", encoding="utf-8")
    with (
        mock.patch.object(models, "SESSION_DIR", tmp_path),
        mock.patch.object(
            models.Session,
            "load_metadata_only",
            side_effect=OSError("metadata temporarily unreadable"),
        ),
    ):
        assert streaming._load_session_toolset_selection(session, "session-1") == ["file"]


def test_absent_or_non_list_webui_retains_legacy_cli_resolution():
    import api.config as config

    resolver = mock.Mock(return_value=["terminal", "mcp-docs"])
    with mock.patch.dict(sys.modules, _resolver_modules(resolver)):
        assert config._resolve_webui_toolsets(
            {"platform_toolsets": {"cli": ["terminal"]}}
        ) == ["terminal", "mcp-docs"]
        assert config._resolve_webui_toolsets(
            {"platform_toolsets": {"webui": "terminal", "cli": ["terminal"]}}
        ) == ["terminal", "mcp-docs"]


def _agent_toolset_call_shapes(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    shapes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not any(
            keyword.arg == "platform"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value == "webui"
            for keyword in node.keywords
        ):
            continue
        enabled = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "enabled_toolsets"),
            None,
        )
        if enabled is not None:
            shapes.append(ast.dump(enabled, include_attributes=False))
    return shapes


def test_browser_agent_paths_share_effective_resolver_or_explicit_no_tools():
    repo = Path(__file__).resolve().parent.parent
    shapes = _agent_toolset_call_shapes(repo / "api" / "streaming.py")
    shapes += _agent_toolset_call_shapes(repo / "api" / "routes.py")

    # Utility agents that are intentionally tool-free keep literal []. Every
    # browser chat/compression agent must consume the same effective resolver;
    # no path may use a raw profile list or the legacy CLI resolver directly.
    unsafe = [
        shape
        for shape in shapes
        if shape != "List(elts=[], ctx=Load())"
        and shape != "Name(id='_toolsets', ctx=Load())"
        and "_resolve_webui_toolsets" not in shape
    ]
    assert not unsafe
    resolver_shapes = [shape for shape in shapes if "_resolve_webui_toolsets" in shape]
    streaming_tree = ast.parse(
        (repo / "api" / "streaming.py").read_text(encoding="utf-8")
    )
    streaming_resolutions = [
        node.value
        for node in ast.walk(streaming_tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "_toolsets" for target in node.targets)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "_resolve_webui_toolsets"
    ]
    assert len(resolver_shapes) == 2
    assert len(streaming_resolutions) == 1
    assert all("selected_toolsets" in shape for shape in resolver_shapes)
    assert any(keyword.arg == "selected_toolsets" for keyword in streaming_resolutions[0].keywords)
