from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
PANELS = (ROOT / "static" / "panels.js").read_text(encoding="utf-8")
CHANNELS = (ROOT / "static" / "channels.js").read_text(encoding="utf-8")
FRONTEND = PANELS + CHANNELS
ROUTES = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")


def test_channels_settings_navigation_and_panel_exist():
    assert 'data-settings-section="channels"' in INDEX
    assert 'id="settingsPaneChannels"' in INDEX
    assert "Matrix channel for" in INDEX


def test_matrix_form_uses_password_inputs_for_secrets():
    assert 'id="matrixAccessToken" type="password"' in INDEX
    assert 'id="matrixPassword" type="password"' in INDEX
    assert 'autocomplete="new-password"' in INDEX


def test_channels_frontend_uses_profile_scoped_api_and_sanitized_secret_flags():
    assert "function loadChannelsPanel" in FRONTEND
    assert "'/api/channels/matrix'" in FRONTEND or '"/api/channels/matrix"' in FRONTEND
    assert "has_access_token" in FRONTEND
    assert "has_password" in FRONTEND
    assert "matrixAccessToken.value = ''" in FRONTEND
    assert "matrixPassword.value = ''" in FRONTEND


def test_channels_routes_are_registered_for_get_save_clear_and_restart():
    assert 'parsed.path == "/api/channels/matrix"' in ROUTES
    assert 'parsed.path == "/api/channels/matrix/restart"' in ROUTES
    assert "get_matrix_channel" in ROUTES
    assert "save_matrix_channel" in ROUTES
    assert "clear_matrix_channel" in ROUTES
    assert "restart_matrix_gateway" in ROUTES


def test_matrix_account_provisioning_control_and_route_exist():
    assert 'id="matrixCreateAccountBtn"' in INDEX
    assert 'id="matrixRegistrationSecret"' in INDEX
    assert 'id="matrixRegistrationSecretField" class="settings-field" hidden' in INDEX
    assert 'type="password"' in INDEX
    assert "Create Matrix account" in INDEX
    assert "registration_secret" in FRONTEND
    assert "registrationSecret.value=''" in FRONTEND
    assert "const secretField=registrationSecret.closest('.settings-field')" in FRONTEND
    assert "if(secretField)secretField.hidden" in FRONTEND
    assert "function createMatrixAccount" in FRONTEND
    assert 'parsed.path == "/api/channels/matrix/provision"' in ROUTES
    assert "provision_matrix_account" in ROUTES


def test_matrix_async_actions_guard_terminal_ui_updates_against_stale_profile():
    assert "function _channelsRequestIsCurrent" in CHANNELS
    for function_name in (
        "saveMatrixChannel",
        "restartMatrixGateway",
        "createMatrixAccount",
        "clearMatrixChannel",
    ):
        function_source = CHANNELS.split(f"async function {function_name}", 1)[1].split(
            "async function ", 1
        )[0]
        assert "const generation=_channelsGeneration" in function_source
        assert "_channelsRequestIsCurrent(generation,profile)" in function_source


def test_matrix_provisioning_ui_honors_backend_availability_and_origin():
    assert "provisioning_available" in CHANNELS
    assert "provisioning_homeserver" in CHANNELS
