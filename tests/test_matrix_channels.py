from __future__ import annotations

import pytest
import yaml


@pytest.fixture
def channels(monkeypatch, tmp_path):
    from api import channels as module

    monkeypatch.setattr(module, "get_active_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(module, "get_active_profile_name", lambda: "maverick")
    monkeypatch.setenv(
        "HERMES_WEBUI_MATRIX_PROVISIONING_HOMESERVER",
        "https://matrix.example.org",
    )
    return module


def _valid_payload(**overrides):
    payload = {
        "homeserver": "https://matrix.example.org",
        "user_id": "@maverick:example.org",
        "auth_method": "access_token",
        "access_token": "secret-token",
        "allowed_users": ["@tyler:example.org", "@kendal:example.org"],
        "allowed_rooms": ["!family:example.org"],
        "require_mention": True,
        "session_scope": "room",
        "auto_thread": False,
        "e2ee_mode": "required",
    }
    payload.update(overrides)
    return payload


def test_get_matrix_channel_never_returns_secrets(channels, tmp_path):
    (tmp_path / ".env").write_text(
        "MATRIX_HOMESERVER=https://matrix.example.org\n"
        "MATRIX_USER_ID=@maverick:example.org\n"
        "MATRIX_ACCESS_TOKEN=super-secret\n"
        "MATRIX_PASSWORD=also-secret\n",
        encoding="utf-8",
    )

    result = channels.get_matrix_channel()

    serialized = repr(result)
    assert "super-secret" not in serialized
    assert "also-secret" not in serialized
    assert result["has_access_token"] is True
    assert result["has_password"] is True
    assert result["profile"] == "maverick"


def test_save_matrix_channel_writes_only_active_profile(channels, tmp_path):
    other_home = tmp_path.parent / "other"
    other_home.mkdir()
    (other_home / ".env").write_text("UNCHANGED=yes\n", encoding="utf-8")

    result = channels.save_matrix_channel(_valid_payload())

    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "MATRIX_ACCESS_TOKEN=secret-token" in env_text
    assert "MATRIX_PASSWORD=" not in env_text
    assert "MATRIX_E2EE_MODE=required" in env_text
    assert "MATRIX_ENCRYPTION=true" in env_text
    assert "MATRIX_ALLOWED_USERS=@tyler:example.org,@kendal:example.org" in env_text
    assert "MATRIX_ALLOWED_ROOMS=!family:example.org" in env_text
    assert "MATRIX_REQUIRE_MENTION=true" in env_text
    assert "MATRIX_AUTO_THREAD=false" in env_text
    assert (other_home / ".env").read_text(encoding="utf-8") == "UNCHANGED=yes\n"
    assert result["profile"] == "maverick"
    assert result["has_access_token"] is True

    config = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert config["matrix"]["allowed_users"] == [
        "@tyler:example.org",
        "@kendal:example.org",
    ]
    assert config["matrix"]["allowed_rooms"] == ["!family:example.org"]
    assert config["matrix"]["require_mention"] is True
    assert config["matrix"]["session_scope"] == "room"
    assert config["matrix"]["auto_thread"] is False
    assert "e2ee_mode" not in config["matrix"]


def test_blank_secret_preserves_existing_access_token(channels, tmp_path):
    (tmp_path / ".env").write_text(
        "MATRIX_ACCESS_TOKEN=existing-token\nKEEP_ME=yes\n", encoding="utf-8"
    )

    channels.save_matrix_channel(_valid_payload(access_token=""))

    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "MATRIX_ACCESS_TOKEN=existing-token" in env_text
    assert "KEEP_ME=yes" in env_text


def test_switching_auth_method_removes_old_secret(channels, tmp_path):
    (tmp_path / ".env").write_text(
        "MATRIX_ACCESS_TOKEN=old-token\n", encoding="utf-8"
    )

    channels.save_matrix_channel(
        _valid_payload(
            auth_method="password",
            access_token="",
            password="new-password",
        )
    )

    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "MATRIX_ACCESS_TOKEN" not in env_text
    assert "MATRIX_PASSWORD=new-password" in env_text


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("homeserver", "http://matrix.example.org"),
        ("homeserver", "https://matrix.example.org\nINJECTED=yes"),
        ("user_id", "maverick@example.org"),
        ("allowed_users", ["tyler@example.org"]),
        ("allowed_rooms", ["family-room"]),
        ("session_scope", "global"),
        ("e2ee_mode", "sometimes"),
    ],
)
def test_invalid_matrix_configuration_is_rejected(channels, field, value):
    with pytest.raises(ValueError):
        channels.save_matrix_channel(_valid_payload(**{field: value}))


def test_activation_requires_user_allowlist(channels):
    with pytest.raises(ValueError, match="allowed user"):
        channels.save_matrix_channel(_valid_payload(allowed_users=[]))


def test_room_allowlist_is_optional_for_new_direct_messages(channels):
    result = channels.save_matrix_channel(_valid_payload(allowed_rooms=[]))

    assert result["allowed_rooms"] == []


def test_clear_matrix_channel_removes_only_matrix_keys(channels, tmp_path):
    (tmp_path / ".env").write_text(
        "MATRIX_ACCESS_TOKEN=secret\nOPENAI_API_KEY=keep\n", encoding="utf-8"
    )
    (tmp_path / "config.yaml").write_text(
        "model:\n  default: test\nmatrix:\n  require_mention: true\n",
        encoding="utf-8",
    )

    result = channels.clear_matrix_channel()

    assert "MATRIX_" not in (tmp_path / ".env").read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=keep" in (tmp_path / ".env").read_text(encoding="utf-8")
    config = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert "matrix" not in config
    assert config["model"]["default"] == "test"
    assert result["configured"] is False


def test_restart_matrix_gateway_enables_and_targets_request_profile(channels, monkeypatch, tmp_path):
    channels.save_matrix_channel(_valid_payload())
    calls = []
    monkeypatch.setattr(
        channels,
        "restart_profile_gateway",
        lambda profile: calls.append(profile) or {
            "profile": profile,
            "status": "running",
            "managed": True,
        },
    )

    result = channels.restart_matrix_gateway()

    assert calls == ["maverick"]
    assert result["status"] == "running"
    assert result["managed"] is True
    assert "HERMES_WEBUI_MATRIX_GATEWAY_ENABLED=1" in (tmp_path / ".env").read_text()


def test_get_matrix_channel_never_exposes_registration_secret(channels):
    result = channels.get_matrix_channel()

    assert "registration_secret" not in result
    assert result["provisioning_available"] is True
    assert result["provisioning_homeserver"] == "https://matrix.example.org"


@pytest.mark.parametrize(
    "operator_value",
    [
        "",
        "http://matrix.example.org",
        "https://matrix.example.org/",
        "https://matrix.example.org?",
        "https://matrix.example.org#",
        "https://matrix.example.org/#",
        "https://matrix.example.org:",
        "https://one.example https://two.example",
    ],
)
def test_invalid_operator_provisioning_origin_disables_provisioning(
    channels, monkeypatch, operator_value
):
    monkeypatch.setenv("HERMES_WEBUI_MATRIX_PROVISIONING_HOMESERVER", operator_value)

    result = channels.get_matrix_channel()

    assert result["provisioning_available"] is False
    assert result["provisioning_homeserver"] == ""


def test_provisioning_rejects_homeserver_not_exactly_allowed_by_operator(
    channels, monkeypatch
):
    monkeypatch.setattr(
        channels,
        "_register_synapse_user",
        lambda *_args: pytest.fail("network must not be called"),
    )

    with pytest.raises(ValueError, match="operator-configured homeserver"):
        channels.provision_matrix_account(
            _valid_payload(
                homeserver="https://other.example.org",
                password="correct-horse-battery-staple",
                registration_secret="registration-secret",
            )
        )


def test_provisioning_compares_normalized_operator_homeserver(
    channels, monkeypatch
):
    monkeypatch.setattr(
        channels,
        "_register_synapse_user",
        lambda *_args: "@maverick:example.org",
    )

    result = channels.provision_matrix_account(
        _valid_payload(
            homeserver="  https://matrix.example.org  ",
            password="correct-horse-battery-staple",
            registration_secret="registration-secret",
        )
    )

    assert result["user_id"] == "@maverick:example.org"


def test_provision_matrix_account_creates_non_admin_profile_account_and_saves_channel(
    channels, monkeypatch, tmp_path
):
    registration_calls = []

    def fake_register(homeserver, secret, username, password):
        registration_calls.append((homeserver, secret, username, password))
        return "@maverick:example.org"

    monkeypatch.setattr(channels, "_register_synapse_user", fake_register)
    payload = _valid_payload(
        auth_method="password",
        access_token="must-not-be-used",
        password="correct-horse-battery-staple",
        user_id="@someone-else:example.org",
        registration_secret="registration-secret",
    )

    result = channels.provision_matrix_account(payload)

    assert registration_calls == [
        (
            "https://matrix.example.org",
            "registration-secret",
            "maverick",
            "correct-horse-battery-staple",
        )
    ]
    assert result["user_id"] == "@maverick:example.org"
    assert result["auth_method"] == "password"
    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "MATRIX_USER_ID=@maverick:example.org" in env_text
    assert "MATRIX_PASSWORD=correct-horse-battery-staple" in env_text
    assert "MATRIX_ACCESS_TOKEN" not in env_text
    assert "registration-secret" not in env_text
    assert "registration-secret" not in repr(result)


def test_provision_matrix_account_requires_one_time_registration_secret(channels):
    with pytest.raises(ValueError, match="registration_secret"):
        channels.provision_matrix_account(
            _valid_payload(
                auth_method="password",
                password="correct-horse-battery-staple",
            )
        )


@pytest.mark.parametrize("field", ["password", "registration_secret"])
@pytest.mark.parametrize(
    "value", [None, 123, [], {}, "", "contains\rreturn", "contains\nnewline"]
)
def test_provisioning_secrets_reject_non_strings_empty_and_newlines(
    channels, monkeypatch, field, value
):
    monkeypatch.setattr(
        channels,
        "_register_synapse_user",
        lambda *_args: pytest.fail("network must not be called"),
    )
    payload = _valid_payload(
        password="correct-horse-battery-staple",
        registration_secret="registration-secret",
    )
    payload[field] = value

    with pytest.raises(ValueError, match=field):
        channels.provision_matrix_account(payload)


def test_provisioning_rejects_registration_secret_over_limit(channels, monkeypatch):
    monkeypatch.setattr(
        channels,
        "_register_synapse_user",
        lambda *_args: pytest.fail("network must not be called"),
    )

    with pytest.raises(ValueError, match="registration_secret"):
        channels.provision_matrix_account(
            _valid_payload(
                password="correct-horse-battery-staple",
                registration_secret="x" * 4097,
            )
        )


def test_provisioning_preserves_registration_secret_exactly(
    channels, monkeypatch, tmp_path
):
    calls = []
    monkeypatch.setattr(
        channels,
        "_register_synapse_user",
        lambda homeserver, secret, username, password: calls.append((secret, password))
        or "@maverick:example.org",
    )
    password = "twelve chars preserved"
    registration_secret = "  opaque registration secret  "

    channels.provision_matrix_account(
        _valid_payload(password=password, registration_secret=registration_secret)
    )

    assert calls == [(registration_secret, password)]
    stored_password = (tmp_path / ".env").read_text(encoding="utf-8").split(
        "MATRIX_PASSWORD=", 1
    )[1].splitlines()[0]
    assert stored_password == password


@pytest.mark.parametrize(
    "password", [" leading-space-password", "trailing-space-password ", '\"quoted-password\"', "'quoted-password'"]
)
def test_profile_runtime_incompatible_passwords_are_rejected_before_network(
    channels, monkeypatch, password
):
    monkeypatch.setattr(
        channels,
        "_register_synapse_user",
        lambda *_args: pytest.fail("network must not be called"),
    )

    with pytest.raises(ValueError, match="password"):
        channels.provision_matrix_account(
            _valid_payload(password=password, registration_secret="registration-secret")
        )


@pytest.mark.parametrize(
    "operator_value",
    [
        "https://matrix.example.org:notaport",
        "https://matrix.example.org:0",
        "https://matrix.example.org:65536",
    ],
)
def test_invalid_operator_provisioning_port_disables_provisioning(
    channels, monkeypatch, operator_value
):
    monkeypatch.setenv("HERMES_WEBUI_MATRIX_PROVISIONING_HOMESERVER", operator_value)

    result = channels.get_matrix_channel()

    assert result["provisioning_available"] is False
    assert result["provisioning_homeserver"] == ""


def test_blank_password_preserves_existing_value_byte_for_byte(channels, tmp_path):
    password = "  existing opaque password  "
    (tmp_path / ".env").write_text(
        f"MATRIX_PASSWORD={password}\n", encoding="utf-8"
    )

    channels.save_matrix_channel(
        _valid_payload(auth_method="password", access_token="", password="")
    )

    stored_password = (tmp_path / ".env").read_text(encoding="utf-8").split(
        "MATRIX_PASSWORD=", 1
    )[1].splitlines()[0]
    assert stored_password == password


@pytest.mark.parametrize(
    "password",
    ["short", "contains\nnewline", "contains\x00nul-byte", "x" * 1025],
)
def test_provision_matrix_account_rejects_unsafe_password_before_network(
    channels, monkeypatch, password
):
    monkeypatch.setattr(
        channels,
        "_register_synapse_user",
        lambda *_args: pytest.fail("network must not be called"),
        raising=False,
    )

    with pytest.raises(ValueError, match="password"):
        channels.provision_matrix_account(
            _valid_payload(
                auth_method="password",
                password=password,
                registration_secret="registration-secret",
            )
        )


def test_synapse_registration_mac_matches_documented_protocol(channels):
    assert channels._synapse_registration_mac(
        "shared", "nonce", "maverick", "password", admin=False
    ) == "709b3ebdb0f75ed36ead5f49e9c055716dba4fcb"


def test_synapse_registration_request_is_non_admin_and_does_not_send_shared_secret(
    channels, monkeypatch
):
    requests = []

    class Response:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            import json

            return json.dumps(self.payload).encode("utf-8")

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        if request.get_method() == "GET":
            return Response({"nonce": "nonce"})
        return Response({"user_id": "@maverick:example.org"})

    monkeypatch.setattr(channels, "_urlopen_no_redirect", fake_urlopen)

    user_id = channels._register_synapse_user(
        "https://matrix.example.org",
        "shared-secret",
        "maverick",
        "correct-horse-battery-staple",
    )

    assert user_id == "@maverick:example.org"
    assert [request.get_method() for request, _timeout in requests] == ["GET", "POST"]
    assert [timeout for _request, timeout in requests] == [15, 15]
    post_body = requests[1][0].data.decode("utf-8")
    assert '"admin":false' in post_body
    assert '"username":"maverick"' in post_body
    assert "shared-secret" not in post_body


def test_synapse_registration_success_with_invalid_user_id_warns_not_to_retry(
    channels, monkeypatch
):
    responses = iter([{"nonce": "nonce"}, {}])

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            import json

            return json.dumps(next(responses)).encode("utf-8")

    monkeypatch.setattr(
        channels, "_urlopen_no_redirect", lambda _request, timeout: Response()
    )

    with pytest.raises(channels.MatrixProvisioningError) as caught:
        channels._register_synapse_user(
            "https://matrix.example.org",
            "shared-secret",
            "maverick",
            "correct-horse-battery-staple",
        )

    message = str(caught.value).lower()
    assert "account may have been created" in message
    assert "do not retry" in message


def test_synapse_registration_post_transport_failure_warns_not_to_retry(
    channels, monkeypatch
):
    calls = 0

    class NonceResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"nonce":"nonce"}'

    def fake_urlopen(_request, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            return NonceResponse()
        raise channels.URLError("connection reset after POST")

    monkeypatch.setattr(channels, "_urlopen_no_redirect", fake_urlopen)

    with pytest.raises(channels.MatrixProvisioningError) as caught:
        channels._register_synapse_user(
            "https://matrix.example.org",
            "shared-secret",
            "maverick",
            "correct-horse-battery-staple",
        )

    message = str(caught.value).lower()
    assert "account may have been created" in message
    assert "do not retry" in message
    assert "connection reset" not in message


def test_synapse_registration_post_truncated_response_warns_not_to_retry(
    channels, monkeypatch
):
    import http.client

    calls = 0

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            if calls == 1:
                return b'{"nonce":"nonce"}'
            raise http.client.IncompleteRead(b'{"user_id":')

    def fake_urlopen(_request, timeout):
        nonlocal calls
        calls += 1
        return Response()

    monkeypatch.setattr(channels, "_urlopen_no_redirect", fake_urlopen)

    with pytest.raises(channels.MatrixProvisioningError) as caught:
        channels._register_synapse_user(
            "https://matrix.example.org",
            "shared-secret",
            "maverick",
            "correct-horse-battery-staple",
        )

    assert "do not retry" in str(caught.value).lower()


def test_synapse_user_in_use_maps_any_explicit_4xx_to_conflict(channels, monkeypatch):
    import io

    calls = 0

    class NonceResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"nonce":"nonce"}'

    def fake_urlopen(request, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            return NonceResponse()
        raise channels.HTTPError(
            request.full_url,
            409,
            "Conflict",
            {},
            io.BytesIO(b'{"errcode":"M_USER_IN_USE"}'),
        )

    monkeypatch.setattr(channels, "_urlopen_no_redirect", fake_urlopen)

    with pytest.raises(channels.MatrixProvisioningError) as caught:
        channels._register_synapse_user(
            "https://matrix.example.org",
            "shared-secret",
            "maverick",
            "correct-horse-battery-staple",
        )

    assert caught.value.status == 409
    assert "already exists" in str(caught.value).lower()


def test_synapse_post_5xx_with_unreadable_body_warns_not_to_retry(
    channels, monkeypatch
):
    import http.client

    calls = 0

    class NonceResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"nonce":"nonce"}'

    class BrokenErrorBody:
        def read(self, _limit):
            raise http.client.IncompleteRead(b"")

        def close(self):
            pass

    def fake_urlopen(request, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            return NonceResponse()
        raise channels.HTTPError(
            request.full_url, 502, "Bad Gateway", {}, BrokenErrorBody()
        )

    monkeypatch.setattr(channels, "_urlopen_no_redirect", fake_urlopen)

    with pytest.raises(channels.MatrixProvisioningError) as caught:
        channels._register_synapse_user(
            "https://matrix.example.org",
            "shared-secret",
            "maverick",
            "correct-horse-battery-staple",
        )

    message = str(caught.value).lower()
    assert "account may have been created" in message
    assert "do not retry" in message


def test_synapse_registration_redirects_are_rejected(channels):
    request = channels.Request("https://matrix.example.org/register")

    assert channels._RejectRedirects().redirect_request(
        request, None, 0, "Found", {}, "https://attacker.example/register"
    ) is None


def test_provisioning_rejects_unexpected_returned_localpart_before_save(
    channels, monkeypatch, tmp_path
):
    monkeypatch.setattr(
        channels,
        "_register_synapse_user",
        lambda *_args: "@someone-else:example.org",
    )

    with pytest.raises(channels.MatrixProvisioningError) as caught:
        channels.provision_matrix_account(
            _valid_payload(
                password="correct-horse-battery-staple",
                registration_secret="registration-secret",
            )
        )

    message = str(caught.value).lower()
    assert "account was created" in message
    assert "do not retry" in message
    assert not (tmp_path / ".env").exists()


def test_remote_success_local_save_failure_is_sanitized_and_actionable(
    channels, monkeypatch
):
    monkeypatch.setattr(
        channels,
        "_register_synapse_user",
        lambda *_args: "@maverick:example.org",
    )

    def fail_save(_payload):
        raise OSError("sensitive disk detail")

    monkeypatch.setattr(channels, "save_matrix_channel", fail_save)

    with pytest.raises(channels.MatrixProvisioningError) as caught:
        channels.provision_matrix_account(
            _valid_payload(
                password="correct-horse-battery-staple",
                registration_secret="registration-secret",
            )
        )

    message = str(caught.value)
    assert caught.value.status == 500
    assert "account was created" in message.lower()
    assert "configure" in message.lower()
    assert "registration-secret" not in message
    assert "sensitive disk detail" not in message
