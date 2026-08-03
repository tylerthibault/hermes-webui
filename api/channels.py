"""Profile-scoped messaging channel configuration.

Secrets are written to the active profile's ``.env`` and are never returned by
read APIs. Non-secret Matrix behavior lives in that profile's ``config.yaml``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import threading
from functools import wraps
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml

from api.config import _save_yaml_config_file
from api.profiles import get_active_hermes_home, get_active_profile_name
from api.channel_gateway_supervisor import (
    get_profile_gateway_status,
    restart_profile_gateway,
    stop_profile_gateway,
)

_MATRIX_ENV_KEYS = (
    "MATRIX_HOMESERVER",
    "MATRIX_USER_ID",
    "MATRIX_ACCESS_TOKEN",
    "MATRIX_PASSWORD",
    "MATRIX_E2EE_MODE",
    "MATRIX_ENCRYPTION",
    "MATRIX_ALLOWED_USERS",
    "MATRIX_ALLOWED_ROOMS",
    "MATRIX_REQUIRE_MENTION",
    "MATRIX_AUTO_THREAD",
    "HERMES_WEBUI_MATRIX_GATEWAY_ENABLED",
)
_MATRIX_USER_ID_RE = re.compile(r"^@[^\s:]+:[^\s:]+$")
_MATRIX_ROOM_ID_RE = re.compile(r"^![^\s:]+:[^\s:]+$")
_MATRIX_LOCALPART_RE = re.compile(r"^[a-z0-9._=-]+$")
_HTTPS_ORIGIN_RE = re.compile(
    r"^https://(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::[0-9]{1,5})?$"
)
_ENV_WRITE_LOCK = threading.RLock()
_CHANNEL_CONFIG_LOCK = threading.RLock()


class MatrixProvisioningError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _urlopen_no_redirect(request: Request, timeout: int):
    return build_opener(_RejectRedirects()).open(request, timeout=timeout)


def _channel_transaction(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with _CHANNEL_CONFIG_LOCK:
            return function(*args, **kwargs)

    return wrapped


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _write_env_updates(path: Path, updates: dict[str, str | None]) -> None:
    """Atomically update selected env keys without mutating process-global env."""
    with _ENV_WRITE_LOCK:
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        key_indexes: dict[str, int] = {}
        for index, raw in enumerate(lines):
            stripped = raw.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key_indexes[stripped.split("=", 1)[0].strip()] = index

        pending: list[str] = []
        for key, value in updates.items():
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"{key} must be a string")
                if "\n" in value or "\r" in value:
                    raise ValueError(f"{key} must not contain newline characters")
            if key in key_indexes:
                lines[key_indexes[key]] = None if value is None else f"{key}={value}"
            elif value is not None:
                pending.append(f"{key}={value}")

        output = [line for line in lines if line is not None]
        if pending:
            if output and output[-1].strip():
                output.append("")
            output.extend(pending)
        content = "\n".join(output)
        if content:
            content += "\n"

        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".env_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(temp_name, path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _read_config(path: Path) -> dict:
    if not path.exists():
        return {}
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def _clean_text(value: object, field: str) -> str:
    text = str(value or "").strip()
    if "\n" in text or "\r" in text:
        raise ValueError(f"{field} must not contain newline characters")
    return text


def _validate_homeserver(value: object) -> str:
    homeserver = _clean_text(value, "homeserver").rstrip("/")
    if not _HTTPS_ORIGIN_RE.fullmatch(homeserver):
        raise ValueError(
            "homeserver must be an HTTPS origin, for example https://matrix.example.org"
        )
    parsed = urlparse(homeserver)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            "homeserver must be an HTTPS origin, for example https://matrix.example.org"
        ) from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("homeserver must be an HTTPS origin, for example https://matrix.example.org")
    return homeserver


def _provisioning_homeserver() -> str:
    """Return the exact operator-approved origin, or empty when misconfigured."""
    configured = os.environ.get("HERMES_WEBUI_MATRIX_PROVISIONING_HOMESERVER", "")
    if not configured:
        return ""
    try:
        validated = _validate_homeserver(configured)
    except ValueError:
        return ""
    return configured if configured == validated else ""


def _validate_opaque_secret(
    value: object,
    field: str,
    *,
    minimum: int,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{field} must not contain newline characters")
    if not value and allow_empty:
        return value
    if len(value) < minimum or len(value) > maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum} characters")
    return value


def _validate_profile_password(value: object, *, allow_empty: bool = False) -> str:
    password = _validate_opaque_secret(
        value,
        "password",
        minimum=12,
        maximum=1024,
        allow_empty=allow_empty,
    )
    if password and (
        "\x00" in password
        or password != password.strip()
        or password.startswith(("\"", "'"))
        or password.endswith(("\"", "'"))
    ):
        raise ValueError(
            "password must not contain NUL or begin or end with whitespace or quote characters"
        )
    return password


def _synapse_registration_mac(
    secret: str,
    nonce: str,
    username: str,
    password: str,
    *,
    admin: bool,
) -> str:
    fields = [nonce, username, password, "admin" if admin else "notadmin"]
    message = b"\x00".join(field.encode("utf-8") for field in fields)
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha1).hexdigest()


def _read_synapse_json(response) -> dict:
    try:
        payload = json.loads(response.read(65537))
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError) as exc:
        raise MatrixProvisioningError("Synapse returned an invalid response", status=502) from exc
    if not isinstance(payload, dict):
        raise MatrixProvisioningError("Synapse returned an invalid response", status=502)
    return payload


def _indeterminate_matrix_creation_error() -> MatrixProvisioningError:
    return MatrixProvisioningError(
        "The Matrix account may have been created, but Synapse did not return a reliable "
        "success response. Do not retry account creation; inspect Synapse and configure "
        "the account manually.",
        status=502,
    )


def _register_synapse_user(homeserver: str, secret: str, username: str, password: str) -> str:
    endpoint = f"{homeserver}/_synapse/admin/v1/register"
    nonce_request = Request(endpoint, headers={"Accept": "application/json"})
    try:
        with _urlopen_no_redirect(nonce_request, timeout=15) as response:
            nonce_payload = _read_synapse_json(response)
    except HTTPError as exc:
        raise MatrixProvisioningError(
            "Synapse rejected the registration nonce request", status=502
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise MatrixProvisioningError(
            "Could not reach the configured Synapse homeserver", status=502
        ) from exc

    nonce = str(nonce_payload.get("nonce") or "")
    if not nonce:
        raise MatrixProvisioningError(
            "Synapse did not provide a registration nonce", status=502
        )

    registration = {
        "nonce": nonce,
        "username": username,
        "password": password,
        "admin": False,
        "mac": _synapse_registration_mac(
            secret,
            nonce,
            username,
            password,
            admin=False,
        ),
    }
    body = json.dumps(registration, separators=(",", ":")).encode("utf-8")
    create_request = Request(
        endpoint,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _urlopen_no_redirect(create_request, timeout=15) as response:
            created = _read_synapse_json(response)
    except HTTPError as exc:
        try:
            error_payload = _read_synapse_json(exc)
        except Exception:
            error_payload = {}
        if error_payload.get("errcode") == "M_USER_IN_USE" and 400 <= exc.code < 500:
            raise MatrixProvisioningError(
                "That Matrix account already exists", status=409
            ) from exc
        if 400 <= exc.code < 500:
            raise MatrixProvisioningError(
                "Synapse rejected the account creation request", status=502
            ) from exc
        raise _indeterminate_matrix_creation_error() from exc
    except MatrixProvisioningError as exc:
        raise _indeterminate_matrix_creation_error() from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise _indeterminate_matrix_creation_error() from exc
    except Exception as exc:
        # Once the POST is submitted, any unexpected response/read failure is
        # indeterminate: Synapse may already have committed the account.
        raise _indeterminate_matrix_creation_error() from exc

    user_id = str(created.get("user_id") or "")
    if not _MATRIX_USER_ID_RE.fullmatch(user_id):
        raise _indeterminate_matrix_creation_error()
    return user_id


def _validate_matrix_id(value: object, field: str, pattern: re.Pattern[str]) -> str:
    matrix_id = _clean_text(value, field)
    if not pattern.fullmatch(matrix_id):
        raise ValueError(f"invalid Matrix {field.replace('_', ' ')}")
    return matrix_id


def _validate_id_list(value: object, field: str, pattern: re.Pattern[str]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    result: list[str] = []
    for item in value:
        matrix_id = _validate_matrix_id(item, field, pattern)
        if matrix_id not in result:
            result.append(matrix_id)
    return result


@_channel_transaction
def get_matrix_channel() -> dict:
    home = Path(get_active_hermes_home())
    env = _read_env_file(home / ".env")
    config = _read_config(home / "config.yaml")
    matrix = config.get("matrix") if isinstance(config.get("matrix"), dict) else {}
    has_token = bool(env.get("MATRIX_ACCESS_TOKEN"))
    has_password = bool(env.get("MATRIX_PASSWORD"))
    homeserver = env.get("MATRIX_HOMESERVER", "")
    user_id = env.get("MATRIX_USER_ID", "")
    profile = str(get_active_profile_name() or "default")
    process_status = get_profile_gateway_status(profile)
    provisioning_homeserver = _provisioning_homeserver()
    return {
        "profile": profile,
        "configured": bool(homeserver and (has_token or (user_id and has_password))),
        "homeserver": homeserver,
        "user_id": user_id,
        "auth_method": "access_token" if has_token else "password",
        "has_access_token": has_token,
        "has_password": has_password,
        "allowed_users": list(matrix.get("allowed_users") or []),
        "allowed_rooms": list(matrix.get("allowed_rooms") or []),
        "require_mention": bool(matrix.get("require_mention", True)),
        "session_scope": str(matrix.get("session_scope") or "room"),
        "auto_thread": bool(matrix.get("auto_thread", False)),
        "e2ee_mode": str(env.get("MATRIX_E2EE_MODE") or "required"),
        "gateway_status": process_status["status"],
        "gateway_managed": process_status["managed"],
        "provisioning_available": bool(provisioning_homeserver),
        "provisioning_homeserver": provisioning_homeserver,
    }


@_channel_transaction
def save_matrix_channel(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("request body must be an object")

    homeserver = _validate_homeserver(payload.get("homeserver"))
    user_id = _validate_matrix_id(payload.get("user_id"), "user_id", _MATRIX_USER_ID_RE)
    allowed_users = _validate_id_list(payload.get("allowed_users"), "allowed_users", _MATRIX_USER_ID_RE)
    allowed_rooms = _validate_id_list(payload.get("allowed_rooms"), "allowed_rooms", _MATRIX_ROOM_ID_RE)
    if not allowed_users:
        raise ValueError("at least one allowed user is required")

    auth_method = _clean_text(payload.get("auth_method"), "auth_method")
    if auth_method not in {"access_token", "password"}:
        raise ValueError("auth_method must be access_token or password")
    session_scope = _clean_text(payload.get("session_scope", "room"), "session_scope")
    if session_scope not in {"auto", "room", "thread"}:
        raise ValueError("session_scope must be auto, room, or thread")
    e2ee_mode = _clean_text(payload.get("e2ee_mode", "required"), "e2ee_mode")
    if e2ee_mode not in {"off", "optional", "required"}:
        raise ValueError("e2ee_mode must be off, optional, or required")

    home = Path(get_active_hermes_home())
    env_path = home / ".env"
    existing = _read_env_file(env_path)
    access_token = _clean_text(payload.get("access_token"), "access_token")
    password = _validate_profile_password(
        payload.get("password", ""), allow_empty=True
    )
    if auth_method == "access_token":
        if not access_token and not existing.get("MATRIX_ACCESS_TOKEN"):
            raise ValueError("an access token is required")
        secret_updates = {"MATRIX_PASSWORD": None}
        if access_token:
            secret_updates["MATRIX_ACCESS_TOKEN"] = access_token
    else:
        if not password and not existing.get("MATRIX_PASSWORD"):
            raise ValueError("a password is required")
        secret_updates = {"MATRIX_ACCESS_TOKEN": None}
        if password:
            secret_updates["MATRIX_PASSWORD"] = password

    _write_env_updates(
        env_path,
        {
            "MATRIX_HOMESERVER": homeserver,
            "MATRIX_USER_ID": user_id,
            "MATRIX_E2EE_MODE": e2ee_mode,
            "MATRIX_ENCRYPTION": "false" if e2ee_mode == "off" else "true",
            "MATRIX_ALLOWED_USERS": ",".join(allowed_users),
            "MATRIX_ALLOWED_ROOMS": ",".join(allowed_rooms),
            "MATRIX_REQUIRE_MENTION": "true" if bool(payload.get("require_mention", True)) else "false",
            "MATRIX_AUTO_THREAD": "true" if bool(payload.get("auto_thread", False)) else "false",
            **secret_updates,
        },
    )

    config_path = home / "config.yaml"
    config = _read_config(config_path)
    config["matrix"] = {
        "allowed_users": allowed_users,
        "allowed_rooms": allowed_rooms,
        "require_mention": bool(payload.get("require_mention", True)),
        "session_scope": session_scope,
        "auto_thread": bool(payload.get("auto_thread", False)),
    }
    _save_yaml_config_file(config_path, config)
    return get_matrix_channel()


@_channel_transaction
def provision_matrix_account(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("request body must be an object")

    requested_homeserver = payload.get("homeserver")
    homeserver = _validate_homeserver(requested_homeserver)
    provisioning_homeserver = _provisioning_homeserver()
    if not provisioning_homeserver or homeserver != provisioning_homeserver:
        raise ValueError("homeserver must exactly match the operator-configured homeserver")
    registration_secret = _validate_opaque_secret(
        payload.get("registration_secret"),
        "registration_secret",
        minimum=1,
        maximum=4096,
    )

    profile = str(get_active_profile_name() or "default")
    username = profile.lower()
    if not _MATRIX_LOCALPART_RE.fullmatch(username):
        raise ValueError("the active profile name cannot be used as a Matrix username")

    password = _validate_profile_password(payload.get("password"))

    # Validate all local configuration before creating the durable Synapse account.
    allowed_users = _validate_id_list(
        payload.get("allowed_users"), "allowed_users", _MATRIX_USER_ID_RE
    )
    if not allowed_users:
        raise ValueError("at least one allowed user is required")
    _validate_id_list(payload.get("allowed_rooms"), "allowed_rooms", _MATRIX_ROOM_ID_RE)
    session_scope = _clean_text(payload.get("session_scope", "room"), "session_scope")
    if session_scope not in {"auto", "room", "thread"}:
        raise ValueError("session_scope must be auto, room, or thread")
    e2ee_mode = _clean_text(payload.get("e2ee_mode", "required"), "e2ee_mode")
    if e2ee_mode not in {"off", "optional", "required"}:
        raise ValueError("e2ee_mode must be off, optional, or required")

    user_id = _register_synapse_user(
        homeserver,
        registration_secret,
        username,
        password,
    )
    if (
        not isinstance(user_id, str)
        or not _MATRIX_USER_ID_RE.fullmatch(user_id)
        or user_id.split(":", 1)[0] != f"@{username}"
    ):
        raise MatrixProvisioningError(
            "The Matrix account was created, but Synapse returned an unexpected Matrix user ID. "
            "The credentials were not saved; do not retry account creation. Configure the "
            "created account manually.",
            status=502,
        )
    saved_payload = {
        key: value for key, value in payload.items() if key != "registration_secret"
    }
    saved_payload.update(
        {
            "homeserver": homeserver,
            "user_id": user_id,
            "auth_method": "password",
            "access_token": "",
            "password": password,
        }
    )
    try:
        return save_matrix_channel(saved_payload)
    except Exception as exc:
        raise MatrixProvisioningError(
            "The Matrix account was created, but its credentials could not be saved to "
            "the active profile. Configure the created account manually before retrying.",
            status=500,
        ) from exc


@_channel_transaction
def clear_matrix_channel() -> dict:
    profile = str(get_active_profile_name() or "default")
    home = Path(get_active_hermes_home())
    _write_env_updates(home / ".env", {"HERMES_WEBUI_MATRIX_GATEWAY_ENABLED": "0"})
    stop_profile_gateway(profile)
    _write_env_updates(home / ".env", {key: None for key in _MATRIX_ENV_KEYS})
    config_path = home / "config.yaml"
    config = _read_config(config_path)
    config.pop("matrix", None)
    _save_yaml_config_file(config_path, config)
    return get_matrix_channel()


@_channel_transaction
def restart_matrix_gateway() -> dict:
    profile = str(get_active_profile_name() or "default")
    home = Path(get_active_hermes_home())
    current = get_matrix_channel()
    if not current.get("configured"):
        raise ValueError("Matrix must be configured before starting the gateway")
    _write_env_updates(home / ".env", {"HERMES_WEBUI_MATRIX_GATEWAY_ENABLED": "1"})
    result = restart_profile_gateway(profile)
    return {
        **result,
        "message": f"Matrix gateway is running for profile {profile}",
    }
