"""Fixed-endpoint GitHub OAuth login backed by stable numeric identities."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookies
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from api import auth_users
from api.config import get_config

logger = logging.getLogger(__name__)

AUTHORIZATION_ENDPOINT = "https://github.com/login/oauth/authorize"
TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
USER_ENDPOINT = "https://api.github.com/user"
GITHUB_ISSUER = "https://github.com"
FLOW_COOKIE_NAME = "hermes_github_oauth_flow"
CALLBACK_PATH = "/api/auth/github/callback"

_PENDING_TTL_SECONDS = 600
_MAX_PENDING_FLOWS = 128
_MAX_RESPONSE_BYTES = 1024 * 1024
_USER_AGENT = "Hermes-WebUI GitHub OAuth"
_STATE_COOKIE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

_pending_lock = threading.Lock()
_pending_flows: dict[str, dict[str, Any]] = {}


class GitHubConfigError(Exception):
    pass


class GitHubAuthError(Exception):
    def __init__(self, message: str, *, status_code: int = 401):
        super().__init__(message)
        self.status_code = status_code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def is_github_enabled() -> bool:
    cfg = _resolve_github_config()
    return bool(cfg.get("client_id") and cfg.get("client_secret"))


def _resolve_github_config() -> dict[str, Any]:
    """Resolve supported settings only; provider URLs are intentionally fixed."""
    raw: dict[str, Any] = {}
    try:
        config = get_config()
        value = config.get("webui_github") if isinstance(config, dict) else None
        if isinstance(value, dict):
            raw.update(value)
    except Exception:
        logger.debug("Failed to read webui_github config", exc_info=True)

    def pick(name: str, environment: str) -> Any:
        value = os.getenv(environment)
        return value if value is not None else raw.get(name)

    return {
        "client_id": str(
            pick("client_id", "HERMES_WEBUI_GITHUB_CLIENT_ID") or ""
        ).strip(),
        "client_secret": str(
            pick("client_secret", "HERMES_WEBUI_GITHUB_CLIENT_SECRET") or ""
        ).strip(),
        "redirect_uri": str(
            pick("redirect_uri", "HERMES_WEBUI_GITHUB_REDIRECT_URI") or ""
        ).strip(),
        "allow_user_ids": _numeric_user_ids(
            pick("allow_user_ids", "HERMES_WEBUI_GITHUB_ALLOW_USER_IDS")
        ),
        "auto_provision": _as_bool(
            pick("auto_provision", "HERMES_WEBUI_GITHUB_AUTO_PROVISION")
        ),
        "default_profiles": _valid_profile_ids(
            pick("default_profiles", "HERMES_WEBUI_GITHUB_DEFAULT_PROFILES")
        ),
        "bootstrap_admin_user_id": _canonical_bootstrap_user_id(
            pick(
                "bootstrap_admin_user_id",
                "HERMES_WEBUI_GITHUB_BOOTSTRAP_ADMIN_USER_ID",
            )
        ),
    }


def _require_config() -> dict[str, Any]:
    cfg = _resolve_github_config()
    if not cfg.get("client_id") or not cfg.get("client_secret"):
        raise GitHubConfigError(
            "GitHub login requires a client ID and client secret"
        )
    return cfg


def build_authorization_redirect(
    request_base_url: str, next_path: str | None = None
) -> str:
    cfg = _require_config()
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = _b64u(hashlib.sha256(verifier.encode("ascii")).digest())
    _store_pending_flow(
        state,
        {
            "created_at": time.time(),
            "code_verifier": verifier,
            "next_path": _safe_next_path(next_path),
        },
    )
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": _redirect_uri(cfg, request_base_url),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return AUTHORIZATION_ENDPOINT + "?" + urllib.parse.urlencode(params)


def flow_state_from_authorization_redirect(location: str) -> str:
    states = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get(
        "state", []
    )
    if len(states) != 1 or not states[0]:
        raise GitHubAuthError(
            "GitHub authorization redirect did not include state", status_code=502
        )
    return states[0]


def flow_cookie_header(
    state: str = "", *, secure: bool = False, clear: bool = False
) -> str:
    if not clear and not _valid_flow_state(state):
        raise GitHubAuthError("GitHub authorization state was invalid", status_code=502)
    max_age = 0 if clear else _PENDING_TTL_SECONDS
    header = (
        f"{FLOW_COOKIE_NAME}={state}; Path={CALLBACK_PATH}; Max-Age={max_age}; "
        "HttpOnly; SameSite=Lax"
    )
    if secure:
        header += "; Secure"
    return header


def flow_cookie_matches(cookie_header: str, callback_state: str) -> bool:
    if not cookie_header or not _valid_flow_state(callback_state):
        return False
    cookies = http.cookies.SimpleCookie()
    try:
        cookies.load(cookie_header)
    except http.cookies.CookieError:
        return False
    value = cookies.get(FLOW_COOKIE_NAME)
    return (
        bool(value)
        and _valid_flow_state(value.value)
        and hmac.compare_digest(value.value, callback_state)
    )


def _valid_flow_state(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and all(character in _STATE_COOKIE_CHARS for character in value)
    )


def complete_authorization_code_flow(
    request_base_url: str, state: str, code: str
) -> dict[str, Any]:
    pending = _consume_pending_flow(state)
    if pending is None:
        raise GitHubAuthError("Invalid GitHub OAuth state")
    cfg = _require_config()

    token_response = _request_json(
        urllib.request.Request(
            TOKEN_ENDPOINT,
            data=urllib.parse.urlencode(
                {
                    "client_id": cfg["client_id"],
                    "client_secret": cfg["client_secret"],
                    "code": code,
                    "redirect_uri": _redirect_uri(cfg, request_base_url),
                    "code_verifier": pending["code_verifier"],
                }
            ).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": _USER_AGENT,
            },
            method="POST",
        ),
        "GitHub authorization code exchange failed",
    )
    access_token = token_response.get("access_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise GitHubAuthError(
            "GitHub token response did not include an access token", status_code=502
        )
    access_token = access_token.strip()
    user_payload = _request_json(
        urllib.request.Request(
            USER_ENDPOINT,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": _USER_AGENT,
            },
        ),
        "GitHub user lookup failed",
    )
    # The provider credential is deliberately not included in, attached to, or
    # persisted with the admission result. It becomes unreachable after return.
    try:
        user = _admit_github_identity(user_payload, cfg)
    except GitHubAuthError:
        raise
    except Exception as exc:
        # Do not log the provider payload or credential, even at debug level.
        logger.warning("GitHub identity admission failed")
        raise GitHubAuthError(
            "GitHub identity could not be verified", status_code=502
        ) from exc
    return {
        "next_path": pending["next_path"],
        "user": user,
        "external_issuer": GITHUB_ISSUER,
        "external_subject": str(user_payload["id"]),
    }


def _admit_github_identity(
    user_payload: dict[str, Any], cfg: dict[str, Any]
) -> dict[str, Any]:
    numeric_id = user_payload.get("id")
    if type(numeric_id) is not int or numeric_id <= 0:
        raise GitHubAuthError(
            "GitHub user response did not include a valid numeric user ID",
            status_code=502,
        )
    subject = str(numeric_id)
    display_name = _display_name(user_payload, subject)
    email_value = user_payload.get("email")
    email = email_value.strip() if isinstance(email_value, str) else ""

    existing = auth_users.find_user_by_identity(
        "github", GITHUB_ISSUER, subject
    )
    if existing is not None:
        if existing.get("enabled") is not True:
            raise GitHubAuthError("GitHub identity is disabled", status_code=403)
        user = auth_users.upsert_external_user(
            "github",
            GITHUB_ISSUER,
            subject,
            display_name=display_name,
            email=email,
        )
        if user is None:
            raise GitHubAuthError("GitHub identity is not admitted", status_code=403)
        return user

    bootstrap_target = cfg.get("bootstrap_admin_user_id")
    if isinstance(bootstrap_target, str) and subject == bootstrap_target:
        try:
            bootstrapped = auth_users.bootstrap_external_admin_if_empty(
                "github",
                GITHUB_ISSUER,
                subject,
                display_name,
                email,
                bootstrap_target,
                profiles=cfg.get("default_profiles", []),
            )
        except ValueError as exc:
            raise GitHubAuthError(
                "GitHub bootstrap administrator profiles are invalid or unavailable",
                status_code=403,
            ) from exc
        if bootstrapped is not None:
            return bootstrapped
        # Another exact callback may have won the empty-store race. Admit only
        # the same stable numeric identity, never whichever identity won first.
        raced = auth_users.find_user_by_identity("github", GITHUB_ISSUER, subject)
        if raced is not None:
            if raced.get("enabled") is not True:
                raise GitHubAuthError("GitHub identity is disabled", status_code=403)
            user = auth_users.upsert_external_user(
                "github",
                GITHUB_ISSUER,
                subject,
                display_name=display_name,
                email=email,
            )
            if user is not None:
                return user

    invited = auth_users.consume_invitation_and_create_user(
        "github",
        subject,
        GITHUB_ISSUER,
        subject,
        display_name,
        email,
    )
    if invited is not None:
        return invited

    if (
        not cfg.get("auto_provision")
        or subject not in cfg.get("allow_user_ids", [])
        or not cfg.get("default_profiles")
    ):
        raise GitHubAuthError("GitHub identity is not admitted", status_code=403)
    user = auth_users.upsert_external_user(
        "github",
        GITHUB_ISSUER,
        subject,
        display_name=display_name,
        email=email,
        allow_create=True,
        profiles=cfg["default_profiles"],
    )
    if user is None:
        raise GitHubAuthError(
            "GitHub identity could not be provisioned", status_code=403
        )
    return user


def _display_name(user_payload: dict[str, Any], subject: str) -> str:
    for field in ("name", "login"):
        value = user_payload.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return f"GitHub user {subject}"


def _request_json(
    request: urllib.request.Request, safe_error: str
) -> dict[str, Any]:
    try:
        with _github_opener().open(request, timeout=10) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise GitHubAuthError(
                "GitHub returned an oversized response", status_code=502
            )
        payload = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except GitHubAuthError:
        raise
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        raise GitHubAuthError(safe_error, status_code=502) from exc
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise GitHubAuthError(
            "GitHub returned an invalid JSON response", status_code=502
        ) from exc
    if not isinstance(payload, dict):
        raise GitHubAuthError(
            "GitHub returned an invalid JSON response", status_code=502
        )
    return payload


def _github_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)


def _store_pending_flow(state: str, payload: dict[str, Any]) -> None:
    now = time.time()
    with _pending_lock:
        _prune_pending_flows(now)
        if state in _pending_flows:
            raise GitHubAuthError(
                "Authentication flow state could not be reserved", status_code=503
            )
        if len(_pending_flows) >= _MAX_PENDING_FLOWS:
            raise GitHubAuthError(
                "Too many authentication flows are already pending", status_code=429
            )
        _pending_flows[state] = payload


def _consume_pending_flow(state: str) -> dict[str, Any] | None:
    now = time.time()
    with _pending_lock:
        _prune_pending_flows(now)
        return _pending_flows.pop(state, None)


def _prune_pending_flows(now: float) -> None:
    expired = [
        state
        for state, payload in _pending_flows.items()
        if now - float(payload.get("created_at") or 0) > _PENDING_TTL_SECONDS
    ]
    for state in expired:
        _pending_flows.pop(state, None)


def _redirect_uri(cfg: dict[str, Any], request_base_url: str) -> str:
    explicit = str(cfg.get("redirect_uri") or "").strip()
    return explicit or request_base_url.rstrip("/") + CALLBACK_PATH


def _safe_next_path(raw_path: str | None) -> str:
    path = str(raw_path or "").strip()
    if (
        not path
        or not path.startswith("/")
        or path[1:2] in {"/", "\\"}
        or any(
            ord(character) < 32
            or ord(character) == 127
            or character.isspace()
            for character in path
        )
    ):
        return "/"
    return path


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {
        "1", "true", "yes", "on"
    }


def _text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [text for item in value if (text := str(item).strip())]
    text = str(value).replace("\n", ",")
    result: list[str] = []
    for comma_part in text.split(","):
        result.extend(item for item in comma_part.split() if item)
    return result


def _numeric_user_ids(value: Any) -> list[str]:
    result: list[str] = []
    for candidate in _text_list(value):
        if (
            candidate.isascii()
            and candidate.isdigit()
            and candidate != "0"
            and str(int(candidate)) == candidate
            and candidate not in result
        ):
            result.append(candidate)
        else:
            logger.warning("Ignoring invalid GitHub allowlisted user ID: %r", candidate)
    return result


def _canonical_bootstrap_user_id(value: Any) -> str:
    if value is None:
        return ""
    candidate = str(value).strip()
    if not candidate:
        return ""
    try:
        return auth_users._canonical_invitation_target("github", candidate)[1]
    except ValueError:
        # Never put the configured administrator identifier in logs.
        logger.warning("Ignoring invalid GitHub bootstrap administrator user ID")
        return ""


def _valid_profile_ids(value: Any) -> list[str]:
    result: list[str] = []
    for profile_id in _text_list(value):
        if profile_id in result:
            continue
        try:
            auth_users._validate_profiles([profile_id])
        except ValueError:
            logger.warning(
                "Ignoring invalid GitHub default profile ID: %r", profile_id
            )
            continue
        result.append(profile_id)
    return result


def _reject_constant(value: str):
    raise ValueError(f"Unsupported JSON constant: {value}")


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
