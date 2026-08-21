"""Local users, invitations, external identities, and role-based access state.

The store is deliberately independent from the existing single-user auth paths. Merely
importing this module does not create or change any state; callers opt into it by using
one of the public functions below.
"""

from __future__ import annotations

import copy
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from api import config
from api import profiles as profiles_api
from api.profiles import _PROFILE_ID_RE, _profiles_match

try:  # POSIX, including all supported server/container deployments.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None  # type: ignore[assignment]


STORE_VERSION = 3
GOOGLE_ISSUER = "https://accounts.google.com"
GITHUB_ISSUER = "https://github.com"
INVITATION_MAX_AGE = timedelta(days=30)
MAX_ACTIVE_INVITATIONS = 256
MAX_AUTH_STORE_BYTES = 2 * 1024 * 1024
PASSWORD_HASH_ALGORITHM = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 600_000
ROLES = frozenset({"admin", "member"})

# Permission names are intentionally capability-oriented rather than HTTP-route names.
# Profile assignment remains a separate, per-user decision in user_allows_profile().
_ROLE_PERMISSIONS = {
    "member": frozenset({"chat", "profiles:read"}),
    # Privileged route policy lives in api.auth. The wildcard means newly-added
    # administrative capabilities fail closed for members without duplicating
    # every route capability in this role bundle.
    "admin": frozenset(
        {"*", "chat", "profiles:read", "profiles:write", "users:read", "users:write"}
    ),
}

_USER_FIELDS = frozenset(
    {
        "id",
        "display_name",
        "email",
        "role",
        "enabled",
        "profiles",
        "identities",
        "created_at",
        "updated_at",
        "last_login_at",
        "username",
        "password_hash",
        "failed_login_count",
        "last_failed_login_at",
        "session_revocation_version",
    }
)
_LEGACY_USER_FIELDS = _USER_FIELDS - frozenset(
    {
        "username",
        "password_hash",
        "failed_login_count",
        "last_failed_login_at",
        "session_revocation_version",
    }
)
_UPDATE_FIELDS = frozenset(
    {"display_name", "email", "role", "enabled", "profiles", "identities", "username"}
)
_IDENTITY_FIELDS = frozenset({"provider", "issuer", "subject"})
_INVITATION_FIELDS = frozenset(
    {"id", "provider", "target", "profiles", "created_at", "expires_at", "created_by"}
)
_GOOGLE_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)
_process_lock = threading.RLock()


class AuthUserStoreError(RuntimeError):
    """Raised when persisted auth-user state cannot be safely read or validated."""


def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_HASH_ITERATIONS)
    return "$".join((PASSWORD_HASH_ALGORITHM, str(PASSWORD_HASH_ITERATIONS), base64.urlsafe_b64encode(salt).decode(), base64.urlsafe_b64encode(digest).decode()))


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != PASSWORD_HASH_ALGORITHM:
            return False
        iterations = int(iterations_text)
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return False


def _store_path() -> Path:
    return Path(config.STATE_DIR) / ".auth_users.json"


def _lock_path() -> Path:
    return Path(config.STATE_DIR) / ".auth_users.lock"


@contextmanager
def _locked_store() -> Iterator[None]:
    """Serialize reads and read-modify-write operations in and across processes."""
    with _process_lock:
        Path(config.STATE_DIR).mkdir(parents=True, exist_ok=True)
        lock_path = _lock_path()
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.chmod(lock_path, 0o600)
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _empty_store() -> dict[str, Any]:
    return {"version": STORE_VERSION, "users": [], "invitations": []}


def _read_store_unlocked() -> dict[str, Any]:
    path = _store_path()
    if not path.exists():
        return _empty_store()
    try:
        with path.open("r", encoding="utf-8") as handle:
            # Correct permissive modes before any contents cross the trust boundary.
            # fchmod applies to the file we actually opened rather than re-resolving
            # the path between a permission check and the read.
            os.fchmod(handle.fileno(), 0o600)
            if os.fstat(handle.fileno()).st_size > MAX_AUTH_STORE_BYTES:
                raise AuthUserStoreError("Auth user store is too large")
            store = json.load(handle)
        if isinstance(store, dict) and type(store.get("version")) is int and store["version"] in {1, 2}:
            if store["version"] == 1:
                _validate_v1_store(store)
            else:
                _validate_legacy_store(store)
            store = {
                "version": STORE_VERSION,
                "users": [_with_local_fields(user) for user in store["users"]],
                "invitations": store.get("invitations", []),
            }
            _write_store_unlocked(store)
        else:
            _validate_store(store)
    except AuthUserStoreError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise AuthUserStoreError(f"Could not read auth user store: {exc}") from exc
    return store


def _write_store_unlocked(store: dict[str, Any]) -> None:
    _validate_store(store)
    serialized = json.dumps(store, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(serialized.encode("utf-8")) > MAX_AUTH_STORE_BYTES:
        raise AuthUserStoreError("Auth user store is too large")
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f"{path.name}.",
        suffix=".tmp",
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        # Make the directory entry durable where the platform supports it.
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _validate_store(store: Any) -> None:
    if not isinstance(store, dict):
        raise AuthUserStoreError("Auth user store must be a JSON object")
    if set(store) != {"version", "users", "invitations"}:
        raise AuthUserStoreError("Auth user store has an invalid shape")
    if type(store.get("version")) is not int or store["version"] != STORE_VERSION:
        raise AuthUserStoreError("Unsupported auth user store version")
    users = store.get("users")
    if not isinstance(users, list):
        raise AuthUserStoreError("Auth user store users must be a list")

    user_ids: set[str] = set()
    identity_keys: set[tuple[str, str, str]] = set()
    for user in users:
        try:
            _validate_user(user)
        except ValueError as exc:
            raise AuthUserStoreError(f"Invalid auth user store: {exc}") from exc
        if user["id"] in user_ids:
            raise AuthUserStoreError("Invalid auth user store: duplicate user ID")
        user_ids.add(user["id"])
        for identity in user["identities"]:
            key = _identity_key(identity)
            if key in identity_keys:
                raise AuthUserStoreError("Invalid auth user store: duplicate identity")
            identity_keys.add(key)

    invitations = store.get("invitations")
    if not isinstance(invitations, list):
        raise AuthUserStoreError("Auth user store invitations must be a list")
    invitation_ids: set[str] = set()
    invitation_targets: set[tuple[str, str]] = set()
    for invitation in invitations:
        try:
            _validate_invitation(invitation)
        except ValueError as exc:
            raise AuthUserStoreError(
                f"Invalid auth user store invitation: {exc}"
            ) from exc
        if invitation["created_by"] not in user_ids:
            raise AuthUserStoreError("Invalid auth user store: invitation creator does not exist")
        if invitation["id"] in invitation_ids:
            raise AuthUserStoreError("Invalid auth user store: duplicate invitation ID")
        invitation_ids.add(invitation["id"])
        key = (invitation["provider"], invitation["target"])
        if key in invitation_targets:
            raise AuthUserStoreError("Invalid auth user store: duplicate invitation target")
        invitation_targets.add(key)


def _validate_v1_store(store: Any) -> None:
    if not isinstance(store, dict) or set(store) != {"version", "users"}:
        raise AuthUserStoreError("Auth user store v1 has an invalid shape")
    if type(store.get("version")) is not int or store["version"] != 1:
        raise AuthUserStoreError("Unsupported auth user store version")
    users = store.get("users")
    if not isinstance(users, list):
        raise AuthUserStoreError("Auth user store users must be a list")

    user_ids: set[str] = set()
    identity_keys: set[tuple[str, str, str]] = set()
    for user in users:
        try:
            if isinstance(user, dict) and set(user) == _USER_FIELDS:
                _validate_user(user)
            else:
                _validate_legacy_user(user)
        except ValueError as exc:
            raise AuthUserStoreError(f"Invalid auth user store: {exc}") from exc
        if user["id"] in user_ids:
            raise AuthUserStoreError("Invalid auth user store: duplicate user ID")
        user_ids.add(user["id"])
        for identity in user["identities"]:
            key = _identity_key(identity)
            if key in identity_keys:
                raise AuthUserStoreError("Invalid auth user store: duplicate identity")
            identity_keys.add(key)


def _validate_legacy_store(store: Any) -> None:
    if not isinstance(store, dict) or set(store) != {"version", "users", "invitations"}:
        raise AuthUserStoreError("Auth user store v2 has an invalid shape")
    if type(store.get("version")) is not int or store["version"] != 2:
        raise AuthUserStoreError("Unsupported auth user store version")
    if not isinstance(store["users"], list) or not isinstance(store["invitations"], list):
        raise AuthUserStoreError("Auth user store v2 has invalid lists")
    for user in store["users"]:
        try:
            _validate_legacy_user(user)
        except ValueError as exc:
            raise AuthUserStoreError(f"Invalid auth user store: {exc}") from exc


def _validate_legacy_user(user: Any) -> None:
    if not isinstance(user, dict) or set(user) != _LEGACY_USER_FIELDS:
        raise ValueError("user has invalid or unknown fields")
    _validate_user(
        {
            **user,
            "username": None,
            "password_hash": None,
            "failed_login_count": 0,
            "last_failed_login_at": None,
            "session_revocation_version": 0,
        }
    )


def _with_local_fields(user: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **copy.deepcopy(dict(user)),
        "username": None,
        "password_hash": None,
        "failed_login_count": 0,
        "last_failed_login_at": None,
        "session_revocation_version": 0,
    }


def _validate_user(user: Any) -> None:
    if not isinstance(user, dict) or set(user) != _USER_FIELDS:
        raise ValueError("user has invalid or unknown fields")
    if not isinstance(user["id"], str):
        raise ValueError("user id must be a canonical UUID")
    try:
        if str(uuid.UUID(user["id"])) != user["id"]:
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise ValueError("user id must be a canonical UUID") from exc
    for field in ("display_name", "email"):
        if not isinstance(user[field], str):
            raise ValueError(f"{field} must be a string")
    for field in ("created_at", "updated_at"):
        _validate_timestamp(user[field], field)
    if user["last_login_at"] is not None:
        _validate_timestamp(user["last_login_at"], "last_login_at")
    if user["last_failed_login_at"] is not None:
        _validate_timestamp(user["last_failed_login_at"], "last_failed_login_at")
    if user["username"] is not None:
        if user["username"] != _normalize_username(user["username"]):
            raise ValueError("username must be canonical")
    if user["password_hash"] is not None and not isinstance(user["password_hash"], str):
        raise ValueError("password_hash must be a string or null")
    if not isinstance(user["failed_login_count"], int) or user["failed_login_count"] < 0:
        raise ValueError("failed_login_count must be a non-negative integer")
    if not isinstance(user["session_revocation_version"], int) or user["session_revocation_version"] < 0:
        raise ValueError("session_revocation_version must be a non-negative integer")
    _validate_role(user["role"])
    if not isinstance(user["enabled"], bool):
        raise ValueError("enabled must be a boolean")
    _validate_profiles(user["profiles"])
    _validate_identities(user["identities"])


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} must be a UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise ValueError(f"{field} must be a UTC timestamp")
    return parsed


def _validate_timestamp(value: Any, field: str) -> str:
    _parse_timestamp(value, field)
    return value


def _validate_role(role: Any) -> str:
    if not isinstance(role, str) or role not in ROLES:
        raise ValueError("role must be exactly 'admin' or 'member'")
    return role


def _validate_profiles(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("profiles must be a list")
    seen: set[str] = set()
    for profile_id in value:
        if not isinstance(profile_id, str) or (
            profile_id != "default" and not _PROFILE_ID_RE.fullmatch(profile_id)
        ):
            raise ValueError(f"Invalid profile ID: {profile_id!r}")
        if profile_id in seen:
            raise ValueError(f"Duplicate profile ID: {profile_id!r}")
        seen.add(profile_id)
    return value


def _canonical_invitation_target(provider: Any, target: Any) -> tuple[str, str]:
    if not isinstance(provider, str) or provider not in {"google", "github"}:
        raise ValueError("invitation provider must be exactly 'google' or 'github'")
    if not isinstance(target, str):
        raise ValueError("invitation target must be a string")
    candidate = target.strip()
    if provider == "google":
        if (
            not candidate
            or not candidate.isascii()
            or len(candidate) > 320
            or _GOOGLE_EMAIL_RE.fullmatch(candidate) is None
        ):
            raise ValueError("Google invitation target must be a valid email")
        return provider, candidate.lower()
    if (
        not candidate
        or not candidate.isascii()
        or not candidate.isdigit()
        or candidate == "0"
        or str(int(candidate)) != candidate
    ):
        raise ValueError("GitHub invitation target must be a canonical positive decimal user ID")
    return provider, candidate


def _validate_invitation(invitation: Any) -> None:
    if not isinstance(invitation, dict) or set(invitation) != _INVITATION_FIELDS:
        raise ValueError("invitation has invalid or unknown fields")
    invitation_id = invitation["id"]
    if (
        not isinstance(invitation_id, str)
        or not (16 <= len(invitation_id) <= 256)
        or not invitation_id.isascii()
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in invitation_id)
    ):
        raise ValueError("invitation id must be an opaque URL-safe value")
    provider, target = _canonical_invitation_target(
        invitation["provider"], invitation["target"]
    )
    if provider != invitation["provider"] or target != invitation["target"]:
        raise ValueError("invitation provider and target must be canonical")
    _validate_profiles(invitation["profiles"])
    created_at = _parse_timestamp(invitation["created_at"], "created_at")
    expires_at = _parse_timestamp(invitation["expires_at"], "expires_at")
    if expires_at <= created_at:
        raise ValueError("invitation expires_at must be after created_at")
    if expires_at - created_at > INVITATION_MAX_AGE:
        raise ValueError("invitation expiry may not exceed 30 days")
    creator = invitation["created_by"]
    if not isinstance(creator, str):
        raise ValueError("invitation created_by must be a canonical UUID")
    try:
        if str(uuid.UUID(creator)) != creator:
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise ValueError("invitation created_by must be a canonical UUID") from exc


def _validate_identities(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ValueError("identities must be a list")
    seen: set[tuple[str, str, str]] = set()
    for identity in value:
        if not isinstance(identity, dict) or set(identity) != _IDENTITY_FIELDS:
            raise ValueError("identity has invalid or unknown fields")
        key = _identity_key(identity)
        if any(not part for part in key):
            raise ValueError("identity provider, issuer, and subject must be non-empty strings")
        if key in seen:
            raise ValueError("Duplicate identity")
        seen.add(key)
    return value


def _identity(provider: Any, issuer: Any, subject: Any) -> dict[str, str]:
    identity = {
        "provider": _required_text(provider, "provider"),
        "issuer": _required_text(issuer, "issuer"),
        "subject": _required_text(subject, "subject"),
    }
    _validate_identities([identity])
    return identity


def _identity_key(identity: Mapping[str, Any]) -> tuple[str, str, str]:
    values = tuple(identity.get(field) for field in ("provider", "issuer", "subject"))
    if any(not isinstance(value, str) for value in values):
        raise ValueError("identity provider, issuer, and subject must be strings")
    return tuple(value.strip() for value in values)  # type: ignore[return-value]


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"identity {field} must be a non-empty string")
    return value.strip()


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value.strip()


def _normalize_username(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("username must be a string")
    normalized = value.strip().casefold()
    if not normalized or len(normalized) > 128 or any(character.isspace() for character in normalized):
        raise ValueError("username must be non-empty and contain no whitespace")
    return normalized


def hash_local_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 12 or len(password) > 1024:
        raise ValueError("password must be between 12 and 1024 characters")
    iterations = 310_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
    )


def verify_local_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, raw_iterations, raw_salt, raw_digest = password_hash.split("$", 3)
        iterations = int(raw_iterations)
        if algorithm != "pbkdf2_sha256" or not 100_000 <= iterations <= 1_000_000:
            return False
        salt = base64.urlsafe_b64decode(raw_salt + "=" * (-len(raw_salt) % 4))
        expected = base64.urlsafe_b64decode(raw_digest + "=" * (-len(raw_digest) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return False


def _canonical_identities(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ValueError("identities must be a list")
    identities = []
    for identity in value:
        if not isinstance(identity, dict) or set(identity) != _IDENTITY_FIELDS:
            raise ValueError("identity has invalid or unknown fields")
        identities.append(
            _identity(identity["provider"], identity["issuer"], identity["subject"])
        )
    _validate_identities(identities)
    return identities


def _now_datetime() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _now() -> str:
    return _timestamp(_now_datetime())


def _find_index_by_identity(
    store: Mapping[str, Any], identity_key: tuple[str, str, str]
) -> int | None:
    for index, user in enumerate(store["users"]):
        if any(_identity_key(identity) == identity_key for identity in user["identities"]):
            return index
    return None


def find_user_by_identity(provider: str, issuer: str, subject: str) -> dict[str, Any] | None:
    """Return the user bound to provider + issuer + subject, never by email."""
    key = _identity_key(_identity(provider, issuer, subject))
    with _locked_store():
        store = _read_store_unlocked()
        index = _find_index_by_identity(store, key)
        return copy.deepcopy(store["users"][index]) if index is not None else None


def get_user(user_id: str) -> dict[str, Any] | None:
    with _locked_store():
        store = _read_store_unlocked()
        for user in store["users"]:
            if user["id"] == user_id:
                return copy.deepcopy(user)
    return None


def list_users() -> list[dict[str, Any]]:
    with _locked_store():
        return copy.deepcopy(_read_store_unlocked()["users"])


def has_local_users() -> bool:
    with _locked_store():
        return any(user.get("username") and user.get("password_hash") for user in _read_store_unlocked()["users"])


def _find_index_by_username(store: Mapping[str, Any], username: str) -> int | None:
    for index, user in enumerate(store["users"]):
        if user["username"] == username:
            return index
    return None


def find_user_by_username(username: str) -> dict[str, Any] | None:
    normalized = _normalize_username(username)
    with _locked_store():
        store = _read_store_unlocked()
        index = _find_index_by_username(store, normalized)
        return copy.deepcopy(store["users"][index]) if index is not None else None


def create_local_user(
    *,
    username: str,
    display_name: str,
    password_hash: str,
    role: str = "member",
    email: str = "",
    profiles: list[str] | None = None,
) -> dict[str, Any]:
    normalized = _normalize_username(username)
    display_name = _text(display_name, "display_name")
    email = _text(email, "email")
    if not isinstance(password_hash, str) or not password_hash.strip():
        raise ValueError("password_hash must be a non-empty string")
    role = _validate_role(role)
    canonical_profiles = copy.deepcopy(_validate_profiles(profiles or []))
    _validate_existing_profiles(canonical_profiles, subject="user")
    with _locked_store():
        store = _read_store_unlocked()
        if _find_index_by_username(store, normalized) is not None:
            raise ValueError("username already exists")
        now = _now()
        user = {
            "id": str(uuid.uuid4()),
            "display_name": display_name,
            "email": email,
            "role": role,
            "enabled": True,
            "profiles": canonical_profiles,
            "identities": [],
            "created_at": now,
            "updated_at": now,
            "last_login_at": None,
            "username": normalized,
            "password_hash": password_hash.strip(),
            "failed_login_count": 0,
            "last_failed_login_at": None,
            "session_revocation_version": 0,
        }
        _validate_user(user)
        store["users"].append(user)
        _write_store_unlocked(store)
        return copy.deepcopy(user)


def reset_local_password(user_id: str, password_hash: str) -> dict[str, Any]:
    if not isinstance(password_hash, str) or not password_hash.strip():
        raise ValueError("password_hash must be a non-empty string")
    with _locked_store():
        store = _read_store_unlocked()
        index = next((i for i, user in enumerate(store["users"]) if user["id"] == user_id), None)
        if index is None:
            raise KeyError(user_id)
        user = copy.deepcopy(store["users"][index])
        user["password_hash"] = password_hash.strip()
        user["failed_login_count"] = 0
        user["last_failed_login_at"] = None
        user["session_revocation_version"] += 1
        user["updated_at"] = _now()
        _validate_user(user)
        store["users"][index] = user
        _write_store_unlocked(store)
        return copy.deepcopy(user)


def _update_login_state(user_id: str, *, success: bool) -> dict[str, Any]:
    with _locked_store():
        store = _read_store_unlocked()
        index = next((i for i, user in enumerate(store["users"]) if user["id"] == user_id), None)
        if index is None:
            raise KeyError(user_id)
        user = copy.deepcopy(store["users"][index])
        now = _now()
        user["updated_at"] = now
        if success:
            user["failed_login_count"] = 0
            user["last_failed_login_at"] = None
            user["last_login_at"] = now
        else:
            user["failed_login_count"] += 1
            user["last_failed_login_at"] = now
        _validate_user(user)
        store["users"][index] = user
        _write_store_unlocked(store)
        return copy.deepcopy(user)


def is_login_throttled(user_id: str, *, limit: int = 10, window_seconds: int = 300) -> bool:
    user = get_user(user_id)
    if not user or user.get("failed_login_count", 0) < limit:
        return False
    stamp = user.get("last_failed_login_at")
    try:
        when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - when).total_seconds() < window_seconds
    except (TypeError, ValueError):
        return False


def record_login_failure(user_id: str) -> dict[str, Any]:
    return _update_login_state(user_id, success=False)


def record_login_success(user_id: str) -> dict[str, Any]:
    return _update_login_state(user_id, success=True)


def increment_session_revocation(user_id: str) -> dict[str, Any]:
    with _locked_store():
        store = _read_store_unlocked()
        index = next((i for i, user in enumerate(store["users"]) if user["id"] == user_id), None)
        if index is None:
            raise KeyError(user_id)
        user = copy.deepcopy(store["users"][index])
        user["session_revocation_version"] += 1
        user["updated_at"] = _now()
        _validate_user(user)
        store["users"][index] = user
        _write_store_unlocked(store)
        return copy.deepcopy(user)


def _canonical_expiry(value: Any, now: datetime) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("expires_at must be a UTC timestamp")
        parsed = value.astimezone(timezone.utc)
    else:
        parsed = _parse_timestamp(value, "expires_at")
    if parsed <= now:
        raise ValueError("invitation expiry must be in the future")
    if parsed - now > INVITATION_MAX_AGE:
        raise ValueError("invitation expiry may not exceed 30 days")
    return _timestamp(parsed)


def _validate_existing_profiles(profile_ids: list[str], *, subject: str = "invitation") -> None:
    try:
        all_exist = profiles_api.profiles_exist_uncached(profile_ids)
    except Exception as exc:
        raise ValueError(f"{subject} profiles could not be validated") from exc
    if not isinstance(all_exist, bool):
        raise ValueError(f"{subject} profiles could not be validated")
    if not all_exist:
        raise ValueError(f"One or more {subject} profiles are unavailable")


def _prune_expired_invitations(store: dict[str, Any], now: datetime) -> bool:
    active = [
        invitation
        for invitation in store["invitations"]
        if _parse_timestamp(invitation["expires_at"], "expires_at") > now
    ]
    changed = len(active) != len(store["invitations"])
    if changed:
        store["invitations"] = active
    return changed


def create_invitation(
    provider: str,
    target: str,
    profiles: list[str],
    created_by: str,
    expires_at: str | datetime,
) -> dict[str, Any]:
    """Create a member-only invitation after validating administrator authority."""
    provider, target = _canonical_invitation_target(provider, target)
    canonical_profiles = copy.deepcopy(_validate_profiles(profiles))
    _validate_existing_profiles(canonical_profiles)
    now_datetime = _now_datetime()
    created_at = _timestamp(now_datetime)
    canonical_expiry = _canonical_expiry(expires_at, now_datetime)

    with _locked_store():
        store = _read_store_unlocked()
        creator = next(
            (user for user in store["users"] if user["id"] == created_by), None
        )
        if (
            creator is None
            or creator.get("enabled") is not True
            or creator.get("role") != "admin"
        ):
            raise ValueError("invitation creator must be an existing enabled admin")
        pruned = _prune_expired_invitations(store, now_datetime)
        active_invitations = store["invitations"]
        if len(active_invitations) >= MAX_ACTIVE_INVITATIONS:
            if pruned:
                _write_store_unlocked(store)
            raise ValueError("maximum active invitation count reached")
        if any(
            invitation["provider"] == provider and invitation["target"] == target
            for invitation in active_invitations
        ):
            if pruned:
                _write_store_unlocked(store)
            raise ValueError("an unexpired invitation already exists for this provider and target")
        invitation = {
            "id": secrets.token_urlsafe(24),
            "provider": provider,
            "target": target,
            "profiles": canonical_profiles,
            "created_at": created_at,
            "expires_at": canonical_expiry,
            "created_by": created_by,
        }
        store["invitations"] = active_invitations + [invitation]
        _write_store_unlocked(store)
        return copy.deepcopy(invitation)


def list_invitations(*, include_expired: bool = False) -> list[dict[str, Any]]:
    """List invitations while durably collecting expired operational records.

    ``include_expired`` is retained for API compatibility, but expired records
    are not audit history and may already have been removed.
    """
    if not isinstance(include_expired, bool):
        raise ValueError("include_expired must be a boolean")
    now = _now_datetime()
    with _locked_store():
        store = _read_store_unlocked()
        if _prune_expired_invitations(store, now):
            _write_store_unlocked(store)
        return copy.deepcopy(store["invitations"])


def revoke_invitation(invitation_id: str) -> dict[str, Any] | bool:
    """Remove an invitation by opaque ID without revealing unrelated records."""
    if not isinstance(invitation_id, str) or not invitation_id:
        return False
    with _locked_store():
        store = _read_store_unlocked()
        pruned = _prune_expired_invitations(store, _now_datetime())
        index = next(
            (
                index
                for index, invitation in enumerate(store["invitations"])
                if invitation["id"] == invitation_id
            ),
            None,
        )
        if index is None:
            if pruned:
                _write_store_unlocked(store)
            return False
        invitation = store["invitations"].pop(index)
        _write_store_unlocked(store)
        return copy.deepcopy(invitation)


def consume_invitation_and_create_user(
    provider: str,
    target: str,
    issuer: str,
    subject: str,
    display_name: str,
    email: str,
) -> dict[str, Any] | None:
    """Atomically exchange one matching invitation for one enabled member user."""
    provider, target = _canonical_invitation_target(provider, target)
    display_name = _text(display_name, "display_name")
    email = _text(email, "email")
    if provider == "google":
        if issuer != GOOGLE_ISSUER:
            raise ValueError("Google invitation issuer is invalid")
        subject = _required_text(subject, "subject")
        _, canonical_email = _canonical_invitation_target("google", email)
        if canonical_email != target:
            raise ValueError("Google email must exactly match the invitation target")
        email = canonical_email
    else:
        if issuer != GITHUB_ISSUER:
            raise ValueError("GitHub invitation issuer is invalid")
        _, canonical_subject = _canonical_invitation_target("github", subject)
        if canonical_subject != target:
            raise ValueError("GitHub subject must exactly match the invitation target")
        subject = canonical_subject
    identity = _identity(provider, issuer, subject)
    now_datetime = _now_datetime()
    now = _timestamp(now_datetime)

    with _locked_store():
        store = _read_store_unlocked()
        pruned = _prune_expired_invitations(store, now_datetime)
        active_invitations = store["invitations"]
        invitation_index = next(
            (
                index
                for index, invitation in enumerate(active_invitations)
                if invitation["provider"] == provider
                and invitation["target"] == target
            ),
            None,
        )
        if invitation_index is None:
            if pruned:
                _write_store_unlocked(store)
            return None
        if _find_index_by_identity(store, _identity_key(identity)) is not None:
            if pruned:
                _write_store_unlocked(store)
            return None
        invitation = active_invitations[invitation_index]
        # Revalidate at the point of use. Failure leaves the matching invitation
        # and user list untouched even if a cached listing still names a deleted
        # profile.
        _validate_existing_profiles(invitation["profiles"])
        active_invitations.pop(invitation_index)
        user = {
            "id": str(uuid.uuid4()),
            "display_name": display_name,
            "email": email,
            "role": "member",
            "enabled": True,
            "profiles": copy.deepcopy(invitation["profiles"]),
            "identities": [identity],
            "created_at": now,
            "updated_at": now,
            "last_login_at": now,
            "username": None,
            "password_hash": None,
            "failed_login_count": 0,
            "last_failed_login_at": None,
            "session_revocation_version": 0,
        }
        store["users"].append(user)
        store["invitations"] = active_invitations
        _write_store_unlocked(store)
        return copy.deepcopy(user)


def bootstrap_local_admin_if_empty(
    *, username: str, display_name: str, password_hash: str, profiles: list[str]
) -> dict[str, Any] | None:
    normalized = _normalize_username(username)
    display_name = _text(display_name, "display_name")
    if not isinstance(password_hash, str) or not password_hash.strip():
        raise ValueError("password_hash must be a non-empty string")
    canonical_profiles = copy.deepcopy(_validate_profiles(profiles))
    if not canonical_profiles:
        raise ValueError("bootstrap administrator profiles must contain at least one profile")
    _validate_existing_profiles(canonical_profiles, subject="bootstrap administrator")
    with _locked_store():
        store = _read_store_unlocked()
        if store["users"]:
            return None
        now = _now()
        user = {
            "id": str(uuid.uuid4()), "display_name": display_name, "email": "",
            "role": "admin", "enabled": True, "profiles": canonical_profiles,
            "identities": [], "created_at": now, "updated_at": now,
            "last_login_at": None, "username": normalized,
            "password_hash": password_hash.strip(), "failed_login_count": 0,
            "last_failed_login_at": None, "session_revocation_version": 0,
        }
        _validate_user(user)
        store["users"].append(user)
        _write_store_unlocked(store)
        return copy.deepcopy(user)


def bootstrap_external_admin_if_empty(
    provider: str,
    issuer: str,
    subject: str,
    display_name: str,
    email: str,
    expected_target: str,
    *,
    profiles: list[str],
) -> dict[str, Any] | None:
    """Atomically create one configured external administrator in an empty store."""
    provider, target = _canonical_invitation_target(provider, expected_target)
    display_name = _text(display_name, "display_name")
    email = _text(email, "email")
    canonical_profiles = copy.deepcopy(_validate_profiles(profiles))
    if not canonical_profiles:
        raise ValueError(
            "bootstrap administrator profiles must contain at least one profile"
        )

    if provider == "google":
        if issuer != GOOGLE_ISSUER:
            raise ValueError("Google bootstrap issuer is invalid")
        subject = _required_text(subject, "subject")
        _, canonical_email = _canonical_invitation_target("google", email)
        if canonical_email != target:
            raise ValueError("Google email must exactly match the bootstrap target")
        email = canonical_email
    else:
        if issuer != GITHUB_ISSUER:
            raise ValueError("GitHub bootstrap issuer is invalid")
        _, canonical_subject = _canonical_invitation_target("github", subject)
        if canonical_subject != target:
            raise ValueError("GitHub subject must exactly match the bootstrap target")
        subject = canonical_subject
    identity = _identity(provider, issuer, subject)

    with _locked_store():
        store = _read_store_unlocked()
        if store["users"]:
            return None
        # Revalidate the explicit provider defaults against the authoritative
        # profile source at the point of use while holding the store lock.
        _validate_existing_profiles(canonical_profiles)
        now = _now()
        user = {
            "id": str(uuid.uuid4()),
            "display_name": display_name,
            "email": email,
            "role": "admin",
            "enabled": True,
            "profiles": canonical_profiles,
            "identities": [identity],
            "created_at": now,
            "updated_at": now,
            "last_login_at": now,
            "username": None,
            "password_hash": None,
            "failed_login_count": 0,
            "last_failed_login_at": None,
            "session_revocation_version": 0,
        }
        store["users"].append(user)
        _write_store_unlocked(store)
        return copy.deepcopy(user)


def upsert_external_user(
    provider: str,
    issuer: str,
    subject: str,
    display_name: str = "",
    email: str = "",
    *,
    allow_create: bool = False,
    auto_create: bool | None = None,
    profiles: list[str] | None = None,
) -> dict[str, Any] | None:
    """Record an external login, optionally creating a member explicitly.

    ``auto_create`` is accepted as a descriptive alias for callers; when supplied
    it must agree with ``allow_create`` if both request creation.
    """
    identity = _identity(provider, issuer, subject)
    display_name = _text(display_name, "display_name")
    email = _text(email, "email")
    create_profiles = copy.deepcopy(
        _validate_profiles(profiles if profiles is not None else [])
    )
    if not isinstance(allow_create, bool) or (auto_create is not None and not isinstance(auto_create, bool)):
        raise ValueError("allow_create must be a boolean")
    if auto_create is not None:
        if allow_create and not auto_create:
            raise ValueError("allow_create and auto_create disagree")
        allow_create = auto_create

    with _locked_store():
        store = _read_store_unlocked()
        index = _find_index_by_identity(store, _identity_key(identity))
        now = _now()
        if index is None:
            if not allow_create:
                return None
            user = {
                "id": str(uuid.uuid4()),
                "display_name": display_name,
                "email": email,
                "role": "member",
                "enabled": True,
                "profiles": create_profiles,
                "identities": [identity],
                "created_at": now,
                "updated_at": now,
                "last_login_at": now,
            "username": None,
            "password_hash": None,
            "failed_login_count": 0,
            "last_failed_login_at": None,
            "session_revocation_version": 0,
            }
            store["users"].append(user)
        else:
            user = store["users"][index]
            user["display_name"] = display_name
            user["email"] = email
            user["updated_at"] = now
            user["last_login_at"] = now
        _write_store_unlocked(store)
        return copy.deepcopy(user)


def update_user(
    user_id: str,
    updates: Mapping[str, Any] | None = None,
    **changes: Any,
) -> dict[str, Any]:
    """Update mutable user fields while preserving ID and creation metadata."""
    if updates is None:
        requested = dict(changes)
    else:
        if not isinstance(updates, Mapping):
            raise ValueError("updates must be a mapping")
        requested = dict(updates)
        overlap = requested.keys() & changes.keys()
        if overlap:
            raise ValueError(f"Duplicate update field: {sorted(overlap)[0]}")
        requested.update(changes)
    unknown = set(requested) - _UPDATE_FIELDS
    if unknown:
        raise ValueError(f"Unknown update field: {sorted(unknown)[0]}")

    with _locked_store():
        store = _read_store_unlocked()
        index = next(
            (i for i, candidate in enumerate(store["users"]) if candidate["id"] == user_id),
            None,
        )
        if index is None:
            raise KeyError(user_id)
        original = store["users"][index]
        updated = copy.deepcopy(original)
        for field, value in requested.items():
            if field in {"display_name", "email"}:
                updated[field] = _text(value, field)
            elif field == "role":
                updated[field] = _validate_role(value)
            elif field == "enabled":
                if not isinstance(value, bool):
                    raise ValueError("enabled must be a boolean")
                updated[field] = value
            elif field == "profiles":
                canonical_profiles = copy.deepcopy(_validate_profiles(value))
                # Validate against the uncached authoritative inventory while the
                # auth-store update is locked and immediately before persistence.
                _validate_existing_profiles(canonical_profiles, subject="user")
                updated[field] = canonical_profiles
            elif field == "identities":
                updated[field] = _canonical_identities(value)

        other_viable_admin = any(
            candidate["id"] != user_id
            and candidate["role"] == "admin"
            and candidate["enabled"]
            and candidate["identities"]
            for candidate in store["users"]
        )
        if not other_viable_admin:
            removes_last_admin = (
                original["role"] == "admin"
                and original["enabled"]
                and not (updated["role"] == "admin" and updated["enabled"])
            )
            leaves_last_admin_unusable = (
                updated["role"] == "admin"
                and updated["enabled"]
                and not updated["identities"]
            )
            if removes_last_admin or leaves_last_admin_unusable:
                raise ValueError("Cannot disable, demote, or remove every identity from the last enabled admin")

        # Validate duplicate external identities against every other user.
        other_keys = {
            _identity_key(identity)
            for candidate in store["users"]
            if candidate["id"] != user_id
            for identity in candidate["identities"]
        }
        if any(_identity_key(identity) in other_keys for identity in updated["identities"]):
            raise ValueError("Duplicate identity")

        updated["updated_at"] = _now()
        _validate_user(updated)
        store["users"][index] = updated
        _write_store_unlocked(store)
        return copy.deepcopy(updated)


def permissions_for_role(role: str) -> frozenset[str]:
    _validate_role(role)
    return _ROLE_PERMISSIONS[role]


def remove_profile_assignments(profile_id: str) -> dict[str, Any]:
    """Atomically remove a profile grant and return a narrow rollback token."""
    _validate_profiles([profile_id])
    with _locked_store():
        store = _read_store_unlocked()
        changed = False
        now = _now()
        affected_user_ids: list[str] = []
        affected_invitation_ids: list[str] = []
        for user in store["users"]:
            retained = [
                candidate
                for candidate in user["profiles"]
                if not _profiles_match(candidate, profile_id)
            ]
            if retained != user["profiles"]:
                affected_user_ids.append(user["id"])
                user["profiles"] = retained
                user["updated_at"] = now
                changed = True
        for invitation in store["invitations"]:
            retained = [
                candidate
                for candidate in invitation["profiles"]
                if not _profiles_match(candidate, profile_id)
            ]
            if retained != invitation["profiles"]:
                affected_invitation_ids.append(invitation["id"])
                invitation["profiles"] = retained
                changed = True
        if changed:
            _write_store_unlocked(store)
        return {
            "profile_id": profile_id,
            "user_ids": affected_user_ids,
            "invitation_ids": affected_invitation_ids,
        }


def restore_profile_assignments(token: Mapping[str, Any]) -> None:
    """Merge one removed grant into current records without replacing snapshots."""
    if not isinstance(token, Mapping) or set(token) != {
        "profile_id", "user_ids", "invitation_ids"
    }:
        raise ValueError("invalid profile assignment rollback token")
    profile_id = token.get("profile_id")
    user_ids = token.get("user_ids")
    invitation_ids = token.get("invitation_ids")
    _validate_profiles([profile_id])
    if (
        not isinstance(user_ids, list)
        or not isinstance(invitation_ids, list)
        or any(not isinstance(value, str) for value in user_ids + invitation_ids)
        or len(set(user_ids)) != len(user_ids)
        or len(set(invitation_ids)) != len(invitation_ids)
    ):
        raise ValueError("invalid profile assignment rollback token")

    user_id_set = set(user_ids)
    invitation_id_set = set(invitation_ids)
    with _locked_store():
        # Never resurrect grants after the profile has actually disappeared.
        # Validate while holding the auth-store lock so no auth mutation can be
        # interleaved between validation and this merge.  The uncached check
        # avoids restoring based on a stale profile-list cache.
        if not profiles_api.profiles_exist_uncached([profile_id]):
            raise ValueError(f"Profile {profile_id!r} is unavailable for grant restoration")
        store = _read_store_unlocked()
        changed = False
        now = _now()
        for user in store["users"]:
            if user["id"] in user_id_set and not any(
                _profiles_match(candidate, profile_id) for candidate in user["profiles"]
            ):
                user["profiles"].append(profile_id)
                user["updated_at"] = now
                changed = True
        for invitation in store["invitations"]:
            if invitation["id"] in invitation_id_set and not any(
                _profiles_match(candidate, profile_id) for candidate in invitation["profiles"]
            ):
                invitation["profiles"].append(profile_id)
                changed = True
        if changed:
            _write_store_unlocked(store)


def user_allows_profile(user: Mapping[str, Any], profile_id: str) -> bool:
    """Return whether an enabled user may use a valid profile.

    Administrators can use every valid profile. Members are limited to their
    assignments; root/default aliases compare through the canonical profile helper.
    Invalid user/profile data fails closed.
    """
    try:
        if not isinstance(user, Mapping) or user.get("enabled") is not True:
            return False
        role = _validate_role(user.get("role"))
        _validate_profiles([profile_id])
        assigned = user.get("profiles")
        _validate_profiles(assigned)
    except (TypeError, ValueError):
        return False
    if role == "admin":
        return True
    try:
        if not profiles_api.profiles_exist_uncached([profile_id]):
            return False
    except Exception:
        return False
    return any(_profiles_match(candidate, profile_id) for candidate in assigned)
