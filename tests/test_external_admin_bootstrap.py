from concurrent.futures import ThreadPoolExecutor

import pytest


@pytest.fixture
def users(tmp_path, monkeypatch):
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(
        auth_users.profiles_api, "profiles_exist_uncached", lambda _ids: True
    )
    return auth_users


def test_bootstrap_external_admin_exact_empty_store_and_profiles(users):
    admin = users.bootstrap_external_admin_if_empty(
        "google", users.GOOGLE_ISSUER, "subject", "Ada", "Ada@Example.com",
        "ada@example.com", profiles=["default"],
    )
    assert admin["role"] == "admin"
    assert admin["enabled"] is True
    assert admin["email"] == "ada@example.com"
    assert admin["profiles"] == ["default"]
    assert admin["identities"] == [{
        "provider": "google", "issuer": users.GOOGLE_ISSUER, "subject": "subject"
    }]
    assert users.bootstrap_external_admin_if_empty(
        "github", users.GITHUB_ISSUER, "123", "Grace", "", "123",
        profiles=["default"],
    ) is None


@pytest.mark.parametrize(
    "provider,issuer,subject,email,target",
    [
        ("oidc", "https://issuer.example", "subject", "a@example.com", "a@example.com"),
        ("google", "https://evil.example", "subject", "a@example.com", "a@example.com"),
        ("google", "https://accounts.google.com", "", "a@example.com", "a@example.com"),
        ("google", "https://accounts.google.com", "subject", "other@example.com", "a@example.com"),
        ("github", "https://github.com", "0123", "", "123"),
        ("github", "https://github.com", "123", "", "0123"),
    ],
)
def test_bootstrap_external_admin_rejects_invalid_identity(
    users, provider, issuer, subject, email, target
):
    with pytest.raises(ValueError):
        users.bootstrap_external_admin_if_empty(
            provider, issuer, subject, "Name", email, target, profiles=["default"]
        )
    assert users.list_users() == []


def test_bootstrap_external_admin_validates_authoritative_profiles(users, monkeypatch):
    monkeypatch.setattr(
        users.profiles_api, "profiles_exist_uncached", lambda ids: ids != ["missing"]
    )
    with pytest.raises(ValueError, match="profile"):
        users.bootstrap_external_admin_if_empty(
            "github", users.GITHUB_ISSUER, "123", "Ada", "", "123",
            profiles=["missing"],
        )
    assert users.list_users() == []


@pytest.mark.parametrize(
    "profiles",
    [
        pytest.param(None, id="absent"),
        pytest.param([], id="empty"),
        pytest.param(["bad/profile"], id="all-syntactically-invalid"),
        pytest.param(["missing"], id="all-unavailable"),
    ],
)
def test_bootstrap_external_admin_requires_explicit_valid_profiles(
    users, monkeypatch, profiles
):
    monkeypatch.setattr(
        users.profiles_api,
        "profiles_exist_uncached",
        lambda ids: all(profile_id != "missing" for profile_id in ids),
    )

    with pytest.raises(ValueError, match="profile"):
        users.bootstrap_external_admin_if_empty(
            "github",
            users.GITHUB_ISSUER,
            "123",
            "Ada",
            "",
            "123",
            profiles=profiles,
        )

    assert users.list_users() == []


@pytest.mark.parametrize(
    "profiles",
    [
        pytest.param(["default"], id="one"),
        pytest.param(["default", "team-one"], id="multiple"),
    ],
)
def test_bootstrap_external_admin_accepts_one_or_multiple_current_profiles(
    users, profiles
):
    admin = users.bootstrap_external_admin_if_empty(
        "github",
        users.GITHUB_ISSUER,
        "123",
        "Ada",
        "",
        "123",
        profiles=profiles,
    )

    assert admin["profiles"] == profiles
    assert users.list_users() == [admin]


def test_bootstrap_external_admin_is_atomic_across_competing_identities(users):
    def bootstrap(index):
        subject = str(index + 100)
        return users.bootstrap_external_admin_if_empty(
            "github", users.GITHUB_ISSUER, subject, f"User {index}", "", subject,
            profiles=["default"],
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(bootstrap, range(8)))
    assert sum(result is not None for result in results) == 1
    assert len(users.list_users()) == 1


def test_bootstrap_external_admin_exact_callers_create_once(users):
    def bootstrap(_index):
        return users.bootstrap_external_admin_if_empty(
            "github", users.GITHUB_ISSUER, "123", "Admin", "", "123",
            profiles=["default"],
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(bootstrap, range(8)))
    assert sum(result is not None for result in results) == 1
    assert len(users.list_users()) == 1


def test_any_existing_member_makes_bootstrap_inert(users):
    users.upsert_external_user(
        "oidc", "https://issuer.example", "member", allow_create=True
    )
    assert users.bootstrap_external_admin_if_empty(
        "github", users.GITHUB_ISSUER, "123", "Admin", "", "123",
        profiles=["default"],
    ) is None
    [member] = users.list_users()
    assert member["role"] == "member"


def test_google_exact_verified_bootstrap_and_config(monkeypatch, tmp_path):
    from api import auth_oidc as oidc
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(auth_users.profiles_api, "profiles_exist_uncached", lambda _ids: True)
    monkeypatch.setattr(oidc, "get_config", lambda: {
        "webui_google": {"bootstrap_admin_email": "file@example.com"}
    })
    monkeypatch.setenv(
        "HERMES_WEBUI_GOOGLE_BOOTSTRAP_ADMIN_EMAIL", " Admin@Example.COM "
    )
    assert oidc._resolve_google_config()["bootstrap_admin_email"] == "admin@example.com"
    monkeypatch.delenv("HERMES_WEBUI_GOOGLE_BOOTSTRAP_ADMIN_EMAIL")

    cfg = {
        "bootstrap_admin_email": "admin@example.com",
        "default_profiles": ["default"],
        "auto_provision": False,
        "allow_emails": [],
        "allow_domains": [],
    }
    admin = oidc._admit_google_identity(
        {"sub": "admin", "email": "ADMIN@example.com", "email_verified": True}, cfg
    )
    assert admin["role"] == "admin"


@pytest.mark.parametrize("email,verified", [
    ("other@example.com", True), ("admin@example.com", False), ("", True)
])
def test_google_bootstrap_mismatch_or_unverified_denies(monkeypatch, tmp_path, email, verified):
    from api import auth_oidc as oidc
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    cfg = {
        "bootstrap_admin_email": "admin@example.com", "default_profiles": ["default"],
        "auto_provision": False, "allow_emails": [], "allow_domains": [],
    }
    with pytest.raises(oidc.OIDCAuthError):
        oidc._admit_google_identity(
            {"sub": "candidate", "email": email, "email_verified": verified}, cfg
        )
    assert auth_users.list_users() == []


@pytest.mark.parametrize(
    "profiles",
    [
        pytest.param(None, id="absent"),
        pytest.param([], id="empty"),
        pytest.param(["bad/profile"], id="all-syntactically-invalid"),
        pytest.param(["missing"], id="all-unavailable"),
    ],
)
def test_google_bootstrap_fails_closed_without_valid_current_profiles(
    monkeypatch, tmp_path, profiles
):
    from api import auth_oidc as oidc
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(
        auth_users.profiles_api,
        "profiles_exist_uncached",
        lambda ids: all(profile_id != "missing" for profile_id in ids),
    )
    raw = {"bootstrap_admin_email": "admin@example.com"}
    if profiles is not None:
        raw["default_profiles"] = profiles
    monkeypatch.delenv("HERMES_WEBUI_GOOGLE_BOOTSTRAP_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("HERMES_WEBUI_GOOGLE_DEFAULT_PROFILES", raising=False)
    monkeypatch.setattr(oidc, "get_config", lambda: {"webui_google": raw})
    cfg = oidc._resolve_google_config()

    with pytest.raises(oidc.OIDCAuthError, match="profile"):
        oidc._admit_google_identity(
            {"sub": "admin", "email": "admin@example.com", "email_verified": True},
            cfg,
        )

    assert auth_users.list_users() == []


@pytest.mark.parametrize(
    "profiles",
    [
        pytest.param(["default"], id="one"),
        pytest.param(["default", "team-one"], id="multiple"),
    ],
)
def test_google_bootstrap_accepts_one_or_multiple_current_profiles(
    monkeypatch, tmp_path, profiles
):
    from api import auth_oidc as oidc
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(
        auth_users.profiles_api, "profiles_exist_uncached", lambda _ids: True
    )
    admin = oidc._admit_google_identity(
        {"sub": "admin", "email": "admin@example.com", "email_verified": True},
        {
            "bootstrap_admin_email": "admin@example.com",
            "default_profiles": profiles,
            "auto_provision": False,
            "allow_emails": [],
            "allow_domains": [],
        },
    )

    assert admin["profiles"] == profiles


def test_github_exact_bootstrap_config_and_existing_user_inert(monkeypatch, tmp_path):
    from api import auth_github as github
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(auth_users.profiles_api, "profiles_exist_uncached", lambda _ids: True)
    monkeypatch.setattr(github, "get_config", lambda: {
        "webui_github": {"bootstrap_admin_user_id": "999"}
    })
    monkeypatch.setenv("HERMES_WEBUI_GITHUB_BOOTSTRAP_ADMIN_USER_ID", " 123 ")
    assert github._resolve_github_config()["bootstrap_admin_user_id"] == "123"
    monkeypatch.setenv("HERMES_WEBUI_GITHUB_BOOTSTRAP_ADMIN_USER_ID", "0123")
    assert github._resolve_github_config()["bootstrap_admin_user_id"] == ""

    cfg = {
        "bootstrap_admin_user_id": "123", "default_profiles": ["default"],
        "auto_provision": False, "allow_user_ids": [],
    }
    admin = github._admit_github_identity({"id": 123, "login": "admin"}, cfg)
    assert admin["role"] == "admin"
    with pytest.raises(github.GitHubAuthError, match="not admitted"):
        github._admit_github_identity({"id": 124, "login": "other"}, cfg)


@pytest.mark.parametrize(
    "profiles",
    [
        pytest.param(None, id="absent"),
        pytest.param([], id="empty"),
        pytest.param(["bad/profile"], id="all-syntactically-invalid"),
        pytest.param(["missing"], id="all-unavailable"),
    ],
)
def test_github_bootstrap_fails_closed_without_valid_current_profiles(
    monkeypatch, tmp_path, profiles
):
    from api import auth_github as github
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(
        auth_users.profiles_api,
        "profiles_exist_uncached",
        lambda ids: all(profile_id != "missing" for profile_id in ids),
    )
    raw = {"bootstrap_admin_user_id": "123"}
    if profiles is not None:
        raw["default_profiles"] = profiles
    monkeypatch.delenv("HERMES_WEBUI_GITHUB_BOOTSTRAP_ADMIN_USER_ID", raising=False)
    monkeypatch.delenv("HERMES_WEBUI_GITHUB_DEFAULT_PROFILES", raising=False)
    monkeypatch.setattr(github, "get_config", lambda: {"webui_github": raw})
    cfg = github._resolve_github_config()

    with pytest.raises(github.GitHubAuthError, match="profile"):
        github._admit_github_identity({"id": 123, "login": "admin"}, cfg)

    assert auth_users.list_users() == []


@pytest.mark.parametrize(
    "profiles",
    [
        pytest.param(["default"], id="one"),
        pytest.param(["default", "team-one"], id="multiple"),
    ],
)
def test_github_bootstrap_accepts_one_or_multiple_current_profiles(
    monkeypatch, tmp_path, profiles
):
    from api import auth_github as github
    from api import auth_users

    monkeypatch.setattr(auth_users.config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(
        auth_users.profiles_api, "profiles_exist_uncached", lambda _ids: True
    )
    admin = github._admit_github_identity(
        {"id": 123, "login": "admin"},
        {
            "bootstrap_admin_user_id": "123",
            "default_profiles": profiles,
            "auto_provision": False,
            "allow_user_ids": [],
        },
    )

    assert admin["profiles"] == profiles
