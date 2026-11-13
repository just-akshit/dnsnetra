"""Central authentication configuration with production fail-closed validation.

The session secret is an HMAC pepper for session-token hashing, not a JWT key.
"""

from __future__ import annotations

import os

DEV_SESSION_PEPPER = "dnsnetra-dev-session-pepper-not-for-production"
DEV_CAPTCHA_SECRET = "dnsnetra-dev-captcha-secret-not-for-production"

INSECURE_SECRETS = frozenset(
    {
        "",
        "change-this-in-production-session-secret-key-min-32-chars",
        "change-this-in-production-captcha-secret-key-min-32-chars",
        "dnsnetra-secure-default-change-in-prod",
        "dnsnetra-dev-test-jwt-secret-do-not-use-in-production",
        "dnsnetra-dev-test-captcha-secret-key-do-not-use-in-production",
        DEV_SESSION_PEPPER,
        DEV_CAPTCHA_SECRET,
        "secret",
        "changeme",
        "default",
    }
)


def is_production() -> bool:
    env = (
        os.getenv("DNSNETRA_ENV")
        or os.getenv("APP_ENV")
        or os.getenv("ENVIRONMENT")
        or "development"
    )
    return env.strip().lower() in ("production", "prod")


def _env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None:
            return value.strip()
    return ""


def require_secret(
    name: str,
    *,
    dev_default: str,
    aliases: tuple[str, ...] = (),
    min_length: int = 32,
) -> str:
    value = _env(name, *aliases)
    if is_production():
        if value in INSECURE_SECRETS or len(value) < min_length:
            raise RuntimeError(
                f"CRITICAL SECURITY CONFIGURATION ERROR: {name} must be set to a "
                f"non-default secret of at least {min_length} characters in production."
            )
        return value
    return value or dev_default


def get_session_pepper() -> str:
    return require_secret(
        "AUTH_SESSION_SECRET",
        dev_default=DEV_SESSION_PEPPER,
        aliases=("AUTH_SECRET_KEY", "JWT_SECRET"),
    )


def get_captcha_secret() -> str:
    return require_secret(
        "AUTH_CAPTCHA_SECRET",
        dev_default=DEV_CAPTCHA_SECRET,
        aliases=("CAPTCHA_SECRET",),
    )


def _positive_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be greater than zero, got {value}")
    return value


def get_session_ttl_minutes() -> int:
    return _positive_int("AUTH_SESSION_EXPIRE_MINUTES", 1440)


def get_session_ttl_seconds() -> int:
    return get_session_ttl_minutes() * 60


def get_captcha_ttl_seconds() -> int:
    return _positive_int("AUTH_CAPTCHA_EXPIRE_SECONDS", 300)


def cookie_secure() -> bool:
    return is_production() or _env("AUTH_COOKIE_SECURE").lower() in ("1", "true", "yes")


def signup_enabled() -> bool:
    return _env("AUTH_ALLOW_SIGNUP").lower() in ("1", "true", "yes")


def validate_auth_config() -> None:
    """Fail at import/startup when production secrets are missing or unsafe."""
    get_session_pepper()
    get_captcha_secret()
    get_session_ttl_minutes()
    get_captcha_ttl_seconds()
