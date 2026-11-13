import pytest

from dnsnetra.core.config import auth as auth_config
from dnsnetra.core.security.csrf import get_allowed_origins
from dnsnetra.core.security.sessions import hash_session_token


def _prod(monkeypatch):
    monkeypatch.setattr(auth_config, "is_production", lambda: True)


def test_dev_mode_falls_back_to_dev_pepper(monkeypatch):
    monkeypatch.setattr(auth_config, "is_production", lambda: False)
    monkeypatch.delenv("AUTH_SESSION_SECRET", raising=False)
    assert auth_config.get_session_pepper() == auth_config.DEV_SESSION_PEPPER


def test_production_requires_session_secret(monkeypatch):
    _prod(monkeypatch)
    monkeypatch.delenv("AUTH_SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        auth_config.get_session_pepper()


def test_production_rejects_example_placeholder(monkeypatch):
    _prod(monkeypatch)
    monkeypatch.setenv(
        "AUTH_SESSION_SECRET",
        "change-this-in-production-session-secret-key-min-32-chars",
    )
    with pytest.raises(RuntimeError):
        auth_config.get_session_pepper()


def test_production_accepts_a_strong_secret(monkeypatch):
    _prod(monkeypatch)
    monkeypatch.setenv("AUTH_SESSION_SECRET", "a" * 64)
    assert auth_config.get_session_pepper() == "a" * 64


def test_production_requires_captcha_secret(monkeypatch):
    _prod(monkeypatch)
    monkeypatch.delenv("AUTH_CAPTCHA_SECRET", raising=False)
    monkeypatch.delenv("CAPTCHA_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        auth_config.validate_auth_config()


def test_session_ttl_comes_from_environment(monkeypatch):
    monkeypatch.setenv("AUTH_SESSION_EXPIRE_MINUTES", "5")
    assert auth_config.get_session_ttl_minutes() == 5


def test_invalid_ttl_is_rejected(monkeypatch):
    monkeypatch.setenv("AUTH_SESSION_EXPIRE_MINUTES", "soon")
    with pytest.raises(RuntimeError):
        auth_config.get_session_ttl_minutes()


def test_session_hash_changes_with_the_pepper(monkeypatch):
    monkeypatch.setenv("AUTH_SESSION_SECRET", "a" * 64)
    first = hash_session_token("same-token")
    monkeypatch.setenv("AUTH_SESSION_SECRET", "b" * 64)
    second = hash_session_token("same-token")
    assert first != second
    assert len(first) == 64


def test_configured_origins_are_not_merged_with_localhost(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://dnsnetra.corp.local")
    assert get_allowed_origins() == {"https://dnsnetra.corp.local"}


def test_signup_is_off_by_default(monkeypatch):
    monkeypatch.delenv("AUTH_ALLOW_SIGNUP", raising=False)
    assert auth_config.signup_enabled() is False
