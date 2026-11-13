"""Environment-file loading shared by backend configuration modules."""

from __future__ import annotations

from dotenv import load_dotenv

from .paths import REPO_ROOT


def load_environment(*, override: bool = False) -> None:
    """Load the repository's canonical environment files.

    ``.env`` holds PostgreSQL and application settings. ``api.env`` holds
    online threat-intelligence credentials. Both live at the repository root
    so existing variable names and deployment files keep working.
    """
    load_dotenv(REPO_ROOT / ".env", override=override)
    load_dotenv(REPO_ROOT / "api.env", override=override)


__all__ = ["load_environment"]
