"""
CSRF Defense and Request Origin Validation for DNSNetra API
===========================================================
Protects state-changing requests (POST, PUT, PATCH, DELETE) that authenticate
via browser cookies against Cross-Site Request Forgery (CSRF).
Validates request Origin/Referer headers against configured trusted origins.
Does not restrict Bearer token API requests, which cannot be initiated cross-origin
by standard browser form/navigation contexts.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse
from typing import Set

from fastapi import HTTPException, Request, status

DEFAULT_ALLOWED_ORIGINS = {
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
}


def get_allowed_origins() -> Set[str]:
    """Retrieve set of allowed web origins for CORS and CSRF validation."""
    raw = os.getenv("CORS_ALLOWED_ORIGINS") or os.getenv("ALLOWED_ORIGINS") or ""
    if raw.strip():
        configured = {o.strip() for o in raw.split(",") if o.strip()}
        configured.update(DEFAULT_ALLOWED_ORIGINS)
        return configured
    return set(DEFAULT_ALLOWED_ORIGINS)


def extract_origin_from_url(url_str: str) -> str:
    """Extract scheme://host[:port] from an arbitrary URL string."""
    try:
        parsed = urlparse(url_str)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}".lower()
    except Exception:
        return ""


def verify_csrf_protection(request: Request) -> None:
    """
    Enforce CSRF protection on state-changing requests authenticated via cookies.
    Raises HTTP 403 Forbidden if origin is missing or untrusted.
    """
    # Only enforce for state-changing methods
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return

    # Check if request was authenticated using cookie
    auth_method = getattr(request.state, "auth_method", None)
    if auth_method != "cookie":
        # Bearer token API clients do not require origin check
        return

    origin = request.headers.get("origin")
    referer = request.headers.get("referer")

    effective_origin = ""
    if origin:
        effective_origin = extract_origin_from_url(origin)
    elif referer:
        effective_origin = extract_origin_from_url(referer)

    allowed = get_allowed_origins()

    if not effective_origin or effective_origin not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"CSRF protection: untrusted or missing request origin ('{effective_origin or 'none'}')",
        )
