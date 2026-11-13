"""Create a real server-side session for local verification scripts.

Scripts run on the server and cannot solve an image CAPTCHA, so they use the
same trusted database access the application already has.
"""

from __future__ import annotations

from dnsnetra.core.security.auth import get_user_by_username
from dnsnetra.core.security.sessions import create_session


def bearer_for_username(username: str = "admin") -> str:
    user = get_user_by_username(username)
    if not user:
        raise SystemExit(f"user '{username}' does not exist")
    raw_token, _ = create_session(user_id=user["id"], user_agent="verification-script")
    return raw_token
