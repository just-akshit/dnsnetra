"""
Trusted Proxy and Client IP Resolution for DNSNetra API
=======================================================
Safeguards against client IP spoofing via fabricated X-Forwarded-For
or X-Real-IP headers. Only honors proxy headers when the direct TCP peer
is explicitly present in TRUSTED_PROXIES.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Set
from fastapi import Request

DEFAULT_TRUSTED_PROXIES = {
    "127.0.0.1",
    "::1",
    "localhost",
}


def get_trusted_proxies() -> Set[str]:
    """Retrieve set of configured trusted reverse proxy IP addresses."""
    env_proxies = os.getenv("TRUSTED_PROXIES", "")
    if env_proxies.strip():
        proxies = {p.strip() for p in env_proxies.split(",") if p.strip()}
        proxies.update(DEFAULT_TRUSTED_PROXIES)
        return proxies
    return set(DEFAULT_TRUSTED_PROXIES)


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """
    Resolve client IP address securely:
    - If direct peer is in TRUSTED_PROXIES, parse X-Forwarded-For or X-Real-IP.
    - If direct peer is UNTRUSTED, use direct peer IP and ignore forwarded headers.
    """
    peer_ip = "127.0.0.1"
    if request.client and request.client.host:
        peer_ip = request.client.host.strip()

    trusted = get_trusted_proxies()

    # If the direct peer is not a trusted proxy, ignore all forwarded headers
    if peer_ip not in trusted:
        return peer_ip

    # Peer is a trusted reverse proxy; safely inspect forwarded headers
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # X-Forwarded-For is a comma-separated list of client, proxy1, proxy2...
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        for hop in hops:
            if is_valid_ip(hop):
                return hop

    real_ip = request.headers.get("x-real-ip")
    if real_ip and is_valid_ip(real_ip):
        return real_ip.strip()

    return peer_ip
