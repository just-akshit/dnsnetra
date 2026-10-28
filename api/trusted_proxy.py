"""
Trusted Proxy and Client IP Resolution for DNSNetra API
=======================================================
Safeguards against client IP spoofing via fabricated X-Forwarded-For
or X-Real-IP headers. Only honors proxy headers when the direct TCP peer
is explicitly present in TRUSTED_PROXIES.

No proxy is trusted by default: loopback is a proxy only when the operator
says so, which is the production nginx deployment.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Set
from fastapi import Request

DEFAULT_TRUSTED_PROXIES: Set[str] = set()


def get_trusted_proxies() -> Set[str]:
    """Retrieve the explicitly configured trusted reverse proxy addresses."""
    raw = os.getenv("TRUSTED_PROXIES", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


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
    - If direct peer is in TRUSTED_PROXIES, walk X-Forwarded-For right-to-left
      and return the first hop that is not itself a trusted proxy.
    - If direct peer is UNTRUSTED, use direct peer IP and ignore forwarded headers.
    """
    peer_ip = "127.0.0.1"
    if request.client and request.client.host:
        peer_ip = request.client.host.strip()

    trusted = get_trusted_proxies()

    # If the direct peer is not a trusted proxy, ignore all forwarded headers
    if peer_ip not in trusted:
        return peer_ip

    # Peer is a trusted reverse proxy; walk from the closest hop backwards.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        for hop in reversed(hops):
            if not is_valid_ip(hop):
                continue
            if hop in trusted:
                continue
            return hop

    real_ip = request.headers.get("x-real-ip")
    if real_ip and is_valid_ip(real_ip) and real_ip.strip() not in trusted:
        return real_ip.strip()

    return peer_ip
