"""SSRF guard: refuses to let Sentivra's own outbound HTTP client (used by
URLDetector reputation lookups, media retrieval, etc.) connect to internal
or link-local addresses, and never follows a redirect blindly.

This resolves DNS itself and checks the resolved IP(s) — checking only the
hostname string is not sufficient (DNS rebinding, "localtest.me"-style
hostnames that resolve to 127.0.0.1, etc.).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class SSRFBlocked(ValueError):
    pass


_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, incl. cloud metadata endpoints
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
]


def _is_blocked_ip(ip_str: str) -> bool:
    addr = ipaddress.ip_address(ip_str)
    return any(addr in net for net in _BLOCKED_NETWORKS) or addr.is_multicast or addr.is_reserved


def assert_safe_url(url: str) -> None:
    """Raises SSRFBlocked if the URL's scheme or resolved address is
    internal/private. Call this before every outbound fetch Sentivra makes
    on behalf of analyzing untrusted content."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlocked(f"Blocked scheme: {parsed.scheme!r}")
    if not parsed.hostname:
        raise SSRFBlocked("URL has no hostname")

    try:
        resolved = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"DNS resolution failed for {parsed.hostname!r}: {exc}") from exc

    for family, _, _, _, sockaddr in resolved:
        ip_str = sockaddr[0]
        if _is_blocked_ip(ip_str):
            raise SSRFBlocked(f"{parsed.hostname!r} resolves to blocked address {ip_str}")
