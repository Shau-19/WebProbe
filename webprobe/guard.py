"""Scope guard: WebProbe only talks to the local machine.

The check is purely syntactic (no DNS lookups), so a hostname that merely
*resolves* to a loopback address is not accepted. Only the literal name
``localhost`` or a loopback IP literal passes.
"""

import ipaddress
from urllib.parse import urlsplit


class TargetNotLocal(ValueError):
    """Raised when a URL points anywhere other than the local machine."""


def ensure_local(url: str) -> None:
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError as exc:
        raise TargetNotLocal(f"malformed URL: {url!r}") from exc

    if parts.scheme not in ("http", "https"):
        raise TargetNotLocal(f"only http/https targets are allowed, got {parts.scheme!r}")
    # "http://127.0.0.1@evil.com/" has hostname evil.com; refuse any userinfo outright.
    if parts.username is not None or parts.password is not None:
        raise TargetNotLocal("URLs with embedded credentials are not allowed")
    if not host:
        raise TargetNotLocal("URL has no host")
    if host.lower() == "localhost":
        return
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise TargetNotLocal(
            f"{host!r} is not localhost or a loopback IP; WebProbe only scans local targets"
        ) from None
    if not ip.is_loopback:
        raise TargetNotLocal(f"{host} is not a loopback address; WebProbe only scans local targets")
