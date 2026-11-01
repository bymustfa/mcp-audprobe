"""Target safety guard: by default only loopback hosts may be probed."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class UnsafeTargetError(ValueError):
    pass


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_target(url: str, allow_remote: bool = False) -> None:
    """Raise ``UnsafeTargetError`` unless ``url`` is http(s) on loopback (or ``allow_remote``)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError(f"unsupported URL scheme in {url!r}")
    if is_loopback_host(parsed.hostname):
        return
    if not allow_remote:
        raise UnsafeTargetError(
            f"refusing to probe non-loopback host {parsed.hostname!r}. mcp-audprobe must only be used "
            "against servers you own or are explicitly authorized to test. If that applies, re-run "
            "with --allow-remote."
        )
