"""Scope normalization and matching helpers."""

from __future__ import annotations

import ipaddress
import unicodedata
from urllib.parse import urlsplit


def normalize_scope_host(value: str) -> str:
    """Return a comparable hostname/IP from a URL, host, or host:port string."""
    raw = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not raw:
        return ""

    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname or raw.split("/", 1)[0].rsplit("@", 1)[-1]
    except ValueError:
        return ""

    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    host = host.strip().rstrip(".").lower()
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""


def _normalize_scope_pattern(pattern: str) -> str:
    raw = str(pattern or "").strip()
    if not raw:
        return ""

    if raw.startswith("*."):
        suffix = normalize_scope_host(raw[2:])
        return f"*.{suffix}" if suffix else ""
    return normalize_scope_host(raw)


def _ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def host_matches_scope(target: str, pattern: str) -> bool:
    """Match host/IP target against exact domains, wildcards, IPs, and CIDR."""
    host = normalize_scope_host(target)
    pat = _normalize_scope_pattern(pattern)
    if not host or not pat:
        return False

    target_ip = _ip(host)
    network = _network(str(pattern).strip())
    if target_ip and network:
        return target_ip in network

    pattern_ip = _ip(pat)
    if target_ip or pattern_ip:
        return target_ip == pattern_ip

    if pat.startswith("*."):
        suffix = pat[2:]
        return host.endswith(f".{suffix}")

    return host == pat or host.endswith(f".{pat}")


def is_target_in_scope(target: str, in_scope: list[str],
                       out_of_scope: list[str]) -> tuple[bool, bool]:
    """Return (allowed, explicitly_denied); out-of-scope always wins."""
    if any(host_matches_scope(target, item) for item in out_of_scope):
        return False, True
    if any(host_matches_scope(target, item) for item in in_scope):
        return True, False
    return False, False
