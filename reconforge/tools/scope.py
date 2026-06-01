"""Scope normalization and matching helpers."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit


CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SHELL_META_CHARS = set(";&|`$<>(){}\\\"'")


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


def validate_target(value: str, *, allow_local: bool = False) -> str:
    """Return a canonical CLI target or raise ValueError.

    This is intentionally stricter than scope matching because CLI targets are
    later displayed in shell commands and may be written into workspace scope.
    """
    raw = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not raw:
        raise ValueError("Invalid target: target is required")
    if CONTROL_RE.search(raw):
        raise ValueError("Invalid target: control characters are not allowed")
    if any(ch.isspace() for ch in raw):
        raise ValueError("Invalid target: whitespace is not allowed")
    if any(ch in raw for ch in SHELL_META_CHARS):
        raise ValueError("Invalid target: shell metacharacters are not allowed")
    if _has_path_traversal(raw):
        raise ValueError("Invalid target: path traversal is not allowed")

    has_scheme = "://" in raw
    if has_scheme:
        try:
            parsed = urlsplit(raw)
        except ValueError as exc:
            raise ValueError("Invalid target: malformed URL") from exc
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Invalid target: only http and https URLs are supported")
        if parsed.username or parsed.password:
            raise ValueError("Invalid target: userinfo is not allowed")
        host = _canonical_host(parsed.hostname or "")
        _validate_port(parsed)
        _validate_host_syntax(host)
        _reject_local_without_policy(host, allow_local)
        netloc = host
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((
            parsed.scheme.lower(),
            netloc,
            parsed.path or "",
            parsed.query or "",
            "",
        ))

    if "/" in raw:
        raise ValueError("Invalid target: paths require an http or https URL")
    try:
        parsed = urlsplit(f"//{raw}")
    except ValueError as exc:
        raise ValueError("Invalid target: malformed host") from exc
    if parsed.username or parsed.password:
        raise ValueError("Invalid target: userinfo is not allowed")
    host = _canonical_host(parsed.hostname or "")
    _validate_port(parsed)
    _validate_host_syntax(host)
    _reject_local_without_policy(host, allow_local)
    if parsed.port is not None:
        return f"{host}:{parsed.port}"
    return host


def target_is_local(value: str) -> bool:
    """Return True for localhost and loopback IP targets."""
    host = normalize_scope_host(value)
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    ip = _ip(host)
    return bool(ip and ip.is_loopback)


def _canonical_host(host: str) -> str:
    host = str(host or "").strip().rstrip(".").lower()
    if not host:
        raise ValueError("Invalid target: host is required")
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid target: host is not valid IDNA") from exc


def _validate_host_syntax(host: str) -> None:
    if host == "localhost" or host.endswith(".localhost"):
        return
    if _ip(host):
        return
    if len(host) > 253 or "." not in host:
        raise ValueError("Invalid target: host syntax is invalid")
    labels = host.split(".")
    if any(not label or not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Invalid target: host syntax is invalid")


def _validate_port(parsed) -> None:
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Invalid target: port is invalid") from exc


def _reject_local_without_policy(host: str, allow_local: bool) -> None:
    if target_is_local(host) and not allow_local:
        raise ValueError(
            "Invalid target: localhost/loopback targets require explicit local-lab policy"
        )


def _has_path_traversal(raw: str) -> bool:
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    except ValueError:
        return True
    path = parsed.path if "://" in raw else raw
    return any(part == ".." for part in path.replace("\\", "/").split("/"))


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
