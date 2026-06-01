"""Akagami terminal theme primitives."""

from __future__ import annotations

BRAND = "AKAGAMI"
VERSION = "2.0.0"
TAGLINE = "Recon Command Deck"

ACCENT = "bright_red"
PASSIVE = "cyan"
ACTIVE = "yellow"
SUCCESS = "green"
AI = "magenta"
MUTED = "dim"
METADATA = "grey62"
SURFACE = "grey15"
BORDER = "cyan"
TABLE_BORDER = "bright_black"
WARN = ACTIVE
DANGER = "red"
INFO = PASSIVE
HEADER_STYLE = f"bold {PASSIVE}"
TITLE_STYLE = f"bold {PASSIVE}"
SUBTITLE_STYLE = METADATA
BRAND_STYLE = f"bold {ACCENT}"
TABLE_HEADER_STYLE = "bold white"


def badge(name: str) -> str:
    """Compatibility wrapper for callers that imported badges from theme."""
    from reconforge.ui.badges import badge as _badge

    return _badge(name)


def risk_badge(value: str) -> str:
    """Compatibility wrapper for callers that imported badges from theme."""
    from reconforge.ui.badges import risk_badge as _risk_badge

    return _risk_badge(value)


def yes_no(value: bool, yes: str = "yes", no: str = "no") -> str:
    """Compatibility wrapper for callers that imported badges from theme."""
    from reconforge.ui.badges import yes_no as _yes_no

    return _yes_no(value, yes=yes, no=no)


def passed_blocked(value: bool) -> str:
    """Compatibility wrapper for callers that imported badges from theme."""
    from reconforge.ui.badges import passed_blocked as _passed_blocked

    return _passed_blocked(value)
