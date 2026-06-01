"""Status badge helpers for Akagami command-deck output."""

from __future__ import annotations

from dataclasses import dataclass

from reconforge.ui.console import use_plain_mode


@dataclass(frozen=True)
class BadgeSpec:
    label: str
    style: str


BADGES: dict[str, BadgeSpec] = {
    "PASSIVE": BadgeSpec("PASSIVE", "bold black on cyan"),
    "INTEL": BadgeSpec("INTEL", "bold black on cyan"),
    "ACTIVE": BadgeSpec("ACTIVE", "bold black on yellow"),
    "RISK": BadgeSpec("RISK", "bold black on yellow"),
    "OPSEC": BadgeSpec("OPSEC", "bold white on magenta"),
    "AI": BadgeSpec("AI", "bold white on magenta"),
    "PLANNER": BadgeSpec("PLANNER", "bold white on magenta"),
    "APPROVED": BadgeSpec("APPROVED", "bold black on green"),
    "SUCCESS": BadgeSpec("SUCCESS", "bold black on green"),
    "READY": BadgeSpec("READY", "bold black on green"),
    "FOUND": BadgeSpec("FOUND", "bold black on green"),
    "COMPATIBLE": BadgeSpec("COMPATIBLE", "bold black on green"),
    "INCOMPATIBLE": BadgeSpec("INCOMPATIBLE", "bold black on yellow"),
    "BLOCKED": BadgeSpec("BLOCKED", "bold white on red"),
    "REQUIRED": BadgeSpec("REQUIRED", "bold black on yellow"),
    "MISSING": BadgeSpec("MISSING", "bold white on red"),
    "EXPERIMENTAL": BadgeSpec("EXPERIMENTAL", "bold white on magenta"),
    "HIGH": BadgeSpec("HIGH", "bold white on red"),
    "MEDIUM": BadgeSpec("MEDIUM", "bold black on yellow"),
    "LOW": BadgeSpec("LOW", "bold black on green"),
    "UNKNOWN": BadgeSpec("UNKNOWN", "bold white on grey23"),
}


def badge(name: str) -> str:
    """Return a styled badge, falling back to a readable plain token."""
    key = str(name or "UNKNOWN").upper().replace("-", "_").replace(" ", "_")
    spec = BADGES.get(key, BadgeSpec(key, "bold white on grey23"))
    if use_plain_mode():
        return f"[{spec.label}]"
    return f"[{spec.style}] {spec.label} [/{spec.style}]"


def risk_badge(value: str) -> str:
    """Normalize a risk label into a status badge."""
    normalized = (value or "unknown").strip().upper()
    if normalized == "PASSIVE":
        return badge("PASSIVE")
    if normalized in {"LOW", "MEDIUM", "HIGH"}:
        return badge(normalized)
    if normalized == "ACTIVE":
        return badge("ACTIVE")
    return badge("UNKNOWN") if normalized == "UNKNOWN" else _muted(normalized)


def approval_badge(state: str) -> str:
    """Return a badge for escalation checkpoint state."""
    normalized = (state or "required").strip().upper()
    if normalized in {"APPROVED", "BLOCKED", "REQUIRED"}:
        return badge(normalized)
    return badge("UNKNOWN")


def yes_no(value: bool, yes: str = "yes", no: str = "no") -> str:
    if use_plain_mode():
        return yes if value else no
    return f"[bold green]{yes}[/bold green]" if value else f"[bold red]{no}[/bold red]"


def passed_blocked(value: bool) -> str:
    return badge("APPROVED") if value else badge("BLOCKED")


def _muted(label: str) -> str:
    return f"[{label}]" if use_plain_mode() else f"[dim]{label}[/dim]"
