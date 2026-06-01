"""Console and plain-output helpers for Akagami CLI presentation."""

from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from typing import Any, Iterator

import click
from rich.console import Console


_plain_mode = False
_verbose_mode = False
_console: Console | None = None


def no_color_requested() -> bool:
    """Return True when the environment asks for colorless output."""
    return bool(os.environ.get("NO_COLOR"))


def set_plain_mode(enabled: bool) -> None:
    """Enable or disable line-oriented plain output for the process."""
    global _plain_mode, _console
    _plain_mode = bool(enabled)
    _console = None


def set_verbose_mode(enabled: bool) -> None:
    """Enable or disable detailed operator output."""
    global _verbose_mode
    _verbose_mode = bool(enabled)


def use_plain_mode() -> bool:
    """Return True when Rich presentation should be bypassed."""
    return _plain_mode


def use_verbose_mode() -> bool:
    """Return True when detailed presentation should be rendered."""
    return _verbose_mode


def get_console() -> Console:
    """Return the shared Rich console configured for current mode/env."""
    global _console
    if _console is None:
        _console = Console(
            no_color=_plain_mode or no_color_requested(),
            highlight=False,
            width=terminal_width(120),
        )
    return _console


def emit_json(data: Any) -> None:
    """Emit script-friendly JSON without banners, panels, or Rich markup."""
    click.echo(json.dumps(data, indent=2, default=str))


def print_line(text: str = "") -> None:
    """Print one plain line through Click so tests and shells capture it."""
    click.echo(text)


@contextmanager
def mission_status(message: str) -> Iterator[None]:
    """Show a transient status spinner for interactive Rich sessions."""
    console = get_console()
    if use_plain_mode() or not console.is_terminal:
        yield
        return

    with console.status(message, spinner="dots12"):
        yield


def terminal_width(default: int = 100) -> int:
    """Best-effort terminal width for readable tables."""
    try:
        return max(80, min(140, os.get_terminal_size(sys.stdout.fileno()).columns))
    except OSError:
        return default
