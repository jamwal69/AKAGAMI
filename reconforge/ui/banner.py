"""Akagami banner and command-deck help presentation."""

from __future__ import annotations

from rich import box
from rich.panel import Panel
from rich.table import Table

from reconforge.ui.console import get_console, print_line, use_plain_mode
from reconforge.ui.theme import BORDER, BRAND, BRAND_STYLE, TAGLINE, VERSION


AKAGAMI_BANNER = r"""
        ___    __ __    ___    ____    ___    __  ___ ____
       /   |  / //_/  /   |  / ___/  /   |  /  |/  //  _/
      / /| | / ,<    / /| | / / _   / /| | / /|_/ / / /
     / ___ |/ /| |  / ___ |/ /_/ / / ___ |/ /  / /_/ /
    /_/  |_/_/ |_| /_/  |_|\____/ /_/  |_/_/  /_//___/
"""

AKAGAMI_TAGLINE = f"{TAGLINE} v{VERSION}"
AKAGAMI_LINE = "-" * 60
AKAGAMI_JA = "赤髪"
AKAGAMI_TERMINAL_MARK = "◎/刀"
AKAGAMI_HEADLINE = "Red Moon Operator Command Deck"
AKAGAMI_MODES = (
    "scoped recon",
    "passive-first",
    "opsec-aware",
    "approval-gated escalation",
)
RESPONSIBLE_USE_NOTICE = (
    "Authorized security testing only. Scope first. Exploitation requires approval."
)


def print_banner() -> None:
    """Print the full Akagami banner."""
    if use_plain_mode():
        print_line(f"{AKAGAMI_TERMINAL_MARK} {BRAND} / {AKAGAMI_JA} v{VERSION}")
        print_line(AKAGAMI_HEADLINE)
        print_line(" | ".join(AKAGAMI_MODES))
        print_line(RESPONSIBLE_USE_NOTICE)
        print_line(AKAGAMI_LINE)
        print_line()
        return

    console = get_console()
    console.print(AKAGAMI_BANNER, style="bold bright_red", highlight=False)

    body = Table.grid(padding=(0, 1))
    body.add_column(style="white")
    body.add_row(
        f"[bold bright_red]{AKAGAMI_TERMINAL_MARK}[/bold bright_red] "
        f"[bold bright_red]{BRAND}[/bold bright_red] "
        f"[red]{AKAGAMI_JA}[/red] "
        f"[dim]v{VERSION}[/dim]"
    )
    body.add_row(f"[bold white]{AKAGAMI_HEADLINE}[/bold white]")
    body.add_row(
        "[cyan]scoped recon[/cyan] [dim]//[/dim] "
        "[white]passive-first[/white] [dim]//[/dim] "
        "[magenta]opsec-aware[/magenta] [dim]//[/dim] "
        "[yellow]operator approval required[/yellow]"
    )
    body.add_row(f"[dim]{RESPONSIBLE_USE_NOTICE}[/dim]")
    console.print(
        Panel(
            body,
            border_style="bright_red",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )
    console.print()


def print_mini_banner() -> None:
    """Print a compact command banner."""
    if use_plain_mode():
        print_line(f"{AKAGAMI_TERMINAL_MARK} {BRAND} v{VERSION} > {TAGLINE}")
        print_line()
        return

    get_console().print(
        f"  [bold bright_red]{AKAGAMI_TERMINAL_MARK}[/bold bright_red] "
        f"[{BRAND_STYLE}]{BRAND} v{VERSION}[/{BRAND_STYLE}] "
        f"[dim]▸[/dim] [bold cyan]{TAGLINE}[/bold cyan]\n"
    )


def print_command_deck() -> None:
    """Show the default top-level command deck when no command is provided."""
    if use_plain_mode():
        print_banner()
        print_line("Usage: akagami [--plain] <command> [options]")
        print_line()
        print_line("Commands:")
        for name, desc in _COMMANDS:
            print_line(f"  {name:<16} {desc}")
        print_line()
        print_line("Next Moves:")
        for command in _FIRST_MOVES:
            print_line(f"  {command}")
        print_line()
        print_line("Run 'akagami <command> --help' for command options.")
        return

    print_banner()
    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style=BORDER,
        show_header=True,
        header_style="bold white",
        pad_edge=False,
    )
    table.add_column("Command", style="bold cyan", no_wrap=True)
    table.add_column("Purpose", style="white")
    for name, desc in _COMMANDS:
        table.add_row(name, desc)

    panel = Panel(
        table,
        title="[bold cyan]Command Deck[/bold cyan]",
        subtitle="[dim]akagami <command> --help for mission options[/dim]",
        border_style=BORDER,
        box=box.ROUNDED,
    )
    get_console().print(panel)
    get_console().print(
        "\n  [dim]First run:[/dim] [bold cyan]akagami quickstart[/bold cyan]"
        "\n  [dim]Plain/scriptable mode:[/dim] [bold]akagami --plain <command>[/bold]"
    )


def format_help_banner(*, plain: bool = False) -> str:
    """Return the top-level help banner as Click-compatible plain text."""
    if plain:
        lines = [
            f"{AKAGAMI_TERMINAL_MARK} {BRAND} / {AKAGAMI_JA} v{VERSION}",
            AKAGAMI_HEADLINE,
            " | ".join(AKAGAMI_MODES),
            RESPONSIBLE_USE_NOTICE,
        ]
    else:
        lines = [
            AKAGAMI_BANNER.rstrip("\n"),
            f"    {AKAGAMI_TERMINAL_MARK} {BRAND} / {AKAGAMI_JA} v{VERSION}",
            f"    {AKAGAMI_HEADLINE}",
            f"    {' | '.join(AKAGAMI_MODES)}",
            f"    {RESPONSIBLE_USE_NOTICE}",
        ]
    return "\n".join(lines)


_COMMANDS = (
    ("quickstart", "Show the recommended beginner workflow"),
    ("recon", "Start a reconnaissance mission or dry-run plan"),
    ("workspaces", "List company workspaces"),
    ("intel", "Inspect stored mission intel"),
    ("endpoints", "Review ranked HTTP/API surfaces"),
    ("resume", "Print saved mission context"),
    ("gate", "Evaluate stage-gate readiness"),
    ("approval-status", "Show exploit-planning approval state"),
    ("approve", "Record operator approval"),
    ("report", "Generate a Markdown report"),
    ("tools", "Check toolchain and local environment"),
    ("db", "Manage local CVE/vector stores"),
    ("watcher", "Run the experimental target watcher"),
)

_FIRST_MOVES = (
    "akagami quickstart",
    "akagami tools doctor",
    "akagami recon -t example.com -C Example --passive-only --dry-run",
)
