"""Reusable Rich/plain panels for Akagami command output."""

from __future__ import annotations

import json
import shlex
from typing import Any

from rich import box
from rich.panel import Panel
from rich.table import Table

from reconforge.ui.badges import approval_badge, badge, passed_blocked, yes_no
from reconforge.ui.banner import RESPONSIBLE_USE_NOTICE
from reconforge.ui.console import get_console, print_line, use_plain_mode
from reconforge.ui.theme import BORDER, METADATA, TITLE_STYLE


QUICKSTART_COMMANDS = [
    "akagami tools doctor",
    "akagami recon -t example.com -C Example --passive-only --dry-run",
    "akagami recon -t example.com -C Example --passive-only",
    "akagami endpoints -m <mission-id> -C Example",
    "akagami report -m <mission-id> -C Example -t example.com",
]


def print_quickstart() -> None:
    """Render the recommended beginner workflow."""
    intro = (
        "Begin passive, confirm scope locally, then review stored surfaces and "
        "generate the report from the mission store."
    )

    if use_plain_mode():
        print_line("Quickstart:")
        print_line(f"  {intro}")
        for index, command in enumerate(QUICKSTART_COMMANDS, start=1):
            print_line(f"  {index}. {command}")
        print_line()
        return

    rows = Table.grid(padding=(0, 1))
    rows.add_column(style="bold cyan", no_wrap=True)
    rows.add_column(style="white", overflow="fold")
    labels = [
        "Doctor",
        "Dry Run",
        "Passive Recon",
        "Endpoints",
        "Report",
    ]
    for index, (label, command) in enumerate(zip(labels, QUICKSTART_COMMANDS), start=1):
        rows.add_row(f"{index}. {label}", command)

    body = Table.grid(padding=(1, 0))
    body.add_column()
    body.add_row(f"[dim]{intro}[/dim]")
    body.add_row(rows)
    body.add_row(f"[yellow]{RESPONSIBLE_USE_NOTICE}[/yellow]")

    get_console().print(
        Panel(
            body,
            title=f"[{TITLE_STYLE}]Quickstart[/{TITLE_STYLE}]",
            subtitle="[dim]passive-first scoped recon workflow[/dim]",
            border_style=BORDER,
            box=box.ROUNDED,
        )
    )


def print_next_moves(
    moves: list[str],
    *,
    intro: str = "",
    include_recommended_label: bool = False,
) -> None:
    """Render a reusable next-step guidance block."""
    if not moves:
        return

    if use_plain_mode():
        print_line("Next Moves:")
        if intro:
            print_line(f"  {intro}")
        if include_recommended_label:
            print_line("Recommended next commands:")
        for move in moves:
            print_line(f"  {move}")
        print_line()
        return

    body = Table.grid(padding=(0, 1))
    body.add_column(style="bold cyan", overflow="fold")
    if intro:
        body.add_row(f"[dim]{intro}[/dim]")
    if include_recommended_label:
        body.add_row("[bold]Recommended next commands[/bold]")
    for move in moves:
        body.add_row(move)

    get_console().print(
        Panel(
            body,
            title=f"[{TITLE_STYLE}]Next Moves[/{TITLE_STYLE}]",
            border_style=BORDER,
            box=box.ROUNDED,
        )
    )


def print_mission_start(
    mission: Any,
    *,
    target: str,
    active_requested: bool,
    dry_run: bool,
) -> None:
    """Render the mission start briefing."""
    active_allowed = bool(getattr(mission, "active_scan_permitted", False))
    opsec_enabled = bool(getattr(mission, "opsec_mode", False))
    scan_mode = _scan_mode(active_allowed, active_requested)
    run_label = "Dry Run Briefing" if dry_run else "Mission Start"
    warning = ""
    if active_requested and not active_allowed:
        warning = "Active scan requested but blocked by mission config."

    rows = [
        ("Target", target),
        ("Company", getattr(mission, "company_name", "") or "-"),
        ("Workspace", getattr(mission, "workspace_dir", "") or "-"),
        ("Mode", getattr(mission, "mode", "") or "standard"),
        ("Scan Profile", scan_mode),
        ("OPSEC", badge("OPSEC") if opsec_enabled else "disabled"),
        ("Mission ID", getattr(mission, "mission_id", "")),
    ]

    if use_plain_mode():
        print_line(f"{run_label}:")
        for key, value in rows:
            print_line(f"  {key}: {value}")
        if warning:
            print_line(f"  Warning: {warning}")
        print_line()
        return

    table = _kv_grid(rows)
    if warning:
        table.add_row("Warning:", f"[bold yellow]{warning}[/bold yellow]")

    get_console().print(
        Panel(
            table,
            title=f"[{TITLE_STYLE}]{run_label}[/{TITLE_STYLE}]",
            subtitle="[dim]scope-aware operator workflow[/dim]",
            border_style=BORDER,
            box=box.ROUNDED,
        )
    )


def print_dry_run_boundary(result: dict) -> None:
    """Render the local-only dry-run command-deck briefing."""
    mission = result["mission"]
    mission_rows = [
        ("Target", getattr(mission, "target", "") or "-"),
        ("Company", getattr(mission, "company_name", "") or "-"),
        ("Mode", getattr(mission, "mode", "") or "standard"),
        ("Mission ID", getattr(mission, "mission_id", "") or "-"),
    ]
    execution_rows = [
        ("Planner", f"{result['planner']} {badge('PLANNER')}"),
        ("Config", _config_status(result)),
        ("LLM API calls", str(result["llm_calls"])),
        ("External executions", str(result["external_tools_executed"])),
        ("Runtime writes", _runtime_writes(result)),
    ]
    safety_rows = [
        (
            "Active scanning",
            f"{badge('APPROVED') if getattr(mission, 'active_scan_permitted', False) else badge('BLOCKED')} "
            f"{'permitted by config' if getattr(mission, 'active_scan_permitted', False) else 'not permitted'}",
        ),
        ("OPSEC", badge("OPSEC") if getattr(mission, "opsec_mode", False) else "disabled"),
        ("Validation", f"{badge('APPROVED')} local scope and tool policy"),
    ]
    scope_rows = [
        ("In scope", ", ".join(getattr(mission, "scope", []) or []) or "-"),
        ("Out of scope", ", ".join(getattr(mission, "out_of_scope", []) or []) or "-"),
        ("Rejected tasks", str(len(result.get("rejected_tasks", [])))),
    ]

    if use_plain_mode():
        _print_plain_section("Mission", mission_rows)
        _print_plain_section("Execution", execution_rows)
        _print_plain_section("Safety Gate", safety_rows)
        _print_plain_section("Scope", scope_rows)
        return

    cards = Table.grid(expand=True)
    cards.add_column(ratio=1)
    cards.add_column(ratio=1)
    cards.add_row(
        _card("Mission", mission_rows),
        _card("Execution", execution_rows),
    )
    get_console().print(cards)
    get_console().print(_card("Safety Gate", safety_rows, border_style="yellow"))
    get_console().print(_card("Scope", scope_rows, border_style="bright_black"))


def print_dry_run_guarantee(result: dict) -> None:
    """Render the dry-run guarantee and recommended next actions."""
    mission = result["mission"]
    guarantees = [
        f"{badge('APPROVED')} No external tools executed",
        f"{badge('APPROVED')} No LLM/API calls made",
        f"{badge('APPROVED')} No mission database writes",
        f"{badge('APPROVED')} Local plan validation only",
    ]
    next_moves = _dry_run_next_moves(result, mission)

    if use_plain_mode():
        print_line("Dry Run Guarantee:")
        for item in guarantees:
            print_line(f"  {item}")
        print_line()
        print_next_moves(next_moves)
        return

    guarantee_table = Table.grid(padding=(0, 1))
    guarantee_table.add_column()
    for item in guarantees:
        guarantee_table.add_row(item)
    get_console().print(
        Panel(
            guarantee_table,
            title=f"[{TITLE_STYLE}]Dry Run Guarantee[/{TITLE_STYLE}]",
            border_style="green",
            box=box.ROUNDED,
        )
    )

    print_next_moves(next_moves)


def print_mission_complete(
    result: dict,
    *,
    target: str = "",
    company: str = "",
) -> None:
    """Render final mission summary and next commands."""
    mission_id = result.get("mission_id", "unknown")
    gate_passed = bool(result.get("stage_gate", {}).get("passed"))
    task_summary = result.get("task_summary", {})
    attack_surface = result.get("attack_surface", {}) or {}
    report_path = result.get("report_path")
    commands = _recommended_commands(
        mission_id,
        gate_passed,
        target=target,
        company=company,
    )

    summary_rows = [
        ("Mission ID", str(mission_id)),
        ("Stage Gate", _gate_label(gate_passed)),
        ("Tasks", _task_summary_text(task_summary)),
        ("Hosts", str(attack_surface.get("hosts", 0))),
        ("HTTP/API Surfaces", str(attack_surface.get("http_api_surfaces", 0))),
        ("Vulnerabilities", str(attack_surface.get("vulnerabilities", 0))),
        ("Report", str(report_path or "-")),
    ]

    if use_plain_mode():
        print_line("Mission Complete:")
        for key, value in summary_rows:
            print_line(f"  {key}: {value}")
        print_next_moves(commands, include_recommended_label=True)
        return

    summary = _kv_grid(summary_rows)

    get_console().print(
        Panel(
            summary,
            title=f"[{TITLE_STYLE}]Mission Complete[/{TITLE_STYLE}]",
            border_style="green" if gate_passed else "yellow",
            box=box.ROUNDED,
        )
    )
    print_next_moves(commands, include_recommended_label=True)


def print_approval_status(status: dict | None) -> None:
    """Render operator approval status."""
    if not status:
        return
    gate = status.get("stage_gate", {}) or {}
    gate_passed = bool(status.get("stage_gate_passed"))
    operator_approved = bool(status.get("operator_approved"))
    exploit_approved = bool(status.get("exploit_planning_approved"))
    requires_operator = bool(status.get("requires_operator_approval", True))
    operator_state = (
        "APPROVED" if operator_approved
        else "REQUIRED" if requires_operator
        else "APPROVED"
    )
    exploit_state = "APPROVED" if exploit_approved else "BLOCKED"

    rows = [
        ("Mission ID", status.get("mission_id", "")),
        ("Target", status.get("target", "")),
        ("Stage Gate", _gate_label(gate_passed)),
        ("Operator Approval", f"{approval_badge(operator_state)} {operator_state}"),
        ("Exploit Planning", f"{approval_badge(exploit_state)} {exploit_state}"),
        ("Approval Required", yes_no(requires_operator)),
        ("Reason", gate.get("reason", "not recorded")),
    ]

    if use_plain_mode():
        print_line("Escalation Checkpoint:")
        for key, value in rows:
            print_line(f"  {key}: {value}")
        print_line()
        return

    get_console().print(
        Panel(
            _kv_grid(rows),
            title=f"[{TITLE_STYLE}]Escalation Checkpoint[/{TITLE_STYLE}]",
            subtitle="[dim]operator approval controls exploit-planning unlock[/dim]",
            border_style="yellow" if operator_state == "REQUIRED" else BORDER,
            box=box.ROUNDED,
        )
    )


def print_gate_status(result: Any, summary: dict) -> None:
    """Render stage-gate evaluation status."""
    passed = bool(getattr(result, "passed", False))
    requires_operator = bool(getattr(result, "requires_operator_approval", True))
    checkpoint = "APPROVED" if passed else "BLOCKED"
    approval_state = "REQUIRED" if requires_operator else "APPROVED"
    rows = [
        ("Checkpoint", f"{approval_badge(checkpoint)} {checkpoint}"),
        ("Operator Approval", f"{approval_badge(approval_state)} {approval_state}"),
        ("Confidence", f"{getattr(result, 'confidence', 0):.0%}"),
        ("Reason", getattr(result, "reason", "")),
    ]

    if use_plain_mode():
        print_line("Escalation Checkpoint:")
        for key, value in rows:
            print_line(f"  {key}: {value}")
        _print_missing_coverage(getattr(result, "missing_coverage", []) or [])
        return

    get_console().print(
        Panel(
            _kv_grid(rows),
            title=f"[{TITLE_STYLE}]Escalation Checkpoint[/{TITLE_STYLE}]",
            subtitle="[dim]recon sufficiency and operator approval state[/dim]",
            border_style="green" if passed else "red",
            box=box.ROUNDED,
        )
    )
    _print_missing_coverage(getattr(result, "missing_coverage", []) or [])


def print_report_summary(
    *,
    mission_id: str,
    output: str,
    character_count: int,
    target: str = "",
    company: str = "",
) -> None:
    """Render report generation summary."""
    rows = [
        ("Mission ID", mission_id),
        ("Output", output),
        ("Characters", f"{character_count:,}"),
    ]
    if use_plain_mode():
        _print_plain_section("Report Generated", rows)
        print_next_moves(_report_next_moves(mission_id, target=target, company=company))
        return

    get_console().print(
        Panel(
            _kv_grid(rows),
            title=f"[{TITLE_STYLE}]Report Generated[/{TITLE_STYLE}]",
            border_style="green",
            box=box.ROUNDED,
        )
    )
    print_next_moves(_report_next_moves(mission_id, target=target, company=company))


def _card(
    title: str,
    rows: list[tuple[str, Any]],
    *,
    border_style: str = BORDER,
) -> Panel:
    return Panel(
        _kv_grid(rows),
        title=f"[{TITLE_STYLE}]{title}[/{TITLE_STYLE}]",
        border_style=border_style,
        box=box.ROUNDED,
    )


def _kv_grid(rows: list[tuple[str, Any]]) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=METADATA, no_wrap=True)
    table.add_column(style="white", overflow="fold")
    for key, value in rows:
        table.add_row(f"{key}:", str(value))
    return table


def _print_plain_section(title: str, rows: list[tuple[str, Any]]) -> None:
    print_line(f"{title}:")
    for key, value in rows:
        print_line(f"  {key}: {value}")
    print_line()


def _print_missing_coverage(missing: list[str]) -> None:
    if not missing:
        return
    if use_plain_mode():
        print_line("Missing coverage:")
        for gap in missing:
            print_line(f"  - {gap}")
        return
    get_console().print("\n[bold yellow]Missing coverage[/bold yellow]")
    for gap in missing:
        get_console().print(f"  [yellow]-[/yellow] {gap}")


def _scan_mode(active_allowed: bool, active_requested: bool) -> str:
    if active_allowed:
        return f"{badge('ACTIVE')} + {badge('PASSIVE')}"
    if active_requested:
        return f"{badge('PASSIVE')} active denied by config"
    return badge("PASSIVE")


def _config_status(result: dict) -> str:
    if result.get("config_loaded"):
        return f"loaded from {result.get('config_path') or '-'}"
    return f"not found at {result.get('config_path') or '-'}; using CLI/defaults"


def _runtime_writes(result: dict) -> str:
    runtime_writes = result.get("runtime_writes") or []
    return ", ".join(runtime_writes) if runtime_writes else "none"


def _gate_label(passed: bool) -> str:
    return f"{'PASSED' if passed else 'NOT PASSED'} {passed_blocked(passed)}"


def _task_summary_text(task_summary: dict) -> str:
    if not task_summary:
        return "{}"
    try:
        return ", ".join(f"{key}={value}" for key, value in task_summary.items())
    except AttributeError:
        return json.dumps(task_summary, default=str)


def _recommended_commands(
    mission_id: str,
    gate_passed: bool,
    *,
    target: str = "",
    company: str = "",
) -> list[str]:
    company_arg = _company_arg(company)
    target_arg = _target_arg(target)
    commands = [
        f"akagami endpoints -m {_shell_arg(mission_id)}{company_arg} -l 20",
        f"akagami intel -m {_shell_arg(mission_id)}{company_arg}",
        f"akagami report -m {_shell_arg(mission_id)}{company_arg}{target_arg}",
    ]
    if gate_passed:
        commands.insert(2, f"akagami approval-status -m {_shell_arg(mission_id)}{company_arg}")
    else:
        commands.insert(2, f"akagami gate -m {_shell_arg(mission_id)}{target_arg}{company_arg}")
    return commands


def _dry_run_next_moves(result: dict, mission: Any) -> list[str]:
    target = getattr(mission, "target", "") or "<target>"
    company = getattr(mission, "company_name", "") or "<company>"
    company_arg = _company_arg(company)
    target_arg = _target_arg(target)
    return [
        f"Run passive mission: akagami recon{target_arg}{company_arg} --passive-only",
        f"Review endpoints after completion: akagami endpoints -m <mission-id>{company_arg}",
        f"Generate report: akagami report -m <mission-id>{company_arg}{target_arg}",
        "Review local health: akagami tools doctor",
        f"Use verbose dry-run: akagami recon{target_arg}{company_arg} --passive-only --dry-run --verbose",
    ]


def _report_next_moves(mission_id: str, *, target: str = "", company: str = "") -> list[str]:
    company_arg = _company_arg(company)
    target_arg = _target_arg(target)
    return [
        f"Review endpoint inventory: akagami endpoints -m {_shell_arg(mission_id)}{company_arg}",
        f"Check escalation state: akagami approval-status -m {_shell_arg(mission_id)}{company_arg or ' -C <company>'}",
        f"Regenerate after new intel: akagami report -m {_shell_arg(mission_id)}{company_arg}{target_arg}",
    ]


def _company_arg(company: str) -> str:
    return f" -C {_shell_arg(company)}" if company else " -C <company>"


def _target_arg(target: str) -> str:
    return f" -t {_shell_arg(target)}" if target else " -t <target>"


def _shell_arg(value: str) -> str:
    return shlex.quote(str(value))
