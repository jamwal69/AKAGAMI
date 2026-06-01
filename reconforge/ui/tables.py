"""Reusable table renderers for Akagami CLI output."""

from __future__ import annotations

import json
import shlex
from typing import Any, Iterable

from rich import box
from rich.table import Table

from reconforge.ui.badges import badge, risk_badge, yes_no
from reconforge.ui.console import (
    get_console,
    print_line,
    use_plain_mode,
    use_verbose_mode,
)
from reconforge.ui.panels import print_next_moves
from reconforge.ui.theme import BORDER, TABLE_BORDER, TABLE_HEADER_STYLE, TITLE_STYLE


def print_workspaces(rows: list[dict]) -> None:
    """Render workspace inventory."""
    if not rows:
        print_line("No workspaces found. Start a mission with --company to create one.")
        return

    if use_plain_mode():
        print_line("Workspaces:")
        for row in rows:
            print_line(
                f"  {row['name']} | path={row['path']} | "
                f"in_scope={row['in_scope_count']} | "
                f"out_scope={row['out_of_scope_count']} | "
                f"db={yes_no(bool(row['has_db']))}"
            )
        return

    table = _base_table("Akagami Workspaces")
    table.add_column("Company", style="bold cyan")
    table.add_column("Path", style="dim")
    table.add_column("In Scope", justify="center", style="green")
    table.add_column("Out Scope", justify="center", style="red")
    table.add_column("DB", justify="center")
    for row in rows:
        table.add_row(
            row["name"],
            row["path"],
            str(row["in_scope_count"]),
            str(row["out_of_scope_count"]),
            badge("APPROVED") if row["has_db"] else badge("BLOCKED"),
        )
    get_console().print(table)


def print_tool_checks(
    rows: list[dict],
    title: str = "External Tools",
) -> None:
    """Render configured tool availability."""
    if use_plain_mode():
        print_line(f"{_strip_markup(title)}:")
        for row in rows:
            status = _tool_status(row)
            print_line(
                f"  {row['name']} | status={status} | "
                f"binary={row['binary']} | {row['requirement']} | "
                f"path={row['path'] or '-'} | "
                f"category={row['category'] or '-'} | risk={row['risk'] or '-'} | "
                f"reason={row.get('reason') or '-'}"
            )
        return

    table = _base_table(_strip_markup(title))
    table.add_column("Tool", style="bold cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True, min_width=12)
    table.add_column("Binary")
    table.add_column("Class")
    table.add_column("Path", overflow="fold", max_width=58)
    table.add_column("Category", no_wrap=True)
    table.add_column("Risk", no_wrap=True, min_width=12)
    table.add_column("Reason", overflow="fold", max_width=48)
    for row in rows:
        raw_risk = row["risk"] or "-"
        table.add_row(
            row["name"],
            badge(_tool_status(row)),
            row["binary"],
            row["requirement"],
            row["path"] or "-",
            row["category"] or "-",
            (
                f"{risk_badge(raw_risk)} [dim]{raw_risk}[/dim]"
                if raw_risk != "-"
                else "-"
            ),
            row.get("reason") or "-",
        )
    get_console().print(table)


def print_doctor_checks(checks: dict) -> None:
    """Render local doctor diagnostics."""
    grouped = _doctor_groups(checks)
    next_moves = [
        "akagami recon -t example.com -C Example --passive-only --dry-run",
        "akagami recon -t example.com -C Example --passive-only",
        "akagami endpoints -m <mission-id> -C Example",
    ]
    if use_plain_mode():
        for title in (
            "Runtime",
            "Package Resources",
            "External Tools",
            "Environment Variables",
            "Workspace",
        ):
            print_line(f"{title}:")
            if title == "External Tools":
                for row in grouped[title]:
                    print_line(
                        f"  {row['name']}: {_tool_status(row)} | "
                        f"binary={row['binary']} | path={row['path'] or '-'} | "
                        f"risk={row['risk'] or '-'} | reason={row.get('reason') or '-'}"
                    )
                print_line()
                continue
            if title == "Environment Variables":
                for row in grouped[title]:
                    print_line(
                        f"  {row['name']}: "
                        f"required={yes_no(bool(row['required']))} | "
                        f"present={yes_no(bool(row['present']))}"
                    )
                print_line()
                continue
            for check in grouped[title]:
                print_line(
                    f"  {check['name']}: {'APPROVED' if check['ok'] else 'BLOCKED'} | "
                    f"{check['detail']}"
                )
            print_line()
        print_next_moves(
            next_moves,
            intro="If the local deck looks ready, validate scope with a dry-run before running recon.",
        )
        return

    for title in ("Runtime", "Package Resources", "Workspace"):
        table = _base_table(title)
        table.add_column("Check", style="bold cyan")
        table.add_column("Status")
        table.add_column("Detail", overflow="fold", max_width=80)
        for check in grouped[title]:
            table.add_row(
                check["name"],
                badge("APPROVED") if check["ok"] else badge("BLOCKED"),
                check["detail"],
            )
        get_console().print(table)
        get_console().print()

    print_tool_checks(grouped["External Tools"], title="External Tools")
    get_console().print()

    env = _base_table("Environment Variables")
    env.add_column("Name", style="bold cyan")
    env.add_column("Required")
    env.add_column("Present")
    for row in grouped["Environment Variables"]:
        env.add_row(
            row["name"],
            yes_no(bool(row["required"])),
            badge("APPROVED") if row["present"] else badge("BLOCKED"),
        )
    get_console().print(env)
    print_next_moves(
        next_moves,
        intro="If the local deck looks ready, validate scope with a dry-run before running recon.",
    )


def print_dry_run_tables(result: dict) -> None:
    """Render dry-run plan, with detailed internals only in verbose mode."""
    _print_recon_plan(result["task_rows"])

    if use_verbose_mode():
        _print_task_rows(result["task_rows"])
        _print_agent_rows(result["agent_rows"])
        _print_tool_rows(result["tool_rows"])
        _print_risk_rows(result["risk_rows"])
        _print_scope_rows(result["scope_rows"])

    if not result["planned_tasks"]:
        if use_plain_mode():
            print_line(
                "No executable tasks survived local validation. "
                "Review scope and mission permissions."
            )
        else:
            get_console().print(
                "\n[bold red]No executable tasks survived local validation.[/bold red] "
                "[dim]Review scope and mission permissions.[/dim]"
            )


def _print_recon_plan(rows: list[dict]) -> None:
    if use_plain_mode():
        print_line("Recon Plan:")
        for index, row in enumerate(rows, start=1):
            print_line(
                f"  {index} | task={row['id']} | agent={row['agent']} | "
                f"tools={_tools_cell(row)} | risk={row['risk']} | "
                f"status={row['validation']}"
            )
        print_line()
        return

    table = _base_table("Recon Plan")
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Task", style="bold white", overflow="fold", max_width=28)
    table.add_column("Agent", style="bold magenta", no_wrap=True)
    table.add_column("Tool(s)", style="cyan", overflow="fold", max_width=34)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    for index, row in enumerate(rows, start=1):
        planned = row["validation"] == "planned"
        table.add_row(
            str(index),
            row["id"],
            row["agent"],
            _tools_cell(row),
            _risk_list(row["risk"]),
            badge("APPROVED") if planned else badge("BLOCKED"),
        )
    get_console().print(table)
    get_console().print()


def print_intel_tables(data: dict) -> None:
    """Render mission intel categories."""
    rendered = False
    for category, items in data.items():
        if not items:
            continue
        rendered = True
        title = category.replace("_", " ").title()
        if use_plain_mode():
            print_line(f"{title}:")
            _plain_records(items[:50], skip={"raw_output", "data_json", "config_json"})
            print_line()
            continue

        table = _base_table(title)
        columns = [
            col for col in items[0].keys()
            if col not in ("raw_output", "data_json", "config_json")
        ]
        for col in columns:
            table.add_column(col, overflow="fold", max_width=40)
        for item in items[:50]:
            table.add_row(*[str(item.get(col, ""))[:80] for col in columns])
        get_console().print(table)
        get_console().print()

    if not rendered:
        print_line("No intel records found for this mission.")


def print_endpoint_table(
    rows: list[dict],
    *,
    mission_id: str = "<mission-id>",
    company: str = "",
) -> None:
    """Render ranked HTTP/API endpoint inventory."""
    if not rows:
        print_line("No HTTP/API inventory records found for this mission.")
        print_next_moves(
            _empty_endpoint_next_moves(mission_id, company),
            intro=(
                "Confirm the mission completed, inspect raw intel, or rerun a passive scoped mission."
            ),
        )
        return

    if use_plain_mode():
        print_line("HTTP/API Intelligence Board:")
        for index, row in enumerate(rows, start=1):
            signal = _signal_cell(row)
            notes = _endpoint_notes(row)
            host = row.get("host", "")
            path = row.get("normalized_route") or row.get("path", "")
            print_line(
                f"  {index} | {row.get('method', '')} {host}{path} | "
                f"signal={signal} | source={row.get('source', '') or '-'} | "
                f"auth={row.get('auth_required', '') or 'unknown'} | notes={notes}"
            )
        return

    table = _base_table("HTTP/API Intelligence Board")
    table.add_column("Rank", justify="right", style="dim", no_wrap=True)
    table.add_column("Method", style="bold cyan", no_wrap=True)
    table.add_column("Endpoint", style="bold white", overflow="fold", max_width=42)
    table.add_column("Signal", overflow="fold", max_width=38)
    table.add_column("Source", style="magenta", no_wrap=True)
    table.add_column("Auth", no_wrap=True)
    table.add_column("Notes", overflow="fold", max_width=42)
    for index, row in enumerate(rows, start=1):
        host = row.get("host", "")
        path = row.get("normalized_route") or row.get("path", "")
        table.add_row(
            str(index),
            row.get("method", ""),
            f"{host}{path}",
            _signal_cell(row),
            row.get("source", ""),
            row.get("auth_required", "") or "unknown",
            _endpoint_notes(row),
        )
    get_console().print(table)


def print_attack_surface_summary(
    summary: dict,
    title: str = "Attack Surface Summary",
) -> None:
    """Render attack surface summary metrics."""
    if not summary:
        return

    if use_plain_mode():
        print_line(f"{title}:")
        for key, value in summary.items():
            if key not in ("missing_coverage", "vulnerabilities_by_severity"):
                print_line(f"  {key.replace('_', ' ').title()}: {value}")
        missing = summary.get("missing_coverage", [])
        if missing:
            print_line("Missing coverage:")
            for gap in missing:
                print_line(f"  - {gap}")
        return

    table = _base_table(title)
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", style="bold")
    for key, value in summary.items():
        if key not in ("missing_coverage", "vulnerabilities_by_severity"):
            table.add_row(key.replace("_", " ").title(), str(value))
    get_console().print(table)

    missing = summary.get("missing_coverage", [])
    if missing:
        get_console().print("\n[bold yellow]Missing coverage[/bold yellow]")
        for gap in missing:
            get_console().print(f"  [yellow]-[/yellow] {gap}")


def print_db_stats(stats: dict) -> None:
    """Render local ChromaDB collection stats."""
    if use_plain_mode():
        print_line("ChromaDB Collections:")
        for name, count in stats.items():
            print_line(f"  {name}: {count}")
        return

    table = _base_table("ChromaDB Collections")
    table.add_column("Collection", style="bold cyan")
    table.add_column("Documents", style="bold", justify="right")
    for name, count in stats.items():
        table.add_row(name, str(count))
    get_console().print(table)


def _print_task_rows(rows: list[dict]) -> None:
    if use_plain_mode():
        print_line("Planned Tasks:")
        for row in rows:
            print_line(
                f"  {row['id']} | agent={row['agent']} | task_tool={row['task_tool']} | "
                f"requested={', '.join(row['requested_tools']) or '-'} | "
                f"risk={row['risk']} | depends_on={', '.join(row['depends_on']) or '-'} | "
                f"scope={row['scope_status']} | status={row['validation']}"
            )
        print_line()
        return

    table = _base_table("Planned Tasks")
    table.add_column("Task", style="bold cyan")
    table.add_column("Agent", style="magenta")
    table.add_column("Task Tool")
    table.add_column("Requested Tools", overflow="fold", max_width=34)
    table.add_column("Risk")
    table.add_column("Depends On", overflow="fold", max_width=28)
    table.add_column("Scope")
    table.add_column("Status")
    for row in rows:
        planned = row["validation"] == "planned"
        table.add_row(
            row["id"],
            row["agent"],
            row["task_tool"],
            ", ".join(row["requested_tools"]) or "-",
            _risk_list(row["risk"]),
            ", ".join(row["depends_on"]) if row["depends_on"] else "-",
            row["scope_status"],
            badge("APPROVED") if planned else badge("BLOCKED"),
        )
    get_console().print(table)
    get_console().print()


def _print_agent_rows(rows: list[dict]) -> None:
    if use_plain_mode():
        print_line("Agents That Would Run:")
        for row in rows:
            print_line(
                f"  {row['agent']} | tasks={row['tasks']} | "
                f"tools={', '.join(row['tools']) if row['tools'] else '-'}"
            )
        print_line()
        return

    table = _base_table("Agents That Would Run")
    table.add_column("Agent", style="bold magenta")
    table.add_column("Tasks", justify="right")
    table.add_column("Requested Tools", overflow="fold", max_width=60)
    for row in rows:
        table.add_row(
            row["agent"],
            str(row["tasks"]),
            ", ".join(row["tools"]) if row["tools"] else "-",
        )
    get_console().print(table)
    get_console().print()


def _print_tool_rows(rows: list[dict]) -> None:
    if use_plain_mode():
        print_line("Tools That Would Be Requested:")
        for row in rows:
            print_line(
                f"  {row['tool']} | route={row['route']} | binary={row['binary']} | "
                f"risk={row['risk']} | requests={row['count']} | "
                f"tasks={', '.join(row['tasks'])}"
            )
        print_line()
        return

    table = _base_table("Tools That Would Be Requested")
    table.add_column("Tool", style="bold cyan")
    table.add_column("Route")
    table.add_column("Binary")
    table.add_column("Risk")
    table.add_column("Requests", justify="right")
    table.add_column("From Tasks", overflow="fold", max_width=60)
    for row in rows:
        table.add_row(
            row["tool"],
            row["route"],
            row["binary"],
            risk_badge(row["risk"]),
            str(row["count"]),
            ", ".join(row["tasks"]),
        )
    get_console().print(table)
    get_console().print()


def _print_risk_rows(rows: list[dict]) -> None:
    if use_plain_mode():
        print_line("Active/Passive Risk:")
        for row in rows:
            print_line(f"  {row['risk']}: {row['tasks']}")
        print_line()
        return

    table = _base_table("Active/Passive Risk")
    table.add_column("Risk")
    table.add_column("Tasks", justify="right")
    for row in rows:
        table.add_row(risk_badge(row["risk"]), str(row["tasks"]))
    get_console().print(table)
    get_console().print()


def _print_scope_rows(rows: list[dict]) -> None:
    if use_plain_mode():
        print_line("Scope Decisions:")
        for row in rows:
            subjects = ", ".join(row["subjects"]) if row["subjects"] else "-"
            print_line(
                f"  {row['task']} | tool={row['tool']} | "
                f"decision={row['status']} | subjects={subjects}"
            )
        return

    table = _base_table("Scope Decisions")
    table.add_column("Task", style="bold cyan")
    table.add_column("Tool")
    table.add_column("Decision")
    table.add_column("Subject(s)", overflow="fold", max_width=80)
    for row in rows:
        decision = badge("BLOCKED") if row["status"] == "denied" else row["status"]
        table.add_row(
            row["task"],
            row["tool"],
            decision,
            ", ".join(row["subjects"]) if row["subjects"] else "-",
        )
    get_console().print(table)


def _doctor_groups(checks: dict) -> dict[str, list[dict]]:
    system = checks.get("system", [])
    runtime = [
        check for check in system
        if not check.get("name", "").startswith("Packaged")
        and "Workspace" not in check.get("name", "")
    ]
    resources = [
        check for check in system
        if check.get("name", "").startswith("Packaged")
    ]
    workspace = [
        check for check in system
        if "Workspace" in check.get("name", "")
    ]
    return {
        "Runtime": runtime,
        "Package Resources": resources,
        "External Tools": checks.get("tools", []),
        "Environment Variables": checks.get("environment", []),
        "Workspace": workspace,
    }


def _tools_cell(row: dict) -> str:
    requested = row.get("requested_tools") or []
    if requested:
        return ", ".join(requested)
    return row.get("task_tool") or "-"


def _signal_cell(row: dict) -> str:
    score = float(row.get("interestingness_score") or 0)
    signals = _json_cell(row.get("interestingness_signals"))[:2]
    signal_text = "; ".join(signals) if signals else "baseline signal"
    return f"{score:.0f} | {signal_text}"


def _endpoint_notes(row: dict) -> str:
    tests = _json_cell(row.get("recommended_manual_tests"))[:2]
    confidence = float(row.get("confidence") or 0)
    fp_risk = row.get("false_positive_risk", "medium")
    parts = [f"conf {confidence:.0%}", f"fp {fp_risk}"]
    if tests:
        parts.append("; ".join(tests))
    return " | ".join(parts)


def _base_table(title: str) -> Table:
    return Table(
        title=f"[{TITLE_STYLE}]{title}[/{TITLE_STYLE}]",
        box=box.ROUNDED,
        border_style=TABLE_BORDER if title != "Recon Plan" else BORDER,
        header_style=TABLE_HEADER_STYLE,
    )


def _tool_status(row: dict) -> str:
    status = row.get("status")
    if status:
        return str(status).upper()
    return "FOUND" if row.get("installed") else "MISSING"


def _plain_records(items: Iterable[dict], skip: set[str]) -> None:
    for item in items:
        parts = [
            f"{key}={value}"
            for key, value in item.items()
            if key not in skip
        ]
        print_line(f"  {' | '.join(parts)}")


def _json_cell(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(v) for v in parsed]
    except (TypeError, json.JSONDecodeError):
        pass
    return [str(value)]


def _risk_list(value: str) -> str:
    risks = [risk.strip() for risk in str(value).split(",") if risk.strip()]
    return " ".join(risk_badge(risk) for risk in risks) if risks else "-"


def _strip_markup(value: str) -> str:
    return (
        value.replace("[bold]", "")
        .replace("[/bold]", "")
        .replace("[bold red]", "")
        .replace("[/bold red]", "")
    )


def _empty_endpoint_next_moves(mission_id: str, company: str) -> list[str]:
    company_arg = f" -C {shlex.quote(company)}" if company else " -C <company>"
    mission_arg = shlex.quote(str(mission_id))
    return [
        f"Inspect stored intel: akagami intel -m {mission_arg}{company_arg}",
        f"Validate local plan: akagami recon -t <target>{company_arg} --passive-only --dry-run",
        f"Run passive recon: akagami recon -t <target>{company_arg} --passive-only",
    ]
