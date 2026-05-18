"""
Akagami CLI — Click entrypoint with Rich progress display.
Branded CLI for the multi-agent reconnaissance engine.
"""

import asyncio
import json
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from reconforge.intel.models import MissionState
from reconforge.intel.store import IntelStore
from reconforge.memory.episodic import EpisodicMemory
from reconforge.orchestrator.master import MasterOrchestrator
from reconforge.workspace import (
    init_workspace, get_db_path, get_report_dir,
    list_workspaces, append_engagement_log, sanitize_name,
)

console = Console()

# ── Akagami Banner ──────────────────────────────────────────────
AKAGAMI_BANNER = r"""
    ___    __ __    ___    ____    ___    __  ___ ____
   /   |  / //_/  /   |  / ___/  /   |  /  |/  //  _/
  / /| | / ,<    / /| | / / _   / /| | / /|_/ / / /
 / ___ |/ /| |  / ___ |/ /_/ / / ___ |/ /  / /_/ /
/_/  |_/_/ |_| /_/  |_|\____/ /_/  |_/_/  /_//___/
"""

AKAGAMI_TAGLINE = "⚔️  Multi-Agent Reconnaissance Engine  v2.0.0"
AKAGAMI_LINE = "━" * 54


def print_banner():
    """Print the Akagami banner in bold red."""
    console.print(AKAGAMI_BANNER, style="bold red", highlight=False)
    console.print(f"    {AKAGAMI_TAGLINE}", style="bold red", highlight=False)
    console.print(f"    {AKAGAMI_LINE}", style="red", highlight=False)
    console.print()


def print_mini_banner():
    """Compact single-line banner for sub-commands."""
    console.print(
        f"  [bold red]赤髪 AKAGAMI[/bold red]  [dim]|[/dim]  "
        f"[dim]Multi-Agent Reconnaissance Engine[/dim]"
    )
    console.print()


# ── Config Loader ───────────────────────────────────────────────

def load_mission_config(config_path: str, target: str,
                        passive_only: bool = True,
                        opsec_mode: bool = False,
                        company: str = "",
                        mode: str = "standard") -> tuple[MissionState, dict]:
    """Load mission config from YAML and create MissionState."""
    config = {}
    config_file = Path(config_path)
    if config_file.exists():
        with open(config_file) as f:
            config = yaml.safe_load(f) or {}

    mission_cfg = config.get("mission", {})
    scope_cfg = config.get("scope", {})
    perms_cfg = config.get("permissions", {})
    opsec_cfg = config.get("opsec", {})

    in_scope = scope_cfg.get("in_scope", [target] if target else [])
    out_scope = scope_cfg.get("out_of_scope", [])

    if target and target not in in_scope:
        in_scope.append(target)

    # ── Workspace scaffolding ─────────────────────────────────
    company_name = company or mission_cfg.get("company_name", "")
    workspace_dir = ""

    if company_name:
        ws = init_workspace(company_name, in_scope=in_scope, out_of_scope=out_scope)
        workspace_dir = str(ws)
    else:
        # Fallback: derive company name from target domain
        if target:
            domain_parts = target.replace("www.", "").split(".")
            company_name = domain_parts[0] if domain_parts else target
            ws = init_workspace(company_name, in_scope=in_scope, out_of_scope=out_scope)
            workspace_dir = str(ws)

    mission = MissionState(
        target=target or mission_cfg.get("target", ""),
        mission_name=mission_cfg.get("mission_name", f"Recon: {target}"),
        company_name=company_name,
        workspace_dir=workspace_dir,
        scope=in_scope,
        out_of_scope=out_scope,
        active_scan_permitted=not passive_only and perms_cfg.get("active_scanning", False),
        opsec_mode=opsec_mode or opsec_cfg.get("enabled", False),
        mode=mode,
    )
    return mission, config


# ── CLI Group ───────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option(version="2.0.0", prog_name="Akagami")
@click.pass_context
def cli(ctx):
    """Akagami — Professional-grade multi-agent reconnaissance engine."""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("  [dim]Usage:[/dim]  [bold]akagami[/bold] [red]<command>[/red] [dim][options][/dim]")
        console.print()
        console.print("  [red]Commands:[/red]")
        console.print("    [bold]recon[/bold]       Start a reconnaissance mission")
        console.print("    [bold]workspaces[/bold]  List all company workspaces")
        console.print("    [bold]intel[/bold]       View current intel store")
        console.print("    [bold]endpoints[/bold]   View high-signal HTTP/API surfaces")
        console.print("    [bold]resume[/bold]      Resume an interrupted mission")
        console.print("    [bold]gate[/bold]        Evaluate stage gate readiness")
        console.print("    [bold]report[/bold]      Generate professional report")
        console.print("    [bold]db[/bold]          Database management")
        console.print()
        console.print("  [dim]Run[/dim] [bold]akagami <command> --help[/bold] [dim]for details.[/dim]")
        console.print()


# ── Recon Command ───────────────────────────────────────────────

@cli.command()
@click.option("--target", "-t", required=True, help="Target domain or IP")
@click.option("--company", "-C", default="", help="Company/program name (auto-creates workspace)")
@click.option("--passive-only", is_flag=True, default=False, help="Passive recon only")
@click.option("--active", is_flag=True, default=False, help="Enable active scanning")
@click.option("--opsec-mode", is_flag=True, default=False, help="Enable opsec controls")
@click.option("--config", "-c", default="config/mission.yaml", help="Mission config path")
@click.option("--mode", type=click.Choice(["standard", "bug-bounty"]), default="standard", help="Mission execution mode")
def recon(target, company, passive_only, active, opsec_mode, config, mode):
    """Start a reconnaissance mission."""
    print_banner()

    mission, cfg = load_mission_config(
        config, target,
        passive_only=passive_only or not active,
        opsec_mode=opsec_mode,
        company=company,
        mode=mode)

    mode_str = "[green]Passive Only[/green]" if passive_only or not active else "[yellow]Active + Passive[/yellow]"
    opsec_str = "[yellow]Enabled[/yellow]" if opsec_mode else "[dim]Disabled[/dim]"

    console.print(Panel.fit(
        f"[bold red]AKAGAMI[/bold red] — Mission Initiated\n"
        f"\n"
        f"  Target:    [bold white]{target}[/bold white]\n"
        f"  Company:   [bold magenta]{mission.company_name}[/bold magenta]\n"
        f"  Workspace: [dim]{mission.workspace_dir}[/dim]\n"
        f"  Mission Mode: [bold cyan]{mission.mode}[/bold cyan]\n"
        f"  Scan Type: {mode_str}\n"
        f"  Opsec:     {opsec_str}",
        title="[bold red]⚔️  Mission Briefing[/bold red]",
        border_style="red",
        box=box.HEAVY))

    console.print(f"\n  [dim]Mission ID:[/dim] [bold]{mission.mission_id}[/bold]")
    console.print(f"  [dim]Scope:     [/dim] [dim]{mission.scope}[/dim]\n")

    # Use company-specific database
    if mission.workspace_dir:
        db_path = get_db_path(Path(mission.workspace_dir))
        cfg["_db_path"] = db_path
        append_engagement_log(
            Path(mission.workspace_dir),
            f"Mission started: {mission.mission_id} → {target}")

    orchestrator = MasterOrchestrator(mission, cfg)
    try:
        result = asyncio.run(orchestrator.run())
        _display_results(result)

        # Log completion
        if mission.workspace_dir:
            gate = "PASSED" if result.get("stage_gate", {}).get("passed") else "FAILED"
            append_engagement_log(
                Path(mission.workspace_dir),
                f"Mission completed: {mission.mission_id} | Gate: {gate}")
    except KeyboardInterrupt:
        console.print("\n  [yellow]⚠  Mission interrupted by operator[/yellow]")
    except Exception as e:
        console.print(f"\n  [red]✗  Mission failed: {e}[/red]")
        raise
    finally:
        orchestrator.cleanup()


# ── Workspaces Command ──────────────────────────────────────────

@cli.command()
def workspaces():
    """List all company workspaces."""
    print_mini_banner()

    ws_list = list_workspaces()
    if not ws_list:
        console.print("  [dim]No workspaces found. Start a mission with --company to create one.[/dim]")
        return

    table = Table(
        title="[bold red]⚔️  Akagami Workspaces[/bold red]",
        box=box.ROUNDED,
        border_style="red",
        title_style="bold red",
    )
    table.add_column("Company", style="cyan bold")
    table.add_column("Path", style="dim")
    table.add_column("In Scope", style="green", justify="center")
    table.add_column("Out Scope", style="red", justify="center")
    table.add_column("DB", style="yellow", justify="center")

    for ws in ws_list:
        table.add_row(
            ws["name"],
            ws["path"],
            str(ws["in_scope_count"]),
            str(ws["out_of_scope_count"]),
            "✓" if ws["has_db"] else "—",
        )
    console.print(table)


# ── Resume Command ──────────────────────────────────────────────

@cli.command()
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--company", "-C", default="", help="Company name to find workspace")
def resume(mission_id, company):
    """Resume a previous mission."""
    print_mini_banner()
    console.print(f"  [bold red]⚔️  Resuming mission:[/bold red] [bold]{mission_id}[/bold]")

    db_path = "output/missions.db"
    if company:
        ws = init_workspace(company)
        db_path = get_db_path(ws)

    episodic = EpisodicMemory(db_path)
    ctx = episodic.get_resume_context(mission_id)
    if not ctx["mission"]:
        console.print(f"  [red]✗  Mission {mission_id} not found[/red]")
        return
    console.print_json(json.dumps(ctx, indent=2, default=str))
    episodic.close()


# ── Intel Command ───────────────────────────────────────────────

@cli.command()
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--company", "-C", default="", help="Company name to find workspace")
def intel(mission_id, fmt, company):
    """View current intel store."""
    print_mini_banner()

    db_path = "output/missions.db"
    if company:
        ws = init_workspace(company)
        db_path = get_db_path(ws)

    store = IntelStore(db_path)
    data = store.export_json(mission_id)

    if fmt == "json":
        console.print_json(json.dumps(data, default=str))
    else:
        _display_intel_table(data)
    store.close()


# ── Endpoints Command ──────────────────────────────────────────────

@cli.command()
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--company", "-C", default="", help="Company name to find workspace")
@click.option("--limit", "-l", default=20, show_default=True, help="Maximum endpoints to show")
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
def endpoints(mission_id, company, limit, fmt):
    """View high-signal passive HTTP/API surfaces."""
    print_mini_banner()

    db_path = "output/missions.db"
    if company:
        ws = init_workspace(company)
        db_path = get_db_path(ws)

    store = IntelStore(db_path)
    rows = store.top_http_endpoints(mission_id, limit=limit)
    if fmt == "json":
        console.print_json(json.dumps(rows, default=str))
    elif not rows:
        console.print("  [dim]No HTTP/API inventory records found for this mission.[/dim]")
    else:
        _display_endpoint_table(rows)
    store.close()


# ── Gate Command ────────────────────────────────────────────────

@cli.command()
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--target", "-t", default="", help="Target (for context)")
@click.option("--company", "-C", default="", help="Company name to find workspace")
def gate(mission_id, target, company):
    """Evaluate stage gate — is recon complete enough?"""
    from reconforge.orchestrator.stage_gate import StageGate

    print_mini_banner()

    db_path = "output/missions.db"
    if company:
        ws = init_workspace(company)
        db_path = get_db_path(ws)

    store = IntelStore(db_path)
    summary = store.get_attack_surface_summary(mission_id)
    mission = MissionState(
        target=target or "unknown", scope=[target] if target else [],
        mission_name=f"Gate check: {mission_id}")

    stage_gate = StageGate()
    result = asyncio.run(stage_gate.evaluate(store, mission))
    store.close()

    status = "[bold green]PASSED ✅[/bold green]" if result.passed else "[bold red]FAILED ❌[/bold red]"
    console.print(Panel.fit(
        f"Stage Gate: {status}\n"
        f"Confidence: {result.confidence:.0%}\n"
        f"Reason: {result.reason}\n"
        f"Operator Approval Required: {result.requires_operator_approval}",
        title="[bold red]🚦 Stage Gate Evaluation[/bold red]",
        border_style="red"))

    if result.missing_coverage:
        console.print("\n  [yellow]Missing coverage:[/yellow]")
        for gap in result.missing_coverage:
            console.print(f"    ⚠ {gap}")

    # Show attack surface summary
    table = Table(
        title="[bold]Attack Surface[/bold]",
        box=box.ROUNDED,
        border_style="red",
    )
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")
    for key, val in summary.items():
        if key not in ("missing_coverage", "vulnerabilities_by_severity"):
            table.add_row(key.replace("_", " ").title(), str(val))
    console.print(table)


# ── Report Command ──────────────────────────────────────────────

@cli.command()
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--output", "-o", default="", help="Output path (auto-detected from workspace if --company)")
@click.option("--target", "-t", default="", help="Target name")
@click.option("--name", "-n", default="", help="Mission name")
@click.option("--company", "-C", default="", help="Company name to find workspace")
def report(mission_id, output, target, name, company):
    """Generate professional reconnaissance report."""
    from reconforge.report.generator import ReportGenerator

    print_mini_banner()
    console.print(f"  [bold red]⚔️  Generating report:[/bold red] [bold]{mission_id}[/bold]")

    db_path = "output/missions.db"
    if company:
        ws = init_workspace(company)
        db_path = get_db_path(ws)
        if not output:
            output = str(get_report_dir(ws) / f"report_{mission_id[:8]}.md")

    if not output:
        output = f"output/report_{mission_id[:8]}.md"

    store = IntelStore(db_path)
    episodic = EpisodicMemory(db_path)
    generator = ReportGenerator()

    report_content = asyncio.run(generator.generate(
        intel=store, mission_id=mission_id, output_path=output,
        mission_name=name, target=target, episodic=episodic))

    store.close()
    episodic.close()

    console.print(f"\n  [bold green]✓  Report generated:[/bold green] {output}")
    console.print(f"  [dim]{len(report_content)} characters written[/dim]")


# ── DB Commands ─────────────────────────────────────────────────

@cli.group()
def db():
    """Database management commands."""
    pass


@db.command("seed-cves")
@click.option("--nvd-feed", required=True, help="Path to NVD JSON feed file")
@click.option("--persist-dir", default="output/chromadb", help="ChromaDB directory")
def seed_cves(nvd_feed, persist_dir):
    """Seed the CVE database from an NVD JSON feed."""
    from reconforge.memory.semantic import SemanticMemory

    print_mini_banner()
    console.print(f"  [bold red]⚔️  Seeding CVEs:[/bold red] [dim]{nvd_feed}[/dim]")

    semantic = SemanticMemory(persist_dir=persist_dir)
    try:
        count = semantic.seed_cves(nvd_feed)
        console.print(f"\n  [bold green]✓  Seeded {count} CVEs into ChromaDB[/bold green]")
    except Exception as e:
        console.print(f"\n  [red]✗  Failed: {e}[/red]")


@db.command("stats")
@click.option("--persist-dir", default="output/chromadb", help="ChromaDB directory")
def db_stats(persist_dir):
    """Show ChromaDB collection statistics."""
    from reconforge.memory.semantic import SemanticMemory

    print_mini_banner()

    semantic = SemanticMemory(persist_dir=persist_dir)
    stats = semantic.get_collection_stats()
    table = Table(
        title="[bold]ChromaDB Collections[/bold]",
        box=box.ROUNDED,
        border_style="red",
    )
    table.add_column("Collection", style="cyan")
    table.add_column("Documents", style="bold")
    for name, count in stats.items():
        table.add_row(name, str(count))
    console.print(table)


# ── Display Helpers ─────────────────────────────────────────────

def _display_results(result: dict) -> None:
    """Display mission results with Rich."""
    console.print("\n")

    gate_passed = result.get("stage_gate", {}).get("passed")
    gate_str = "[bold green]✅ PASSED[/bold green]" if gate_passed else "[bold red]❌ NOT PASSED[/bold red]"

    console.print(Panel.fit(
        f"[bold red]AKAGAMI[/bold red] — Mission Complete\n\n"
        f"  Mission ID:  {result.get('mission_id', 'unknown')}\n"
        f"  Tasks:       {json.dumps(result.get('task_summary', {}))}\n"
        f"  Stage Gate:  {gate_str}",
        title="[bold red]📋 Results[/bold red]",
        border_style="red",
        box=box.HEAVY))

    surface = result.get("attack_surface", {})
    table = Table(
        title="[bold]Attack Surface Summary[/bold]",
        box=box.ROUNDED,
        border_style="red",
    )
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")
    for key, val in surface.items():
        if key != "missing_coverage":
            table.add_row(key.replace("_", " ").title(), str(val))
    console.print(table)

    missing = surface.get("missing_coverage", [])
    if missing:
        console.print("\n  [yellow]Missing coverage:[/yellow]")
        for gap in missing:
            console.print(f"    ⚠ {gap}")


def _display_intel_table(data: dict) -> None:
    """Display intel data as Rich tables."""
    for category, items in data.items():
        if not items:
            continue
        table = Table(
            title=f"[bold]{category.replace('_', ' ').title()}[/bold]",
            box=box.ROUNDED,
            border_style="red",
        )
        if items:
            for col in items[0].keys():
                if col not in ("raw_output", "data_json", "config_json"):
                    table.add_column(col, overflow="fold", max_width=40)
            for item in items[:50]:
                row = [str(item.get(col, ""))[:40]
                       for col in items[0].keys()
                       if col not in ("raw_output", "data_json", "config_json")]
                table.add_row(*row)
        console.print(table)
        console.print()


def _display_endpoint_table(rows: list[dict]) -> None:
    """Display high-signal HTTP/API surfaces."""
    table = Table(
        title="[bold red]High-Signal HTTP/API Surfaces[/bold red]",
        box=box.ROUNDED,
        border_style="red",
    )
    table.add_column("Score", justify="right", style="bold yellow")
    table.add_column("Method", style="cyan")
    table.add_column("Endpoint", style="bold")
    table.add_column("Why Interesting", overflow="fold", max_width=42)
    table.add_column("Manual Tests", overflow="fold", max_width=48)
    table.add_column("Source", style="magenta")
    table.add_column("Conf", justify="right")
    table.add_column("FP Risk", style="red")

    for row in rows:
        signals = _json_cell(row.get("interestingness_signals"))[:4]
        tests = _json_cell(row.get("recommended_manual_tests"))[:2]
        host = row.get("host", "")
        path = row.get("normalized_route") or row.get("path", "")
        table.add_row(
            f"{float(row.get('interestingness_score') or 0):.0f}",
            row.get("method", ""),
            f"{host}{path}",
            "; ".join(signals),
            "; ".join(tests),
            row.get("source", ""),
            f"{float(row.get('confidence') or 0):.0%}",
            row.get("false_positive_risk", "medium"),
        )
    console.print(table)


def _json_cell(value) -> list[str]:
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

@cli.command()
def watcher():
    """Start the Program Watcher daemon to monitor for new scopes."""
    from reconforge.watcher import ProgramWatcher
    from rich.console import Console
    import asyncio
    
    console = Console()
    console.print("[bold cyan]Starting Akagami Program Watcher daemon...[/bold cyan]")
    
    w = ProgramWatcher(check_interval_seconds=60)
    
    try:
        asyncio.run(w.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Watcher stopped by user.[/yellow]")


def main():
    cli()


if __name__ == "__main__":
    main()
