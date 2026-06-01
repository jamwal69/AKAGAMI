"""
Akagami CLI — Click entrypoint with Rich progress display.
Branded CLI for the multi-agent reconnaissance engine.
"""

import asyncio
import sys
from pathlib import Path

import click
import yaml

from reconforge.intel.models import MissionState
from reconforge.intel.store import IntelStore
from reconforge.llm.router import llm_disabled_by_env
from reconforge.memory.episodic import EpisodicMemory
from reconforge.orchestrator.dry_run import build_recon_dry_run
from reconforge.orchestrator.master import MasterOrchestrator
from reconforge.tools.scope import (
    is_target_in_scope,
    normalize_scope_host,
    target_is_local,
    validate_target,
)
from reconforge.workspace import (
    init_workspace, get_db_path, get_report_dir,
    list_workspaces, append_engagement_log, get_workspace,
)
from reconforge.utils.logger import set_global_level
from reconforge.ui.banner import (
    AKAGAMI_TAGLINE,
    format_help_banner,
    print_command_deck,
    print_mini_banner,
)
from reconforge.ui.console import (
    emit_json,
    get_console,
    mission_status,
    print_line,
    set_plain_mode,
    set_verbose_mode,
    use_plain_mode,
)
from reconforge.ui.panels import (
    print_approval_status,
    print_dry_run_boundary,
    print_dry_run_guarantee,
    print_gate_status,
    print_mission_complete,
    print_mission_start,
    print_quickstart,
    print_report_summary,
)
from reconforge.ui.tables import (
    print_attack_surface_summary,
    print_db_stats,
    print_doctor_checks,
    print_dry_run_tables,
    print_endpoint_table,
    print_intel_tables,
    print_tool_checks,
    print_workspaces,
)

CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 110,
}

console = get_console()


class AkagamiGroup(click.Group):
    """Top-level Click group that brands only the root help screen."""

    def parse_args(self, ctx, args):
        ctx.meta["akagami_plain_requested"] = "--plain" in args
        return super().parse_args(ctx, args)

    def format_help(self, ctx, formatter):
        if ctx.parent is None:
            formatter.write(
                format_help_banner(plain=_plain_help_requested(ctx)) + "\n\n"
            )
        super().format_help(ctx, formatter)


def _plain_help_requested(ctx) -> bool:
    params = getattr(ctx, "params", {}) or {}
    return (
        bool(params.get("plain"))
        or bool(ctx.meta.get("akagami_plain_requested"))
        or "--plain" in sys.argv[1:]
    )


def _run_coroutine(coro):
    """Run a coroutine from Click while preserving a default loop for tests."""
    try:
        return asyncio.run(coro)
    finally:
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())


# ── Config Loader ───────────────────────────────────────────────

def load_mission_config(config_path: str, target: str,
                        passive_only: bool = True,
                        opsec_mode: bool = False,
                        company: str = "",
                        mode: str = "standard",
                        create_workspace: bool = True,
                        no_llm: bool = False) -> tuple[MissionState, dict]:
    """Load mission config from YAML and create MissionState."""
    config = {}
    config_file = Path(config_path)
    if config_file.exists():
        with open(config_file) as f:
            config = yaml.safe_load(f) or {}
        config["_config_loaded"] = True
    else:
        config["_config_loaded"] = False
    config["_config_path"] = str(config_file)
    config["_no_llm"] = bool(no_llm or llm_disabled_by_env())

    mission_cfg = config.get("mission", {})
    scope_cfg = config.get("scope", {})
    perms_cfg = config.get("permissions", {})
    opsec_cfg = config.get("opsec", {})

    requested_target = target or mission_cfg.get("target", "")
    canonical_target = ""
    if requested_target:
        canonical_target = validate_target(
            requested_target,
            allow_local=_local_target_allowed_by_config(
                requested_target, scope_cfg, perms_cfg, mission_cfg)
        )

    in_scope = list(scope_cfg.get("in_scope") or ([canonical_target] if canonical_target else []))
    out_scope = list(scope_cfg.get("out_of_scope") or [])

    if canonical_target and canonical_target not in in_scope:
        in_scope.append(canonical_target)

    # ── Workspace scaffolding ─────────────────────────────────
    company_name = company or mission_cfg.get("company_name", "")
    workspace_dir = ""

    if company_name:
        ws = (
            init_workspace(company_name, in_scope=in_scope, out_of_scope=out_scope)
            if create_workspace else get_workspace(company_name)
        )
        workspace_dir = str(ws)
    else:
        # Fallback: derive company name from target domain
        if canonical_target:
            host = normalize_scope_host(canonical_target)
            domain_parts = host.replace("www.", "").split(".")
            company_name = domain_parts[0] if domain_parts else canonical_target
            ws = (
                init_workspace(company_name, in_scope=in_scope, out_of_scope=out_scope)
                if create_workspace else get_workspace(company_name)
            )
            workspace_dir = str(ws)

    mission = MissionState(
        target=canonical_target,
        mission_name=mission_cfg.get("mission_name", f"Recon: {canonical_target}"),
        company_name=company_name,
        workspace_dir=workspace_dir,
        scope=in_scope,
        out_of_scope=out_scope,
        active_scan_permitted=not passive_only and perms_cfg.get("active_scanning", False),
        opsec_mode=opsec_mode or opsec_cfg.get("enabled", False),
        mode=mode,
    )
    return mission, config


def _local_target_allowed_by_config(
    target: str,
    scope_cfg: dict,
    perms_cfg: dict,
    mission_cfg: dict,
) -> bool:
    """Localhost requires an explicit local-lab/dev policy or config scope."""
    if not target_is_local(target):
        return False
    explicit_flag = any(bool(mapping.get(key)) for mapping in (scope_cfg, perms_cfg, mission_cfg)
                        for key in ("allow_local_targets", "local_lab", "dev_mode"))
    if explicit_flag:
        return True
    configured_scope = list(scope_cfg.get("in_scope") or [])
    configured_out = list(scope_cfg.get("out_of_scope") or [])
    if not configured_scope:
        return False
    allowed, denied = is_target_in_scope(target, configured_scope, configured_out)
    return allowed and not denied


# ── CLI Group ───────────────────────────────────────────────────

@click.group(
    cls=AkagamiGroup,
    invoke_without_command=True,
    context_settings=CONTEXT_SETTINGS,
)
@click.option(
    "--plain",
    is_flag=True,
    help="Disable Rich styling and use line-oriented output for terminals/scripts.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed scope, dependency, and diagnostic presentation.",
)
@click.version_option(version="2.0.0", prog_name="Akagami")
@click.pass_context
def cli(ctx, plain, verbose):
    """Akagami - operator-grade reconnaissance command deck.

    Run without a command to open the command deck. Use --plain before the
    command when output must be colorless and easy to parse.
    """
    global console
    set_plain_mode(plain)
    set_verbose_mode(verbose)
    set_global_level("INFO" if verbose else "WARNING")
    console = get_console()
    if ctx.invoked_subcommand is None:
        print_command_deck()


# ── Quickstart Command ──────────────────────────────────────────

@cli.command(context_settings=CONTEXT_SETTINGS)
def quickstart():
    """Show the recommended passive-first beginner workflow."""
    print_mini_banner()
    print_quickstart()


# ── Recon Command ───────────────────────────────────────────────

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("--target", "-t", required=True, help="Target domain or IP inside authorized scope.")
@click.option("--company", "-C", default="", help="Company/program name. Creates or reuses its workspace.")
@click.option("--passive-only", is_flag=True, default=False, help="Force passive-only recon.")
@click.option("--active", is_flag=True, default=False, help="Request active scanning. Config permission is still required.")
@click.option("--opsec-mode", is_flag=True, default=False, help="Enable OPSEC controls from supported components.")
@click.option("--dry-run", is_flag=True, default=False, help="Build the mission plan without tools, LLM calls, or runtime writes.")
@click.option("--no-llm", is_flag=True, default=False, help="Run deterministic parsers and heuristic fallbacks without LLM providers.")
@click.option("--config", "-c", default="config/mission.yaml", help="Mission config path.")
@click.option("--mode", type=click.Choice(["standard", "bug-bounty"]), default="standard", help="Mission execution mode.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show dry-run dependencies, scope decisions, and requested tool internals.")
def recon(target, company, passive_only, active, opsec_mode, dry_run, no_llm, config, mode, verbose):
    """Start a reconnaissance mission or show a local-only dry-run briefing."""
    if verbose:
        set_verbose_mode(True)
        set_global_level("INFO")
    print_mini_banner()

    try:
        mission, cfg = load_mission_config(
            config, target,
            passive_only=passive_only or not active,
            opsec_mode=opsec_mode,
            company=company,
            mode=mode,
            create_workspace=not dry_run,
            no_llm=no_llm)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    active_requested = active and not passive_only

    if dry_run:
        dry_run_result = build_recon_dry_run(mission, cfg)
        _display_dry_run(dry_run_result)
        return

    print_mission_start(
        mission,
        target=mission.target,
        active_requested=active_requested,
        dry_run=dry_run,
    )

    # Use company-specific database
    if mission.workspace_dir:
        db_path = get_db_path(Path(mission.workspace_dir))
        cfg["_db_path"] = db_path
        append_engagement_log(
            Path(mission.workspace_dir),
            f"Mission started: {mission.mission_id} → {mission.target}")

    orchestrator = MasterOrchestrator(mission, cfg)
    try:
        with mission_status("[bold cyan]Mission running[/bold cyan] [dim]agents coordinating[/dim]"):
            result = _run_coroutine(orchestrator.run())
        _display_results(
            result,
            target=mission.target,
            company=mission.company_name,
        )

        # Log completion
        if mission.workspace_dir:
            gate = "PASSED" if result.get("stage_gate", {}).get("passed") else "FAILED"
            append_engagement_log(
                Path(mission.workspace_dir),
                f"Mission completed: {mission.mission_id} | Gate: {gate}")
    except KeyboardInterrupt:
        print_line("\nMission interrupted by operator.")
    except Exception as e:
        print_line(f"\nMission failed: {e}")
        raise
    finally:
        orchestrator.cleanup()


# ── Workspaces Command ──────────────────────────────────────────

@cli.command(context_settings=CONTEXT_SETTINGS)
def workspaces():
    """List all company workspaces."""
    print_mini_banner()
    print_workspaces(list_workspaces())


# ── Resume Command ──────────────────────────────────────────────

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--company", "-C", default="", help="Company name to find workspace")
def resume(mission_id, company):
    """Print saved mission context as JSON. This does not restart execution."""
    db_path = "output/missions.db"
    if company:
        ws = init_workspace(company)
        db_path = get_db_path(ws)

    episodic = EpisodicMemory(db_path)
    try:
        ctx = episodic.get_resume_context(mission_id)
        if not ctx["mission"]:
            print_mini_banner()
            console.print(f"  [red]✗  Mission {mission_id} not found[/red]")
            return
        emit_json(ctx)
    finally:
        episodic.close()


# ── Operator Approval Commands ─────────────────────────────────

@cli.command("approval-status", context_settings=CONTEXT_SETTINGS)
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--company", "-C", required=True, help="Company name to find workspace")
def approval_status(mission_id, company):
    """Show stage-gate and exploit-planning approval status."""
    print_mini_banner()

    db_path = get_db_path(get_workspace(company))
    if not Path(db_path).exists():
        console.print(f"  [red]✗  Mission {mission_id} not found for {company}[/red]")
        return

    episodic = EpisodicMemory(db_path)
    try:
        status = episodic.get_approval_status(mission_id)
    finally:
        episodic.close()

    if not status:
        console.print(f"  [red]✗  Mission {mission_id} not found for {company}[/red]")
        return

    _display_approval_status(status)


@cli.command("approve", context_settings=CONTEXT_SETTINGS)
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--company", "-C", required=True, help="Company name to find workspace")
def approve(mission_id, company):
    """Record operator approval for exploit planning after stage gate."""
    print_mini_banner()

    db_path = get_db_path(get_workspace(company))
    if not Path(db_path).exists():
        console.print(f"  [red]✗  Mission {mission_id} not found for {company}[/red]")
        return

    episodic = EpisodicMemory(db_path)
    try:
        if not episodic.approve_mission(mission_id):
            console.print(f"  [red]✗  Mission {mission_id} not found for {company}[/red]")
            return
        status = episodic.get_approval_status(mission_id)
    finally:
        episodic.close()

    if use_plain_mode():
        print_line("Operator approval recorded. No exploit planning was executed.")
        print_line()
    else:
        console.print(
            "  [bold green]Operator approval recorded.[/bold green] "
            "[dim]No exploit planning was executed.[/dim]\n"
        )
    _display_approval_status(status)


# ── Intel Command ───────────────────────────────────────────────

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--company", "-C", default="", help="Company name to find workspace")
def intel(mission_id, fmt, company):
    """View current intel store."""
    db_path = "output/missions.db"
    if company:
        ws = init_workspace(company)
        db_path = get_db_path(ws)

    store = IntelStore(db_path)
    try:
        data = store.export_json(mission_id)
        if fmt == "json":
            emit_json(data)
        else:
            print_mini_banner()
            _display_intel_table(data)
    finally:
        store.close()


# ── Endpoints Command ──────────────────────────────────────────────

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--company", "-C", default="", help="Company name to find workspace")
@click.option("--limit", "-l", default=20, show_default=True, help="Maximum endpoints to show")
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
def endpoints(mission_id, company, limit, fmt):
    """View high-signal passive HTTP/API surfaces."""
    db_path = "output/missions.db"
    if company:
        ws = init_workspace(company)
        db_path = get_db_path(ws)

    store = IntelStore(db_path)
    try:
        rows = store.top_http_endpoints(mission_id, limit=limit)
        if fmt == "json":
            emit_json(rows)
        else:
            print_mini_banner()
            _display_endpoint_table(rows, mission_id=mission_id, company=company)
    finally:
        store.close()


# ── Gate Command ────────────────────────────────────────────────

@cli.command(context_settings=CONTEXT_SETTINGS)
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
    result = _run_coroutine(stage_gate.evaluate(store, mission))
    episodic = EpisodicMemory(db_path)
    try:
        episodic.update_mission_control(
            mission_id,
            stage_gate_passed=bool(result.passed),
            stage_gate=result.model_dump(),
        )
    finally:
        episodic.close()
    store.close()

    print_gate_status(result, summary)
    print_attack_surface_summary(summary, title="Attack Surface")


# ── Report Command ──────────────────────────────────────────────

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("--mission-id", "-m", required=True, help="Mission ID")
@click.option("--output", "-o", default="", help="Output path (auto-detected from workspace if --company)")
@click.option("--target", "-t", default="", help="Target name")
@click.option("--name", "-n", default="", help="Mission name")
@click.option("--company", "-C", default="", help="Company name to find workspace")
def report(mission_id, output, target, name, company):
    """Generate professional reconnaissance report."""
    from reconforge.report.generator import ReportGenerator

    print_mini_banner()
    if use_plain_mode():
        print_line(f"Generating report: {mission_id}")
    else:
        console.print(f"  [bold cyan]Generating report:[/bold cyan] [bold]{mission_id}[/bold]")

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

    with mission_status("[bold cyan]Rendering report[/bold cyan] [dim]collecting stored intel[/dim]"):
        report_content = _run_coroutine(generator.generate(
            intel=store, mission_id=mission_id, output_path=output,
            mission_name=name, target=target, episodic=episodic))

    store.close()
    episodic.close()

    print_report_summary(
        mission_id=mission_id,
        output=output,
        character_count=len(report_content),
        target=target,
        company=company,
    )


# ── Tool Diagnostics Commands ──────────────────────────────────

@cli.group(context_settings=CONTEXT_SETTINGS)
def tools():
    """Toolchain diagnostics that never run scans or contact targets."""
    pass


@tools.command("check", context_settings=CONTEXT_SETTINGS)
@click.option("--config", "config_path", default="config/tools.yaml",
              help="Tools config path")
def tools_check(config_path):
    """Show configured external binary availability."""
    from reconforge.diagnostics import check_configured_tools

    print_mini_banner()
    _display_tool_checks(check_configured_tools(config_path))


@tools.command("doctor", context_settings=CONTEXT_SETTINGS)
@click.option("--config", "config_path", default="config/tools.yaml",
              help="Tools config path")
@click.option("--workspace-root", default="workspace",
              help="Workspace directory to check")
def tools_doctor(config_path, workspace_root):
    """Run local diagnostics without scans, targets, or API calls."""
    from reconforge.diagnostics import doctor_checks

    print_mini_banner()
    checks = doctor_checks(
        config_path=config_path,
        workspace_root=workspace_root,
    )
    print_doctor_checks(checks)


# ── DB Commands ─────────────────────────────────────────────────

@cli.group(context_settings=CONTEXT_SETTINGS)
def db():
    """Database management commands."""
    pass


@db.command("seed-cves", context_settings=CONTEXT_SETTINGS)
@click.option("--nvd-feed", required=True, help="Path to NVD JSON feed file")
@click.option("--persist-dir", default="output/chromadb", help="ChromaDB directory")
def seed_cves(nvd_feed, persist_dir):
    """Seed the CVE database from an NVD JSON feed."""
    from reconforge.memory.semantic import SemanticMemory

    print_mini_banner()
    if use_plain_mode():
        print_line(f"Seeding CVEs: {nvd_feed}")
    else:
        console.print(f"  [bold red]Seeding CVEs:[/bold red] [dim]{nvd_feed}[/dim]")

    semantic = SemanticMemory(persist_dir=persist_dir)
    try:
        count = semantic.seed_cves(nvd_feed)
        print_line(f"\nSeeded {count} CVEs into ChromaDB")
    except Exception as e:
        print_line(f"\nFailed: {e}")


@db.command("stats", context_settings=CONTEXT_SETTINGS)
@click.option("--persist-dir", default="output/chromadb", help="ChromaDB directory")
def db_stats(persist_dir):
    """Show ChromaDB collection statistics."""
    from reconforge.memory.semantic import SemanticMemory

    print_mini_banner()

    semantic = SemanticMemory(persist_dir=persist_dir)
    stats = semantic.get_collection_stats()
    print_db_stats(stats)


# ── Display Helpers ─────────────────────────────────────────────

def _display_tool_checks(rows: list[dict],
                         title: str = "External Tools") -> None:
    """Display configured tool binary availability."""
    print_tool_checks(rows, title=title)


def _display_results(result: dict, *, target: str = "", company: str = "") -> None:
    """Display mission results with Rich."""
    print_line()
    print_mission_complete(result, target=target, company=company)
    print_attack_surface_summary(
        result.get("attack_surface", {}),
        title="Attack Surface Summary",
    )


def _display_approval_status(status: dict | None) -> None:
    print_approval_status(status)


def _display_dry_run(result: dict) -> None:
    """Display a safe local-only recon plan."""
    print_dry_run_boundary(result)
    print_dry_run_tables(result)
    print_dry_run_guarantee(result)


def _display_intel_table(data: dict) -> None:
    """Display intel data as Rich tables."""
    print_intel_tables(data)


def _display_endpoint_table(
    rows: list[dict],
    *,
    mission_id: str = "<mission-id>",
    company: str = "",
) -> None:
    """Display high-signal HTTP/API surfaces."""
    print_endpoint_table(rows, mission_id=mission_id, company=company)

@cli.command(context_settings=CONTEXT_SETTINGS)
def watcher():
    """Start the Program Watcher daemon to monitor for new scopes."""
    from reconforge.watcher import ProgramWatcher
    from reconforge.ui.badges import badge

    print_mini_banner()
    console.print(f"{badge('EXPERIMENTAL')} [bold cyan]Starting Akagami Program Watcher daemon...[/bold cyan]")

    w = ProgramWatcher(check_interval_seconds=60)

    try:
        _run_coroutine(w.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Watcher stopped by user.[/yellow]")


def main():
    cli()


if __name__ == "__main__":
    main()
