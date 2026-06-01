"""Tests for recon dry-run planning."""

import asyncio
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from reconforge import cli as cli_module
from reconforge import workspace as workspace_module
from reconforge.cli import cli
from reconforge.intel.models import MissionState
from reconforge.llm.router import LLMRouter
from reconforge.orchestrator.dry_run import build_recon_dry_run
from reconforge.tools.executor import ToolExecutor


def _write_mission_config(path, active=True):
    path.write_text(
        f"""
mission:
  mission_name: Dry Run Test

scope:
  in_scope:
    - example.com
  out_of_scope: []

permissions:
  active_scanning: {str(active).lower()}

opsec:
  enabled: false
""".lstrip()
    )


def test_recon_dry_run_prints_plan_without_tool_subprocess_or_llm(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=True)

    def fail_init_workspace(*args, **kwargs):
        raise AssertionError("dry-run must not initialize workspace files")

    subprocess_calls = []

    async def fail_subprocess(*cmd, **kwargs):
        subprocess_calls.append(cmd)
        raise AssertionError(f"subprocess called: {cmd}")

    tool_run = AsyncMock(side_effect=AssertionError("ToolExecutor.run called"))
    llm_call = AsyncMock(side_effect=AssertionError("LLMRouter.call called"))

    monkeypatch.setattr(cli_module, "init_workspace", fail_init_workspace)
    monkeypatch.setattr(
        cli_module,
        "get_workspace",
        lambda company_name: workspace_root / workspace_module.sanitize_name(company_name),
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fail_subprocess)
    monkeypatch.setattr(ToolExecutor, "run", tool_run)
    monkeypatch.setattr(LLMRouter, "call", llm_call)

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            "example.com",
            "-C",
            "Dry Co",
            "--active",
            "--dry-run",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert "Dry Run" in result.output
    assert "Mission" in result.output
    assert "Execution" in result.output
    assert "Safety Gate" in result.output
    assert "Scope" in result.output
    assert "Recon Plan" in result.output
    assert "Dry Run Guarantee" in result.output
    assert "Agents That Would Run" not in result.output
    assert "Tools That Would Be Requested" not in result.output
    assert "Active/Passive Risk" not in result.output
    assert "Scope Decisions" not in result.output
    assert "LLM API calls:" in result.output
    assert "External executions:" in result.output
    assert "nmap" in result.output
    assert "httpx" in result.output
    assert "ffuf" in result.output
    assert "nuclei" in result.output
    assert "akagami recon -t example.com -C 'Dry Co' --passive-only" in result.output
    assert "akagami report -m <mission-id> -C 'Dry Co' -t example.com" in result.output
    assert tool_run.await_count == 0
    assert llm_call.await_count == 0
    assert subprocess_calls == []
    assert not (workspace_root / "dry_co").exists()


def test_recon_dry_run_verbose_prints_plan_internals(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=True)

    def fail_init_workspace(*args, **kwargs):
        raise AssertionError("dry-run must not initialize workspace files")

    monkeypatch.setattr(cli_module, "init_workspace", fail_init_workspace)
    monkeypatch.setattr(
        cli_module,
        "get_workspace",
        lambda company_name: workspace_root / workspace_module.sanitize_name(company_name),
    )

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            "example.com",
            "-C",
            "Dry Co",
            "--active",
            "--dry-run",
            "--verbose",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert "Recon Plan" in result.output
    assert "Agents That Would Run" in result.output
    assert "Tools That Would Be Requested" in result.output
    assert "Active/Passive Risk" in result.output
    assert "Scope Decisions" in result.output


def test_recon_dry_run_does_not_modify_existing_workspace_files(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    company_dir = workspace_root / "dry_co"
    scope_dir = company_dir / "scope"
    scope_dir.mkdir(parents=True)
    in_scope = scope_dir / "in_scope.txt"
    in_scope.write_text("# IN-SCOPE targets - one per line\noriginal.example\n")
    _write_mission_config(config, active=True)

    def fail_init_workspace(*args, **kwargs):
        raise AssertionError("dry-run must not initialize workspace files")

    monkeypatch.setattr(cli_module, "init_workspace", fail_init_workspace)
    monkeypatch.setattr(
        cli_module,
        "get_workspace",
        lambda company_name: workspace_root / workspace_module.sanitize_name(company_name),
    )

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            "example.com",
            "-C",
            "Dry Co",
            "--active",
            "--dry-run",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert in_scope.read_text() == "# IN-SCOPE targets - one per line\noriginal.example\n"
    assert not (company_dir / "data" / "missions.db").exists()
    assert not (company_dir / "output" / "reports").exists()


@pytest.mark.parametrize(
    "target",
    [
        "example.com;id",
        "../../../etc/passwd",
        "example.com\nid",
        "`id`",
    ],
)
def test_recon_rejects_unsafe_targets_before_workspace_writes(target, tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=True)

    def fail_init_workspace(*args, **kwargs):
        raise AssertionError("unsafe target must be rejected before workspace init")

    monkeypatch.setattr(cli_module, "init_workspace", fail_init_workspace)
    monkeypatch.setattr(
        cli_module,
        "get_workspace",
        lambda company_name: workspace_root / workspace_module.sanitize_name(company_name),
    )

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            target,
            "-C",
            "Dry Co",
            "--active",
            "--dry-run",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code != 0
    assert "Invalid target" in result.output
    assert "Next Moves" not in result.output
    assert "Run passive mission" not in result.output
    assert not workspace_root.exists()


@pytest.mark.parametrize("target", ["example.com", "https://example.com"])
def test_recon_dry_run_accepts_normal_targets_without_workspace_writes(
    target, tmp_path, monkeypatch
):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=True)

    def fail_init_workspace(*args, **kwargs):
        raise AssertionError("dry-run must not initialize workspace files")

    monkeypatch.setattr(cli_module, "init_workspace", fail_init_workspace)
    monkeypatch.setattr(
        cli_module,
        "get_workspace",
        lambda company_name: workspace_root / workspace_module.sanitize_name(company_name),
    )

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            target,
            "-C",
            "Dry Co",
            "--active",
            "--dry-run",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert "Dry Run" in result.output
    assert not workspace_root.exists()


def test_localhost_requires_explicit_local_scope_policy(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=True)

    def fail_init_workspace(*args, **kwargs):
        raise AssertionError("local target must be rejected before workspace init")

    monkeypatch.setattr(cli_module, "init_workspace", fail_init_workspace)
    monkeypatch.setattr(
        cli_module,
        "get_workspace",
        lambda company_name: workspace_root / workspace_module.sanitize_name(company_name),
    )

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            "http://127.0.0.1:1",
            "-C",
            "Dry Co",
            "--active",
            "--dry-run",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code != 0
    assert "localhost/loopback targets require explicit local-lab policy" in result.output
    assert not workspace_root.exists()


def test_localhost_is_accepted_with_explicit_local_scope_policy(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    config.write_text(
        """
mission:
  mission_name: Local Dry Run Test

scope:
  in_scope:
    - 127.0.0.1
  out_of_scope: []

permissions:
  active_scanning: true

opsec:
  enabled: false
""".lstrip()
    )

    def fail_init_workspace(*args, **kwargs):
        raise AssertionError("dry-run must not initialize workspace files")

    monkeypatch.setattr(cli_module, "init_workspace", fail_init_workspace)
    monkeypatch.setattr(
        cli_module,
        "get_workspace",
        lambda company_name: workspace_root / workspace_module.sanitize_name(company_name),
    )

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            "http://127.0.0.1:1",
            "-C",
            "Local Lab",
            "--active",
            "--dry-run",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert "http://127.0.0.1:1" in result.output
    assert not workspace_root.exists()


def test_recon_dry_run_builder_reports_requested_tools_without_executor_run(monkeypatch):
    tool_run = AsyncMock(side_effect=AssertionError("ToolExecutor.run called"))
    monkeypatch.setattr(ToolExecutor, "run", tool_run)

    mission = MissionState(
        target="example.com",
        scope=["example.com"],
        active_scan_permitted=True,
    )

    result = build_recon_dry_run(mission, {"tools_config": "config/tools.yaml"})
    tools = {row["tool"]: row for row in result["tool_rows"]}

    assert "nmap" in tools
    assert "httpx" in tools
    assert "ffuf" in tools
    assert "nuclei" in tools
    assert tools["nmap"]["route"] == "subprocess"
    assert result["external_tools_executed"] == 0
    assert result["llm_calls"] == 0
    assert tool_run.await_count == 0


def test_recon_dry_run_scope_decisions_reject_out_of_scope_target():
    mission = MissionState(
        target="blocked.example.com",
        scope=["*.example.com"],
        out_of_scope=["blocked.example.com"],
        active_scan_permitted=True,
    )

    result = build_recon_dry_run(mission, {"tools_config": "config/tools.yaml"})

    assert result["planned_tasks"] == []
    assert result["rejected_tasks"]
    assert {row["status"] for row in result["scope_rows"]} == {"denied"}
