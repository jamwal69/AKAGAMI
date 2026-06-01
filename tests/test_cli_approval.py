"""CLI tests for operator approval workflow."""

from click.testing import CliRunner

from reconforge import cli as cli_module
from reconforge import workspace as workspace_module
from reconforge.agents.exploit_planner import ExploitPlannerAgent
from reconforge.cli import cli
from reconforge.intel.models import GateResult
from reconforge.memory.episodic import EpisodicMemory
from reconforge.ui.console import set_plain_mode
from reconforge.ui.panels import print_gate_status
from reconforge.workspace import get_db_path


def _seed_mission(tmp_path, monkeypatch, gate_passed=True):
    workspace_root = tmp_path / "workspace"
    company_dir = workspace_module.init_workspace(
        "Acme Corp",
        in_scope=["example.com"],
        root=workspace_root,
    )
    monkeypatch.setattr(cli_module, "get_workspace", lambda company: company_dir)

    mem = EpisodicMemory(get_db_path(company_dir))
    gate = GateResult(
        passed=gate_passed,
        confidence=0.9 if gate_passed else 0.2,
        reason="coverage sufficient" if gate_passed else "missing coverage",
        requires_operator_approval=True,
    )
    mem.create_mission("mission-1", "example.com")
    mem.update_mission_control(
        "mission-1",
        stage_gate_passed=gate_passed,
        stage_gate=gate.model_dump(),
    )
    mem.close()
    return company_dir


def test_approval_status_shows_gate_and_operator_state(tmp_path, monkeypatch):
    _seed_mission(tmp_path, monkeypatch, gate_passed=True)

    result = CliRunner().invoke(
        cli,
        ["approval-status", "-m", "mission-1", "-C", "Acme Corp"],
    )

    assert result.exit_code == 0
    assert "Escalation Checkpoint" in result.output
    assert "Stage Gate:" in result.output
    assert "PASSED" in result.output
    assert "Operator Approval:" in result.output
    assert "Exploit Planning:" in result.output
    assert "APPROVED" in result.output
    assert "REQUIRED" in result.output


def test_approve_sets_operator_approval_without_running_exploit_planning(
    tmp_path,
    monkeypatch,
):
    company_dir = _seed_mission(tmp_path, monkeypatch, gate_passed=True)
    unlock_calls = []
    monkeypatch.setattr(
        ExploitPlannerAgent,
        "unlock",
        classmethod(lambda cls: unlock_calls.append(True)),
    )

    result = CliRunner().invoke(
        cli,
        ["approve", "-m", "mission-1", "-C", "Acme Corp"],
    )

    assert result.exit_code == 0
    assert "Operator approval recorded" in result.output
    assert "No exploit planning was executed" in result.output
    assert unlock_calls == []

    mem = EpisodicMemory(get_db_path(company_dir))
    status = mem.get_approval_status("mission-1")
    actions = mem.get_recent_actions("mission-1")
    mem.close()

    assert status["operator_approved"] is True
    assert status["exploit_planning_approved"] is True
    assert actions == []


def test_approve_before_stage_gate_does_not_approve_exploit_planning(
    tmp_path,
    monkeypatch,
):
    company_dir = _seed_mission(tmp_path, monkeypatch, gate_passed=False)

    result = CliRunner().invoke(
        cli,
        ["approve", "-m", "mission-1", "-C", "Acme Corp"],
    )

    assert result.exit_code == 0
    mem = EpisodicMemory(get_db_path(company_dir))
    status = mem.get_approval_status("mission-1")
    mem.close()

    assert status["operator_approved"] is True
    assert status["stage_gate_passed"] is False
    assert status["exploit_planning_approved"] is False


def test_gate_status_renderer_shows_clear_checkpoint_status(capsys):
    result = GateResult(
        passed=False,
        confidence=0.4,
        reason="missing coverage",
        requires_operator_approval=True,
    )

    try:
        set_plain_mode(True)
        print_gate_status(result, {})
        output = capsys.readouterr().out
    finally:
        set_plain_mode(False)

    assert "Escalation Checkpoint" in output
    assert "BLOCKED" in output
    assert "REQUIRED" in output
