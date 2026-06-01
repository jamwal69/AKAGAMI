"""CLI presentation behavior tests."""

import json

from click.testing import CliRunner

from reconforge import cli as cli_module
from reconforge import diagnostics
from reconforge import workspace as workspace_module
from reconforge.report import generator as report_module
from reconforge.cli import cli


def _write_mission_config(path, active=True):
    path.write_text(
        f"""
mission:
  mission_name: UX Test

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


def test_help_still_works():
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "AKAGAMI / 赤髪" in result.output
    assert "Red Moon Operator Command Deck" in result.output
    assert "passive-first" in result.output
    assert "Authorized security testing only. Scope first. Exploitation requires approval." in result.output
    assert "Akagami" in result.output
    assert "Commands:" in result.output
    assert "quickstart" in result.output
    assert "recon" in result.output


def test_plain_help_skips_heavy_ascii_art():
    result = CliRunner().invoke(cli, ["--plain", "--help"])

    assert result.exit_code == 0
    assert "AKAGAMI / 赤髪" in result.output
    assert "___    __ __" not in result.output
    assert "\x1b[" not in result.output


def test_plain_command_deck_is_line_oriented():
    result = CliRunner().invoke(cli, ["--plain"])

    assert result.exit_code == 0
    assert "AKAGAMI" in result.output
    assert "Usage: akagami [--plain] <command> [options]" in result.output
    assert "╭" not in result.output


def test_quickstart_command_shows_beginner_workflow():
    result = CliRunner().invoke(cli, ["quickstart"])

    assert result.exit_code == 0
    assert "Quickstart" in result.output
    assert "akagami tools doctor" in result.output
    assert "akagami recon -t example.com -C Example --passive-only --dry-run" in result.output
    assert "akagami recon -t example.com -C Example --passive-only" in result.output
    assert "akagami endpoints -m <mission-id> -C Example" in result.output
    assert "akagami report -m <mission-id> -C Example -t example.com" in result.output


def test_quickstart_plain_and_no_color_have_no_ansi(monkeypatch):
    plain = CliRunner().invoke(cli, ["--plain", "quickstart"])

    assert plain.exit_code == 0
    assert "\x1b[" not in plain.output
    assert "╭" not in plain.output

    monkeypatch.setenv("NO_COLOR", "1")
    no_color = CliRunner().invoke(cli, ["quickstart"])

    assert no_color.exit_code == 0
    assert "\x1b[" not in no_color.output


def test_plain_recon_dry_run_keeps_core_sections_without_rich_boxes(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=True)

    def init_workspace_in_tmp(company_name, in_scope=None, out_of_scope=None):
        return workspace_module.init_workspace(
            company_name,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            root=workspace_root,
        )

    monkeypatch.setattr(cli_module, "init_workspace", init_workspace_in_tmp)

    result = CliRunner().invoke(
        cli,
        [
            "--plain",
            "recon",
            "-t",
            "example.com",
            "-C",
            "UX Co",
            "--active",
            "--dry-run",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert "AKAGAMI v2.0.0 > Recon Command Deck" in result.output
    assert "Mission:" in result.output
    assert "Execution:" in result.output
    assert "Safety Gate:" in result.output
    assert "Scope:" in result.output
    assert "Recon Plan:" in result.output
    assert "Dry Run Guarantee:" in result.output
    assert "[APPROVED] permitted by config" in result.output
    assert "Tools That Would Be Requested:" not in result.output
    assert "\x1b[" not in result.output
    assert "╭" not in result.output


def test_json_intel_output_has_no_banner_or_rich_markup(monkeypatch):
    class FakeStore:
        def __init__(self, db_path):
            self.db_path = db_path

        def export_json(self, mission_id):
            return {"hosts": [{"mission_id": mission_id, "hostname": "api.example.com"}]}

        def close(self):
            pass

    monkeypatch.setattr(cli_module, "IntelStore", FakeStore)

    result = CliRunner().invoke(cli, ["intel", "-m", "mission-ux", "-f", "json"])

    assert result.exit_code == 0
    assert json.loads(result.output) == {
        "hosts": [{"mission_id": "mission-ux", "hostname": "api.example.com"}]
    }
    assert "AKAGAMI" not in result.output
    assert "╭" not in result.output


def test_json_endpoint_output_is_unchanged(monkeypatch):
    endpoint_rows = [
        {
            "mission_id": "mission-ux",
            "method": "POST",
            "host": "api.example.com",
            "normalized_route": "/login",
            "interestingness_score": 90,
            "auth_required": "anonymous",
        }
    ]

    class FakeStore:
        def __init__(self, db_path):
            self.db_path = db_path

        def top_http_endpoints(self, mission_id, limit=20):
            assert mission_id == "mission-ux"
            assert limit == 20
            return endpoint_rows

        def close(self):
            pass

    monkeypatch.setattr(cli_module, "IntelStore", FakeStore)

    result = CliRunner().invoke(cli, ["endpoints", "-m", "mission-ux", "-f", "json"])

    assert result.exit_code == 0
    assert json.loads(result.output) == endpoint_rows
    assert "AKAGAMI" not in result.output
    assert "╭" not in result.output


def test_empty_endpoints_output_recommends_next_moves(tmp_path, monkeypatch):
    workspace_root = tmp_path / "workspace"

    def init_workspace_in_tmp(company_name, in_scope=None, out_of_scope=None):
        return workspace_module.init_workspace(
            company_name,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            root=workspace_root,
        )

    class FakeStore:
        def __init__(self, db_path):
            self.db_path = db_path

        def top_http_endpoints(self, mission_id, limit=20):
            assert mission_id == "mission-ux"
            return []

        def close(self):
            pass

    monkeypatch.setattr(cli_module, "init_workspace", init_workspace_in_tmp)
    monkeypatch.setattr(cli_module, "IntelStore", FakeStore)

    result = CliRunner().invoke(cli, ["endpoints", "-m", "mission-ux", "-C", "UX Co"])

    assert result.exit_code == 0
    assert "No HTTP/API inventory records found for this mission." in result.output
    assert "Next Moves" in result.output
    assert "akagami intel -m mission-ux -C 'UX Co'" in result.output
    assert "akagami recon -t <target> -C 'UX Co' --passive-only --dry-run" in result.output


def test_no_color_dry_run_has_no_ansi_codes(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=False)
    monkeypatch.setenv("NO_COLOR", "1")

    def init_workspace_in_tmp(company_name, in_scope=None, out_of_scope=None):
        return workspace_module.init_workspace(
            company_name,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            root=workspace_root,
        )

    monkeypatch.setattr(cli_module, "init_workspace", init_workspace_in_tmp)

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            "example.com",
            "-C",
            "UX Co",
            "--dry-run",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert "Mission" in result.output
    assert "\x1b[" not in result.output


def test_tools_check_uses_compatibility_status_badges(tmp_path, monkeypatch):
    config = tmp_path / "tools.yaml"
    config.write_text(
        """
tools:
  whois:
    binary: whois
    category: passive-osint
    opsec_risk: passive
    required: true
  nuclei:
    binary: nuclei
    category: active-recon
    opsec_risk: high
""".lstrip()
    )
    monkeypatch.setattr(
        diagnostics.shutil,
        "which",
        lambda binary: "/usr/bin/whois" if binary == "whois" else None,
    )

    result = CliRunner().invoke(cli, ["tools", "check", "--config", str(config)])

    assert result.exit_code == 0
    assert "FOUND" in result.output
    assert "MISSING" in result.output
    assert "PASSIVE" in result.output
    assert "HIGH" in result.output
    assert "External Tools" in result.output


def test_mission_completion_summary_recommends_next_commands(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=False)

    def init_workspace_in_tmp(company_name, in_scope=None, out_of_scope=None):
        return workspace_module.init_workspace(
            company_name,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            root=workspace_root,
        )

    class FakeOrchestrator:
        def __init__(self, mission, cfg):
            self.mission = mission

        async def run(self):
            return {
                "mission_id": self.mission.mission_id,
                "stage_gate": {"passed": True},
                "task_summary": {"completed": 1},
                "attack_surface": {"hosts": 1, "missing_coverage": []},
            }

        def cleanup(self):
            pass

    monkeypatch.setattr(cli_module, "init_workspace", init_workspace_in_tmp)
    monkeypatch.setattr(cli_module, "MasterOrchestrator", FakeOrchestrator)

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            "example.com",
            "-C",
            "UX Co",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert "Mission Complete" in result.output
    assert "Next Moves" in result.output
    assert "Recommended next commands" in result.output
    assert "akagami endpoints -m" in result.output
    assert "akagami report -m" in result.output


def test_recon_no_llm_option_marks_config_offline(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=False)
    captured = {}

    def init_workspace_in_tmp(company_name, in_scope=None, out_of_scope=None):
        return workspace_module.init_workspace(
            company_name,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            root=workspace_root,
        )

    class FakeOrchestrator:
        def __init__(self, mission, cfg):
            captured["cfg"] = cfg
            self.mission = mission

        async def run(self):
            return {
                "mission_id": self.mission.mission_id,
                "stage_gate": {"passed": False},
                "task_summary": {"completed": 0},
                "attack_surface": {"hosts": 0, "missing_coverage": []},
                "report_path": None,
            }

        def cleanup(self):
            pass

    monkeypatch.setattr(cli_module, "init_workspace", init_workspace_in_tmp)
    monkeypatch.setattr(cli_module, "MasterOrchestrator", FakeOrchestrator)

    result = CliRunner().invoke(
        cli,
        [
            "recon",
            "-t",
            "example.com",
            "-C",
            "UX Co",
            "--no-llm",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert captured["cfg"]["_no_llm"] is True


def test_report_generation_recommends_next_moves(tmp_path, monkeypatch):
    workspace_root = tmp_path / "workspace"

    def init_workspace_in_tmp(company_name, in_scope=None, out_of_scope=None):
        return workspace_module.init_workspace(
            company_name,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            root=workspace_root,
        )

    class FakeStore:
        def __init__(self, db_path):
            self.db_path = db_path

        def close(self):
            pass

    class FakeMemory:
        def __init__(self, db_path):
            self.db_path = db_path

        def close(self):
            pass

    class FakeGenerator:
        async def generate(self, intel, mission_id, output_path, mission_name="", target="", episodic=None):
            assert mission_id == "mission-ux"
            assert target == "example.com"
            return "report body"

    monkeypatch.setattr(cli_module, "init_workspace", init_workspace_in_tmp)
    monkeypatch.setattr(cli_module, "IntelStore", FakeStore)
    monkeypatch.setattr(cli_module, "EpisodicMemory", FakeMemory)
    monkeypatch.setattr(report_module, "ReportGenerator", FakeGenerator)

    result = CliRunner().invoke(
        cli,
        ["report", "-m", "mission-ux", "-C", "UX Co", "-t", "example.com"],
    )

    assert result.exit_code == 0
    assert "Report Generated" in result.output
    assert "Next Moves" in result.output
    assert "akagami endpoints -m mission-ux -C 'UX Co'" in result.output
    assert "akagami approval-status -m mission-ux -C 'UX Co'" in result.output
