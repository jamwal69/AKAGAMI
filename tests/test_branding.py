"""AKAGAMI branding integration tests."""

import asyncio
from importlib.resources import files

from click.testing import CliRunner

from reconforge import cli as cli_module
from reconforge import diagnostics
from reconforge import workspace as workspace_module
from reconforge.cli import cli
from reconforge.intel.store import IntelStore
from reconforge.report.generator import ReportGenerator


def _write_mission_config(path, active=False):
    path.write_text(
        f"""
mission:
  mission_name: Branding Test

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


def _write_tools_config(path):
    path.write_text(
        """
tools:
  whois:
    binary: whois
    category: passive-osint
    opsec_risk: passive
    required: true
""".lstrip()
    )


def _run_async(coro):
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def test_brand_assets_are_package_loadable():
    brand_root = files("reconforge.assets.brand")

    for filename in ("akagami-logo.png", "akagami-mark.png"):
        resource = brand_root.joinpath(filename)
        assert resource.is_file()
        assert resource.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")


def test_report_generation_copies_brand_assets_next_to_report(tmp_path):
    db_path = tmp_path / "missions.db"
    report_path = tmp_path / "report.md"
    store = IntelStore(str(db_path))
    generator = ReportGenerator()

    try:
        report = _run_async(
            generator.generate(
                store,
                "brand-report",
                output_path=str(report_path),
                target="example.com",
                mission_name="Brand Report",
            )
        )
    finally:
        store.close()

    assert report_path.exists()
    assert "AKAGAMI Reconnaissance Report" in report
    assert "assets/akagami-logo.png" in report
    assert "assets/akagami-mark.png" in report
    assert (tmp_path / "assets" / "akagami-logo.png").read_bytes().startswith(
        b"\x89PNG\r\n\x1a\n"
    )
    assert (tmp_path / "assets" / "akagami-mark.png").read_bytes().startswith(
        b"\x89PNG\r\n\x1a\n"
    )


def test_report_template_includes_brand_header_references():
    template = files("reconforge.report.templates").joinpath(
        "recon_report.md.j2"
    ).read_text(encoding="utf-8")

    assert "AKAGAMI Reconnaissance Report" in template
    assert "{{ brand.logo_path }}" in template
    assert "{{ brand.mark_path }}" in template


def test_cli_brand_headers_for_help_dry_run_and_tools(tmp_path, monkeypatch):
    config = tmp_path / "mission.yaml"
    tools_config = tmp_path / "tools.yaml"
    workspace_root = tmp_path / "workspace"
    _write_mission_config(config, active=False)
    _write_tools_config(tools_config)

    def init_workspace_in_tmp(company_name, in_scope=None, out_of_scope=None):
        return workspace_module.init_workspace(
            company_name,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            root=workspace_root,
        )

    monkeypatch.setattr(cli_module, "init_workspace", init_workspace_in_tmp)
    monkeypatch.setattr(diagnostics.shutil, "which", lambda binary: None)
    monkeypatch.setattr(
        diagnostics,
        "check_playwright_chromium",
        lambda: {
            "name": "Playwright chromium",
            "ok": True,
            "detail": "/tmp/chromium",
        },
    )

    runner = CliRunner()
    help_result = runner.invoke(cli, ["--help"])
    dry_run_result = runner.invoke(
        cli,
        [
            "recon",
            "-t",
            "example.com",
            "-C",
            "Brand Co",
            "--dry-run",
            "-c",
            str(config),
        ],
    )
    check_result = runner.invoke(
        cli,
        ["tools", "check", "--config", str(tools_config)],
    )
    doctor_result = runner.invoke(
        cli,
        [
            "tools",
            "doctor",
            "--config",
            str(tools_config),
            "--workspace-root",
            str(workspace_root),
        ],
    )

    for result in (help_result, dry_run_result, check_result, doctor_result):
        assert result.exit_code == 0
        assert "AKAGAMI" in result.output

    assert "Red Moon Operator Command Deck" in help_result.output
    assert "Recon Command Deck" in dry_run_result.output
    assert "Recon Command Deck" in check_result.output
    assert "Recon Command Deck" in doctor_result.output


def test_no_color_brand_header_has_no_ansi_codes(tmp_path, monkeypatch):
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
            "Brand Co",
            "--dry-run",
            "-c",
            str(config),
        ],
    )

    assert result.exit_code == 0
    assert "AKAGAMI" in result.output
    assert "\x1b[" not in result.output
