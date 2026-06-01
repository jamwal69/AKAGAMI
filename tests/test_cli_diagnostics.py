"""CLI diagnostics tests."""

import subprocess

from click.testing import CliRunner

from reconforge import diagnostics
from reconforge.cli import cli


def _write_tools_config(path):
    path.write_text(
        """
tools:
  whois:
    binary: whois
    category: passive-osint
    opsec_risk: passive
    required: true
  nmap:
    binary: nmap
    opsec_risk: medium
""".lstrip()
    )


def test_tools_check_reports_configured_binary_status(tmp_path, monkeypatch):
    config = tmp_path / "tools.yaml"
    _write_tools_config(config)

    def fake_which(binary):
        return {"whois": "/bin/w"}.get(binary)

    monkeypatch.setattr(diagnostics.shutil, "which", fake_which)

    result = CliRunner().invoke(cli, ["tools", "check", "--config", str(config)])

    assert result.exit_code == 0
    assert "External Tools" in result.output
    assert "whois" in result.output
    assert "/bin/w" in result.output
    assert "nmap" in result.output
    assert "passive-osint" in result.output
    assert "passive" in result.output
    assert "medium" in result.output


def test_doctor_reports_env_presence_without_values(tmp_path, monkeypatch):
    config = tmp_path / "tools.yaml"
    workspace = tmp_path / "workspace"
    _write_tools_config(config)

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
    monkeypatch.setenv("GROQ_API_KEY", "secret-groq-value")
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)

    result = CliRunner().invoke(
        cli,
        [
            "tools",
            "doctor",
            "--config",
            str(config),
            "--workspace-root",
            str(workspace),
        ],
    )

    assert result.exit_code == 0
    assert "Runtime" in result.output
    assert "Package Resources" in result.output
    assert "External Tools" in result.output
    assert "Environment Variables" in result.output
    assert "Workspace" in result.output
    assert "Python version" in result.output
    assert "Package import" in result.output
    assert "Playwright chromium" in result.output
    assert "Workspace writable" in result.output
    assert "Packaged tools config" in result.output
    assert "Packaged report template" in result.output
    assert "GROQ_API_KEY" in result.output
    assert "SHODAN_API_KEY" in result.output
    assert "secret-groq-value" not in result.output
    assert "Next Moves" in result.output
    assert "akagami recon -t example.com -C Example --passive-only --dry-run" in result.output


def test_check_environment_marks_required_and_optional(monkeypatch):
    monkeypatch.setenv("HOME", "/tmp/home")
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")
    monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)

    rows = diagnostics.check_environment()
    by_name = {row["name"]: row for row in rows}

    assert by_name["HOME"]["required"] is True
    assert by_name["HOME"]["present"] is True
    assert by_name["GITHUB_TOKEN"]["required"] is False
    assert by_name["GITHUB_TOKEN"]["present"] is True
    assert by_name["NVIDIA_NIM_API_KEY"]["present"] is False


def _write_httpx_config(path):
    path.write_text(
        """
tools:
  httpx:
    binary: httpx
    category: active-recon
    opsec_risk: low
    required: true
""".lstrip()
    )


def test_tools_check_marks_projectdiscovery_httpx_compatible(tmp_path, monkeypatch):
    config = tmp_path / "tools.yaml"
    _write_httpx_config(config)
    commands = []

    monkeypatch.setattr(diagnostics.shutil, "which", lambda binary: "/opt/pd/httpx")

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="projectdiscovery httpx\nCurrent Version: v1.6.8\n",
            stderr="",
        )

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)

    rows = diagnostics.check_configured_tools(str(config))

    assert rows[0]["status"] == "COMPATIBLE"
    assert "projectdiscovery" in rows[0]["reason"].lower()
    assert commands == [["/opt/pd/httpx", "-version"]]
    assert all(command[0] != "sudo" for command in commands)


def test_tools_check_marks_python_httpx_cli_incompatible(tmp_path, monkeypatch):
    config = tmp_path / "tools.yaml"
    _write_httpx_config(config)

    monkeypatch.setattr(diagnostics.shutil, "which", lambda binary: "/usr/bin/httpx")

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd,
            2,
            stdout="",
            stderr="Usage: httpx [OPTIONS] URL\nError: No such option: -version\n",
        )

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)

    rows = diagnostics.check_configured_tools(str(config))

    assert rows[0]["status"] == "INCOMPATIBLE"
    assert "Python httpx CLI" in rows[0]["reason"]


def test_tools_check_marks_missing_binary_without_probe(tmp_path, monkeypatch):
    config = tmp_path / "tools.yaml"
    _write_httpx_config(config)

    monkeypatch.setattr(diagnostics.shutil, "which", lambda binary: None)
    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("probe ran")),
    )

    rows = diagnostics.check_configured_tools(str(config))

    assert rows[0]["status"] == "MISSING"
    assert rows[0]["installed"] is False
    assert "not found" in rows[0]["reason"]


def test_tools_check_marks_version_probe_timeout_incompatible(tmp_path, monkeypatch):
    config = tmp_path / "tools.yaml"
    _write_httpx_config(config)

    monkeypatch.setattr(diagnostics.shutil, "which", lambda binary: "/usr/bin/httpx")

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)

    rows = diagnostics.check_configured_tools(str(config))

    assert rows[0]["status"] == "INCOMPATIBLE"
    assert "timed out" in rows[0]["reason"]


def test_tools_check_marks_version_probe_failure_incompatible(tmp_path, monkeypatch):
    config = tmp_path / "tools.yaml"
    _write_httpx_config(config)

    monkeypatch.setattr(diagnostics.shutil, "which", lambda binary: "/usr/bin/httpx")
    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(
            cmd, 1, stdout="", stderr="unexpected probe failure"
        ),
    )

    rows = diagnostics.check_configured_tools(str(config))

    assert rows[0]["status"] == "INCOMPATIBLE"
    assert "unexpected probe failure" in rows[0]["reason"]


def test_playwright_timeout_returns_clean_diagnostic(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)

    result = diagnostics.check_playwright_chromium(timeout_seconds=1)

    assert result["ok"] is False
    assert "timed out after 1s" in result["detail"]
    assert "Task was destroyed" not in result["detail"]


def test_playwright_failure_returns_clean_diagnostic(monkeypatch):
    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(
            cmd, 1, stdout="", stderr="browser executable missing"
        ),
    )

    result = diagnostics.check_playwright_chromium(timeout_seconds=1)

    assert result["ok"] is False
    assert "browser executable missing" in result["detail"]
    assert "Task was destroyed" not in result["detail"]
