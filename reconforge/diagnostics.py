"""Local diagnostics for Akagami CLI health checks."""

from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys
import tempfile
from importlib.resources import files
from pathlib import Path
from typing import Mapping

from reconforge.tools.executor import ToolExecutor


MIN_PYTHON = (3, 11)

OPTIONAL_ENV_VARS = (
    "NVIDIA_NIM_API_KEY",
    "NVIDIA_NIM_MODEL",
    "GROQ_API_KEY",
    "GROQ_MODEL_FAST",
    "GROQ_MODEL_REASONING",
    "SHODAN_API_KEY",
    "GITHUB_TOKEN",
)

REQUIRED_ENV_VARS = ("HOME",)

DEFAULT_REQUIRED_TOOL_NAMES = {
    "whois",
    "crt_sh",
    "theharvester",
    "httpx",
    "nmap",
    "ffuf",
    "nuclei",
}

PROBE_TIMEOUT_SECONDS = 3


def _combined_output(result: subprocess.CompletedProcess) -> str:
    return "\n".join(
        part for part in (result.stdout or "", result.stderr or "") if part
    ).strip()


def _first_line(text: str, fallback: str = "") -> str:
    for line in str(text or "").splitlines():
        line = line.strip()
        if line:
            return line[:240]
    return fallback


def _looks_like_projectdiscovery_httpx(output: str) -> bool:
    lowered = output.lower()
    return (
        "projectdiscovery" in lowered
        or "github.com/projectdiscovery/httpx" in lowered
        or "current version" in lowered
    )


def _looks_like_python_httpx(output: str) -> bool:
    lowered = output.lower()
    return (
        "no such option" in lowered
        and "httpx" in lowered
        and ("[options]" in lowered or "usage:" in lowered)
    )


def _probe_tool(
    name: str,
    path: str,
    *,
    timeout_seconds: int = PROBE_TIMEOUT_SECONDS,
) -> tuple[str, str]:
    """Run a bounded, non-invasive compatibility probe for critical tools."""
    probes = {
        "httpx": (["-version"], _looks_like_projectdiscovery_httpx),
        "nuclei": (["-version"], lambda out: "nuclei" in out.lower() or "projectdiscovery" in out.lower()),
        "ffuf": (["-V"], lambda out: "ffuf" in out.lower()),
        "nmap": (["--version"], lambda out: "nmap" in out.lower()),
        "amass": (["-version"], lambda out: "amass" in out.lower()),
        "theharvester": (["--version"], lambda out: "theharvester" in out.lower()),
        "crt_sh": (["--version"], lambda out: "curl" in out.lower()),
    }
    probe = probes.get(name)
    if not probe:
        return "FOUND", "binary present; no compatibility probe configured"

    args, validator = probe
    command = [path, *args]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "INCOMPATIBLE", f"version probe timed out after {timeout_seconds}s"
    except OSError as exc:
        return "INCOMPATIBLE", f"version probe failed: {exc}"

    output = _combined_output(result)
    if name == "httpx" and _looks_like_python_httpx(output):
        return "INCOMPATIBLE", "Python httpx CLI detected; ProjectDiscovery httpx is required"
    if result.returncode == 0 and validator(output):
        return "COMPATIBLE", _first_line(output, "version probe passed")
    reason = _first_line(output, f"version probe exited {result.returncode}")
    if name == "httpx":
        reason = f"not ProjectDiscovery httpx: {reason}"
    return "INCOMPATIBLE", reason


def load_tools_config(config_path: str = "config/tools.yaml") -> dict:
    """Load the source checkout tools config, falling back to package data."""
    return ToolExecutor(config_path).tools_config


def check_configured_tools(config_path: str = "config/tools.yaml") -> list[dict]:
    """Check configured tool binaries and probe critical tool compatibility."""
    config = load_tools_config(config_path)
    rows = []
    for name, tool in sorted(config.get("tools", {}).items()):
        binary = str(tool.get("binary", "")).strip()
        found_path = shutil.which(binary) if binary else None
        is_required = tool.get("required") or name in DEFAULT_REQUIRED_TOOL_NAMES
        requirement = "required" if is_required else "optional"
        status = "MISSING"
        reason = "binary not found on PATH"
        if found_path:
            status, reason = _probe_tool(name, found_path)
        rows.append({
            "name": name,
            "binary": binary,
            "installed": found_path is not None,
            "status": status,
            "reason": reason,
            "path": found_path or "",
            "category": str(tool.get("category", "")),
            "risk": str(tool.get("opsec_risk", "")),
            "requirement": requirement,
        })
    return rows


def check_python_version() -> dict:
    version = sys.version_info
    version_text = (
        f"{version.major}.{version.minor}.{version.micro}"
    )
    return {
        "name": "Python version",
        "ok": (version.major, version.minor) >= MIN_PYTHON,
        "detail": f"{version_text} at {sys.executable}",
    }


def check_package_import() -> dict:
    try:
        module = importlib.import_module("reconforge")
        detail = getattr(module, "__file__", "") or "imported"
        return {"name": "Package import", "ok": True, "detail": detail}
    except Exception as exc:
        return {"name": "Package import", "ok": False, "detail": str(exc)}


def check_playwright_chromium(timeout_seconds: int = 3) -> dict:
    """Check Chromium availability in an isolated, bounded subprocess."""
    script = (
        "from pathlib import Path\n"
        "from playwright.sync_api import sync_playwright\n"
        "with sync_playwright() as p:\n"
        "    executable = p.chromium.executable_path\n"
        "    print(executable or '')\n"
        "    raise SystemExit(0 if executable and Path(executable).exists() else 2)\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "name": "Playwright chromium",
            "ok": False,
            "detail": f"playwright chromium check timed out after {timeout_seconds}s",
        }
    except Exception as exc:
        return {
            "name": "Playwright chromium",
            "ok": False,
            "detail": f"playwright check failed: {exc}",
        }

    output = _combined_output(result)
    if result.returncode == 0:
        return {
            "name": "Playwright chromium",
            "ok": True,
            "detail": _first_line(output, "available"),
        }
    return {
        "name": "Playwright chromium",
        "ok": False,
        "detail": f"playwright chromium unavailable: {_first_line(output, 'not found')}",
    }


def check_environment(
    env: Mapping[str, str] | None = None,
) -> list[dict]:
    source = os.environ if env is None else env
    rows = []
    for name in REQUIRED_ENV_VARS:
        rows.append({
            "name": name,
            "required": True,
            "present": bool(source.get(name)),
        })
    for name in OPTIONAL_ENV_VARS:
        rows.append({
            "name": name,
            "required": False,
            "present": bool(source.get(name)),
        })
    return rows


def check_workspace_writable(workspace_root: str | Path = "workspace") -> dict:
    root = Path(workspace_root)
    try:
        root.mkdir(parents=True, exist_ok=True)
        temp_path = None
        with tempfile.NamedTemporaryFile(
            prefix=".doctor-", dir=root, delete=False,
        ) as handle:
            handle.write(b"ok")
            temp_path = Path(handle.name)
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        return {
            "name": "Workspace writable",
            "ok": True,
            "detail": str(root),
        }
    except Exception as exc:
        return {
            "name": "Workspace writable",
            "ok": False,
            "detail": f"{root}: {exc}",
        }


def check_packaged_resources() -> list[dict]:
    checks = []

    try:
        config_resource = files("reconforge.config").joinpath("tools.yaml")
        ok = config_resource.is_file()
        if ok:
            config_resource.read_text(encoding="utf-8")
        detail = str(config_resource)
    except Exception as exc:
        ok = False
        detail = str(exc)
    checks.append({
        "name": "Packaged tools config",
        "ok": ok,
        "detail": detail,
    })

    try:
        template_resource = files("reconforge.report.templates").joinpath(
            "recon_report.md.j2"
        )
        ok = template_resource.is_file()
        if ok:
            template_resource.read_text(encoding="utf-8")
        detail = str(template_resource)
    except Exception as exc:
        ok = False
        detail = str(exc)
    checks.append({
        "name": "Packaged report template",
        "ok": ok,
        "detail": detail,
    })

    try:
        brand_root = files("reconforge.assets.brand")
        missing = [
            name for name in ("akagami-logo.png", "akagami-mark.png")
            if not brand_root.joinpath(name).is_file()
        ]
        ok = not missing
        detail = (
            str(brand_root)
            if ok
            else f"missing: {', '.join(missing)}"
        )
    except Exception as exc:
        ok = False
        detail = str(exc)
    checks.append({
        "name": "Packaged brand assets",
        "ok": ok,
        "detail": detail,
    })

    return checks


def doctor_checks(
    config_path: str = "config/tools.yaml",
    workspace_root: str | Path = "workspace",
) -> dict:
    """Collect local health checks without running scans or network calls."""
    return {
        "system": [
            check_python_version(),
            check_package_import(),
            check_playwright_chromium(),
            check_workspace_writable(workspace_root),
            *check_packaged_resources(),
        ],
        "environment": check_environment(),
        "tools": check_configured_tools(config_path),
    }
