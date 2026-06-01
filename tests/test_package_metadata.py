"""Package metadata checks for runtime dependency and version drift."""

from importlib.resources import files
import re
import tomllib
from pathlib import Path

import yaml
from click.testing import CliRunner

from reconforge.cli import AKAGAMI_TAGLINE, cli


ROOT = Path(__file__).resolve().parents[1]


def _project_metadata() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())


def _dependency_names(entries: list[str]) -> set[str]:
    names = set()
    for entry in entries:
        name = re.split(r"[<>=!~;\[]", entry, maxsplit=1)[0].strip().lower()
        if name:
            names.add(name)
    return names


def _requirements_names() -> set[str]:
    names = set()
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        requirement = line.split("#", 1)[0].strip()
        if not requirement:
            continue
        names.update(_dependency_names([requirement]))
    return names


def test_runtime_import_dependencies_are_declared():
    project = _project_metadata()["project"]
    dependencies = _dependency_names(project["dependencies"])
    assert {"httpx", "playwright"} <= dependencies


def test_requirements_entries_are_reflected_in_pyproject():
    project = _project_metadata()["project"]
    declared = _dependency_names(project["dependencies"])
    for entries in project.get("optional-dependencies", {}).values():
        declared |= _dependency_names(entries)

    assert _requirements_names() - declared == set()


def test_project_license_uses_spdx_string():
    assert _project_metadata()["project"]["license"] == "MIT"


def test_cli_version_matches_project_metadata():
    version = _project_metadata()["project"]["version"]

    assert version in AKAGAMI_TAGLINE
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert version in result.output


def test_runtime_package_data_is_declared():
    package_data = _project_metadata()["tool"]["setuptools"]["package-data"]["reconforge"]

    assert "config/*.yaml" in package_data
    assert "assets/brand/*.png" in package_data
    assert "report/templates/*.j2" in package_data


def test_packaged_tool_config_matches_root_config():
    """Developer config and packaged fallback stay intentionally duplicated."""
    root_config = (ROOT / "config" / "tools.yaml").read_text()
    package_config = (ROOT / "reconforge" / "config" / "tools.yaml").read_text()

    assert package_config == root_config


def test_packaged_tool_config_resource_is_loadable():
    resource = files("reconforge.config").joinpath("tools.yaml")

    assert resource.is_file()
    data = yaml.safe_load(resource.read_text(encoding="utf-8"))
    assert {"whois", "httpx", "nuclei"} <= set(data["tools"])


def test_packaged_report_template_resource_is_loadable():
    resource = files("reconforge.report.templates").joinpath("recon_report.md.j2")

    assert resource.is_file()
    assert "executive_summary" in resource.read_text(encoding="utf-8")


def test_packaged_brand_asset_resources_are_loadable():
    brand_root = files("reconforge.assets.brand")

    for filename in ("akagami-logo.png", "akagami-mark.png"):
        resource = brand_root.joinpath(filename)
        assert resource.is_file()
        assert resource.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
