"""Package metadata checks for runtime dependency and version drift."""

import re
import tomllib
from pathlib import Path

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
