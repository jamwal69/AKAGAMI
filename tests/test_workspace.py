"""
Tests for ReconForge Workspace Manager.
"""

import tempfile
from pathlib import Path

import pytest

from reconforge.workspace import (
    sanitize_name, init_workspace, get_db_path, get_chromadb_dir,
    get_report_dir, get_tool_output_dir, list_workspaces,
    append_engagement_log, _count_scope,
)


class TestSanitizeName:
    def test_basic(self):
        assert sanitize_name("HackerOne Corp.") == "hackerone_corp"

    def test_spaces_and_dashes(self):
        assert sanitize_name("Bug Crowd - Main") == "bug_crowd_main"

    def test_special_chars(self):
        assert sanitize_name("Google (LLC)") == "google_llc"

    def test_already_clean(self):
        assert sanitize_name("tesla") == "tesla"

    def test_leading_trailing_whitespace(self):
        assert sanitize_name("  Apple  ") == "apple"

    def test_multiple_underscores(self):
        assert sanitize_name("foo___bar") == "foo_bar"


class TestInitWorkspace:
    def test_creates_directory_tree(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        assert ws == tmp_path / "testcorp"
        assert (ws / "scope" / "in_scope.txt").exists()
        assert (ws / "scope" / "out_of_scope.txt").exists()
        assert (ws / "output" / "nmap").is_dir()
        assert (ws / "output" / "nuclei").is_dir()
        assert (ws / "output" / "httpx").is_dir()
        assert (ws / "output" / "ffuf").is_dir()
        assert (ws / "output" / "amass").is_dir()
        assert (ws / "output" / "osint").is_dir()
        assert (ws / "output" / "misc").is_dir()
        assert (ws / "output" / "reports").is_dir()
        assert (ws / "data" / "chromadb").is_dir()
        assert (ws / "notes" / "engagement_log.md").exists()

    def test_writes_scope_files(self, tmp_path):
        init_workspace("TestCorp",
                       in_scope=["example.com", "*.example.com"],
                       out_of_scope=["mail.example.com"],
                       root=tmp_path)
        ws = tmp_path / "testcorp"
        in_scope = (ws / "scope" / "in_scope.txt").read_text()
        assert "example.com" in in_scope
        assert "*.example.com" in in_scope
        out_scope = (ws / "scope" / "out_of_scope.txt").read_text()
        assert "mail.example.com" in out_scope

    def test_idempotent(self, tmp_path):
        """Running init_workspace twice should not duplicate scope entries."""
        init_workspace("TestCorp",
                       in_scope=["a.com", "b.com"],
                       root=tmp_path)
        init_workspace("TestCorp",
                       in_scope=["a.com", "c.com"],
                       root=tmp_path)
        ws = tmp_path / "testcorp"
        lines = [l for l in (ws / "scope" / "in_scope.txt").read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        # a.com should appear only once, c.com should be appended
        assert lines.count("a.com") == 1
        assert "c.com" in lines

    def test_engagement_log_created(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        log = (ws / "notes" / "engagement_log.md").read_text()
        assert "TestCorp" in log
        assert "Workspace initialized" in log

    def test_engagement_log_not_overwritten(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        log_path = ws / "notes" / "engagement_log.md"
        log_path.write_text("Custom content")
        init_workspace("TestCorp", root=tmp_path)
        assert log_path.read_text() == "Custom content"


class TestGetPaths:
    def test_db_path(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        db = get_db_path(ws)
        assert db.endswith("data/missions.db")

    def test_chromadb_dir(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        cd = get_chromadb_dir(ws)
        assert cd.endswith("data/chromadb")

    def test_report_dir(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        rd = get_report_dir(ws)
        assert rd == ws / "output" / "reports"


class TestToolOutputDir:
    def test_nmap(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        assert get_tool_output_dir(ws, "nmap") == ws / "output" / "nmap"

    def test_nuclei(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        assert get_tool_output_dir(ws, "nuclei") == ws / "output" / "nuclei"

    def test_osint_tools_map_to_osint_dir(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        for tool in ["whois", "theharvester", "crt_sh", "shodan", "github_dork"]:
            assert get_tool_output_dir(ws, tool) == ws / "output" / "osint"

    def test_unknown_tool_maps_to_misc(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        assert get_tool_output_dir(ws, "custom_tool") == ws / "output" / "misc"


class TestListWorkspaces:
    def test_empty(self, tmp_path):
        assert list_workspaces(root=tmp_path) == []

    def test_lists_existing(self, tmp_path):
        init_workspace("CompanyA", in_scope=["a.com"], root=tmp_path)
        init_workspace("CompanyB", in_scope=["b.com", "c.com"], root=tmp_path)
        ws_list = list_workspaces(root=tmp_path)
        assert len(ws_list) == 2
        names = [w["name"] for w in ws_list]
        assert "companya" in names
        assert "companyb" in names

    def test_in_scope_count(self, tmp_path):
        init_workspace("CompanyA", in_scope=["a.com", "b.com"], root=tmp_path)
        ws_list = list_workspaces(root=tmp_path)
        assert ws_list[0]["in_scope_count"] == 2


class TestAppendEngagementLog:
    def test_appends_entry(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        append_engagement_log(ws, "Started nmap scan")
        log = (ws / "notes" / "engagement_log.md").read_text()
        assert "Started nmap scan" in log

    def test_multiple_entries(self, tmp_path):
        ws = init_workspace("TestCorp", root=tmp_path)
        append_engagement_log(ws, "Entry 1")
        append_engagement_log(ws, "Entry 2")
        log = (ws / "notes" / "engagement_log.md").read_text()
        assert "Entry 1" in log
        assert "Entry 2" in log
