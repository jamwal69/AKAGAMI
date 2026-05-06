"""Tests for Phase 5 — Self-correction, mission resume, Jinja2 template, integration."""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reconforge.agents.exploit_planner import ExploitPlannerAgent
from reconforge.intel.models import (
    Host, MissionState, OsintFinding, Port, Task, TaskStatus,
    Vulnerability, WebPath,
)
from reconforge.intel.store import IntelStore
from reconforge.memory.episodic import EpisodicMemory
from reconforge.orchestrator.task_graph import TaskCoordinationGraph
from reconforge.report.generator import ReportGenerator


# ── Self-Correction Loop Tests ───────────────────────────────

class TestSelfCorrection:
    """Test the orchestrator's self-correction capabilities."""

    def test_mark_pending_resets_task(self):
        """Task graph can reset a failed task to pending for retry."""
        graph = TaskCoordinationGraph()
        tasks = [Task(id="t1", agent_type="osint", tool="whois",
                       params={"target": "test.com"})]
        graph.load(tasks)

        graph.mark_running("t1")
        graph.mark_failed("t1", "Connection refused")
        assert graph.tasks["t1"].status == TaskStatus.FAILED

        graph.mark_pending("t1")
        assert graph.tasks["t1"].status == TaskStatus.PENDING
        assert graph.tasks["t1"].result is None

    def test_retried_task_becomes_ready(self):
        """After mark_pending, task should appear in get_ready_tasks."""
        graph = TaskCoordinationGraph()
        tasks = [Task(id="t1", agent_type="osint", tool="whois",
                       params={"target": "test.com"})]
        graph.load(tasks)

        graph.mark_running("t1")
        graph.mark_failed("t1", "Timeout")
        graph.mark_pending("t1")

        ready = graph.get_ready_tasks()
        assert any(t.id == "t1" for t in ready)

    def test_graph_not_complete_with_pending_retry(self):
        """Graph should not be complete if a task is pending retry."""
        graph = TaskCoordinationGraph()
        tasks = [
            Task(id="t1", agent_type="osint", tool="whois",
                 params={"target": "test.com"}),
            Task(id="t2", agent_type="osint", tool="crt_sh",
                 params={"target": "test.com"}),
        ]
        graph.load(tasks)

        graph.mark_complete("t1")
        graph.mark_running("t2")
        graph.mark_failed("t2", "Error")
        graph.mark_pending("t2")

        assert graph.is_complete() is False


# ── Mission Resume Tests ─────────────────────────────────────

class TestMissionResume:
    """Test mission resume from episodic memory."""

    def setup_method(self):
        self.tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmpfile.close()
        self.episodic = EpisodicMemory(self.tmpfile.name)

    def teardown_method(self):
        self.episodic.close()
        os.unlink(self.tmpfile.name)

    def test_resume_context_available(self):
        """Episodic memory should provide resume context."""
        mid = "resume-test-001"
        self.episodic.create_mission(mid, "test.com", {"scope": ["test.com"]})
        self.episodic.log_action("whois", {"target": "test.com"},
                                 "Registrant: Test Corp", mid)
        self.episodic.store_summary(mid, "Found test.com owned by Test Corp", 100)

        ctx = self.episodic.get_resume_context(mid)
        assert ctx["mission"] is not None
        assert ctx["mission"]["target"] == "test.com"
        assert ctx["latest_summary"] == "Found test.com owned by Test Corp"
        assert len(ctx["recent_actions"]) == 1

    def test_resume_nonexistent_mission(self):
        """Resume should return empty context for unknown missions."""
        ctx = self.episodic.get_resume_context("nonexistent")
        assert ctx["mission"] is None
        assert ctx["latest_summary"] is None

    def test_mission_stats(self):
        """Mission stats should track actions and findings."""
        mid = "stats-test-001"
        self.episodic.create_mission(mid, "test.com")
        self.episodic.log_action("whois", {}, "output1", mid)
        self.episodic.log_action("nmap", {}, "output2", mid)
        self.episodic.log_finding("f1", "Host", {}, mid, 0.9, True)

        stats = self.episodic.get_mission_stats(mid)
        assert stats["total_actions"] == 2
        assert stats["total_findings"] == 1
        assert "whois" in stats["tools_used"]
        assert "nmap" in stats["tools_used"]


# ── Jinja2 Template Tests ────────────────────────────────────

class TestJinja2Template:
    """Test the full Jinja2 report template rendering."""

    def setup_method(self):
        self.tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmpfile.close()
        self.store = IntelStore(self.tmpfile.name)
        self.output_dir = tempfile.mkdtemp()
        # Use the real template directory
        template_dir = str(Path(__file__).parent.parent / "reconforge" / "report" / "templates")
        self.generator = ReportGenerator(
            template_dir=template_dir, client=None)
        self.mission_id = "jinja-test"

    def teardown_method(self):
        self.store.close()
        os.unlink(self.tmpfile.name)
        import shutil
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_jinja2_template_renders(self):
        """Verify Jinja2 template renders without errors."""
        # Add realistic data
        mid = self.mission_id
        self.store.write(Host(
            source_agent="t", source_tool="nmap", confidence=0.9,
            mission_id=mid, ip="10.0.0.1", hostname="web.test.local",
            os_guess="Ubuntu 22.04", tags=["web", "linux"]))
        self.store.write(Port(
            source_agent="t", source_tool="nmap", confidence=0.9,
            mission_id=mid, host_id="h1", port=80,
            service="http", version="Apache 2.4.52"))
        self.store.write(Port(
            source_agent="t", source_tool="nmap", confidence=0.9,
            mission_id=mid, host_id="h1", port=443,
            service="https", version="Apache 2.4.52"))
        self.store.write(Vulnerability(
            source_agent="t", source_tool="nuclei", confidence=0.85,
            mission_id=mid, host_id="10.0.0.1",
            title="Apache Path Traversal", severity="critical",
            cve_id="CVE-2021-41773", cvss_score=9.8,
            evidence="GET /cgi-bin/.%2e/.%2e/etc/passwd HTTP/1.1\nHTTP/1.1 200 OK",
            remediation="Upgrade Apache to 2.4.51+",
            exploit_available=True,
            exploit_reference="https://www.exploit-db.com/exploits/50383"))
        self.store.write(OsintFinding(
            source_agent="t", source_tool="whois", confidence=0.9,
            mission_id=mid, category="whois",
            value="test.local", context="Registrant: TestCorp Inc."))
        self.store.write(WebPath(
            source_agent="t", source_tool="ffuf", confidence=0.8,
            mission_id=mid, host_id="h1",
            url="http://10.0.0.1/admin", status_code=200,
            interesting=True, reason="Admin panel"))

        output_path = os.path.join(self.output_dir, "jinja_report.md")
        report = asyncio.get_event_loop().run_until_complete(
            self.generator.generate(
                self.store, mid, output_path=output_path,
                target="test.local", mission_name="Jinja2 Test Assessment"))

        # Verify report content
        assert os.path.exists(output_path)
        assert len(report) > 500
        assert "test.local" in report
        assert "10.0.0.1" in report
        assert "Apache Path Traversal" in report
        assert "CVE-2021-41773" in report
        assert "CRITICAL" in report or "critical" in report.lower()
        assert "Recommendations" in report or "recommendations" in report.lower()

    def test_jinja2_empty_data(self):
        """Template should handle empty data gracefully."""
        output_path = os.path.join(self.output_dir, "empty_report.md")
        report = asyncio.get_event_loop().run_until_complete(
            self.generator.generate(
                self.store, "empty-mission", output_path=output_path,
                target="empty.com"))
        assert len(report) > 100
        assert "empty.com" in report


# ── End-to-End Integration Tests ─────────────────────────────

class TestEndToEndIntegration:
    """Integration tests that verify the full pipeline works together."""

    def setup_method(self):
        self.tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmpfile.close()
        self.store = IntelStore(self.tmpfile.name)
        self.mission = MissionState(
            target="integration.test",
            scope=["integration.test"],
            mission_name="E2E Integration Test",
            active_scan_permitted=True)

    def teardown_method(self):
        self.store.close()
        os.unlink(self.tmpfile.name)

    def test_full_pipeline_flow(self):
        """Test: ingest → critic → enrich → store → gate → report."""
        from reconforge.skills.critic import CriticAgent
        from reconforge.skills.enricher import CveEnricher
        from reconforge.orchestrator.stage_gate import StageGate

        mid = self.mission.mission_id

        # 1. Create findings (simulate agent output)
        host = Host(source_agent="recon", source_tool="nmap",
                    confidence=0.9, mission_id=mid, ip="10.0.0.1",
                    hostname="integration.test", os_guess="Linux")
        vuln = Vulnerability(
            source_agent="vuln", source_tool="nuclei",
            confidence=0.8, mission_id=mid,
            host_id="10.0.0.1", title="SQL Injection",
            severity="high", evidence="sqlmap confirmed",
            cve_id="CVE-2023-99999")

        # 2. Critic review
        critic = CriticAgent(client=None)
        host_review = asyncio.get_event_loop().run_until_complete(
            critic.review(host))
        vuln_review = asyncio.get_event_loop().run_until_complete(
            critic.review(vuln))

        # Without a critic router, findings are kept unverified/quarantined.
        assert host_review.verdict == "quarantine"

        # 3. Enrich vulnerability
        enricher = CveEnricher(semantic=None, client=None)
        enriched = asyncio.get_event_loop().run_until_complete(
            enricher.enrich(vuln, service="mysql", version="5.7"))

        # 4. Store findings
        self.store.write(host)
        self.store.write(enriched)

        # Add OSINT and ports for gate
        for cat in ["whois", "cert", "dns"]:
            self.store.write(OsintFinding(
                source_agent="t", source_tool="w", confidence=0.8,
                mission_id=mid, category=cat,
                value=f"{cat}.test", context="test"))
        for p in [22, 80, 443]:
            self.store.write(Port(
                source_agent="t", source_tool="nmap", confidence=0.9,
                mission_id=mid, host_id="h1", port=p, service="http"))
        for i in range(3):
            self.store.write(Vulnerability(
                source_agent="t", source_tool="nuclei", confidence=0.7,
                mission_id=mid, host_id="10.0.0.1",
                title=f"Extra Vuln {i}", severity="medium"))
        for path in ["/a", "/b", "/c", "/d", "/e"]:
            self.store.write(WebPath(
                source_agent="t", source_tool="ffuf", confidence=0.8,
                mission_id=mid, host_id="h1",
                url=f"http://10.0.0.1{path}", status_code=200))

        # 5. Verify intel store
        data = self.store.export_json(mid)
        assert len(data["hosts"]) >= 1
        assert len(data["vulnerabilities"]) >= 1

        # 6. Stage gate evaluation
        gate = StageGate(client=None)
        gate_result = asyncio.get_event_loop().run_until_complete(
            gate.evaluate(self.store, self.mission))
        assert gate_result.confidence > 0

        # 7. Generate report
        output_dir = tempfile.mkdtemp()
        report_path = os.path.join(output_dir, "e2e_report.md")
        gen = ReportGenerator(client=None)
        report = asyncio.get_event_loop().run_until_complete(
            gen.generate(self.store, mid, report_path, target="integration.test"))
        assert len(report) > 200
        assert "10.0.0.1" in report

        import shutil
        shutil.rmtree(output_dir, ignore_errors=True)

    def test_dedup_prevents_duplicates(self):
        """Verify intel store dedup across the pipeline."""
        mid = self.mission.mission_id
        host1 = Host(source_agent="t", source_tool="nmap",
                     confidence=0.9, mission_id=mid, ip="10.0.0.1")
        host2 = Host(source_agent="t", source_tool="shodan",
                     confidence=0.85, mission_id=mid, ip="10.0.0.1")

        self.store.write(host1)
        self.store.write(host2)  # Should be deduped

        hosts = self.store.hosts(mid)
        assert len(hosts) == 1

    def test_scope_enforcement_across_agents(self):
        """Verify scope check works at base agent level."""
        from reconforge.agents.base import BaseAgent
        from reconforge.intel.models import OutOfScopeError

        class DummyAgent(BaseAgent):
            async def run(self, task, memory, intel, mission):
                return []

        agent = DummyAgent.__new__(DummyAgent)
        agent.name = "test"
        agent.logger = MagicMock()

        mission = MissionState(
            target="safe.com", scope=["safe.com"],
            out_of_scope=["evil.com"])

        # In scope — should pass
        agent._assert_in_scope("safe.com", mission)
        agent._assert_in_scope("sub.safe.com", mission)

        # Out of scope — should raise
        with pytest.raises(OutOfScopeError):
            agent._assert_in_scope("evil.com", mission)
        with pytest.raises(OutOfScopeError):
            agent._assert_in_scope("other.com", mission)


# ── CLI Integration Tests ────────────────────────────────────

class TestCLIIntegration:
    """Test CLI command structure without executing real recon."""

    def test_cli_help(self):
        from click.testing import CliRunner
        from reconforge.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Akagami" in result.output

    def test_cli_recon_help(self):
        from click.testing import CliRunner
        from reconforge.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["recon", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output
        assert "--passive-only" in result.output

    def test_cli_report_help(self):
        from click.testing import CliRunner
        from reconforge.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0
        assert "--mission-id" in result.output

    def test_cli_gate_help(self):
        from click.testing import CliRunner
        from reconforge.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["gate", "--help"])
        assert result.exit_code == 0
        assert "--mission-id" in result.output

    def test_cli_db_stats(self):
        from click.testing import CliRunner
        from reconforge.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["db", "stats", "--persist-dir",
                                     tempfile.mkdtemp()])
        assert result.exit_code == 0
        assert "ChromaDB" in result.output or "Collection" in result.output
