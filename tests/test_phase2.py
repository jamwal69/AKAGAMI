"""Tests for Phase 2 — Active Recon Agent, Parser, Scorer, and Active Plan."""

import json
import pytest
from reconforge.intel.models import (
    Host, MissionState, Port, Task, Vulnerability, WebPath, Subdomain,
)
from reconforge.agents.recon import ActiveReconAgent
from reconforge.skills.scorer import SeverityScorer
from reconforge.orchestrator.task_graph import TaskCoordinationGraph
from reconforge.parsers.nmap_parser import NmapParser
from reconforge.parsers.httpx_parser import HttpxParser
from reconforge.parsers.ffuf_parser import FfufParser
from reconforge.parsers.nuclei_parser import NucleiParser


# ── Sample tool outputs for testing ──────────────────────────

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="test.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache" version="2.4.54"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Apache" version="2.4.54"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="8.0.32"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
  </host>
</nmaprun>"""

SAMPLE_HTTPX_JSON = """{"url":"http://test.local","status_code":200,"title":"Welcome","tech":["Apache","PHP"],"host":"192.168.1.1","content_type":"text/html"}
{"url":"http://test.local:8080","status_code":401,"title":"Admin Panel","tech":["Tomcat"],"host":"192.168.1.1","content_type":"text/html"}"""

SAMPLE_FFUF_JSON = json.dumps({
    "results": [
        {"url": "http://test.local/admin", "status": 403, "length": 287, "content-type": "text/html"},
        {"url": "http://test.local/login", "status": 200, "length": 4523, "content-type": "text/html"},
        {"url": "http://test.local/.git", "status": 403, "length": 287, "content-type": "text/html"},
        {"url": "http://test.local/api", "status": 200, "length": 128, "content-type": "application/json"},
    ]
})

SAMPLE_NUCLEI_JSON = """{"template-id":"apache-detect","info":{"name":"Apache HTTP Server Detection","severity":"info","description":"Apache detected","classification":{"cve-id":null}},"host":"http://test.local","matched-at":"http://test.local"}
{"template-id":"cve-2021-41773","info":{"name":"Apache 2.4.49 Path Traversal","severity":"critical","description":"Path traversal in Apache 2.4.49","classification":{"cve-id":["CVE-2021-41773"],"cvss-score":9.8},"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],"remediation":"Upgrade Apache"},"host":"http://test.local","matched-at":"http://test.local/cgi-bin/.%2e/.%2e/etc/passwd"}"""


# ── ActiveReconAgent Tests ───────────────────────────────────

class TestActiveReconAgentParsers:
    """Test the native parsers in ActiveReconAgent."""

    def setup_method(self):
        from unittest.mock import MagicMock
        self.agent = ActiveReconAgent.__new__(ActiveReconAgent)
        self.agent.name = "recon_agent"
        self.agent.logger = MagicMock()

    def test_parse_nmap_xml(self):
        findings = self.agent._parse_nmap_xml(
            SAMPLE_NMAP_XML, "test.local", "mission-1")
        hosts = [f for f in findings if isinstance(f, Host)]
        ports = [f for f in findings if isinstance(f, Port)]

        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.1"
        assert hosts[0].hostname == "test.local"
        assert hosts[0].os_guess == "Linux 5.x"
        assert len(ports) == 4
        assert any(p.port == 22 and p.service == "ssh" for p in ports)
        assert any(p.port == 80 and p.service == "http" for p in ports)
        assert any(p.port == 3306 and p.service == "mysql" for p in ports)

    def test_parse_nmap_host_tags(self):
        findings = self.agent._parse_nmap_xml(
            SAMPLE_NMAP_XML, "test.local", "mission-1")
        hosts = [f for f in findings if isinstance(f, Host)]
        assert "web" in hosts[0].tags
        assert "ssh" in hosts[0].tags
        assert "database" in hosts[0].tags

    def test_parse_nmap_invalid_xml(self):
        findings = self.agent._parse_nmap_xml(
            "not valid xml", "test.local", "mission-1")
        assert findings == []

    def test_parse_httpx_json(self):
        findings = self.agent._parse_httpx_json(
            SAMPLE_HTTPX_JSON, "test.local", "mission-1")
        web_paths = [f for f in findings if isinstance(f, WebPath)]
        subdomains = [f for f in findings if isinstance(f, Subdomain)]

        assert len(web_paths) == 2
        assert any(w.url == "http://test.local" for w in web_paths)
        assert any(w.status_code == 401 for w in web_paths)
        assert len(subdomains) >= 1

    def test_parse_httpx_interesting_paths(self):
        findings = self.agent._parse_httpx_json(
            SAMPLE_HTTPX_JSON, "test.local", "mission-1")
        web_paths = [f for f in findings if isinstance(f, WebPath)]
        # 401 admin panel should be flagged as interesting
        admin = [w for w in web_paths if w.status_code == 401]
        assert len(admin) == 1
        assert admin[0].interesting is True

    def test_parse_ffuf_json(self):
        findings = self.agent._parse_ffuf_json(
            SAMPLE_FFUF_JSON, "http://test.local", "test.local", "mission-1")
        assert len(findings) == 4
        assert all(isinstance(f, WebPath) for f in findings)
        admin = [f for f in findings if "/admin" in f.url]
        assert len(admin) == 1

    def test_is_interesting_path(self):
        assert self.agent._is_interesting_path("http://x/admin", 200, "")
        assert self.agent._is_interesting_path("http://x/login", 200, "")
        assert self.agent._is_interesting_path("http://x/.git", 403, "")
        assert self.agent._is_interesting_path("http://x/page", 401, "")
        assert not self.agent._is_interesting_path("http://x/index.html", 200, "Home")

    def test_active_scan_not_permitted(self):
        """Agent should return empty when active scanning not permitted."""
        import asyncio
        from unittest.mock import MagicMock
        from reconforge.llm.router import LLMRouter
        router = MagicMock(spec=LLMRouter)
        agent = ActiveReconAgent(router, MagicMock(), MagicMock())
        mission = MissionState(
            target="test.local", scope=["test.local"],
            active_scan_permitted=False)
        task = Task(id="t1", agent_type="recon", tool="nmap",
                    params={"target": "test.local"})
        result = asyncio.get_event_loop().run_until_complete(
            agent.run(task, MagicMock(), MagicMock(), mission))
        assert result == []


# ── Deterministic Parser Tests (V2) ─────────────────────────
# OutputParser was removed in V2. These tests use the new deterministic parsers.

class TestDeterministicParsers:
    """Test the V2 deterministic parsers."""

    def test_nmap_parser_extracts_host_and_ports(self):
        findings = NmapParser().parse(SAMPLE_NMAP_XML, "mission-1", "test_agent")
        hosts = [f for f in findings if isinstance(f, Host)]
        ports = [f for f in findings if isinstance(f, Port)]
        assert len(hosts) == 1
        assert len(ports) == 4

    def test_httpx_parser_extracts_web_paths(self):
        findings = HttpxParser().parse(SAMPLE_HTTPX_JSON, "mission-1", "test_agent")
        from reconforge.intel.models import WebPath
        paths = [f for f in findings if isinstance(f, WebPath)]
        assert len(paths) > 0

    def test_ffuf_parser_extracts_paths(self):
        findings = FfufParser().parse(SAMPLE_FFUF_JSON, "mission-1", "test_agent")
        from reconforge.intel.models import WebPath
        paths = [f for f in findings if isinstance(f, WebPath)]
        assert len(paths) == 4

    def test_nuclei_parser_extracts_vulns(self):
        findings = NucleiParser().parse(SAMPLE_NUCLEI_JSON, "mission-1", "test_agent")
        vulns = [f for f in findings if isinstance(f, Vulnerability)]
        assert len(vulns) == 2
        critical = [v for v in vulns if v.severity == "critical"]
        assert len(critical) == 1
        assert critical[0].cve_id == "CVE-2021-41773"


# ── SeverityScorer Tests ─────────────────────────────────────

class TestSeverityScorer:
    """Test the heuristic scoring logic."""

    def setup_method(self):
        self.scorer = SeverityScorer(router=None)  # V2: router kwarg

    def test_heuristic_internet_facing_boost(self):
        import asyncio
        vuln = Vulnerability(
            source_agent="test", source_tool="nuclei",
            confidence=0.8, mission_id="m1", host_id="h1",
            title="Test Vuln", severity="medium")
        context = {"internet_facing": True, "waf_detected": False}
        result = asyncio.get_event_loop().run_until_complete(
            self.scorer.score(vuln, context))
        # Medium + internet_facing + no WAF should boost
        assert result.severity in ("high", "critical")

    def test_heuristic_exploit_available_boost(self):
        import asyncio
        vuln = Vulnerability(
            source_agent="test", source_tool="nuclei",
            confidence=0.8, mission_id="m1", host_id="h1",
            title="Test Vuln", severity="low",
            exploit_available=True)
        context = {"internet_facing": False}
        result = asyncio.get_event_loop().run_until_complete(
            self.scorer.score(vuln, context))
        assert result.severity in ("medium", "high")

    def test_heuristic_no_boost(self):
        import asyncio
        vuln = Vulnerability(
            source_agent="test", source_tool="nuclei",
            confidence=0.8, mission_id="m1", host_id="h1",
            title="Test Vuln", severity="info")
        context = {"internet_facing": False, "waf_detected": True}
        result = asyncio.get_event_loop().run_until_complete(
            self.scorer.score(vuln, context))
        assert result.severity == "info"

    def test_batch_scoring(self):
        import asyncio
        vulns = [
            Vulnerability(source_agent="t", source_tool="n",
                          confidence=0.8, mission_id="m1", host_id="h1",
                          title=f"Vuln {i}", severity="medium")
            for i in range(3)
        ]
        context = {"internet_facing": True}
        results = asyncio.get_event_loop().run_until_complete(
            self.scorer.score_batch(vulns, context))
        assert len(results) == 3

    def test_stats(self):
        import asyncio
        vuln = Vulnerability(
            source_agent="t", source_tool="n",
            confidence=0.8, mission_id="m1", host_id="h1",
            title="V", severity="info")
        asyncio.get_event_loop().run_until_complete(
            self.scorer.score(vuln, {}))
        stats = self.scorer.get_stats()
        assert stats["rescored"] == 1


# ── Active Plan Tests ────────────────────────────────────────

class TestActivePlan:
    """Test the default active plan dependency chain."""

    def test_passive_plan_no_active_deps(self):
        tasks = TaskCoordinationGraph.build_default_passive_plan("test.com")
        assert len(tasks) == 3
        # All passive
        assert all(t.opsec_risk == "passive" for t in tasks)

    def test_active_plan_has_all_phases(self):
        tasks = TaskCoordinationGraph.build_default_active_plan("test.com")
        agents = {t.agent_type for t in tasks}
        assert "osint" in agents
        assert "recon" in agents
        assert "vuln" in agents

    def test_active_plan_dependency_chain(self):
        tasks = TaskCoordinationGraph.build_default_active_plan("test.com")
        graph = TaskCoordinationGraph()
        graph.load(tasks)

        # Initially only passive tasks should be ready
        ready = graph.get_ready_tasks()
        ready_ids = {t.id for t in ready}
        assert "whois_lookup" in ready_ids
        assert "cert_transparency" in ready_ids
        # Active tasks should NOT be ready
        assert "httpx_probe" not in ready_ids
        assert "nmap_top_ports" not in ready_ids

    def test_active_plan_unlocks_correctly(self):
        tasks = TaskCoordinationGraph.build_default_active_plan("test.com")
        graph = TaskCoordinationGraph()
        graph.load(tasks)

        # Complete all passive tasks
        for task in list(graph.tasks.values()):
            if task.opsec_risk == "passive" and not task.depends_on:
                graph.mark_complete(task.id)

        # Now subdomain_enum_crt should be ready (depends on cert_transparency)
        ready = graph.get_ready_tasks()
        ready_ids = {t.id for t in ready}
        assert "subdomain_enum_crt" in ready_ids

    def test_active_plan_httpx_after_passive(self):
        tasks = TaskCoordinationGraph.build_default_active_plan("test.com")
        graph = TaskCoordinationGraph()
        graph.load(tasks)

        # Complete all tasks that httpx depends on
        graph.mark_complete("passive_dns")
        graph.mark_complete("cert_transparency")
        graph.mark_complete("subdomain_enum_crt")

        ready = graph.get_ready_tasks()
        ready_ids = {t.id for t in ready}
        assert "httpx_probe" in ready_ids

    def test_active_plan_nmap_after_httpx(self):
        tasks = TaskCoordinationGraph.build_default_active_plan("test.com")
        graph = TaskCoordinationGraph()
        graph.load(tasks)

        # Complete up to httpx
        for tid in ["whois_lookup", "cert_transparency", "passive_dns",
                     "subdomain_enum_crt", "httpx_probe"]:
            graph.mark_complete(tid)

        ready = graph.get_ready_tasks()
        ready_ids = {t.id for t in ready}
        assert "nmap_top_ports" in ready_ids
        assert "tech_fingerprint" in ready_ids

    def test_tasks_by_agent(self):
        tasks = TaskCoordinationGraph.build_default_active_plan("test.com")
        graph = TaskCoordinationGraph()
        graph.load(tasks)
        by_agent = graph.get_tasks_by_agent()
        assert len(by_agent["osint"]) >= 3
        assert len(by_agent["recon"]) >= 4
        assert len(by_agent["vuln"]) >= 1
