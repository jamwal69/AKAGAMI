"""Tests for Phase 4 — MCP Bridge, ExploitPlanner, OSINT Upgrade, Integration."""

import asyncio
import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reconforge.agents.exploit_planner import ExploitPlan, ExploitPlannerAgent
from reconforge.agents.osint import OsintAgent
from reconforge.intel.models import (
    AgentLockedError, Host, MissionState, OsintFinding, Port,
    Task, ToolResult, Vulnerability,
)
from reconforge.intel.store import IntelStore
from reconforge.orchestrator.master import MasterOrchestrator
from reconforge.tools.mcp_bridge import McpBridge


# ── MCP Bridge Tests ─────────────────────────────────────────

class TestMcpBridge:
    """Test the MCP bridge tool dispatcher."""

    def setup_method(self):
        self.bridge = McpBridge(client=None)

    def test_get_available_tools_no_keys(self):
        tools = self.bridge.get_available_tools()
        # No API keys set, no tools available (except possibly web_search)
        assert "shodan" not in tools
        assert "github_code_search" not in tools

    def test_get_available_tools_with_shodan_key(self):
        with patch.dict(os.environ, {"SHODAN_API_KEY": "test_key"}):
            tools = self.bridge.get_available_tools()
            assert "shodan" in tools
            assert "shodan_host_lookup" in tools

    def test_get_available_tools_with_github_token(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test_token"}):
            tools = self.bridge.get_available_tools()
            assert "github_code_search" in tools

    def test_unknown_tool_raises(self):
        with pytest.raises(ValueError, match="Unknown MCP tool"):
            asyncio.get_event_loop().run_until_complete(
                self.bridge.call("unknown_tool", {}))

    def test_shodan_no_api_key(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SHODAN_API_KEY", None)
            result = asyncio.get_event_loop().run_until_complete(
                self.bridge.call("shodan", {"target": "1.2.3.4"}))
            assert result.exit_code == 1
            assert "not set" in result.error.lower() or "not set" in result.clean.lower()

    def test_github_no_token(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_TOKEN", None)
            result = asyncio.get_event_loop().run_until_complete(
                self.bridge.call("github_code_search",
                                 {"query": "test password"}))
            assert result.exit_code == 1

    def test_web_search_no_client(self):
        result = asyncio.get_event_loop().run_until_complete(
            self.bridge.call("web_search", {"query": "test"}))
        assert result.exit_code == 1

    def test_web_search_router_without_client_is_cleanly_unavailable(self):
        bridge = McpBridge(router=MagicMock(), client=None)

        result = asyncio.get_event_loop().run_until_complete(
            bridge.call("web_search", {"query": "test"}))

        assert result.exit_code == 1
        assert result.error == "web_search unavailable"
        assert "web_search" not in bridge.get_available_tools()

    def test_orchestrator_constructs_mcp_bridge_without_broken_web_search(self, tmp_path):
        mission = MissionState(
            target="example.com",
            scope=["example.com"],
        )
        orch = MasterOrchestrator(
            mission,
            {"_db_path": str(tmp_path / "mission.db")},
        )
        try:
            assert orch.mcp_bridge.router is orch.router
            result = asyncio.get_event_loop().run_until_complete(
                orch.mcp_bridge.call("web_search", {"query": "example.com"}))
            assert result.exit_code == 1
            assert result.error == "web_search unavailable"
        finally:
            orch.episodic.close()
            orch.intel.close()

    def test_stats_tracking(self):
        asyncio.get_event_loop().run_until_complete(
            self.bridge.call("shodan", {"target": "1.2.3.4"}))
        stats = self.bridge.get_stats()
        assert stats["calls"] == 1


# ── ExploitPlanner Tests ─────────────────────────────────────

class TestExploitPlanner:
    """Test the exploit planner agent."""

    def test_locked_by_default(self):
        assert ExploitPlannerAgent.is_locked() is True

    def test_raises_when_locked(self):
        agent = ExploitPlannerAgent(MagicMock(), MagicMock(), MagicMock())
        task = Task(id="t1", agent_type="exploit_planner",
                    tool="plan_exploits", params={"target": "test"})
        mission = MissionState(
            target="test.local", scope=["test.local"],
            active_scan_permitted=True)

        with pytest.raises(AgentLockedError):
            asyncio.get_event_loop().run_until_complete(
                agent.run(task, MagicMock(), MagicMock(), mission))

    def test_unlock_lock(self):
        # Save original state
        original = ExploitPlannerAgent.LOCKED
        try:
            ExploitPlannerAgent.unlock()
            assert ExploitPlannerAgent.is_locked() is False
            ExploitPlannerAgent.lock()
            assert ExploitPlannerAgent.is_locked() is True
        finally:
            ExploitPlannerAgent.LOCKED = original

    def test_exploit_plan_model(self):
        plan = ExploitPlan({
            "id": "EP-001",
            "title": "Apache Path Traversal to RCE",
            "target_vuln": "CVE-2021-41773",
            "attack_chain": ["Send crafted request", "Execute command"],
            "tools_required": ["curl"],
            "commands": ["curl http://target/cgi-bin/.%2e/.%2e/bin/sh"],
            "expected_outcome": "Remote code execution",
            "difficulty": "easy",
            "detection_risk": "medium",
            "prerequisites": [],
            "priv_esc_potential": True,
            "impact": "critical",
            "notes": "Well-known exploit",
        })
        assert plan.title == "Apache Path Traversal to RCE"
        assert plan.difficulty == "easy"
        assert plan.priv_esc_potential is True

        # Test serialization
        d = plan.to_dict()
        assert d["id"] == "EP-001"
        assert len(d["attack_chain"]) == 2

    def test_plan_summary_empty(self):
        agent = ExploitPlannerAgent(MagicMock(), MagicMock(), MagicMock())
        summary = agent.get_plan_summary()
        assert summary["total"] == 0

    def test_prioritize_plans(self):
        agent = ExploitPlannerAgent(MagicMock(), MagicMock(), MagicMock())
        agent._plans = [
            ExploitPlan({"id": "1", "title": "Low Easy", "impact": "low", "difficulty": "easy"}),
            ExploitPlan({"id": "2", "title": "Critical Hard", "impact": "critical", "difficulty": "hard"}),
            ExploitPlan({"id": "3", "title": "Critical Easy", "impact": "critical", "difficulty": "easy"}),
        ]
        result = agent._prioritize_plans()
        assert result[0].title == "Critical Easy"
        assert result[1].title == "Critical Hard"
        assert result[2].title == "Low Easy"


# ── OSINT Agent Upgrade Tests ────────────────────────────────

class TestOsintAgentShodan:
    """Test the Shodan parsing in the OSINT agent."""

    def setup_method(self):
        self.agent = OsintAgent.__new__(OsintAgent)
        self.agent.name = "osint_agent"
        self.agent.logger = MagicMock()
        self.agent.mcp = None
        self.mission_id = "test-mission"

    def test_parse_shodan_host(self):
        shodan_data = json.dumps({
            "ip_str": "93.184.216.34",
            "hostnames": ["example.com"],
            "os": "Linux",
            "org": "Edgecast",
            "isp": "Verizon",
            "country_code": "US",
            "tags": ["cloud"],
            "vulns": ["CVE-2021-44228"],
            "data": [
                {"port": 80, "transport": "tcp", "product": "nginx",
                 "version": "1.21.0", "data": "HTTP/1.1 200 OK",
                 "_shodan": {"module": "http"}},
                {"port": 443, "transport": "tcp", "product": "nginx",
                 "version": "1.21.0", "data": "HTTP/1.1 200 OK",
                 "_shodan": {"module": "https"}},
            ],
        })

        findings = self.agent._parse_shodan(shodan_data, "example.com", self.mission_id)

        # Should have Host + OsintFinding (org) + 2 Ports + 1 Vuln finding
        hosts = [f for f in findings if isinstance(f, Host)]
        ports = [f for f in findings if isinstance(f, Port)]
        osint = [f for f in findings if isinstance(f, OsintFinding)]

        assert len(hosts) == 1
        assert hosts[0].ip == "93.184.216.34"
        assert hosts[0].hostname == "example.com"
        assert hosts[0].os_guess == "Linux"
        assert len(ports) == 2
        assert any(p.port == 80 for p in ports)
        assert any(p.port == 443 for p in ports)
        assert len(osint) >= 2  # org info + vuln

    def test_parse_shodan_search_results(self):
        search_data = json.dumps({
            "matches": [
                {"ip_str": "1.2.3.4", "port": 80, "product": "Apache",
                 "version": "2.4", "org": "Test Corp"},
                {"ip_str": "5.6.7.8", "port": 443, "product": "nginx",
                 "version": "1.21", "org": "Another Corp"},
            ],
        })

        findings = self.agent._parse_shodan(search_data, "test.com", self.mission_id)
        assert len(findings) == 2
        assert all(isinstance(f, OsintFinding) for f in findings)

    def test_parse_shodan_invalid_json(self):
        findings = self.agent._parse_shodan("not json", "test.com", self.mission_id)
        assert findings == []


class TestOsintAgentGithub:
    """Test GitHub dorking parsing."""

    def setup_method(self):
        self.agent = OsintAgent.__new__(OsintAgent)
        self.agent.name = "osint_agent"
        self.agent.logger = MagicMock()
        self.mission_id = "test-mission"

    def test_parse_github_code_results(self):
        github_data = json.dumps({
            "items": [
                {
                    "repository": {"full_name": "test-org/test-repo"},
                    "path": "config/.env",
                    "html_url": "https://github.com/test-org/test-repo/blob/main/config/.env",
                },
                {
                    "repository": {"full_name": "test-org/docs"},
                    "path": "README.md",
                    "html_url": "https://github.com/test-org/docs/blob/main/README.md",
                },
            ],
        })

        findings = self.agent._parse_github(
            github_data, '"test.com" password', "test.com", self.mission_id)

        # .env file should generate 2 findings (match + potential leak)
        # README.md should generate 1 finding (match only)
        assert len(findings) >= 2
        assert all(isinstance(f, OsintFinding) for f in findings)

        # Check credential leak detection
        leak_findings = [f for f in findings if "LEAK" in f.value]
        assert len(leak_findings) >= 1

    def test_parse_github_empty(self):
        findings = self.agent._parse_github(
            json.dumps({"items": []}), "test", "test.com", self.mission_id)
        assert findings == []

    def test_parse_github_invalid_json(self):
        findings = self.agent._parse_github(
            "not json", "test", "test.com", self.mission_id)
        assert findings == []


# ── Integration: Stage Gate → Exploit Planner ────────────────

class TestStageGateUnlock:
    """Test the stage gate → exploit planner unlock flow."""

    def test_gate_pass_unlocks_planner(self):
        """When stage gate passes, exploit planner should be unlockable."""
        from reconforge.orchestrator.stage_gate import StageGate

        original = ExploitPlannerAgent.LOCKED
        try:
            # Simulate gate pass
            gate = StageGate(client=None)
            tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            tmpfile.close()
            store = IntelStore(tmpfile.name)
            mission = MissionState(
                target="test.local", scope=["test.local"])

            # Add data to pass the gate
            mid = mission.mission_id
            store.write(Host(source_agent="t", source_tool="nmap",
                             confidence=0.9, mission_id=mid, ip="10.0.0.1"))
            for port_num in [22, 80, 443]:
                store.write(Port(source_agent="t", source_tool="nmap",
                                 confidence=0.9, mission_id=mid,
                                 host_id="h1", port=port_num, service="http"))
            for cat in ["whois", "cert", "dns"]:
                store.write(OsintFinding(
                    source_agent="t", source_tool="w", confidence=0.8,
                    mission_id=mid, category=cat,
                    value=f"{cat}.test", context="test"))
            for i in range(3):
                store.write(Vulnerability(
                    source_agent="t", source_tool="nuclei", confidence=0.7,
                    mission_id=mid, host_id="10.0.0.1",
                    title=f"Vuln {i}", severity="medium"))
            from reconforge.intel.models import WebPath
            for path in ["/a", "/b", "/c", "/d", "/e"]:
                store.write(WebPath(source_agent="t", source_tool="ffuf",
                                    confidence=0.8, mission_id=mid,
                                    host_id="h1",
                                    url=f"http://10.0.0.1{path}",
                                    status_code=200))

            result = asyncio.get_event_loop().run_until_complete(
                gate.evaluate(store, mission))

            if result.passed:
                ExploitPlannerAgent.unlock()
                assert ExploitPlannerAgent.is_locked() is False

            store.close()
            os.unlink(tmpfile.name)
        finally:
            ExploitPlannerAgent.LOCKED = original


# ── Integration: Full Pipeline ───────────────────────────────

class TestToolBusMcpRouting:
    """Test that ToolBus correctly routes MCP tools."""

    def test_mcp_tools_set(self):
        from reconforge.tools.bus import MCP_TOOLS, PASSIVE_TOOLS, ACTIVE_TOOLS
        assert "shodan" in MCP_TOOLS
        assert "github" in MCP_TOOLS
        assert "web_search" in MCP_TOOLS
        assert "shodan" in PASSIVE_TOOLS
        # Active tools should not include MCP tools
        assert "shodan" not in ACTIVE_TOOLS

    def test_exploit_plan_serialization(self):
        plan = ExploitPlan({
            "id": "EP-001",
            "title": "SQL Injection",
            "attack_chain": ["Identify input", "Craft payload", "Extract data"],
            "difficulty": "moderate",
            "impact": "high",
            "priv_esc_potential": False,
        })
        d = plan.to_dict()
        assert d["title"] == "SQL Injection"
        assert len(d["attack_chain"]) == 3
        assert d["priv_esc_potential"] is False

        # Verify repr
        assert "SQL Injection" in repr(plan)
