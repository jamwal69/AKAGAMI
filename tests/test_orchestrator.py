"""Tests for Orchestrator and TaskCoordinationGraph."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from reconforge.intel.models import (
    GateResult,
    MissionState,
    MissionMode,
    OsintFinding,
    ReviewResult,
    ReviewVerdict,
    SecretFinding,
    Task,
    TaskStatus,
    Vulnerability,
    WebPath,
)
from reconforge.agents.exploit_planner import ExploitPlannerAgent
from reconforge.orchestrator.master import MAX_TASK_RETRIES, MasterOrchestrator
from reconforge.orchestrator.task_graph import TaskCoordinationGraph


class TestTaskGraph:
    def test_load_tasks(self):
        graph = TaskCoordinationGraph()
        tasks = [
            Task(id="t1", agent_type="osint", tool="whois", params={}),
            Task(id="t2", agent_type="osint", tool="crt_sh", params={}, depends_on=["t1"]),
        ]
        graph.load(tasks)
        assert len(graph.tasks) == 2

    def test_get_ready_tasks_no_deps(self):
        graph = TaskCoordinationGraph()
        graph.load([
            Task(id="t1", agent_type="osint", tool="whois", params={}),
            Task(id="t2", agent_type="osint", tool="crt_sh", params={}),
        ])
        ready = graph.get_ready_tasks()
        assert len(ready) == 2

    def test_get_ready_tasks_with_deps(self):
        graph = TaskCoordinationGraph()
        graph.load([
            Task(id="t1", agent_type="osint", tool="whois", params={}),
            Task(id="t2", agent_type="osint", tool="crt_sh", params={}, depends_on=["t1"]),
        ])
        ready = graph.get_ready_tasks()
        assert len(ready) == 1
        assert ready[0].id == "t1"

    def test_dependency_unlock(self):
        graph = TaskCoordinationGraph()
        graph.load([
            Task(id="t1", agent_type="osint", tool="whois", params={}),
            Task(id="t2", agent_type="osint", tool="crt_sh", params={}, depends_on=["t1"]),
        ])
        graph.mark_complete("t1")
        ready = graph.get_ready_tasks()
        assert len(ready) == 1
        assert ready[0].id == "t2"

    def test_failed_prerequisite_does_not_unlock_dependent_task(self):
        graph = TaskCoordinationGraph()
        graph.load([
            Task(id="t1", agent_type="osint", tool="whois", params={}),
            Task(id="t2", agent_type="osint", tool="crt_sh", params={}, depends_on=["t1"]),
        ])
        graph.mark_failed("t1", "error")
        assert graph.get_ready_tasks() == []
        assert graph.tasks["t2"].status == TaskStatus.BLOCKED

    def test_failed_then_retried_then_successful_unlocks_dependent_task(self):
        graph = TaskCoordinationGraph()
        graph.load([
            Task(id="t1", agent_type="osint", tool="whois", params={}),
            Task(id="t2", agent_type="osint", tool="crt_sh", params={}, depends_on=["t1"]),
        ])
        graph.mark_failed("t1", "timeout")
        assert graph.tasks["t2"].status == TaskStatus.BLOCKED
        graph.mark_pending("t1")
        assert graph.tasks["t2"].status == TaskStatus.PENDING
        assert graph.get_ready_tasks() == [graph.tasks["t1"]]
        graph.mark_complete("t1")
        assert [t.id for t in graph.get_ready_tasks()] == ["t2"]

    def test_permanently_failed_prerequisite_keeps_dependent_blocked(self):
        graph = TaskCoordinationGraph()
        graph.load([
            Task(id="t1", agent_type="osint", tool="whois", params={}),
            Task(id="t2", agent_type="osint", tool="crt_sh", params={}, depends_on=["t1"]),
        ])
        graph.mark_failed("t1", "fatal")
        assert graph.is_complete()
        assert graph.tasks["t2"].status == TaskStatus.BLOCKED

    def test_is_complete(self):
        graph = TaskCoordinationGraph()
        graph.load([Task(id="t1", agent_type="osint", tool="whois", params={})])
        assert not graph.is_complete()
        graph.mark_complete("t1")
        assert graph.is_complete()

    def test_failed_tasks_count_as_complete(self):
        graph = TaskCoordinationGraph()
        graph.load([Task(id="t1", agent_type="osint", tool="whois", params={})])
        graph.mark_failed("t1", "error")
        assert graph.is_complete()

    def test_status_summary(self):
        graph = TaskCoordinationGraph()
        graph.load([
            Task(id="t1", agent_type="osint", tool="whois", params={}),
            Task(id="t2", agent_type="osint", tool="crt_sh", params={}),
        ])
        graph.mark_complete("t1")
        summary = graph.get_status_summary()
        assert summary["complete"] == 1
        assert summary["pending"] == 1

    def test_priority_ordering(self):
        graph = TaskCoordinationGraph()
        graph.load([
            Task(id="t1", agent_type="osint", tool="whois", params={}, priority=3),
            Task(id="t2", agent_type="osint", tool="crt_sh", params={}, priority=1),
        ])
        ready = graph.get_ready_tasks()
        assert ready[0].id == "t2"  # Higher priority first

    def test_serialize(self):
        graph = TaskCoordinationGraph()
        graph.load([Task(id="t1", agent_type="osint", tool="whois", params={})])
        serialized = graph.serialize()
        assert len(serialized) == 1
        assert serialized[0]["id"] == "t1"

    def test_load_from_dicts(self):
        graph = TaskCoordinationGraph()
        graph.load([{"id": "t1", "agent_type": "osint", "tool": "whois", "params": {}}])
        assert "t1" in graph.tasks


class TestMasterOrchestratorScheduling:
    def make_orchestrator(self, active=False):
        orch = MasterOrchestrator.__new__(MasterOrchestrator)
        orch.mission = MissionState(
            target="example.com",
            scope=["example.com"],
            active_scan_permitted=active,
        )
        orch.task_graph = TaskCoordinationGraph()
        orch.task_queue = asyncio.Queue()
        orch._queued_task_ids = set()
        orch._task_fingerprints = set()
        orch._task_retries = {}
        orch.agents = {}
        orch.intel = MagicMock()
        orch.intel.store = MagicMock()
        orch.memory = MagicMock()
        orch.memory.update_from_result = MagicMock()
        orch.episodic = MagicMock()
        orch.event_bus = MagicMock()
        orch.event_bus.publish = AsyncMock()
        orch.critic = MagicMock()
        return orch

    def run(self, coro):
        loop = getattr(self, "_loop", None)
        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
        return loop.run_until_complete(coro)

    def test_dependent_tasks_do_not_run_before_prerequisites(self):
        orch = self.make_orchestrator(active=False)
        tasks = [
            Task(id="t1", agent_type="osint", tool="whois",
                 params={"target": "example.com"}, opsec_risk="passive"),
            Task(id="t2", agent_type="osint", tool="crt_sh",
                 params={"target": "example.com"}, depends_on=["t1"],
                 opsec_risk="passive"),
        ]
        orch.task_graph.load(tasks)
        orch._register_task_fingerprints(tasks)

        queued = self.run(orch._enqueue_ready_tasks())

        assert queued == 1
        assert orch.task_queue.qsize() == 1
        assert orch.task_queue.get_nowait().id == "t1"

    def test_completed_tasks_unlock_dependents(self):
        orch = self.make_orchestrator(active=False)
        tasks = [
            Task(id="t1", agent_type="osint", tool="whois",
                 params={"target": "example.com"}, opsec_risk="passive"),
            Task(id="t2", agent_type="osint", tool="crt_sh",
                 params={"target": "example.com"}, depends_on=["t1"],
                 opsec_risk="passive"),
        ]
        orch.task_graph.load(tasks)
        orch._register_task_fingerprints(tasks)

        orch.task_graph.mark_running("t1")
        orch.task_graph.mark_complete("t1")
        queued = self.run(orch._enqueue_ready_tasks())

        assert queued == 1
        assert orch.task_queue.get_nowait().id == "t2"

    def test_failed_task_corrected_by_self_correction_is_retried(self):
        orch = self.make_orchestrator(active=False)
        task = Task(id="t1", agent_type="osint", tool="theharvester",
                    params={"target": "example.com", "domain": "example.com",
                            "source": "all"},
                    opsec_risk="passive")
        corrected = Task(id="t1", agent_type="osint", tool="theharvester",
                         params={"target": "example.com", "domain": "example.com",
                                 "source": "bing"},
                         opsec_risk="passive")
        orch.task_graph.load([task])
        orch._register_task_fingerprints([task])
        orch.agents = {"osint": MagicMock()}
        orch.agents["osint"].run = AsyncMock(side_effect=RuntimeError("timeout"))
        orch._self_correct = AsyncMock(return_value=corrected)

        self.run(orch._execute_task(task))

        assert orch._task_retries["t1"] == 1
        assert orch.task_graph.tasks["t1"].status == TaskStatus.PENDING
        assert orch.task_queue.qsize() == 1
        assert orch.task_queue.get_nowait().params["source"] == "bing"

    def test_failed_tasks_do_not_retry_forever(self):
        orch = self.make_orchestrator(active=False)
        task = Task(id="t1", agent_type="osint", tool="whois",
                    params={"target": "example.com"}, opsec_risk="passive")
        orch.task_graph.load([task])
        orch._register_task_fingerprints([task])
        orch._task_retries["t1"] = MAX_TASK_RETRIES
        orch.agents = {"osint": MagicMock()}
        orch.agents["osint"].run = AsyncMock(side_effect=RuntimeError("timeout"))
        orch._self_correct = AsyncMock()

        self.run(orch._execute_task(task))

        assert orch._self_correct.await_count == 0
        assert orch.task_graph.tasks["t1"].status == TaskStatus.FAILED
        assert orch.task_queue.qsize() == 0

    def test_quarantined_findings_are_retained_unverified_without_events(self):
        orch = self.make_orchestrator(active=False)
        task = Task(id="t1", agent_type="osint", tool="whois",
                    params={"target": "example.com"}, opsec_risk="passive")
        finding = OsintFinding(
            source_agent="osint",
            source_tool="whois",
            confidence=0.8,
            mission_id=orch.mission.mission_id,
            category="whois",
            value="example.com",
            context="registrant data",
        )
        review = ReviewResult(
            verdict=ReviewVerdict.QUARANTINE,
            reason="critic unavailable",
            improved_finding={"verified": False, "confidence": 0.55},
        )
        orch.task_graph.load([task])
        orch._register_task_fingerprints([task])
        orch.agents = {"osint": MagicMock()}
        orch.agents["osint"].run = AsyncMock(return_value=[finding])
        orch.critic.review_batch = AsyncMock(return_value=[(finding, review)])

        self.run(orch._execute_task(task))

        retained = orch.intel.store.call_args.args[0]
        assert len(retained) == 1
        assert retained[0].verified is False
        assert retained[0].confidence == 0.55
        assert orch.task_graph.tasks["t1"].status == TaskStatus.COMPLETE
        orch.event_bus.publish.assert_not_awaited()

    def test_approved_vulnerabilities_are_enriched_and_scored_before_storage(self):
        orch = self.make_orchestrator(active=True)
        task = Task(id="t1", agent_type="vuln", tool="nuclei",
                    params={"target": "example.com"}, opsec_risk="medium")
        finding = Vulnerability(
            source_agent="vuln",
            source_tool="nuclei",
            confidence=0.8,
            mission_id=orch.mission.mission_id,
            host_id="example.com",
            title="Apache path traversal",
            severity="info",
            evidence="matched template",
        )

        async def enrich(vuln):
            vuln.cve_id = "CVE-2021-41773"
            vuln.cvss_score = 9.8
            return vuln

        async def score(vuln, context):
            vuln.severity = "critical"
            return vuln

        orch.task_graph.load([task])
        orch._register_task_fingerprints([task])
        orch.agents = {"vuln": MagicMock()}
        orch.agents["vuln"].run = AsyncMock(return_value=[finding])
        orch.critic.review_batch = AsyncMock(return_value=[(
            finding,
            ReviewResult(verdict=ReviewVerdict.APPROVE),
        )])
        orch.enricher = MagicMock()
        orch.enricher.enrich = AsyncMock(side_effect=enrich)
        orch.scorer = MagicMock()
        orch.scorer.score = AsyncMock(side_effect=score)

        self.run(orch._execute_task(task))

        stored = orch.intel.store.call_args.args[0]
        assert len(stored) == 1
        assert stored[0].verified is True
        assert stored[0].cve_id == "CVE-2021-41773"
        assert stored[0].cvss_score == 9.8
        assert stored[0].severity == "critical"
        orch.enricher.enrich.assert_awaited_once()
        orch.scorer.score.assert_awaited_once()

    def test_vulnerability_post_processing_failures_do_not_fail_task(self):
        orch = self.make_orchestrator(active=True)
        task = Task(id="t1", agent_type="vuln", tool="nuclei",
                    params={"target": "example.com"}, opsec_risk="medium")
        finding = Vulnerability(
            source_agent="vuln",
            source_tool="nuclei",
            confidence=0.8,
            mission_id=orch.mission.mission_id,
            host_id="example.com",
            title="Weak TLS",
            severity="medium",
            evidence="scanner output",
        )
        orch.task_graph.load([task])
        orch._register_task_fingerprints([task])
        orch.agents = {"vuln": MagicMock()}
        orch.agents["vuln"].run = AsyncMock(return_value=[finding])
        orch.critic.review_batch = AsyncMock(return_value=[(
            finding,
            ReviewResult(verdict=ReviewVerdict.APPROVE),
        )])
        orch.enricher = MagicMock()
        orch.enricher.enrich = AsyncMock(side_effect=RuntimeError("nvd down"))
        orch.scorer = MagicMock()
        orch.scorer.score = AsyncMock(side_effect=RuntimeError("scorer down"))

        self.run(orch._execute_task(task))

        stored = orch.intel.store.call_args.args[0]
        assert len(stored) == 1
        assert stored[0].title == "Weak TLS"
        assert orch.task_graph.tasks["t1"].status == TaskStatus.COMPLETE

    def test_dynamic_exploit_task_is_queued_when_ready(self):
        orch = self.make_orchestrator(active=False)
        task = Task(id="exploit-now", agent_type="exploit_planner",
                    tool="plan_exploits", params={"target": "example.com"},
                    opsec_risk="passive")

        added = self.run(orch._add_dynamic_task(task))

        assert added is True
        assert "exploit-now" in orch.task_graph.tasks
        assert orch.task_queue.qsize() == 1
        assert orch.task_queue.get_nowait().id == "exploit-now"

    def test_llm_generated_unknown_tools_are_rejected(self):
        orch = self.make_orchestrator(active=True)

        tasks = orch._validated_tasks_from_llm([{
            "id": "bad-tool",
            "agent_type": "osint",
            "tool": "curl_shell",
            "params": {"target": "example.com"},
            "opsec_risk": "passive",
        }])

        assert tasks == []

    def test_active_tasks_are_rejected_in_passive_only_mode(self):
        orch = self.make_orchestrator(active=False)

        tasks = orch._validated_tasks_from_llm([{
            "id": "active-httpx",
            "agent_type": "recon",
            "tool": "httpx",
            "params": {"target": "example.com"},
            "opsec_risk": "low",
        }])

        assert tasks == []

    def test_validation_rejects_searchsploit_in_passive_only_from_yaml_risk(self):
        orch = self.make_orchestrator(active=False)
        task = Task(id="sploit", agent_type="vuln", tool="searchsploit",
                    params={"target": "Apache 2.4"}, opsec_risk="passive")
        assert orch._validate_task(task) is False

    def test_validation_and_toolbus_risk_metadata_match_for_registered_tools(self):
        orch = self.make_orchestrator(active=False)
        registry = orch._tool_registry_for_validation()
        for tool_name, tool_def in registry.items():
            task = Task(id=f"t-{tool_name}", agent_type="osint",
                        tool=tool_name, params={}, opsec_risk=tool_def["opsec_risk"])
            assert orch._tool_risk(task) == tool_def["opsec_risk"]

    def test_self_correction_cannot_change_target(self):
        orch = self.make_orchestrator(active=False)
        original = Task(id="t1", agent_type="osint", tool="whois",
                        params={"target": "example.com"}, opsec_risk="passive")
        corrected = Task(id="t1", agent_type="osint", tool="whois",
                         params={"target": "evil.com"}, opsec_risk="passive")
        assert orch._safe_corrected_task(original, corrected) is None

    def test_self_correction_cannot_change_passive_tool_to_active_tool(self):
        orch = self.make_orchestrator(active=True)
        original = Task(id="t1", agent_type="osint", tool="whois",
                        params={"target": "example.com"}, opsec_risk="passive")
        corrected = Task(id="t1", agent_type="recon", tool="nmap",
                         params={"target": "example.com"}, opsec_risk="medium")
        assert orch._safe_corrected_task(original, corrected) is None

    def test_self_correction_cannot_change_agent_type_to_forbidden_agent(self):
        orch = self.make_orchestrator(active=False)
        original = Task(id="t1", agent_type="osint", tool="whois",
                        params={"target": "example.com"}, opsec_risk="passive")
        corrected = Task(id="t1", agent_type="browser", tool="browser",
                         params={"target": "example.com"}, opsec_risk="passive")
        assert orch._safe_corrected_task(original, corrected) is None

    def test_duplicate_tasks_are_not_enqueued(self):
        orch = self.make_orchestrator(active=False)
        task = Task(id="t1", agent_type="osint", tool="whois",
                    params={"target": "example.com"}, opsec_risk="passive")
        orch.task_graph.load([task])
        orch._register_task_fingerprints([task])

        first = self.run(orch._enqueue_ready_tasks())
        second = self.run(orch._enqueue_ready_tasks())

        assert first == 1
        assert second == 0
        assert orch.task_queue.qsize() == 1

    def test_duplicate_dynamic_tasks_are_not_added_or_enqueued(self):
        orch = self.make_orchestrator(active=False)
        task = Task(id="exploit-now", agent_type="exploit_planner",
                    tool="plan_exploits", params={"target": "example.com"},
                    opsec_risk="passive")

        assert self.run(orch._add_dynamic_task(task)) is True
        assert self.run(orch._add_dynamic_task(task)) is False
        assert orch.task_queue.qsize() == 1

    def test_evaluate_attack_paths_reads_typed_models(self, intel_store, mission):
        orch = self.make_orchestrator(active=True)
        orch.mission = mission
        orch.intel = intel_store
        orch.chainer = MagicMock()
        orch.chainer.evaluate_chain = AsyncMock(return_value=None)

        intel_store.write(Vulnerability(
            source_agent="vuln",
            source_tool="nuclei",
            confidence=0.8,
            mission_id=mission.mission_id,
            host_id="10.0.0.1",
            title="Missing HSTS",
            severity="info",
            evidence="nuclei output",
        ))
        intel_store.write(OsintFinding(
            source_agent="osint",
            source_tool="whois",
            confidence=0.8,
            mission_id=mission.mission_id,
            category="whois",
            value="example.com",
            context="registrant",
        ))
        intel_store.write(SecretFinding(
            source_agent="js_agent",
            source_tool="trufflehog",
            confidence=0.9,
            mission_id=mission.mission_id,
            host_id="app.example.com",
            file_path="app.js",
            secret_type="api_key",
            secret_value="redacted-in-test",
            is_verified=True,
        ))
        intel_store.write(WebPath(
            source_agent="recon",
            source_tool="ffuf",
            confidence=0.8,
            mission_id=mission.mission_id,
            host_id="app.example.com",
            url="https://app.example.com/admin",
            status_code=200,
            interesting=True,
        ))

        self.run(orch._evaluate_attack_paths())

        findings = orch.chainer.evaluate_chain.await_args.args[0]
        assert any(isinstance(f, Vulnerability) for f in findings)
        assert any(isinstance(f, OsintFinding) for f in findings)
        assert any(isinstance(f, SecretFinding) for f in findings)
        assert any(isinstance(f, WebPath) for f in findings)

    def test_standard_mode_gate_pass_does_not_unlock_without_operator_approval(self):
        orch = self.make_orchestrator(active=True)
        orch.mission.operator_approved = False
        orch.mission.mode = MissionMode.STANDARD
        gate = GateResult(passed=True, requires_operator_approval=True)
        original = ExploitPlannerAgent.LOCKED
        try:
            ExploitPlannerAgent.lock()
            if orch._operator_may_unlock_exploits(gate):
                ExploitPlannerAgent.unlock()
            assert ExploitPlannerAgent.is_locked() is True
        finally:
            ExploitPlannerAgent.LOCKED = original

    def test_standard_mode_gate_pass_unlocks_with_operator_approval(self):
        orch = self.make_orchestrator(active=True)
        orch.mission.operator_approved = True
        orch.mission.mode = MissionMode.STANDARD
        gate = GateResult(passed=True, requires_operator_approval=True)
        original = ExploitPlannerAgent.LOCKED
        try:
            ExploitPlannerAgent.lock()
            if orch._operator_may_unlock_exploits(gate):
                ExploitPlannerAgent.unlock()
            assert ExploitPlannerAgent.is_locked() is False
        finally:
            ExploitPlannerAgent.LOCKED = original

    def test_operator_approval_after_gate_pass_can_unlock_planner(self):
        orch = self.make_orchestrator(active=True)
        orch.mission.stage_gate_passed = True
        orch.mission.operator_approved = True
        orch.mission.mode = MissionMode.STANDARD
        gate = GateResult(passed=True, requires_operator_approval=True)
        original = ExploitPlannerAgent.LOCKED
        try:
            ExploitPlannerAgent.lock()
            assert orch._unlock_exploits_if_allowed(gate) is True
            assert ExploitPlannerAgent.is_locked() is False
        finally:
            ExploitPlannerAgent.LOCKED = original
