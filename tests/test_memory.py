"""Tests for Memory system."""

import pytest
from reconforge.intel.models import GateResult, OsintFinding
from reconforge.memory.working import WorkingMemory
from reconforge.memory.episodic import EpisodicMemory


class TestWorkingMemory:
    def test_set_and_get(self, working_memory):
        working_memory.set("key", "value")
        assert working_memory.get("key") == "value"

    def test_token_count(self, working_memory):
        working_memory.set("data", "x" * 4000)
        assert working_memory.token_count() > 0

    def test_needs_compression(self, working_memory):
        working_memory.set("big_data", "x" * 100000)
        assert working_memory.needs_compression()

    def test_update_from_result(self, working_memory, mission):
        finding = OsintFinding(
            source_agent="test", source_tool="whois", confidence=0.9,
            mission_id=mission.mission_id, category="whois",
            value="test.com", context="test context")
        working_memory.update_from_result([finding])
        ctx = working_memory.get_context_for_agent("test_agent")
        assert "OsintFinding" in ctx

    def test_clear(self, working_memory):
        working_memory.set("key", "val")
        working_memory.clear()
        assert working_memory.get("key") is None

    def test_replace_with_summary(self, working_memory):
        working_memory.set("big", "x" * 100000)
        working_memory.replace_with_summary("compressed summary")
        assert working_memory.get("compressed_summary") == "compressed summary"
        assert not working_memory.needs_compression()


class TestEpisodicMemory:
    def test_create_mission(self, episodic_memory):
        episodic_memory.create_mission("test-1", "test.com", {"key": "val"})
        m = episodic_memory.get_mission("test-1")
        assert m is not None
        assert m["target"] == "test.com"

    def test_log_action(self, episodic_memory):
        episodic_memory.create_mission("test-2", "test.com")
        episodic_memory.log_action("whois", {"target": "test.com"},
                                   "output data", "test-2")
        actions = episodic_memory.get_recent_actions("test-2")
        assert len(actions) == 1
        assert actions[0]["tool"] == "whois"

    def test_dedup_check(self, episodic_memory):
        episodic_memory.create_mission("test-3", "test.com")
        episodic_memory.log_action("whois", {"target": "test.com"},
                                   "output", "test-3")
        # Same call should be detected as duplicate
        result = episodic_memory.dedup_check(
            "whois", {"target": "test.com"}, "test-3")
        assert result is not None

    def test_dedup_no_match(self, episodic_memory):
        episodic_memory.create_mission("test-4", "test.com")
        result = episodic_memory.dedup_check(
            "nmap", {"target": "test.com"}, "test-4")
        assert result is None

    def test_summary_storage(self, episodic_memory):
        episodic_memory.create_mission("test-5", "test.com")
        episodic_memory.store_summary("test-5", "summary content", 100)
        result = episodic_memory.get_latest_summary("test-5")
        assert result == "summary content"

    def test_resume_context(self, episodic_memory):
        episodic_memory.create_mission("test-6", "test.com")
        episodic_memory.log_action("whois", {}, "out", "test-6")
        ctx = episodic_memory.get_resume_context("test-6")
        assert ctx["mission"] is not None
        assert len(ctx["recent_actions"]) == 1

    def test_approval_status_defaults_to_safe_values(self, episodic_memory):
        episodic_memory.create_mission("test-7", "test.com")

        status = episodic_memory.get_approval_status("test-7")

        assert status["stage_gate_passed"] is False
        assert status["operator_approved"] is False
        assert status["exploit_planning_approved"] is False

    def test_approve_mission_sets_operator_approval_only(self, episodic_memory):
        episodic_memory.create_mission("test-8", "test.com")

        assert episodic_memory.approve_mission("test-8") is True
        status = episodic_memory.get_approval_status("test-8")

        assert status["operator_approved"] is True
        assert status["stage_gate_passed"] is False
        assert status["exploit_planning_approved"] is False

    def test_exploit_planning_approved_requires_gate_and_operator(self, episodic_memory):
        gate = GateResult(
            passed=True,
            confidence=0.9,
            reason="coverage sufficient",
            requires_operator_approval=True,
        )
        episodic_memory.create_mission("test-9", "test.com")
        episodic_memory.update_mission_control(
            "test-9",
            stage_gate_passed=True,
            stage_gate=gate.model_dump(),
        )
        assert episodic_memory.get_approval_status("test-9")[
            "exploit_planning_approved"
        ] is False

        episodic_memory.approve_mission("test-9")

        assert episodic_memory.get_approval_status("test-9")[
            "exploit_planning_approved"
        ] is True
