"""Tests for runtime-only authenticated scan handoff."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

from reconforge.agents.browser import BrowserAgent
from reconforge.agents.vuln import VulnAnalysisAgent
from reconforge.intel.models import MissionState, SessionContext, ToolResult
from reconforge.intel.store import IntelStore
from reconforge.memory.episodic import EpisodicMemory
from reconforge.memory.working import WorkingMemory
from reconforge.tools.bus import ToolBus
from reconforge.tools.executor import ToolExecutor


def run_async(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def test_browser_runtime_auth_is_available_to_nuclei_scan():
    memory = WorkingMemory()
    mission = MissionState(
        target="app.example.com",
        scope=["example.com", "*.example.com"],
        active_scan_permitted=True,
    )
    raw_token = "jwt-runtime-token-8a8bd2"
    raw_cookie = "session-cookie-f0f02d"

    browser = BrowserAgent.__new__(BrowserAgent)
    browser.name = "browser_agent"
    browser._remember_runtime_auth_context(
        memory,
        mission,
        "app.example.com",
        [{"name": "sid", "value": raw_cookie, "domain": "app.example.com"}],
        {},
        {},
        [raw_token],
        {"Authorization": f"Bearer {raw_token}"},
    )

    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.name = "vuln_agent"
    agent.logger = MagicMock()
    agent.memory = memory
    agent.tool_bus = MagicMock()
    raw = '{"info":{"name":"Auth check","severity":"low"},"host":"https://app.example.com","matched-at":"https://app.example.com"}\n'
    agent.tool_bus.call = AsyncMock(return_value=ToolResult(
        tool="nuclei", params={}, raw=raw, clean=raw, exit_code=0))

    findings = run_async(agent._run_nuclei("https://app.example.com", {}, mission))

    params = agent.tool_bus.call.await_args.args[1]
    assert len(findings) == 1
    assert params["headers"]["Authorization"] == f"Bearer {raw_token}"
    assert params["headers"]["Cookie"] == f"sid={raw_cookie}"


def test_runtime_auth_is_excluded_from_working_memory_summaries():
    memory = WorkingMemory()
    raw_token = "runtime-summary-token-3d459b"
    memory.set_sensitive("runtime_auth_contexts", [{
        "mission_id": "m1",
        "host_id": "app.example.com",
        "auth_headers": {"Authorization": f"Bearer {raw_token}"},
    }])

    assert raw_token not in memory.get_summary_for_compression()
    assert raw_token not in memory.get_context_for_agent("vuln")
    assert raw_token not in str(memory.token_count())


def test_redacted_session_context_persistence_does_not_store_raw_auth(tmp_path):
    raw_token = "persist-token-078a28"
    raw_cookie = "persist-cookie-97ba6f"
    mission = MissionState(target="app.example.com", scope=["*.example.com"])
    store = IntelStore(str(tmp_path / "intel.db"))
    browser = BrowserAgent.__new__(BrowserAgent)
    try:
        session = SessionContext(
            source_agent="browser_agent",
            source_tool="playwright",
            confidence=0.9,
            mission_id=mission.mission_id,
            host_id="app.example.com",
            cookies=browser._redacted_cookies([
                {"name": "sid", "value": raw_cookie, "domain": "app.example.com"}
            ]),
            jwt_tokens=[],
            auth_headers=browser._redacted_auth_headers({
                "Authorization": f"Bearer {raw_token}"
            }),
        )
        store.store([session])

        row_blob = json.dumps(store.session_contexts(mission.mission_id))
        model_blob = json.dumps(
            [item.model_dump(mode="json") for item in store._read_all(
                SessionContext, mission.mission_id)]
        )
        assert raw_token not in row_blob
        assert raw_cookie not in row_blob
        assert raw_token not in model_blob
        assert raw_cookie not in model_blob
        assert "[REDACTED]" in row_blob
    finally:
        store.close()


def test_toolbus_audit_params_do_not_persist_raw_auth(tmp_path):
    bus = ToolBus(
        ToolExecutor(),
        EpisodicMemory(str(tmp_path / "episodic.db")),
    )
    raw_token = "audit-token-912d1e"
    raw_cookie = "audit-cookie-6ff143"

    audited = bus._audit_params({
        "target": "app.example.com",
        "headers": {
            "Authorization": f"Bearer {raw_token}",
            "Cookie": f"sid={raw_cookie}",
        },
    })

    encoded = json.dumps(audited)
    assert raw_token not in encoded
    assert raw_cookie not in encoded
    assert "[REDACTED:" in encoded


def test_jwt_tool_echoed_token_is_redacted_from_vulnerability():
    memory = WorkingMemory()
    mission = MissionState(
        target="app.example.com",
        scope=["example.com", "*.example.com"],
        active_scan_permitted=True,
    )
    raw_token = "header.jwt-echo-token-314159.signature"
    memory.set_sensitive("runtime_auth_contexts", [{
        "mission_id": mission.mission_id,
        "host_id": "app.example.com",
        "jwt_tokens": [raw_token],
    }])

    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.name = "vuln_agent"
    agent.logger = MagicMock()
    agent.memory = memory
    agent.tool_bus = MagicMock()
    raw = f"Vulnerability found: Weak secret for token {raw_token}"
    agent.tool_bus.call = AsyncMock(return_value=ToolResult(
        tool="jwt_tool", params={}, raw=raw, clean=raw, exit_code=0))

    findings = run_async(agent._run_jwt_tool(
        "app.example.com", {}, memory, mission))

    assert len(findings) == 1
    assert raw_token not in findings[0].evidence
    assert raw_token not in findings[0].raw_output
    assert "[REDACTED_JWT]" in findings[0].evidence
    assert "[REDACTED_JWT]" in findings[0].raw_output
