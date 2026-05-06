import asyncio
import yaml
from unittest.mock import MagicMock

import pytest

from reconforge.agents.base import BaseAgent
from reconforge.intel.models import MissionState, OutOfScopeError, ToolExecutionError
from reconforge.memory.episodic import EpisodicMemory
from reconforge.tools.bus import ToolBus
from reconforge.tools.executor import ToolExecutor


def make_bus(tmp_path):
    return ToolBus(ToolExecutor(), EpisodicMemory(str(tmp_path / "memory.db")))


def test_url_matches_wildcard_domain(tmp_path):
    mission = MissionState(scope=["*.example.com"])
    make_bus(tmp_path)._assert_in_scope(
        {"target": "https://sub.example.com/path"}, mission)


def test_url_with_port_matches_exact_domain(tmp_path):
    mission = MissionState(scope=["example.com"])
    make_bus(tmp_path)._assert_in_scope(
        {"target": "http://example.com:8080/admin"}, mission)


def test_out_of_scope_subdomain_is_blocked(tmp_path):
    mission = MissionState(
        scope=["*.example.com"], out_of_scope=["blocked.example.com"])
    with pytest.raises(OutOfScopeError):
        make_bus(tmp_path)._assert_in_scope(
            {"target": "https://blocked.example.com/path"}, mission)


def test_out_of_scope_overrides_in_scope(tmp_path):
    mission = MissionState(
        scope=["example.com"], out_of_scope=["*.admin.example.com"])
    with pytest.raises(OutOfScopeError):
        make_bus(tmp_path)._assert_in_scope(
            {"target": "https://dev.admin.example.com"}, mission)


def test_cidr_in_scope_ip_is_allowed(tmp_path):
    mission = MissionState(scope=["10.10.0.0/16"])
    make_bus(tmp_path)._assert_in_scope({"target": "10.10.4.5"}, mission)


def test_cidr_out_of_scope_ip_is_blocked(tmp_path):
    mission = MissionState(
        scope=["10.10.0.0/16"], out_of_scope=["10.10.4.0/24"])
    with pytest.raises(OutOfScopeError):
        make_bus(tmp_path)._assert_in_scope({"target": "10.10.4.5"}, mission)


def test_malformed_url_denied_deterministically(tmp_path):
    mission = MissionState(scope=["example.com"])
    with pytest.raises(OutOfScopeError):
        make_bus(tmp_path)._assert_in_scope({"target": "http://[::1"}, mission)


def test_malformed_ipv6_url_does_not_crash(tmp_path):
    mission = MissionState(scope=["example.com"])
    with pytest.raises(OutOfScopeError):
        make_bus(tmp_path)._assert_in_scope({"target": "http://[::1"}, mission)


def test_malformed_punycode_does_not_crash(tmp_path):
    mission = MissionState(scope=["example.com"])
    with pytest.raises(OutOfScopeError):
        make_bus(tmp_path)._assert_in_scope({"target": "http://\ud800.com"}, mission)


def test_empty_target_denied_for_scoped_tool(tmp_path):
    mission = MissionState(scope=["example.com"])
    with pytest.raises(OutOfScopeError):
        make_bus(tmp_path)._assert_in_scope("whois", {}, mission)


def test_ffuf_url_in_scope_allowed(tmp_path):
    mission = MissionState(scope=["example.com"])
    make_bus(tmp_path)._assert_in_scope(
        "ffuf", {"url": "https://app.example.com/admin"}, mission)


def test_ffuf_url_out_of_scope_blocked(tmp_path):
    mission = MissionState(scope=["example.com"])
    with pytest.raises(OutOfScopeError):
        make_bus(tmp_path)._assert_in_scope(
            "ffuf", {"url": "https://evil.com/admin"}, mission)


def test_target_fields_registry_metadata_is_honored(tmp_path):
    config = yaml.safe_load(open("config/tools.yaml"))
    config["tools"]["custom_tool"] = {
        "binary": "custom_tool",
        "description": "test",
        "opsec_risk": "passive",
        "target_fields": ["endpoint"],
        "allowed_params": {"endpoint": {"type": "string", "required": True}},
        "command_template": "custom_tool {endpoint}",
    }
    cfg = tmp_path / "tools.yaml"
    cfg.write_text(yaml.safe_dump(config))
    bus = ToolBus(ToolExecutor(str(cfg)), EpisodicMemory(str(tmp_path / "m.db")))
    mission = MissionState(scope=["example.com"])
    bus._assert_in_scope("custom_tool", {"endpoint": "https://api.example.com"}, mission)


def test_base_agent_uses_normalized_scope_checks():
    class DummyAgent(BaseAgent):
        async def run(self, task, memory, intel, mission):
            return []

    agent = DummyAgent.__new__(DummyAgent)
    agent.logger = MagicMock()
    mission = MissionState(scope=["*.example.com"])
    agent._assert_in_scope("https://sub.example.com/path", mission)


def test_unknown_tool_is_denied(tmp_path):
    mission = MissionState(active_scan_permitted=True)
    with pytest.raises(PermissionError):
        make_bus(tmp_path)._assert_permitted("made_up_tool", mission)


def test_missing_opsec_risk_denies_execution(tmp_path):
    bus = make_bus(tmp_path)
    bus.tool_registry["bad"] = {"binary": "bad", "allowed_params": {}}
    with pytest.raises(PermissionError):
        bus._assert_permitted("bad", MissionState(active_scan_permitted=True))


def test_invalid_opsec_risk_denies_execution(tmp_path):
    bus = make_bus(tmp_path)
    bus.tool_registry["bad"] = {
        "binary": "bad", "opsec_risk": "banana", "allowed_params": {}}
    with pytest.raises(PermissionError):
        bus._assert_permitted("bad", MissionState(active_scan_permitted=True))


@pytest.mark.parametrize(
    "tool_name",
    ["arjun", "corsy", "searchsploit", "trufflehog", "jwt_tool", "ssrfmap"],
)
def test_intrusive_tools_blocked_in_passive_only_mode(tmp_path, tool_name):
    mission = MissionState(active_scan_permitted=False)
    with pytest.raises(PermissionError):
        make_bus(tmp_path)._assert_permitted(tool_name, mission)


def test_whois_command_does_not_duplicate_target():
    executor = ToolExecutor()
    assert executor._build_command("whois", {"target": "example.com"}) == [
        "whois", "example.com"]


def test_searchsploit_command_does_not_duplicate_executable_or_target():
    executor = ToolExecutor()
    assert executor._build_command("searchsploit", {"target": "apache"}) == [
        "searchsploit", "apache"]


@pytest.mark.parametrize(
    ("tool_name", "params", "expected"),
    [
        ("jwt_tool",
         {"target": "example.com", "token": "header.payload.sig", "mode": "pb"},
         ["jwt_tool", "header.payload.sig", "-M", "pb"]),
        ("graphql_cop",
         {"target": "example.com", "url": "https://example.com/graphql"},
         ["graphql-cop", "-t", "https://example.com/graphql"]),
        ("clairvoyance",
         {"target": "example.com", "url": "https://example.com/graphql"},
         ["clairvoyance", "https://example.com/graphql"]),
        ("arjun",
         {"target": "example.com", "url": "https://example.com", "output_file": "-"},
         ["arjun", "-u", "https://example.com", "-oJ", "-"]),
        ("corsy",
         {"target": "example.com", "url": "https://example.com"},
         ["corsy", "-u", "https://example.com"]),
        ("ssrfmap",
         {"target": "example.com", "request_file": "request.txt",
          "parameter": "url", "module": "readfiles"},
         ["ssrfmap", "-r", "request.txt", "-p", "url", "-m", "readfiles"]),
        ("trufflehog",
         {"target": "example.com", "scan_target": "/tmp/repo",
          "only_verified": True, "json_output": True},
         ["trufflehog", "filesystem", "/tmp/repo", "--only-verified", "--json"]),
        ("nuclei",
         {"target": "example.com", "severity": "critical,high"},
         ["nuclei", "-u", "http://example.com", "-severity", "critical,high", "-jsonl"]),
    ],
)
def test_migrated_tools_build_deterministic_argv(tool_name, params, expected):
    assert ToolExecutor()._build_command(tool_name, params) == expected


@pytest.mark.parametrize(
    "tool_name",
    ["jwt_tool", "graphql_cop", "clairvoyance", "arjun", "corsy",
     "ssrfmap", "trufflehog", "nuclei"],
)
def test_migrated_tools_reject_raw_args(tool_name):
    params = {"target": "example.com", "args": ["other-binary", "--bad"]}
    if tool_name in {"graphql_cop", "clairvoyance", "arjun", "corsy"}:
        params["url"] = "https://example.com"
    if tool_name == "jwt_tool":
        params["token"] = "header.payload.sig"
    if tool_name == "trufflehog":
        params["scan_target"] = "/tmp/repo"

    with pytest.raises(ToolExecutionError):
        ToolExecutor()._build_command(tool_name, params)


def test_no_tools_allow_raw_args_after_migration():
    tools = ToolExecutor().tools_config["tools"]
    assert {
        name for name, config in tools.items()
        if config.get("allow_raw_args")
    } == set()


def test_known_risky_tools_are_not_passive():
    risky = {
        "nmap", "ssrfmap", "trufflehog", "nuclei", "ffuf", "arjun",
        "corsy", "jwt_tool", "graphql_cop", "clairvoyance",
        "searchsploit", "ai_redteam",
    }
    tools = ToolExecutor().tools_config["tools"]
    assert {tool for tool in risky if tools[tool]["opsec_risk"] == "passive"} == set()


def test_every_tool_has_valid_opsec_risk():
    tools = ToolExecutor().tools_config["tools"]
    assert {
        name for name, config in tools.items()
        if config.get("opsec_risk") not in {"passive", "low", "medium", "high"}
    } == set()


def test_raw_argv_rejected_unless_registry_allows_it():
    executor = ToolExecutor()
    with pytest.raises(ToolExecutionError):
        executor._build_command("whois", {
            "target": "example.com",
            "args": ["example.com"],
        })


def test_shell_true_is_not_used(monkeypatch):
    captured = {}

    class Proc:
        returncode = 0

        async def communicate(self):
            return b"ok", b""

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return Proc()

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = asyncio.run(ToolExecutor().run("whois", {"target": "example.com"}))

    assert result.stdout == "ok"
    assert "shell" not in captured["kwargs"]
    assert captured["cmd"] == ("whois", "example.com")
