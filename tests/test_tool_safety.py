import asyncio
import yaml
from unittest.mock import MagicMock

import pytest

from reconforge.agents.base import BaseAgent
from reconforge.intel.models import MissionState, OutOfScopeError, ToolExecutionError
from reconforge.memory.episodic import EpisodicMemory
from reconforge.tools.bus import ToolBus
from reconforge.tools.executor import ToolExecutor
from reconforge.utils.sanitizer import redact_sensitive_output


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
        "searchsploit", "-j", "apache"]


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
        ("ffuf",
         {"url": "https://example.com"},
         ["ffuf", "-u", "https://example.com/FUZZ", "-w",
          "/usr/share/wordlists/dirb/common.txt", "-rate", "0",
          "-json", "-noninteractive"]),
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


@pytest.mark.parametrize(
    ("tool_name", "params"),
    [
        ("httpx", {"target": "example.com", "headers": ["-o", "/tmp/out"]}),
        ("nuclei", {"target": "example.com", "headers": ["-o", "/tmp/out"]}),
        ("ffuf", {"url": "https://example.com", "headers": ["-o", "/tmp/out"]}),
    ],
)
def test_header_argv_lists_are_rejected(tool_name, params):
    with pytest.raises(ToolExecutionError):
        ToolExecutor()._build_command(tool_name, params)


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Test\r\n-o": "safe"},
        {"X-Test": "safe\r\n-o /tmp/out"},
        {"": "safe"},
        {"Bad Header": "safe"},
    ],
)
def test_invalid_header_names_and_crlf_are_rejected(headers):
    with pytest.raises(ToolExecutionError):
        ToolExecutor()._build_command("nuclei", {
            "target": "example.com",
            "headers": headers,
        })


def test_rate_args_are_not_accepted_as_free_form_argv():
    with pytest.raises(ToolExecutionError):
        ToolExecutor()._build_command("nuclei", {
            "target": "example.com",
            "rate_args": ["-o", "/tmp/out"],
        })
    with pytest.raises(ToolExecutionError):
        ToolExecutor()._build_command("nuclei", {
            "target": "example.com",
            "rate_limit": ["-o", "/tmp/out"],
        })


def test_remaining_list_params_reject_unsupported_argv_items():
    with pytest.raises(ToolExecutionError):
        ToolExecutor()._build_command("nmap", {
            "target": "example.com",
            "flags": ["-sV", "-oX", "/tmp/out"],
        })


def test_nuclei_template_args_list_is_not_accepted():
    with pytest.raises(ToolExecutionError):
        ToolExecutor()._build_command("nuclei", {
            "target": "example.com",
            "template_args": ["-o", "/tmp/out"],
        })


def test_nuclei_templates_value_cannot_be_used_as_a_flag():
    with pytest.raises(ToolExecutionError):
        ToolExecutor()._build_command("nuclei", {
            "target": "example.com",
            "templates": "-o",
        })


def test_executor_debug_logs_do_not_include_raw_auth(monkeypatch):
    import reconforge.tools.executor as executor_module

    messages = []

    class Proc:
        returncode = 0

        async def communicate(self):
            return b"ok", b""

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        return Proc()

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(
        executor_module.logger, "debug",
        lambda message: messages.append(str(message)))

    token = "jwt-log-token-7a8b9c"
    cookie = "cookie-log-secret-8d9e0f"
    asyncio.run(ToolExecutor().run(
        "nuclei",
        {
            "target": "example.com",
            "headers": {
                "Authorization": f"Bearer {token}",
                "Cookie": f"sid={cookie}",
            },
        },
        audit_params={
            "target": "example.com",
            "headers": {
                "Authorization": "[REDACTED]",
                "Cookie": "[REDACTED]",
            },
        },
    ))

    combined = "\n".join(messages)
    assert token not in combined
    assert cookie not in combined


def run_executor_with_stderr(monkeypatch, params, stderr):
    import reconforge.tools.executor as executor_module

    warnings = []

    class Proc:
        returncode = 2

        async def communicate(self):
            return b"", stderr.encode()

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        return Proc()

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(
        executor_module.logger, "warning",
        lambda message: warnings.append(str(message)))

    result = asyncio.run(ToolExecutor().run(
        "nuclei",
        params,
        audit_params={"target": params["target"], "headers": "[REDACTED]"},
    ))
    return result, "\n".join(warnings)


def test_executor_stderr_warning_redacts_authorization_header(monkeypatch):
    token = "auth-warning-token-1234567890"
    stderr = (
        "template failed before retry\n"
        f"Authorization: Bearer {token}\n"
        f"debug token {token}\n"
        "request aborted"
    )
    result, warnings = run_executor_with_stderr(
        monkeypatch,
        {
            "target": "example.com",
            "headers": {"Authorization": f"Bearer {token}"},
        },
        stderr,
    )

    assert token not in warnings
    assert token not in result.stderr
    assert "Authorization: Bearer [REDACTED_AUTH]" in warnings
    assert "debug token [REDACTED_SECRET]" in result.stderr
    assert "template failed before retry" in warnings
    assert "request aborted" in result.stderr


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("Authorization: Bearer abc123", "Authorization: Bearer [REDACTED_AUTH]"),
        ("Authorization: Basic abc123", "Authorization: Basic [REDACTED_AUTH]"),
        ("Authorization: opaque-token-value", "Authorization: [REDACTED_AUTH]"),
        ("Authorization: ", "Authorization: [REDACTED_AUTH]"),
    ],
)
def test_authorization_header_redaction_formats(stderr, expected):
    assert redact_sensitive_output(stderr) == expected


def test_executor_stderr_warning_redacts_schemeless_authorization_header(monkeypatch):
    token = "opaque-token-value-1234567890"
    stderr = (
        "template failed before retry\n"
        f"Authorization: {token}\n"
        "request aborted"
    )
    result, warnings = run_executor_with_stderr(
        monkeypatch,
        {"target": "example.com", "headers": {"X-Trace": "debug-context"}},
        stderr,
    )

    assert token not in warnings
    assert token not in result.stderr
    assert "Authorization: [REDACTED_AUTH]" in warnings
    assert "template failed before retry" in warnings
    assert "request aborted" in result.stderr


def test_executor_stderr_warning_redacts_cookie_header(monkeypatch):
    cookie_value = "cookie-warning-secret-1234567890"
    cookie = f"sid={cookie_value}; theme=light"
    stderr = (
        "http replay failed\n"
        f"Cookie: {cookie}\n"
        f"cookie jar sid={cookie_value}\n"
        "status=403"
    )
    result, warnings = run_executor_with_stderr(
        monkeypatch,
        {
            "target": "example.com",
            "headers": {"Cookie": cookie},
        },
        stderr,
    )

    assert cookie not in warnings
    assert cookie not in result.stderr
    assert cookie_value not in warnings
    assert cookie_value not in result.stderr
    assert "Cookie: [REDACTED_COOKIE]" in warnings
    assert "cookie jar sid=[REDACTED_SECRET]" in result.stderr
    assert "http replay failed" in warnings
    assert "status=403" in result.stderr


def test_executor_stderr_warning_redacts_jwt_token(monkeypatch):
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    stderr = f"jwt parse failed for {jwt}; retry disabled"
    result, warnings = run_executor_with_stderr(
        monkeypatch,
        {
            "target": "example.com",
            "headers": {"Authorization": f"Bearer {jwt}"},
        },
        stderr,
    )

    assert jwt not in warnings
    assert jwt not in result.stderr
    assert "[REDACTED_JWT]" in warnings
    assert "jwt parse failed" in warnings
    assert "retry disabled" in result.stderr


def test_executor_stderr_warning_preserves_non_sensitive_text(monkeypatch):
    stderr = "template parse failed at line 12: missing matcher"
    result, warnings = run_executor_with_stderr(
        monkeypatch,
        {"target": "example.com", "headers": {"X-Trace": "debug-context"}},
        stderr,
    )

    assert stderr in warnings
    assert result.stderr == stderr


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
