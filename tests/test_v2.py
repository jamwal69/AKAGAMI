"""Tests for all deterministic parsers. No mocks. No network. No LLM."""

import asyncio
import pytest
from reconforge.parsers.nmap_parser import NmapParser
from reconforge.parsers.nuclei_parser import NucleiParser
from reconforge.parsers.httpx_parser import HttpxParser
from reconforge.parsers.amass_parser import AmassParser
from reconforge.parsers.ffuf_parser import FfufParser
from reconforge.parsers.theharvester_parser import TheHarvesterParser
from reconforge.intel.models import Host, Port, Vulnerability, Subdomain, WebPath, OsintFinding

MID = "test-mission"
AGENT = "test-agent"

# ── NmapParser ────────────────────────────────────────────────

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="web.example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.52"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Apache" version="2.4.52"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="filtered"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

class TestNmapParser:
    def test_parses_host(self):
        results = NmapParser().parse(NMAP_XML, MID, AGENT)
        hosts = [r for r in results if isinstance(r, Host)]
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"
        assert hosts[0].hostname == "web.example.com"

    def test_parses_open_ports_only(self):
        results = NmapParser().parse(NMAP_XML, MID, AGENT)
        ports = [r for r in results if isinstance(r, Port)]
        assert len(ports) == 2  # filtered port excluded
        port_nums = {p.port for p in ports}
        assert port_nums == {80, 443}
        assert 22 not in port_nums

    def test_port_service_version(self):
        results = NmapParser().parse(NMAP_XML, MID, AGENT)
        ports = [r for r in results if isinstance(r, Port)]
        p80 = next(p for p in ports if p.port == 80)
        assert p80.service == "http"
        assert "Apache" in p80.version
        assert "2.4.52" in p80.version

    def test_empty_input_returns_empty(self):
        assert NmapParser().parse("", MID, AGENT) == []

    def test_invalid_xml_returns_empty(self):
        assert NmapParser().parse("not xml at all ><><", MID, AGENT) == []

    def test_down_host_excluded(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="down"/><address addr="1.2.3.4" addrtype="ipv4"/>
  <ports/></host>
</nmaprun>"""
        results = NmapParser().parse(xml, MID, AGENT)
        hosts = [r for r in results if isinstance(r, Host)]
        assert len(hosts) == 0


# ── NucleiParser ──────────────────────────────────────────────

NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-41773","info":{"name":"Apache Path Traversal",'
    '"severity":"critical","description":"Path traversal in Apache 2.4.49",'
    '"classification":{"cve-id":"CVE-2021-41773","cvss-score":"9.8"}},'
    '"host":"http://10.0.0.1","matched-at":"http://10.0.0.1/cgi-bin/.%2e/"}\n'
    '{"template-id":"http-missing-hsts","info":{"name":"Missing HSTS",'
    '"severity":"info","description":"HSTS header missing"},'
    '"host":"http://10.0.0.1","matched-at":"http://10.0.0.1/"}\n'
)

class TestNucleiParser:
    def test_parses_two_vulns(self):
        results = NucleiParser().parse(NUCLEI_JSONL, MID, AGENT)
        assert len(results) == 2

    def test_cve_extracted(self):
        results = NucleiParser().parse(NUCLEI_JSONL, MID, AGENT)
        vulns = [r for r in results if isinstance(r, Vulnerability)]
        critical = next(v for v in vulns if v.severity == "critical")
        assert critical.cve_id == "CVE-2021-41773"
        assert critical.cvss_score == 9.8
        assert critical.title == "Apache Path Traversal"

    def test_empty_returns_empty(self):
        assert NucleiParser().parse("", MID, AGENT) == []

    def test_non_json_lines_skipped(self):
        raw = "not json\n{\"info\":{\"name\":\"X\",\"severity\":\"low\"},\"host\":\"h\",\"matched-at\":\"u\"}\n"
        results = NucleiParser().parse(raw, MID, AGENT)
        assert len(results) == 1


# ── HttpxParser ───────────────────────────────────────────────

HTTPX_JSONL = (
    '{"url":"http://10.0.0.1/","status_code":200,"title":"Apache Default",'
    '"tech":["Apache"],"a":["10.0.0.1"]}\n'
    '{"url":"http://10.0.0.1/admin","status_code":403,"title":"Forbidden"}\n'
    '{"url":"http://10.0.0.1/.git","status_code":200,"title":"Index"}\n'
)

class TestHttpxParser:
    def test_produces_web_paths(self):
        results = HttpxParser().parse(HTTPX_JSONL, MID, AGENT)
        paths = [r for r in results if isinstance(r, WebPath)]
        assert len(paths) == 3

    def test_admin_403_is_interesting(self):
        results = HttpxParser().parse(HTTPX_JSONL, MID, AGENT)
        paths = [r for r in results if isinstance(r, WebPath)]
        admin = next(p for p in paths if "admin" in p.url)
        assert admin.interesting is True
        assert "auth" in admin.reason

    def test_git_path_is_interesting(self):
        results = HttpxParser().parse(HTTPX_JSONL, MID, AGENT)
        paths = [r for r in results if isinstance(r, WebPath)]
        git = next(p for p in paths if ".git" in p.url)
        assert git.interesting is True

    def test_produces_subdomain_with_tech(self):
        results = HttpxParser().parse(HTTPX_JSONL, MID, AGENT)
        subs = [r for r in results if isinstance(r, Subdomain)]
        assert len(subs) >= 1
        root = next((s for s in subs if s.domain == "10.0.0.1"), None)
        assert root is not None
        assert "Apache" in root.technologies

    def test_empty_returns_empty(self):
        assert HttpxParser().parse("", MID, AGENT) == []


# ── AmassParser ───────────────────────────────────────────────

AMASS_JSONL = (
    '{"name":"api.example.com","addresses":[{"ip":"1.2.3.4"}]}\n'
    '{"name":"mail.example.com","addresses":[{"ip":"1.2.3.5"}]}\n'
    '{"name":"www.example.com","addresses":[]}\n'
)

class TestAmassParser:
    def test_parses_three_subdomains(self):
        results = AmassParser().parse(AMASS_JSONL, MID, AGENT)
        subs = [r for r in results if isinstance(r, Subdomain)]
        assert len(subs) == 3

    def test_ip_extracted(self):
        results = AmassParser().parse(AMASS_JSONL, MID, AGENT)
        subs = [r for r in results if isinstance(r, Subdomain)]
        api = next(s for s in subs if s.domain == "api.example.com")
        assert api.ip == "1.2.3.4"

    def test_plain_text_fallback(self):
        plain = "sub1.example.com\nsub2.example.com\nnot-a-domain\n"
        results = AmassParser().parse(plain, MID, AGENT)
        subs = [r for r in results if isinstance(r, Subdomain)]
        assert len(subs) == 2

    def test_empty_returns_empty(self):
        assert AmassParser().parse("", MID, AGENT) == []


# ── FfufParser ────────────────────────────────────────────────

FFUF_JSON = """{
  "results": [
    {"url": "http://10.0.0.1/admin", "status": 200, "length": 5400},
    {"url": "http://10.0.0.1/config.php", "status": 403, "length": 512},
    {"url": "http://10.0.0.1/secret", "status": 200, "length": 42}
  ]
}"""

FFUF_JSONL = (
    '{"url":"http://10.0.0.1/admin","status":200,"length":5400}\n'
    '{"url":"http://10.0.0.1/config.php","status":403,"length":512}\n'
)

class TestFfufParser:
    def test_parses_three_paths(self):
        results = FfufParser().parse(FFUF_JSON, MID, AGENT)
        assert len(results) == 3

    def test_403_is_interesting(self):
        results = FfufParser().parse(FFUF_JSON, MID, AGENT)
        paths = [r for r in results if isinstance(r, WebPath)]
        p403 = next(p for p in paths if p.status_code == 403)
        assert p403.interesting is True
        assert "auth" in p403.reason

    def test_small_200_is_interesting(self):
        results = FfufParser().parse(FFUF_JSON, MID, AGENT)
        paths = [r for r in results if isinstance(r, WebPath)]
        small = next(p for p in paths if p.url.endswith("/secret"))
        assert small.interesting is True

    def test_empty_results_array(self):
        results = FfufParser().parse('{"results": []}', MID, AGENT)
        assert results == []

    def test_invalid_json_returns_empty(self):
        assert FfufParser().parse("not json", MID, AGENT) == []

    def test_json_lines_stdout_records(self):
        results = FfufParser().parse(FFUF_JSONL, MID, AGENT)
        paths = [r for r in results if isinstance(r, WebPath)]
        assert len(paths) == 2
        assert {p.status_code for p in paths} == {200, 403}


# ── TheHarvesterParser ────────────────────────────────────────

HARVESTER_JSON = """{
  "emails": ["admin@example.com", "info@example.com", "admin@example.com"],
  "hosts": ["mail.example.com", "www.example.com"],
  "ips": ["1.2.3.4", "5.6.7.8"]
}"""

class TestTheHarvesterParser:
    def test_emails_deduplicated(self):
        results = TheHarvesterParser().parse(HARVESTER_JSON, MID, AGENT)
        emails = [r for r in results if isinstance(r, OsintFinding) and r.category == "email"]
        assert len(emails) == 2  # deduped

    def test_hosts_extracted(self):
        results = TheHarvesterParser().parse(HARVESTER_JSON, MID, AGENT)
        hosts = [r for r in results if isinstance(r, OsintFinding) and r.category == "subdomain"]
        assert len(hosts) == 2

    def test_ips_extracted(self):
        results = TheHarvesterParser().parse(HARVESTER_JSON, MID, AGENT)
        ips = [r for r in results if isinstance(r, OsintFinding) and r.category == "ip"]
        assert len(ips) == 2

    def test_empty_json_returns_empty(self):
        results = TheHarvesterParser().parse('{"emails":[],"hosts":[],"ips":[]}', MID, AGENT)
        assert results == []

    def test_invalid_json_returns_empty(self):
        assert TheHarvesterParser().parse("not json", MID, AGENT) == []

    def test_filters_banner_metadata_and_out_of_scope_emails(self):
        raw = """{
          "emails": [
            "cmartorella@edge-security.com",
            "security@example.com",
            "admin@evil.com"
          ],
          "hosts": ["www.example.com", "edge-security.com"],
          "interesting_urls": ["https://api.example.com/v1", "https://evil.com"],
          "ips": []
        }"""
        results = TheHarvesterParser().parse(raw, MID, AGENT, target="example.com")
        values = {getattr(r, "value", "") for r in results}

        assert "security@example.com" in values
        assert "www.example.com" in values
        assert "https://api.example.com/v1" in values
        assert "cmartorella@edge-security.com" not in values
        assert "admin@evil.com" not in values
        assert "edge-security.com" not in values
        assert "https://evil.com" not in values


# ── LLM Router ────────────────────────────────────────────────

class TestLLMRouter:
    def test_router_initializes_without_keys(self):
        """Router should initialize gracefully with no API keys set."""
        import os
        # Remove keys if set
        old_nim = os.environ.pop("NVIDIA_NIM_API_KEY", None)
        old_groq = os.environ.pop("GROQ_API_KEY", None)
        try:
            from reconforge.llm.router import LLMRouter
            router = LLMRouter()
            assert not router.is_available()
        finally:
            if old_nim:
                os.environ["NVIDIA_NIM_API_KEY"] = old_nim
            if old_groq:
                os.environ["GROQ_API_KEY"] = old_groq

    def test_routing_table_coverage(self):
        """All expected task types exist in routing table."""
        from reconforge.llm.router import ROUTING_TABLE
        expected = {
            "mission_planning", "critic_review", "vuln_reasoning",
            "stage_gate_judgment", "report_writing", "exploit_planning",
            "context_summarization", "contextual_scoring", "cve_enrichment",
            "self_correction",
        }
        for task in expected:
            assert task in ROUTING_TABLE, f"Missing task_type: {task}"

    def test_nim_tasks_route_to_nim(self):
        from reconforge.llm.router import ROUTING_TABLE
        nim_tasks = ["mission_planning", "critic_review", "vuln_reasoning",
                     "stage_gate_judgment", "report_writing", "exploit_planning"]
        for task in nim_tasks:
            primary, _ = ROUTING_TABLE[task]
            assert primary == "nim", f"{task} should route to nim, got {primary}"

    def test_groq_tasks_route_to_groq(self):
        from reconforge.llm.router import ROUTING_TABLE
        groq_tasks = ["context_summarization", "contextual_scoring", "cve_enrichment"]
        for task in groq_tasks:
            primary, _ = ROUTING_TABLE[task]
            assert primary == "groq", f"{task} should route to groq, got {primary}"

    def test_nim_default_model_matches_documented_v4_flash(self, monkeypatch):
        from reconforge.llm.router import DEFAULT_NIM_MODEL, LLMRouter

        monkeypatch.setenv("NVIDIA_NIM_API_KEY", "test-key")
        monkeypatch.delenv("NVIDIA_NIM_MODEL", raising=False)
        monkeypatch.delenv("GROQ_API_KEY", raising=False)

        router = LLMRouter()
        assert router.status()["nim_model"] == DEFAULT_NIM_MODEL
        assert DEFAULT_NIM_MODEL == "deepseek-ai/deepseek-v4-flash"

    def test_no_keys_enters_offline_mode_without_fallback_calls(self, monkeypatch):
        from unittest.mock import AsyncMock
        from reconforge.llm.fallback import LLMUnavailableError
        from reconforge.llm.router import LLMRouter

        monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("AKAGAMI_NO_LLM", raising=False)

        router = LLMRouter()
        router._fallback.call = AsyncMock(side_effect=AssertionError("fallback called"))

        with pytest.raises(LLMUnavailableError):
            asyncio.get_event_loop().run_until_complete(router.call(
                task_type="mission_planning",
                system="system",
                messages=[{"role": "user", "content": "prompt"}],
            ))

        assert router.status()["offline_mode"] is True
        assert router._fallback.call.await_count == 0

    def test_no_llm_env_prevents_provider_initialization(self, monkeypatch):
        from reconforge.llm import router as router_module
        from reconforge.llm.router import LLMRouter

        monkeypatch.setenv("NVIDIA_NIM_API_KEY", "test-nim")
        monkeypatch.setenv("GROQ_API_KEY", "test-groq")
        monkeypatch.setenv("AKAGAMI_NO_LLM", "1")
        monkeypatch.setattr(
            router_module,
            "NvidiaProvider",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("NIM initialized")),
        )
        monkeypatch.setattr(
            router_module,
            "GroqProvider",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Groq initialized")),
        )

        router = LLMRouter()

        assert not router.is_available()
        assert router.status()["offline_reason"] == "AKAGAMI_NO_LLM=1"

    def test_placeholder_api_keys_are_ignored_without_provider_initialization(self, monkeypatch):
        from reconforge.llm import router as router_module
        from reconforge.llm.router import LLMRouter

        initialized = []
        warnings = []

        def fail_provider(name):
            def _fail(*args, **kwargs):
                initialized.append(name)
                raise AssertionError(f"{name} provider initialized")
            return _fail

        monkeypatch.setenv("NVIDIA_NIM_API_KEY", "nvapi-xxxx")
        monkeypatch.setenv("GROQ_API_KEY", "gsk_xxxx")
        monkeypatch.delenv("AKAGAMI_NO_LLM", raising=False)
        monkeypatch.setattr(LLMRouter, "_placeholder_warnings_emitted", set())
        monkeypatch.setattr(LLMRouter, "_offline_warnings_emitted", set())
        monkeypatch.setattr(
            router_module,
            "NvidiaProvider",
            fail_provider("NIM"),
        )
        monkeypatch.setattr(
            router_module,
            "GroqProvider",
            fail_provider("Groq"),
        )
        monkeypatch.setattr(
            router_module.logger,
            "warning",
            lambda message: warnings.append(str(message)),
        )

        router = LLMRouter()

        assert initialized == []
        assert not router.is_available()
        placeholder_warnings = [
            message for message in warnings
            if message.startswith("Ignoring placeholder LLM API key")
        ]
        assert placeholder_warnings == [
            "Ignoring placeholder LLM API key(s): GROQ_API_KEY, NVIDIA_NIM_API_KEY"
        ]
        warning_text = "\n".join(warnings)
        assert "nvapi-xxxx" not in warning_text
        assert "gsk_xxxx" not in warning_text


# ── SeverityScorer lookup table ───────────────────────────────

class TestCvssLookupTable:
    def test_critical(self):
        from reconforge.skills.scorer import cvss_to_severity
        assert cvss_to_severity(9.8) == "critical"
        assert cvss_to_severity(9.0) == "critical"
        assert cvss_to_severity(10.0) == "critical"

    def test_high(self):
        from reconforge.skills.scorer import cvss_to_severity
        assert cvss_to_severity(7.0) == "high"
        assert cvss_to_severity(8.9) == "high"

    def test_medium(self):
        from reconforge.skills.scorer import cvss_to_severity
        assert cvss_to_severity(4.0) == "medium"
        assert cvss_to_severity(6.9) == "medium"

    def test_low(self):
        from reconforge.skills.scorer import cvss_to_severity
        assert cvss_to_severity(1.0) == "low"
        assert cvss_to_severity(3.9) == "low"

    def test_info(self):
        from reconforge.skills.scorer import cvss_to_severity
        assert cvss_to_severity(0.0) == "info"
        assert cvss_to_severity(None) == "info"
