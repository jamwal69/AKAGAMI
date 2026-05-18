"""Tests for Phase 3 — Critic, Enricher, SemanticMemory, StageGate, ReportGenerator."""

import asyncio
import json
import os
import tempfile

import pytest

from reconforge.intel.models import (
    Host, MissionState, OsintFinding, Port, ReviewVerdict,
    SecretFinding, Vulnerability, WebPath,
)
from reconforge.intel.store import IntelStore
from reconforge.memory.semantic import SemanticMemory
from reconforge.orchestrator.stage_gate import StageGate
from reconforge.report.generator import ReportGenerator
from reconforge.skills.critic import CriticAgent
from reconforge.skills.enricher import CveEnricher


# ── CriticAgent Tests ────────────────────────────────────────

class TestCriticAgent:
    """Test the heuristic pre-filters and dedup in CriticAgent."""

    def setup_method(self):
        self.critic = CriticAgent(client=None)
        self.mission_id = "test-mission"

    def test_quarantine_without_client(self):
        finding = OsintFinding(
            source_agent="test", source_tool="whois",
            confidence=0.8, mission_id=self.mission_id,
            category="whois", value="test.com", context="test")
        result = asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        assert result.verdict == ReviewVerdict.QUARANTINE

    def test_reject_false_positive_pattern(self):
        finding = OsintFinding(
            source_agent="test", source_tool="nmap",
            confidence=0.9, mission_id=self.mission_id,
            category="dns", value="test.com",
            context="test", raw_output="connection refused by host")
        result = asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        assert result.verdict == ReviewVerdict.REJECT

    def test_reject_empty_host(self):
        finding = Host(
            source_agent="test", source_tool="nmap",
            confidence=0.9, mission_id=self.mission_id, ip="")
        result = asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        assert result.verdict == ReviewVerdict.REJECT

    def test_reject_invalid_port(self):
        finding = Port(
            source_agent="test", source_tool="nmap",
            confidence=0.9, mission_id=self.mission_id,
            host_id="h1", port=99999, protocol="tcp")
        result = asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        assert result.verdict == ReviewVerdict.REJECT

    def test_improve_overconfident(self):
        finding = OsintFinding(
            source_agent="test", source_tool="whois",
            confidence=0.99, mission_id=self.mission_id,
            category="whois", value="test.com", context="test")
        result = asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        assert result.verdict == ReviewVerdict.IMPROVE

    def test_improve_vuln_no_evidence(self):
        finding = Vulnerability(
            source_agent="test", source_tool="nuclei",
            confidence=0.8, mission_id=self.mission_id,
            host_id="h1", title="Test Vuln", severity="high")
        result = asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        assert result.verdict == ReviewVerdict.REJECT

    def test_reject_vuln_no_title(self):
        finding = Vulnerability(
            source_agent="test", source_tool="nuclei",
            confidence=0.8, mission_id=self.mission_id,
            host_id="h1", title="", severity="high",
            evidence="some evidence")
        result = asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        assert result.verdict == ReviewVerdict.REJECT

    def test_dedup_detection(self):
        finding = OsintFinding(
            source_agent="test", source_tool="whois",
            confidence=0.8, mission_id=self.mission_id,
            category="whois", value="test.com", context="test")
        # First review should approve
        r1 = asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        # Second review of same finding should be caught as dedup
        r2 = asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        assert r2.verdict == ReviewVerdict.REJECT
        assert "Duplicate" in r2.reason

    def test_batch_review(self):
        findings = [
            OsintFinding(
                source_agent="t", source_tool="w", confidence=0.8,
                mission_id=self.mission_id, category="dns",
                value=f"sub{i}.test.com", context="test")
            for i in range(3)
        ]
        results = asyncio.get_event_loop().run_until_complete(
            self.critic.review_batch(findings))
        assert len(results) == 3

    def test_stats_tracking(self):
        self.critic.reset_session()
        finding = OsintFinding(
            source_agent="t", source_tool="w", confidence=0.8,
            mission_id=self.mission_id, category="dns",
            value="stats.test.com", context="test")
        asyncio.get_event_loop().run_until_complete(
            self.critic.review(finding))
        stats = self.critic.get_stats()
        assert stats["quarantined"] >= 1
        assert "dedup_keys_tracked" in stats

    def test_reset_session(self):
        self.critic._seen_keys.add("test_key")
        self.critic.reset_session()
        assert len(self.critic._seen_keys) == 0


# ── CveEnricher Tests ────────────────────────────────────────

class TestCveEnricher:
    """Test the heuristic enrichment logic."""

    def setup_method(self):
        self.enricher = CveEnricher(semantic=None, client=None)

    def test_heuristic_enrich_nvd_format(self):
        vuln = Vulnerability(
            source_agent="test", source_tool="nuclei",
            confidence=0.8, mission_id="m1", host_id="h1",
            title="Apache RCE", severity="high")
        cve_matches = [{
            "cve_id": "CVE-2021-41773",
            "cvss_score": 9.8,
            "severity": "critical",
            "description": "Path traversal in Apache 2.4.49",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        }]
        result = self.enricher._heuristic_enrich(vuln, cve_matches)
        assert result.cve_id == "CVE-2021-41773"
        assert result.cvss_score == 9.8
        assert result.severity == "critical"

    def test_heuristic_enrich_chromadb_format(self):
        vuln = Vulnerability(
            source_agent="test", source_tool="nuclei",
            confidence=0.8, mission_id="m1", host_id="h1",
            title="OpenSSH Issue", severity="medium")
        cve_matches = [{
            "id": "CVE-2023-12345",
            "document": "OpenSSH vulnerability",
            "metadata": {
                "cve_id": "CVE-2023-12345",
                "cvss_score": 7.5,
                "severity": "high",
            },
            "distance": 0.2,
        }]
        result = self.enricher._heuristic_enrich(vuln, cve_matches)
        assert result.cve_id == "CVE-2023-12345"
        assert result.cvss_score == 7.5

    def test_enrich_already_complete(self):
        vuln = Vulnerability(
            source_agent="test", source_tool="nuclei",
            confidence=0.8, mission_id="m1", host_id="h1",
            title="Complete Vuln", severity="critical",
            cve_id="CVE-2021-44228", cvss_score=10.0,
            remediation="Upgrade Log4j")
        result = asyncio.get_event_loop().run_until_complete(
            self.enricher.enrich(vuln))
        assert result.cve_id == "CVE-2021-44228"  # Unchanged
        assert self.enricher.stats["unchanged"] == 1

    def test_stats(self):
        self.enricher.stats = {"enriched": 0, "local_hits": 0,
                               "nvd_hits": 0, "claude_enriched": 0,
                               "unchanged": 0}
        stats = self.enricher.get_stats()
        assert "enriched" in stats


# ── SemanticMemory Tests ─────────────────────────────────────

class TestSemanticMemory:
    """Test ChromaDB semantic memory."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.semantic = SemanticMemory(persist_dir=self.tmpdir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_initialization(self):
        self.semantic._ensure_init()
        assert self.semantic._initialized is True

    def test_add_and_query(self):
        self.semantic.add_documents(
            "cve_database",
            documents=["CVE-2021-44228: Log4Shell RCE in Apache Log4j"],
            metadatas=[{"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "severity": "critical", "products": "apache:log4j"}],
            ids=["CVE-2021-44228"])

        results = self.semantic.query("Log4j vulnerability", "cve_database", n_results=1)
        assert len(results) >= 1
        assert results[0]["metadata"]["cve_id"] == "CVE-2021-44228"

    def test_query_empty_collection(self):
        results = self.semantic.query("nonexistent", "exploit_refs")
        assert results == []

    def test_add_report(self):
        self.semantic.add_report(
            "Test report content " * 50,
            {"mission_id": "test-1", "target": "test.com"})
        results = self.semantic.query("test report", "past_reports")
        assert len(results) >= 1

    def test_add_tool_knowledge(self):
        self.semantic.add_tool_knowledge(
            "nmap", "Use -sV for version detection, -sC for default scripts")
        results = self.semantic.query("version detection", "tool_knowledge")
        assert len(results) >= 1

    def test_collection_stats(self):
        self.semantic.add_documents(
            "cve_database", ["test doc"], [{"cve_id": "test", "cvss_score": 0.0, "severity": "low", "products": ""}], ["test-1"])
        stats = self.semantic.get_collection_stats()
        assert stats["cve_database"] >= 1

    def test_query_cves(self):
        self.semantic.add_documents(
            "cve_database",
            ["CVE-2021-41773: Apache 2.4.49 path traversal allowing RCE"],
            [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8, "severity": "critical", "products": "apache:httpd"}],
            ["CVE-2021-41773"])
        # Use general query (query_cves has a distance filter)
        results = self.semantic.query("Apache 2.4.49 path traversal", "cve_database", n_results=1)
        assert len(results) >= 1
        assert results[0]["metadata"]["cve_id"] == "CVE-2021-41773"

    def test_ingest_mission_findings_uses_typed_verified_store_rows(self):
        tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmpfile.close()
        store = IntelStore(tmpfile.name)
        mission_id = "semantic-ingest-test"
        try:
            vuln = Vulnerability(
                source_agent="vuln",
                source_tool="nuclei",
                confidence=0.8,
                mission_id=mission_id,
                verified=True,
                host_id="10.0.0.1",
                title="SQL Injection",
                severity="high",
                evidence="confirmed by scanner",
            )
            osint = OsintFinding(
                source_agent="osint",
                source_tool="whois",
                confidence=0.8,
                mission_id=mission_id,
                verified=True,
                category="whois",
                value="example.com",
                context="Registrant Example Corp",
            )
            unverified = OsintFinding(
                source_agent="osint",
                source_tool="crt_sh",
                confidence=0.7,
                mission_id=mission_id,
                category="cert",
                value="dev.example.com",
                context="certificate transparency",
            )
            store.store([vuln, osint, unverified])

            count = self.semantic.ingest_mission_findings(store, mission_id)

            assert count == 2
            results = self.semantic.query(
                "SQL Injection Example Corp",
                "cross_mission_intel",
                n_results=2,
            )
            assert len(results) >= 1
        finally:
            store.close()
            os.unlink(tmpfile.name)

    def test_secret_finding_ingest_redacts_secret_value(self):
        tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmpfile.close()
        store = IntelStore(tmpfile.name)
        mission_id = "semantic-secret-redaction-test"
        raw_secret = "rf-test-secret-value-6c8f5a2b"
        raw_output_secret = "raw-output-secret-1b9f3d4e"
        captured = {}

        def capture_documents(collection, documents, metadatas, ids):
            captured["collection"] = collection
            captured["documents"] = documents
            captured["metadatas"] = metadatas
            captured["ids"] = ids
            return len(documents)

        try:
            secret = SecretFinding(
                source_agent="js_agent",
                source_tool="trufflehog",
                confidence=0.91,
                mission_id=mission_id,
                verified=True,
                raw_output=f"matched secret {raw_output_secret}",
                host_id="app.example.com",
                file_path="static/app.js",
                secret_type="stripe_key",
                secret_value=raw_secret,
                is_verified=True,
            )
            store.store([secret])
            self.semantic._initialized = True
            self.semantic.add_documents = capture_documents

            count = self.semantic.ingest_mission_findings(store, mission_id)

            assert count == 1
            document = captured["documents"][0]
            assert raw_secret not in document
            assert raw_output_secret not in document
            assert "secret_value" not in document
            assert "raw_output" not in document
            assert "stripe_key" in document
            assert "static/app.js" in document
            assert captured["metadatas"][0]["type"] == "SecretFinding"
        finally:
            store.close()
            os.unlink(tmpfile.name)

    def test_vulnerability_ingest_excludes_raw_output(self):
        tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmpfile.close()
        store = IntelStore(tmpfile.name)
        mission_id = "semantic-vuln-redaction-test"
        raw_token = "semantic-jwt-token-2d5b7c"
        captured = {}

        def capture_documents(collection, documents, metadatas, ids):
            captured["documents"] = documents
            return len(documents)

        try:
            vuln = Vulnerability(
                source_agent="vuln",
                source_tool="jwt_tool",
                confidence=0.9,
                mission_id=mission_id,
                verified=True,
                raw_output=f"jwt_tool echoed {raw_token}",
                host_id="app.example.com",
                title="JWT Vulnerability Detected",
                severity="high",
                evidence="Weak secret detected",
            )
            store.store([vuln])
            self.semantic._initialized = True
            self.semantic.add_documents = capture_documents

            count = self.semantic.ingest_mission_findings(store, mission_id)

            assert count == 1
            document = captured["documents"][0]
            assert raw_token not in document
            assert "raw_output" not in document
            assert "JWT Vulnerability Detected" in document
        finally:
            store.close()
            os.unlink(tmpfile.name)


# ── StageGate Tests ──────────────────────────────────────────

class TestStageGate:
    """Test the stage gate evaluation logic."""

    def setup_method(self):
        self.gate = StageGate(client=None)
        self.tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmpfile.close()
        self.store = IntelStore(self.tmpfile.name)
        self.mission = MissionState(
            target="test.local", scope=["test.local"],
            mission_name="Test Mission")

    def teardown_method(self):
        self.store.close()
        os.unlink(self.tmpfile.name)

    def test_gate_fails_with_no_data(self):
        result = asyncio.get_event_loop().run_until_complete(
            self.gate.evaluate(self.store, self.mission))
        assert result.passed is False
        assert len(result.missing_coverage) > 0

    def test_gate_passes_with_sufficient_data(self):
        # Add enough data to pass quantitative + heuristic gates
        mid = self.mission.mission_id
        self.store.write(Host(
            source_agent="t", source_tool="nmap", confidence=0.9,
            mission_id=mid, ip="192.168.1.1"))
        # Ports are needed for service enumeration coverage
        for port_num in [22, 80, 443]:
            self.store.write(Port(
                source_agent="t", source_tool="nmap", confidence=0.9,
                mission_id=mid, host_id="h1",
                port=port_num, service="http" if port_num > 22 else "ssh"))
        # OSINT categories
        for cat in ["whois", "cert", "dns"]:
            self.store.write(OsintFinding(
                source_agent="t", source_tool="w", confidence=0.8,
                mission_id=mid,
                category=cat, value=f"{cat}.test", context="test"))
        # Vulnerabilities
        for i in range(3):
            self.store.write(Vulnerability(
                source_agent="t", source_tool="nuclei", confidence=0.7,
                mission_id=mid,
                host_id="192.168.1.1", title=f"Vuln {i}", severity="medium"))
        # Web paths
        for path in ["/admin", "/login", "/api", "/index", "/docs"]:
            self.store.write(WebPath(
                source_agent="t", source_tool="ffuf", confidence=0.8,
                mission_id=mid, host_id="h1",
                url=f"http://192.168.1.1{path}", status_code=200))

        result = asyncio.get_event_loop().run_until_complete(
            self.gate.evaluate(self.store, self.mission))
        assert result.passed is True
        assert result.confidence > 0

    def test_gate_requires_operator_approval(self):
        result = asyncio.get_event_loop().run_until_complete(
            self.gate.evaluate(self.store, self.mission))
        assert result.requires_operator_approval is True

    def test_metrics_computation(self):
        self.store.write(Host(
            source_agent="t", source_tool="nmap", confidence=0.9,
            mission_id=self.mission.mission_id, ip="10.0.0.1"))
        self.store.write(Port(
            source_agent="t", source_tool="nmap", confidence=0.9,
            mission_id=self.mission.mission_id,
            host_id="h1", port=80, service="http"))

        summary = self.store.get_attack_surface_summary(self.mission.mission_id)
        data = self.store.export_json(self.mission.mission_id)
        metrics = self.gate._compute_metrics(summary, data)

        assert metrics["hosts_discovered"] == 1
        assert metrics["total_ports"] == 1
        assert metrics["average_confidence"] > 0

    def test_custom_thresholds(self):
        gate = StageGate(client=None, thresholds={"min_hosts_verified": 5})
        self.store.write(Host(
            source_agent="t", source_tool="nmap", confidence=0.9,
            mission_id=self.mission.mission_id, ip="10.0.0.1"))
        result = asyncio.get_event_loop().run_until_complete(
            gate.evaluate(self.store, self.mission))
        assert result.passed is False  # Need 5 hosts, only have 1


# ── ReportGenerator Tests ────────────────────────────────────

class TestReportGenerator:
    """Test report generation."""

    def setup_method(self):
        self.generator = ReportGenerator(
            template_dir="nonexistent", client=None)
        self.tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmpfile.close()
        self.store = IntelStore(self.tmpfile.name)
        self.mission_id = "test-report-mission"
        self.output_dir = tempfile.mkdtemp()

    def teardown_method(self):
        self.store.close()
        os.unlink(self.tmpfile.name)
        import shutil
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_generate_empty_report(self):
        output_path = os.path.join(self.output_dir, "report.md")
        report = asyncio.get_event_loop().run_until_complete(
            self.generator.generate(
                self.store, self.mission_id,
                output_path=output_path,
                target="test.local"))
        assert len(report) > 0
        assert os.path.exists(output_path)
        assert "Reconnaissance Report" in report

    def test_generate_report_with_findings(self):
        # Add findings
        self.store.write(Host(
            source_agent="t", source_tool="nmap", confidence=0.9,
            mission_id=self.mission_id, ip="10.0.0.1",
            hostname="test.local", os_guess="Linux"))
        self.store.write(Port(
            source_agent="t", source_tool="nmap", confidence=0.9,
            mission_id=self.mission_id,
            host_id="h1", port=80, service="http", version="Apache 2.4"))
        self.store.write(Vulnerability(
            source_agent="t", source_tool="nuclei", confidence=0.8,
            mission_id=self.mission_id,
            host_id="10.0.0.1", title="Apache Path Traversal",
            severity="critical", cve_id="CVE-2021-41773",
            cvss_score=9.8, exploit_available=True))

        output_path = os.path.join(self.output_dir, "report2.md")
        report = asyncio.get_event_loop().run_until_complete(
            self.generator.generate(
                self.store, self.mission_id,
                output_path=output_path,
                target="test.local",
                mission_name="Test Mission"))
        assert "10.0.0.1" in report
        assert "Apache Path Traversal" in report
        assert "CRITICAL" in report

    def test_risk_scoring(self):
        summary = {
            "vulnerabilities_by_severity": {
                "critical": 2, "high": 3, "medium": 5
            },
            "credentials_found": 1,
        }
        risk = self.generator._compute_risk_score(summary)
        assert risk["rating"] == "CRITICAL"
        assert risk["score"] > 0

    def test_risk_scoring_low(self):
        summary = {
            "vulnerabilities_by_severity": {"low": 2, "info": 5},
            "credentials_found": 0,
        }
        risk = self.generator._compute_risk_score(summary)
        assert risk["rating"] in ("LOW", "INFORMATIONAL")

    def test_fallback_exec_summary(self):
        summary = {
            "hosts_discovered": 5,
            "open_ports": 20,
            "subdomains": 10,
            "vulnerabilities_by_severity": {"critical": 1, "high": 2},
            "credentials_found": 0,
        }
        text = self.generator._fallback_exec_summary(summary, "test.com")
        assert "test.com" in text
        assert "5 hosts" in text

    def test_fallback_recommendations(self):
        summary = {
            "vulnerabilities_by_severity": {"critical": 2, "high": 1},
            "credentials_found": 1,
            "missing_coverage": ["No web fuzzing"],
        }
        recs = self.generator._fallback_recommendations(summary)
        assert len(recs) >= 2
        assert any(r["priority"] == "P1" for r in recs)

    def test_vuln_stats(self):
        data = {
            "vulnerabilities": [
                {"severity": "critical", "host_id": "h1", "exploit_available": True},
                {"severity": "high", "host_id": "h1", "exploit_available": False},
                {"severity": "medium", "host_id": "h2", "exploit_available": False},
            ]
        }
        stats = self.generator._compute_vuln_stats(data)
        assert stats["total"] == 3
        assert stats["exploitable"] == 1
        assert stats["most_affected_host"] == "h1"
