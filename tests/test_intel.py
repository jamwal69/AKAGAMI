"""Tests for IntelStore."""

import pytest
from reconforge.intel.models import Host, OsintFinding, Port, Subdomain
from reconforge.intel.store import IntelStore


class TestIntelStore:
    def test_write_and_query_host(self, intel_store, mission):
        host = Host(
            source_agent="test", source_tool="nmap", confidence=0.9,
            mission_id=mission.mission_id, ip="192.168.1.1",
            hostname="test.local", tags=["web"])
        intel_store.write(host)
        results = intel_store.hosts(mission.mission_id)
        assert len(results) == 1
        assert results[0]["ip"] == "192.168.1.1"

    def test_write_and_query_osint(self, intel_store, mission, sample_finding):
        intel_store.write(sample_finding)
        results = intel_store.osint_findings(mission.mission_id)
        assert len(results) == 1
        assert results[0]["category"] == "whois"

    def test_dedup_host(self, intel_store, mission):
        host = Host(
            source_agent="test", source_tool="nmap", confidence=0.9,
            mission_id=mission.mission_id, ip="192.168.1.1")
        intel_store.write(host)
        intel_store.write(host)  # duplicate
        results = intel_store.hosts(mission.mission_id)
        assert len(results) == 1

    def test_dedup_osint(self, intel_store, mission):
        f1 = OsintFinding(
            source_agent="test", source_tool="whois", confidence=0.9,
            mission_id=mission.mission_id, category="whois",
            value="test.com", context="test")
        intel_store.write(f1)
        intel_store.write(f1)
        results = intel_store.osint_findings(mission.mission_id)
        assert len(results) == 1

    def test_attack_surface_summary(self, intel_store, mission):
        host = Host(
            source_agent="test", source_tool="nmap", confidence=0.9,
            mission_id=mission.mission_id, ip="10.0.0.1")
        intel_store.write(host)
        summary = intel_store.get_attack_surface_summary(mission.mission_id)
        assert summary["hosts_discovered"] == 1
        assert isinstance(summary["missing_coverage"], list)

    def test_export_json(self, intel_store, mission, sample_finding):
        intel_store.write(sample_finding)
        export = intel_store.export_json(mission.mission_id)
        assert "osint_findings" in export
        assert len(export["osint_findings"]) == 1

    def test_store_multiple(self, intel_store, mission):
        findings = [
            OsintFinding(source_agent="t", source_tool="w", confidence=0.8,
                         mission_id=mission.mission_id, category="dns",
                         value=f"sub{i}.test.com", context="test")
            for i in range(5)
        ]
        ids = intel_store.store(findings)
        assert len(ids) == 5
