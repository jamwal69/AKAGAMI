"""
Nuclei deterministic parser — reads nuclei JSON lines (-json flag).
Zero LLM. Instant. Deterministic.
"""
import json
from reconforge.intel.models import Vulnerability, IntelBase
from reconforge.utils.logger import get_logger

logger = get_logger("parser.nuclei")


class NucleiParser:
    """Parses nuclei JSONL output into Vulnerability objects."""

    def parse(self, raw: str, mission_id: str,
              source_agent: str) -> list[IntelBase]:
        if not raw or not raw.strip():
            return []
        try:
            return self._parse(raw, mission_id, source_agent)
        except Exception as e:
            logger.warning(f"NucleiParser failed: {e} | raw[:200]={raw[:200]!r}")
            return []

    def _parse(self, raw: str, mission_id: str,
               source_agent: str) -> list[IntelBase]:
        findings: list[IntelBase] = []

        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            classification = info.get("classification", {})

            # CVE ID — may be list or string
            cve_id = classification.get("cve-id")
            if isinstance(cve_id, list):
                cve_id = cve_id[0] if cve_id else None
            if cve_id:
                cve_id = cve_id.strip().upper()

            # CVSS score
            cvss = classification.get("cvss-score")
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = None

            severity = info.get("severity", "info").lower()
            title = info.get("name") or data.get("template-id", "")
            description = info.get("description", "")
            evidence = data.get("matched-at", "") or data.get("matched", "")
            remediation = info.get("remediation")
            host = data.get("host", "") or data.get("ip", "")

            # Extract just the host (strip protocol/port for host_id)
            host_id = host
            if "://" in host_id:
                host_id = host_id.split("://", 1)[1]
            host_id = host_id.split(":")[0].split("/")[0]

            findings.append(Vulnerability(
                source_agent=source_agent,
                source_tool="nuclei",
                confidence=0.80,
                mission_id=mission_id,
                host_id=host_id,
                title=title,
                description=description,
                severity=severity,
                cve_id=cve_id,
                cvss_score=cvss,
                evidence=evidence,
                remediation=remediation,
                raw_output=json.dumps(data)[:1000],
            ))

        logger.info(f"NucleiParser: {len(findings)} vulnerabilities")
        return findings
