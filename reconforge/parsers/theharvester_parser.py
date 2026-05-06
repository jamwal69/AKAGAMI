"""
theHarvester deterministic parser — reads theHarvester JSON output (-f flag).
Zero LLM. Instant. Deterministic.
"""
import json
from reconforge.intel.models import OsintFinding, IntelBase
from reconforge.utils.logger import get_logger

logger = get_logger("parser.theharvester")


class TheHarvesterParser:
    """Parses theHarvester JSON output into OsintFinding objects."""

    def parse(self, raw: str, mission_id: str, source_agent: str) -> list[IntelBase]:
        if not raw or not raw.strip():
            return []
        try:
            return self._parse(raw, mission_id, source_agent)
        except Exception as e:
            logger.warning(f"TheHarvesterParser failed: {e} | raw[:200]={raw[:200]!r}")
            return []

    def _parse(self, raw: str, mission_id: str, source_agent: str) -> list[IntelBase]:
        findings: list[IntelBase] = []
        seen_emails: set[str] = set()
        seen_hosts: set[str] = set()
        seen_ips: set[str] = set()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("TheHarvesterParser: JSON decode failed, returning empty")
            return []

        # Emails
        for email in data.get("emails", []):
            e = str(email).strip().lower()
            if e and e not in seen_emails:
                seen_emails.add(e)
                findings.append(OsintFinding(
                    source_agent=source_agent, source_tool="theharvester",
                    confidence=0.85, mission_id=mission_id,
                    category="email", value=e,
                    context="Email found by theHarvester"))

        # Hosts / subdomains
        for host in data.get("hosts", []):
            h = str(host).strip().lower()
            if h and h not in seen_hosts:
                seen_hosts.add(h)
                findings.append(OsintFinding(
                    source_agent=source_agent, source_tool="theharvester",
                    confidence=0.80, mission_id=mission_id,
                    category="subdomain", value=h,
                    context="Subdomain found by theHarvester"))

        # Also check "interesting_urls" field if present
        for url in data.get("interesting_urls", []):
            u = str(url).strip()
            if u:
                findings.append(OsintFinding(
                    source_agent=source_agent, source_tool="theharvester",
                    confidence=0.75, mission_id=mission_id,
                    category="url", value=u,
                    context="Interesting URL found by theHarvester"))

        # IPs
        for ip in data.get("ips", []):
            i = str(ip).strip()
            if i and i not in seen_ips:
                seen_ips.add(i)
                findings.append(OsintFinding(
                    source_agent=source_agent, source_tool="theharvester",
                    confidence=0.80, mission_id=mission_id,
                    category="ip", value=i,
                    context="IP found by theHarvester"))

        logger.info(
            f"TheHarvesterParser: {len(seen_emails)} emails, "
            f"{len(seen_hosts)} hosts, {len(seen_ips)} IPs")
        return findings
