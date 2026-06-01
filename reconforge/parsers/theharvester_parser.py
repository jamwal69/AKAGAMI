"""
theHarvester deterministic parser — reads theHarvester JSON output (-f flag).
Zero LLM. Instant. Deterministic.
"""
import json
from reconforge.intel.models import OsintFinding, IntelBase
from reconforge.tools.scope import normalize_scope_host
from reconforge.utils.logger import get_logger

logger = get_logger("parser.theharvester")

THEHARVESTER_METADATA_EMAILS = {
    "cmartorella@edge-security.com",
}


class TheHarvesterParser:
    """Parses theHarvester JSON output into OsintFinding objects."""

    def parse(self, raw: str, mission_id: str, source_agent: str,
              target: str = "") -> list[IntelBase]:
        if not raw or not raw.strip():
            return []
        try:
            return self._parse(raw, mission_id, source_agent, target)
        except Exception as e:
            logger.warning(f"TheHarvesterParser failed: {e} | raw[:200]={raw[:200]!r}")
            return []

    def _parse(self, raw: str, mission_id: str, source_agent: str,
               target: str = "") -> list[IntelBase]:
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
            if should_keep_theharvester_email(e, target) and e not in seen_emails:
                seen_emails.add(e)
                findings.append(OsintFinding(
                    source_agent=source_agent, source_tool="theharvester",
                    confidence=0.85, mission_id=mission_id,
                    category="email", value=e,
                    context="Email found by theHarvester"))

        # Hosts / subdomains
        for host in data.get("hosts", []):
            h = str(host).strip().lower()
            if h and value_matches_target_scope(h, target) and h not in seen_hosts:
                seen_hosts.add(h)
                findings.append(OsintFinding(
                    source_agent=source_agent, source_tool="theharvester",
                    confidence=0.80, mission_id=mission_id,
                    category="subdomain", value=h,
                    context="Subdomain found by theHarvester"))

        # Also check "interesting_urls" field if present
        for url in data.get("interesting_urls", []):
            u = str(url).strip()
            if u and value_matches_target_scope(u, target):
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


def should_keep_theharvester_email(email: str, target: str = "") -> bool:
    normalized = str(email or "").strip().lower()
    if not normalized:
        return False
    if normalized in THEHARVESTER_METADATA_EMAILS:
        return False
    return value_matches_target_scope(normalized, target, value_type="email")


def value_matches_target_scope(
    value: str,
    target: str = "",
    *,
    value_type: str = "host",
) -> bool:
    """Return True when value belongs to the requested target scope."""
    if not target:
        return True
    target_host = _scope_host(target)
    if not target_host:
        return True
    if value_type == "email":
        if "@" not in value:
            return False
        host = value.rsplit("@", 1)[1].strip().lower()
    else:
        host = _scope_host(value)
    if not host:
        return False
    return host == target_host or host.endswith(f".{target_host}")


def _scope_host(value: str) -> str:
    try:
        return normalize_scope_host(str(value or "")).strip(".").lower()
    except Exception:
        return ""
