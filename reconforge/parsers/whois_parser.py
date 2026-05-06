"""
whois deterministic parser — uses python-whois library.
Zero LLM. Instant. Deterministic.
"""
from typing import Any
from reconforge.intel.models import OsintFinding, IntelBase
from reconforge.utils.logger import get_logger

logger = get_logger("parser.whois")


def _str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0] if val else ""
    return str(val).strip()


class WhoisParser:
    """Calls python-whois and extracts OsintFinding objects."""

    def parse(self, raw: str, mission_id: str, source_agent: str) -> list[IntelBase]:
        """raw is the domain name to query."""
        domain = raw.strip()
        if not domain:
            return []
        try:
            return self._parse(domain, mission_id, source_agent)
        except Exception as e:
            logger.warning(f"WhoisParser failed for {domain}: {e}")
            return []

    def parse_domain(self, domain: str, mission_id: str, source_agent: str) -> list[IntelBase]:
        return self.parse(domain, mission_id, source_agent)

    def parse_raw(self, raw_text: str, domain: str, mission_id: str, source_agent: str) -> list[IntelBase]:
        try:
            return self._parse_text(raw_text, domain, mission_id, source_agent)
        except Exception as e:
            logger.warning(f"WhoisParser.parse_raw failed: {e}")
            return []

    def _parse(self, domain: str, mission_id: str, source_agent: str) -> list[IntelBase]:
        try:
            import whois as whois_lib
            w = whois_lib.whois(domain)
        except ImportError:
            logger.warning("python-whois not installed. Run: pip install python-whois")
            return []

        findings: list[IntelBase] = []

        def add(field: str, value: Any, context: str = "") -> None:
            v = _str(value)
            if v and v.lower() not in ("none", "redacted for privacy", ""):
                findings.append(OsintFinding(
                    source_agent=source_agent, source_tool="whois",
                    confidence=0.95, mission_id=mission_id,
                    category="whois", value=v[:500],
                    context=context or field))

        add("registrar", w.registrar, "Domain registrar")
        add("registrant_org", w.org, "Registrant organization")
        add("creation_date", w.creation_date, "Domain creation date")
        add("expiration_date", w.expiration_date, "Domain expiration date")
        add("updated_date", w.updated_date, "Last updated date")
        add("registrant_country", w.country, "Registrant country")

        nameservers = w.name_servers or []
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        for ns in set(str(ns).strip().lower() for ns in nameservers if ns):
            add("nameserver", ns, f"Nameserver: {ns}")

        statuses = w.status or []
        if isinstance(statuses, str):
            statuses = [statuses]
        for s in statuses[:5]:
            add("status", s, "Whois status flag")

        emails = w.emails or []
        if isinstance(emails, str):
            emails = [emails]
        for email in set(str(e).strip() for e in emails if e):
            add("email", email, "Contact email from whois")

        logger.info(f"WhoisParser: {len(findings)} findings for {domain}")
        return findings

    def _parse_text(self, raw_text: str, domain: str, mission_id: str, source_agent: str) -> list[IntelBase]:
        findings: list[IntelBase] = []
        important_keys = {"registrar", "registrant", "organization",
                          "creation date", "expiry date", "name server", "status"}
        for line in raw_text.split("\n"):
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if value and any(k in key for k in important_keys):
                findings.append(OsintFinding(
                    source_agent=source_agent, source_tool="whois",
                    confidence=0.85, mission_id=mission_id,
                    category="whois", value=value[:500], context=key))
        return findings
