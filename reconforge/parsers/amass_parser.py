"""
amass deterministic parser — reads amass -json output.
Falls back to plain line splitting if JSON fails.
Zero LLM. Instant. Deterministic.
"""
import json
from reconforge.intel.models import Subdomain, IntelBase
from reconforge.utils.logger import get_logger

logger = get_logger("parser.amass")


class AmassParser:
    """Parses amass JSON lines output into Subdomain objects."""

    def parse(self, raw: str, mission_id: str,
              source_agent: str) -> list[IntelBase]:
        if not raw or not raw.strip():
            return []
        try:
            return self._parse(raw, mission_id, source_agent)
        except Exception as e:
            logger.warning(f"AmassParser failed: {e} | raw[:200]={raw[:200]!r}")
            return []

    def _parse(self, raw: str, mission_id: str,
               source_agent: str) -> list[IntelBase]:
        findings: list[IntelBase] = []
        seen: set[str] = set()

        # Try JSON lines first
        json_success = False
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                json_success = True
            except json.JSONDecodeError:
                continue

            name = data.get("name", "")
            if not name or name in seen:
                continue
            seen.add(name)

            # Extract IPs from addresses array
            addresses = data.get("addresses", [])
            ip = None
            if addresses:
                first = addresses[0]
                if isinstance(first, dict):
                    ip = first.get("ip")
                elif isinstance(first, str):
                    ip = first

            findings.append(Subdomain(
                source_agent=source_agent,
                source_tool="amass",
                confidence=0.85,
                mission_id=mission_id,
                domain=name,
                ip=ip,
            ))

        # Fallback: plain line splitting (passive mode output)
        if not json_success:
            logger.debug("AmassParser: falling back to plain line split")
            for line in raw.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or " " in line:
                    continue
                # Looks like a domain name
                if "." in line and line not in seen:
                    seen.add(line)
                    findings.append(Subdomain(
                        source_agent=source_agent,
                        source_tool="amass",
                        confidence=0.75,
                        mission_id=mission_id,
                        domain=line,
                    ))

        logger.info(f"AmassParser: {len(findings)} subdomains")
        return findings
