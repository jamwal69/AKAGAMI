"""
httpx deterministic parser — reads httpx JSON lines (-json flag).
Zero LLM. Instant. Deterministic.
"""
import json
from reconforge.intel.models import Subdomain, WebPath, IntelBase
from reconforge.utils.logger import get_logger

logger = get_logger("parser.httpx")

# Paths that are always interesting when found
INTERESTING_PATHS = {
    "admin", "login", "dashboard", "portal", "api", "swagger", "graphql",
    ".git", ".env", "backup", "config", "phpinfo", "wp-admin", "jenkins",
    "kibana", "grafana", "jira", "confluence", "phpmyadmin", "actuator",
    "setup", "install", "console", "manager", "administrator", "shell",
}


class HttpxParser:
    """Parses httpx JSONL output into Subdomain and WebPath objects."""

    def parse(self, raw: str, mission_id: str,
              source_agent: str) -> list[IntelBase]:
        if not raw or not raw.strip():
            return []
        try:
            return self._parse(raw, mission_id, source_agent)
        except Exception as e:
            logger.warning(f"HttpxParser failed: {e} | raw[:200]={raw[:200]!r}")
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

            url = data.get("url", "") or data.get("input", "")
            if not url:
                continue

            status = data.get("status_code") or data.get("status-code") or 0
            try:
                status = int(status)
            except (ValueError, TypeError):
                status = 0

            # Extract host from URL
            host_part = url.split("//", 1)[-1].split("/")[0]
            host_no_port = host_part.split(":")[0]

            content_type = (data.get("content_type") or
                            data.get("content-type") or "")

            # Interesting path detection
            url_lower = url.lower()
            is_interesting = (
                status in (401, 403) or
                any(kw in url_lower for kw in INTERESTING_PATHS)
            )
            reason = ""
            if status in (401, 403):
                reason = "auth required"
            elif any(kw in url_lower for kw in INTERESTING_PATHS):
                matched = next(kw for kw in INTERESTING_PATHS if kw in url_lower)
                reason = f"sensitive path: {matched}"

            findings.append(WebPath(
                source_agent=source_agent,
                source_tool="httpx",
                confidence=0.90,
                mission_id=mission_id,
                host_id=host_no_port,
                url=url,
                status_code=status,
                content_type=content_type,
                interesting=is_interesting,
                reason=reason or None,
            ))

            # Also produce a Subdomain if technologies were detected
            tech = data.get("tech") or data.get("technologies") or []
            if isinstance(tech, str):
                tech = [tech]

            ip_list = data.get("a") or data.get("host") or []
            if isinstance(ip_list, str):
                ip_list = [ip_list]
            resolved_ip = ip_list[0] if ip_list else None

            title = data.get("title") or data.get("web_title")

            findings.append(Subdomain(
                source_agent=source_agent,
                source_tool="httpx",
                confidence=0.90,
                mission_id=mission_id,
                domain=host_no_port,
                ip=resolved_ip,
                http_status=status,
                http_title=title,
                technologies=tech if isinstance(tech, list) else [],
            ))

        web_count = sum(1 for f in findings if isinstance(f, WebPath))
        sub_count = sum(1 for f in findings if isinstance(f, Subdomain))
        logger.info(f"HttpxParser: {web_count} web paths, {sub_count} subdomains")
        return findings
