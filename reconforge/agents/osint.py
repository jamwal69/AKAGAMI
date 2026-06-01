"""
ReconForge OSINT Agent — Purely passive intelligence gathering.
Never touches the target network.

Tools:
- whois          (subprocess)
- crt.sh         (HTTPS API)
- theHarvester   (subprocess)
- shodan         (MCP bridge / API)
- github_dork    (MCP bridge / API)
- web_search     (Anthropic built-in tool)
"""

import json
import re
from typing import Optional

from reconforge.llm.router import LLMRouter

from reconforge.agents.base import BaseAgent
from reconforge.intel.models import (
    Credential, Host, IntelBase, MissionState, OsintFinding,
    Port, Subdomain, Task, OsintCategory, OutOfScopeError, ToolExecutionError,
)
from reconforge.intel.store import IntelStore
from reconforge.memory.working import WorkingMemory
from reconforge.tools.bus import ToolBus
from reconforge.tools.mcp_bridge import McpBridge
from reconforge.utils.logger import log_agent_start, log_agent_complete

OSINT_SYSTEM_PROMPT = """You are the OSINT specialist of ReconForge. You only use passive sources.
You NEVER send packets to the target. You gather intelligence from:
public databases, certificate logs, search engines, code repositories,
Shodan's pre-indexed data, and WHOIS records.

Your job is to answer: Who owns this target? What infrastructure exists?
What has leaked publicly? What can an attacker see without touching the target?

Output ONLY JSON arrays of objects with these fields:
- type: "OsintFinding" or "Subdomain" or "Host" or "Credential"
- For OsintFinding: category, value, context, confidence, source_tool
- For Subdomain: domain, ip, cname, technologies, confidence, source_tool
- For Host: ip, hostname, os_guess, tags, confidence, source_tool
- For Credential: service, username, source, confidence, source_tool
No prose. Only valid JSON."""


class OsintAgent(BaseAgent):
    """Passive OSINT gathering agent. Never sends packets to the target."""

    def __init__(self, router: LLMRouter, tool_bus: ToolBus,
                 memory: WorkingMemory,
                 mcp_bridge: Optional[McpBridge] = None) -> None:
        super().__init__("osint_agent", router, tool_bus, memory)
        self.mcp = mcp_bridge

    async def run(self, task: Task, memory: WorkingMemory,
                  intel: IntelStore, mission: MissionState) -> list[IntelBase]:
        """Execute OSINT task and return structured findings."""
        log_agent_start(self.logger, self.name, task.id)
        target = task.params.get("target") or task.params.get("domain", mission.target)
        self._assert_in_scope(target, mission)

        findings: list[IntelBase] = []
        tool = task.tool

        if tool == "whois" or tool == "all":
            findings.extend(await self._run_whois(target, mission))
        if tool == "crt_sh" or tool == "all":
            findings.extend(await self._run_crt_sh(target, mission))
        if tool == "theharvester" or tool == "all":
            findings.extend(await self._run_theharvester(target, mission))
        if tool == "shodan" or tool == "all":
            findings.extend(await self._run_shodan(target, mission))
        if tool == "github_dork" or tool == "all":
            findings.extend(await self._run_github_dork(target, mission))
        if tool == "web_search":
            findings.extend(await self._run_web_search(target, task.params, mission))

        log_agent_complete(self.logger, self.name, task.id, len(findings))
        return findings

    # ── Whois ────────────────────────────────────────────────

    async def _run_whois(self, target: str,
                         mission: MissionState) -> list[IntelBase]:
        """Run whois lookup."""
        try:
            result = await self.tool_bus.call(
                "whois", {"target": target}, mission)
            parsed = self._parse_whois(result.clean, target, mission.mission_id)
            return parsed
        except (OutOfScopeError, PermissionError, ToolExecutionError):
            raise
        except Exception as e:
            self.logger.warning(f"Whois failed for {target}: {e}")
            return []

    def _parse_whois(self, output: str, target: str,
                     mission_id: str) -> list[IntelBase]:
        """Parse whois output deterministically — zero LLM."""
        from reconforge.parsers.whois_parser import WhoisParser
        parser = WhoisParser()
        # Try structured parsing via python-whois first
        findings = parser.parse(target, mission_id, self.name)
        if findings:
            return findings
        # Fallback: parse the raw text output
        findings = parser.parse_raw(output, target, mission_id, self.name)
        if findings:
            return findings
        # Last resort: store raw
        return [OsintFinding(
            source_agent=self.name, source_tool="whois",
            confidence=0.6, mission_id=mission_id,
            category=OsintCategory.WHOIS, value=target,
            context=output[:2000], raw_output=output[:2000])]

    # ── crt.sh ───────────────────────────────────────────────

    async def _run_crt_sh(self, target: str,
                          mission: MissionState) -> list[IntelBase]:
        """Query crt.sh certificate transparency logs."""
        try:
            result = await self.tool_bus.call(
                "crt_sh", {"target": target, "domain": target}, mission)
            return self._parse_crt_sh(result.raw, target, mission.mission_id)
        except (OutOfScopeError, PermissionError, ToolExecutionError):
            raise
        except Exception as e:
            self.logger.warning(f"crt.sh failed for {target}: {e}")
            return []

    def _parse_crt_sh(self, data: str, target: str,
                      mission_id: str) -> list[IntelBase]:
        """Parse crt.sh JSON response into Subdomain objects."""
        findings: list[IntelBase] = []
        try:
            certs = json.loads(data)
            seen_domains = set()
            for cert in certs[:100]:
                name = cert.get("name_value", "")
                for domain in name.split("\n"):
                    domain = domain.strip().lower()
                    if domain and domain not in seen_domains and not domain.startswith("*"):
                        seen_domains.add(domain)
                        findings.append(Subdomain(
                            source_agent=self.name, source_tool="crt_sh",
                            confidence=0.9, mission_id=mission_id,
                            domain=domain, raw_output=json.dumps(cert)[:500]))
                        findings.append(OsintFinding(
                            source_agent=self.name, source_tool="crt_sh",
                            confidence=0.9, mission_id=mission_id,
                            category=OsintCategory.CERT, value=domain,
                            context=f"Found in certificate transparency log (issuer: {cert.get('issuer_name', 'unknown')})"))
        except json.JSONDecodeError:
            self.logger.warning("crt.sh response was not valid JSON")
        return findings

    # ── theHarvester ─────────────────────────────────────────

    async def _run_theharvester(self, target: str,
                                mission: MissionState) -> list[IntelBase]:
        """Run theHarvester for email/subdomain gathering."""
        try:
            result = await self.tool_bus.call(
                "theharvester",
                {"target": target, "domain": target, "source": "all", "limit": 200},
                mission)
            parsed = self._parse_theharvester(result.clean, target, mission.mission_id)
            return parsed
        except (OutOfScopeError, PermissionError, ToolExecutionError):
            raise
        except Exception as e:
            self.logger.warning(f"theHarvester failed for {target}: {e}")
            return []

    def _parse_theharvester(self, output: str, target: str,
                            mission_id: str) -> list[IntelBase]:
        """Parse theHarvester output deterministically — zero LLM."""
        from reconforge.parsers.theharvester_parser import TheHarvesterParser
        parser = TheHarvesterParser()
        # Try JSON parsing first (theHarvester supports JSON output)
        findings = parser.parse(output, mission_id, self.name, target=target)
        if findings:
            return findings
        # Fallback: parse plain text output with regex
        return self._parse_theharvester_text(output, target, mission_id)

    def _parse_theharvester_text(self, output: str, target: str,
                                  mission_id: str) -> list[IntelBase]:
        """Parse theHarvester plain text output using regex — zero LLM."""
        findings: list[IntelBase] = []
        seen = set()

        # Extract emails: anything@domain.tld
        from reconforge.parsers.theharvester_parser import (
            should_keep_theharvester_email,
            value_matches_target_scope,
        )

        for email in re.findall(r'[\w.+-]+@[\w.-]+\.\w{2,}', output):
            email = email.lower().strip()
            if should_keep_theharvester_email(email, target) and email not in seen:
                seen.add(email)
                findings.append(OsintFinding(
                    source_agent=self.name, source_tool="theharvester",
                    confidence=0.85, mission_id=mission_id,
                    category=OsintCategory.EMAIL, value=email,
                    context=f"Email found by theHarvester for {target}"))

        # Extract subdomains: anything.target
        target_escaped = re.escape(target)
        for sub in re.findall(rf'([\w.-]+\.{target_escaped})', output):
            sub = sub.lower().strip()
            if (
                sub not in seen
                and not sub.startswith("*.")
                and value_matches_target_scope(sub, target)
            ):
                seen.add(sub)
                findings.append(Subdomain(
                    source_agent=self.name, source_tool="theharvester",
                    confidence=0.8, mission_id=mission_id,
                    domain=sub))

        # Extract IPs
        for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', output):
            if ip not in seen and not ip.startswith("0.") and not ip.startswith("127."):
                seen.add(ip)
                findings.append(OsintFinding(
                    source_agent=self.name, source_tool="theharvester",
                    confidence=0.75, mission_id=mission_id,
                    category=OsintCategory.OTHER, value=ip,
                    context=f"IP found by theHarvester for {target}"))

        self.logger.info(f"theHarvester text parser: {len(findings)} findings")
        return findings

    # ── Shodan (MCP Bridge) ──────────────────────────────────

    async def _run_shodan(self, target: str,
                          mission: MissionState) -> list[IntelBase]:
        """Query Shodan for pre-indexed data about the target."""
        if not self.mcp:
            self.logger.debug("No MCP bridge configured, skipping Shodan")
            return []

        findings: list[IntelBase] = []
        mission_id = mission.mission_id

        try:
            # Host lookup
            result = await self.tool_bus.call(
                "shodan", {"target": target, "ip": target}, mission)

            if result.exit_code != 0:
                self.logger.warning(f"Shodan lookup failed: {result.error}")
                return []

            # Parse Shodan response
            findings.extend(
                self._parse_shodan(result.raw, target, mission_id))

            # Also search for the domain
            if not target.replace(".", "").isdigit():  # Not an IP
                search_result = await self.tool_bus.call(
                    "shodan_search",
                    {"target": target, "query": f"hostname:{target}"}, mission)
                if search_result.exit_code == 0:
                    findings.extend(
                        self._parse_shodan(search_result.raw, target, mission_id))

        except (OutOfScopeError, PermissionError, ToolExecutionError):
            raise
        except Exception as e:
            self.logger.warning(f"Shodan failed for {target}: {e}")

        return findings

    def _parse_shodan(self, data: str, target: str,
                      mission_id: str) -> list[IntelBase]:
        """Parse Shodan JSON response into structured findings."""
        findings: list[IntelBase] = []
        try:
            shodan_data = json.loads(data)
        except json.JSONDecodeError:
            return []

        # Single host response
        if isinstance(shodan_data, dict) and "ip_str" in shodan_data:
            ip = shodan_data.get("ip_str", "")
            hostnames = shodan_data.get("hostnames", [])
            os_guess = shodan_data.get("os")

            # Create Host
            host = Host(
                source_agent=self.name, source_tool="shodan",
                confidence=0.85, mission_id=mission_id,
                ip=ip, hostname=hostnames[0] if hostnames else None,
                os_guess=os_guess,
                tags=shodan_data.get("tags", []),
                raw_output=json.dumps(shodan_data)[:2000])
            findings.append(host)

            # Create OsintFinding for org/ISP info
            org = shodan_data.get("org", "")
            isp = shodan_data.get("isp", "")
            if org or isp:
                findings.append(OsintFinding(
                    source_agent=self.name, source_tool="shodan",
                    confidence=0.9, mission_id=mission_id,
                    category=OsintCategory.OTHER,
                    value=f"{ip} — {org}",
                    context=f"Organization: {org}, ISP: {isp}, "
                            f"Country: {shodan_data.get('country_code', '?')}"))

            # Extract ports/services from Shodan data
            for service in shodan_data.get("data", []):
                port_num = service.get("port", 0)
                transport = service.get("transport", "tcp")
                product = service.get("product", "")
                version = service.get("version", "")

                findings.append(Port(
                    source_agent=self.name, source_tool="shodan",
                    confidence=0.85, mission_id=mission_id,
                    host_id=host.id, port=port_num,
                    protocol=transport, state="open",
                    service=product or service.get("_shodan", {}).get("module", ""),
                    version=f"{product} {version}".strip() or None,
                    banner=service.get("data", "")[:500]))

            # Extract vulnerabilities from Shodan
            for vuln_id in shodan_data.get("vulns", []):
                findings.append(OsintFinding(
                    source_agent=self.name, source_tool="shodan",
                    confidence=0.75, mission_id=mission_id,
                    category=OsintCategory.OTHER,
                    value=vuln_id,
                    context=f"Shodan reports {vuln_id} for {ip}"))

        # Search results (list of matches)
        elif isinstance(shodan_data, dict) and "matches" in shodan_data:
            for match in shodan_data.get("matches", [])[:20]:
                ip = match.get("ip_str", "")
                findings.append(OsintFinding(
                    source_agent=self.name, source_tool="shodan",
                    confidence=0.8, mission_id=mission_id,
                    category=OsintCategory.OTHER,
                    value=f"{ip}:{match.get('port', '')}",
                    context=f"Shodan: {match.get('product', '')} "
                            f"{match.get('version', '')} "
                            f"({match.get('org', '')})"))

        return findings

    # ── GitHub Dorking (MCP Bridge) ──────────────────────────

    async def _run_github_dork(self, target: str,
                               mission: MissionState) -> list[IntelBase]:
        """Search GitHub for leaked credentials, configs, and code."""
        if not self.mcp:
            self.logger.debug("No MCP bridge configured, skipping GitHub")
            return []

        findings: list[IntelBase] = []
        mission_id = mission.mission_id

        # Standard GitHub dork queries
        dork_queries = [
            f'"{target}" password',
            f'"{target}" api_key OR apikey OR api-key',
            f'"{target}" secret OR token',
            f'org:{target.split(".")[0]} password',
            f'"{target}" filename:.env',
            f'"{target}" filename:config',
        ]

        for query in dork_queries:
            try:
                result = await self.tool_bus.call(
                    "github_code_search",
                    {"target": target, "query": query, "max_results": 5},
                    mission)

                if result.exit_code != 0:
                    continue

                findings.extend(
                    self._parse_github(result.raw, query, target, mission_id))

            except (OutOfScopeError, PermissionError, ToolExecutionError):
                raise
            except Exception as e:
                self.logger.debug(f"GitHub dork '{query[:40]}' failed: {e}")

        return findings

    def _parse_github(self, data: str, query: str, target: str,
                      mission_id: str) -> list[IntelBase]:
        """Parse GitHub code search results."""
        findings: list[IntelBase] = []
        try:
            github_data = json.loads(data)
        except json.JSONDecodeError:
            return []

        items = github_data.get("items", [])
        for item in items[:5]:
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            html_url = item.get("html_url", "")

            findings.append(OsintFinding(
                source_agent=self.name, source_tool="github_dork",
                confidence=0.6, mission_id=mission_id,
                category=OsintCategory.GITHUB,
                value=f"{repo}/{path}",
                context=f"GitHub code match for '{query[:50]}' — {html_url}",
                raw_output=json.dumps(item)[:500]))

            # Check if this looks like a credential leak
            name_lower = path.lower()
            if any(kw in name_lower for kw in [".env", "credential", "secret",
                                                "password", "api_key", "config"]):
                findings.append(OsintFinding(
                    source_agent=self.name, source_tool="github_dork",
                    confidence=0.5, mission_id=mission_id,
                    category=OsintCategory.GITHUB,
                    value=f"POTENTIAL LEAK: {repo}/{path}",
                    context=f"Possible credential/config leak: {html_url}"))

        return findings

    # ── Web Search (MCP Bridge) ──────────────────────────────

    async def _run_web_search(self, target: str, params: dict,
                              mission: MissionState) -> list[IntelBase]:
        """Use web search for additional OSINT gathering."""
        if not self.mcp:
            self.logger.debug("No MCP bridge configured, skipping web search")
            return []

        query = params.get("query", f"{target} site:linkedin.com OR site:github.com")
        try:
            result = await self.tool_bus.call(
                "web_search", {"target": target, "query": query}, mission)
            if result.exit_code != 0:
                return []

            return [OsintFinding(
                source_agent=self.name, source_tool="web_search",
                confidence=0.5, mission_id=mission.mission_id,
                category=OsintCategory.OTHER,
                value=f"Web search: {query[:50]}",
                context=result.clean[:2000],
                raw_output=result.raw[:2000])]
        except (OutOfScopeError, PermissionError, ToolExecutionError):
            raise
        except Exception as e:
            self.logger.warning(f"Web search failed: {e}")
            return []

    # ── Finding builder ──────────────────────────────────────

    def _build_findings(self, parsed_data: list | dict, tool: str,
                        target: str, mission_id: str) -> list[IntelBase]:
        """Convert parsed JSON into IntelBase objects."""
        if isinstance(parsed_data, dict):
            parsed_data = [parsed_data]

        findings = []
        for item in parsed_data:
            obj_type = item.get("type", "OsintFinding")
            item.setdefault("source_agent", self.name)
            item.setdefault("source_tool", tool)
            item.setdefault("mission_id", mission_id)
            item.setdefault("confidence", 0.7)
            item.pop("type", None)

            try:
                if obj_type == "Subdomain":
                    findings.append(Subdomain(**item))
                elif obj_type == "Host":
                    findings.append(Host(**item))
                elif obj_type == "Credential":
                    findings.append(Credential(**item))
                else:
                    findings.append(OsintFinding(**item))
            except Exception as e:
                self.logger.debug(f"Failed to build {obj_type}: {e}")
        return findings
