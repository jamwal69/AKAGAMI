"""
ReconForge Report Generator — Professional Markdown pentest report.

Generates a comprehensive report with:
- Claude-powered executive summary narrative
- Structured Jinja2 template for findings
- Risk scoring and prioritized remediation
- Attack surface visualization data
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reconforge.llm.router import LLMRouter
from typing import Optional
from jinja2 import Environment, FileSystemLoader
from tenacity import retry, stop_after_attempt, wait_exponential

from reconforge.intel.store import IntelStore
from reconforge.memory.episodic import EpisodicMemory
from reconforge.utils.logger import get_logger

logger = get_logger("report")

REPORT_SECTIONS = [
    "executive_summary",
    "scope_and_methodology",
    "attack_surface_overview",
    "hosts_and_services",
    "vulnerabilities",
    "osint_findings",
    "web_application_findings",
    "credentials_and_secrets",
    "recommendations",
    "appendix",
]

EXEC_SUMMARY_PROMPT = """You are writing the executive summary for a professional penetration testing report.
Write a concise, executive-friendly summary that covers:
1. Scope of the assessment
2. Key findings (most critical first)
3. Overall risk posture
4. Top 3 recommendations

Use professional language. No technical jargon. Focus on business impact.
Keep it under 300 words. Output ONLY the executive summary text, no JSON."""

RECOMMENDATIONS_PROMPT = """Based on these reconnaissance findings, generate prioritized security recommendations.
For each recommendation include: priority (P1-P4), title, description, and estimated effort.
Output ONLY valid JSON array:
[{"priority": "P1"|"P2"|"P3"|"P4", "title": str, "description": str, "effort": "low"|"medium"|"high"}]"""


class ReportGenerator:
    """Generates professional Markdown pentest reports from intel store."""

    def __init__(self, template_dir: str = "reconforge/report/templates",
                 router: Optional[LLMRouter] = None, client=None) -> None:
        self.template_dir = Path(template_dir)
        self.client = client
        self.env = None
        if self.template_dir.exists():
            self.env = Environment(
                loader=FileSystemLoader(str(self.template_dir)),
                trim_blocks=True,
                lstrip_blocks=True,
            )

    async def generate(self, intel: IntelStore, mission_id: str,
                       output_path: str = "output/report.md",
                       mission_name: str = "",
                       target: str = "",
                       episodic: Optional[EpisodicMemory] = None) -> str:
        """
        Generate full professional report.

        Returns the report content string.
        """
        data = intel.export_json(mission_id)
        summary = intel.get_attack_surface_summary(mission_id)

        # Generate Claude-powered sections
        exec_summary = await self._generate_executive_summary(
            data, summary, target, mission_name)
        recommendations = await self._generate_recommendations(data, summary)

        # Compute risk score
        risk = self._compute_risk_score(summary)

        # Get mission timeline from episodic memory
        timeline = []
        if episodic:
            try:
                actions = episodic.get_recent_actions(mission_id, limit=50)
                timeline = actions
            except Exception:
                pass

        # Build template context
        context = {
            "mission_id": mission_id,
            "mission_name": mission_name or f"Reconnaissance: {target}",
            "target": target,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "data": data,
            "summary": summary,
            "executive_summary": exec_summary,
            "recommendations": recommendations,
            "risk_score": risk,
            "timeline": timeline,
            "vuln_stats": self._compute_vuln_stats(data),
        }

        # Render with Jinja2 template or fallback
        if self.env and (self.template_dir / "recon_report.md.j2").exists():
            template = self.env.get_template("recon_report.md.j2")
            report = template.render(**context)
        else:
            report = self._generate_full_report(context)

        # Write output
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            f.write(report)

        logger.info(f"Report generated: {output_path} ({len(report)} chars)")
        return report

    # ── Claude-powered sections ──────────────────────────────

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=1, max=10))
    async def _generate_executive_summary(self, data: dict, summary: dict,
                                          target: str, mission_name: str) -> str:
        """Generate executive summary using Claude."""
        if not self.client:
            return self._fallback_exec_summary(summary, target)

        try:
            prompt = (
                f"Target: {target}\nMission: {mission_name}\n\n"
                f"Attack surface:\n{json.dumps(summary, indent=2, default=str)}\n\n"
                f"Hosts: {len(data.get('hosts', []))}\n"
                f"Open ports: {len(data.get('ports', []))}\n"
                f"Vulnerabilities: {len(data.get('vulnerabilities', []))}\n"
                f"Critical vulns: {summary.get('vulnerabilities_by_severity', {}).get('critical', 0)}\n"
                f"Credentials found: {summary.get('credentials_found', 0)}\n"
            )
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514", max_tokens=512,
                system=EXEC_SUMMARY_PROMPT,
                messages=[{"role": "user", "content": prompt}])
            return response.content[0].text.strip()
        except Exception as e:
            logger.warning(f"Exec summary generation failed: {e}")
            return self._fallback_exec_summary(summary, target)

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=1, max=10))
    async def _generate_recommendations(self, data: dict,
                                        summary: dict) -> list[dict]:
        """Generate prioritized recommendations using Claude."""
        if not self.client:
            return self._fallback_recommendations(summary)

        try:
            prompt = (
                f"Attack surface:\n{json.dumps(summary, indent=2, default=str)}\n\n"
                f"Vulnerabilities ({len(data.get('vulnerabilities', []))}):\n"
                f"{json.dumps(data.get('vulnerabilities', [])[:10], indent=2, default=str)[:3000]}\n\n"
                f"Missing coverage: {summary.get('missing_coverage', [])}"
            )
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514", max_tokens=1024,
                system=RECOMMENDATIONS_PROMPT,
                messages=[{"role": "user", "content": prompt}])

            text = response.content[0].text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            return json.loads(text)
        except Exception as e:
            logger.warning(f"Recommendations generation failed: {e}")
            return self._fallback_recommendations(summary)

    # ── Risk scoring ─────────────────────────────────────────

    def _compute_risk_score(self, summary: dict) -> dict:
        """Compute overall risk score from findings."""
        vuln_counts = summary.get("vulnerabilities_by_severity", {})
        critical = vuln_counts.get("critical", 0)
        high = vuln_counts.get("high", 0)
        medium = vuln_counts.get("medium", 0)
        low = vuln_counts.get("low", 0)
        creds = summary.get("credentials_found", 0)

        # Weighted score
        score = (critical * 40) + (high * 20) + (medium * 5) + (low * 1) + (creds * 30)
        normalized = min(100, score)

        if normalized >= 80:
            rating = "CRITICAL"
            color = "🔴"
        elif normalized >= 60:
            rating = "HIGH"
            color = "🟠"
        elif normalized >= 30:
            rating = "MEDIUM"
            color = "🟡"
        elif normalized > 0:
            rating = "LOW"
            color = "🟢"
        else:
            rating = "INFORMATIONAL"
            color = "🔵"

        return {
            "score": normalized,
            "rating": rating,
            "color": color,
            "breakdown": {
                "critical_vulns": critical,
                "high_vulns": high,
                "medium_vulns": medium,
                "low_vulns": low,
                "credentials": creds,
            },
        }

    def _compute_vuln_stats(self, data: dict) -> dict:
        """Compute vulnerability statistics for the report."""
        vulns = data.get("vulnerabilities", [])
        by_severity = {}
        by_host = {}
        exploitable = 0

        for v in vulns:
            sev = v.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            host = v.get("host_id", "unknown")
            by_host[host] = by_host.get(host, 0) + 1
            if v.get("exploit_available"):
                exploitable += 1

        return {
            "total": len(vulns),
            "by_severity": by_severity,
            "by_host": by_host,
            "exploitable": exploitable,
            "most_affected_host": max(by_host, key=by_host.get) if by_host else None,
        }

    # ── Fallbacks ────────────────────────────────────────────

    def _fallback_exec_summary(self, summary: dict, target: str) -> str:
        """Generate executive summary without Claude."""
        vulns = summary.get("vulnerabilities_by_severity", {})
        critical = vulns.get("critical", 0)
        high = vulns.get("high", 0)
        total_vulns = sum(vulns.values()) if vulns else 0

        return (
            f"A reconnaissance assessment was performed against {target}. "
            f"The assessment identified {summary.get('hosts_discovered', 0)} hosts, "
            f"{summary.get('open_ports', 0)} open ports, and "
            f"{summary.get('subdomains', 0)} subdomains. "
            f"A total of {total_vulns} potential vulnerabilities were identified, "
            f"including {critical} critical and {high} high severity issues. "
            f"{summary.get('credentials_found', 0)} credentials were discovered. "
            f"{'Immediate remediation is recommended for critical findings.' if critical else 'No critical vulnerabilities were identified.'}"
        )

    def _fallback_recommendations(self, summary: dict) -> list[dict]:
        """Generate basic recommendations without Claude."""
        recs = []
        vulns = summary.get("vulnerabilities_by_severity", {})

        if vulns.get("critical", 0) > 0:
            recs.append({
                "priority": "P1", "effort": "high",
                "title": "Remediate Critical Vulnerabilities",
                "description": f"{vulns['critical']} critical vulnerabilities require immediate patching."})

        if vulns.get("high", 0) > 0:
            recs.append({
                "priority": "P2", "effort": "medium",
                "title": "Address High Severity Issues",
                "description": f"{vulns['high']} high severity vulnerabilities should be remediated within 30 days."})

        if summary.get("credentials_found", 0) > 0:
            recs.append({
                "priority": "P1", "effort": "low",
                "title": "Rotate Exposed Credentials",
                "description": "Credentials were discovered during reconnaissance. Immediate rotation required."})

        gaps = summary.get("missing_coverage", [])
        if gaps:
            recs.append({
                "priority": "P3", "effort": "medium",
                "title": "Address Coverage Gaps",
                "description": f"The following areas need further investigation: {', '.join(gaps[:3])}"})

        return recs

    # ── Full report (no template) ────────────────────────────

    def _generate_full_report(self, ctx: dict) -> str:
        """Generate complete report when Jinja2 template is unavailable."""
        lines = []
        data = ctx["data"]
        summary = ctx["summary"]
        risk = ctx["risk_score"]

        # Header
        lines.append(f"# Reconnaissance Report — {ctx['mission_name']}")
        lines.append(f"\n**Target:** {ctx['target']}")
        lines.append(f"**Mission ID:** {ctx['mission_id']}")
        lines.append(f"**Generated:** {ctx['generated_at']}")
        lines.append(f"\n---\n")

        # Risk score
        lines.append(f"## Risk Assessment\n")
        lines.append(f"**Overall Risk: {risk['color']} {risk['rating']} ({risk['score']}/100)**\n")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for sev in ["critical", "high", "medium", "low"]:
            count = risk["breakdown"].get(f"{sev}_vulns", 0)
            if count:
                lines.append(f"| {sev.title()} | {count} |")
        lines.append("")

        # Executive summary
        lines.append(f"## Executive Summary\n")
        lines.append(ctx["executive_summary"])
        lines.append(f"\n---\n")

        # Attack surface
        lines.append("## Attack Surface Overview\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        for key, val in summary.items():
            if key != "missing_coverage" and key != "vulnerabilities_by_severity":
                lines.append(f"| {key.replace('_', ' ').title()} | {val} |")
        lines.append("")

        # Hosts
        if data.get("hosts"):
            lines.append("## Hosts and Services\n")
            lines.append("| IP | Hostname | OS | Tags |")
            lines.append("|----|----------|----|----|")
            for h in data["hosts"]:
                lines.append(
                    f"| {h.get('ip', '-')} | {h.get('hostname', '-')} | "
                    f"{h.get('os_guess', '-')} | {h.get('tags', '-')} |")
            lines.append("")

        # Ports
        if data.get("ports"):
            lines.append("### Open Ports\n")
            lines.append("| Port | Protocol | Service | Version |")
            lines.append("|------|----------|---------|---------|")
            for p in data["ports"][:50]:
                lines.append(
                    f"| {p.get('port', '-')} | {p.get('protocol', '-')} | "
                    f"{p.get('service', '-')} | {p.get('version', '-')} |")
            lines.append("")

        # Vulnerabilities
        if data.get("vulnerabilities"):
            lines.append("## Vulnerabilities\n")
            lines.append("| Severity | Title | CVE | CVSS | Exploit |")
            lines.append("|----------|-------|-----|------|---------|")
            for v in sorted(data["vulnerabilities"],
                            key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                                           "low": 3, "info": 4}.get(
                                           x.get("severity", "info"), 5)):
                lines.append(
                    f"| {v.get('severity', '-').upper()} | {v.get('title', '-')[:50]} | "
                    f"{v.get('cve_id', '-')} | {v.get('cvss_score', '-')} | "
                    f"{'✅' if v.get('exploit_available') else '❌'} |")
            lines.append("")

        # Web paths
        interesting = [p for p in data.get("web_paths", []) if p.get("interesting")]
        if interesting:
            lines.append("## Interesting Web Paths\n")
            lines.append("| URL | Status | Reason |")
            lines.append("|-----|--------|--------|")
            for p in interesting[:30]:
                lines.append(
                    f"| {p.get('url', '-')[:60]} | {p.get('status_code', '-')} | "
                    f"{p.get('reason', '-')[:40]} |")
            lines.append("")

        # OSINT
        if data.get("osint_findings"):
            lines.append("## OSINT Findings\n")
            lines.append("| Category | Value | Context |")
            lines.append("|----------|-------|---------|")
            for f in data["osint_findings"][:30]:
                lines.append(
                    f"| {f.get('category', '-')} | {str(f.get('value', '-'))[:40]} | "
                    f"{str(f.get('context', '-'))[:50]} |")
            lines.append("")

        # Recommendations
        if ctx.get("recommendations"):
            lines.append("## Recommendations\n")
            for rec in ctx["recommendations"]:
                lines.append(
                    f"### [{rec.get('priority', 'P3')}] {rec.get('title', '')}\n")
                lines.append(f"{rec.get('description', '')}")
                lines.append(f"**Effort:** {rec.get('effort', 'medium')}\n")

        # Missing coverage
        if summary.get("missing_coverage"):
            lines.append("## Coverage Gaps\n")
            for gap in summary["missing_coverage"]:
                lines.append(f"- ⚠ {gap}")
            lines.append("")

        lines.append(f"\n---\n*Report generated by ReconForge v0.1.0*\n")
        return "\n".join(lines)
