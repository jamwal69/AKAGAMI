"""
ReconForge Stage Gate — V2.
Arithmetic metrics are pure Python. LLM (NIM) only for final go/no-go judgment.
"""
import json
from typing import Optional

from reconforge.intel.models import GateResult, MissionState
from reconforge.intel.store import IntelStore
from reconforge.llm.router import LLMRouter
from reconforge.utils.logger import get_logger

logger = get_logger("stage_gate")

GATE_THRESHOLDS = {
    "min_hosts_verified": 1,
    "min_ports_per_host": 100,
    "min_osint_categories": 3,
    "min_confidence_average": 0.6,
    "require_vuln_scan": True,
    "require_operator_approval": True,
}

GATE_SYSTEM_PROMPT = """You are a QA reviewer for a penetration testing team.
Evaluate whether reconnaissance is thorough enough to proceed to exploitation.

Analyze: host coverage, service enumeration, vulnerability coverage,
OSINT completeness, web application coverage, missing areas.

Output ONLY valid JSON:
{
  "passed": bool,
  "confidence": float,
  "reason": "Brief summary",
  "scores": {"host_coverage": float, "service_enumeration": float,
             "vulnerability_coverage": float, "osint_completeness": float,
             "web_application": float},
  "missing_coverage": ["list of gaps"],
  "recommendations": ["list of next steps if not passed"]
}"""


class StageGate:
    """Evaluates recon completeness. Arithmetic in Python, judgment via NIM."""

    def __init__(self, router: Optional[LLMRouter] = None,
                 thresholds: Optional[dict] = None,
                 # Legacy compat
                 client=None) -> None:
        self.router = router
        self.thresholds = {**GATE_THRESHOLDS, **(thresholds or {})}

    async def evaluate(self, intel: IntelStore,
                       mission: MissionState) -> GateResult:
        summary = intel.get_attack_surface_summary(mission.mission_id)
        data = intel.export_json(mission.mission_id)

        # Step 1: pure Python arithmetic metrics
        metrics = self._compute_metrics(summary, data)

        # Step 2: quantitative threshold checks (pure Python)
        quant_passed, quant_failures = self._check_quantitative(metrics)

        # Step 3: LLM final judgment (NIM) — only for go/no-go call
        if self.router:
            qual = await self._llm_evaluate(summary, data, mission)
        else:
            qual = self._heuristic_evaluate(metrics, summary)

        passed = quant_passed and qual.get("passed", False)
        confidence = min(
            metrics.get("overall_confidence", 0.5),
            qual.get("confidence", 0.5))

        missing = list(set(
            summary.get("missing_coverage", []) +
            qual.get("missing_coverage", []) +
            quant_failures))

        recommendations = qual.get("recommendations", [])
        if not passed and not recommendations:
            recommendations = [f"Address: {gap}" for gap in missing[:5]]

        result = GateResult(
            passed=passed,
            confidence=confidence,
            reason=qual.get("reason", "Quantitative " +
                            ("passed" if quant_passed else "failed")),
            missing_coverage=missing,
            requires_operator_approval=self.thresholds["require_operator_approval"])

        status = "PASSED ✅" if passed else "FAILED ❌"
        logger.info(f"Stage gate: {status} (confidence: {confidence:.0%}) | Missing: {missing}")
        return result

    # ── Pure Python arithmetic ─────────────────────────────────

    def _compute_metrics(self, summary: dict, data: dict) -> dict:
        """All arithmetic. Zero LLM calls."""
        hosts = data.get("hosts", [])
        ports = data.get("ports", [])
        vulns = data.get("vulnerabilities", [])
        osint = data.get("osint_findings", [])
        web_paths = data.get("web_paths", [])
        subdomains = data.get("subdomains", [])

        hosts_count = len(hosts)
        hosts_with_ports = len({p["host_id"] for p in ports})
        osint_categories = {f["category"] for f in osint} if osint else set()
        hosts_vuln_scanned = {v["host_id"] for v in vulns}

        all_findings = hosts + ports + vulns + osint + web_paths + subdomains
        confidences = [f.get("confidence", 0.5) for f in all_findings]
        avg_confidence = sum(confidences) / max(len(confidences), 1)
        verified = sum(1 for f in all_findings if f.get("verified"))
        verified_ratio = verified / max(len(all_findings), 1)
        has_web = any(p.get("service") in ("http", "https") for p in ports)

        return {
            "hosts_discovered": hosts_count,
            "hosts_with_port_scans": hosts_with_ports,
            "total_ports": len(ports),
            "osint_findings": len(osint),
            "osint_categories": len(osint_categories),
            "osint_category_names": list(osint_categories),
            "vulns_found": len(vulns),
            "hosts_vuln_scanned": len(hosts_vuln_scanned),
            "subdomains_found": len(subdomains),
            "web_paths_found": len(web_paths),
            "has_web_services": has_web,
            "average_confidence": round(avg_confidence, 3),
            "verified_ratio": round(verified_ratio, 3),
            "overall_confidence": round(avg_confidence * 0.7 + verified_ratio * 0.3, 3),
            "total_findings": len(all_findings),
        }

    def _check_quantitative(self, metrics: dict) -> tuple[bool, list[str]]:
        failures = []
        if metrics["hosts_discovered"] < self.thresholds["min_hosts_verified"]:
            failures.append(f"Need {self.thresholds['min_hosts_verified']} hosts, found {metrics['hosts_discovered']}")
        if metrics["osint_categories"] < self.thresholds["min_osint_categories"]:
            failures.append(
                f"Need {self.thresholds['min_osint_categories']} OSINT categories, "
                f"covered {metrics['osint_categories']} categories from "
                f"{metrics.get('osint_findings', 0)} OSINT findings"
            )
        if metrics["average_confidence"] < self.thresholds["min_confidence_average"]:
            failures.append(f"Avg confidence {metrics['average_confidence']:.0%} below {self.thresholds['min_confidence_average']:.0%}")
        if self.thresholds["require_vuln_scan"] and metrics["vulns_found"] == 0 and metrics["hosts_discovered"] > 0:
            failures.append("No vulnerability scanning performed")
        return len(failures) == 0, failures

    # ── NIM judgment ───────────────────────────────────────────

    async def _llm_evaluate(self, summary: dict, data: dict,
                            mission: MissionState) -> dict:
        """NIM makes the final go/no-go call with full context."""
        prompt = (
            f"Evaluate reconnaissance completeness for: {mission.target}\n\n"
            f"Scope: {json.dumps(mission.scope)}\n"
            f"Active scanning: {'enabled' if mission.active_scan_permitted else 'disabled'}\n\n"
            f"Summary:\n{json.dumps(summary, indent=2, default=str)}\n\n"
            f"Hosts: {len(data.get('hosts', []))} | Ports: {len(data.get('ports', []))} | "
            f"Subdomains: {len(data.get('subdomains', []))} | Vulns: {len(data.get('vulnerabilities', []))} | "
            f"Web paths: {len(data.get('web_paths', []))} | OSINT: {len(data.get('osint_findings', []))}"
        )
        try:
            text = await self.router.call(
                task_type="stage_gate_judgment", system=GATE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}], max_tokens=1024)
            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            logger.debug("[NIM] Stage gate judgment received")
            return json.loads(text)
        except Exception as e:
            logger.warning(f"NIM stage gate evaluation failed: {e}")
            return self._heuristic_evaluate(
                self._compute_metrics(summary, data), summary)

    def _heuristic_evaluate(self, metrics: dict, summary: dict) -> dict:
        scores = {
            "host_coverage": min(1.0, metrics["hosts_discovered"]),
            "service_enumeration": min(1.0, metrics["total_ports"] / 10),
            "vulnerability_coverage": min(1.0, metrics["vulns_found"] / 3),
            "osint_completeness": min(1.0, metrics["osint_categories"] / 3),
            "web_application": min(1.0, metrics["web_paths_found"] / 5),
        }
        avg = sum(scores.values()) / len(scores)
        passed = avg >= 0.5 and metrics["hosts_discovered"] >= 1
        missing = list(summary.get("missing_coverage", []))
        if scores["vulnerability_coverage"] < 0.3:
            missing.append("Insufficient vulnerability scanning")
        return {"passed": passed, "confidence": round(avg, 2),
                "reason": f"Heuristic evaluation: {avg:.0%}",
                "scores": scores, "missing_coverage": missing, "recommendations": []}
