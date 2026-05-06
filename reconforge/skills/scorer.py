"""
ReconForge Severity Scorer — V2.
CVSS→severity is a lookup table (pure Python, no LLM).
LLM kept ONLY for contextual re-scoring where env context overrides CVSS.
Routes contextual_scoring → Groq (fast).
"""
import json
from typing import Optional

from reconforge.intel.models import Vulnerability
from reconforge.llm.router import LLMRouter
from reconforge.utils.logger import get_logger

logger = get_logger("scorer")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

SCORER_SYSTEM_PROMPT = """You are a vulnerability severity scorer.
Re-evaluate severity only when environmental context meaningfully changes the risk.

Context factors that INCREASE severity:
- Internet-facing service + no WAF + known exploit available
- Critical business service (auth, database, payment)
- Default credentials exposed

Context factors that DECREASE severity:
- Confirmed internal-only, no external exposure
- Already patched or mitigated
- Low-value asset

Output ONLY valid JSON:
{"severity": "critical"|"high"|"medium"|"low"|"info", "confidence": 0.0-1.0,
 "reason": str, "cvss_adjustment": float|null}"""


def cvss_to_severity(score: Optional[float]) -> str:
    """Pure Python CVSS score → severity label. No LLM. No network."""
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "info"


class SeverityScorer:
    """Re-evaluates severity. CVSS→label is deterministic. Context override uses Groq."""

    def __init__(self, router: Optional[LLMRouter] = None,
                 # Legacy compat
                 client=None) -> None:
        self.router = router
        self.stats = {"rescored": 0, "upgraded": 0, "downgraded": 0, "unchanged": 0}

    async def score(self, vuln: Vulnerability, context: dict) -> Vulnerability:
        """
        First apply deterministic CVSS label, then optionally use Groq for
        contextual adjustment when environment factors justify it.
        """
        # Step 1: deterministic CVSS label (always)
        if vuln.cvss_score is not None:
            cvss_severity = cvss_to_severity(vuln.cvss_score)
            if vuln.severity == "info" and cvss_severity != "info":
                # Upgrade bare "info" if we have a CVSS score
                vuln.severity = cvss_severity

        # Step 2: contextual re-scoring (LLM) only if context has meaningful data
        has_context = any(context.get(k) for k in
                          ("internet_facing", "waf_detected", "service",
                           "technologies", "other_vulns"))
        if has_context and self.router:
            return await self._llm_score(vuln, context)

        # Step 3: heuristic fallback
        return self._heuristic_score(vuln, context)

    async def _llm_score(self, vuln: Vulnerability, context: dict) -> Vulnerability:
        prompt = (
            f"Re-evaluate this vulnerability's severity based on context:\n\n"
            f"Vulnerability: {json.dumps({'title': vuln.title, 'severity': vuln.severity, 'cvss_score': vuln.cvss_score, 'exploit_available': vuln.exploit_available}, indent=2)}\n\n"
            f"Context: {json.dumps(context, indent=2, default=str)[:2000]}")
        try:
            text = await self.router.call(
                task_type="contextual_scoring", system=SCORER_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}], max_tokens=512)
            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            result = json.loads(text)
            return self._apply_score(vuln, result)
        except Exception as e:
            logger.warning(f"Groq contextual scoring failed: {e}, using heuristic")
            return self._heuristic_score(vuln, context)

    def _apply_score(self, vuln: Vulnerability, result: dict) -> Vulnerability:
        original = vuln.severity
        new_sev = result.get("severity", vuln.severity)
        self.stats["rescored"] += 1
        try:
            if SEVERITY_ORDER.index(new_sev) > SEVERITY_ORDER.index(original):
                self.stats["upgraded"] += 1
                logger.info(f"Severity ↑ {vuln.title}: {original}→{new_sev}")
            elif SEVERITY_ORDER.index(new_sev) < SEVERITY_ORDER.index(original):
                self.stats["downgraded"] += 1
                logger.info(f"Severity ↓ {vuln.title}: {original}→{new_sev}")
            else:
                self.stats["unchanged"] += 1
        except ValueError:
            self.stats["unchanged"] += 1

        vuln.severity = new_sev
        vuln.confidence = result.get("confidence", vuln.confidence)
        adj = result.get("cvss_adjustment")
        if adj is not None and vuln.cvss_score is not None:
            vuln.cvss_score = max(0.0, min(10.0, vuln.cvss_score + adj))
        return vuln

    def _heuristic_score(self, vuln: Vulnerability, context: dict) -> Vulnerability:
        boost = 0
        if context.get("internet_facing"):
            boost += 1
        if not context.get("waf_detected"):
            boost += 0.5
        if vuln.exploit_available:
            boost += 1
        if any(s in context.get("service", "").lower()
               for s in ("database", "auth", "admin", "payment", "ssh")):
            boost += 0.5
        try:
            idx = SEVERITY_ORDER.index(vuln.severity)
        except ValueError:
            idx = 0
        vuln.severity = SEVERITY_ORDER[min(len(SEVERITY_ORDER) - 1, int(idx + boost))]
        self.stats["rescored"] += 1
        return vuln

    async def score_batch(self, vulns: list[Vulnerability],
                          context: dict) -> list[Vulnerability]:
        return [await self.score(v, context) for v in vulns]

    def get_stats(self) -> dict:
        return self.stats.copy()
