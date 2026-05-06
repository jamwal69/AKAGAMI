"""
ReconForge CVE Enricher — V2. Uses LLMRouter (Groq) for CVE correlation.
Pipeline: ChromaDB → NVD API → Groq enrichment.
"""
import json
import re
import urllib.request
import urllib.parse
from typing import Optional

from reconforge.intel.models import Severity, Vulnerability
from reconforge.llm.router import LLMRouter
from reconforge.memory.semantic import SemanticMemory
from reconforge.utils.logger import get_logger

logger = get_logger("enricher")

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$")
VALID_SEVERITIES = {s.value for s in Severity}

ENRICHER_SYSTEM_PROMPT = """You are a CVE enrichment specialist.
Given a vulnerability finding and CVE database matches, enhance the finding with:
1. Correct CVE ID (if missing)
2. Accurate CVSS score
3. Specific remediation steps
4. Whether a public exploit exists
5. Adjusted severity

Output ONLY valid JSON:
{"cve_id": str|null, "cvss_score": float|null, "severity": str,
 "description": str, "remediation": str, "exploit_available": bool,
 "exploit_reference": str|null, "confidence": float}"""


class CveEnricher:
    """Enriches vulnerabilities with CVE data via ChromaDB RAG + NVD + Groq."""

    def __init__(self, semantic: Optional[SemanticMemory] = None,
                 router: Optional[LLMRouter] = None,
                 # Legacy compat
                 client=None) -> None:
        self.semantic = semantic
        self.router = router
        self.stats = {"enriched": 0, "local_hits": 0, "nvd_hits": 0,
                      "llm_enriched": 0, "unchanged": 0}

    async def enrich(self, vuln: Vulnerability,
                     service: str = "", version: str = "") -> Vulnerability:
        if vuln.cve_id and vuln.cvss_score and vuln.remediation:
            self.stats["unchanged"] += 1
            return vuln

        cve_matches: list[dict] = []

        if self.semantic:
            cve_matches = self.semantic.query_cves(
                service=service or vuln.title, version=version, n_results=5)
            if cve_matches:
                self.stats["local_hits"] += 1

        if not cve_matches and (service or vuln.cve_id):
            cve_matches = await self._query_nvd(
                cve_id=vuln.cve_id,
                keyword=f"{service} {version}".strip() if not vuln.cve_id else "")
            if cve_matches:
                self.stats["nvd_hits"] += 1

        if cve_matches and self.router:
            vuln = await self._llm_enrich(vuln, cve_matches, service, version)
            self.stats["llm_enriched"] += 1
        elif cve_matches:
            vuln = self._heuristic_enrich(vuln, cve_matches)

        self.stats["enriched"] += 1
        return vuln

    async def enrich_batch(self, vulns: list[Vulnerability],
                           service_map: Optional[dict] = None) -> list[Vulnerability]:
        service_map = service_map or {}
        enriched = []
        for vuln in vulns:
            svc = service_map.get(vuln.host_id, {})
            enriched.append(await self.enrich(
                vuln, service=svc.get("service", ""),
                version=svc.get("version", "")))
        return enriched

    async def _query_nvd(self, cve_id: str = "", keyword: str = "") -> list[dict]:
        try:
            if cve_id:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            elif keyword:
                enc = urllib.parse.quote(keyword)
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={enc}&resultsPerPage=5"
            else:
                return []

            req = urllib.request.Request(url, headers={
                "User-Agent": "ReconForge/2.0", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            results = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_data = {}
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        obj = metrics[key][0].get("cvssData", {})
                        cvss_data = {"score": obj.get("baseScore"),
                                     "severity": obj.get("baseSeverity", "").lower()}
                        break
                desc = next((d["value"] for d in cve.get("descriptions", [])
                             if d.get("lang") == "en"), "")
                refs = [r.get("url", "") for r in cve.get("references", [])[:5]]
                results.append({"cve_id": cve.get("id", ""), "description": desc,
                                 "cvss_score": cvss_data.get("score"),
                                 "severity": cvss_data.get("severity", ""),
                                 "references": refs, "source": "nvd_api"})
            return results
        except Exception as e:
            logger.debug(f"NVD API query failed: {e}")
            return []

    async def _llm_enrich(self, vuln: Vulnerability, cve_matches: list[dict],
                          service: str, version: str) -> Vulnerability:
        prompt = (
            f"Enrich this vulnerability with the CVE data.\n\n"
            f"Finding: {json.dumps(vuln.model_dump(include={'title', 'description', 'severity', 'cve_id', 'cvss_score', 'evidence'}), indent=2, default=str)}\n\n"
            f"Service: {service} {version}\n\n"
            f"CVE matches:\n{json.dumps(cve_matches[:5], indent=2, default=str)[:3000]}")
        try:
            text = await self.router.call(
                task_type="cve_enrichment", system=ENRICHER_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}], max_tokens=1024)
            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            enrichment = json.loads(text)
            logger.info(f"[Groq] Enriched: {vuln.title} → CVE:{enrichment.get('cve_id')}")
            return self._apply_enrichment(vuln, enrichment)
        except Exception as e:
            logger.warning(f"Groq CVE enrichment failed: {e}")
            return self._heuristic_enrich(vuln, cve_matches)

    def _heuristic_enrich(self, vuln: Vulnerability, cve_matches: list[dict]) -> Vulnerability:
        if not cve_matches:
            return vuln
        best = cve_matches[0]
        if "metadata" in best:
            meta = best["metadata"]
            if not vuln.cve_id and meta.get("cve_id"):
                cve_id = self._valid_cve_id(meta.get("cve_id"))
                if cve_id:
                    vuln.cve_id = cve_id
            if not vuln.cvss_score and meta.get("cvss_score"):
                vuln.cvss_score = self._clamp_float(meta["cvss_score"], 0.0, 10.0)
            if meta.get("severity"):
                vuln.severity = self._valid_severity(meta["severity"], vuln.severity)
        else:
            if not vuln.cve_id and best.get("cve_id"):
                cve_id = self._valid_cve_id(best.get("cve_id"))
                if cve_id:
                    vuln.cve_id = cve_id
            if not vuln.cvss_score and best.get("cvss_score"):
                vuln.cvss_score = self._clamp_float(best["cvss_score"], 0.0, 10.0)
            if best.get("severity"):
                vuln.severity = self._valid_severity(best["severity"], vuln.severity)
            if best.get("description") and not vuln.description:
                vuln.description = best["description"][:500]
            if best.get("references"):
                vuln.exploit_reference = ", ".join(best["references"][:3])
        return vuln

    def _apply_enrichment(self, vuln: Vulnerability, e: dict) -> Vulnerability:
        if e.get("cve_id"):
            cve_id = self._valid_cve_id(e.get("cve_id"))
            if cve_id:
                vuln.cve_id = cve_id
        if e.get("cvss_score") is not None:
            vuln.cvss_score = self._clamp_float(e["cvss_score"], 0.0, 10.0)
        if e.get("severity"):
            vuln.severity = self._valid_severity(e["severity"], vuln.severity)
        if e.get("description"):
            vuln.description = e["description"]
        if e.get("remediation"):
            vuln.remediation = e["remediation"]
        if e.get("exploit_available") is not None:
            vuln.exploit_available = bool(e["exploit_available"])
        if e.get("exploit_reference"):
            vuln.exploit_reference = e["exploit_reference"]
        if e.get("confidence") is not None:
            vuln.confidence = self._clamp_float(e["confidence"], 0.0, 1.0)
        return vuln

    def _valid_cve_id(self, value) -> Optional[str]:
        cve_id = str(value or "").strip().upper()
        if not cve_id or not CVE_ID_RE.match(cve_id):
            logger.warning(f"Rejecting invalid CVE ID from enrichment: {value!r}")
            return None
        return cve_id

    def _valid_severity(self, value, fallback: str) -> str:
        severity = str(value or "").strip().lower()
        if severity not in VALID_SEVERITIES:
            logger.warning(f"Rejecting invalid severity from enrichment: {value!r}")
            return fallback
        return severity

    def _clamp_float(self, value, minimum: float, maximum: float) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return minimum
        return max(minimum, min(maximum, number))

    def get_stats(self) -> dict:
        return self.stats.copy()
