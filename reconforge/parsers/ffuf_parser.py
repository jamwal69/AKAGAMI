"""
ffuf deterministic parser — reads ffuf JSON output (-of json flag).
Zero LLM. Instant. Deterministic.
"""
import json
from reconforge.intel.models import WebPath, IntelBase
from reconforge.utils.logger import get_logger

logger = get_logger("parser.ffuf")


class FfufParser:
    """Parses ffuf JSON output into WebPath objects."""

    def parse(self, raw: str, mission_id: str,
              source_agent: str) -> list[IntelBase]:
        if not raw or not raw.strip():
            return []
        try:
            return self._parse(raw, mission_id, source_agent)
        except Exception as e:
            logger.warning(f"FfufParser failed: {e} | raw[:200]={raw[:200]!r}")
            return []

    def _parse(self, raw: str, mission_id: str,
               source_agent: str) -> list[IntelBase]:
        findings: list[IntelBase] = []

        results = self._load_results(raw)
        if not isinstance(results, list):
            return []

        for item in results:
            if not isinstance(item, dict):
                logger.warning(f"FfufParser: skipping non-object result: {item!r}")
                continue

            input_data = item.get("input", {})
            if not isinstance(input_data, dict):
                input_data = {}

            url = item.get("url", "")
            if not url and input_data.get("FUZZ"):
                url = str(input_data["FUZZ"])
            if not url:
                continue

            status = item.get("status", 0)
            try:
                status = int(status)
            except (ValueError, TypeError):
                status = 0

            length = item.get("length", 0)
            try:
                length = int(length)
            except (ValueError, TypeError):
                length = 0

            # Host from URL
            host_part = url.split("//", 1)[-1].split("/")[0].split(":")[0]

            # Interesting detection
            is_interesting = False
            reason = ""

            if status in (401, 403):
                is_interesting = True
                reason = "auth required"
            elif status == 200 and length < 100:
                is_interesting = True
                reason = "possible redirect or empty"
            elif status == 200:
                is_interesting = True
                reason = f"found (size={length})"

            findings.append(WebPath(
                source_agent=source_agent,
                source_tool="ffuf",
                confidence=0.85,
                mission_id=mission_id,
                host_id=host_part,
                url=url,
                status_code=status,
                content_type=item.get("content-type", "") or "",
                interesting=is_interesting,
                reason=reason or None,
            ))

        logger.info(f"FfufParser: {len(findings)} paths")
        return findings

    def _load_results(self, raw: str) -> list:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("FfufParser: could not parse JSON")
            return []

        if isinstance(data, dict):
            results = data.get("results", [])
            return results if isinstance(results, list) else []
        if isinstance(data, list):
            return data

        logger.warning(f"FfufParser: unsupported JSON shape: {type(data).__name__}")
        return []
