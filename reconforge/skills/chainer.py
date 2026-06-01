"""
ReconForge Attack Path Chainer
Evaluates a collection of low-severity findings to deduce if a high-severity
chained exploit path exists. Uses SemanticMemory for context on known attack patterns.
"""
import json
from typing import Optional
from pydantic import BaseModel, Field

from reconforge.intel.models import IntelBase, Vulnerability, Severity
from reconforge.llm.router import LLMRouter
from reconforge.memory.semantic import SemanticMemory
from reconforge.utils.logger import get_logger

logger = get_logger("chainer")


class AttackPathResult(BaseModel):
    path_exists: bool = Field(description="True if a realistic attack path can be chained from these findings")
    reasoning: str = Field(description="Detailed explanation of how the findings chain together")
    chained_vulnerability: Optional[dict] = Field(description="If path_exists is true, generate a new Vulnerability JSON object representing the chained exploit")


CHAINER_SYSTEM_PROMPT = """You are a top-tier bug bounty hunter and exploit developer.
You will be provided with a list of low-severity (Info/Low/P4) findings from automated tools,
along with some context from a global knowledge base.

Your job is to determine if these separate low-severity findings can be chained together
to form a high-severity or critical attack path (e.g., SSRF + Cloud Metadata, 
GraphQL Introspection + Weak Auth, CORS wildcard + Session cookies).

If a chain exists:
1. Explain the attack path clearly.
2. Provide a new Vulnerability object with severity="high" or "critical" that encapsulates the chained exploit.

Output strictly according to the provided JSON schema."""


class AttackPathChainer:
    """Skill to deduce attack paths from P4/Info findings."""

    def __init__(self, router: Optional[LLMRouter], semantic: Optional[SemanticMemory] = None) -> None:
        self.router = router
        self.semantic = semantic

    async def evaluate_chain(self, findings: list[IntelBase], mission_id: str) -> Optional[Vulnerability]:
        """Evaluate a list of findings to see if they chain into a higher severity vuln."""
        if len(findings) < 2:
            return None

        # Filter to only relevant findings for chaining (vulnerabilities, secrets, osint)
        chainable = []
        for f in findings:
            if isinstance(f, Vulnerability) and f.severity in (Severity.INFO, Severity.LOW):
                chainable.append(f)
            elif type(f).__name__ in ("SecretFinding", "OsintFinding", "WebPath"):
                chainable.append(f)

        if len(chainable) < 2:
            return None

        if not self.router:
            logger.debug("AttackPathChainer skipped: LLM disabled")
            return None

        findings_json = [json.loads(f.model_dump_json(exclude={"mission_id"})) for f in chainable]

        # Retrieve relevant past patterns
        context = ""
        if self.semantic:
            # Query based on the titles/values of the findings
            query_str = " ".join([f.get("title", f.get("value", "")) for f in findings_json[:3]])
            past_intel = self.semantic.query(query_str, collection="cross_mission_intel", n_results=3)
            if past_intel:
                context = f"\nRelevant past intelligence:\n{json.dumps([p['document'] for p in past_intel], indent=2)}"

        prompt = (f"Analyze these findings for potential attack chains:\n\n"
                  f"{json.dumps(findings_json, indent=2)}\n{context}")

        try:
            schema = AttackPathResult.model_json_schema()
            text = await self.router.call(
                task_type="vuln_reasoning", system=CHAINER_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}], max_tokens=2048,
                response_format={"type": "json_schema", "json_schema": {"name": "AttackPathResult", "schema": schema, "strict": False}})

            result_data = json.loads(text)
            
            if result_data.get("path_exists") and result_data.get("chained_vulnerability"):
                vuln_data = result_data["chained_vulnerability"]
                logger.info(f"🚨 AttackPathChainer discovered chained exploit: {vuln_data.get('title')}")
                
                # Ensure the generated vulnerability has required fields
                host_id = chainable[0].host_id if hasattr(chainable[0], "host_id") else "unknown"
                vuln = Vulnerability(
                    mission_id=mission_id,
                    host_id=host_id,
                    title=vuln_data.get("title", "Chained Attack Path"),
                    severity=vuln_data.get("severity", Severity.HIGH),
                    description=vuln_data.get("description", result_data.get("reasoning", "")),
                    evidence=vuln_data.get("evidence", "Deduced via AttackPathChainer"),
                    confidence=0.8,
                    verified=False  # Requires human or ExploitPlanner verification
                )
                return vuln
            else:
                logger.debug("AttackPathChainer: No viable chain found.")
                return None

        except Exception as e:
            logger.warning(f"AttackPathChainer failed: {e}")
            return None
