"""
ReconForge JS Analysis Agent — Analyzes JavaScript bundles.
Looks for semantic triggers (impersonate, admin) and hardcoded secrets using trufflehog.
"""

import json
import re
from typing import Optional

from reconforge.llm.router import LLMRouter

from reconforge.agents.base import BaseAgent
from reconforge.intel.models import (
    IntelBase, MissionState, Task, SecretFinding, OsintFinding, OsintCategory,
    OutOfScopeError, ToolExecutionError,
)
from reconforge.intel.store import IntelStore
from reconforge.memory.working import WorkingMemory
from reconforge.tools.bus import ToolBus
from reconforge.utils.logger import log_agent_start, log_agent_complete

JS_SYSTEM_PROMPT = """You are the JavaScript Analysis specialist of ReconForge.
You review JavaScript files and extracted endpoints for high-value administrative functions,
hardcoded credentials, and hidden API endpoints.
"""

# Regex patterns for high-value semantic triggers in JS
SEMANTIC_TRIGGERS = [
    r'impersonat(e|ion)',
    r'admin_?panel',
    r'super_?user',
    r'internal_?api',
    r'bypass_?auth',
    r'override',
    r'/api/v[0-9]+/admin',
    r'x-admin-token'
]

class JSAnalysisAgent(BaseAgent):
    """Agent for deep semantic analysis of JavaScript bundles."""

    def __init__(self, router: LLMRouter, tool_bus: ToolBus,
                 memory: WorkingMemory) -> None:
        super().__init__("js_agent", router, tool_bus, memory)

    async def run(self, task: Task, memory: WorkingMemory,
                  intel: IntelStore, mission: MissionState) -> list[IntelBase]:
        """Execute JS analysis task."""
        log_agent_start(self.logger, self.name, task.id)
        target = task.params.get("target", mission.target)

        findings: list[IntelBase] = []
        action = task.params.get("action", "analyze")

        if action == "analyze":
            findings.extend(await self._analyze_js_endpoints(target, intel, mission))
            findings.extend(await self._run_trufflehog(target, task.params, mission))
        else:
            self.logger.warning(f"Unknown JS analysis action: {action}")

        log_agent_complete(self.logger, self.name, task.id, len(findings))
        return findings

    async def _analyze_js_endpoints(self, target: str, intel: IntelStore, mission: MissionState) -> list[IntelBase]:
        """Analyze previously found JS endpoints and content for semantic triggers."""
        findings = []
        web_paths = intel.web_paths(mission.mission_id)
        js_files = [p for p in web_paths if p.get("url", "").endswith(".js")]

        for js_file in js_files:
            url = js_file.get("url", "")
            if not url:
                continue
            
            # Simple keyword matching on the URL itself
            url_lower = url.lower()
            for trigger in SEMANTIC_TRIGGERS:
                if re.search(trigger, url_lower):
                    findings.append(OsintFinding(
                        source_agent=self.name, source_tool="semantic_regex",
                        confidence=0.85, mission_id=mission.mission_id,
                        category=OsintCategory.OTHER,
                        value=url,
                        context=f"High-value semantic trigger '{trigger}' matched in JS path"
                    ))

            # In a full implementation, we would fetch the JS content and regex it as well.
            # Due to environment constraints without a headless browser/downloader integrated right here,
            # we rely on trufflehog for the deep scan.
            
        return findings

    async def _run_trufflehog(self, target: str, params: dict, mission: MissionState) -> list[IntelBase]:
        """Run TruffleHog on a target directory or URL list to find verified secrets."""
        findings = []
        # Fallback to a single URL if provided, otherwise it expects a directory
        scan_target = params.get("scan_target", target)
        
        try:
            # Requires trufflehog configured in tools.yaml
            result = await self.tool_bus.call(
                "trufflehog", 
                {"target": scan_target, "scan_target": scan_target,
                 "only_verified": True, "json_output": True},
                mission
            )
            
            # Parse TruffleHog JSON output
            for line in result.raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    detector_name = data.get("DetectorName", "Unknown")
                    raw_secret = data.get("Raw", "Redacted")
                    file_path = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", scan_target)
                    
                    finding = SecretFinding(
                        source_agent=self.name,
                        source_tool="trufflehog",
                        confidence=0.99, # verified
                        mission_id=mission.mission_id,
                        host_id=target,
                        file_path=file_path,
                        secret_type=detector_name,
                        secret_value=raw_secret,
                        is_verified=True,
                        raw_output=line[:1000]
                    )
                    findings.append(finding)
                except json.JSONDecodeError:
                    pass

        except (OutOfScopeError, PermissionError, ToolExecutionError):
            raise
        except Exception as e:
            self.logger.warning(f"Trufflehog failed for {scan_target}: {e}")

        return findings
