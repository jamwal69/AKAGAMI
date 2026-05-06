"""
ReconForge BaseAgent — V2.
Uses LLMRouter instead of direct Anthropic client.
"""

import json
from abc import ABC, abstractmethod

from reconforge.intel.models import IntelBase, MissionState, OutOfScopeError, Task
from reconforge.intel.store import IntelStore
from reconforge.llm.router import LLMRouter
from reconforge.memory.working import WorkingMemory
from reconforge.tools.bus import ToolBus
from reconforge.tools.scope import is_target_in_scope
from reconforge.utils.logger import (
    get_logger, log_agent_start, log_agent_complete, log_scope_violation,
)


class BaseAgent(ABC):
    """Abstract base class for all ReconForge agents. V2: uses LLMRouter."""

    def __init__(self, name: str, router: LLMRouter,
                 tool_bus: ToolBus, memory: WorkingMemory) -> None:
        self.name = name
        self.router = router
        # Legacy alias so agent code that references self.client still works
        # (it should be replaced over time, but this prevents breakage)
        self.client = None
        self.tool_bus = tool_bus
        self.memory = memory
        self.logger = get_logger(name)

    @abstractmethod
    async def run(self, task: Task, memory: WorkingMemory,
                  intel: IntelStore, mission: MissionState) -> list[IntelBase]:
        """Execute task and return structured intel objects."""

    async def _call_llm(self, task_type: str, system: str,
                        messages: list, max_tokens: int = 2048) -> str:
        """Route LLM call through the router. Logs provider used."""
        self.logger.debug(f"LLM call [{task_type}]: {system[:80]}...")
        text = await self.router.call(
            task_type=task_type, system=system,
            messages=messages, max_tokens=max_tokens)
        self.logger.debug(f"LLM response [{task_type}]: {len(text)} chars")
        return text

    # Keep _call_claude as alias for backwards compatibility with agent code
    async def _call_claude(self, system: str, messages: list,
                           max_tokens: int = 2048) -> str:
        """Backwards-compat alias → routes to _call_llm with default task type."""
        return await self._call_llm("vuln_reasoning", system, messages, max_tokens)

    async def _call_claude_json(self, system: str, prompt: str,
                                max_tokens: int = 4096,
                                task_type: str = "vuln_reasoning") -> dict | list:
        """Call LLM expecting JSON response, with retry on parse failure."""
        text = await self._call_llm(
            task_type, system,
            [{"role": "user", "content": prompt}], max_tokens)
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            text = text.rsplit("```", 1)[0] if "```" in text else text
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            self.logger.warning("JSON parse failed, retrying once")
            retry_prompt = (
                f"Your previous response was not valid JSON. "
                f"Please respond with ONLY valid JSON, no markdown or prose.\n\n"
                f"Original request: {prompt[:2000]}")
            text2 = await self._call_llm(
                task_type, system,
                [{"role": "user", "content": retry_prompt}], max_tokens)
            text2 = text2.strip()
            if text2.startswith("```"):
                text2 = text2.split("\n", 1)[1] if "\n" in text2 else text2[3:]
                text2 = text2.rsplit("```", 1)[0] if "```" in text2 else text2
            return json.loads(text2.strip())

    def _build_context(self, memory: WorkingMemory, intel: IntelStore,
                       mission_id: str = "") -> str:
        """Build relevant context string for this agent's task."""
        parts = [memory.get_context_for_agent(self.name)]
        if mission_id and intel is not None:
            summary = intel.get_attack_surface_summary(mission_id)
            parts.append(f"Current attack surface: {json.dumps(summary, default=str)}")
        return "\n\n".join(p for p in parts if p)

    def _assert_in_scope(self, target: str, mission: MissionState) -> None:
        """Verify target is in scope. Raises OutOfScopeError."""
        allowed, denied = is_target_in_scope(target, mission.scope, mission.out_of_scope)
        if denied:
            log_scope_violation(self.logger, target, mission.scope)
            raise OutOfScopeError(f"Target '{target}' is out of scope")
        if allowed:
            return
        log_scope_violation(self.logger, target, mission.scope)
        raise OutOfScopeError(f"Target '{target}' not in scope {mission.scope}")
