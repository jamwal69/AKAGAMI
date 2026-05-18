"""
ReconForge Working Memory — In-process state for current mission.
Token budget: hard cap at 12,000 tokens. Triggers summarizer when exceeded.
"""

import json
from typing import Any, Optional

from reconforge.intel.models import IntelBase
from reconforge.utils.logger import get_logger

logger = get_logger("working_memory")

# Approximate tokens per character ratio
CHARS_PER_TOKEN = 4
MAX_TOKEN_BUDGET = 12_000


class WorkingMemory:
    """In-process state holding current plan, recent results, and active context."""

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}
        self._sensitive_store: dict[str, Any] = {}
        self._recent_results: list[dict] = []
        self._agent_contexts: dict[str, list[str]] = {}
        self._max_recent = 20

    def set(self, key: str, value: Any) -> None:
        self._store[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._store.get(key, default)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def set_sensitive(self, key: str, value: Any) -> None:
        """Store runtime-only sensitive data excluded from prompts/summaries."""
        self._sensitive_store[key] = value

    def get_sensitive(self, key: str, default: Any = None) -> Any:
        return self._sensitive_store.get(key, default)

    def delete_sensitive(self, key: str) -> None:
        self._sensitive_store.pop(key, None)

    def token_count(self) -> int:
        """Estimate current context size in tokens."""
        total_chars = len(json.dumps(self._store, default=str))
        for result in self._recent_results:
            total_chars += len(json.dumps(result, default=str))
        return total_chars // CHARS_PER_TOKEN

    def needs_compression(self) -> bool:
        return self.token_count() > MAX_TOKEN_BUDGET

    def update_from_result(self, findings: list[IntelBase]) -> None:
        """Add latest findings to working context."""
        for finding in findings:
            summary = {"type": type(finding).__name__, "id": finding.id,
                       "confidence": finding.confidence, "verified": finding.verified}
            # Add type-specific key fields
            data = finding.model_dump(exclude={"raw_output"})
            for key in ("ip", "hostname", "domain", "port", "service",
                        "title", "severity", "category", "value", "url"):
                if key in data and data[key]:
                    summary[key] = data[key]
            self._recent_results.append(summary)

        # Trim old results
        if len(self._recent_results) > self._max_recent:
            self._recent_results = self._recent_results[-self._max_recent:]
        logger.debug(f"Working memory updated: {len(findings)} findings, {self.token_count()} tokens")

    def get_context_for_agent(self, agent_name: str) -> str:
        """Returns compressed, relevant context for a specific agent."""
        context_parts = []
        plan = self.get("plan")
        if plan:
            context_parts.append(f"Current plan: {json.dumps(plan, default=str)[:2000]}")
        if self._recent_results:
            context_parts.append(f"Recent findings ({len(self._recent_results)}):")
            for r in self._recent_results[-10:]:
                context_parts.append(f"  - {r.get('type', '?')}: {json.dumps(r, default=str)[:200]}")
        agent_ctx = self._agent_contexts.get(agent_name, [])
        if agent_ctx:
            context_parts.append(f"Agent-specific context for {agent_name}:")
            for item in agent_ctx[-5:]:
                context_parts.append(f"  - {item[:200]}")
        return "\n".join(context_parts)

    def add_agent_context(self, agent_name: str, context: str) -> None:
        if agent_name not in self._agent_contexts:
            self._agent_contexts[agent_name] = []
        self._agent_contexts[agent_name].append(context)

    def get_summary_for_compression(self) -> str:
        """Get full state as string for summarizer to compress."""
        return json.dumps({"store": self._store, "recent_results": self._recent_results,
                           "agent_contexts": self._agent_contexts}, default=str)

    def replace_with_summary(self, summary: str) -> None:
        """Replace current state with compressed summary."""
        self._store = {"compressed_summary": summary}
        self._recent_results = []
        self._agent_contexts = {}
        logger.info(f"Working memory compressed to {self.token_count()} tokens")

    def clear(self) -> None:
        self._store.clear()
        self._sensitive_store.clear()
        self._recent_results.clear()
        self._agent_contexts.clear()
