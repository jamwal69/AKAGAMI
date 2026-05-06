"""
ReconForge Context Summarizer — V2. Uses LLMRouter (Groq fast model).
"""
from reconforge.llm.router import LLMRouter
from reconforge.utils.logger import get_logger

logger = get_logger("summarizer")

SUMMARIZER_SYSTEM_PROMPT = """You are compressing the working memory of a security reconnaissance mission.
Preserve: all discovered hosts, ports, services, vulnerabilities, credentials.
Preserve: current plan status, completed/pending tasks.
Drop: raw tool output, duplicate information, verbose banners.
Output ONLY a dense structured summary. Aim for 800 tokens maximum."""


class ContextSummarizer:
    """Compresses working memory when token budget is exceeded."""

    def __init__(self, router: LLMRouter | None = None) -> None:
        self.router = router

    async def summarize(self, context: str) -> str:
        """Compress context using Groq fast model. Falls back to truncation."""
        if not self.router:
            return self._fallback_truncate(context)
        try:
            text = await self.router.call(
                task_type="context_summarization",
                system=SUMMARIZER_SYSTEM_PROMPT,
                messages=[{"role": "user",
                           "content": f"Compress this working memory:\n\n{context}"}],
                max_tokens=1024)
            logger.info(f"Context compressed: {len(context)} → {len(text)} chars")
            return text
        except Exception as e:
            logger.warning(f"Summarizer failed, using fallback: {e}")
            return self._fallback_truncate(context)

    def _fallback_truncate(self, context: str) -> str:
        max_chars = 3200
        if len(context) <= max_chars:
            return context
        return context[:max_chars] + "\n\n[TRUNCATED — summarizer unavailable]"
