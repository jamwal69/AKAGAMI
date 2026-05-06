"""
LLM Fallback Handler — cross-provider fallback with graceful degradation.
If primary provider fails after all retries, tries the fallback provider.
If both fail, raises LLMUnavailableError — mission catches this and pauses.
"""
from reconforge.utils.logger import get_logger

logger = get_logger("llm.fallback")


class LLMUnavailableError(Exception):
    """Raised when ALL LLM providers fail for a given task."""
    pass


class FallbackHandler:
    """Manages cross-provider fallback logic."""

    async def call(self, primary, fallback, primary_name: str,
                   fallback_name: str, task_type: str,
                   system: str, messages: list[dict],
                   max_tokens: int, response_format: dict | None = None) -> str:
        """
        Try primary provider, fall back to secondary if it fails.
        Raises LLMUnavailableError if both fail.
        """
        # Try primary
        if primary is not None:
            try:
                result = await primary.call(
                    system=system, messages=messages, max_tokens=max_tokens, response_format=response_format)
                return result
            except Exception as e:
                logger.warning(
                    f"[{task_type}] Provider [{primary_name.upper()}] failed: "
                    f"{type(e).__name__}: {str(e)[:200]}. "
                    f"Falling back to [{fallback_name.upper()}]")

        # Try fallback
        if fallback is not None:
            try:
                result = await fallback.call(
                    system=system, messages=messages, max_tokens=max_tokens, response_format=response_format)
                logger.info(
                    f"[{task_type}] Fallback [{fallback_name.upper()}] succeeded")
                return result
            except Exception as e:
                logger.error(
                    f"[{task_type}] Fallback [{fallback_name.upper()}] also failed: "
                    f"{type(e).__name__}: {str(e)[:200]}")

        raise LLMUnavailableError(
            f"All LLM providers failed for task_type='{task_type}'. "
            f"Primary: {primary_name}, Fallback: {fallback_name}. "
            f"Check API keys and network connectivity.")
