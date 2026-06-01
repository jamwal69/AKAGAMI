"""
LLM Router — routes task_type to the right provider + model.
NVIDIA NIM (DeepSeek) for heavy reasoning.
Groq for fast repetitive tasks.

ROUTING TABLE:
  mission_planning      → NIM   (complex multi-step reasoning)
  critic_review         → NIM   (nuanced quality judgement)
  vuln_reasoning        → NIM   (security knowledge-heavy)
  stage_gate_judgment   → NIM   (final go/no-go decision)
  report_writing        → NIM   (long-form professional prose)
  context_summarization → Groq  (fast, repetitive compression)
  contextual_scoring    → Groq  (fast severity adjustment)
  cve_enrichment        → Groq  (rapid CVE correlation)
  exploit_planning      → NIM   (attack chain reasoning)
  self_correction       → Groq  (fast error analysis + retry)
"""
import os
import re
from typing import Optional

from reconforge.llm.providers.nvidia_nim import NvidiaProvider
from reconforge.llm.providers.groq import GroqProvider
from reconforge.llm.fallback import FallbackHandler, LLMUnavailableError
from reconforge.utils.logger import get_logger

logger = get_logger("llm.router")

DEFAULT_NIM_MODEL = "deepseek-ai/deepseek-v4-flash"
DEFAULT_GROQ_FAST_MODEL = "llama-3.3-70b-versatile"
DEFAULT_GROQ_REASONING_MODEL = "deepseek-r1-distill-llama-70b"
NO_LLM_ENV = "AKAGAMI_NO_LLM"

# Maps task_type → (primary_provider, fallback_provider)
ROUTING_TABLE: dict[str, tuple[str, str]] = {
    "mission_planning":      ("nim",  "groq"),
    "critic_review":         ("nim",  "groq"),
    "vuln_reasoning":        ("nim",  "groq"),
    "stage_gate_judgment":   ("nim",  "groq"),
    "report_writing":        ("nim",  "groq"),
    "exploit_planning":      ("nim",  "groq"),
    "context_summarization": ("groq", "nim"),
    "contextual_scoring":    ("groq", "nim"),
    "cve_enrichment":        ("groq", "nim"),
    "self_correction":       ("groq", "nim"),
    # Default for any new task type not yet in table
    "default":               ("nim",  "groq"),
}


class LLMRouter:
    """
    Single entry point for all LLM calls.
    Usage:
        router = LLMRouter()
        text = await router.call(
            task_type="critic_review",
            system="You are...",
            messages=[{"role": "user", "content": "..."}],
            max_tokens=1024)
    """

    _offline_warnings_emitted: set[str] = set()
    _placeholder_warnings_emitted: set[str] = set()

    def __init__(
        self,
        enabled: bool | None = None,
        disabled_reason: str = "",
    ) -> None:
        self._nim: Optional[NvidiaProvider] = None
        self._groq: Optional[GroqProvider] = None
        self._fallback = FallbackHandler()
        self._offline_reason = ""

        env_disabled = llm_disabled_by_env()
        if enabled is False or env_disabled:
            if disabled_reason:
                self._offline_reason = disabled_reason
            elif env_disabled:
                self._offline_reason = f"{NO_LLM_ENV}=1"
            else:
                self._offline_reason = "--no-llm requested"
            self._log_offline_mode()
            return

        self._init_providers()
        if not self.is_available():
            self._offline_reason = "no LLM API keys configured"
            self._log_offline_mode()

    def _init_providers(self) -> None:
        ignored_placeholders: list[str] = []
        nim_key = self._api_key_from_env("NVIDIA_NIM_API_KEY", ignored_placeholders)
        nim_model = os.getenv("NVIDIA_NIM_MODEL", DEFAULT_NIM_MODEL)
        groq_key = self._api_key_from_env("GROQ_API_KEY", ignored_placeholders)
        groq_model_fast = os.getenv("GROQ_MODEL_FAST", DEFAULT_GROQ_FAST_MODEL)
        groq_model_reasoning = os.getenv("GROQ_MODEL_REASONING",
                                         DEFAULT_GROQ_REASONING_MODEL)

        self._log_placeholder_keys(ignored_placeholders)

        if nim_key:
            self._nim = NvidiaProvider(api_key=nim_key, model=nim_model)
            logger.debug(f"NIM provider initialized: {nim_model}")

        if groq_key:
            self._groq = GroqProvider(
                api_key=groq_key,
                model_fast=groq_model_fast,
                model_reasoning=groq_model_reasoning)
            logger.debug(f"Groq provider initialized: fast={groq_model_fast}")

    def _api_key_from_env(self, name: str, ignored_placeholders: list[str]) -> str:
        value = os.getenv(name, "").strip()
        if is_placeholder_api_key(value):
            ignored_placeholders.append(name)
            return ""
        return value

    def _log_placeholder_keys(self, names: list[str]) -> None:
        fresh = [name for name in names
                 if name not in self._placeholder_warnings_emitted]
        if not fresh:
            return
        self._placeholder_warnings_emitted.update(fresh)
        logger.warning(
            "Ignoring placeholder LLM API key(s): "
            f"{', '.join(sorted(fresh))}"
        )

    def _log_offline_mode(self) -> None:
        reason = self._offline_reason or "disabled"
        if reason in self._offline_warnings_emitted:
            return
        self._offline_warnings_emitted.add(reason)
        logger.warning(
            f"LLM disabled ({reason}); using deterministic parsers and "
            "heuristic fallbacks only"
        )

    async def call(self, task_type: str, system: str,
                   messages: list[dict], max_tokens: int = 2048,
                   response_format: dict | None = None) -> str:
        """
        Route task to appropriate provider, with automatic fallback.
        Returns response text string.
        Raises LLMUnavailableError only if ALL providers fail.
        """
        if not self.is_available():
            raise LLMUnavailableError(
                f"LLM disabled ({self._offline_reason or 'unavailable'}); "
                "using offline/no-LLM mode"
            )

        primary_name, fallback_name = ROUTING_TABLE.get(
            task_type, ROUTING_TABLE["default"])

        primary = self._get_provider(primary_name)
        fallback = self._get_provider(fallback_name)

        logger.debug(f"[{task_type}] → [{primary_name.upper()}]")

        return await self._fallback.call(
            primary=primary,
            fallback=fallback,
            primary_name=primary_name,
            fallback_name=fallback_name,
            task_type=task_type,
            system=system,
            messages=messages,
            max_tokens=max_tokens,
            response_format=response_format)

    def _get_provider(self, name: str):
        if name == "nim":
            return self._nim
        if name == "groq":
            return self._groq
        return None

    def is_available(self) -> bool:
        return self._nim is not None or self._groq is not None

    def offline_reason(self) -> str:
        return self._offline_reason

    def status(self) -> dict:
        return {
            "nim_available": self._nim is not None,
            "groq_available": self._groq is not None,
            "offline_mode": not self.is_available(),
            "offline_reason": self._offline_reason,
            "nim_model": self._nim.model if self._nim else os.getenv(
                "NVIDIA_NIM_MODEL", "not set"),
            "groq_model_fast": self._groq.model_fast if self._groq else os.getenv(
                "GROQ_MODEL_FAST", "not set"),
        }


def llm_disabled_by_env(env: dict[str, str] | None = None) -> bool:
    source = os.environ if env is None else env
    value = str(source.get(NO_LLM_ENV, "")).strip().lower()
    return value in {"1", "true", "yes", "on"}


def is_placeholder_api_key(value: str) -> bool:
    """Detect documented example keys without rejecting normal test strings."""
    normalized = value.strip().strip("'\"").lower()
    if not normalized:
        return False
    return bool(
        re.fullmatch(r"nvapi[-_]x{4,}", normalized)
        or re.fullmatch(r"gsk[-_]x{4,}", normalized)
        or normalized in {
            "nvapi-<key>",
            "nvapi_<key>",
            "gsk_<key>",
            "gsk-<key>",
        }
    )
