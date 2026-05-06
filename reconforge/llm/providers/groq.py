"""
Groq provider — uses openai SDK with Groq base_url.
800+ tokens/second on LPU hardware. Best for fast repetitive tasks.
"""
from tenacity import retry, stop_after_attempt, wait_exponential

from reconforge.utils.logger import get_logger

logger = get_logger("llm.groq")


class GroqProvider:
    """OpenAI-compatible client pointing at Groq's LPU API."""

    BASE_URL = "https://api.groq.com/openai/v1"

    def __init__(self, api_key: str, model_fast: str,
                 model_reasoning: str) -> None:
        self.model_fast = model_fast
        self.model_reasoning = model_reasoning
        self._api_key = api_key
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                base_url=self.BASE_URL,
                api_key=self._api_key)
        return self._client

    def _pick_model(self, task_type: str = "") -> str:
        """Use reasoning model for cve_enrichment, fast for everything else."""
        if task_type in ("cve_enrichment",):
            return self.model_reasoning
        return self.model_fast

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=20))
    async def call(self, system: str, messages: list[dict],
                   max_tokens: int = 2048,
                   task_type: str = "",
                   response_format: dict | None = None) -> str:
        """Call Groq and return response text."""
        client = self._get_client()
        model = self._pick_model(task_type)
        full_messages = [{"role": "system", "content": system}] + messages

        kwargs = {
            "model": model,
            "messages": full_messages,
            "max_tokens": max_tokens,
            "temperature": 0.1
        }
        if response_format:
            kwargs["response_format"] = response_format

        response = client.chat.completions.create(**kwargs)

        text = response.choices[0].message.content or ""
        logger.debug(f"[Groq/{model}] {len(text)} chars returned")
        return text
