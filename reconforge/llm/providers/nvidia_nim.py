"""
NVIDIA NIM provider — uses openai SDK with NIM base_url.
Supports DeepSeek V4 Flash with streaming + reasoning/thinking tokens.
"""
import os
from tenacity import retry, stop_after_attempt, wait_exponential

from reconforge.utils.logger import get_logger

logger = get_logger("llm.nim")


class NvidiaProvider:
    """OpenAI-compatible client pointing at NVIDIA NIM."""

    BASE_URL = "https://integrate.api.nvidia.com/v1"

    def __init__(self, api_key: str, model: str) -> None:
        self.model = model
        self._api_key = api_key
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                base_url=self.BASE_URL,
                api_key=self._api_key)
        return self._client

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=30))
    async def call(self, system: str, messages: list[dict],
                   max_tokens: int = 4096,
                   response_format: dict | None = None) -> str:
        """
        Call NVIDIA NIM with streaming to handle DeepSeek V4 reasoning tokens.
        Returns only the final answer content (not the <think>...</think> block).
        """
        client = self._get_client()
        full_messages = [{"role": "system", "content": system}] + messages

        # DeepSeek V4 Flash uses streaming + thinking mode
        kwargs = {
            "model": self.model,
            "messages": full_messages,
            "temperature": 0.1,
            "top_p": 0.95,
            "max_tokens": max_tokens,
            "extra_body": {
                "chat_template_kwargs": {
                    "thinking": True,
                    "reasoning_effort": "high",
                }
            },
            "stream": True,
        }
        if response_format:
            kwargs["response_format"] = response_format

        completion = client.chat.completions.create(**kwargs)

        content_parts = []
        reasoning_chars = 0

        for chunk in completion:
            if not getattr(chunk, "choices", None):
                continue
            delta = chunk.choices[0].delta

            # Collect reasoning tokens (for logging only)
            reasoning = (
                getattr(delta, "reasoning", None) or
                getattr(delta, "reasoning_content", None)
            )
            if reasoning:
                reasoning_chars += len(reasoning)

            # Collect actual answer content
            if delta.content is not None:
                content_parts.append(delta.content)

        text = "".join(content_parts)
        logger.debug(
            f"[NIM/{self.model}] {reasoning_chars} reasoning chars, "
            f"{len(text)} answer chars returned")
        return text
