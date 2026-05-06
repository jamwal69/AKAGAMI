"""
ReconForge LLM Router — V2.
The ONLY place in the codebase that instantiates LLM clients.
Routes tasks to NVIDIA NIM (DeepSeek — heavy reasoning) or Groq (fast repetitive).
"""
from reconforge.llm.router import LLMRouter, LLMUnavailableError

__all__ = ["LLMRouter", "LLMUnavailableError"]
