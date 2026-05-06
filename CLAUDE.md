# Akagami (赤髪) — Claude Code Context

---
## V2 ARCHITECTURE — READ THIS FIRST

1. **PARSING IS DETERMINISTIC.** `reconforge/parsers/` has one parser per tool.
   Pure Python. Zero LLM calls for parsing. Tools always invoked with `required_flags`
   from `tools.yaml` (e.g. nmap `-oX -`, nuclei `-json`, httpx `-json`, ffuf `-of json`).

2. **LLM IS USED ONLY FOR:** mission planning, critic review, vulnerability reasoning,
   stage gate final go/no-go judgment, contextual severity re-scoring,
   CVE enrichment on unmatched versions, executive summary and recommendations in report.
   **Nothing else.**

3. **ALL LLM CALLS go through `reconforge/llm/router.py` only.**
   No direct provider instantiation anywhere else in the codebase.
   Every call passes a `task_type` string from the routing table.

4. **TWO PROVIDERS:**
   - **NVIDIA NIM** (DeepSeek R1) for reasoning-heavy tasks: planning, critic, vuln, gate, report.
   - **Groq** for fast repetitive tasks: summarization, scoring, CVE enrichment.
   Routing is automatic by `task_type`. If primary fails, fallback fires automatically.

5. **NO ANTHROPIC SDK.** Both providers use `openai.OpenAI()` with a custom `base_url`.
   NIM: `https://integrate.api.nvidia.com/v1`
   Groq: `https://api.groq.com/openai/v1`
   This is correct — both are OpenAI-API-compatible.

6. **CVSS→SEVERITY IS A LOOKUP TABLE.** `skills/scorer.py::cvss_to_severity()` is pure Python.
   LLM is called only when environmental context (internet-facing, WAF, exploitability) justifies override.
---

## Project Overview

ReconForge is a multi-agent reconnaissance engine. It automates the full penetration testing
recon lifecycle from passive OSINT to active scanning to vulnerability correlation.

## Architecture Rules

1. All I/O is async — `asyncio`, `async def`, `await` throughout
2. All LLM calls through `LLMRouter().call(task_type=...)` — never instantiate providers directly
3. Never `shell=True` — always `subprocess.run(list_of_args)`
4. All tool output sanitized before reaching LLM — pass through `sanitizer.clean()`
5. Scope check before everything — every agent calls `self._assert_in_scope()` first
6. Pydantic for all data — use models in `intel/models.py`, no raw dicts between components
7. JSON-only LLM responses — every system prompt says "Output ONLY valid JSON"
8. Secrets in `.env` — `NVIDIA_NIM_API_KEY`, `GROQ_API_KEY`, `SHODAN_API_KEY`, `GITHUB_TOKEN`
9. Never skip critic review before writing to intel store
10. Never delete episodic memory — it's an audit trail

## Key Entry Points

- **CLI**: `reconforge/cli.py`
- **Orchestrator**: `reconforge/orchestrator/master.py`
- **LLM Router**: `reconforge/llm/router.py` ← all LLM calls go here
- **Parsers**: `reconforge/parsers/` ← zero LLM, pure Python
- **Tests**: `tests/` — run with `pytest tests/ -v`

## Routing Table (task_type → provider)

| task_type | Provider | Reason |
|---|---|---|
| mission_planning | NIM | Complex multi-step reasoning |
| critic_review | NIM | Nuanced quality judgment |
| vuln_reasoning | NIM | Security knowledge-heavy |
| stage_gate_judgment | NIM | Final go/no-go decision |
| report_writing | NIM | Long-form professional prose |
| exploit_planning | NIM | Attack chain reasoning |
| context_summarization | Groq | Fast compression |
| contextual_scoring | Groq | Fast severity adjustment |
| cve_enrichment | Groq | Rapid CVE correlation |
| self_correction | Groq | Fast error analysis |
