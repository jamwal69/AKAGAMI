# ⚔️ Akagami V2 Bug Bounty Edition

**Professional-grade, multi-agent reconnaissance and bug bounty engine. Free to run — no paid API subscriptions required.**

Akagami (赤髪) is an autonomous penetration testing and bug bounty system that uses **NVIDIA NIM (DeepSeek V4 Flash)** for heavy reasoning and **Groq** for fast repetitive tasks. Specialized sub-agents handle discrete phases, and a three-tier memory system maintains persistent knowledge across sessions. It automates the full vulnerability discovery lifecycle — from passive OSINT, to active scanning, authenticated session capture, and deep JavaScript analysis — while maintaining strict scope enforcement and opsec controls.

---

## ⚡ Features

### 🤖 Multi-Agent Architecture
| Agent | Role | Tools |
|-------|------|-------|
| **OsintAgent** | Passive intelligence gathering | whois, crt.sh, theHarvester, Shodan, GitHub dorking, web search, subfinder, gau |
| **ActiveReconAgent** | Network scanning & enumeration | nmap, httpx-pd, ffuf, banner grabbing, katana, arjun, corsy, ssrfmap |
| **VulnAnalysisAgent** | Vulnerability detection | nuclei (authenticated), searchsploit, jwt_tool, graphql-cop, clairvoyance |
| **BrowserAgent** | Authenticated session capture | Playwright (headless auth flows, JWT interception, DOM storage extraction) |
| **JSAnalysisAgent** | JavaScript bundle semantic analysis | regex triggers, trufflehog (hardcoded secrets) |
| **ExploitPlannerAgent** | Attack chain planning (Stage 2) | DeepSeek-powered planning (locked until stage gate passes or bug bounty trigger) |

### 🧠 Intelligence Pipeline
- **CriticAgent** — Co-RedTeam style reviewer that gates every finding before storage. Rejects false positives, flags overconfident results, improves incomplete findings, and does not auto-approve high-impact findings if critic review fails. Powered by DeepSeek V4 Flash (NIM).
- **CveEnricher** — 3-stage CVE enrichment: ChromaDB (local) → NVD REST API → Groq correlation
- **SeverityScorer** — CVSS→severity is a **pure Python lookup table** (no LLM). Contextual override via Groq only when environmental factors justify it (internet-facing + no WAF + exploit available)
- **Deterministic Parsers** — One pure Python parser per tool (`reconforge/parsers/`). Zero LLM calls for parsing. Instant. Deterministic.

### 🔀 Dual LLM Router (V2)
All LLM calls route through `reconforge/llm/router.py`. Zero direct provider instantiation anywhere else.

| Task Type | Provider | Model | Why |
|---|---|---|---|
| `mission_planning` | NVIDIA NIM | DeepSeek V4 Flash | Complex multi-step reasoning |
| `critic_review` | NVIDIA NIM | DeepSeek V4 Flash | Nuanced quality judgment |
| `vuln_reasoning` | NVIDIA NIM | DeepSeek V4 Flash | Security knowledge-heavy |
| `stage_gate_judgment` | NVIDIA NIM | DeepSeek V4 Flash | Final go/no-go decision |
| `report_writing` | NVIDIA NIM | DeepSeek V4 Flash | Long-form professional prose |
| `exploit_planning` | NVIDIA NIM | DeepSeek V4 Flash | Attack chain reasoning |
| `context_summarization` | Groq | Llama 3.3 70B | Fast compression |
| `contextual_scoring` | Groq | Llama 3.3 70B | Fast severity adjustment |
| `cve_enrichment` | Groq | DeepSeek R1 Distill | Rapid CVE correlation |
| `self_correction` | Groq | Llama 3.3 70B | Fast error analysis |

If the primary provider fails, the fallback fires automatically and the mission continues.

### 🧱 Three-Tier Memory
| Layer | Backing | Purpose |
|-------|---------|----|
| **Working** | In-process dict | Current plan, recent results, agent context (12K token budget, auto-compression via Groq) |
| **Episodic** | SQLite | Permanent audit trail — every tool call, finding, and summary. Enables mission resume |
| **Semantic** | ChromaDB | RAG-based CVE lookups, exploit references, past report knowledge, tool guides |

### 🔐 Security & Safety
- **Scope enforcement** — Every tool call is checked against normalized domains, URLs, ports, IPs, punycode, and CIDR ranges before execution; out-of-scope rules take precedence over in-scope rules
- **Centralized ToolBus enforcement** — Subprocess tools, API calls, and MCP calls route through ToolBus or an approved safety wrapper with scope, permission/risk, and sanitizer controls
- **Deterministic command execution** — Tool commands are built from validated YAML schemas/templates with no raw argument injection
- **Permission check** — Active tools blocked unless explicitly permitted
- **Anti-prompt-injection** — Output sanitizer on all tool results before reaching any LLM
- **Opsec controls** — Timing randomization, rate limiting, user-agent rotation, nmap timing override
- **Bug Bounty Mode / Stage gate** — Normally, exploit planning is locked until reconnaissance is deemed complete. In `--mode bug-bounty`, a high-confidence finding instantly overrides the gate to trigger opportunistic exploitation.
- **Operator approval** — Required before advancing to exploitation stage in standard mode

### 📊 Professional Reporting
- DeepSeek-powered executive summaries and prioritized recommendations
- Risk scoring (CRITICAL → INFORMATIONAL with weighted vulnerability/credential analysis)
- Full Jinja2 template with vulnerability details, OSINT findings, credential alerts, timeline
- Markdown output ready for client delivery

### 🔄 Resilience & Performance
- **Parallel Execution** — Massive 10x speedup via `asyncio.gather` for task execution.
- **Self-correction loops** — Failed tasks get LLM-powered error analysis, and retries are validated so they cannot change scope, tool, or risk class
- **Dependency-aware execution** — Tasks run only after prerequisites succeed; failed prerequisites block dependents.
- **Mission resume** — Restore interrupted missions from episodic memory
- **Retry logic** — Tenacity exponential backoff on all API calls (NIM, Groq, NVD, Shodan)
- **Graceful fallbacks** — Every LLM-dependent component has a heuristic fallback

### 📂 Structured Workspaces (Bug Bounty Ready)
Every engagement gets its own isolated directory tree — no more dumping everything into a shared `output/` folder.

```
workspace/
└── hackerone/
    ├── scope/
    │   ├── in_scope.txt        ← domains/IPs allowed
    │   └── out_of_scope.txt    ← domains/IPs excluded
    ├── output/
    │   ├── reports/            ← final Markdown reports
    │   ├── nmap/               ← raw nmap XML output
    │   ├── nuclei/             ← nuclei JSONL results
    │   ├── httpx/              ← httpx-pd JSONL results
    │   ├── ffuf/               ← ffuf JSON results
    │   ├── amass/              ← amass enumeration output
    │   ├── katana/             ← katana JS/endpoint crawling
    │   ├── gau/                ← wayback machine URL discovery
    │   ├── osint/              ← whois, theharvester, subfinder, crt.sh
    │   └── misc/               ← anything else
    ├── data/
    │   ├── missions.db         ← SQLite intel store + episodic memory
    │   └── chromadb/           ← ChromaDB vector store
    └── notes/
        └── engagement_log.md   ← auto-created engagement journal
```

- Workspace is **auto-created** when you pass `--company` (or `-C`) to the `recon` command
- If you omit `--company`, the target domain name is used as the company name
- Scope files are **append-only** — running against the same company again adds new targets without duplicating
- Engagement log is timestamped automatically on mission start/end
- All databases, reports, and tool output go inside the company folder

---

## 🚀 Quick Start

```bash
# Clone and install
cd reconforge
pip install -r requirements.txt

# Configure environment
cp .env.example .env
```

Edit `.env` with your keys:
```bash
# NVIDIA NIM — free at https://build.nvidia.com/
NVIDIA_NIM_API_KEY=nvapi-...
NVIDIA_NIM_MODEL=deepseek-ai/deepseek-v4-flash

# Groq — free at https://console.groq.com/
GROQ_API_KEY=gsk_...
GROQ_MODEL_FAST=llama-3.3-70b-versatile
GROQ_MODEL_REASONING=deepseek-r1-distill-llama-70b
```

```bash
# Run passive-only recon (auto-creates workspace/example/ folder)
python -m reconforge.cli recon --target example.com --passive-only

# Run with explicit company name (creates workspace/hackerone/)
python -m reconforge.cli recon --target example.com -C "HackerOne" --active

# Run with opsec controls
python -m reconforge.cli recon --target example.com -C "HackerOne" --active --opsec-mode

# List all company workspaces
python -m reconforge.cli workspaces
```

## 📋 CLI Commands

```bash
# Reconnaissance (with company workspace and Bug Bounty mode)
akagami recon -t <target> -C <company> [--passive-only|--active] [--opsec-mode] [--mode standard|bug-bounty] [-c config.yaml]

# List all company workspaces
akagami workspaces

# View intel store (company-aware)
akagami intel -m <mission-id> -C <company> [-f table|json]

# View high-signal HTTP/API endpoints (company-aware)
akagami endpoints -m <mission-id> -C <company> [-l <limit>] [-f table|json]

# Resume interrupted mission
akagami resume -m <mission-id> -C <company>

# Evaluate stage gate
akagami gate -m <mission-id> -t <target> -C <company>

# Generate report (auto-saves to workspace/company/output/reports/)
akagami report -m <mission-id> -t <target> -C <company>

# Database management
akagami db seed-cves --nvd-feed <path-to-nvd-json>
akagami db stats
```

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Master Orchestrator                     │
│           (NIM/DeepSeek planning + self-correction)         │
├──────────┬───────────┬──────────────┬───────────────────────┤
│  OSINT   │  Active   │    Vuln      │   Exploit Planner     │
│  Agent   │  Recon    │  Analysis    │   (Stage 2, locked)   │
│          │  Agent    │   Agent      │                       │
├──────────┴───────────┴──────────────┴───────────────────────┤
│              CriticAgent (NIM — gates all findings)         │
├──────────┬───────────┬─────────────────────────────────────┤
│ ToolBus  │MCP Bridge │  CveEnricher (Groq)                 │
│(subprocess)│(API calls)│  ChromaDB → NVD → Groq           │
├──────────┴───────────┴─────────────────────────────────────┤
│         LLM Router: NIM (heavy) ↔ Groq (fast)             │
├────────────────────────────────────────────────────────────┤
│  Working Memory │ Episodic Memory  │  Semantic Memory      │
│  (in-process)   │   (SQLite)       │   (ChromaDB)          │
├─────────────────┴──────────────────┴──────────────────────┤
│                      Intel Store                           │
│       (SQLite: hosts, ports, vulns, creds, ...)            │
└────────────────────────────────────────────────────────────┘
```

### V2 Data Flow

```
1. Orchestrator plans tasks (NIM/DeepSeek or default DAG plan)
2. Tasks execute via agents → ToolBus (scope + permission + sanitizer) → subprocess/MCP/API
3. Raw output → Deterministic Parser (pure Python, zero LLM)
4. Findings → CriticAgent (NIM) → approved/rejected/improved
5. Approved findings → SeverityScorer (CVSS lookup table + Groq context)
6.                  → CveEnricher (Groq) → IntelStore
7. StageGate (NIM judgment) → unlock ExploitPlanner
8. ReportGenerator (NIM prose + Jinja2 tables) → Markdown report
```

---

## 📁 Project Structure

```
reconforge/
├── workspace.py             # ← NEW: per-company directory scaffolding
├── agents/
│   ├── base.py              # BaseAgent ABC — uses LLMRouter, not direct client
│   ├── osint.py             # Passive OSINT (whois, crt.sh, Shodan, GitHub)
│   ├── recon.py             # Active scanning (nmap, httpx, ffuf, arjun, corsy)
│   ├── vuln.py              # Vulnerability analysis (nuclei, jwt_tool, graphql)
│   ├── browser.py           # Playwright headless browser for auth and tokens
│   ├── js_analysis.py       # JavaScript semantic and secret analysis
│   └── exploit_planner.py   # Exploit planning (Stage 2, locked)
├── llm/                     # LLM abstraction layer
│   ├── router.py            # Single entry point — all LLM calls go here
│   ├── fallback.py          # Cross-provider fallback + LLMUnavailableError
│   └── providers/
│       ├── nvidia_nim.py    # DeepSeek V4 Flash via openai SDK (streaming)
│       └── groq.py          # Llama/DeepSeek via openai SDK (fast)
├── parsers/                 # Deterministic per-tool parsers
│   ├── nmap_parser.py       # XML via ElementTree — open ports only
│   ├── nuclei_parser.py     # JSONL — CVE/CVSS extraction
│   ├── httpx_parser.py      # JSONL — interesting path detection (20+ keywords)
│   ├── amass_parser.py      # JSONL + plain-text fallback
│   ├── ffuf_parser.py       # JSON results array
│   ├── whois_parser.py      # python-whois library
│   └── theharvester_parser.py # JSON — deduped emails/hosts/IPs
├── intel/
│   ├── models.py            # Pydantic v2 models (Host, Port, Vuln, MissionState...)
│   └── store.py             # SQLite intel store with dedup
├── memory/
│   ├── working.py           # In-process context (12K token budget)
│   ├── episodic.py          # SQLite audit trail + mission resume
│   ├── semantic.py          # ChromaDB vector store (CVE, exploits, reports)
│   └── summarizer.py        # Groq context compression
├── orchestrator/
│   ├── master.py            # Main loop + self-correction (NIM-powered)
│   ├── task_graph.py        # DAG-based task scheduling
│   └── stage_gate.py        # Arithmetic metrics + NIM go/no-go judgment
├── report/
│   ├── generator.py         # NIM prose + Jinja2 tables
│   └── templates/           # Jinja2 Markdown templates
├── skills/
│   ├── critic.py            # Finding review — powered by NIM/DeepSeek
│   ├── enricher.py          # CVE enrichment — powered by Groq
│   ├── parser.py            # TOMBSTONED V2 — see reconforge/parsers/
│   └── scorer.py            # CVSS lookup table (pure Python) + Groq context
├── tools/
│   ├── bus.py               # Central tool dispatcher (scope/opsec/log)
│   ├── executor.py          # Safe subprocess execution (never shell=True)
│   ├── mcp_bridge.py        # Shodan/GitHub/web search via APIs
│   └── definitions/         # Per-tool YAML configs with required_flags
├── utils/
│   ├── logger.py            # Rich logging with finding/scope formatters
│   ├── sanitizer.py         # Anti-prompt-injection output cleaner
│   └── opsec.py             # Timing, rate limiting, user-agent rotation
└── cli.py                   # Click CLI with Rich display + workspace support
```

---

## ⚙️ Configuration

### Mission Config (`config/mission.yaml`)

```yaml
mission:
  target: example.com
  mission_name: "Q4 External Assessment"

scope:
  in_scope:
    - example.com
    - "*.example.com"
    - "192.168.1.0/24"
  out_of_scope:
    - production.example.com
    - "10.0.0.0/8"

permissions:
  active_scanning: true

opsec:
  enabled: true
```

### Environment Variables (`.env`)

```bash
# Required — get free at https://build.nvidia.com/
NVIDIA_NIM_API_KEY=nvapi-...
NVIDIA_NIM_MODEL=deepseek-ai/deepseek-v4-flash

# Required — get free at https://console.groq.com/
GROQ_API_KEY=gsk_...
GROQ_MODEL_FAST=llama-3.3-70b-versatile
GROQ_MODEL_REASONING=deepseek-r1-distill-llama-70b

# Optional — enables Shodan OSINT
SHODAN_API_KEY=...

# Optional — enables GitHub dorking
GITHUB_TOKEN=...
```

---

## 🧪 Testing

```bash
# Run all tests (365 tests)
python -m pytest tests/ -v

# Run by phase/component
python -m pytest tests/test_intel.py tests/test_memory.py tests/test_orchestrator.py tests/test_tools.py -v  # Phase 1 (44 tests)
python -m pytest tests/test_phase2.py -v    # Phase 2: Active recon
python -m pytest tests/test_phase3.py -v    # Phase 3: Vuln analysis + memory
python -m pytest tests/test_phase4.py -v    # Phase 4: MCP + exploit planner
python -m pytest tests/test_phase5.py -v    # Phase 5: Integration + resilience
python -m pytest tests/test_v2.py -v        # V2: Parsers + router + CVSS table
python -m pytest tests/test_workspace.py -v # Workspace manager (23 tests)
```

---

## ⚖️ Legal

> **This tool requires explicit operator confirmation of scope before any scanning.**
> It never assumes permission. Always obtain written authorization before testing.
> Akagami is designed for authorized penetration testing engagements only.
> Unauthorized use against systems you do not own or have permission to test is illegal.

---

*Built with DeepSeek V4 Flash (NVIDIA NIM) • Groq Llama 3.3 70B • Python 3.11+ • SQLite • ChromaDB*

# AKAGAMI
