# Akagami V2

Akagami is a Python 3.11+ reconnaissance automation tool for authorized security testing and bug bounty work. It coordinates OSINT collection, active recon, scanner output parsing, endpoint inventory, CVE enrichment, memory/storage, and Markdown reporting.

It is not a guaranteed bug-finding system. Passing tests and clean scanner output do not prove that a target is vulnerable or safe. Real HackerOne-style use still requires scope review, manual validation, and human judgment.

## Capability Status Matrix

| Capability | Status | What is implemented | Current limits |
|---|---|---|---|
| Workspace creation | Stable | Per-company workspace tree with scope files, output folders, SQLite DB, ChromaDB folder, and engagement log | Local filesystem only |
| Scope enforcement | Stable | ToolBus checks domains, URLs, ports, IPs, CIDRs, and out-of-scope precedence before tool execution | Scope quality depends on mission config and operator review |
| Safe command rendering | Stable | Subprocess commands are rendered from validated YAML definitions and executed without `shell=True` | External binaries must still be installed and trusted |
| Deterministic parsing | Stable | Supported tool outputs are parsed by Python parser modules, not by LLMs | Unsupported or malformed output may fall back to partial/raw storage |
| Intel storage | Stable | SQLite-backed storage for hosts, ports, web paths, vulnerabilities, OSINT, credentials, sessions, and endpoint inventory | Schema is local to this project |
| Endpoint inventory | Stable | `akagami endpoints` shows high-signal HTTP/API surfaces from stored inventory | It ranks surfaces for manual testing; it does not prove exploitability |
| Recon dry-run | Stable | `akagami recon --dry-run` validates mission/scope, builds the default task graph, and prints planned tasks, agents, requested tools, risk, and scope decisions | It uses deterministic default planning only; it does not call LLMs or execute tools |
| Passive OSINT | Beta | whois, crt.sh, theHarvester, Shodan, GitHub code search, and web search paths exist | Shodan/GitHub require API keys; web search depends on the MCP/API bridge |
| Active recon | Beta | nmap, ProjectDiscovery `httpx`, ffuf, nuclei, arjun, corsy, and ssrfmap execution paths exist | Requires explicit active permission and installed external binaries |
| Report generation | Beta | Orchestrated missions can use router-backed prose plus a Jinja2 Markdown template; manual `akagami report` uses the same template with heuristic fallback prose | Manual report command does not initialize an LLM router |
| CVE enrichment/scoring | Beta | Local ChromaDB lookup, NVD API lookup, Groq enrichment, CVSS lookup, and contextual scoring paths exist | Results require validation and depend on available CVE data/API access |
| Browser/session capture | Experimental | Playwright can attempt simple login/capture flows and store redacted session context while keeping raw runtime auth in working memory | No polished CLI for selectors/credential workflows; authenticated scanning is not turnkey |
| Authenticated nuclei handoff | Experimental | Captured runtime auth headers/cookies can be handed to nuclei in memory | Depends on successful browser capture and task ordering |
| AI endpoint testing | Experimental | AI red-team agent has prompt-injection and endpoint test paths | Requires explicit task planning and careful scope control |
| Exploit planning | Experimental | Planner can generate exploit plans after stage-gate conditions | Planning only; it does not execute exploits |
| Watcher daemon | Experimental | `akagami watcher` polls a local `new_targets.txt` file and can launch missions for new entries | It does not currently poll HackerOne/Bugcrowd APIs; it consumes the local file |
| subfinder/gau/katana | Configured but not wired | Definitions exist in `config/tools.yaml` and packaged `reconforge/config/tools.yaml` | Default agents/task graph do not currently execute them |
| amass/masscan/gobuster/wpscan | Configured but not wired | Tool definitions exist | Not part of default mission execution |
| Operator approval CLI | Stable | `akagami approval-status` shows gate/approval state and `akagami approve` records operator approval in the mission store | Approval is a stored flag only; it does not run exploit planning |
| True mission resume execution | Not implemented | `akagami resume` prints resume context from episodic memory | It does not restart the orchestrator from the saved point |
| Automated valid-bug discovery | Not implemented | The tool can collect evidence and scanner findings | It does not reliably discover complex business logic, authz, payment, race, or IDOR bugs by itself |

## Installation

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -r requirements.txt
python -m playwright install chromium
```

The package exposes the `akagami` console script:

```bash
akagami --version
```

## Environment Variables

Akagami loads `.env` during orchestrated missions.

```bash
# Optional, enables LLM-backed planning/review/report prose when configured
NVIDIA_NIM_API_KEY=...
NVIDIA_NIM_MODEL=deepseek-ai/deepseek-v4-flash

GROQ_API_KEY=...
GROQ_MODEL_FAST=llama-3.3-70b-versatile
GROQ_MODEL_REASONING=deepseek-r1-distill-llama-70b

# Optional passive OSINT integrations
SHODAN_API_KEY=...
GITHUB_TOKEN=...
```

Without LLM keys, many components use heuristic fallbacks, but advanced planning, critic review, enrichment, scoring context, and report prose are reduced.

## External Tools

Install only the tools needed for the modes you intend to run.

You can inspect local binary availability and bounded compatibility probes without running scans or contacting targets:

```bash
akagami tools check
akagami tools doctor
```

| Area | Tools used by wired code paths |
|---|---|
| Passive OSINT | `whois`, `curl`, `theHarvester` |
| Active recon | `nmap`, ProjectDiscovery `httpx`, `ffuf`, `nuclei`, `arjun`, `corsy`, `ssrfmap` |
| Vulnerability and technology checks | `nuclei`, `searchsploit`, `jwt_tool`, `graphql-cop`, `clairvoyance` |
| JavaScript/secret checks | `trufflehog` |
| Browser capture | Playwright Chromium |

`subfinder`, `gau`, `katana`, `amass`, `masscan`, `gobuster`, and `wpscan` are present in the tool config but are not wired into default agent execution at this checkpoint.

## CLI UX and Plain Mode

Akagami's CLI uses Rich-powered banners, panels, status badges, and tables for operator-facing output. Human-readable commands show a compact command deck, mission briefings, dry-run safety boundaries, planned task/tool tables, gate and approval panels, endpoint/intel tables, tool doctor status, report summaries, and mission-completion next commands.

Status badges include `PASSIVE`, `ACTIVE`, `OPSEC`, `APPROVED`, `BLOCKED`, `EXPERIMENTAL`, and risk labels such as `HIGH`, `MEDIUM`, and `LOW`.

For script-friendly output, use the global plain mode before the command:

```bash
akagami --plain recon -t example.com -C Example --dry-run
akagami --plain tools check
```

JSON output modes remain banner-free and parseable:

```bash
akagami intel -m <mission-id> -f json
akagami endpoints -m <mission-id> -f json
```

Akagami also respects `NO_COLOR` by disabling terminal color styling where Rich output is used.

## CLI Commands

```bash
akagami recon -t <target> [-C <company>] [--passive-only|--active] [--opsec-mode] [--dry-run] [--mode standard|bug-bounty] [-c config/mission.yaml]
```

Starts a mission, creates or updates a workspace, loads mission config, and runs the orchestrator. Active scans require `--active` and `permissions.active_scanning: true` in the mission config.

```bash
akagami recon -t <target> -C <company> --active --dry-run
```

Builds a safe plan without running the mission. Dry-run validates the local mission/scope configuration, builds the task graph, shows planned tasks, agents, requested tools, active/passive risk, and scope decisions. It does not execute external tools, call LLM APIs, create mission DB rows, write action/finding logs, or generate reports.

```bash
akagami workspaces
```

Lists known company workspaces under `workspace/`.

```bash
akagami intel -m <mission-id> [-C <company>] [-f table|json]
```

Reads stored intel from the mission database and prints a table or JSON.

```bash
akagami endpoints -m <mission-id> [-C <company>] [-l 20] [-f table|json]
```

Shows ranked HTTP/API inventory rows for manual review.

```bash
akagami resume -m <mission-id> [-C <company>]
```

Prints saved mission context from episodic memory. It does not continue execution automatically.

```bash
akagami gate -m <mission-id> [-t <target>] [-C <company>]
```

Evaluates whether stored recon data is broad enough to pass the stage gate. When a mission row exists, the gate result is persisted for the approval workflow.

```bash
akagami approval-status -m <mission-id> -C <company>
```

Shows whether the stage gate has passed, whether an operator has approved exploit planning, and whether exploit planning is approved for the mission.

```bash
akagami approve -m <mission-id> -C <company>
```

Records `operator_approved=true` for the mission in the company workspace database. This command does not execute exploit planning or unlock/run agents by itself.

```bash
akagami report -m <mission-id> [-t <target>] [-n <name>] [-C <company>] [-o output/report.md]
```

Generates a Markdown report from stored intel. This manual command uses the packaged Jinja2 template and heuristic fallback prose because it does not initialize the LLM router.

```bash
akagami tools check [--config config/tools.yaml]
```

Shows every configured tool from the source checkout `config/tools.yaml`, or the packaged fallback when installed, with its binary name, required/optional marker, installed status, discovered path, category, risk metadata, and compatibility status. It uses PATH lookup and may run bounded safe version probes for critical tools. It does not run scans or contact targets.

```bash
akagami tools doctor [--config config/tools.yaml] [--workspace-root workspace]
```

Runs local health checks for Python version, package import, configured binaries and bounded version probes, Playwright Chromium availability, environment variable presence without printing values, workspace writability, and packaged resources. It does not run scans, contact targets, or require API keys.

```bash
akagami db seed-cves --nvd-feed <path-to-nvd-json> [--persist-dir output/chromadb]
akagami db stats [--persist-dir output/chromadb]
```

Seeds or inspects the local ChromaDB CVE store.

```bash
akagami watcher
```

Starts the experimental watcher loop. Current behavior watches for a local `new_targets.txt`, consumes it, and launches bug-bounty-mode missions for new targets.

## Mission Configuration

Default source checkout config lives at `config/mission.yaml`. Installed packages also carry the runtime tool definitions needed by the default executor.

```yaml
mission:
  target: example.com
  mission_name: "Authorized External Recon"
  company_name: "Example"

scope:
  in_scope:
    - example.com
    - "*.example.com"
  out_of_scope:
    - "10.0.0.0/8"

permissions:
  active_scanning: true

opsec:
  enabled: true
```

Safe synthetic examples are available in `config/example_mission.yaml`, `config/example_bug_bounty.yaml`, and `docs/example_scenario.md`. Use target-specific configs only for private/local engagements. Do not publish real program scopes, customer names, headers, tokens, or mission artifacts.

## Workspace Layout

Running a mission creates this tree:

```text
workspace/
└── <company>/
    ├── scope/
    │   ├── in_scope.txt
    │   ├── out_of_scope.txt
    │   └── subdomains.txt
    ├── output/
    │   ├── reports/
    │   ├── nmap/
    │   ├── nuclei/
    │   ├── httpx/
    │   ├── ffuf/
    │   ├── amass/
    │   ├── osint/
    │   └── misc/
    ├── loot/
    ├── data/
    │   ├── missions.db
    │   └── chromadb/
    └── notes/
        └── engagement_log.md
```

There are no default `katana/` or `gau/` workspace output directories in the current code.

## Real-World Bug Bounty Usefulness

Akagami is most useful as a recon and evidence organization assistant. It can help map domains, services, HTTP metadata, endpoint inventory, scanner findings, CVE candidates, obvious exposed paths, and verified secret findings when the right tools and inputs are available.

It is unlikely to reliably find complex business logic bugs, authorization bypasses, chained privilege escalation, payment flaws, race conditions, deep IDORs, subtle GraphQL/API abuse, or client-specific workflow bugs without a human building and validating the test cases.

For a real HackerOne target, treat output as leads. Validate scope, reproduce manually, remove false positives, and write the final report yourself.

## Safety Model

- Passive mode is the safer default.
- Active scanning requires both the `--active` CLI flag and mission config permission.
- Dry-run mode is plan-only: it uses local deterministic planning and tool metadata, then stops before subprocesses, MCP/API calls, LLM calls, mission DB writes, runtime action logs, intel storage, and report generation.
- ToolBus enforces scope before execution.
- Out-of-scope entries take precedence over in-scope entries.
- Opsec mode applies timing/rate/user-agent controls where supported.
- Raw auth captured by the browser agent is kept in sensitive working memory; stored session context is redacted.
- Exploit planning is plan-only and should not be treated as authorization to run exploit commands.
- Standard mode requires a passed stage gate and operator approval before exploit-planning unlock checks pass. `akagami approve` records approval only; it does not execute exploit planning.

## Project Structure

```text
reconforge/
├── agents/          # OSINT, active recon, vuln, browser, JS, AI, exploit planner agents
├── assets/          # Packaged brand assets
├── config/          # Packaged runtime tool definitions
├── intel/           # Pydantic models, SQLite store, endpoint inventory helpers
├── llm/             # Provider router and provider clients
├── memory/          # Working, episodic, semantic, and summarization memory
├── orchestrator/    # Master orchestrator, task graph, event bus, stage gate
├── parsers/         # Deterministic parsers for supported tool outputs
├── report/          # Markdown report generator and packaged Jinja2 template
├── skills/          # Critic, CVE enricher, parser tombstone, severity scorer
├── tools/           # ToolBus, executor, scope checks, MCP/API bridge
├── ui/              # Rich terminal UI helpers
├── utils/           # Logging, sanitizer, opsec helpers
├── cli.py           # Click CLI entry point
├── diagnostics.py   # Local runtime and tool diagnostics
├── watcher.py       # Experimental local-file watcher
└── workspace.py     # Per-company workspace creation helpers
```

## Testing and Build

```bash
python -m pytest tests/ -q
python -m compileall reconforge tests
python -m build --no-isolation --outdir /tmp/reconforge-build
git diff --check
```

Current release-hardening checkpoint: 436 tests are expected.

## Public Release Hygiene

Before publishing, verify private/local artifacts such as `.env`, `venv/`, `.pytest_cache/`, `akagami.egg-info/`, `output/`, `workspace/`, real target configs, and real scenario logs are not tracked. Public examples should stay synthetic and use reserved domains/IP ranges only.

## Legal

Use Akagami only on systems you own or are explicitly authorized to test. Confirm program scope before every mission, especially before enabling active scans, authenticated testing, watcher-triggered missions, or exploit planning.
