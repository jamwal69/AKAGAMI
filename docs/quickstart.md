# AKAGAMI Quick Start

## Requirements

- Python 3.11 or 3.12 recommended.
- External recon tools are optional until you run commands that need them.
- Only test assets you own or are explicitly authorized to test.

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -e .
```

## Diagnostics

Run local health checks before a mission:

```bash
akagami tools doctor
```

## Dry Run

Validate the mission plan without running scanners, calling LLMs, or writing mission output:

```bash
akagami recon -t example.com -C Example --passive-only --dry-run
```

## No-LLM Passive Smoke Test

Run a passive smoke test with LLM-backed paths disabled:

```bash
AKAGAMI_NO_LLM=1 akagami recon -t example.com -C Example --passive-only
```

## Safety

Use AKAGAMI only where you have explicit authorization. Confirm scope before every run, especially before enabling active scans or authenticated testing.
