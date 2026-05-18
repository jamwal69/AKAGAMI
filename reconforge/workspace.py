"""
ReconForge Workspace Manager — Structured per-company engagement directories.

Creates a clean, organized folder tree for each bug bounty target:

    workspace/
    └── <company_name>/
        ├── scope/
        │   ├── in_scope.txt        ← domains/IPs allowed
        │   ├── out_of_scope.txt    ← domains/IPs excluded
        │   └── subdomains.txt      ← discovered subdomains (auto-populated)
        ├── output/
        │   ├── reports/            ← final Markdown reports
        │   ├── nmap/               ← raw nmap XML output
        │   ├── nuclei/             ← nuclei JSONL results
        │   ├── httpx/              ← httpx JSONL results
        │   ├── ffuf/               ← ffuf JSON results
        │   ├── amass/              ← amass enumeration output
        │   ├── osint/              ← whois, theharvester, crt.sh
        │   └── misc/               ← anything else
        ├── loot/                   ← PoC screenshots, captured tokens, evidence
        ├── data/
        │   ├── missions.db         ← SQLite intel store + episodic memory
        │   └── chromadb/           ← ChromaDB vector store
        └── notes/
            └── engagement_log.md   ← auto-created engagement journal
"""

import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# Base workspace root — all engagements live under here
WORKSPACE_ROOT = Path("workspace")

# Tool output subdirectories (one per tool)
TOOL_DIRS = [
    "nmap", "nuclei", "httpx", "ffuf", "amass", "osint", "misc"
]


def sanitize_name(name: str) -> str:
    """Sanitize a company name into a filesystem-safe directory name.
    
    'Example Corp.' → 'example_corp'
    'Demo LLC' → 'demo_llc'
    """
    name = name.strip().lower()
    name = re.sub(r'[^\w\s-]', '', name)   # remove special chars
    name = re.sub(r'[\s-]+', '_', name)     # spaces/dashes → underscores
    name = re.sub(r'_+', '_', name)         # collapse multiple underscores
    return name.strip('_')


def init_workspace(company_name: str,
                   in_scope: list[str] | None = None,
                   out_of_scope: list[str] | None = None,
                   root: Path | None = None) -> Path:
    """Create a structured workspace for a company/engagement.
    
    Args:
        company_name: Human-readable company name (e.g. "Example Corp")
        in_scope: List of in-scope domains/IPs/CIDRs
        out_of_scope: List of out-of-scope domains/IPs
        root: Override workspace root (default: ./workspace)
    
    Returns:
        Path to the company workspace root directory
    """
    base = root or WORKSPACE_ROOT
    safe_name = sanitize_name(company_name)
    company_dir = base / safe_name

    # Create directory tree
    dirs = [
        company_dir / "scope",
        company_dir / "notes",
        company_dir / "loot",
        company_dir / "data" / "chromadb",
    ]
    for tool in TOOL_DIRS:
        dirs.append(company_dir / "output" / tool)
    dirs.append(company_dir / "output" / "reports")

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # Write scope files
    scope_dir = company_dir / "scope"
    _write_scope_file(scope_dir / "in_scope.txt", in_scope or [])
    _write_scope_file(scope_dir / "out_of_scope.txt", out_of_scope or [])

    # Create engagement log if it doesn't exist
    log_path = company_dir / "notes" / "engagement_log.md"
    if not log_path.exists():
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        log_path.write_text(
            f"# {company_name} — Engagement Log\n\n"
            f"Created: {now}\n\n"
            f"## Timeline\n\n"
            f"- **{now}** — Workspace initialized\n"
        )

    return company_dir


def _write_scope_file(path: Path, items: list[str]) -> None:
    """Write or update a scope file. Appends new entries, keeps existing ones."""
    existing: set[str] = set()
    if path.exists():
        existing = {line.strip() for line in path.read_text().splitlines()
                    if line.strip() and not line.startswith('#')}

    new_items = [item for item in items if item not in existing]
    if new_items or not path.exists():
        with open(path, 'a' if path.exists() else 'w') as f:
            if not path.exists() or path.stat().st_size == 0:
                header = "in-scope" if "in_scope" in path.name else "out-of-scope"
                f.write(f"# {header.upper()} targets — one per line\n")
            for item in new_items:
                f.write(f"{item}\n")


def get_workspace(company_name: str, root: Path | None = None) -> Path:
    """Get the workspace path for an existing company."""
    base = root or WORKSPACE_ROOT
    safe_name = sanitize_name(company_name)
    return base / safe_name


def get_db_path(company_dir: Path) -> str:
    """Get the SQLite database path within a company workspace."""
    return str(company_dir / "data" / "missions.db")


def get_chromadb_dir(company_dir: Path) -> str:
    """Get the ChromaDB directory within a company workspace."""
    return str(company_dir / "data" / "chromadb")


def get_report_dir(company_dir: Path) -> Path:
    """Get the reports output directory within a company workspace."""
    return company_dir / "output" / "reports"


def get_tool_output_dir(company_dir: Path, tool_name: str) -> Path:
    """Get the output directory for a specific tool.
    
    Maps tool names to their directories:
        nmap → output/nmap/
        nuclei → output/nuclei/
        httpx → output/httpx/
        ffuf → output/ffuf/
        amass → output/amass/
        whois, theharvester, crt_sh → output/osint/
        anything else → output/misc/
    """
    osint_tools = {"whois", "theharvester", "crt_sh", "crt.sh", "shodan",
                   "github_dork", "web_search"}
    
    if tool_name in TOOL_DIRS:
        out = company_dir / "output" / tool_name
    elif tool_name in osint_tools:
        out = company_dir / "output" / "osint"
    else:
        out = company_dir / "output" / "misc"

    out.mkdir(parents=True, exist_ok=True)
    return out


def list_workspaces(root: Path | None = None) -> list[dict]:
    """List all existing company workspaces."""
    base = root or WORKSPACE_ROOT
    if not base.exists():
        return []

    results = []
    for d in sorted(base.iterdir()):
        if d.is_dir() and (d / "scope").exists():
            # Read scope counts
            in_scope = _count_scope(d / "scope" / "in_scope.txt")
            out_scope = _count_scope(d / "scope" / "out_of_scope.txt")
            # Count missions
            db_path = d / "data" / "missions.db"
            results.append({
                "name": d.name,
                "path": str(d),
                "in_scope_count": in_scope,
                "out_of_scope_count": out_scope,
                "has_db": db_path.exists(),
            })
    return results


def _count_scope(path: Path) -> int:
    """Count non-comment, non-empty lines in a scope file."""
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text().splitlines()
               if line.strip() and not line.startswith('#'))


def append_engagement_log(company_dir: Path, entry: str) -> None:
    """Append a timestamped entry to the engagement log."""
    log = company_dir / "notes" / "engagement_log.md"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(log, 'a') as f:
        f.write(f"- **{now}** — {entry}\n")


def save_subdomains(company_dir: Path, subdomains: list[str]) -> int:
    """Save discovered subdomains to scope/subdomains.txt (deduped, append-only).

    Returns the number of NEW subdomains added.
    """
    path = company_dir / "scope" / "subdomains.txt"
    existing: set[str] = set()
    if path.exists():
        existing = {
            line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.startswith('#')
        }

    new_subs = sorted(set(s.strip().lower() for s in subdomains if s.strip()) - existing)
    if new_subs or not path.exists():
        with open(path, 'a' if path.exists() else 'w') as f:
            if not existing and not path.exists():
                f.write("# Discovered subdomains — auto-populated by Akagami\n")
            for sub in new_subs:
                f.write(f"{sub}\n")

    return len(new_subs)


def get_subdomains(company_dir: Path) -> list[str]:
    """Read all discovered subdomains from scope/subdomains.txt."""
    path = company_dir / "scope" / "subdomains.txt"
    if not path.exists():
        return []
    return [
        line.strip() for line in path.read_text().splitlines()
        if line.strip() and not line.startswith('#')
    ]
