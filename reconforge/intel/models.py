"""
ReconForge Intel Models — Canonical data types for the entire system.

Every object that flows through agents, skills, memory, and intel store
must use these Pydantic v2 models. No raw dicts between components.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MissionMode(str, Enum):
    STANDARD = "standard"
    BUG_BOUNTY = "bug-bounty"


class PortState(str, Enum):
    OPEN = "open"
    FILTERED = "filtered"
    CLOSED = "closed"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    BLOCKED = "blocked"


class OpsecRisk(str, Enum):
    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class StageType(str, Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    REPORT = "report"


class OsintCategory(str, Enum):
    EMAIL = "email"
    GITHUB = "github"
    LINKEDIN = "linkedin"
    PASTEBIN = "pastebin"
    CERT = "cert"
    WHOIS = "whois"
    DNS = "dns"
    SUBDOMAIN = "subdomain"
    TECHNOLOGY = "technology"
    OTHER = "other"


# ──────────────────────────────────────────────────────────────
# Base Intel Model
# ──────────────────────────────────────────────────────────────

def _gen_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class IntelBase(BaseModel):
    """Every object in the system has these base fields."""
    id: str = Field(default_factory=_gen_id)
    source_agent: str                          # which agent created this
    source_tool: str                           # which tool produced the raw data
    confidence: float = Field(ge=0.0, le=1.0)  # 0.0–1.0
    timestamp: datetime = Field(default_factory=_now)
    mission_id: str
    verified: bool = False                     # True after critic agent review
    raw_output: str = ""                       # always preserve original tool output


# ──────────────────────────────────────────────────────────────
# Intel Types
# ──────────────────────────────────────────────────────────────

class Host(IntelBase):
    ip: str
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    os_confidence: Optional[float] = None
    tags: list[str] = Field(default_factory=list)  # e.g. ["web", "database", "exposed"]


class Port(IntelBase):
    host_id: str                       # FK to Host.id
    port: int
    protocol: str = Protocol.TCP       # tcp/udp
    state: str = PortState.OPEN        # open/filtered/closed
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


class Subdomain(IntelBase):
    domain: str
    ip: Optional[str] = None
    cname: Optional[str] = None
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    technologies: list[str] = Field(default_factory=list)


class Vulnerability(IntelBase):
    host_id: str
    port_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: str = Severity.INFO      # critical/high/medium/low/info
    title: str = ""
    description: str = ""
    evidence: str = ""
    remediation: Optional[str] = None
    exploit_available: bool = False
    exploit_reference: Optional[str] = None


class Credential(IntelBase):
    host_id: Optional[str] = None
    service: str = ""
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None
    source: str = ""                   # where it was found


class WebPath(IntelBase):
    host_id: str
    url: str
    status_code: int = 0
    content_type: Optional[str] = None
    interesting: bool = False
    reason: Optional[str] = None       # why flagged as interesting


class OsintFinding(IntelBase):
    category: str = OsintCategory.OTHER  # email/github/linkedin/pastebin/cert/whois
    value: str = ""
    context: str = ""


class SessionContext(IntelBase):
    """Authenticated session context for BrowserAgent."""
    host_id: str
    cookies: list[dict] = Field(default_factory=list)
    local_storage: dict = Field(default_factory=dict)
    session_storage: dict = Field(default_factory=dict)
    jwt_tokens: list[str] = Field(default_factory=list)
    auth_headers: dict = Field(default_factory=dict)
    username: Optional[str] = None
    role: Optional[str] = None


class SecretFinding(IntelBase):
    """Hardcoded secret or credential found in JS or source."""
    host_id: Optional[str] = None
    file_path: str = ""
    secret_type: str = ""              # e.g., aws_key, stripe_key, password
    secret_value: str = ""
    is_verified: bool = False


# ──────────────────────────────────────────────────────────────
# Mission State
# ──────────────────────────────────────────────────────────────

class MissionState(BaseModel):
    """Full state of a running mission."""
    mission_id: str = Field(default_factory=_gen_id)
    target: str = ""
    mission_name: str = ""
    company_name: str = ""                                    # bug bounty company name
    workspace_dir: str = ""                                   # path to company workspace root
    scope: list[str] = Field(default_factory=list)            # in-scope IPs/domains
    out_of_scope: list[str] = Field(default_factory=list)
    current_stage: str = StageType.RECON
    stage_gate_passed: bool = False
    operator_approved: bool = False
    opsec_mode: bool = False
    active_scan_permitted: bool = False
    mode: str = MissionMode.STANDARD                          # standard or bug-bounty
    started_at: datetime = Field(default_factory=_now)
    completed_at: Optional[datetime] = None
    task_graph: dict = Field(default_factory=dict)            # serialized TCG state


# ──────────────────────────────────────────────────────────────
# Task (for TaskCoordinationGraph)
# ──────────────────────────────────────────────────────────────

class Task(BaseModel):
    """A single task node in the TaskCoordinationGraph."""
    id: str = Field(default_factory=_gen_id)
    agent_type: str = ""          # osint / recon / vuln / exploit_planner
    tool: str = ""                # specific tool to run
    params: dict = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)  # task IDs that must complete first
    status: str = TaskStatus.PENDING
    priority: int = 2             # 1=high, 2=medium, 3=low
    opsec_risk: str = OpsecRisk.PASSIVE
    result: Optional[dict] = None


# ──────────────────────────────────────────────────────────────
# Tool Result
# ──────────────────────────────────────────────────────────────

class ToolResult(BaseModel):
    """Structured result from a tool execution."""
    tool: str
    params: dict = Field(default_factory=dict)
    raw: str = ""            # original output, unmodified
    clean: str = ""          # sanitized output safe for LLM
    exit_code: int = 0
    duration_ms: int = 0
    error: Optional[str] = None


class RawResult(BaseModel):
    """Raw subprocess output before sanitization."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 0


# ──────────────────────────────────────────────────────────────
# Skill / Critic models
# ──────────────────────────────────────────────────────────────

class ReviewVerdict(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    IMPROVE = "improve"
    QUARANTINE = "quarantine"


class ReviewResult(BaseModel):
    """Result from the CriticAgent review of a finding."""
    verdict: str = ReviewVerdict.APPROVE
    reason: str = ""
    confidence_adjustment: Optional[float] = None
    improved_finding: Optional[dict] = None


class GateResult(BaseModel):
    """Result from StageGate evaluation."""
    passed: bool = False
    confidence: float = 0.0
    reason: str = ""
    missing_coverage: list[str] = Field(default_factory=list)
    requires_operator_approval: bool = True


# ──────────────────────────────────────────────────────────────
# Custom Exceptions
# ──────────────────────────────────────────────────────────────

class OutOfScopeError(Exception):
    """Raised when a target is not in the mission scope."""
    pass


class AgentLockedError(Exception):
    """Raised when a locked agent (e.g. ExploitPlanner) is called."""
    pass


class ToolTimeoutError(Exception):
    """Raised when a tool exceeds its timeout."""
    pass


class ToolExecutionError(Exception):
    """Raised when a tool fails to execute."""
    pass
