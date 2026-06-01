"""Dry-run planning helpers for recon missions.

This module deliberately avoids runtime stores, agents, workers, and LLM
routers. It only loads local tool metadata, builds the deterministic task
graph, validates it through the same local safety gates, and summarizes what
would happen during a real mission.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from reconforge.intel.models import MissionState, Task
from reconforge.orchestrator.master import (
    SYNTHETIC_PASSIVE_TOOLS,
    TOOL_ALIASES,
    MasterOrchestrator,
)
from reconforge.orchestrator.task_graph import TaskCoordinationGraph
from reconforge.tools.bus import MCP_TOOLS
from reconforge.tools.executor import ToolExecutor
from reconforge.tools.scope import is_target_in_scope


SYNTHETIC_TOOL_REQUESTS: dict[str, list[str]] = {
    "all": [
        "whois",
        "crt_sh",
        "theharvester",
        "shodan",
        "shodan_search",
        "github_code_search",
    ],
    "correlate": [],
    "vuln_correlation": [],
    "plan_exploits": [],
    "prioritize": [],
    "chain_analysis": [],
}

INTERNAL_TOOLS = {
    "correlate",
    "vuln_correlation",
    "plan_exploits",
    "prioritize",
    "chain_analysis",
}

DEFAULT_TARGET_FIELDS = ("target", "domain", "url", "host", "ip")


def build_recon_dry_run(mission: MissionState, config: dict) -> dict[str, Any]:
    """Build a local-only dry-run plan summary for a recon mission."""
    executor = ToolExecutor(config.get("tools_config", "config/tools.yaml"))
    registry = executor.tools_config.get("tools", {})
    raw_plan = (
        TaskCoordinationGraph.build_default_active_plan(mission.target)
        if mission.active_scan_permitted
        else TaskCoordinationGraph.build_default_passive_plan(mission.target)
    )

    validator = _validation_orchestrator(mission, config, executor)
    validated = validator._validated_tasks_from_llm(
        [task.model_dump() for task in raw_plan]
    )

    graph = TaskCoordinationGraph()
    graph.load(validated)

    valid_ids = {task.id for task in validated}
    task_rows = [
        _task_row(task, task.id in valid_ids, registry, mission)
        for task in raw_plan
    ]

    return {
        "mission": mission,
        "config_path": config.get("_config_path", ""),
        "config_loaded": bool(config.get("_config_loaded", False)),
        "planner": (
            "default_active" if mission.active_scan_permitted
            else "default_passive"
        ),
        "llm_calls": 0,
        "external_tools_executed": 0,
        "runtime_writes": [],
        "task_graph": graph,
        "planned_tasks": validated,
        "rejected_tasks": [
            row for row in task_rows if row["validation"] != "planned"
        ],
        "task_rows": task_rows,
        "agent_rows": _agent_rows(validated),
        "tool_rows": _tool_rows(validated, registry),
        "risk_rows": _risk_rows(validated),
        "scope_rows": _scope_rows(raw_plan, registry, mission),
    }


def _validation_orchestrator(
    mission: MissionState,
    config: dict,
    executor: ToolExecutor,
) -> MasterOrchestrator:
    """Create a minimal object with only fields needed by validation methods."""
    orch = MasterOrchestrator.__new__(MasterOrchestrator)
    orch.mission = mission
    orch.config = config
    orch.executor = executor
    orch._tool_registry = executor.tools_config.get("tools", {})
    orch.task_graph = TaskCoordinationGraph()
    return orch


def _task_row(
    task: Task,
    planned: bool,
    registry: dict,
    mission: MissionState,
) -> dict[str, Any]:
    requested = _requested_tools(task)
    risks = sorted({
        _tool_risk(tool, registry, task.opsec_risk)
        for tool in requested
    } or {task.opsec_risk})
    scope = _task_scope_decision(task, registry, mission)
    return {
        "id": task.id,
        "agent": task.agent_type,
        "task_tool": task.tool,
        "requested_tools": requested,
        "risk": ", ".join(risks),
        "depends_on": task.depends_on,
        "scope_status": scope["status"],
        "scope_subjects": scope["subjects"],
        "validation": "planned" if planned else "rejected",
    }


def _agent_rows(tasks: list[Task]) -> list[dict[str, Any]]:
    by_agent: dict[str, list[Task]] = defaultdict(list)
    for task in tasks:
        by_agent[task.agent_type].append(task)

    rows = []
    for agent, agent_tasks in sorted(by_agent.items()):
        tools = sorted({
            tool
            for task in agent_tasks
            for tool in _requested_tools(task)
        })
        rows.append({
            "agent": agent,
            "tasks": len(agent_tasks),
            "tools": tools,
        })
    return rows


def _tool_rows(tasks: list[Task], registry: dict) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    task_ids: dict[str, list[str]] = defaultdict(list)
    for task in tasks:
        for tool in _requested_tools(task):
            counts[tool] += 1
            task_ids[tool].append(task.id)

    rows = []
    for tool, count in sorted(counts.items()):
        meta = registry.get(tool, {})
        rows.append({
            "tool": tool,
            "count": count,
            "binary": meta.get("binary", "-") if tool not in INTERNAL_TOOLS else "-",
            "risk": _tool_risk(tool, registry, "passive"),
            "route": _tool_route(tool),
            "tasks": task_ids[tool],
        })
    return rows


def _risk_rows(tasks: list[Task]) -> list[dict[str, Any]]:
    counts = Counter(task.opsec_risk for task in tasks)
    return [
        {"risk": risk, "tasks": counts.get(risk, 0)}
        for risk in ("passive", "low", "medium", "high")
        if counts.get(risk, 0)
    ]


def _scope_rows(tasks: list[Task], registry: dict, mission: MissionState) -> list[dict[str, Any]]:
    return [
        {
            "task": task.id,
            "tool": task.tool,
            **_task_scope_decision(task, registry, mission),
        }
        for task in tasks
    ]


def _requested_tools(task: Task) -> list[str]:
    if task.tool in SYNTHETIC_TOOL_REQUESTS:
        return SYNTHETIC_TOOL_REQUESTS[task.tool] or [task.tool]
    return [TOOL_ALIASES.get(task.tool, task.tool)]


def _tool_risk(tool: str, registry: dict, fallback: str) -> str:
    if tool in INTERNAL_TOOLS:
        return "passive"
    meta = registry.get(tool, {})
    return meta.get("opsec_risk") or fallback or "unknown"


def _tool_route(tool: str) -> str:
    if tool in INTERNAL_TOOLS:
        return "internal"
    if tool in MCP_TOOLS:
        return "MCP/API"
    return "subprocess"


def _task_scope_decision(task: Task, registry: dict, mission: MissionState) -> dict[str, Any]:
    subjects = _scope_subjects(task, registry)
    if not subjects:
        return {"status": "no scoped subject", "subjects": []}

    allowed_subjects = []
    denied_subjects = []
    undecided_subjects = []
    for subject in subjects:
        allowed, denied = is_target_in_scope(
            subject, mission.scope, mission.out_of_scope
        )
        if denied:
            denied_subjects.append(subject)
        elif allowed:
            allowed_subjects.append(subject)
        else:
            undecided_subjects.append(subject)

    if denied_subjects:
        status = "denied"
    elif allowed_subjects:
        status = "allowed"
    else:
        status = "not in scope"

    return {
        "status": status,
        "subjects": subjects,
        "allowed": allowed_subjects,
        "denied": denied_subjects,
        "not_in_scope": undecided_subjects,
    }


def _scope_subjects(task: Task, registry: dict) -> list[str]:
    if task.tool in SYNTHETIC_PASSIVE_TOOLS:
        fields = DEFAULT_TARGET_FIELDS
    else:
        canonical = TOOL_ALIASES.get(task.tool, task.tool)
        tool_def = registry.get(canonical, {})
        fields = tool_def.get("target_fields") or DEFAULT_TARGET_FIELDS

    subjects = []
    for field in fields:
        value = task.params.get(field)
        if isinstance(value, str) and value.strip():
            subjects.append(value)
    return subjects
