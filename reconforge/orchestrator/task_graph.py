"""
ReconForge Task Coordination Graph — Dependency-aware task scheduling.
Borrowed from xOffense. Encodes what depends on what as a DAG.

Default web target dependency chain:
1. whois_lookup         (passive, no deps)
2. cert_transparency    (passive, no deps)
3. github_dork          (passive, no deps)
4. shodan_lookup        (passive, no deps)
5. passive_dns          (passive, no deps)
6. subdomain_enum_amass (passive, depends: 5)
7. subdomain_enum_crt   (passive, depends: 2)
8. merge_subdomains     (skill, depends: 6, 7)
9. httpx_probe          (active, depends: 8)   ← first active step
10. nmap_top_ports      (active, depends: 9)
11. banner_grab         (active, depends: 10)
12. tech_fingerprint    (active, depends: 9)
13. dir_fuzz_ffuf       (active, depends: 9, 12)
14. nuclei_scan         (active, depends: 9, 10)
15. vuln_correlation    (skill, depends: 14, 10, 11)
"""

from typing import Optional

from reconforge.intel.models import Task, TaskStatus
from reconforge.utils.logger import get_logger

logger = get_logger("task_graph")


class TaskCoordinationGraph:
    """
    Directed acyclic graph of tasks. Tasks become 'ready' when all
    their dependencies are marked complete.
    """

    def __init__(self) -> None:
        self.tasks: dict[str, Task] = {}

    def load(self, tasks: list[Task] | list[dict]) -> None:
        """Load tasks into the graph."""
        for t in tasks:
            if isinstance(t, dict):
                t = Task(**t)
            self.tasks[t.id] = t
        logger.info(f"Task graph loaded: {len(self.tasks)} tasks")

    def add_task(self, task: Task) -> None:
        self.tasks[task.id] = task

    def get_ready_tasks(self) -> list[Task]:
        """Returns tasks whose all dependencies are complete."""
        ready = []
        for task in self.tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            deps_met = all(
                self.tasks.get(dep_id) and
                self.tasks[dep_id].status == TaskStatus.COMPLETE
                for dep_id in task.depends_on
            )
            if deps_met:
                ready.append(task)
        # Sort by priority (1=high first), then by opsec risk (passive first)
        risk_order = {"passive": 0, "low": 1, "medium": 2, "high": 3}
        ready.sort(key=lambda t: (t.priority, risk_order.get(t.opsec_risk, 2)))
        return ready

    def mark_running(self, task_id: str) -> None:
        if task_id in self.tasks:
            self.tasks[task_id].status = TaskStatus.RUNNING

    def mark_complete(self, task_id: str, result: Optional[dict] = None) -> None:
        """Mark task done, potentially unlocking dependent tasks."""
        if task_id in self.tasks:
            self.tasks[task_id].status = TaskStatus.COMPLETE
            self.tasks[task_id].result = result
            self._unblock_dependents(task_id)
            logger.debug(f"Task {task_id} completed")

    def mark_failed(self, task_id: str, error: Optional[str] = None) -> None:
        if task_id in self.tasks:
            self.tasks[task_id].status = TaskStatus.FAILED
            self.tasks[task_id].result = {"error": error}
            self._block_dependents(task_id)
            logger.warning(f"Task {task_id} failed: {error}")

    def mark_pending(self, task_id: str) -> None:
        """Reset a task to pending for retry (self-correction loop)."""
        if task_id in self.tasks:
            self.tasks[task_id].status = TaskStatus.PENDING
            self.tasks[task_id].result = None
            self._unblock_dependents(task_id)
            logger.info(f"Task {task_id} reset to pending for retry")

    def mark_blocked(self, task_id: str, blocked_by: str) -> None:
        if task_id in self.tasks:
            task = self.tasks[task_id]
            if task.status == TaskStatus.PENDING:
                task.status = TaskStatus.BLOCKED
                task.result = {"blocked_by": blocked_by}
                logger.warning(f"Task {task_id} blocked by failed dependency {blocked_by}")

    def _block_dependents(self, failed_task_id: str) -> None:
        for task in self.tasks.values():
            if failed_task_id in task.depends_on and task.status == TaskStatus.PENDING:
                self.mark_blocked(task.id, failed_task_id)
                self._block_dependents(task.id)

    def _unblock_dependents(self, dependency_id: str) -> None:
        for task in self.tasks.values():
            if dependency_id not in task.depends_on:
                continue
            if task.status == TaskStatus.BLOCKED and task.result and task.result.get("blocked_by") == dependency_id:
                task.status = TaskStatus.PENDING
                task.result = None

    def is_complete(self) -> bool:
        """True when all tasks are complete or failed."""
        return all(
            t.status in (TaskStatus.COMPLETE, TaskStatus.FAILED, TaskStatus.BLOCKED)
            for t in self.tasks.values()
        )

    def get_critical_path(self) -> list[Task]:
        """Returns the longest dependency chain — useful for ETA."""
        def chain_len(task_id: str, visited: set) -> int:
            if task_id in visited or task_id not in self.tasks:
                return 0
            visited.add(task_id)
            task = self.tasks[task_id]
            if not task.depends_on:
                return 1
            return 1 + max(chain_len(d, visited) for d in task.depends_on)

        max_len = 0
        critical = []
        for tid in self.tasks:
            length = chain_len(tid, set())
            if length > max_len:
                max_len = length
                critical = self._trace_chain(tid)
        return critical

    def _trace_chain(self, task_id: str) -> list[Task]:
        """Trace the dependency chain backwards from a task."""
        chain = []
        visited = set()
        current = task_id
        while current and current not in visited and current in self.tasks:
            visited.add(current)
            task = self.tasks[current]
            chain.append(task)
            current = task.depends_on[0] if task.depends_on else None
        chain.reverse()
        return chain

    def get_status_summary(self) -> dict:
        """Get summary of task statuses."""
        summary = {"pending": 0, "running": 0, "complete": 0, "failed": 0, "total": len(self.tasks)}
        for t in self.tasks.values():
            summary[t.status] = summary.get(t.status, 0) + 1
        return summary

    def get_tasks_by_agent(self) -> dict[str, list[Task]]:
        """Group tasks by agent type."""
        by_agent: dict[str, list[Task]] = {}
        for task in self.tasks.values():
            by_agent.setdefault(task.agent_type, []).append(task)
        return by_agent

    def get_pending_count(self) -> int:
        """Count pending tasks."""
        return sum(1 for t in self.tasks.values() if t.status == TaskStatus.PENDING)

    def serialize(self) -> list[dict]:
        """Serialize graph for persistence."""
        return [t.model_dump() for t in self.tasks.values()]

    # ── Default Plans ────────────────────────────────────────

    @staticmethod
    def build_default_passive_plan(target: str) -> list[Task]:
        """Default passive-only OSINT task plan."""
        return [
            Task(id="whois_lookup", agent_type="osint", tool="whois",
                 params={"target": target}, priority=1, opsec_risk="passive"),
            Task(id="cert_transparency", agent_type="osint", tool="crt_sh",
                 params={"target": target, "domain": target},
                 priority=1, opsec_risk="passive"),
            Task(id="harvester_scan", agent_type="osint", tool="theharvester",
                 params={"target": target, "domain": target},
                 depends_on=["whois_lookup"], priority=2, opsec_risk="passive"),
        ]

    @staticmethod
    def build_default_active_plan(target: str) -> list[Task]:
        """
        Default full recon task plan for a web target.
        Implements the dependency chain from Section 6 of the spec.
        """
        return [
            # ── Phase 1: Passive (no deps) ───────────────
            Task(id="whois_lookup", agent_type="osint", tool="whois",
                 params={"target": target},
                 priority=1, opsec_risk="passive"),
            Task(id="cert_transparency", agent_type="osint", tool="crt_sh",
                 params={"target": target, "domain": target},
                 priority=1, opsec_risk="passive"),
            Task(id="passive_dns", agent_type="osint", tool="all",
                 params={"target": target, "domain": target},
                 priority=1, opsec_risk="passive"),

            # ── Phase 2: Subdomain enum (depends on passive) ─
            Task(id="subdomain_enum_crt", agent_type="osint", tool="crt_sh",
                 params={"target": target, "domain": target},
                 depends_on=["cert_transparency"],
                 priority=1, opsec_risk="passive"),

            # ── Phase 3: Active probing ──────────────────
            Task(id="httpx_probe", agent_type="recon", tool="httpx",
                 params={"target": target,
                         "ports": "80,443,8080,8443,8000,3000"},
                 depends_on=["passive_dns", "subdomain_enum_crt"],
                 priority=1, opsec_risk="low"),

            # ── Phase 4: Port scanning + banner grab ─────
            Task(id="nmap_top_ports", agent_type="recon", tool="nmap",
                 params={"target": target, "ports": "1-10000",
                         "timing": 3},
                 depends_on=["httpx_probe"],
                 priority=1, opsec_risk="medium"),
            Task(id="banner_grab", agent_type="recon", tool="banner_grab",
                 params={"target": target},
                 depends_on=["nmap_top_ports"],
                 priority=2, opsec_risk="medium"),

            # ── Phase 5: Tech fingerprint + dir fuzz ─────
            Task(id="tech_fingerprint", agent_type="recon", tool="tech_fingerprint",
                 params={"target": target},
                 depends_on=["httpx_probe"],
                 priority=2, opsec_risk="low"),
            Task(id="dir_fuzz_ffuf", agent_type="recon", tool="ffuf",
                 params={"target": target,
                         "wordlist": "/usr/share/wordlists/dirb/common.txt"},
                 depends_on=["httpx_probe", "tech_fingerprint"],
                 priority=2, opsec_risk="medium"),

            # ── Phase 6: Vulnerability scanning ──────────
            Task(id="nuclei_scan", agent_type="vuln", tool="nuclei",
                 params={"target": target,
                         "severity": "critical,high,medium"},
                 depends_on=["httpx_probe", "nmap_top_ports"],
                 priority=2, opsec_risk="medium"),

            # ── Phase 7: Correlation ─────────────────────
            Task(id="vuln_correlation", agent_type="vuln", tool="correlate",
                 params={"target": target},
                 depends_on=["nuclei_scan", "nmap_top_ports", "banner_grab"],
                 priority=3, opsec_risk="passive"),
        ]
