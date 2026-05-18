"""
ReconForge Master Orchestrator — The brain. Plans, delegates, reviews, decides.
Never executes tools directly. Only plans and reviews through sub-agents.

Phase 5 enhancements:
- Self-correction loops: failed tasks get retried with adjusted params
- Mission resume: restore from episodic memory on crash/restart
- MCP bridge integration: Shodan/GitHub tools available to OSINT agent
- Exploit planner unlock: automatically after stage gate pass
- Report generation: auto-generate at mission completion
"""

import json
from typing import Optional
from pathlib import Path

from reconforge.llm.router import LLMRouter
from dotenv import load_dotenv

from reconforge.agents.base import BaseAgent
from reconforge.agents.exploit_planner import ExploitPlannerAgent
from reconforge.agents.osint import OsintAgent
from reconforge.agents.recon import ActiveReconAgent
from reconforge.agents.vuln import VulnAnalysisAgent
from reconforge.agents.browser import BrowserAgent
from reconforge.agents.js_analysis import JSAnalysisAgent
from reconforge.agents.ai_redteam import AIRedTeamAgent
from reconforge.intel.models import IntelBase, MissionState, Task, ReviewVerdict, MissionMode, Vulnerability, SecretFinding
from reconforge.intel.store import IntelStore
from reconforge.memory.episodic import EpisodicMemory
from reconforge.memory.summarizer import ContextSummarizer
from reconforge.memory.working import WorkingMemory
from reconforge.orchestrator.stage_gate import StageGate
from reconforge.orchestrator.task_graph import TaskCoordinationGraph
from reconforge.orchestrator.event_bus import EventBus, Event
from reconforge.report.generator import ReportGenerator
from reconforge.skills.critic import CriticAgent
from reconforge.skills.enricher import CveEnricher
from reconforge.skills.scorer import SeverityScorer
from reconforge.skills.chainer import AttackPathChainer
from reconforge.memory.semantic import SemanticMemory

from reconforge.tools.bus import ToolBus, VALID_OPSEC_RISKS
from reconforge.tools.executor import ToolExecutor
from reconforge.tools.mcp_bridge import McpBridge
from reconforge.utils.logger import get_logger
from reconforge.utils.opsec import OpsecController
from reconforge.utils.sanitizer import OutputSanitizer

logger = get_logger("orchestrator")

# Max retries for self-correction loop per task
MAX_TASK_RETRIES = 2

SYNTHETIC_PASSIVE_TOOLS = {"all", "correlate", "vuln_correlation",
                           "plan_exploits", "prioritize", "chain_analysis"}
TOOL_ALIASES = {
    "nmap_top_ports": "nmap",
    "banner_grab": "nmap",
    "httpx_probe": "httpx",
    "tech_fingerprint": "httpx",
    "dir_fuzz_ffuf": "ffuf",
    "github_dork": "github_code_search",
    "playwright": "browser",
    "prompt_injection": "ai_redteam",
    "js_analysis": "trufflehog",
}

AGENT_TOOL_ALLOWLIST: dict[str, set[str]] = {
    "osint": {"whois", "crt_sh", "theharvester", "shodan", "github_dork",
              "web_search", "subfinder", "gau", "all"},
    "recon": {"nmap", "nmap_top_ports", "httpx", "httpx_probe", "ffuf",
              "dir_fuzz_ffuf", "banner_grab", "tech_fingerprint", "arjun",
              "corsy", "ssrfmap", "all"},
    "vuln": {"nuclei", "correlate", "vuln_correlation", "searchsploit",
             "jwt_tool", "graphql_cop", "clairvoyance"},
    "browser": {"playwright", "playwright_script", "browser"},
    "js_agent": {"js_analysis", "trufflehog"},
    "ai_redteam": {"ai_redteam", "prompt_injection"},
    "exploit_planner": {"plan_exploits", "prioritize", "chain_analysis"},
}

ORCHESTRATOR_SYSTEM_PROMPT = """You are the Master Orchestrator of ReconForge, a professional penetration testing agent system.
Your role is PLANNING and REVIEW only — you never execute tools yourself.

You think like a senior red team lead:
- You reason about attack surface methodically
- You always confirm scope before any action
- You produce structured, machine-parseable plans (JSON task lists)
- You review agent findings critically — you flag low-confidence results
- You think about what's MISSING, not just what was found
- You consider opsec implications of every action
- You know that passive recon always precedes active scanning

When planning, output ONLY valid JSON matching this schema:
[{"id": str, "agent_type": "osint"|"recon"|"vuln"|"browser"|"ai_redteam", "tool": str, "params": dict, "depends_on": [str], "priority": 1|2|3, "opsec_risk": "passive"|"low"|"medium"|"high"}]
Never produce conversational text in your planning responses."""

SELF_CORRECT_PROMPT = """A task failed during reconnaissance. Analyze the error and suggest a corrected task.

Failed task:
{task_json}

Error message:
{error}

Available tools: {tools}

Respond with ONE corrected task as JSON. Adjust parameters, change tool, or mark as skip.
If the error is unrecoverable, respond: {{"skip": true, "reason": "explanation"}}"""


class MasterOrchestrator:
    """The brain of ReconForge. Plans, delegates, reviews, decides."""

    def __init__(self, mission: MissionState, config: dict,
                 db_path: str = "output/missions.db") -> None:
        load_dotenv()
        self.mission = mission
        self.config = config
        #V2: LLM calls go through router

        # Use workspace-specific db if available
        effective_db = config.get("_db_path", db_path)

        # Initialize components
        self.memory = WorkingMemory()
        self.sanitizer = OutputSanitizer()

        # Load custom headers from mission config (e.g. X-Comolho-Client for ClearTax)
        custom_headers = config.get("custom_headers", {})
        self.opsec = OpsecController(custom_headers=custom_headers)

        self.episodic = EpisodicMemory(effective_db)
        self.intel = IntelStore(effective_db)
        self.executor = ToolExecutor(config.get("tools_config", "config/tools.yaml"))
        self._tool_registry = self.executor.tools_config.get("tools", {})
        self.router = LLMRouter()
        self.mcp_bridge = McpBridge(router=self.router)
        self.tool_bus = ToolBus(
            self.executor, self.episodic, self.sanitizer,
            self.opsec, self.mcp_bridge)
        self.task_graph = TaskCoordinationGraph()
        self.event_bus = EventBus()
        import asyncio
        self.task_queue = asyncio.Queue()
        self.semantic = SemanticMemory()
        self.chainer = AttackPathChainer(router=self.router, semantic=self.semantic)
        self.stage_gate = StageGate(router=self.router)
        self.critic = CriticAgent(router=self.router)
        self.summarizer = ContextSummarizer(router=self.router)
        self.enricher = CveEnricher(router=self.router, semantic=self.semantic)
        self.scorer = SeverityScorer(router=self.router)
        self.report_gen = ReportGenerator(router=self.router)

        # Track retries for self-correction
        self._task_retries: dict[str, int] = {}
        self._queued_task_ids: set[str] = set()
        self._task_fingerprints: set[str] = set()

        # Initialize agents (OSINT gets MCP bridge for Shodan/GitHub)
        self.agents: dict[str, BaseAgent] = {
            "osint": OsintAgent(self.router, self.tool_bus, self.memory,
                                mcp_bridge=self.mcp_bridge),
            "recon": ActiveReconAgent(self.router, self.tool_bus, self.memory),
            "vuln": VulnAnalysisAgent(self.router, self.tool_bus, self.memory),
            "js_agent": JSAnalysisAgent(self.router, self.tool_bus, self.memory),
            "browser": BrowserAgent(self.router, self.tool_bus, self.memory),
            "exploit_planner": ExploitPlannerAgent(self.router, self.tool_bus, self.memory),
            "ai_redteam": AIRedTeamAgent(self.router, self.tool_bus, self.memory),
        }

    def _setup_event_handlers(self):
        """Register event handlers for dynamic task generation."""
        async def on_subdomain(event: Event):
            subdomain = event.data["subdomain"]
            task = Task(id=f"dyn_httpx_{self._safe_task_id(subdomain)}",
                        agent_type="recon", tool="httpx",
                        params={"target": subdomain, "ports": "80,443"},
                        opsec_risk="low")
            await self._add_dynamic_task(task)
            
        async def on_host(event: Event):
            ip = event.data["ip"]
            if self.mission.active_scan_permitted:
                task = Task(id=f"dyn_nmap_{self._safe_task_id(ip)}",
                            agent_type="recon", tool="nmap",
                            params={"target": ip, "ports": "top-100"},
                            opsec_risk="medium")
                await self._add_dynamic_task(task)
                
        async def on_webpath(event: Event):
            url = event.data["url"]
            if self.mission.active_scan_permitted:
                # Spawn multiple downstream tasks for the URL
                for tool in ["nuclei", "ffuf", "arjun", "corsy", "ssrfmap"]:
                    task = Task(id=f"dyn_{tool}_{self._safe_task_id(url)}",
                                agent_type="recon" if tool in ["ffuf", "arjun", "corsy", "ssrfmap"] else "vuln",
                                tool=tool, params={"target": url},
                                opsec_risk="medium")
                    await self._add_dynamic_task(task)

        self.event_bus.subscribe("SubdomainFoundEvent", on_subdomain)
        self.event_bus.subscribe("HostFoundEvent", on_host)
        self.event_bus.subscribe("WebPathFoundEvent", on_webpath)

    async def _task_worker(self):
        import asyncio
        while True:
            task = None
            try:
                task = await self.task_queue.get()
                self._queued_task_ids.discard(task.id)
                await self._execute_task(task)
                self.task_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker error: {e}")
                if task is not None:
                    self.task_queue.task_done()

    async def run(self) -> dict:
        """Execute the full orchestrator loop."""
        logger.info(f"Starting mission: {self.mission.mission_name} → {self.mission.target}")

        import asyncio
        # Register mission in episodic memory
        self.episodic.create_mission(
            self.mission.mission_id, self.mission.target,
            self.config)

        self.event_bus.start()
        self._setup_event_handlers()

        # Step 1: Build initial plan via Claude
        plan = await self._plan_mission()
        if not plan:
            logger.warning("Empty plan generated. Ending mission.")
            return {
                "mission_id": self.mission.mission_id,
                "attack_surface": self.intel.get_attack_surface_summary(self.mission.mission_id),
                "task_summary": {"total": 0},
                "stage_gate": {"passed": False, "confidence": 0, "reason": "Empty plan"},
                "report_path": None,
                "retries": {}
            }

        self.task_graph.load(plan)
        self._register_task_fingerprints(plan)
        self.memory.set("plan", [t.model_dump() for t in plan] if isinstance(plan[0], Task) else plan)
        
        # Enqueue only tasks whose dependencies are satisfied.
        await self._enqueue_ready_tasks()

        # Step 2: Execute task graph using streaming event-driven workers
        workers = [asyncio.create_task(self._task_worker()) for _ in range(5)]
        
        # Wait for all initial and dynamically spawned tasks to complete
        while True:
            await self.task_queue.join()
            await self.event_bus.join()
            if self.task_queue.empty() and self.event_bus._queue.empty():
                break

        for w in workers:
            w.cancel()

        await self.event_bus.stop()

        # Step 2.25: Build passive HTTP/API request inventory from stored URL evidence.
        self._refresh_http_inventory()

        # Step 2.5: Evaluate Attack Paths from P4 findings
        logger.info("Evaluating findings for chained attack paths...")
        await self._evaluate_attack_paths()

        # Step 3: Evaluate stage gate (if not already passed via bug-bounty mode)
        if not self.mission.stage_gate_passed:
            gate_result = await self.stage_gate.evaluate(self.intel, self.mission)
            
            # Step 4: If gate passed, unlock exploit planner
            if gate_result.passed:
                self.mission.stage_gate_passed = True
                if self._unlock_exploits_if_allowed(gate_result):
                    logger.info("Stage gate PASSED — ExploitPlannerAgent unlocked")
                else:
                    logger.info(
                        "Stage gate PASSED — awaiting operator approval before "
                        "unlocking ExploitPlannerAgent"
                    )
        else:
            # Create a mock gate result since it was bypassed
            from reconforge.intel.models import GateResult
            reason = (
                "Bypassed by BUG-BOUNTY mode high-confidence finding"
                if self.mission.mode == MissionMode.BUG_BOUNTY
                else "Stage gate previously passed"
            )
            gate_result = GateResult(passed=True, confidence=1.0, reason=reason)
            if self._unlock_exploits_if_allowed(gate_result):
                logger.info("Stage gate already passed — ExploitPlannerAgent unlocked")

        # Step 5: Generate report — use workspace-aware path
        if self.mission.workspace_dir:
            from reconforge.workspace import get_report_dir
            report_dir = get_report_dir(Path(self.mission.workspace_dir))
            report_path = str(report_dir / f"report_{self.mission.mission_id[:8]}.md")
        else:
            Path("output").mkdir(exist_ok=True)
            report_path = f"output/report_{self.mission.mission_id[:8]}.md"
        try:
            await self.report_gen.generate(
                intel=self.intel,
                mission_id=self.mission.mission_id,
                output_path=report_path,
                mission_name=self.mission.mission_name,
                target=self.mission.target,
                episodic=self.episodic)
            logger.info(f"Report generated: {report_path}")
        except Exception as e:
            logger.warning(f"Report generation failed: {e}")
            report_path = None

        # Step 6: Complete mission
        self.episodic.complete_mission(self.mission.mission_id)

        summary = self.intel.get_attack_surface_summary(self.mission.mission_id)
        task_summary = self.task_graph.get_status_summary()

        logger.info(f"Mission complete. Tasks: {task_summary}, Gate: {'PASSED' if gate_result.passed else 'FAILED'}")

        return {
            "mission_id": self.mission.mission_id,
            "attack_surface": summary,
            "task_summary": task_summary,
            "stage_gate": gate_result.model_dump(),
            "report_path": report_path,
            "retries": dict(self._task_retries),
        }

    async def resume(self, mission_id: str) -> dict:
        """Resume a previously interrupted mission."""
        logger.info(f"Resuming mission: {mission_id}")
        ctx = self.episodic.get_resume_context(mission_id)
        if not ctx["mission"]:
            raise ValueError(f"Mission {mission_id} not found in episodic memory")

        # Restore mission state
        mission_data = ctx["mission"]
        self.mission.mission_id = mission_id
        self.mission.target = mission_data["target"]

        # Restore working memory from latest summary
        if ctx["latest_summary"]:
            self.memory.set("resume_context", ctx["latest_summary"])
            logger.info("Restored working memory from episodic summary")

        # Re-plan from current state (Claude sees what's already done)
        existing_summary = self.intel.get_attack_surface_summary(mission_id)
        self.memory.set("existing_surface", existing_summary)

        # Re-build plan, skipping already-completed work
        plan = await self._plan_mission()
        self.task_graph.load(plan)

        # Run remaining tasks
        return await self.run()

    # ── Task scheduling and validation ───────────────────────

    def _register_task_fingerprints(self, tasks: list[Task]) -> None:
        self._task_fingerprints = {self._task_fingerprint(t) for t in tasks}

    def _task_fingerprint(self, task: Task) -> str:
        payload = {
            "agent_type": task.agent_type,
            "tool": task.tool,
            "params": task.params,
            "depends_on": sorted(task.depends_on),
        }
        return json.dumps(payload, sort_keys=True, default=str)

    def _safe_task_id(self, value: str) -> str:
        import re
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())[:80]
        return safe.strip("_") or "target"

    async def _enqueue_task(self, task: Task) -> bool:
        """Queue a task once. Task graph status remains the source of truth."""
        if task.id in self._queued_task_ids:
            return False
        if task.status != "pending":
            return False
        self._queued_task_ids.add(task.id)
        await self.task_queue.put(task)
        return True

    async def _enqueue_ready_tasks(self) -> int:
        queued = 0
        for task in self.task_graph.get_ready_tasks():
            if await self._enqueue_task(task):
                queued += 1
        return queued

    async def _add_dynamic_task(self, task: Task) -> bool:
        """Validate, register, and enqueue a dynamically generated task if ready."""
        if not self._validate_task(task):
            return False
        if task.id in self.task_graph.tasks:
            logger.debug(f"Skipping duplicate dynamic task id: {task.id}")
            return False
        fingerprint = self._task_fingerprint(task)
        if fingerprint in self._task_fingerprints:
            logger.debug(f"Skipping duplicate dynamic task: {task.id}")
            return False

        self.task_graph.add_task(task)
        self._task_fingerprints.add(fingerprint)
        await self._enqueue_ready_tasks()
        return True

    def _validate_task(self, task: Task) -> bool:
        """Local safety gate for executable tasks, including LLM-generated ones."""
        allowed_tools = AGENT_TOOL_ALLOWLIST.get(task.agent_type)
        if not allowed_tools:
            logger.warning(f"Rejecting task {task.id}: unknown agent_type {task.agent_type}")
            return False
        if task.tool not in allowed_tools:
            logger.warning(
                f"Rejecting task {task.id}: tool {task.tool} is not allowed for {task.agent_type}")
            return False
        if task.opsec_risk not in VALID_OPSEC_RISKS:
            logger.warning(f"Rejecting task {task.id}: invalid opsec_risk {task.opsec_risk}")
            return False
        if not isinstance(task.params, dict):
            logger.warning(f"Rejecting task {task.id}: params must be an object")
            return False
        for dep_id in task.depends_on:
            if dep_id not in self.task_graph.tasks:
                logger.warning(f"Rejecting task {task.id}: unknown dependency {dep_id}")
                return False
        if not self._validate_task_params_and_scope(task):
            return False
        if not self.mission.active_scan_permitted:
            risk = self._tool_risk(task)
            is_passive = task.opsec_risk == "passive" and risk == "passive"
            if not is_passive:
                logger.warning(
                    f"Rejecting active task {task.id} while active scanning is disabled")
                return False
        return True

    def _tool_registry_for_validation(self) -> dict:
        if hasattr(self, "_tool_registry"):
            return self._tool_registry
        if hasattr(self, "tool_bus"):
            return self.tool_bus.tool_registry
        if hasattr(self, "executor"):
            return self.executor.tools_config.get("tools", {})
        self.executor = ToolExecutor()
        self._tool_registry = self.executor.tools_config.get("tools", {})
        return self._tool_registry

    def _tool_risk(self, task: Task) -> str | None:
        if task.tool in SYNTHETIC_PASSIVE_TOOLS:
            return "passive"
        tool_def = self._tool_registry_for_validation().get(
            TOOL_ALIASES.get(task.tool, task.tool))
        if not tool_def:
            return None
        risk = tool_def.get("opsec_risk")
        return risk if risk in VALID_OPSEC_RISKS else None

    def _validate_task_params_and_scope(self, task: Task) -> bool:
        if task.tool in SYNTHETIC_PASSIVE_TOOLS:
            return True
        canonical_tool = TOOL_ALIASES.get(task.tool, task.tool)
        tool_def = self._tool_registry_for_validation().get(canonical_tool)
        if not tool_def:
            logger.warning(f"Rejecting task {task.id}: unregistered tool {task.tool}")
            return False
        if tool_def.get("opsec_risk") not in VALID_OPSEC_RISKS:
            logger.warning(f"Rejecting task {task.id}: invalid tool risk for {task.tool}")
            return False
        if task.tool not in TOOL_ALIASES:
            try:
                self.executor._validate_params(task.tool, tool_def.get("allowed_params", {}),
                                               task.params, tool_def)
            except Exception as e:
                logger.warning(f"Rejecting task {task.id}: invalid params for {task.tool}: {e}")
                return False

        from reconforge.tools.scope import is_target_in_scope
        target_fields = tool_def.get("target_fields") or ["target", "domain", "url"]
        subjects = [
            task.params[field] for field in target_fields
            if isinstance(task.params.get(field), str) and task.params.get(field).strip()
        ]
        if not subjects:
            logger.warning(f"Rejecting task {task.id}: no scoped target field")
            return False
        for subject in subjects:
            allowed, denied = is_target_in_scope(
                subject, self.mission.scope, self.mission.out_of_scope)
            if denied:
                logger.warning(f"Rejecting task {task.id}: out-of-scope target {subject}")
                return False
            if allowed:
                return True
        logger.warning(f"Rejecting task {task.id}: target not in scope {subjects}")
        return False

    def _validated_tasks_from_llm(self, raw_tasks: list | dict) -> list[Task]:
        """Convert LLM JSON into Task objects only after local safety validation."""
        if isinstance(raw_tasks, dict):
            raw_tasks = [raw_tasks]
        if not isinstance(raw_tasks, list):
            raise ValueError("Planner response must be a JSON list")

        tasks: list[Task] = []
        seen_ids: set[str] = set()
        seen_fingerprints: set[str] = set()
        known_ids: set[str] = set(self.task_graph.tasks)

        for item in raw_tasks:
            if not isinstance(item, dict):
                logger.warning("Rejecting non-object task from planner")
                continue
            try:
                task = Task(**item)
            except Exception as e:
                logger.warning(f"Rejecting malformed task from planner: {e}")
                continue
            if task.id in seen_ids:
                logger.warning(f"Rejecting duplicate task id from planner: {task.id}")
                continue
            if any(dep_id not in known_ids and dep_id not in seen_ids
                   for dep_id in task.depends_on):
                logger.warning(f"Rejecting task {task.id}: unknown dependency in plan")
                continue
            fingerprint = self._task_fingerprint(task)
            if fingerprint in seen_fingerprints:
                logger.warning(f"Rejecting duplicate planner task: {task.id}")
                continue
            # Validate against the plan accumulated so far.
            original_tasks = self.task_graph.tasks
            try:
                temp_tasks = {**original_tasks, **{t.id: t for t in tasks}}
                self.task_graph.tasks = temp_tasks
                valid = self._validate_task(task)
            finally:
                self.task_graph.tasks = original_tasks
            if not valid:
                continue
            tasks.append(task)
            seen_ids.add(task.id)
            seen_fingerprints.add(fingerprint)
        return tasks

    # ── Task execution with self-correction ──────────────────

    async def _execute_task(self, task: Task) -> None:
        """Execute a single task with self-correction on failure."""
        self.task_graph.mark_running(task.id)
        logger.info(f"Executing task: {task.id} ({task.agent_type}/{task.tool})")

        try:
            agent = self.agents.get(task.agent_type)
            if not agent:
                logger.error(f"Unknown agent type: {task.agent_type}")
                self.task_graph.mark_failed(task.id, f"Unknown agent: {task.agent_type}")
                await self._enqueue_ready_tasks()
                return

            # Run agent
            results = await agent.run(task, self.memory, self.intel, self.mission)

            # Critic reviews every result before storing
            reviewed = await self._critic_review(results)
            reviewed = await self._post_process_reviewed_findings(reviewed)

            # Store approved and quarantined findings.
            self.intel.store(reviewed)
            self.task_graph.mark_complete(task.id)
            self.memory.update_from_result(reviewed)

            # Log findings to episodic memory and emit events
            from reconforge.intel.models import Subdomain, Host, WebPath
            for finding in reviewed:
                self.episodic.log_finding(
                    finding.id, type(finding).__name__,
                    finding.model_dump(mode="json"),
                    self.mission.mission_id,
                    finding.confidence, finding.verified)

                # Quarantined findings are retained but must not drive follow-on work.
                if not finding.verified:
                    continue
                
                # Emit events for Streaming DAG
                if isinstance(finding, Subdomain):
                    await self.event_bus.publish(Event(name="SubdomainFoundEvent", data={"subdomain": finding.domain}))
                elif isinstance(finding, Host) and finding.ip:
                    await self.event_bus.publish(Event(name="HostFoundEvent", data={"ip": finding.ip}))
                elif isinstance(finding, WebPath):
                    await self.event_bus.publish(Event(name="WebPathFoundEvent", data={"url": finding.url}))
                elif isinstance(finding, Vulnerability) and finding.severity == "info":
                    await self.event_bus.publish(Event(name="P4FindingEvent", data={"finding": finding.model_dump()}))
                
                # Dynamic Exploit Trigger for Bug Bounty Mode
                if self.mission.mode == MissionMode.BUG_BOUNTY and not self.mission.stage_gate_passed:
                    if (isinstance(finding, Vulnerability) and finding.severity in ["critical", "high"]) or \
                       isinstance(finding, SecretFinding):
                        logger.info(f"BUG BOUNTY TRIGGER: Found {type(finding).__name__} (High/Critical). Unlocking ExploitPlanner early.")
                        self.mission.stage_gate_passed = True
                        ExploitPlannerAgent.unlock()
                        # Prompt the orchestrator to generate an immediate exploit task
                        await self._trigger_immediate_exploit(finding)

            await self._enqueue_ready_tasks()

        except Exception as e:
            logger.error(f"Task {task.id} failed: {e}")

            # Self-correction: retry with adjusted parameters
            retry_count = self._task_retries.get(task.id, 0)
            if retry_count < MAX_TASK_RETRIES:
                corrected = await self._self_correct(task, str(e))
                if corrected:
                    self._task_retries[task.id] = retry_count + 1
                    logger.info(f"Self-correction: retrying {task.id} (attempt {retry_count + 2})")
                    safe_corrected = self._safe_corrected_task(task, corrected)
                    if safe_corrected and self._validate_task(safe_corrected):
                        self.task_graph.mark_pending(task.id)
                        task.params = safe_corrected.params
                        await self._enqueue_task(task)
                    else:
                        self.task_graph.mark_failed(task.id, "Invalid corrected task")
                        await self._enqueue_ready_tasks()
                    return

            self.task_graph.mark_failed(task.id, str(e))
            await self._enqueue_ready_tasks()

    async def _self_correct(self, task: Task, error: str) -> Optional[Task]:
        """Use Claude to analyze failure and suggest corrected task params."""
        try:
            available_tools = (
                "whois, crt_sh, theharvester, nmap, httpx, ffuf, nuclei, "
                "shodan, github_code_search, web_search")

            prompt = SELF_CORRECT_PROMPT.format(
                task_json=json.dumps(task.model_dump(), default=str, indent=2),
                error=error[:500],
                tools=available_tools)

            text = await self.router.call(
                task_type="self_correction",
                system="You are a penetration testing task corrector. Output ONLY valid JSON.",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024)
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()

            data = json.loads(text)

            # Check if Claude says to skip
            if data.get("skip"):
                logger.info(f"Self-correction: skipping {task.id} — {data.get('reason', '')}")
                return None

            # Return corrected task
            data.setdefault("id", task.id)
            data.setdefault("agent_type", task.agent_type)
            data.setdefault("depends_on", task.depends_on)
            return Task(**data)

        except Exception as e:
            logger.debug(f"Self-correction failed: {e}")
            return None

    def _safe_corrected_task(self, original: Task, corrected: Task) -> Optional[Task]:
        """Restrict self-correction to safe parameter-only changes."""
        immutable_fields = ("id", "agent_type", "tool", "opsec_risk", "depends_on")
        for field in immutable_fields:
            if getattr(corrected, field) != getattr(original, field):
                logger.warning(f"Rejecting correction for {original.id}: changed {field}")
                return None
        protected_params = {
            "target", "domain", "url", "host", "base_url", "endpoint",
            "request_url", "scan_target", "ip",
        }
        for key in protected_params:
            if corrected.params.get(key) != original.params.get(key):
                logger.warning(f"Rejecting correction for {original.id}: changed target field {key}")
                return None
        data = original.model_dump()
        data["params"] = corrected.params
        data["priority"] = original.priority
        return Task(**data)

    async def _trigger_immediate_exploit(self, finding: IntelBase) -> None:
        """Generate and enqueue an immediate exploit task based on a finding."""
        try:
            prompt = (
                f"We are in BUG BOUNTY mode. A high-severity finding was just discovered:\n"
                f"{json.dumps(finding.model_dump(), default=str)}\n\n"
                f"Generate a single Task (JSON object) for the 'exploit_planner' agent to "
                f"investigate and exploit this finding immediately. Set priority to 1."
            )
            text = await self.router.call(
                task_type="mission_planning",
                system=ORCHESTRATOR_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024)
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            
            data = json.loads(text)
            if isinstance(data, list) and len(data) > 0:
                data = data[0]
            
            tasks = self._validated_tasks_from_llm(data)
            if not tasks:
                logger.warning("Immediate exploit task rejected by validator")
                return
            if await self._add_dynamic_task(tasks[0]):
                logger.info(f"Enqueued immediate exploit task: {tasks[0].id}")
        except Exception as e:
            logger.error(f"Failed to trigger immediate exploit task: {e}")

    # ── Planning ─────────────────────────────────────────────

    async def _plan_mission(self) -> list[Task]:
        """Claude plans the full task graph for the current stage."""
        prompt = self._build_planning_prompt()
        try:
            text = await self.router.call(
                task_type="mission_planning",
                system=ORCHESTRATOR_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=4096)
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                text = text.rsplit("```", 1)[0].strip()
            tasks_data = json.loads(text)
            tasks = self._validated_tasks_from_llm(tasks_data)
            if not tasks:
                raise ValueError("Planner produced no valid tasks")
            logger.info(f"Plan created: {len(tasks)} tasks")
            return tasks
        except Exception as e:
            logger.warning(f"Planning failed: {e}, using default plan")
            return self._default_plan()

    def _build_planning_prompt(self) -> str:
        """Build the planning prompt with mission context."""
        # Include existing progress if resuming
        existing = self.memory.get("existing_surface")
        resume_ctx = self.memory.get("resume_context", "")

        prompt = (
            f"Plan a reconnaissance mission for target: {self.mission.target}\n"
            f"Scope: {json.dumps(self.mission.scope)}\n"
            f"Out of scope: {json.dumps(self.mission.out_of_scope)}\n"
            f"Active scanning permitted: {self.mission.active_scan_permitted}\n"
            f"Opsec mode: {self.mission.opsec_mode}\n"
            f"Mission mode: {self.mission.mode}\n"
            f"Current stage: {self.mission.current_stage}\n\n"
            f"Available passive tools: whois, crt_sh, theharvester, shodan, github_dork, web_search\n"
            f"Available active tools (if permitted): nmap, httpx, ffuf, nuclei, arjun, corsy, ssrfmap, jwt_tool, graphql-cop, playwright_script, trufflehog, ai_redteam (for prompt injection testing)\n\n"
        )

        if self.mission.mode == MissionMode.BUG_BOUNTY:
            prompt += (
                f"BUG BOUNTY OVERRIDE: Prioritize dev, staging, sandbox, and itservicedesk subdomains. "
                f"Aggressively seek out parameter discovery, CORS misconfigurations, and JavaScript secret scanning.\n\n"
            )

        if existing:
            prompt += (
                f"RESUMING: Previous recon already discovered:\n"
                f"{json.dumps(existing, indent=2, default=str)}\n"
                f"Only plan tasks for what's MISSING.\n\n")

        if resume_ctx:
            prompt += f"Previous context:\n{resume_ctx[:2000]}\n\n"

        prompt += (
            f"Generate a JSON task list. Each task needs: id, agent_type, tool, "
            f"params (with 'target' or 'domain'), depends_on, priority, opsec_risk.")

        return prompt

    def _default_plan(self) -> list[Task]:
        """Fallback plan when Claude planning fails.
        Selects passive or active plan based on mission config."""
        target = self.mission.target
        if self.mission.active_scan_permitted:
            logger.info("Using default ACTIVE recon plan")
            return TaskCoordinationGraph.build_default_active_plan(target)
        else:
            logger.info("Using default PASSIVE recon plan")
            return TaskCoordinationGraph.build_default_passive_plan(target)

    # ── Critic review ────────────────────────────────────────

    async def _critic_review(self, findings: list[IntelBase]) -> list[IntelBase]:
        """Run critic review on all findings in a single batch."""
        if not findings:
            return []
            
        approved = []
        try:
            reviews = await self.critic.review_batch(findings)
            for finding, review in reviews:
                if review.verdict == ReviewVerdict.APPROVE:
                    finding.verified = True
                    approved.append(finding)
                elif review.verdict == ReviewVerdict.IMPROVE and review.improved_finding:
                    finding_data = finding.model_dump()
                    finding_data.update(review.improved_finding)
                    finding_data["verified"] = True
                    improved = type(finding)(**finding_data)
                    approved.append(improved)
                elif review.verdict == ReviewVerdict.QUARANTINE:
                    logger.warning(f"Finding quarantined: {review.reason}")
                    finding_data = finding.model_dump()
                    if review.improved_finding:
                        finding_data.update(review.improved_finding)
                    finding_data["verified"] = False
                    approved.append(type(finding)(**finding_data))
                else:
                    logger.debug(f"Finding rejected: {review.reason}")
        except Exception as e:
            logger.warning(f"Critic batch review failed; no findings approved: {e}")
        return approved

    async def _post_process_reviewed_findings(
        self,
        findings: list[IntelBase],
    ) -> list[IntelBase]:
        processed = []
        for finding in findings:
            if not isinstance(finding, Vulnerability) or not finding.verified:
                processed.append(finding)
                continue

            vuln = finding
            enricher = getattr(self, "enricher", None)
            if enricher:
                try:
                    vuln = await enricher.enrich(vuln)
                except Exception as e:
                    logger.warning(f"CVE enrichment failed for {vuln.id}: {e}")

            scorer = getattr(self, "scorer", None)
            if scorer:
                try:
                    vuln = await scorer.score(vuln, {})
                except Exception as e:
                    logger.warning(f"Severity scoring failed for {vuln.id}: {e}")

            processed.append(vuln)
        return processed

    # ── Memory management ────────────────────────────────────

    async def _compress_memory(self) -> None:
        """Compress working memory when token budget exceeded."""
        context = self.memory.get_summary_for_compression()
        summary = await self.summarizer.summarize(context)
        self.memory.replace_with_summary(summary)
        self.episodic.store_summary(
            self.mission.mission_id, summary, self.memory.token_count())

    async def _evaluate_attack_paths(self) -> None:
        """Run AttackPathChainer on all current findings to deduce high-severity chains."""
        findings = []
        from reconforge.intel.models import OsintFinding, SecretFinding, WebPath
        for v in self.intel._read_all(Vulnerability, self.mission.mission_id):
            findings.append(v)
        for o in self.intel._read_all(OsintFinding, self.mission.mission_id):
            findings.append(o)
        for s in self.intel._read_all(SecretFinding, self.mission.mission_id):
            findings.append(s)
        for w in self.intel._read_all(WebPath, self.mission.mission_id):
            if w.interesting:
                findings.append(w)

        vuln = await self.chainer.evaluate_chain(findings, self.mission.mission_id)
        if vuln:
            self.intel.write(vuln)
            self.episodic.log_finding(
                vuln.id, "Vulnerability", vuln.model_dump(mode="json"),
                self.mission.mission_id, vuln.confidence, False)
            
            if self.mission.mode == MissionMode.BUG_BOUNTY and not self.mission.stage_gate_passed:
                logger.info("BUG BOUNTY TRIGGER: Chained attack path discovered! Unlocking ExploitPlanner.")
                self.mission.stage_gate_passed = True
                ExploitPlannerAgent.unlock()
                await self._trigger_immediate_exploit(vuln)

    def _refresh_http_inventory(self) -> None:
        """Passively derive HTTP/API inventory from already-stored URL findings."""
        try:
            from reconforge.intel.http_inventory import refresh_http_inventory_from_store

            stored = refresh_http_inventory_from_store(
                self.intel,
                self.mission.mission_id,
                source_agent="orchestrator",
                browser_events=self.memory.get("http_inventory_browser_events", []),
                openapi_specs=self.memory.get("http_inventory_openapi_specs", []),
                graphql_metadata=self.memory.get("http_inventory_graphql_metadata", []),
            )
            if stored:
                logger.info(f"HTTP inventory refreshed: {len(stored)} endpoints")
        except Exception as e:
            logger.warning(f"HTTP inventory refresh failed: {e}")

    def _operator_may_unlock_exploits(self, gate_result) -> bool:
        if self.mission.mode == MissionMode.BUG_BOUNTY:
            return True
        if not getattr(gate_result, "requires_operator_approval", True):
            return True
        return bool(self.mission.operator_approved)

    def _unlock_exploits_if_allowed(self, gate_result) -> bool:
        if not self._operator_may_unlock_exploits(gate_result):
            return False
        ExploitPlannerAgent.unlock()
        return True

    def cleanup(self) -> None:
        """Close database connections and ingest knowledge."""
        logger.info("Ingesting mission findings to Global Knowledge Base...")
        self.semantic.ingest_mission_findings(self.intel, self.mission.mission_id)
        self.episodic.close()
        self.intel.close()
