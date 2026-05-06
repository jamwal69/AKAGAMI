"""
ReconForge Tool Bus — Central dispatcher for all tool calls.
Single point of control: scope check, permission check, opsec, sanitize, log.
"""

from typing import Optional

from tenacity import retry, stop_after_attempt, wait_exponential

from reconforge.intel.models import (
    MissionState, OutOfScopeError, ToolResult, ToolExecutionError,
)
from reconforge.memory.episodic import EpisodicMemory
from reconforge.tools.executor import ToolExecutor
from reconforge.tools.mcp_bridge import McpBridge
from reconforge.tools.scope import is_target_in_scope
from reconforge.utils.logger import get_logger, log_scope_violation
from reconforge.utils.opsec import OpsecController
from reconforge.utils.sanitizer import OutputSanitizer

logger = get_logger("tool_bus")

# Tools called via MCP/API bridge instead of subprocess
MCP_TOOLS = {
    "shodan", "shodan_search", "shodan_exploits", "shodan_dns",
    "github", "github_code_search", "web_search",
}
VALID_OPSEC_RISKS = {"passive", "low", "medium", "high"}
DEFAULT_TARGET_FIELDS = (
    "target", "domain", "url", "host", "base_url", "endpoint",
    "request_url", "scan_target", "ip",
)

# Backwards-compatible exports; permission enforcement is registry-driven.
PASSIVE_TOOLS = set(MCP_TOOLS)
ACTIVE_TOOLS = set()


class ToolBus:
    """
    Central dispatcher for all tool calls.
    Nothing calls subprocess directly except through ToolBus.
    """

    def __init__(self, executor: ToolExecutor, episodic: EpisodicMemory,
                 sanitizer: Optional[OutputSanitizer] = None,
                 opsec: Optional[OpsecController] = None,
                 mcp_bridge: Optional[McpBridge] = None) -> None:
        self.executor = executor
        self.episodic = episodic
        self.sanitizer = sanitizer or OutputSanitizer()
        self.opsec = opsec or OpsecController()
        self.mcp_bridge = mcp_bridge
        self.tool_registry = self.executor.tools_config.get("tools", {})
        global PASSIVE_TOOLS, ACTIVE_TOOLS
        PASSIVE_TOOLS = {
            name for name, meta in self.tool_registry.items()
            if meta.get("opsec_risk") == "passive"
        } | MCP_TOOLS
        ACTIVE_TOOLS = {
            name for name, meta in self.tool_registry.items()
            if meta.get("opsec_risk") != "passive"
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=30),
           reraise=True)
    async def call(self, tool_name: str, params: dict,
                   mission: MissionState) -> ToolResult:
        """
        Execute a tool with full safety chain:
        1. Scope check
        2. Permission check
        3. Dedup check
        4. Opsec controls
        5. Execute
        6. Sanitize output
        7. Log to episodic memory
        """
        self.check_safety(tool_name, params, mission)

        # 3. Dedup check
        cached = self.episodic.dedup_check(tool_name, params, mission.mission_id)
        if cached:
            logger.info(f"Using cached result for {tool_name}")
            return ToolResult(tool=tool_name, params=params, raw="[CACHED]",
                              clean="[CACHED - see previous results]",
                              exit_code=0, duration_ms=0)

        # 4. Opsec controls
        exec_params = params.copy()
        if mission.opsec_mode:
            await self.opsec.delay()
            exec_params = self.opsec.apply_opsec_params(tool_name, exec_params)

        # 5. Execute — route MCP tools through bridge
        try:
            if tool_name in MCP_TOOLS and self.mcp_bridge:
                logger.info(f"Routing {tool_name} through MCP bridge")
                mcp_result = await self.mcp_bridge.call(tool_name, exec_params)
                clean = self.sanitizer.clean(mcp_result.raw)
                self.episodic.log_action(tool_name, params, clean,
                                         mission.mission_id,
                                         duration_ms=mcp_result.duration_ms)
                return ToolResult(
                    tool=tool_name, params=params, raw=mcp_result.raw,
                    clean=clean, exit_code=mcp_result.exit_code,
                    duration_ms=mcp_result.duration_ms,
                    error=mcp_result.error)
            if tool_name in MCP_TOOLS:
                raise ToolExecutionError(f"MCP bridge not configured for tool '{tool_name}'")

            raw = await self.executor.run(tool_name, exec_params)
        except ToolExecutionError as e:
            logger.error(f"Tool execution failed: {e}")
            self.episodic.log_action(tool_name, params, str(e),
                                     mission.mission_id, success=False)
            raise

        # 6. Sanitize output
        clean = self.sanitizer.clean(raw.stdout)

        # 7. Log to episodic memory
        self.episodic.log_action(tool_name, params, clean, mission.mission_id,
                                 duration_ms=raw.duration_ms)

        return ToolResult(tool=tool_name, params=params, raw=raw.stdout,
                          clean=clean, exit_code=raw.exit_code,
                          duration_ms=raw.duration_ms,
                          error=raw.stderr if raw.exit_code != 0 else None)

    def check_safety(self, tool_name: str, params: dict,
                     mission: MissionState) -> None:
        """Run the common permission and scope safety gates without executing."""
        self._assert_permitted(tool_name, mission)
        self._assert_in_scope(tool_name, params, mission)

    def _assert_in_scope(self, tool_name: str | dict, params: dict | MissionState,
                         mission: MissionState | None = None) -> None:
        """Verify target is in mission scope. Raises OutOfScopeError."""
        # Backwards compatibility for old tests/callers: _assert_in_scope(params, mission)
        if mission is None:
            mission = params  # type: ignore[assignment]
            params = tool_name  # type: ignore[assignment]
            tool_name = ""

        assert isinstance(params, dict)
        assert mission is not None

        targets = self._scope_subjects(str(tool_name), params)
        if not targets:
            raise OutOfScopeError(
                f"Tool '{tool_name}' has no scoped target field in params"
            )

        for target in targets:
            allowed, denied = is_target_in_scope(target, mission.scope, mission.out_of_scope)
            if denied:
                log_scope_violation(logger, target, mission.scope)
                raise OutOfScopeError(f"Target '{target}' is explicitly out of scope")
            if allowed:
                return

        log_scope_violation(logger, ", ".join(str(t) for t in targets), mission.scope)
        raise OutOfScopeError(f"Target(s) {targets} not in scope {mission.scope}")

    def _scope_subjects(self, tool_name: str, params: dict) -> list[str]:
        tool_def = self.tool_registry.get(tool_name, {})
        fields = tool_def.get("target_fields") or DEFAULT_TARGET_FIELDS
        targets = []
        for field in fields:
            value = params.get(field)
            if isinstance(value, str) and value.strip():
                targets.append(value)
        return targets

    def _assert_permitted(self, tool_name: str, mission: MissionState) -> None:
        """Check if tool type is permitted by mission config."""
        tool_def = self.tool_registry.get(tool_name)
        if not tool_def:
            raise PermissionError(f"Unknown tool '{tool_name}' is not permitted")
        risk = tool_def.get("opsec_risk")
        if risk not in VALID_OPSEC_RISKS:
            raise PermissionError(
                f"Tool '{tool_name}' has invalid or missing opsec_risk"
            )

        if risk != "passive" and not mission.active_scan_permitted:
            raise PermissionError(
                f"Active tool '{tool_name}' not permitted. "
                f"Set active_scan_permitted=True in mission config."
            )
