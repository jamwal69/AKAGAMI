"""
ReconForge Logger — Structured logging with Rich.

Log levels:
- INFO:    task start/complete
- DEBUG:   tool calls, Claude prompts
- WARNING: low-confidence findings, retries
- ERROR:   scope violations, tool failures
"""

import logging
import os
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for ReconForge
RECONFORGE_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "agent": "bold magenta",
    "tool": "bold blue",
    "finding": "bold cyan",
})

console = Console(theme=RECONFORGE_THEME, no_color=bool(os.environ.get("NO_COLOR")))

# Global registry of loggers
_loggers: dict[str, logging.Logger] = {}
_global_level = logging.INFO


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get or create a structured logger for a ReconForge component.

    Args:
        name: Component name (e.g. 'osint_agent', 'tool_bus')
        level: Log level override (DEBUG/INFO/WARNING/ERROR)

    Returns:
        Configured logging.Logger with Rich handler
    """
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(f"reconforge.{name}")

    if level:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    else:
        logger.setLevel(_global_level)

    # Only add handler if none exist (prevent duplicate handlers)
    if not logger.handlers:
        handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    _loggers[name] = logger
    return logger


def set_global_level(level: str) -> None:
    """Set log level for all ReconForge loggers."""
    global _global_level
    log_level = getattr(logging, level.upper(), logging.INFO)
    _global_level = log_level
    for logger in _loggers.values():
        logger.setLevel(log_level)


def log_tool_call(logger: logging.Logger, tool: str, params: dict) -> None:
    """Structured log for a tool call."""
    logger.debug(f"[tool]TOOL_CALL[/tool] {tool} | params={params}")


def log_finding(logger: logging.Logger, finding_type: str,
                summary: str, confidence: float) -> None:
    """Structured log for a new finding."""
    conf_str = f"{confidence:.0%}"
    logger.info(
        f"[finding]FINDING[/finding] [{finding_type}] {summary} "
        f"(confidence: {conf_str})"
    )


def log_agent_start(logger: logging.Logger, agent: str, task_id: str) -> None:
    """Log agent task start."""
    logger.info(f"[agent]AGENT_START[/agent] {agent} → task {task_id}")


def log_agent_complete(logger: logging.Logger, agent: str,
                       task_id: str, findings_count: int) -> None:
    """Log agent task completion."""
    logger.info(
        f"[agent]AGENT_DONE[/agent] {agent} → task {task_id} "
        f"| {findings_count} findings"
    )


def log_scope_violation(logger: logging.Logger, target: str,
                        scope: list[str]) -> None:
    """Log a scope violation as ERROR."""
    logger.error(
        f"[error]SCOPE_VIOLATION[/error] Target '{target}' "
        f"not in scope {scope}"
    )


def log_security_event(logger: logging.Logger, event_type: str,
                       details: str) -> None:
    """Log a security event (e.g. prompt injection detected)."""
    logger.warning(
        f"[warning]SECURITY_EVENT[/warning] [{event_type}] {details}"
    )
