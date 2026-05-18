"""
ReconForge Tool Executor — Subprocess wrapper with timeout, capture, and security.
NEVER uses shell=True. Always asyncio.create_subprocess_exec with argument list.
"""

import asyncio
import copy
import re
import shlex
import time
from pathlib import Path

import yaml

from reconforge.intel.models import RawResult, ToolTimeoutError, ToolExecutionError
from reconforge.utils.logger import get_logger, log_tool_call
from reconforge.utils.sanitizer import collect_sensitive_values, redact_sensitive_output

logger = get_logger("executor")

HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class ToolExecutor:
    """Wraps subprocess with timeout, capture, and structured result."""

    def __init__(self, tools_config_path: str = "config/tools.yaml") -> None:
        self.tools_config = self._load_tools_config(tools_config_path)

    def _load_tools_config(self, path: str) -> dict:
        config_path = Path(path)
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f) or {}
        logger.warning(f"Tools config not found at {path}, using defaults")
        return {}

    async def run(self, tool_name: str, params: dict,
                  timeout: int = 300,
                  audit_params: dict | None = None) -> RawResult:
        """
        Build command from tools.yaml + params, run via asyncio subprocess.
        Enforce timeout. Return structured RawResult.
        """
        cmd = self._build_command(tool_name, params)
        log_tool_call(logger, tool_name, audit_params if audit_params is not None else params)
        logger.debug(f"Executing {tool_name} with {len(cmd)} argv entries")

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                duration = int((time.monotonic() - start) * 1000)
                raise ToolTimeoutError(
                    f"{tool_name} exceeded timeout of {timeout}s"
                )

            duration = int((time.monotonic() - start) * 1000)
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            sensitive_values = collect_sensitive_values(params)
            safe_stdout = redact_sensitive_output(stdout, sensitive_values)
            safe_stderr = redact_sensitive_output(stderr, sensitive_values)

            if proc.returncode != 0:
                logger.warning(
                    f"{tool_name} exited with code {proc.returncode}: "
                    f"{safe_stderr[:200]}"
                )

            return RawResult(
                stdout=safe_stdout, stderr=safe_stderr,
                exit_code=proc.returncode or 0, duration_ms=duration,
            )
        except FileNotFoundError:
            duration = int((time.monotonic() - start) * 1000)
            raise ToolExecutionError(f"Tool binary not found: {cmd[0]}")
        except ToolTimeoutError:
            raise
        except Exception as e:
            duration = int((time.monotonic() - start) * 1000)
            raise ToolExecutionError(f"Failed to execute {tool_name}: {e}")

    def _build_command(self, tool_name: str, params: dict) -> list[str]:
        """
        Build argument list from tool definition + params.
        NEVER uses shell=True or string concatenation. Security boundary.
        """
        tools = self.tools_config.get("tools", {})
        tool_def = tools.get(tool_name)
        if not tool_def:
            raise ToolExecutionError(f"Unknown tool '{tool_name}'")
        if "binary" not in tool_def:
            raise ToolExecutionError(f"Tool '{tool_name}' is missing binary")
        return self._build_from_definition(tool_name, tool_def, params)

    def _build_from_definition(self, tool_name: str, tool_def: dict,
                               params: dict) -> list[str]:
        """Build command from tools.yaml definition using a strict schema."""
        template = tool_def.get("command_template")
        if not template:
            raise ToolExecutionError(f"Tool '{tool_name}' is missing command_template")

        allowed = tool_def.get("allowed_params", {})
        values = self._validate_params(tool_name, allowed, params, tool_def)

        try:
            tokens = shlex.split(template)
        except ValueError as e:
            raise ToolExecutionError(f"Invalid template for '{tool_name}': {e}")

        cmd: list[str] = []
        for token in tokens:
            placeholders = re.findall(r"{([A-Za-z_][A-Za-z0-9_]*)}", token)
            if not placeholders:
                cmd.append(token)
                continue

            if len(placeholders) == 1 and token == f"{{{placeholders[0]}}}":
                value = values[placeholders[0]]
                if isinstance(value, list):
                    cmd.extend(str(item) for item in value)
                elif isinstance(value, bool):
                    if value:
                        cmd.append(str(value))
                elif value not in (None, ""):
                    cmd.append(str(value))
                continue

            rendered = token
            for key in placeholders:
                value = values[key]
                if isinstance(value, list):
                    raise ToolExecutionError(
                        f"List parameter '{key}' must occupy a whole template token"
                    )
                rendered = rendered.replace(f"{{{key}}}", str(value))
            if rendered:
                cmd.append(rendered)

        if not cmd or cmd[0] != tool_def["binary"]:
            raise ToolExecutionError(
                f"Template for '{tool_name}' must start with configured binary"
            )
        return cmd

    def _validate_params(self, tool_name: str, allowed: dict, params: dict,
                         tool_def: dict) -> dict:
        unknown = set(params) - set(allowed)
        if unknown and not tool_def.get("allow_extra_params", False):
            raise ToolExecutionError(
                f"Unknown parameter(s) for '{tool_name}': {', '.join(sorted(unknown))}"
            )

        values = {}
        for key, config in allowed.items():
            if key in params:
                value = params[key]
            elif "default" in config:
                value = copy.deepcopy(config["default"])
            elif config.get("required"):
                raise ToolExecutionError(
                    f"Missing required parameter '{key}' for '{tool_name}'"
                )
            else:
                continue

            values[key] = self._validate_value(
                tool_name, key, value, config, tool_def)
        if "url" in allowed and not values.get("url") and values.get("target"):
            target = values["target"]
            values["url"] = target if str(target).startswith("http") else f"http://{target}"
        return values

    def _validate_value(self, tool_name: str, key: str, value, config: dict,
                        tool_def: dict):
        expected = config.get("type", "string")

        if key == "args" and not tool_def.get("allow_raw_args", False):
            raise ToolExecutionError(
                f"Raw args are not allowed for '{tool_name}'"
            )

        if expected == "string":
            if not isinstance(value, str):
                raise ToolExecutionError(f"Parameter '{key}' for '{tool_name}' must be a string")
            self._reject_nul(tool_name, key, value)
        elif expected == "int":
            if isinstance(value, bool):
                raise ToolExecutionError(f"Parameter '{key}' for '{tool_name}' must be an int")
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ToolExecutionError(f"Parameter '{key}' for '{tool_name}' must be an int")
        elif expected == "bool":
            if not isinstance(value, bool):
                raise ToolExecutionError(f"Parameter '{key}' for '{tool_name}' must be a bool")
        elif expected == "list":
            if not isinstance(value, list):
                raise ToolExecutionError(f"Parameter '{key}' for '{tool_name}' must be a list")
            for item in value:
                self._reject_nul(tool_name, key, item)
            choices = config.get("choices")
            if choices:
                invalid = [item for item in value if item not in choices]
                if invalid:
                    raise ToolExecutionError(
                        f"Parameter '{key}' for '{tool_name}' contains unsupported list item(s): "
                        f"{', '.join(str(item) for item in invalid)}"
                    )
        elif expected == "headers":
            return self._validate_headers(tool_name, key, value)
        elif expected == "rate_limit":
            return self._validate_rate_limit(tool_name, key, value)
        elif expected == "flag_string":
            return self._validate_flag_string(tool_name, key, value, config)
        else:
            raise ToolExecutionError(
                f"Unsupported parameter type '{expected}' for '{tool_name}.{key}'"
            )

        choices = config.get("choices")
        if choices and expected != "list" and value not in choices:
            raise ToolExecutionError(
                f"Parameter '{key}' for '{tool_name}' must be one of {choices}"
            )
        return value

    def _reject_nul(self, tool_name: str, key: str, value) -> None:
        if "\x00" in str(value):
            raise ToolExecutionError(
                f"Parameter '{key}' for '{tool_name}' contains a NUL byte"
            )

    def _reject_crlf(self, tool_name: str, key: str, value) -> None:
        text = str(value)
        if "\r" in text or "\n" in text:
            raise ToolExecutionError(
                f"Parameter '{key}' for '{tool_name}' contains CRLF"
            )

    def _validate_headers(self, tool_name: str, key: str, value) -> list[str]:
        if not isinstance(value, dict):
            raise ToolExecutionError(
                f"Parameter '{key}' for '{tool_name}' must be a header map"
            )

        args: list[str] = []
        for raw_name, raw_value in value.items():
            name = str(raw_name)
            header_value = str(raw_value)
            self._reject_nul(tool_name, key, name)
            self._reject_nul(tool_name, key, header_value)
            self._reject_crlf(tool_name, key, name)
            self._reject_crlf(tool_name, key, header_value)
            if not name or not HEADER_NAME_RE.fullmatch(name):
                raise ToolExecutionError(
                    f"Invalid header name for '{tool_name}': {name!r}"
                )
            args.extend(["-H", f"{name}: {header_value}"])
        return args

    def _validate_rate_limit(self, tool_name: str, key: str, value) -> list[str]:
        if isinstance(value, bool):
            raise ToolExecutionError(f"Parameter '{key}' for '{tool_name}' must be an int")
        try:
            rate = int(value)
        except (TypeError, ValueError):
            raise ToolExecutionError(f"Parameter '{key}' for '{tool_name}' must be an int")
        if rate < 0:
            raise ToolExecutionError(
                f"Parameter '{key}' for '{tool_name}' must be non-negative"
            )
        return ["-rl", str(rate)] if rate > 0 else []

    def _validate_flag_string(self, tool_name: str, key: str, value,
                              config: dict) -> list[str]:
        if not isinstance(value, str):
            raise ToolExecutionError(f"Parameter '{key}' for '{tool_name}' must be a string")
        self._reject_nul(tool_name, key, value)
        self._reject_crlf(tool_name, key, value)
        if not value:
            return []
        if value.startswith("-"):
            raise ToolExecutionError(
                f"Parameter '{key}' for '{tool_name}' must not start with '-'"
            )
        flag = config.get("flag")
        if not flag:
            raise ToolExecutionError(
                f"Parameter '{key}' for '{tool_name}' is missing flag metadata"
            )
        return [str(flag), value]
