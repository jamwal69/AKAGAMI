"""
ReconForge Browser Agent — Handles authenticated flows and dynamic interaction.
Uses Playwright to capture tokens, cookies, and XHR intercepts.
"""

import json
from typing import Optional

from playwright.async_api import async_playwright
from reconforge.llm.router import LLMRouter

from reconforge.agents.base import BaseAgent
from reconforge.intel.models import (
    IntelBase, MissionState, Task, SessionContext,
    OutOfScopeError, ToolExecutionError,
)
from reconforge.intel.store import IntelStore
from reconforge.intel.http_inventory import (
    body_parameter_names,
    redact_url_for_inventory,
    sanitize_header_names,
)
from reconforge.memory.working import WorkingMemory
from reconforge.tools.bus import ToolBus
from reconforge.tools.scope import is_target_in_scope
from reconforge.utils.logger import log_agent_start, log_agent_complete

MAX_INVENTORY_EVENTS = 250


BROWSER_SYSTEM_PROMPT = """You are the Browser Automation specialist of ReconForge.
You execute login flows, intercept XHR requests, and capture authentication tokens.
You output structured SessionContext objects containing cookies, JWTs, and local storage.
"""

class BrowserAgent(BaseAgent):
    """Agent for headless browser automation and session capture."""

    def __init__(self, router: LLMRouter, tool_bus: ToolBus,
                 memory: WorkingMemory) -> None:
        super().__init__("browser_agent", router, tool_bus, memory)

    async def run(self, task: Task, memory: WorkingMemory,
                  intel: IntelStore, mission: MissionState) -> list[IntelBase]:
        """Execute browser automation task."""
        log_agent_start(self.logger, self.name, task.id)
        target = task.params.get("target", mission.target)

        findings: list[IntelBase] = []
        action = task.params.get("action", "login")

        if action == "login":
            findings.extend(await self._execute_login(target, task.params, mission))
        elif action == "capture":
            findings.extend(await self._capture_session(target, task.params, mission))
        else:
            self.logger.warning(f"Unknown browser action: {action}")

        log_agent_complete(self.logger, self.name, task.id, len(findings))
        return findings

    async def _execute_login(self, target: str, params: dict, mission: MissionState) -> list[IntelBase]:
        """Execute a login flow using Playwright to capture the session."""
        findings = []
        username = params.get("username", "testuser")
        password = params.get("password", "testpass")
        login_url = params.get("login_url", target)
        capture_inventory = self._browser_inventory_enabled(params)

        if not login_url.startswith("http"):
            login_url = f"https://{login_url}"

        self.logger.info(f"Executing login flow for {login_url}")
        self.tool_bus.check_safety(
            "browser", {"target": target, "login_url": login_url}, mission)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="ReconForge/1.0 (BugBountyMode)"
                )
                page = await context.new_page()

                # Intercept network requests to grab JWTs from headers
                auth_headers = {}
                jwt_tokens = []
                network_events: dict[str, dict] = {}

                def handle_request(request):
                    headers = request.headers
                    auth = headers.get("authorization", "")
                    if auth and auth.startswith("Bearer "):
                        token = auth.split(" ")[1]
                        if token not in jwt_tokens:
                            jwt_tokens.append(token)
                            auth_headers["Authorization"] = auth
                            self.logger.info("Captured JWT from XHR request")
                    if capture_inventory:
                        self._capture_inventory_request(
                            network_events, request, mission)

                def handle_response(response):
                    if capture_inventory:
                        self._capture_inventory_response(
                            network_events, response, mission)

                page.on("request", handle_request)
                page.on("response", handle_response)

                await page.goto(login_url, wait_until="networkidle")

                # Basic heuristic login (fill first text/email input, first password input)
                # In a real scenario, Claude could generate the exact selectors.
                inputs = await page.locator("input").all()
                user_filled = False
                pass_filled = False
                for i in inputs:
                    type_attr = await i.get_attribute("type")
                    if type_attr in ["text", "email"] and not user_filled:
                        await i.fill(username)
                        user_filled = True
                    elif type_attr == "password" and not pass_filled:
                        await i.fill(password)
                        pass_filled = True

                if user_filled and pass_filled:
                    submit_btns = await page.locator("button[type='submit'], input[type='submit']").all()
                    if submit_btns:
                        await submit_btns[0].click()
                        await page.wait_for_load_state("networkidle")
                    else:
                        await page.keyboard.press("Enter")
                        await page.wait_for_load_state("networkidle")

                # Extract state
                cookies = await context.cookies()
                local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
                session_storage = await page.evaluate("() => JSON.stringify(sessionStorage)")
                local_storage_data = json.loads(local_storage) if local_storage else {}
                session_storage_data = json.loads(session_storage) if session_storage else {}
                self._remember_runtime_auth_context(
                    self.memory,
                    mission,
                    target,
                    cookies,
                    local_storage_data,
                    session_storage_data,
                    jwt_tokens,
                    auth_headers,
                )

                session_ctx = SessionContext(
                    source_agent=self.name,
                    source_tool="playwright",
                    confidence=0.9,
                    mission_id=mission.mission_id,
                    host_id=target,
                    cookies=self._redacted_cookies(cookies),
                    local_storage=self._redacted_storage(local_storage_data),
                    session_storage=self._redacted_storage(session_storage_data),
                    jwt_tokens=[],
                    auth_headers=self._redacted_auth_headers(auth_headers),
                    username=username
                )
                findings.append(session_ctx)
                if capture_inventory:
                    self._remember_inventory_events(
                        self.memory, list(network_events.values()))

                await browser.close()
        except (OutOfScopeError, PermissionError, ToolExecutionError):
            raise
        except Exception as e:
            self.logger.error(f"Browser login execution failed: {e}")

        return findings

    async def _capture_session(self, target: str, params: dict, mission: MissionState) -> list[IntelBase]:
        """Capture session context without an explicit login flow."""
        # Similar logic as login, but just visiting a page and waiting for idle
        findings = []
        url = params.get("url", target)
        capture_inventory = self._browser_inventory_enabled(params)
        if not url.startswith("http"):
            url = f"https://{url}"
        self.tool_bus.check_safety(
            "browser", {"target": target, "url": url}, mission)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()

                auth_headers = {}
                jwt_tokens = []
                network_events: dict[str, dict] = {}

                def handle_request(request):
                    auth = request.headers.get("authorization", "")
                    if auth and auth.startswith("Bearer "):
                        token = auth.split(" ")[1]
                        if token not in jwt_tokens:
                            jwt_tokens.append(token)
                            auth_headers["Authorization"] = auth
                    if capture_inventory:
                        self._capture_inventory_request(
                            network_events, request, mission)

                def handle_response(response):
                    if capture_inventory:
                        self._capture_inventory_response(
                            network_events, response, mission)

                page.on("request", handle_request)
                page.on("response", handle_response)
                await page.goto(url, wait_until="networkidle")

                cookies = await context.cookies()
                local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
                local_storage_data = json.loads(local_storage) if local_storage else {}
                self._remember_runtime_auth_context(
                    self.memory,
                    mission,
                    target,
                    cookies,
                    local_storage_data,
                    {},
                    jwt_tokens,
                    auth_headers,
                )

                session_ctx = SessionContext(
                    source_agent=self.name,
                    source_tool="playwright",
                    confidence=0.8,
                    mission_id=mission.mission_id,
                    host_id=target,
                    cookies=self._redacted_cookies(cookies),
                    local_storage=self._redacted_storage(local_storage_data),
                    jwt_tokens=[]
                )
                findings.append(session_ctx)
                if capture_inventory:
                    self._remember_inventory_events(
                        self.memory, list(network_events.values()))
                await browser.close()
        except (OutOfScopeError, PermissionError, ToolExecutionError):
            raise
        except Exception as e:
            self.logger.error(f"Session capture failed: {e}")

        return findings

    def _capture_inventory_request(self, events: dict[str, dict],
                                   request, mission: MissionState) -> None:
        if not self._inventory_url_in_scope(request.url, mission):
            return
        event = self._sanitized_inventory_event(
            url=request.url,
            method=request.method,
            headers=request.headers,
            post_data=getattr(request, "post_data", None),
        )
        self._merge_inventory_event(events, event)

    def _capture_inventory_response(self, events: dict[str, dict],
                                    response, mission: MissionState) -> None:
        request = response.request
        if not self._inventory_url_in_scope(request.url, mission):
            return
        headers = response.headers
        event = self._sanitized_inventory_event(
            url=request.url,
            method=request.method,
            headers=request.headers,
            post_data=getattr(request, "post_data", None),
            status_code=response.status,
            content_type=headers.get("content-type", ""),
            response_size=self._safe_int(headers.get("content-length")),
        )
        self._merge_inventory_event(events, event)

    def _sanitized_inventory_event(
        self,
        *,
        url: str,
        method: str = "GET",
        headers=None,
        post_data=None,
        status_code: int | None = None,
        content_type: str = "",
        response_size: int | None = None,
    ) -> dict:
        header_names = (
            headers.keys() if isinstance(headers, dict) else headers or []
        )
        lowered = {str(name).strip().lower() for name in header_names}
        has_auth = bool(lowered & {
            "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
        })
        event = {
            "url": redact_url_for_inventory(url),
            "method": str(method or "GET").upper(),
            "headers": sanitize_header_names(header_names),
            "body_parameter_names": body_parameter_names(post_data),
            "auth_required": "authenticated" if has_auth else "unknown",
        }
        if status_code is not None:
            event["status_code"] = status_code
        if content_type:
            event["content_type"] = str(content_type).split(";", 1)[0].strip()
        if response_size is not None:
            event["response_size"] = response_size
        return event

    def _remember_inventory_events(self, memory: WorkingMemory,
                                   events: list[dict]) -> None:
        if not events:
            return
        existing = list(memory.get("http_inventory_browser_events", []))
        merged: dict[str, dict] = {}
        for event in [*existing, *events]:
            key = self._inventory_event_key(event)
            if key:
                merged[key] = event
        memory.set(
            "http_inventory_browser_events",
            list(merged.values())[-MAX_INVENTORY_EVENTS:],
        )

    def _merge_inventory_event(self, events: dict[str, dict], event: dict) -> None:
        key = self._inventory_event_key(event)
        if not key:
            return
        current = events.get(key, {})
        current.update({k: v for k, v in event.items() if v not in (None, "", [])})
        events[key] = current
        if len(events) > MAX_INVENTORY_EVENTS:
            oldest = next(iter(events))
            events.pop(oldest, None)

    def _inventory_event_key(self, event: dict) -> str:
        if not event.get("url"):
            return ""
        params = ",".join(event.get("body_parameter_names") or [])
        return f"{event.get('method', 'GET')}|{event['url']}|{params}"

    def _safe_int(self, value) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _browser_inventory_enabled(self, params: dict) -> bool:
        return bool(
            params.get("capture_http_inventory")
            or params.get("enable_http_inventory")
            or params.get("browser_inventory")
        )

    def _inventory_url_in_scope(self, url: str, mission: MissionState) -> bool:
        allowed, denied = is_target_in_scope(
            url,
            mission.scope if mission else [],
            mission.out_of_scope if mission else [],
        )
        return allowed and not denied

    def _redacted_cookies(self, cookies: list[dict]) -> list[dict]:
        safe_fields = {
            "name", "domain", "path", "expires", "httpOnly", "secure",
            "sameSite",
        }
        redacted = []
        for cookie in cookies or []:
            item = {
                key: value for key, value in cookie.items()
                if key in safe_fields
            }
            if cookie.get("value"):
                item["value"] = "[REDACTED]"
            redacted.append(item)
        return redacted

    def _redacted_storage(self, storage: dict) -> dict:
        return {
            str(key): "[REDACTED]" if value not in (None, "") else ""
            for key, value in (storage or {}).items()
        }

    def _redacted_auth_headers(self, headers: dict) -> dict:
        return {
            str(key): "[REDACTED]" if value else ""
            for key, value in (headers or {}).items()
        }

    def _remember_runtime_auth_context(
        self,
        memory: WorkingMemory,
        mission: MissionState,
        host_id: str,
        cookies: list[dict],
        local_storage: dict,
        session_storage: dict,
        jwt_tokens: list[str],
        auth_headers: dict,
    ) -> None:
        if not hasattr(memory, "set_sensitive"):
            return
        context = {
            "mission_id": mission.mission_id,
            "host_id": host_id,
            "cookies": cookies or [],
            "local_storage": local_storage or {},
            "session_storage": session_storage or {},
            "jwt_tokens": list(dict.fromkeys(jwt_tokens or [])),
            "auth_headers": {
                str(key): str(value)
                for key, value in (auth_headers or {}).items()
                if value
            },
        }
        if not (
            context["cookies"]
            or context["local_storage"]
            or context["session_storage"]
            or context["jwt_tokens"]
            or context["auth_headers"]
        ):
            return

        existing = [
            item for item in memory.get_sensitive("runtime_auth_contexts", [])
            if item.get("mission_id") != mission.mission_id
            or item.get("host_id") != host_id
        ]
        existing.append(context)
        memory.set_sensitive("runtime_auth_contexts", existing[-20:])
