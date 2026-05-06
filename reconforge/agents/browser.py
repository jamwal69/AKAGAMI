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
from reconforge.memory.working import WorkingMemory
from reconforge.tools.bus import ToolBus
from reconforge.utils.logger import log_agent_start, log_agent_complete


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

                async def handle_request(request):
                    headers = request.headers
                    auth = headers.get("authorization", "")
                    if auth and auth.startswith("Bearer "):
                        token = auth.split(" ")[1]
                        if token not in jwt_tokens:
                            jwt_tokens.append(token)
                            auth_headers["Authorization"] = auth
                            self.logger.info("Captured JWT from XHR request")

                page.on("request", handle_request)

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

                session_ctx = SessionContext(
                    source_agent=self.name,
                    source_tool="playwright",
                    confidence=0.9,
                    mission_id=mission.mission_id,
                    host_id=target,
                    cookies=cookies,
                    local_storage=json.loads(local_storage) if local_storage else {},
                    session_storage=json.loads(session_storage) if session_storage else {},
                    jwt_tokens=jwt_tokens,
                    auth_headers=auth_headers,
                    username=username
                )
                findings.append(session_ctx)

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
        if not url.startswith("http"):
            url = f"https://{url}"
        self.tool_bus.check_safety(
            "browser", {"target": target, "url": url}, mission)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()

                jwt_tokens = []
                async def handle_request(request):
                    auth = request.headers.get("authorization", "")
                    if auth and auth.startswith("Bearer "):
                        jwt_tokens.append(auth.split(" ")[1])

                page.on("request", handle_request)
                await page.goto(url, wait_until="networkidle")

                cookies = await context.cookies()
                local_storage = await page.evaluate("() => JSON.stringify(localStorage)")

                session_ctx = SessionContext(
                    source_agent=self.name,
                    source_tool="playwright",
                    confidence=0.8,
                    mission_id=mission.mission_id,
                    host_id=target,
                    cookies=cookies,
                    local_storage=json.loads(local_storage) if local_storage else {},
                    jwt_tokens=jwt_tokens
                )
                findings.append(session_ctx)
                await browser.close()
        except (OutOfScopeError, PermissionError, ToolExecutionError):
            raise
        except Exception as e:
            self.logger.error(f"Session capture failed: {e}")

        return findings
