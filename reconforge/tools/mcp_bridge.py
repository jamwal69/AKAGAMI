"""
ReconForge MCP Bridge — Calls MCP-enabled tools via the Anthropic API.

Supports:
- Shodan MCP (host lookup, search, exploits, dns)
- GitHub MCP (code search / dorking)
- Web Search (Anthropic built-in tool for OSINT enrichment)

MCP tools are called through Claude's tool_use capability, meaning
Claude decides how to invoke the MCP tool and parses the response.
"""

import json
import os
from typing import Optional

from reconforge.llm.router import LLMRouter
from tenacity import retry, stop_after_attempt, wait_exponential

from reconforge.intel.models import RawResult, ToolResult
from reconforge.utils.logger import get_logger

logger = get_logger("mcp_bridge")

# MCP server configurations
MCP_SERVERS = {
    "shodan": {
        "type": "url",
        "url": "https://mcp.shodan.io/sse",
        "name": "shodan-mcp",
        "authorization_token": os.environ.get("SHODAN_API_KEY", ""),
    },
    "github": {
        "type": "url",
        "url": "https://api.githubcopilot.com/mcp/",
        "name": "github-mcp",
        "authorization_token": os.environ.get("GITHUB_TOKEN", ""),
    },
}

# Tool schemas for non-MCP API-based tools
SHODAN_TOOLS = [
    {
        "name": "shodan_host_lookup",
        "description": "Look up all services, banners, and metadata for a specific IP address using Shodan.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "shodan_search",
        "description": "Search Shodan for hosts matching a query (e.g., 'apache port:8080 country:US').",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Shodan search query"},
                "max_results": {"type": "integer", "description": "Max results", "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "shodan_exploits",
        "description": "Search Shodan's exploit database for CVEs or service names.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Exploit search query (CVE ID or service name)"},
            },
            "required": ["query"],
        },
    },
]

GITHUB_TOOLS = [
    {
        "name": "github_code_search",
        "description": "Search GitHub for code containing sensitive information about a target (API keys, passwords, config files).",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "GitHub code search query (e.g., 'org:target password')"},
                "max_results": {"type": "integer", "description": "Max results", "default": 10},
            },
            "required": ["query"],
        },
    },
]


class McpBridge:
    """
    MCP tool caller via Anthropic API.

    Supports two modes:
    1. Full MCP: Uses Anthropic's MCP server connectors (requires API support)
    2. API fallback: Direct HTTP API calls to Shodan/GitHub
    """

    def __init__(self, router: Optional[LLMRouter] = None, client=None) -> None:
        self.client = client
        self.stats = {"calls": 0, "mcp_calls": 0, "api_calls": 0, "failures": 0}

    # ── Main dispatcher ──────────────────────────────────────

    async def call(self, tool_name: str, params: dict) -> ToolResult:
        """
        Call an MCP or API tool. Routes to the appropriate backend.
        """
        self.stats["calls"] += 1

        if tool_name.startswith("shodan"):
            return await self._call_shodan(tool_name, params)
        elif tool_name.startswith("github"):
            return await self._call_github(tool_name, params)
        elif tool_name == "web_search":
            return await self._call_web_search(params)
        else:
            self.stats["failures"] += 1
            raise ValueError(f"Unknown MCP tool: {tool_name}")

    # ── Shodan ───────────────────────────────────────────────

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=2, max=15))
    async def _call_shodan(self, tool_name: str, params: dict) -> ToolResult:
        """Call Shodan via MCP or direct API."""
        api_key = os.environ.get("SHODAN_API_KEY", "")

        # Try MCP first if client supports it
        if self.client and api_key:
            try:
                return await self._call_via_mcp("shodan", tool_name, params)
            except Exception as e:
                logger.debug(f"MCP Shodan failed, trying API: {e}")

        # Fallback to direct Shodan API
        if api_key:
            return await self._shodan_api(tool_name, params, api_key)

        self.stats["failures"] += 1
        return ToolResult(
            tool=tool_name, params=params,
            raw="", clean="[No Shodan API key configured]",
            exit_code=1, error="SHODAN_API_KEY not set")

    async def _shodan_api(self, tool_name: str, params: dict,
                          api_key: str) -> ToolResult:
        """Direct Shodan REST API calls."""
        import urllib.request
        import urllib.parse

        self.stats["api_calls"] += 1
        base = "https://api.shodan.io"

        try:
            if tool_name in ("shodan_host_lookup", "shodan"):
                ip = params.get("ip", params.get("target", ""))
                url = f"{base}/shodan/host/{ip}?key={api_key}"
            elif tool_name == "shodan_search":
                query = urllib.parse.quote(params.get("query", ""))
                url = f"{base}/shodan/host/search?query={query}&key={api_key}"
            elif tool_name == "shodan_exploits":
                query = urllib.parse.quote(params.get("query", ""))
                url = f"{base}/api-ms/exploits/search?query={query}&key={api_key}"
            elif tool_name == "shodan_dns":
                domain = params.get("domain", params.get("target", ""))
                url = f"{base}/dns/domain/{domain}?key={api_key}"
            else:
                query = urllib.parse.quote(params.get("query", params.get("target", "")))
                url = f"{base}/shodan/host/search?query={query}&key={api_key}"

            req = urllib.request.Request(url, headers={
                "User-Agent": "ReconForge/1.0",
                "Accept": "application/json",
            })

            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8")

            logger.info(f"Shodan API: {tool_name} returned {len(data)} bytes")
            return ToolResult(
                tool=tool_name, params=params,
                raw=data, clean=data[:50000],
                exit_code=0, duration_ms=0)

        except Exception as e:
            logger.warning(f"Shodan API error: {e}")
            self.stats["failures"] += 1
            return ToolResult(
                tool=tool_name, params=params,
                raw="", clean=f"[Shodan API error: {e}]",
                exit_code=1, error=str(e))

    # ── GitHub ───────────────────────────────────────────────

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=2, max=15))
    async def _call_github(self, tool_name: str, params: dict) -> ToolResult:
        """Call GitHub code search via MCP or API."""
        token = os.environ.get("GITHUB_TOKEN", "")

        if self.client and token:
            try:
                return await self._call_via_mcp("github", tool_name, params)
            except Exception as e:
                logger.debug(f"MCP GitHub failed, trying API: {e}")

        if token:
            return await self._github_api(params, token)

        self.stats["failures"] += 1
        return ToolResult(
            tool=tool_name, params=params,
            raw="", clean="[No GitHub token configured]",
            exit_code=1, error="GITHUB_TOKEN not set")

    async def _github_api(self, params: dict, token: str) -> ToolResult:
        """Direct GitHub code search API."""
        import urllib.request
        import urllib.parse

        self.stats["api_calls"] += 1
        query = urllib.parse.quote(params.get("query", ""))
        max_results = params.get("max_results", 10)
        url = f"https://api.github.com/search/code?q={query}&per_page={max_results}"

        try:
            req = urllib.request.Request(url, headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "ReconForge/1.0",
            })

            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8")

            logger.info(f"GitHub API: code search returned {len(data)} bytes")
            return ToolResult(
                tool="github_code_search", params=params,
                raw=data, clean=data[:50000],
                exit_code=0, duration_ms=0)

        except Exception as e:
            logger.warning(f"GitHub API error: {e}")
            self.stats["failures"] += 1
            return ToolResult(
                tool="github_code_search", params=params,
                raw="", clean=f"[GitHub API error: {e}]",
                exit_code=1, error=str(e))

    # ── Web Search ───────────────────────────────────────────

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=1, max=10))
    async def _call_web_search(self, params: dict) -> ToolResult:
        """
        Use Anthropic's built-in web search tool for OSINT enrichment.
        This uses Claude's tool_use with the web_search_20250305 connector.
        """
        if not self.client:
            return ToolResult(
                tool="web_search", params=params,
                raw="", clean="[No Anthropic client for web search]",
                exit_code=1, error="No client")

        query = params.get("query", "")
        if not query:
            return ToolResult(
                tool="web_search", params=params,
                raw="", clean="[No query provided]",
                exit_code=1, error="No query")

        try:
            self.stats["mcp_calls"] += 1
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                tools=[{"type": "web_search_20250305", "name": "web_search",
                        "max_uses": 3}],
                messages=[{"role": "user", "content":
                    f"Search the web for: {query}\n\n"
                    f"Return the key findings as a structured summary. "
                    f"Focus on security-relevant information."}],
            )

            # Extract text from response
            text_parts = []
            for block in response.content:
                if hasattr(block, "text"):
                    text_parts.append(block.text)

            result_text = "\n".join(text_parts)
            logger.info(f"Web search for '{query[:50]}' returned {len(result_text)} chars")

            return ToolResult(
                tool="web_search", params=params,
                raw=result_text, clean=result_text[:50000],
                exit_code=0, duration_ms=0)

        except Exception as e:
            logger.warning(f"Web search failed: {e}")
            self.stats["failures"] += 1
            return ToolResult(
                tool="web_search", params=params,
                raw="", clean=f"[Web search error: {e}]",
                exit_code=1, error=str(e))

    # ── MCP server calls ─────────────────────────────────────

    async def _call_via_mcp(self, server_name: str, tool_name: str,
                            params: dict) -> ToolResult:
        """
        Call a tool via Anthropic's MCP server connector.
        Uses Claude's tool_use with MCP server configuration.
        """
        if not self.client:
            raise RuntimeError("No Anthropic client for MCP calls")

        server_config = MCP_SERVERS.get(server_name)
        if not server_config:
            raise ValueError(f"Unknown MCP server: {server_name}")

        self.stats["mcp_calls"] += 1

        # Build tool definitions based on server
        if server_name == "shodan":
            tools = SHODAN_TOOLS
        elif server_name == "github":
            tools = GITHUB_TOOLS
        else:
            tools = []

        prompt = (
            f"Use the {tool_name} tool with these parameters:\n"
            f"{json.dumps(params, indent=2)}\n\n"
            f"Return the raw results."
        )

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                tools=tools,
                messages=[{"role": "user", "content": prompt}],
            )

            # Process tool use blocks
            text_parts = []
            tool_results = []
            for block in response.content:
                if hasattr(block, "text"):
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_results.append({
                        "tool": block.name,
                        "input": block.input,
                    })

            result_text = "\n".join(text_parts)
            if tool_results:
                result_text += "\n" + json.dumps(tool_results, indent=2)

            return ToolResult(
                tool=tool_name, params=params,
                raw=result_text, clean=result_text[:50000],
                exit_code=0, duration_ms=0)

        except Exception as e:
            logger.warning(f"MCP call failed for {tool_name}: {e}")
            raise

    # ── Integration with ToolBus ─────────────────────────────

    def get_available_tools(self) -> list[str]:
        """List available MCP tools based on configured API keys."""
        available = []
        if os.environ.get("SHODAN_API_KEY"):
            available.extend(["shodan", "shodan_host_lookup", "shodan_search",
                              "shodan_exploits", "shodan_dns"])
        if os.environ.get("GITHUB_TOKEN"):
            available.extend(["github_code_search", "github_dork"])
        if self.client:
            available.append("web_search")
        return available

    def get_stats(self) -> dict:
        return self.stats.copy()
