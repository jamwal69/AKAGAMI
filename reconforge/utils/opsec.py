"""
ReconForge Opsec Controller — Controls operational security parameters.

Applied by ToolBus when mission.opsec_mode = True.
Manages timing, rate limits, user-agent rotation, and scan parameter overrides.
"""

import asyncio
import random
from typing import Optional

from reconforge.utils.logger import get_logger

logger = get_logger("opsec")


class OpsecController:
    """
    Controls all opsec parameters for the mission.
    Applied by ToolBus when mission.opsec_mode = True.
    """

    # Pool of realistic user agent strings for rotation
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "curl/7.88.1",
        "curl/8.4.0",
        "python-requests/2.31.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]

    # Rate limits per tool (requests per second) in opsec mode
    TOOL_RATE_LIMITS = {
        "nmap": 1,
        "masscan": 1,
        "httpx": 5,
        "ffuf": 10,
        "gobuster": 10,
        "nuclei": 2,
        "wpscan": 2,
    }

    def __init__(self, delay_min: float = 2.0, delay_max: float = 10.0,
                 custom_headers: dict[str, str] | None = None) -> None:
        self.delay_min = delay_min
        self.delay_max = delay_max
        self._last_ua_index = -1
        # Custom headers required by bug bounty programs (e.g. X-Comolho-Client)
        self.custom_headers: dict[str, str] = custom_headers or {}

    async def delay(self) -> None:
        """Random delay between 2–10 seconds in opsec mode."""
        wait_time = random.uniform(self.delay_min, self.delay_max)
        logger.debug(f"Opsec delay: {wait_time:.1f}s")
        await asyncio.sleep(wait_time)

    def rotate_user_agent(self) -> str:
        """Returns a random UA from the pool."""
        ua = random.choice(self.USER_AGENTS)
        logger.debug(f"UA rotation: {ua[:50]}...")
        return ua

    def get_nmap_timing(self, base_timing: int) -> int:
        """Returns T2 in opsec mode regardless of requested timing."""
        opsec_timing = min(base_timing, 2)
        if opsec_timing != base_timing:
            logger.info(
                f"Opsec override: nmap timing T{base_timing} → T{opsec_timing}"
            )
        return opsec_timing

    def get_rate_limit(self, tool: str) -> int:
        """Returns requests-per-second limit for given tool in opsec mode."""
        return self.TOOL_RATE_LIMITS.get(tool, 5)

    def apply_opsec_params(self, tool_name: str, params: dict) -> dict:
        """
        Apply opsec overrides to tool parameters.
        Returns modified params dict.
        """
        modified = params.copy()

        if tool_name == "nmap":
            if "timing" in modified:
                modified["timing"] = self.get_nmap_timing(modified["timing"])
            else:
                modified["timing"] = 2

        # Add rate limiting where supported
        if tool_name in ("httpx", "ffuf", "nuclei", "gobuster"):
            rate = self.get_rate_limit(tool_name)
            modified["rate_limit"] = rate

        # Rotate user agent for HTTP tools
        if tool_name in ("httpx", "ffuf", "nuclei", "wpscan", "gobuster"):
            modified["user_agent"] = self.rotate_user_agent()

        # Inject custom headers required by bug bounty programs
        if self.custom_headers and tool_name in ("httpx", "ffuf", "nuclei", "wpscan", "gobuster", "curl"):
            modified["custom_headers"] = self.custom_headers
            logger.debug(f"Injecting custom headers into {tool_name}: {list(self.custom_headers.keys())}")

        return modified

