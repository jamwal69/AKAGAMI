"""
ReconForge Watcher — Program Monitor Daemon.
Polls public Bug Bounty scope lists (or local targets) and auto-triggers
Akagami in bug-bounty mode when a new target is discovered.
"""
import asyncio
import json
import os
import subprocess
from pathlib import Path

from reconforge.utils.logger import get_logger

logger = get_logger("watcher")


class ProgramWatcher:
    """Monitors scopes and launches missions."""

    def __init__(self, check_interval_seconds: int = 3600) -> None:
        self.check_interval = check_interval_seconds
        self.cache_file = Path(os.environ.get("HOME", "~")) / ".gemini" / "antigravity" / "watcher_cache.json"
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.known_targets = self._load_cache()

    def _load_cache(self) -> set[str]:
        if not self.cache_file.exists():
            return set()
        try:
            with open(self.cache_file, "r") as f:
                data = json.load(f)
                return set(data.get("known_targets", []))
        except Exception as e:
            logger.warning(f"Failed to load watcher cache: {e}")
            return set()

    def _save_cache(self) -> None:
        try:
            with open(self.cache_file, "w") as f:
                json.dump({"known_targets": list(self.known_targets)}, f)
        except Exception as e:
            logger.error(f"Failed to save watcher cache: {e}")

    async def _fetch_new_targets(self) -> list[str]:
        """
        Mock implementation. In production, this would poll:
        - raw.githubusercontent.com/arkadiyt/bounty-targets-data/...
        - HackerOne / Bugcrowd RSS feeds.
        """
        # For MVP, we check a local targets file if it exists
        mock_file = Path("new_targets.txt")
        targets = []
        if mock_file.exists():
            with open(mock_file, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
            mock_file.unlink() # consume the file
        return targets

    def _trigger_mission(self, target: str) -> None:
        """Launch Akagami CLI for the new target."""
        logger.info(f"Triggering bug-bounty mission for new target: {target}")
        
        # Determine company name from target (naive split)
        company = target.split(".")[-2] if "." in target else target
        
        cmd = [
            "python", "-m", "reconforge.cli", "recon",
            "-t", target,
            "-C", company,
            "--active",
            "--mode", "bug-bounty"
        ]
        
        try:
            # We launch this as a detached subprocess so watcher can keep polling
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"Mission launched successfully for {target}")
        except Exception as e:
            logger.error(f"Failed to launch mission for {target}: {e}")

    async def start(self) -> None:
        """Start the polling loop."""
        logger.info(f"Watcher started. Polling every {self.check_interval} seconds...")
        while True:
            try:
                new_targets = await self._fetch_new_targets()
                for target in new_targets:
                    if target not in self.known_targets:
                        logger.info(f"🚨 NEW TARGET DETECTED: {target} 🚨")
                        self.known_targets.add(target)
                        self._save_cache()
                        self._trigger_mission(target)
            except Exception as e:
                logger.error(f"Watcher polling error: {e}")
                
            await asyncio.sleep(self.check_interval)
