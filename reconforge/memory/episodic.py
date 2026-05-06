"""
ReconForge Episodic Memory — SQLite-backed action and finding log.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reconforge.utils.logger import get_logger

logger = get_logger("episodic_memory")

_EPISODIC_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY, target TEXT NOT NULL,
    started_at TEXT NOT NULL, completed_at TEXT,
    stage TEXT DEFAULT 'recon', config_json TEXT
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL,
    timestamp TEXT NOT NULL, agent TEXT, tool TEXT, params_json TEXT,
    output_hash TEXT, duration_ms INTEGER, success INTEGER DEFAULT 1,
    FOREIGN KEY (mission_id) REFERENCES missions(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, mission_id TEXT NOT NULL,
    timestamp TEXT NOT NULL, type TEXT NOT NULL,
    data_json TEXT, confidence REAL, verified INTEGER DEFAULT 0,
    FOREIGN KEY (mission_id) REFERENCES missions(id)
);
CREATE TABLE IF NOT EXISTS summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL,
    timestamp TEXT NOT NULL, content TEXT NOT NULL, token_count INTEGER,
    FOREIGN KEY (mission_id) REFERENCES missions(id)
);
CREATE INDEX IF NOT EXISTS idx_actions_mission ON actions(mission_id);
CREATE INDEX IF NOT EXISTS idx_findings_mission ON findings(mission_id);
"""


class EpisodicMemory:
    """SQLite-backed permanent audit trail. Never delete entries."""

    def __init__(self, db_path: str = "output/missions.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_EPISODIC_TABLES_SQL)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def create_mission(self, mission_id: str, target: str, config: Optional[dict] = None) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO missions (id, target, started_at, config_json) VALUES (?, ?, ?, ?)",
            (mission_id, target, datetime.now(timezone.utc).isoformat(), json.dumps(config) if config else None))
        self.conn.commit()
        logger.info(f"Mission created: {mission_id} → {target}")

    def complete_mission(self, mission_id: str) -> None:
        self.conn.execute("UPDATE missions SET completed_at = ? WHERE id = ?",
                          (datetime.now(timezone.utc).isoformat(), mission_id))
        self.conn.commit()

    def get_mission(self, mission_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM missions WHERE id = ?", (mission_id,)).fetchone()
        return dict(row) if row else None

    def log_action(self, tool: str, params: dict, output: str, mission_id: str,
                   agent: str = "", duration_ms: int = 0, success: bool = True) -> None:
        output_hash = hashlib.sha256(output.encode()).hexdigest()[:16]
        self.conn.execute(
            "INSERT INTO actions (mission_id, timestamp, agent, tool, params_json, output_hash, duration_ms, success) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (mission_id, datetime.now(timezone.utc).isoformat(), agent, tool,
             json.dumps(params), output_hash, duration_ms, int(success)))
        self.conn.commit()

    def dedup_check(self, tool: str, params: dict, mission_id: str) -> Optional[str]:
        params_json = json.dumps(params, sort_keys=True)
        row = self.conn.execute(
            "SELECT output_hash FROM actions WHERE tool = ? AND params_json = ? AND mission_id = ? AND success = 1 "
            "ORDER BY timestamp DESC LIMIT 1", (tool, params_json, mission_id)).fetchone()
        if row:
            logger.info(f"Dedup hit: {tool} already executed with same params")
            return row["output_hash"]
        return None

    def get_recent_actions(self, mission_id: str, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM actions WHERE mission_id = ? ORDER BY timestamp DESC LIMIT ?",
            (mission_id, limit)).fetchall()
        return [dict(row) for row in rows]

    def log_finding(self, finding_id: str, finding_type: str, data: dict,
                    mission_id: str, confidence: float = 0.0, verified: bool = False) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (id, mission_id, timestamp, type, data_json, confidence, verified) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (finding_id, mission_id, datetime.now(timezone.utc).isoformat(),
             finding_type, json.dumps(data), confidence, int(verified)))
        self.conn.commit()

    def store_summary(self, mission_id: str, content: str, token_count: int = 0) -> None:
        self.conn.execute(
            "INSERT INTO summaries (mission_id, timestamp, content, token_count) VALUES (?, ?, ?, ?)",
            (mission_id, datetime.now(timezone.utc).isoformat(), content, token_count))
        self.conn.commit()

    def get_latest_summary(self, mission_id: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT content FROM summaries WHERE mission_id = ? ORDER BY timestamp DESC LIMIT 1",
            (mission_id,)).fetchone()
        return row["content"] if row else None

    def get_resume_context(self, mission_id: str) -> dict:
        return {
            "mission": self.get_mission(mission_id),
            "latest_summary": self.get_latest_summary(mission_id),
            "recent_actions": self.get_recent_actions(mission_id, limit=10),
        }

    def get_mission_stats(self, mission_id: str) -> dict:
        ac = self.conn.execute("SELECT COUNT(*) as cnt FROM actions WHERE mission_id = ?", (mission_id,)).fetchone()["cnt"]
        fc = self.conn.execute("SELECT COUNT(*) as cnt FROM findings WHERE mission_id = ?", (mission_id,)).fetchone()["cnt"]
        tools = self.conn.execute("SELECT DISTINCT tool FROM actions WHERE mission_id = ?", (mission_id,)).fetchall()
        return {"total_actions": ac, "total_findings": fc, "tools_used": [r["tool"] for r in tools]}
