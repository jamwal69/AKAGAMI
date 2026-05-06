"""
ReconForge Intel Store — Central structured database for all findings.

Single source of truth for everything discovered during a mission.
Backed by SQLite with tables for each intel type.
"""

import json
import sqlite3
from pathlib import Path
from typing import Optional, Type

from reconforge.intel.models import (
    Credential,
    Host,
    IntelBase,
    OsintFinding,
    Port,
    Subdomain,
    Vulnerability,
    WebPath,
)
from reconforge.utils.logger import get_logger, log_finding

logger = get_logger("intel_store")

# Mapping of intel type name to model class
INTEL_TYPES: dict[str, Type[IntelBase]] = {
    "host": Host,
    "port": Port,
    "subdomain": Subdomain,
    "vulnerability": Vulnerability,
    "credential": Credential,
    "web_path": WebPath,
    "osint_finding": OsintFinding,
}

# SQL table definitions
_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    ip TEXT NOT NULL,
    hostname TEXT,
    os_guess TEXT,
    os_confidence REAL,
    tags TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    host_id TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    state TEXT DEFAULT 'open',
    service TEXT,
    version TEXT,
    banner TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS subdomains (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    domain TEXT NOT NULL,
    ip TEXT,
    cname TEXT,
    http_status INTEGER,
    http_title TEXT,
    technologies TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    host_id TEXT NOT NULL,
    port_id TEXT,
    cve_id TEXT,
    cvss_score REAL,
    severity TEXT DEFAULT 'info',
    title TEXT,
    description TEXT,
    evidence TEXT,
    remediation TEXT,
    exploit_available INTEGER DEFAULT 0,
    exploit_reference TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    host_id TEXT,
    service TEXT,
    username TEXT,
    password TEXT,
    hash TEXT,
    source TEXT
);

CREATE TABLE IF NOT EXISTS web_paths (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    host_id TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    content_type TEXT,
    interesting INTEGER DEFAULT 0,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS osint_findings (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    category TEXT,
    value TEXT,
    context TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_mission ON hosts(mission_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_mission ON subdomains(mission_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_osint_category ON osint_findings(category);
"""


class IntelStore:
    """
    Aggregates all findings from all agents into one queryable store.
    Backed by SQLite.
    """

    def __init__(self, db_path: str = "output/missions.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self) -> None:
        """Create all tables if they don't exist."""
        self.conn.executescript(_TABLES_SQL)
        self.conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()

    # ── Write Operations ─────────────────────────────────────

    def write(self, finding: IntelBase) -> str:
        """
        Validate, dedup, and store a finding.
        Returns the finding ID.
        """
        table = self._get_table_name(finding)
        data = self._finding_to_row(finding)

        # Dedup check: same type + same key fields = skip
        if self._is_duplicate(finding, table):
            logger.debug(f"Duplicate finding skipped: {finding.id}")
            return finding.id

        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?" for _ in data])
        sql = f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({placeholders})"

        self.conn.execute(sql, list(data.values()))
        self.conn.commit()

        # Log the finding
        summary = self._get_finding_summary(finding)
        log_finding(logger, type(finding).__name__, summary, finding.confidence)

        return finding.id

    def store(self, findings: list[IntelBase]) -> list[str]:
        """Store multiple findings. Returns list of IDs."""
        ids = []
        for finding in findings:
            try:
                fid = self.write(finding)
                ids.append(fid)
            except Exception as e:
                logger.error(f"Failed to store finding: {e}")
        return ids

    # ── Read Operations ──────────────────────────────────────

    def query(self, intel_type: str, mission_id: Optional[str] = None,
              **filters) -> list[dict]:
        """
        Flexible query interface.

        Args:
            intel_type: One of 'host', 'port', 'subdomain', etc.
            mission_id: Filter by mission
            **filters: Additional column=value filters
        """
        table = self._type_to_table(intel_type)
        conditions = []
        params = []

        if mission_id:
            conditions.append("mission_id = ?")
            params.append(mission_id)

        for col, val in filters.items():
            conditions.append(f"{col} = ?")
            params.append(val)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        sql = f"SELECT * FROM {table}{where}"

        rows = self.conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def hosts(self, mission_id: Optional[str] = None,
              **filters) -> list[dict]:
        return self.query("host", mission_id, **filters)

    def ports(self, mission_id: Optional[str] = None,
              **filters) -> list[dict]:
        return self.query("port", mission_id, **filters)

    def subdomains(self, mission_id: Optional[str] = None,
                   **filters) -> list[dict]:
        return self.query("subdomain", mission_id, **filters)

    def vulnerabilities(self, mission_id: Optional[str] = None,
                        **filters) -> list[dict]:
        return self.query("vulnerability", mission_id, **filters)

    def credentials(self, mission_id: Optional[str] = None,
                    **filters) -> list[dict]:
        return self.query("credential", mission_id, **filters)

    def web_paths(self, mission_id: Optional[str] = None,
                  **filters) -> list[dict]:
        return self.query("web_path", mission_id, **filters)

    def osint_findings(self, mission_id: Optional[str] = None,
                       **filters) -> list[dict]:
        return self.query("osint_finding", mission_id, **filters)

    # ── Analytics ────────────────────────────────────────────

    def get_attack_surface_summary(self,
                                   mission_id: Optional[str] = None) -> dict:
        """Returns concise attack surface metrics for stage gate."""
        return {
            "hosts_discovered": len(self.hosts(mission_id)),
            "open_ports": len(self.ports(mission_id, state="open")),
            "subdomains": len(self.subdomains(mission_id)),
            "vulnerabilities_by_severity": self._vuln_counts_by_severity(
                mission_id
            ),
            "credentials_found": len(self.credentials(mission_id)),
            "interesting_paths": len(
                self.web_paths(mission_id, interesting=1)
            ),
            "osint_findings": len(self.osint_findings(mission_id)),
            "missing_coverage": self._identify_gaps(mission_id),
        }

    def export_json(self, mission_id: Optional[str] = None) -> dict:
        """Full export for report generator."""
        return {
            "hosts": self.hosts(mission_id),
            "ports": self.ports(mission_id),
            "subdomains": self.subdomains(mission_id),
            "vulnerabilities": self.vulnerabilities(mission_id),
            "credentials": self.credentials(mission_id),
            "web_paths": self.web_paths(mission_id),
            "osint_findings": self.osint_findings(mission_id),
        }

    # ── Internal helpers ─────────────────────────────────────

    def _get_table_name(self, finding: IntelBase) -> str:
        """Map finding type to table name."""
        type_map = {
            Host: "hosts",
            Port: "ports",
            Subdomain: "subdomains",
            Vulnerability: "vulnerabilities",
            Credential: "credentials",
            WebPath: "web_paths",
            OsintFinding: "osint_findings",
        }
        return type_map.get(type(finding), "osint_findings")

    def _type_to_table(self, intel_type: str) -> str:
        """Map type string to table name."""
        table_map = {
            "host": "hosts",
            "port": "ports",
            "subdomain": "subdomains",
            "vulnerability": "vulnerabilities",
            "credential": "credentials",
            "web_path": "web_paths",
            "osint_finding": "osint_findings",
        }
        return table_map.get(intel_type, intel_type)

    def _finding_to_row(self, finding: IntelBase) -> dict:
        """Convert a Pydantic model to a flat dict for SQLite."""
        data = finding.model_dump()
        # Convert complex types to JSON strings
        for key, val in data.items():
            if isinstance(val, (list, dict)):
                data[key] = json.dumps(val)
            elif isinstance(val, bool):
                data[key] = int(val)
            elif hasattr(val, 'isoformat'):
                data[key] = val.isoformat()
        return data

    def _is_duplicate(self, finding: IntelBase, table: str) -> bool:
        """Check if an equivalent finding already exists."""
        # Dedup by unique key fields per type
        if isinstance(finding, Host):
            sql = f"SELECT id FROM {table} WHERE ip = ? AND mission_id = ?"
            row = self.conn.execute(
                sql, (finding.ip, finding.mission_id)
            ).fetchone()
        elif isinstance(finding, Port):
            sql = (
                f"SELECT id FROM {table} WHERE host_id = ? AND port = ? "
                f"AND protocol = ? AND mission_id = ?"
            )
            row = self.conn.execute(
                sql,
                (finding.host_id, finding.port, finding.protocol,
                 finding.mission_id),
            ).fetchone()
        elif isinstance(finding, Subdomain):
            sql = f"SELECT id FROM {table} WHERE domain = ? AND mission_id = ?"
            row = self.conn.execute(
                sql, (finding.domain, finding.mission_id)
            ).fetchone()
        elif isinstance(finding, OsintFinding):
            sql = (
                f"SELECT id FROM {table} WHERE category = ? AND value = ? "
                f"AND mission_id = ?"
            )
            row = self.conn.execute(
                sql,
                (finding.category, finding.value, finding.mission_id),
            ).fetchone()
        else:
            return False  # No dedup for other types

        return row is not None

    def _vuln_counts_by_severity(self,
                                 mission_id: Optional[str] = None) -> dict:
        """Count vulnerabilities grouped by severity."""
        where = " WHERE mission_id = ?" if mission_id else ""
        params = [mission_id] if mission_id else []
        sql = (
            f"SELECT severity, COUNT(*) as cnt "
            f"FROM vulnerabilities{where} GROUP BY severity"
        )
        rows = self.conn.execute(sql, params).fetchall()
        return {row["severity"]: row["cnt"] for row in rows}

    def _identify_gaps(self, mission_id: Optional[str] = None) -> list[str]:
        """Identify what hasn't been scanned/checked yet."""
        gaps = []
        summary = self.export_json(mission_id)

        if not summary["hosts"]:
            gaps.append("No hosts discovered")
        if not summary["ports"]:
            gaps.append("No port scans performed")
        if not summary["subdomains"]:
            gaps.append("No subdomain enumeration")
        if not summary["vulnerabilities"]:
            gaps.append("No vulnerability scanning")
        if not summary["osint_findings"]:
            gaps.append("No OSINT gathering")

        # Check OSINT category coverage
        if summary["osint_findings"]:
            categories = {f["category"] for f in summary["osint_findings"]}
            required = {"whois", "cert", "dns"}
            missing = required - categories
            for cat in missing:
                gaps.append(f"Missing OSINT category: {cat}")

        return gaps

    def _get_finding_summary(self, finding: IntelBase) -> str:
        """Generate a brief summary string for logging."""
        if isinstance(finding, Host):
            return f"{finding.ip} ({finding.hostname or 'no hostname'})"
        elif isinstance(finding, Port):
            return f"port {finding.port}/{finding.protocol} ({finding.service or 'unknown'})"
        elif isinstance(finding, Subdomain):
            return f"{finding.domain}"
        elif isinstance(finding, Vulnerability):
            return f"{finding.title} [{finding.severity}]"
        elif isinstance(finding, OsintFinding):
            return f"[{finding.category}] {finding.value[:60]}"
        elif isinstance(finding, WebPath):
            return f"{finding.url} ({finding.status_code})"
        elif isinstance(finding, Credential):
            return f"{finding.service} credential found"
        return str(finding.id)
