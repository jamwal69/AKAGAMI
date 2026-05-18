"""
ReconForge Intel Store — Central structured database for all findings.

Single source of truth for everything discovered during a mission.
Backed by SQLite with tables for each intel type.
"""

import json
import sqlite3
from pathlib import Path
from typing import Optional, Type, TypeVar, get_origin

from reconforge.intel.models import (
    ApiOperation,
    AuthContext,
    Credential,
    Host,
    HttpEndpoint,
    HttpParameter,
    HttpRequestSample,
    IntelBase,
    OsintFinding,
    Port,
    ResponseFingerprint,
    SecretFinding,
    SessionContext,
    Subdomain,
    Vulnerability,
    WebPath,
)
from reconforge.utils.logger import get_logger, log_finding

logger = get_logger("intel_store")
T = TypeVar("T", bound=IntelBase)

# Mapping of intel type name to model class
INTEL_TYPES: dict[str, Type[IntelBase]] = {
    "host": Host,
    "port": Port,
    "subdomain": Subdomain,
    "vulnerability": Vulnerability,
    "credential": Credential,
    "web_path": WebPath,
    "osint_finding": OsintFinding,
    "session_context": SessionContext,
    "secret_finding": SecretFinding,
    "http_endpoint": HttpEndpoint,
    "http_request_sample": HttpRequestSample,
    "http_parameter": HttpParameter,
    "auth_context": AuthContext,
    "api_operation": ApiOperation,
    "response_fingerprint": ResponseFingerprint,
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

CREATE TABLE IF NOT EXISTS session_contexts (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    host_id TEXT NOT NULL,
    cookies TEXT DEFAULT '[]',
    local_storage TEXT DEFAULT '{}',
    session_storage TEXT DEFAULT '{}',
    jwt_tokens TEXT DEFAULT '[]',
    auth_headers TEXT DEFAULT '{}',
    username TEXT,
    role TEXT
);

CREATE TABLE IF NOT EXISTS secret_findings (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    host_id TEXT,
    file_path TEXT,
    secret_type TEXT,
    secret_value TEXT,
    is_verified INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS http_endpoints (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    method TEXT DEFAULT 'GET',
    scheme TEXT DEFAULT 'https',
    host TEXT NOT NULL,
    port INTEGER,
    path TEXT NOT NULL,
    normalized_route TEXT NOT NULL,
    query_parameter_names TEXT DEFAULT '[]',
    body_parameter_names TEXT DEFAULT '[]',
    header_names TEXT DEFAULT '[]',
    auth_required TEXT DEFAULT 'unknown',
    source TEXT DEFAULT 'manual',
    status_code INTEGER,
    content_type TEXT,
    response_size INTEGER,
    response_hash TEXT,
    response_fingerprint TEXT,
    discovered_at TEXT,
    state_changing INTEGER DEFAULT 0,
    interestingness_score REAL DEFAULT 0,
    interestingness_signals TEXT DEFAULT '[]',
    sensitive_parameter_names TEXT DEFAULT '[]',
    recommended_manual_tests TEXT DEFAULT '[]',
    false_positive_risk TEXT DEFAULT 'medium',
    evidence TEXT,
    raw_url TEXT,
    auth_context_id TEXT
);

CREATE TABLE IF NOT EXISTS http_request_samples (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    endpoint_id TEXT,
    method TEXT DEFAULT 'GET',
    scheme TEXT DEFAULT 'https',
    host TEXT NOT NULL,
    port INTEGER,
    path TEXT NOT NULL,
    normalized_route TEXT NOT NULL,
    query_parameter_names TEXT DEFAULT '[]',
    body_parameter_names TEXT DEFAULT '[]',
    header_names TEXT DEFAULT '[]',
    auth_required TEXT DEFAULT 'unknown',
    source TEXT DEFAULT 'manual',
    status_code INTEGER,
    content_type TEXT,
    response_size INTEGER,
    response_hash TEXT,
    response_fingerprint TEXT,
    discovered_at TEXT,
    state_changing INTEGER DEFAULT 0,
    interestingness_score REAL DEFAULT 0,
    interestingness_signals TEXT DEFAULT '[]',
    sensitive_parameter_names TEXT DEFAULT '[]',
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS http_parameters (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    endpoint_id TEXT,
    location TEXT,
    name TEXT,
    normalized_name TEXT,
    categories TEXT DEFAULT '[]',
    sensitive INTEGER DEFAULT 0,
    value_redacted INTEGER DEFAULT 1,
    source TEXT DEFAULT 'manual'
);

CREATE TABLE IF NOT EXISTS auth_contexts (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    auth_required TEXT DEFAULT 'unknown',
    scheme TEXT,
    identity_label TEXT,
    role TEXT,
    has_cookies INTEGER DEFAULT 0,
    has_bearer_token INTEGER DEFAULT 0,
    header_names TEXT DEFAULT '[]',
    source TEXT DEFAULT 'manual'
);

CREATE TABLE IF NOT EXISTS api_operations (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    endpoint_id TEXT,
    operation_id TEXT,
    method TEXT,
    path TEXT,
    normalized_route TEXT,
    source TEXT DEFAULT 'manual',
    summary TEXT,
    tags TEXT DEFAULT '[]',
    operation_type TEXT,
    state_changing INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS response_fingerprints (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    source_agent TEXT,
    source_tool TEXT,
    confidence REAL,
    timestamp TEXT,
    verified INTEGER DEFAULT 0,
    raw_output TEXT,
    endpoint_id TEXT,
    status_code INTEGER,
    content_type TEXT,
    response_size INTEGER,
    body_hash TEXT,
    fingerprint TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_mission ON hosts(mission_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_mission ON subdomains(mission_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_osint_category ON osint_findings(category);
CREATE INDEX IF NOT EXISTS idx_session_contexts_mission ON session_contexts(mission_id);
CREATE INDEX IF NOT EXISTS idx_secret_findings_mission ON secret_findings(mission_id);
CREATE INDEX IF NOT EXISTS idx_secret_findings_type ON secret_findings(secret_type);
CREATE INDEX IF NOT EXISTS idx_http_endpoints_mission ON http_endpoints(mission_id);
CREATE INDEX IF NOT EXISTS idx_http_endpoints_score ON http_endpoints(interestingness_score);
CREATE INDEX IF NOT EXISTS idx_http_endpoints_route ON http_endpoints(host, normalized_route);
CREATE INDEX IF NOT EXISTS idx_http_parameters_endpoint ON http_parameters(endpoint_id);
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

    def session_contexts(self, mission_id: Optional[str] = None,
                         **filters) -> list[dict]:
        return self.query("session_context", mission_id, **filters)

    def secret_findings(self, mission_id: Optional[str] = None,
                        **filters) -> list[dict]:
        return self.query("secret_finding", mission_id, **filters)

    def http_endpoints(self, mission_id: Optional[str] = None,
                       **filters) -> list[dict]:
        return self.query("http_endpoint", mission_id, **filters)

    def http_request_samples(self, mission_id: Optional[str] = None,
                             **filters) -> list[dict]:
        return self.query("http_request_sample", mission_id, **filters)

    def http_parameters(self, mission_id: Optional[str] = None,
                        **filters) -> list[dict]:
        return self.query("http_parameter", mission_id, **filters)

    def auth_contexts(self, mission_id: Optional[str] = None,
                      **filters) -> list[dict]:
        return self.query("auth_context", mission_id, **filters)

    def api_operations(self, mission_id: Optional[str] = None,
                       **filters) -> list[dict]:
        return self.query("api_operation", mission_id, **filters)

    def response_fingerprints(self, mission_id: Optional[str] = None,
                              **filters) -> list[dict]:
        return self.query("response_fingerprint", mission_id, **filters)

    def top_http_endpoints(self, mission_id: Optional[str] = None,
                           limit: int = 20) -> list[dict]:
        where = " WHERE mission_id = ?" if mission_id else ""
        params = [mission_id] if mission_id else []
        sql = (
            "SELECT * FROM http_endpoints"
            f"{where} ORDER BY interestingness_score DESC, confidence DESC LIMIT ?"
        )
        rows = self.conn.execute(sql, [*params, limit]).fetchall()
        return [dict(row) for row in rows]

    def _read_all(self, model_type: Type[T],
                  mission_id: Optional[str] = None) -> list[T]:
        """Read rows for a model type and reconstruct Pydantic models."""
        table = self._get_table_name_for_type(model_type)
        if not table:
            raise ValueError(f"Unsupported intel model type: {model_type.__name__}")

        where = " WHERE mission_id = ?" if mission_id else ""
        params = [mission_id] if mission_id else []
        rows = self.conn.execute(f"SELECT * FROM {table}{where}", params).fetchall()
        return [self._row_to_model(model_type, row) for row in rows]

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
            "http_api_surfaces": len(self.http_endpoints(mission_id)),
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
            "session_contexts": self.session_contexts(mission_id),
            "secret_findings": self.secret_findings(mission_id),
            "http_endpoints": self.http_endpoints(mission_id),
            "http_request_samples": self.http_request_samples(mission_id),
            "http_parameters": self.http_parameters(mission_id),
            "auth_contexts": self.auth_contexts(mission_id),
            "api_operations": self.api_operations(mission_id),
            "response_fingerprints": self.response_fingerprints(mission_id),
        }

    # ── Internal helpers ─────────────────────────────────────

    def _get_table_name(self, finding: IntelBase) -> str:
        """Map finding type to table name."""
        return self._get_table_name_for_type(type(finding)) or "osint_findings"

    def _get_table_name_for_type(self, model_type: Type[IntelBase]) -> Optional[str]:
        """Map finding model type to table name."""
        type_map = {
            Host: "hosts",
            Port: "ports",
            Subdomain: "subdomains",
            Vulnerability: "vulnerabilities",
            Credential: "credentials",
            WebPath: "web_paths",
            OsintFinding: "osint_findings",
            SessionContext: "session_contexts",
            SecretFinding: "secret_findings",
            HttpEndpoint: "http_endpoints",
            HttpRequestSample: "http_request_samples",
            HttpParameter: "http_parameters",
            AuthContext: "auth_contexts",
            ApiOperation: "api_operations",
            ResponseFingerprint: "response_fingerprints",
        }
        return type_map.get(model_type)

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
            "session_context": "session_contexts",
            "secret_finding": "secret_findings",
            "http_endpoint": "http_endpoints",
            "http_request_sample": "http_request_samples",
            "http_parameter": "http_parameters",
            "auth_context": "auth_contexts",
            "api_operation": "api_operations",
            "response_fingerprint": "response_fingerprints",
        }
        return table_map.get(intel_type, intel_type)

    def _row_to_model(self, model_type: Type[T], row: sqlite3.Row) -> T:
        """Convert a SQLite row back into the requested Pydantic model."""
        fields = model_type.model_fields
        data = {key: value for key, value in dict(row).items() if key in fields}

        for key, field in fields.items():
            value = data.get(key)
            if value is None or not isinstance(value, str):
                continue
            origin = get_origin(field.annotation)
            if origin in (list, dict) or field.annotation in (list, dict):
                try:
                    data[key] = json.loads(value)
                except json.JSONDecodeError:
                    data[key] = [] if origin is list or field.annotation is list else {}

        return model_type(**data)

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
        elif isinstance(finding, SecretFinding):
            sql = (
                f"SELECT id FROM {table} WHERE COALESCE(host_id, '') = COALESCE(?, '') "
                f"AND file_path = ? AND secret_type = ? AND secret_value = ? "
                f"AND mission_id = ?"
            )
            row = self.conn.execute(
                sql,
                (
                    finding.host_id, finding.file_path, finding.secret_type,
                    finding.secret_value, finding.mission_id,
                ),
            ).fetchone()
        elif isinstance(finding, SessionContext):
            sql = (
                f"SELECT id FROM {table} WHERE host_id = ? "
                f"AND COALESCE(username, '') = COALESCE(?, '') "
                f"AND COALESCE(role, '') = COALESCE(?, '') "
                f"AND mission_id = ?"
            )
            row = self.conn.execute(
                sql,
                (finding.host_id, finding.username, finding.role,
                 finding.mission_id),
            ).fetchone()
        elif isinstance(finding, HttpEndpoint):
            param_key = json.dumps(
                sorted(
                    set(
                        finding.query_parameter_names
                        + finding.body_parameter_names
                        + finding.header_names
                    )
                )
            )
            sql = (
                f"SELECT id FROM {table} WHERE method = ? AND host = ? "
                f"AND COALESCE(port, -1) = COALESCE(?, -1) "
                f"AND normalized_route = ? AND auth_required = ? "
                f"AND source = ? AND mission_id = ?"
            )
            rows = self.conn.execute(
                sql,
                (
                    finding.method,
                    finding.host,
                    finding.port,
                    finding.normalized_route,
                    finding.auth_required,
                    finding.source,
                    finding.mission_id,
                ),
            ).fetchall()
            row = None
            for candidate in rows:
                existing = self.conn.execute(
                    f"SELECT query_parameter_names, body_parameter_names, header_names "
                    f"FROM {table} WHERE id = ?",
                    (candidate["id"],),
                ).fetchone()
                if not existing:
                    continue
                existing_names = []
                for col in ("query_parameter_names", "body_parameter_names", "header_names"):
                    try:
                        existing_names.extend(json.loads(existing[col] or "[]"))
                    except json.JSONDecodeError:
                        pass
                if json.dumps(sorted(set(existing_names))) == param_key:
                    row = candidate
                    break
        elif isinstance(finding, HttpParameter):
            sql = (
                f"SELECT id FROM {table} WHERE endpoint_id = ? AND location = ? "
                f"AND normalized_name = ? AND mission_id = ?"
            )
            row = self.conn.execute(
                sql,
                (finding.endpoint_id, finding.location, finding.normalized_name,
                 finding.mission_id),
            ).fetchone()
        elif isinstance(finding, HttpRequestSample):
            sql = (
                f"SELECT id FROM {table} WHERE endpoint_id = ? AND method = ? "
                f"AND host = ? AND COALESCE(port, -1) = COALESCE(?, -1) "
                f"AND normalized_route = ? AND auth_required = ? "
                f"AND source = ? AND mission_id = ?"
            )
            row = self.conn.execute(
                sql,
                (
                    finding.endpoint_id,
                    finding.method,
                    finding.host,
                    finding.port,
                    finding.normalized_route,
                    finding.auth_required,
                    finding.source,
                    finding.mission_id,
                ),
            ).fetchone()
        elif isinstance(finding, ResponseFingerprint):
            sql = (
                f"SELECT id FROM {table} WHERE endpoint_id = ? "
                f"AND fingerprint = ? AND mission_id = ?"
            )
            row = self.conn.execute(
                sql,
                (finding.endpoint_id, finding.fingerprint, finding.mission_id),
            ).fetchone()
        elif isinstance(finding, ApiOperation):
            sql = (
                f"SELECT id FROM {table} WHERE endpoint_id = ? "
                f"AND operation_id = ? AND method = ? AND normalized_route = ? "
                f"AND source = ? AND mission_id = ?"
            )
            row = self.conn.execute(
                sql,
                (
                    finding.endpoint_id, finding.operation_id, finding.method,
                    finding.normalized_route, finding.source, finding.mission_id,
                ),
            ).fetchone()
        elif isinstance(finding, AuthContext):
            sql = (
                f"SELECT id FROM {table} WHERE auth_required = ? AND scheme = ? "
                f"AND COALESCE(role, '') = COALESCE(?, '') "
                f"AND source = ? AND mission_id = ?"
            )
            row = self.conn.execute(
                sql,
                (
                    finding.auth_required, finding.scheme, finding.role,
                    finding.source, finding.mission_id,
                ),
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
        if summary["web_paths"] and not summary["http_endpoints"]:
            gaps.append("No HTTP/API request inventory generated")

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
        elif isinstance(finding, SessionContext):
            principal = finding.username or finding.role or "unknown principal"
            return f"session for {finding.host_id} ({principal})"
        elif isinstance(finding, SecretFinding):
            location = finding.file_path or finding.host_id or "unknown location"
            return f"{finding.secret_type or 'secret'} finding in {location}"
        elif isinstance(finding, WebPath):
            return f"{finding.url} ({finding.status_code})"
        elif isinstance(finding, HttpEndpoint):
            return (
                f"{finding.method} {finding.host}{finding.normalized_route} "
                f"(score={finding.interestingness_score:.0f})"
            )
        elif isinstance(finding, HttpParameter):
            return f"{finding.location}:{finding.name}"
        elif isinstance(finding, ApiOperation):
            return f"{finding.method} {finding.normalized_route}"
        elif isinstance(finding, AuthContext):
            return f"{finding.auth_required} auth context"
        elif isinstance(finding, ResponseFingerprint):
            return f"response fingerprint {finding.fingerprint}"
        elif isinstance(finding, Credential):
            return f"{finding.service} credential found"
        return str(finding.id)
