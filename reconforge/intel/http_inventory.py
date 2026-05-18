"""Passive HTTP/API surface inventory helpers.

This module only normalizes already-observed URLs and metadata. It does not
fetch, replay, mutate, or probe requests.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

from reconforge.intel.models import (
    ApiOperation,
    AuthContext,
    HttpEndpoint,
    HttpParameter,
    HttpRequestSample,
    ResponseFingerprint,
)


VALID_SOURCES = {
    "httpx", "katana", "gau", "js", "browser", "openapi", "graphql", "manual"
}
VALID_AUTH_STATES = {"unknown", "anonymous", "authenticated"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SECRET_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "proxy-authorization",
}
STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".map", ".mp4", ".webm", ".pdf", ".zip", ".gz",
}

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
HEX_TOKEN_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
ALNUM_TOKEN_RE = re.compile(r"^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z0-9_-]{6,}$")
AWS_ACCESS_KEY_RE = re.compile(r"^AKIA[0-9A-Z]{16}$")
JWT_PATH_RE = re.compile(
    r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$"
)
SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)

STATIC_ROUTE_WORDS = {
    "api", "v1", "v2", "v3", "users", "user", "accounts", "account",
    "orders", "order", "org", "orgs", "organization", "organizations",
    "team", "teams", "tenant", "tenants", "invite", "invites", "reset",
    "password", "auth", "login", "logout", "signup", "admin", "internal",
    "billing", "payment", "invoice", "invoices", "subscription", "graphql",
}
STATIC_TOKEN_WORDS = {
    "password", "status", "confirm", "verify", "resend", "accept", "decline",
    "settings", "callback", "complete", "start", "finish", "help", "current",
    "new", "change", "forgot",
}
TOKEN_PARENT_SEGMENTS = {
    "invite", "invites", "reset", "token", "tokens", "verify", "confirm",
    "magic", "magic-link", "key", "keys", "api-key", "api_key", "apikey",
    "jwt", "session", "sessions", "sid",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def stable_names(values) -> list[str]:
    """Return sorted unique names, keeping only non-empty strings."""
    return sorted({str(v).strip() for v in (values or []) if str(v).strip()})


def sanitize_header_names(headers) -> list[str]:
    """Keep non-secret header names only; never store header values."""
    if not headers:
        return []
    names = headers.keys() if isinstance(headers, dict) else headers
    safe = []
    for name in names:
        lowered = str(name).strip().lower()
        if not lowered or lowered in SECRET_HEADER_NAMES:
            continue
        if "token" in lowered or "secret" in lowered or "key" in lowered:
            continue
        safe.append(lowered)
    return stable_names(safe)


def normalize_route(path: str) -> str:
    """Normalize path IDs/tokens into route patterns used for clustering."""
    raw_path = urlsplit(path).path if "://" in str(path) else str(path or "")
    raw_path = raw_path or "/"
    parts = [part for part in raw_path.split("/") if part]
    if not parts:
        return "/"

    normalized = []
    for index, segment in enumerate(parts):
        previous = normalized[-1] if normalized else ""
        original_previous = parts[index - 1].lower() if index else ""
        lowered = segment.lower()
        clean_segment = segment.strip()

        if clean_segment.startswith("{") and clean_segment.endswith("}"):
            normalized.append(_placeholder_for_path_param(clean_segment[1:-1]))
        elif UUID_RE.match(clean_segment):
            normalized.append("{uuid}")
        elif clean_segment.isdigit():
            normalized.append("{id}")
        elif _is_token_segment(clean_segment, original_previous):
            normalized.append("{token}")
        elif _is_slug_segment(clean_segment, original_previous):
            normalized.append("{slug}")
        elif previous in {"{slug}", "{token}"} and lowered in STATIC_ROUTE_WORDS:
            normalized.append(lowered)
        else:
            normalized.append(lowered)

    return "/" + "/".join(normalized)


def _placeholder_for_path_param(name: str) -> str:
    normalized = normalize_parameter_name(name)
    categories, sensitive = classify_parameter_name(normalized)
    if sensitive or "token" in normalized:
        return "{token}"
    if "tenant_or_team_id" in categories:
        return "{id}"
    if "user_id" in categories or "object_id" in categories:
        return "{id}"
    if "slug" in normalized:
        return "{slug}"
    if "uuid" in normalized:
        return "{uuid}"
    return "{id}"


def _is_token_segment(segment: str, previous: str) -> bool:
    if _is_static_token_word(segment):
        return False
    if previous in TOKEN_PARENT_SEGMENTS:
        return _is_tokenish_value(segment, min_length=6)
    if AWS_ACCESS_KEY_RE.match(segment) or JWT_PATH_RE.match(segment):
        return True
    if HEX_TOKEN_RE.match(segment):
        return True
    return bool(ALNUM_TOKEN_RE.match(segment) and len(segment) >= 12)


def _is_static_token_word(segment: str) -> bool:
    return segment.strip().lower() in STATIC_TOKEN_WORDS


def _is_tokenish_value(segment: str, *, min_length: int = 8) -> bool:
    clean = segment.strip()
    if not clean or _is_static_token_word(clean):
        return False
    if AWS_ACCESS_KEY_RE.match(clean) or JWT_PATH_RE.match(clean):
        return True
    if UUID_RE.match(clean) or HEX_TOKEN_RE.match(clean):
        return True
    return bool(ALNUM_TOKEN_RE.match(clean) and len(clean) >= min_length)


def _is_slug_segment(segment: str, previous: str) -> bool:
    if previous not in {
        "org", "orgs", "organization", "organizations", "team", "teams",
        "tenant", "tenants", "company", "companies", "workspace",
        "workspaces", "project", "projects",
    }:
        return False
    return segment.lower() not in STATIC_ROUTE_WORDS and bool(SLUG_RE.match(segment))


def classify_parameter_name(name: str) -> tuple[list[str], bool]:
    """Classify a parameter name by bug-bounty-relevant risk hints."""
    normalized = normalize_parameter_name(name)
    categories: list[str] = []

    def add(category: str) -> None:
        if category not in categories:
            categories.append(category)

    if re.search(r"(^|_)(token|secret|password|passwd|pwd|api_key|apikey|key|jwt|session|csrf)(_|$)", normalized):
        add("secret_or_token")
    if re.search(r"(^|_)(user|uid|owner|account|profile)(_id)?(_|$)", normalized):
        add("user_id")
    if re.search(r"(^|_)(org|organization|team|tenant|workspace|company|member)(_id)?(_|$)", normalized):
        add("tenant_or_team_id")
    if re.search(r"(^|_)(role|admin|is_admin|permission|privilege|superuser|is_owner)(_|$)", normalized):
        add("role_or_admin_flag")
    if re.search(r"(^|_)(price|amount|payment|billing|invoice|subscription|coupon|discount|plan|card|tax)(_|$)", normalized):
        add("price_payment_coupon")
    if re.search(r"(^|_)(redirect|return|callback|next|continue|url|uri|dest|destination)(_|$)", normalized):
        add("redirect_url")
    if re.search(r"(^|_)(upload|file|filename|avatar|attachment|import|export|document|path)(_|$)", normalized):
        add("upload_or_file")
    if re.search(r"(^|_)(id|uuid|object|order|resource|item|record)(_id)?(_|$)", normalized):
        add("object_id")

    return categories, "secret_or_token" in categories


def normalize_parameter_name(name: str) -> str:
    raw = str(name or "").strip()
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", raw)
    normalized = re.sub(r"[\[\].:-]+", "_", raw.lower())
    normalized = re.sub(r"__+", "_", normalized).strip("_")
    return normalized


def parameter_models(endpoint: HttpEndpoint) -> list[HttpParameter]:
    """Build redacted parameter metadata for an endpoint."""
    params = []
    for location, names in (
        ("query", endpoint.query_parameter_names),
        ("body", endpoint.body_parameter_names),
        ("header", endpoint.header_names),
    ):
        for name in names:
            categories, sensitive = classify_parameter_name(name)
            params.append(HttpParameter(
                source_agent=endpoint.source_agent,
                source_tool=endpoint.source_tool,
                confidence=endpoint.confidence,
                mission_id=endpoint.mission_id,
                endpoint_id=endpoint.id,
                location=location,
                name=name,
                normalized_name=normalize_parameter_name(name),
                categories=categories,
                sensitive=sensitive,
                value_redacted=True,
                source=endpoint.source,
            ))
    return params


def endpoint_dedupe_key(endpoint: HttpEndpoint) -> str:
    param_names = stable_names(
        endpoint.query_parameter_names
        + endpoint.body_parameter_names
        + endpoint.header_names
    )
    port = endpoint.port or ""
    return "|".join([
        endpoint.method.upper(),
        endpoint.host.lower(),
        str(port),
        endpoint.normalized_route,
        ",".join(param_names),
        endpoint.auth_required,
        endpoint.source,
    ])


def endpoint_history_key(endpoint: HttpEndpoint) -> str:
    """Route-level key for mission-to-mission novelty scoring."""
    port = endpoint.port or ""
    return "|".join([
        endpoint.method.upper(),
        endpoint.host.lower(),
        str(port),
        endpoint.normalized_route,
    ])


def endpoint_from_url(
    url: str,
    mission_id: str,
    *,
    source: str = "manual",
    source_agent: str = "http_inventory",
    method: str = "GET",
    status_code: int | None = None,
    content_type: str = "",
    response_size: int | None = None,
    response_hash: str = "",
    headers=None,
    body_parameter_names=None,
    auth_required: str = "unknown",
    confidence: float = 0.7,
    evidence: str = "",
) -> HttpEndpoint:
    """Create a passive endpoint inventory record from an observed URL."""
    parsed = urlsplit(url if "://" in str(url) else f"https://{url}")
    if not parsed.hostname:
        raise ValueError(f"URL has no host: {url!r}")

    method = method.upper()
    source = source if source in VALID_SOURCES else "manual"
    auth_required = auth_required if auth_required in VALID_AUTH_STATES else "unknown"
    path = parsed.path or "/"
    stored_path = redact_path_segments(path)
    query_names = stable_names(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    body_names = stable_names(body_parameter_names)
    header_names = sanitize_header_names(headers)
    sensitive = _sensitive_names(query_names + body_names + header_names)
    fingerprint = response_fingerprint_value(
        status_code=status_code,
        content_type=content_type,
        response_size=response_size,
        response_hash=response_hash,
    )

    endpoint = HttpEndpoint(
        source_agent=source_agent,
        source_tool=source,
        confidence=confidence,
        mission_id=mission_id,
        method=method,
        scheme=parsed.scheme or "https",
        host=parsed.hostname.lower(),
        port=parsed.port,
        path=stored_path,
        normalized_route=normalize_route(path),
        query_parameter_names=query_names,
        body_parameter_names=body_names,
        header_names=header_names,
        auth_required=auth_required,
        source=source,
        status_code=status_code,
        content_type=content_type or "",
        response_size=response_size,
        response_hash=response_hash or "",
        response_fingerprint=fingerprint,
        discovered_at=_now(),
        state_changing=method in STATE_CHANGING_METHODS,
        sensitive_parameter_names=sensitive,
        evidence=evidence or f"Observed by {source}",
        raw_url=_redacted_url(url),
    )
    apply_interestingness(endpoint)
    return endpoint


def response_fingerprint_value(
    *,
    status_code: int | None = None,
    content_type: str = "",
    response_size: int | None = None,
    response_hash: str = "",
) -> str:
    seed = f"{status_code or ''}|{content_type.lower()}|{response_size or ''}|{response_hash}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def response_fingerprint_model(endpoint: HttpEndpoint) -> ResponseFingerprint:
    return ResponseFingerprint(
        source_agent=endpoint.source_agent,
        source_tool=endpoint.source_tool,
        confidence=endpoint.confidence,
        mission_id=endpoint.mission_id,
        endpoint_id=endpoint.id,
        status_code=endpoint.status_code,
        content_type=endpoint.content_type,
        response_size=endpoint.response_size,
        body_hash=endpoint.response_hash,
        fingerprint=endpoint.response_fingerprint,
    )


def request_sample_from_endpoint(endpoint: HttpEndpoint) -> HttpRequestSample:
    return HttpRequestSample(
        source_agent=endpoint.source_agent,
        source_tool=endpoint.source_tool,
        confidence=endpoint.confidence,
        mission_id=endpoint.mission_id,
        endpoint_id=endpoint.id,
        method=endpoint.method,
        scheme=endpoint.scheme,
        host=endpoint.host,
        port=endpoint.port,
        path=endpoint.path,
        normalized_route=endpoint.normalized_route,
        query_parameter_names=endpoint.query_parameter_names,
        body_parameter_names=endpoint.body_parameter_names,
        header_names=endpoint.header_names,
        auth_required=endpoint.auth_required,
        source=endpoint.source,
        status_code=endpoint.status_code,
        content_type=endpoint.content_type,
        response_size=endpoint.response_size,
        response_hash=endpoint.response_hash,
        response_fingerprint=endpoint.response_fingerprint,
        discovered_at=endpoint.discovered_at,
        state_changing=endpoint.state_changing,
        interestingness_score=endpoint.interestingness_score,
        interestingness_signals=endpoint.interestingness_signals,
        sensitive_parameter_names=endpoint.sensitive_parameter_names,
        evidence=endpoint.evidence,
    )


def auth_context_from_observation(
    mission_id: str,
    *,
    source_agent: str = "http_inventory",
    source_tool: str = "manual",
    auth_required: str = "unknown",
    headers=None,
    role: str | None = None,
    confidence: float = 0.7,
) -> AuthContext:
    names = {str(name).strip().lower() for name in ((headers or {}).keys() if isinstance(headers, dict) else headers or [])}
    return AuthContext(
        source_agent=source_agent,
        source_tool=source_tool,
        confidence=confidence,
        mission_id=mission_id,
        auth_required=auth_required if auth_required in VALID_AUTH_STATES else "unknown",
        scheme="bearer" if "authorization" in names else "",
        role=role,
        has_cookies=bool({"cookie", "set-cookie"} & names),
        has_bearer_token="authorization" in names,
        header_names=sanitize_header_names(names),
        source=source_tool,
    )


def ingest_url_lines(
    raw: str,
    mission_id: str,
    *,
    source: str = "gau",
    source_agent: str = "http_inventory",
) -> list[HttpEndpoint]:
    endpoints = []
    seen = set()
    for line in (raw or "").splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        try:
            endpoint = endpoint_from_url(
                url, mission_id, source=source, source_agent=source_agent,
                evidence=f"{source} URL list")
        except ValueError:
            continue
        key = endpoint_dedupe_key(endpoint)
        if key in seen:
            endpoint.interestingness_signals.append("duplicate route")
            endpoint.interestingness_score = max(0.0, endpoint.interestingness_score - 20)
            continue
        seen.add(key)
        endpoints.append(endpoint)
    return endpoints


def ingest_httpx_jsonl(
    raw: str,
    mission_id: str,
    *,
    source_agent: str = "http_inventory",
) -> list[HttpEndpoint]:
    endpoints = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = data.get("url") or data.get("input")
        if not url:
            continue
        size = data.get("content_length") or data.get("content-length") or data.get("content_length")
        try:
            size = int(size) if size is not None else None
        except (TypeError, ValueError):
            size = None
        status = data.get("status_code") or data.get("status-code")
        try:
            status = int(status) if status is not None else None
        except (TypeError, ValueError):
            status = None
        try:
            endpoints.append(endpoint_from_url(
                url,
                mission_id,
                source="httpx",
                source_agent=source_agent,
                status_code=status,
                content_type=data.get("content_type") or data.get("content-type") or "",
                response_size=size,
                evidence="httpx JSONL result",
                confidence=0.9,
            ))
        except ValueError:
            continue
    return deduplicate_endpoints(endpoints)


def ingest_browser_network(
    events: list[dict],
    mission_id: str,
    *,
    source_agent: str = "http_inventory",
) -> list[HttpEndpoint]:
    endpoints = []
    for event in events or []:
        url = event.get("url") or event.get("request", {}).get("url")
        if not url:
            continue
        method = event.get("method") or event.get("request", {}).get("method") or "GET"
        headers = event.get("headers") or event.get("request", {}).get("headers") or {}
        body_names = stable_names(
            event.get("body_parameter_names")
            or event.get("body_params")
            or event.get("request", {}).get("body_parameter_names")
        )
        if not body_names:
            body_names = body_parameter_names(event.get("post_data") or event.get("body"))
        observed_auth = event.get("auth_required") or event.get("request", {}).get("auth_required")
        if observed_auth in VALID_AUTH_STATES:
            auth_required = observed_auth
        else:
            auth_required = "authenticated" if (
                event.get("has_auth") or _has_auth_headers(headers)
            ) else "unknown"
        try:
            endpoints.append(endpoint_from_url(
                url,
                mission_id,
                source="browser",
                source_agent=source_agent,
                method=method,
                headers=headers,
                body_parameter_names=body_names,
                auth_required=auth_required,
                status_code=event.get("status_code"),
                content_type=event.get("content_type", ""),
                response_size=event.get("response_size"),
                evidence="browser network log",
                confidence=0.85,
            ))
        except ValueError:
            continue
    return deduplicate_endpoints(endpoints)


def ingest_openapi_spec(
    spec: dict,
    base_url: str,
    mission_id: str,
    *,
    source_agent: str = "http_inventory",
) -> tuple[list[HttpEndpoint], list[ApiOperation]]:
    endpoints: list[HttpEndpoint] = []
    operations: list[ApiOperation] = []
    paths = spec.get("paths", {}) if isinstance(spec, dict) else {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            params = operation.get("parameters", []) if isinstance(operation, dict) else []
            query_names = [p.get("name", "") for p in params if p.get("in") == "query"]
            header_names = [p.get("name", "") for p in params if p.get("in") == "header"]
            body_names = _openapi_body_names(operation if isinstance(operation, dict) else {})
            auth_required = _openapi_auth_required(spec, operation if isinstance(operation, dict) else {})
            url = base_url.rstrip("/") + "/" + str(path).lstrip("/")
            endpoint = endpoint_from_url(
                url,
                mission_id,
                source="openapi",
                source_agent=source_agent,
                method=method.upper(),
                headers=header_names,
                body_parameter_names=body_names,
                auth_required=auth_required,
                confidence=0.9,
                evidence="OpenAPI metadata",
            )
            endpoint.query_parameter_names = stable_names(endpoint.query_parameter_names + query_names)
            endpoint.sensitive_parameter_names = _sensitive_names(
                endpoint.query_parameter_names + endpoint.body_parameter_names + endpoint.header_names)
            apply_interestingness(endpoint)
            endpoints.append(endpoint)
            operations.append(ApiOperation(
                source_agent=source_agent,
                source_tool="openapi",
                confidence=0.9,
                mission_id=mission_id,
                endpoint_id=endpoint.id,
                operation_id=operation.get("operationId", "") if isinstance(operation, dict) else "",
                method=endpoint.method,
                path=endpoint.path,
                normalized_route=endpoint.normalized_route,
                source="openapi",
                summary=operation.get("summary", "") if isinstance(operation, dict) else "",
                tags=operation.get("tags", []) if isinstance(operation, dict) else [],
                operation_type="REST",
                state_changing=endpoint.state_changing,
            ))
    return deduplicate_endpoints(endpoints), operations


def ingest_graphql_metadata(
    endpoint_url: str,
    operations: list[dict],
    mission_id: str,
    *,
    source_agent: str = "http_inventory",
) -> tuple[list[HttpEndpoint], list[ApiOperation]]:
    endpoint = endpoint_from_url(
        endpoint_url,
        mission_id,
        source="graphql",
        source_agent=source_agent,
        method="POST",
        body_parameter_names=["query", "variables", "operationName"],
        confidence=0.85,
        evidence="GraphQL metadata",
    )
    endpoint.content_type = endpoint.content_type or "application/json"
    apply_interestingness(endpoint)
    api_ops = []
    for op in operations or []:
        op_type = str(op.get("type") or op.get("operation_type") or "query")
        api_ops.append(ApiOperation(
            source_agent=source_agent,
            source_tool="graphql",
            confidence=0.8,
            mission_id=mission_id,
            endpoint_id=endpoint.id,
            operation_id=str(op.get("name") or ""),
            method="POST",
            path=endpoint.path,
            normalized_route=endpoint.normalized_route,
            source="graphql",
            summary=str(op.get("summary") or ""),
            tags=stable_names(op.get("tags", [])),
            operation_type=op_type,
            state_changing=op_type.lower() in {"mutation", "subscription"},
        ))
    return [endpoint], api_ops


def ingest_web_paths(web_paths: list[dict], mission_id: str,
                     *, source_agent: str = "http_inventory") -> list[HttpEndpoint]:
    """Create endpoint records from already-stored WebPath rows."""
    endpoints = []
    for item in web_paths or []:
        url = item.get("url", "")
        if not url:
            continue
        source_tool = item.get("source_tool") or "manual"
        source = source_tool if source_tool in VALID_SOURCES else "manual"
        try:
            endpoints.append(endpoint_from_url(
                url,
                mission_id,
                source=source,
                source_agent=source_agent,
                status_code=item.get("status_code"),
                content_type=item.get("content_type") or "",
                confidence=float(item.get("confidence") or 0.7),
                evidence=item.get("reason") or f"stored WebPath from {source_tool}",
            ))
        except (TypeError, ValueError):
            continue
    return deduplicate_endpoints(endpoints)


def ingest_osint_findings(osint_findings: list[dict], mission_id: str,
                          *, source_agent: str = "http_inventory") -> list[HttpEndpoint]:
    """Create endpoint records from already-stored OSINT/JS URL evidence."""
    endpoints = []
    seen_urls = set()
    for item in osint_findings or []:
        text = "\n".join(
            str(item.get(field) or "")
            for field in ("value", "context", "raw_output")
        )
        for url in _extract_urls(text):
            if url in seen_urls:
                continue
            seen_urls.add(url)
            source = _source_from_osint_url(item, url)
            try:
                endpoints.append(endpoint_from_url(
                    url,
                    mission_id,
                    source=source,
                    source_agent=source_agent,
                    confidence=float(item.get("confidence") or 0.7),
                    evidence=f"stored OSINT URL from {item.get('source_tool') or 'unknown'}",
                ))
            except (TypeError, ValueError):
                continue
    return deduplicate_endpoints(endpoints)


def ingest_openapi_documents_from_osint(
    osint_findings: list[dict],
    mission_id: str,
    *,
    source_agent: str = "http_inventory",
) -> tuple[list[HttpEndpoint], list[ApiOperation]]:
    """Parse already-collected OpenAPI JSON documents from OSINT rows."""
    endpoints: list[HttpEndpoint] = []
    operations: list[ApiOperation] = []
    for item in osint_findings or []:
        spec = _json_object_from_text(item.get("raw_output") or item.get("value") or "")
        if not _looks_like_openapi_spec(spec):
            continue
        base_url = _openapi_base_url_from_spec_or_finding(spec, item)
        if not base_url:
            continue
        spec_endpoints, spec_operations = ingest_openapi_spec(
            spec,
            base_url,
            mission_id,
            source_agent=source_agent,
        )
        endpoints.extend(spec_endpoints)
        operations.extend(spec_operations)
    return deduplicate_endpoints(endpoints), operations


def refresh_http_inventory_from_store(
    store,
    mission_id: str,
    *,
    source_agent: str = "orchestrator",
    browser_events: list[dict] | None = None,
    openapi_specs: list[dict] | None = None,
    graphql_metadata: list[dict] | None = None,
) -> list[str]:
    """Refresh passive HTTP inventory from stored evidence and optional fixtures.

    This function never fetches or replays URLs. Optional OpenAPI/GraphQL/browser
    inputs must already be collected by an approved passive source.
    """
    endpoints: list[HttpEndpoint] = []
    operations: list[ApiOperation] = []

    osint_rows = store.osint_findings(mission_id)

    endpoints.extend(ingest_web_paths(
        store.web_paths(mission_id),
        mission_id,
        source_agent=source_agent,
    ))
    endpoints.extend(ingest_osint_findings(
        osint_rows,
        mission_id,
        source_agent=source_agent,
    ))
    openapi_doc_endpoints, openapi_doc_operations = ingest_openapi_documents_from_osint(
        osint_rows,
        mission_id,
        source_agent=source_agent,
    )
    endpoints.extend(openapi_doc_endpoints)
    operations.extend(openapi_doc_operations)

    if browser_events:
        endpoints.extend(ingest_browser_network(
            browser_events,
            mission_id,
            source_agent=source_agent,
        ))

    for item in openapi_specs or []:
        spec = item.get("spec") if isinstance(item, dict) else None
        base_url = item.get("base_url") if isinstance(item, dict) else None
        if not spec or not base_url:
            continue
        spec_endpoints, spec_operations = ingest_openapi_spec(
            spec,
            base_url,
            mission_id,
            source_agent=source_agent,
        )
        endpoints.extend(spec_endpoints)
        operations.extend(spec_operations)

    for item in graphql_metadata or []:
        endpoint_url = item.get("endpoint_url") if isinstance(item, dict) else None
        ops = item.get("operations", []) if isinstance(item, dict) else []
        if not endpoint_url:
            continue
        gql_endpoints, gql_operations = ingest_graphql_metadata(
            endpoint_url,
            ops,
            mission_id,
            source_agent=source_agent,
        )
        endpoints.extend(gql_endpoints)
        operations.extend(gql_operations)

    historical_keys = historical_endpoint_keys(store, mission_id)
    deduped = mark_newly_discovered(deduplicate_endpoints(endpoints), historical_keys)
    endpoints_by_original_id = {endpoint.id: endpoint for endpoint in deduped}
    stored_ids = store_endpoint_inventory(store, deduped)

    for operation in operations:
        endpoint = endpoints_by_original_id.get(operation.endpoint_id or "")
        if endpoint:
            operation.endpoint_id = endpoint.id
        store.write(operation)

    return stored_ids


def store_endpoint_inventory(store, endpoints: list[HttpEndpoint]) -> list[str]:
    """Persist endpoints plus passive parameter/sample/fingerprint records."""
    stored_ids = []
    for endpoint in deduplicate_endpoints(endpoints):
        existing_id = _existing_endpoint_id(store, endpoint)
        if existing_id:
            endpoint.id = existing_id
        else:
            store.write(endpoint)
        stored_ids.append(endpoint.id)
        store.write(request_sample_from_endpoint(endpoint))
        store.write(response_fingerprint_model(endpoint))
        auth_context = auth_context_from_endpoint(endpoint)
        if auth_context:
            store.write(auth_context)
        for param in parameter_models(endpoint):
            store.write(param)
    return stored_ids


def deduplicate_endpoints(endpoints: list[HttpEndpoint]) -> list[HttpEndpoint]:
    seen = set()
    deduped = []
    for endpoint in endpoints:
        key = endpoint_dedupe_key(endpoint)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(endpoint)
    return deduped


def _existing_endpoint_id(store, endpoint: HttpEndpoint) -> str | None:
    rows = store.http_endpoints(
        endpoint.mission_id,
        method=endpoint.method,
        host=endpoint.host,
        normalized_route=endpoint.normalized_route,
        auth_required=endpoint.auth_required,
        source=endpoint.source,
    )
    target_params = sorted(
        set(endpoint.query_parameter_names + endpoint.body_parameter_names + endpoint.header_names)
    )
    for row in rows:
        existing = []
        for col in ("query_parameter_names", "body_parameter_names", "header_names"):
            try:
                existing.extend(json.loads(row.get(col) or "[]"))
            except json.JSONDecodeError:
                pass
        if sorted(set(existing)) == target_params:
            return row["id"]
    return None


def historical_endpoint_keys(store, mission_id: str) -> set[str]:
    """Return route keys seen in earlier missions in the same inventory DB."""
    if not hasattr(store, "conn"):
        return set()
    rows = store.conn.execute(
        """
        SELECT method, host, port, normalized_route
        FROM http_endpoints
        WHERE mission_id != ?
        """,
        (mission_id,),
    ).fetchall()
    keys = set()
    for row in rows:
        keys.add("|".join([
            str(row["method"] or "GET").upper(),
            str(row["host"] or "").lower(),
            str(row["port"] or ""),
            str(row["normalized_route"] or "/"),
        ]))
    return keys


def mark_newly_discovered(endpoints: list[HttpEndpoint],
                          historical_keys: set[str]) -> list[HttpEndpoint]:
    """Add novelty signal only when prior mission inventory exists."""
    if not historical_keys:
        return endpoints
    for endpoint in endpoints:
        apply_interestingness(
            endpoint,
            newly_discovered=endpoint_history_key(endpoint) not in historical_keys,
        )
    return endpoints


def auth_context_from_endpoint(endpoint: HttpEndpoint) -> AuthContext | None:
    """Build a redacted auth context when an endpoint has auth evidence."""
    if endpoint.auth_required == "unknown":
        return None
    return AuthContext(
        source_agent=endpoint.source_agent,
        source_tool=endpoint.source_tool,
        confidence=endpoint.confidence,
        mission_id=endpoint.mission_id,
        auth_required=endpoint.auth_required,
        scheme="observed" if endpoint.auth_required == "authenticated" else "",
        role=None,
        has_cookies=False,
        has_bearer_token=False,
        header_names=endpoint.header_names,
        source=endpoint.source,
    )


def apply_interestingness(endpoint: HttpEndpoint, *,
                          newly_discovered: bool = False) -> HttpEndpoint:
    score, signals = score_endpoint(endpoint, newly_discovered=newly_discovered)
    endpoint.interestingness_score = score
    endpoint.interestingness_signals = signals
    endpoint.recommended_manual_tests = recommended_manual_tests(endpoint)
    endpoint.false_positive_risk = false_positive_risk(endpoint)
    return endpoint


def score_endpoint(endpoint: HttpEndpoint, *, duplicate: bool = False,
                   newly_discovered: bool = False) -> tuple[float, list[str]]:
    path = endpoint.normalized_route.lower()
    raw_path = endpoint.path.lower()
    method = endpoint.method.upper()
    params = stable_names(endpoint.query_parameter_names + endpoint.body_parameter_names)
    categories = []
    for name in params:
        found, _ = classify_parameter_name(name)
        categories.extend(found)

    score = 10.0
    signals: list[str] = []

    def add(points: float, signal: str) -> None:
        nonlocal score
        score += points
        if signal not in signals:
            signals.append(signal)

    def subtract(points: float, signal: str) -> None:
        nonlocal score
        score -= points
        if signal not in signals:
            signals.append(signal)

    if any(word in raw_path for word in ("login", "signup", "register", "password", "reset", "mfa", "sso", "oauth", "auth")):
        add(28, "auth identity workflow")
    if any(word in raw_path for word in ("admin", "internal", "debug", "console", "manage")):
        add(26, "admin/internal/debug surface")
    if endpoint.source in {"graphql", "openapi"} or any(word in raw_path for word in ("graphql", "swagger", "openapi", "/api/")):
        add(22, "API metadata or API route")
    if any(word in raw_path for word in ("upload", "import", "export", "download")):
        add(20, "file transfer workflow")
    if any(word in raw_path for word in ("billing", "payment", "invoice", "subscription", "coupon", "checkout")):
        add(28, "billing/payment workflow")
    if any(word in raw_path for word in ("org", "team", "tenant", "invite", "role", "member", "workspace")):
        add(25, "org/team/role workflow")
    if any(word in raw_path for word in ("user", "account", "profile", "session")):
        add(18, "user/account/session workflow")
    if method in STATE_CHANGING_METHODS:
        add(20, "state-changing method")
    if endpoint.auth_required == "authenticated":
        add(10, "authenticated context")
    if "object_id" in categories:
        add(12, "object ID parameter")
    if "user_id" in categories:
        add(12, "user ID parameter")
    if "tenant_or_team_id" in categories:
        add(14, "tenant/team parameter")
    if "role_or_admin_flag" in categories:
        add(14, "role/admin parameter")
    if "price_payment_coupon" in categories:
        add(14, "payment parameter")
    if "redirect_url" in categories:
        add(10, "redirect URL parameter")
    if "upload_or_file" in categories:
        add(10, "file/upload parameter")
    if "secret_or_token" in categories:
        add(8, "sensitive token-like parameter name")
    if newly_discovered:
        add(8, "newly discovered route")

    if _is_static_path(raw_path):
        subtract(45, "static asset")
    if raw_path in {"/", "/home", "/index", "/index.html"}:
        subtract(10, "generic low-value page")
    if "logout" in raw_path:
        subtract(25, "logout route")
    if any(word in raw_path for word in ("health", "status", "ping", "ready", "live")):
        if not any(word in endpoint.host.lower() for word in ("admin", "internal", "debug")):
            subtract(25, "health/status route")
    if duplicate:
        subtract(20, "duplicate route")

    return max(0.0, min(100.0, round(score, 2))), signals


def recommended_manual_tests(endpoint: HttpEndpoint) -> list[str]:
    signals = set(endpoint.interestingness_signals)
    tests = []
    if {"object ID parameter", "user ID parameter", "tenant/team parameter"} & signals:
        tests.append("Manually compare object access with two authorized accounts; do not mutate data.")
    if "org/team/role workflow" in signals:
        tests.append("Review tenant isolation, invite acceptance, member role boundaries, and ownership checks.")
    if "billing/payment workflow" in signals or "payment parameter" in signals:
        tests.append("Inspect price, coupon, invoice, and subscription trust boundaries with non-destructive test data.")
    if "auth identity workflow" in signals:
        tests.append("Review reset, MFA, SSO/OAuth state, callback, and session fixation behavior manually.")
    if "API metadata or API route" in signals:
        tests.append("Map operations and check field/object-level authorization manually.")
    if "file transfer workflow" in signals or "file/upload parameter" in signals:
        tests.append("Review file type, path, import/export authorization, and storage exposure safely.")
    if endpoint.state_changing:
        tests.append("Confirm authorization expectations before any state-changing replay.")
    if not tests:
        tests.append("Manually inspect purpose, authentication boundary, and data sensitivity.")
    return tests


def false_positive_risk(endpoint: HttpEndpoint) -> str:
    if "static asset" in endpoint.interestingness_signals:
        return "high"
    if endpoint.interestingness_score >= 70 and endpoint.confidence >= 0.8:
        return "low"
    if endpoint.interestingness_score >= 35:
        return "medium"
    return "high"


def body_parameter_names(body) -> list[str]:
    if not body:
        return []
    if isinstance(body, dict):
        return stable_names(body.keys())
    if not isinstance(body, str):
        return []
    stripped = body.strip()
    if not stripped:
        return []
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return stable_names(parsed.keys())
        except json.JSONDecodeError:
            return []
    return stable_names(name for name, _ in parse_qsl(stripped, keep_blank_values=True))


def _openapi_body_names(operation: dict) -> list[str]:
    body = operation.get("requestBody", {})
    names = []
    for media in body.get("content", {}).values() if isinstance(body, dict) else []:
        schema = media.get("schema", {}) if isinstance(media, dict) else {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        names.extend(props.keys())
    return stable_names(names)


def _openapi_auth_required(spec: dict, operation: dict) -> str:
    if operation.get("security") == []:
        return "anonymous"
    if operation.get("security") or (isinstance(spec, dict) and spec.get("security")):
        return "authenticated"
    return "unknown"


def _has_auth_headers(headers) -> bool:
    names = {str(name).strip().lower() for name in ((headers or {}).keys() if isinstance(headers, dict) else headers or [])}
    return bool(names & {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"})


def _sensitive_names(names: list[str]) -> list[str]:
    sensitive = []
    for name in names:
        _, is_sensitive = classify_parameter_name(name)
        if is_sensitive:
            sensitive.append(name)
    return stable_names(sensitive)


def _redacted_url(url: str) -> str:
    parsed = urlsplit(url if "://" in str(url) else f"https://{url}")
    redacted_path = redact_path_segments(parsed.path or "/")
    safe_pairs = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        _, sensitive = classify_parameter_name(name)
        safe_pairs.append(f"{name}={'[REDACTED]' if sensitive and value else value}")
    query = "&".join(safe_pairs)
    return parsed._replace(path=redacted_path, query=query).geturl()


def redact_url_for_inventory(url: str) -> str:
    """Public wrapper for inventory-safe URL storage."""
    return _redacted_url(url)


def redact_path_segments(path: str) -> str:
    """Redact secret/token-like path segments before durable storage."""
    raw_path = urlsplit(path).path if "://" in str(path) else str(path or "")
    raw_path = raw_path or "/"
    parts = [part for part in raw_path.split("/") if part]
    if not parts:
        return "/"

    redacted = []
    for index, segment in enumerate(parts):
        previous = parts[index - 1].lower() if index else ""
        if _is_secret_path_segment(segment, previous):
            redacted.append("{token}")
        else:
            redacted.append(segment)
    return "/" + "/".join(redacted)


def _is_secret_path_segment(segment: str, previous: str) -> bool:
    if segment.startswith("{") and segment.endswith("}"):
        return False
    if _is_static_token_word(segment):
        return False
    if previous in TOKEN_PARENT_SEGMENTS:
        return _is_tokenish_value(segment, min_length=6)
    return _is_tokenish_value(segment, min_length=12)


def _is_static_path(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in STATIC_EXTENSIONS)


def _extract_urls(text: str) -> list[str]:
    urls = []
    for match in URL_RE.finditer(text or ""):
        url = match.group(0).rstrip(".,;:)]}")
        if url:
            urls.append(url)
    return stable_names(urls)


def _source_from_osint_url(item: dict, url: str) -> str:
    lower_url = url.lower()
    source_tool = str(item.get("source_tool") or "").lower()
    context = str(item.get("context") or "").lower()

    if "graphql" in lower_url or "graphql" in context:
        return "graphql"
    if any(word in lower_url or word in context for word in ("openapi", "swagger", "api-docs")):
        return "openapi"
    if (
        source_tool in {"semantic_regex", "js_analysis"}
        or lower_url.endswith(".js")
        or ".js?" in lower_url
        or "javascript" in context
    ):
        return "js"
    if source_tool in VALID_SOURCES:
        return source_tool
    return "manual"


def _json_object_from_text(text: str) -> dict | None:
    stripped = str(text or "").strip()
    if not stripped:
        return None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            parsed = json.loads(stripped[start:end + 1])
        except json.JSONDecodeError:
            return None
    return parsed if isinstance(parsed, dict) else None


def _looks_like_openapi_spec(spec: dict | None) -> bool:
    return bool(
        isinstance(spec, dict)
        and isinstance(spec.get("paths"), dict)
        and (spec.get("openapi") or spec.get("swagger"))
    )


def _openapi_base_url_from_spec_or_finding(spec: dict, item: dict) -> str:
    for server in spec.get("servers", []) if isinstance(spec.get("servers"), list) else []:
        url = server.get("url") if isinstance(server, dict) else ""
        if str(url).startswith(("http://", "https://")):
            return str(url).rstrip("/")

    text = "\n".join(
        str(item.get(field) or "")
        for field in ("value", "context", "raw_output")
    )
    urls = _extract_urls(text)
    if not urls:
        return ""
    parsed = urlsplit(urls[0])
    return parsed._replace(path="", query="", fragment="").geturl().rstrip("/")
