"""Tests for passive HTTP/API request inventory."""

import json

from reconforge.intel.http_inventory import (
    classify_parameter_name,
    deduplicate_endpoints,
    endpoint_dedupe_key,
    endpoint_from_url,
    ingest_browser_network,
    ingest_graphql_metadata,
    ingest_httpx_jsonl,
    ingest_openapi_documents_from_osint,
    ingest_osint_findings,
    ingest_url_lines,
    normalize_route,
    parameter_models,
    redact_path_segments,
    request_sample_from_endpoint,
    refresh_http_inventory_from_store,
    store_endpoint_inventory,
)
from reconforge.agents.browser import BrowserAgent
from reconforge.agents.vuln import VulnAnalysisAgent
from reconforge.intel.models import HttpEndpoint, MissionState, OsintFinding, WebPath
from reconforge.tools.bus import ToolBus


def test_route_normalization_numeric_uuid_slug_and_token():
    assert normalize_route("/api/users/123") == "/api/users/{id}"
    assert normalize_route("/orgs/{orgId}/users/{userId}") == "/orgs/{id}/users/{id}"
    assert (
        normalize_route("/org/acme/invite/abc123")
        == "/org/{slug}/invite/{token}"
    )
    assert (
        normalize_route("/v1/orders/550e8400-e29b-41d4-a716-446655440000")
        == "/v1/orders/{uuid}"
    )


def test_static_routes_after_sensitive_parents_are_preserved():
    assert normalize_route("/reset/password") == "/reset/password"
    assert normalize_route("/invite/status") == "/invite/status"
    assert normalize_route("/org/acme/invite/status") == "/org/{slug}/invite/status"
    assert redact_path_segments("/reset/password") == "/reset/password"
    assert redact_path_segments("/invite/status") == "/invite/status"


def test_query_token_parameter_is_marked_sensitive(mission):
    endpoint = endpoint_from_url(
        "https://example.com/reset?token=abc123&email=user@example.com",
        mission.mission_id,
        source="manual",
    )

    assert endpoint.normalized_route == "/reset"
    assert "token" in endpoint.query_parameter_names
    assert "token" in endpoint.sensitive_parameter_names
    assert "abc123" not in endpoint.raw_url
    assert "token=[REDACTED]" in endpoint.raw_url


def test_token_path_segments_are_redacted_in_endpoint_and_samples(mission):
    endpoint = endpoint_from_url(
        "https://app.example.com/org/acme/invite/abc123?token=querysecret",
        mission.mission_id,
        source="browser",
    )
    sample = request_sample_from_endpoint(endpoint)

    dumped = json.dumps({
        "endpoint": endpoint.model_dump(mode="json"),
        "sample": sample.model_dump(mode="json"),
    })
    assert endpoint.normalized_route == "/org/{slug}/invite/{token}"
    assert endpoint.path == "/org/acme/invite/{token}"
    assert "abc123" not in dumped
    assert "querysecret" not in dumped
    assert "token=[REDACTED]" in endpoint.raw_url
    assert sample.path == "/org/acme/invite/{token}"


def test_reset_api_key_and_jwt_path_segments_are_redacted(mission):
    jwt_value = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "signaturepart123456"
    )
    endpoints = [
        endpoint_from_url(
            "https://app.example.com/reset/tokenvalue1234567890",
            mission.mission_id,
        ),
        endpoint_from_url(
            "https://app.example.com/api/key/AKIAIOSFODNN7EXAMPLE",
            mission.mission_id,
        ),
        endpoint_from_url(
            f"https://app.example.com/session/{jwt_value}",
            mission.mission_id,
        ),
    ]
    dumped = json.dumps([endpoint.model_dump(mode="json") for endpoint in endpoints])

    assert "tokenvalue1234567890" not in dumped
    assert "AKIAIOSFODNN7EXAMPLE" not in dumped
    assert jwt_value not in dumped
    assert endpoints[0].path == "/reset/{token}"
    assert endpoints[1].path == "/api/key/{token}"
    assert endpoints[2].path == "/session/{token}"


def test_parameter_classification_high_value_names():
    cases = {
        "user_id": "user_id",
        "tenantId": "tenant_or_team_id",
        "is_admin": "role_or_admin_flag",
        "coupon_code": "price_payment_coupon",
        "redirect_uri": "redirect_url",
        "avatar_file": "upload_or_file",
        "api_key": "secret_or_token",
        "order_id": "object_id",
    }
    for name, expected in cases.items():
        categories, _ = classify_parameter_name(name)
        assert expected in categories


def test_secret_header_names_and_values_are_not_stored(mission):
    endpoint = endpoint_from_url(
        "https://api.example.com/v1/account?api_key=secret-value",
        mission.mission_id,
        headers={
            "Authorization": "Bearer secret-token",
            "Cookie": "session=secret",
            "X-Request-ID": "req-1",
        },
    )

    assert endpoint.header_names == ["x-request-id"]
    assert "secret-value" not in endpoint.raw_url
    assert "secret-token" not in json.dumps(endpoint.model_dump(mode="json"))
    params = parameter_models(endpoint)
    assert any(p.name == "api_key" and p.sensitive for p in params)


def test_deduplication_uses_method_host_normalized_route_params_auth_and_source(mission):
    first = endpoint_from_url(
        "https://api.example.com/api/users/123?include=profile",
        mission.mission_id,
        source="gau",
    )
    second = endpoint_from_url(
        "https://api.example.com/api/users/456?include=profile",
        mission.mission_id,
        source="gau",
    )
    different_source = endpoint_from_url(
        "https://api.example.com/api/users/456?include=profile",
        mission.mission_id,
        source="katana",
    )

    assert endpoint_dedupe_key(first) == endpoint_dedupe_key(second)
    deduped = deduplicate_endpoints([first, second, different_source])
    assert len(deduped) == 2


def test_scoring_high_for_graphql_auth_and_org_team_route(mission):
    endpoint = endpoint_from_url(
        "https://api.example.com/org/acme/graphql?team_id=123",
        mission.mission_id,
        source="graphql",
        method="POST",
        auth_required="authenticated",
    )

    assert endpoint.interestingness_score >= 80
    assert "API metadata or API route" in endpoint.interestingness_signals
    assert "authenticated context" in endpoint.interestingness_signals
    assert "org/team/role workflow" in endpoint.interestingness_signals
    assert "tenant/team parameter" in endpoint.interestingness_signals


def test_scoring_high_for_state_changing_id_bearing_endpoint(mission):
    endpoint = endpoint_from_url(
        "https://app.example.com/api/users/123/orders?user_id=456",
        mission.mission_id,
        source="browser",
        method="PATCH",
        auth_required="authenticated",
        body_parameter_names=["role", "invoice_id"],
    )

    assert endpoint.state_changing is True
    assert endpoint.interestingness_score >= 80
    assert "state-changing method" in endpoint.interestingness_signals
    assert "user ID parameter" in endpoint.interestingness_signals
    assert "role/admin parameter" in endpoint.interestingness_signals


def test_static_assets_are_downgraded(mission):
    endpoint = endpoint_from_url(
        "https://static.example.com/assets/app.js",
        mission.mission_id,
        source="httpx",
        status_code=200,
    )

    assert endpoint.interestingness_score < 20
    assert "static asset" in endpoint.interestingness_signals
    assert endpoint.false_positive_risk == "high"


def test_ingestion_from_url_and_httpx_fixtures(mission):
    url_endpoints = ingest_url_lines(
        """
        https://app.example.com/login
        https://app.example.com/org/acme/invite/abc123
        """,
        mission.mission_id,
        source="gau",
    )
    httpx_endpoints = ingest_httpx_jsonl(
        '{"url":"https://api.example.com/graphql","status_code":200,"content_type":"application/json","content_length":42}\n',
        mission.mission_id,
    )

    assert [e.normalized_route for e in url_endpoints] == [
        "/login",
        "/org/{slug}/invite/{token}",
    ]
    assert httpx_endpoints[0].source == "httpx"
    assert httpx_endpoints[0].response_size == 42


def test_graphql_and_browser_interfaces_are_passive_and_redacted(mission):
    endpoints, operations = ingest_graphql_metadata(
        "https://api.example.com/graphql",
        [{"type": "mutation", "name": "UpdateTeamRole"}],
        mission.mission_id,
    )
    browser = ingest_browser_network([
        {
            "url": "https://api.example.com/team/blue/member/123",
            "method": "POST",
            "headers": {"Authorization": "Bearer real-token", "Content-Type": "application/json"},
            "body": {"user_id": "123", "role": "admin"},
            "status_code": 200,
        }
    ], mission.mission_id)

    assert endpoints[0].source == "graphql"
    assert operations[0].operation_type == "mutation"
    assert browser[0].auth_required == "authenticated"
    assert "authorization" not in browser[0].header_names
    assert "real-token" not in json.dumps(browser[0].model_dump(mode="json"))


def test_browser_network_accepts_redacted_body_parameter_names(mission):
    browser = ingest_browser_network([
        {
            "url": "https://api.example.com/org/acme/member/123",
            "method": "PATCH",
            "headers": {"Authorization": "Bearer real-token"},
            "body_parameter_names": ["user_id", "role", "password"],
            "status_code": 204,
        }
    ], mission.mission_id)

    dumped = json.dumps(browser[0].model_dump(mode="json"))
    assert browser[0].body_parameter_names == ["password", "role", "user_id"]
    assert "password" in browser[0].sensitive_parameter_names
    assert "real-token" not in dumped
    assert "Bearer" not in dumped


def test_browser_agent_records_sanitized_inventory_events(working_memory):
    agent = BrowserAgent(None, None, working_memory)

    event = agent._sanitized_inventory_event(
        url="https://app.example.com/reset?token=secret-value",
        method="POST",
        headers={
            "Authorization": "Bearer real-token",
            "Cookie": "sid=secret-cookie",
            "Content-Type": "application/json",
        },
        post_data='{"password":"secret-password","user_id":"123"}',
        status_code=200,
        content_type="application/json; charset=utf-8",
        response_size=128,
    )
    agent._remember_inventory_events(working_memory, [event])

    stored = working_memory.get("http_inventory_browser_events")
    dumped = json.dumps(stored)
    assert stored[0]["auth_required"] == "authenticated"
    assert stored[0]["headers"] == ["content-type"]
    assert stored[0]["body_parameter_names"] == ["password", "user_id"]
    assert "token=[REDACTED]" in stored[0]["url"]
    assert "secret-value" not in dumped
    assert "real-token" not in dumped
    assert "secret-cookie" not in dumped
    assert "secret-password" not in dumped


def test_browser_inventory_is_disabled_by_default(working_memory):
    agent = BrowserAgent(None, None, working_memory)

    assert agent._browser_inventory_enabled({}) is False
    assert agent._browser_inventory_enabled({"capture_http_inventory": True}) is True


def test_browser_capture_filters_network_events_by_scope(working_memory):
    class FakeRequest:
        def __init__(self, url):
            self.url = url
            self.method = "GET"
            self.headers = {"Cookie": "sid=raw-cookie", "Accept": "application/json"}
            self.post_data = None

    agent = BrowserAgent(None, None, working_memory)
    mission = MissionState(scope=["example.com"], out_of_scope=["blocked.example.com"])
    events = {}

    agent._capture_inventory_request(
        events,
        FakeRequest("https://cdn.thirdparty.net/pixel?session=raw-session"),
        mission,
    )
    agent._capture_inventory_request(
        events,
        FakeRequest("https://api.example.com/api/users/123?token=raw-token"),
        mission,
    )
    agent._capture_inventory_request(
        events,
        FakeRequest("https://blocked.example.com/api/users/123"),
        mission,
    )

    dumped = json.dumps(events)
    assert len(events) == 1
    assert "api.example.com" in dumped
    assert "thirdparty.net" not in dumped
    assert "blocked.example.com" not in dumped
    assert "raw-session" not in dumped
    assert "raw-token" not in dumped
    assert "token=[REDACTED]" in dumped


def test_browser_agent_redacts_session_context_material(working_memory):
    agent = BrowserAgent(None, None, working_memory)

    cookies = agent._redacted_cookies([
        {
            "name": "session",
            "value": "raw-cookie-secret",
            "domain": "app.example.com",
            "path": "/",
            "httpOnly": True,
            "secure": True,
        }
    ])
    storage = agent._redacted_storage({
        "access_token": "raw-storage-token",
        "theme": "dark",
    })
    headers = agent._redacted_auth_headers({
        "Authorization": "Bearer raw-jwt-token",
    })
    dumped = json.dumps({
        "cookies": cookies,
        "storage": storage,
        "headers": headers,
    })

    assert cookies[0]["value"] == "[REDACTED]"
    assert storage == {"access_token": "[REDACTED]", "theme": "[REDACTED]"}
    assert headers == {"Authorization": "[REDACTED]"}
    assert "raw-cookie-secret" not in dumped
    assert "raw-storage-token" not in dumped
    assert "raw-jwt-token" not in dumped


def test_osint_ingestion_classifies_js_openapi_and_graphql_urls(mission):
    findings = [
        {
            "source_tool": "semantic_regex",
            "confidence": 0.85,
            "value": "https://app.example.com/static/app.js",
            "context": "JavaScript URL matched a high-value path",
        },
        {
            "source_tool": "web_search",
            "confidence": 0.8,
            "value": "Swagger exposed at https://api.example.com/swagger.json",
            "context": "OpenAPI metadata URL",
        },
        {
            "source_tool": "web_search",
            "confidence": 0.8,
            "value": "GraphQL endpoint https://api.example.com/graphql",
            "context": "GraphQL metadata URL",
        },
    ]

    endpoints = ingest_osint_findings(findings, mission.mission_id)

    assert {endpoint.source for endpoint in endpoints} == {"js", "openapi", "graphql"}
    assert all(endpoint.raw_url.startswith("https://") for endpoint in endpoints)


def test_openapi_documents_are_ingested_from_stored_osint_without_fetching(mission):
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/orgs/{orgId}/users/{userId}": {
                "patch": {
                    "operationId": "updateOrgUser",
                    "parameters": [
                        {"name": "include_billing", "in": "query"},
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"properties": {"role": {}, "user_id": {}}}
                            }
                        }
                    },
                    "security": [{"bearerAuth": []}],
                }
            }
        },
    }
    endpoints, operations = ingest_openapi_documents_from_osint([
        {
            "source_tool": "web_search",
            "confidence": 0.8,
            "value": "https://api.example.com/openapi.json",
            "raw_output": json.dumps(spec),
        }
    ], mission.mission_id)

    assert len(endpoints) == 1
    assert endpoints[0].source == "openapi"
    assert endpoints[0].auth_required == "authenticated"
    assert endpoints[0].normalized_route == "/orgs/{id}/users/{id}"
    assert "role/admin parameter" in endpoints[0].interestingness_signals
    assert operations[0].operation_id == "updateOrgUser"


def test_graphql_tool_metadata_is_redacted_and_operation_only(working_memory):
    agent = VulnAnalysisAgent(None, None, working_memory)
    agent._remember_graphql_metadata(
        working_memory,
        "https://api.example.com/graphql?token=secret-value",
        """
        type Query {
          viewer: User
        }
        type Mutation {
          updateTeamRole(teamId: ID!, role: String!): Team
        }
        """,
    )

    metadata = working_memory.get("http_inventory_graphql_metadata")
    dumped = json.dumps(metadata)
    assert metadata[0]["endpoint_url"].endswith("token=[REDACTED]")
    assert {"type": "query", "name": "viewer"} in metadata[0]["operations"]
    assert {"type": "mutation", "name": "updateTeamRole"} in metadata[0]["operations"]
    assert "secret-value" not in dumped


def test_inventory_store_works_without_llm_availability(intel_store, mission):
    endpoints = ingest_url_lines(
        "https://api.example.com/org/acme/invite/abc123?token=secret\n",
        mission.mission_id,
        source="katana",
    )

    stored = store_endpoint_inventory(intel_store, endpoints)
    rows = intel_store.http_endpoints(mission.mission_id)
    params = intel_store.http_parameters(mission.mission_id)

    assert stored
    assert len(rows) == 1
    assert rows[0]["normalized_route"] == "/org/{slug}/invite/{token}"
    assert any(row["name"] == "token" and row["sensitive"] == 1 for row in params)


def test_store_records_redacted_auth_context_for_authenticated_endpoint(intel_store, mission):
    endpoint = endpoint_from_url(
        "https://api.example.com/api/users/123",
        mission.mission_id,
        source="browser",
        method="POST",
        auth_required="authenticated",
        headers={"Authorization": "Bearer real-token", "Content-Type": "application/json"},
    )

    store_endpoint_inventory(intel_store, [endpoint])
    auth_contexts = intel_store.auth_contexts(mission.mission_id)

    assert len(auth_contexts) == 1
    assert auth_contexts[0]["auth_required"] == "authenticated"
    assert "real-token" not in json.dumps(auth_contexts)


def test_refresh_inventory_from_store_uses_passive_sources_and_history(intel_store, mission):
    old_endpoint = endpoint_from_url(
        "https://api.example.com/api/users/123",
        "older-mission",
        source="gau",
    )
    store_endpoint_inventory(intel_store, [old_endpoint])
    intel_store.write(WebPath(
        source_agent="recon",
        source_tool="gau",
        confidence=0.8,
        mission_id=mission.mission_id,
        host_id="api.example.com",
        url="https://api.example.com/api/users/456",
        status_code=200,
        content_type="application/json",
    ))
    intel_store.write(OsintFinding(
        source_agent="js_agent",
        source_tool="semantic_regex",
        confidence=0.85,
        mission_id=mission.mission_id,
        category="other",
        value="https://api.example.com/org/acme/invite/abc123?token=secret-value",
        context="High-value JavaScript path",
    ))

    stored_ids = refresh_http_inventory_from_store(intel_store, mission.mission_id)
    endpoints = intel_store.http_endpoints(mission.mission_id)

    assert len(stored_ids) == 2
    assert len(endpoints) == 2
    old_route = next(e for e in endpoints if e["normalized_route"] == "/api/users/{id}")
    new_route = next(e for e in endpoints if e["normalized_route"] == "/org/{slug}/invite/{token}")
    assert "newly discovered route" not in old_route["interestingness_signals"]
    assert "newly discovered route" in new_route["interestingness_signals"]
    assert "secret-value" not in json.dumps(endpoints)


def test_refresh_inventory_consumes_sanitized_memory_sources(intel_store, mission):
    browser_event = {
        "url": "https://app.example.com/api/users/123?token=[REDACTED]",
        "method": "PATCH",
        "headers": ["content-type"],
        "body_parameter_names": ["role", "user_id"],
        "auth_required": "authenticated",
        "status_code": 204,
    }
    openapi_spec = {
        "spec": {
            "openapi": "3.0.0",
            "paths": {"/billing/invoices/{invoiceId}": {"get": {"operationId": "getInvoice"}}},
        },
        "base_url": "https://api.example.com",
    }
    graphql = {
        "endpoint_url": "https://api.example.com/graphql",
        "operations": [{"type": "mutation", "name": "InviteMember"}],
    }

    refresh_http_inventory_from_store(
        intel_store,
        mission.mission_id,
        browser_events=[browser_event],
        openapi_specs=[openapi_spec],
        graphql_metadata=[graphql],
    )
    endpoints = intel_store.http_endpoints(mission.mission_id)
    operations = intel_store.api_operations(mission.mission_id)

    assert {row["source"] for row in endpoints} == {"browser", "openapi", "graphql"}
    assert any(row["auth_required"] == "authenticated" for row in endpoints)
    assert {row["operation_id"] for row in operations} == {"getInvoice", "InviteMember"}
    assert "secret-value" not in json.dumps(endpoints)


def test_inventory_store_deduplicates_repeated_refreshes(intel_store, mission):
    endpoints = ingest_url_lines(
        "https://api.example.com/api/users/123?include=profile\n",
        mission.mission_id,
        source="gau",
    )

    store_endpoint_inventory(intel_store, endpoints)
    store_endpoint_inventory(intel_store, endpoints)

    assert len(intel_store.http_endpoints(mission.mission_id)) == 1
    assert len(intel_store.http_request_samples(mission.mission_id)) == 1
    assert len(intel_store.response_fingerprints(mission.mission_id)) == 1


def test_inventory_creation_does_not_call_toolbus_or_active_scan(monkeypatch, mission):
    called = False

    async def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("ToolBus.call should not be used by passive inventory")

    monkeypatch.setattr(ToolBus, "call", fail_if_called)

    endpoints = ingest_url_lines(
        "https://example.com/api/users/123\n",
        mission.mission_id,
        source="gau",
    )

    assert len(endpoints) == 1
    assert endpoints[0].method == "GET"
    assert called is False


def test_endpoint_model_is_sqlite_compatible(intel_store, mission):
    endpoint = HttpEndpoint(
        source_agent="test",
        source_tool="manual",
        confidence=0.7,
        mission_id=mission.mission_id,
        method="GET",
        scheme="https",
        host="example.com",
        path="/api/users/123",
        normalized_route="/api/users/{id}",
        query_parameter_names=["user_id"],
    )
    intel_store.write(endpoint)

    rows = intel_store.http_endpoints(mission.mission_id)
    assert len(rows) == 1
    assert rows[0]["host"] == "example.com"
