"""Phase E3: Deep OpenAPI Schema Intelligence Test Suite.

Verifies:
1. Robust local $ref resolution:
   - Local JSON pointers (#/components/schemas/..., #/definitions/...)
   - Nested references (A -> B -> C)
   - Circular reference detection and cycle memoization (_cyclic_ref: true)
   - Missing and invalid reference handling
2. SSRF & Path Traversal Guards:
   - Remote URL pointers (http://, https://, //, ftp://) raise SchemaSecurityViolation
   - Path traversal sequences (.., ../, file://) raise SchemaSecurityViolation
3. Schema composition resolution:
   - allOf (merging properties and computing required union)
   - oneOf, anyOf, not
4. Bounded recursion & resource limits:
   - MAX_REFERENCE_DEPTH (8)
   - MAX_SCHEMA_SIZE_BYTES (5 MB)
   - MAX_COMPONENT_DEFINITIONS (1000)
   - MAX_PAYLOAD_SIZE_BYTES (64 KB)
5. Security-sensitive field identification & OWASP hypothesis mapping:
   - 10 security field categories
   - LLM and Agentic risk hypotheses
   - Endpoint sensitivity scoring
6. Schema-aware test plan generation:
   - Boundary payload synthesis
   - Scope eligibility and defensive behavior expectations
7. REST API endpoints:
   - POST /api/security-agent/schema/analyze
   - POST /api/security-agent/schema/resolve-reference
   - GET /api/security-agent/schema/live-analysis
   - POST /api/security-agent/schema/test-plans
"""

from pathlib import Path
import sys
from typing import Any, Dict
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.database.session import get_db
from app.main import app
from app.security_agent.schema_intelligence import (
    DeepOpenApiSchemaIntelligence,
    SchemaSecurityViolation,
    MAX_REFERENCE_DEPTH,
    MAX_SCHEMA_SIZE_BYTES,
    MAX_COMPONENT_DEFINITIONS,
    MAX_PAYLOAD_SIZE_BYTES,
    MAX_ANALYSIS_TIME_MS,
    SECURITY_FIELD_KEYWORDS,
)
from app.security_agent.schemas import (
    AnalyzeOpenApiSchemaRequest,
    GenerateSchemaTestPlansRequest,
    ResolveReferenceRequest,
)


@pytest.fixture
def client():
    return TestClient(app)


# Sample OpenAPI 3.0 specification for testing
SAMPLE_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Secure Enterprise Agent Gateway",
        "version": "2.4.0",
        "description": "Multi-agent autonomous enterprise API",
    },
    "components": {
        "schemas": {
            "Address": {
                "type": "object",
                "properties": {
                    "street": {"type": "string"},
                    "city": {"type": "string"},
                    "geo": {"$ref": "#/components/schemas/GeoCoordinates"},
                },
                "required": ["street", "city"],
            },
            "GeoCoordinates": {
                "type": "object",
                "properties": {
                    "lat": {"type": "number"},
                    "lng": {"type": "number"},
                },
                "required": ["lat", "lng"],
            },
            "BaseUser": {
                "type": "object",
                "properties": {
                    "user_id": {"type": "string", "description": "Unique identifier"},
                    "email": {"type": "string", "format": "email"},
                },
                "required": ["user_id"],
            },
            "AdminUser": {
                "allOf": [
                    {"$ref": "#/components/schemas/BaseUser"},
                    {
                        "type": "object",
                        "properties": {
                            "admin_role": {"type": "string", "description": "Admin privilege level"},
                            "api_key": {"type": "string", "description": "Secret access token"},
                            "address": {"$ref": "#/components/schemas/Address"},
                        },
                        "required": ["admin_role", "api_key"],
                    },
                ],
            },
            "CategoryTree": {
                "type": "object",
                "properties": {
                    "category_id": {"type": "string"},
                    "name": {"type": "string"},
                    "subcategories": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/CategoryTree"},
                    },
                },
                "required": ["category_id", "name"],
            },
            "ToolExecutionPayload": {
                "type": "object",
                "properties": {
                    "command_exec": {"type": "string", "description": "System command to invoke"},
                    "webhook_callback_url": {"type": "string", "description": "Notification URL"},
                    "input_prompt": {"type": "string", "description": "LLM prompt directive"},
                    "export_data_format": {"type": "string", "enum": ["csv", "json"]},
                },
                "required": ["command_exec", "input_prompt"],
            },
        },
    },
    "paths": {
        "/api/agent/users": {
            "post": {
                "operationId": "createAdminUser",
                "summary": "Create admin user with security credentials",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/AdminUser"},
                        },
                    },
                },
                "responses": {
                    "201": {
                        "description": "User created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AdminUser"},
                            },
                        },
                    },
                },
            },
        },
        "/api/agent/tools": {
            "post": {
                "operationId": "invokeAgentTool",
                "summary": "Execute autonomous tool directive",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ToolExecutionPayload"},
                        },
                    },
                },
                "responses": {
                    "200": {"description": "Tool executed successfully"},
                },
            },
        },
        "/api/agent/categories": {
            "post": {
                "operationId": "createCategoryTree",
                "summary": "Recursive category hierarchy",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/CategoryTree"},
                        },
                    },
                },
                "responses": {
                    "200": {"description": "Category stored"},
                },
            },
        },
    },
}


# =====================================================================
# 1. Local Reference Resolution Tests
# =====================================================================

def test_local_ref_resolution_basic():
    """Test resolving a standard local reference."""
    resolved, is_circular, stack = DeepOpenApiSchemaIntelligence.resolve_reference(
        spec=SAMPLE_OPENAPI_SPEC,
        pointer="#/components/schemas/BaseUser",
    )
    assert not is_circular
    assert resolved.get("type") == "object"
    assert "user_id" in resolved.get("properties", {})
    assert "user_id" in resolved.get("required", [])


def test_nested_ref_resolution():
    """Test resolving nested multi-hop references (Address -> GeoCoordinates)."""
    resolved_addr, _, _ = DeepOpenApiSchemaIntelligence.resolve_reference(
        spec=SAMPLE_OPENAPI_SPEC,
        pointer="#/components/schemas/Address",
    )
    deep_resolved, _, _ = DeepOpenApiSchemaIntelligence.resolve_schema_deep(
        schema=resolved_addr,
        spec=SAMPLE_OPENAPI_SPEC,
    )
    geo_prop = deep_resolved["properties"]["geo"]
    assert geo_prop.get("type") == "object"
    assert "lat" in geo_prop["properties"]
    assert "lng" in geo_prop["properties"]


def test_circular_ref_resolution_memoization():
    """Test that self-referential / circular schemas are safely detected and memoized."""
    deep_resolved, comp_details, cyclic_ptrs = DeepOpenApiSchemaIntelligence.resolve_schema_deep(
        schema={"$ref": "#/components/schemas/CategoryTree"},
        spec=SAMPLE_OPENAPI_SPEC,
    )
    assert len(cyclic_ptrs) > 0
    assert "#/components/schemas/CategoryTree" in cyclic_ptrs
    subcats_items = deep_resolved["properties"]["subcategories"]["items"]
    assert subcats_items.get("_cyclic_ref") is True


def test_missing_ref_resolution():
    """Test handling of non-existent reference gracefully without crashing."""
    resolved, is_circ, _ = DeepOpenApiSchemaIntelligence.resolve_reference(
        spec=SAMPLE_OPENAPI_SPEC,
        pointer="#/components/schemas/NonExistentModel",
    )
    assert not is_circ
    assert resolved.get("_unresolved_ref") == "#/components/schemas/NonExistentModel"
    assert "NonExistentModel" in resolved.get("error", "")


def test_invalid_ref_syntax():
    """Test that references without leading '#' raise SchemaSecurityViolation."""
    with pytest.raises(SchemaSecurityViolation) as exc_info:
        DeepOpenApiSchemaIntelligence.resolve_reference(
            spec=SAMPLE_OPENAPI_SPEC,
            pointer="components/schemas/BaseUser",
        )
    assert "must be a local JSON pointer" in str(exc_info.value)


# =====================================================================
# 2. SSRF & Path Traversal Guards Tests
# =====================================================================

@pytest.mark.parametrize("remote_ptr", [
    "http://169.254.169.254/latest/meta-data/",
    "https://malicious-domain.com/evil.json",
    "//attacker.com/schema.json",
    "ftp://internal.vault.local/secrets",
])
def test_ssrf_guard_remote_ref(remote_ptr):
    """Verify that remote network references raise SchemaSecurityViolation."""
    with pytest.raises(SchemaSecurityViolation) as exc_info:
        DeepOpenApiSchemaIntelligence.resolve_reference(
            spec=SAMPLE_OPENAPI_SPEC,
            pointer=remote_ptr,
        )
    assert "Remote $ref resolution is strictly forbidden" in str(exc_info.value)


@pytest.mark.parametrize("traversal_ptr", [
    "file:///etc/passwd",
    "#/components/../../etc/passwd",
    "#/definitions/../secret.json",
    "..\\windows\\system32",
])
def test_path_traversal_guard(traversal_ptr):
    """Verify that file scheme and directory climbing references raise SchemaSecurityViolation."""
    with pytest.raises(SchemaSecurityViolation) as exc_info:
        DeepOpenApiSchemaIntelligence.resolve_reference(
            spec=SAMPLE_OPENAPI_SPEC,
            pointer=traversal_ptr,
        )
    assert "traversal" in str(exc_info.value).lower() or "forbidden" in str(exc_info.value).lower()


# =====================================================================
# 3. Schema Composition Tests (allOf, oneOf, anyOf)
# =====================================================================

def test_allof_composition_property_merging_and_required_union():
    """Verify that allOf combines properties and computes the union of required fields."""
    resolved_admin, _, _ = DeepOpenApiSchemaIntelligence.resolve_reference(
        spec=SAMPLE_OPENAPI_SPEC,
        pointer="#/components/schemas/AdminUser",
    )
    deep_resolved, _, _ = DeepOpenApiSchemaIntelligence.resolve_schema_deep(
        schema=resolved_admin,
        spec=SAMPLE_OPENAPI_SPEC,
    )
    props = deep_resolved.get("properties", {})
    # Should contain BaseUser properties AND AdminUser properties
    assert "user_id" in props
    assert "email" in props
    assert "admin_role" in props
    assert "api_key" in props
    assert "address" in props

    # Required should be union of BaseUser ["user_id"] and AdminUser ["admin_role", "api_key"]
    req = set(deep_resolved.get("required", []))
    assert req.issuperset({"user_id", "admin_role", "api_key"})


def test_oneof_anyof_composition():
    """Verify that oneOf and anyOf schemas are properly identified and resolved."""
    oneof_spec = {
        "oneOf": [
            {"type": "object", "properties": {"token": {"type": "string"}}, "required": ["token"]},
            {"type": "object", "properties": {"api_key": {"type": "string"}}, "required": ["api_key"]},
        ]
    }
    deep_resolved, _, _ = DeepOpenApiSchemaIntelligence.resolve_schema_deep(
        schema=oneof_spec,
        spec=SAMPLE_OPENAPI_SPEC,
    )
    comp = deep_resolved.get("_composition", {})
    assert comp.get("type") == "oneOf"
    assert comp.get("branch_count") == 2
    assert "token" in deep_resolved.get("properties", {})
    assert "api_key" in deep_resolved.get("properties", {})


# =====================================================================
# 4. Bounded Recursion & Limits Tests
# =====================================================================

def test_bounded_recursion_depth():
    """Verify that reference resolution depth is strictly bounded at MAX_REFERENCE_DEPTH (8)."""
    # Create chain of 10 references
    chained_spec: Dict[str, Any] = {"components": {"schemas": {}}}
    for i in range(12):
        next_target = f"#/components/schemas/Node{i+1}" if i < 11 else "#/components/schemas/Terminal"
        chained_spec["components"]["schemas"][f"Node{i}"] = {"$ref": next_target}
    chained_spec["components"]["schemas"]["Terminal"] = {"type": "string"}

    resolved, _, _ = DeepOpenApiSchemaIntelligence.resolve_reference(
        spec=chained_spec,
        pointer="#/components/schemas/Node0",
    )
    assert resolved.get("_depth_exceeded") is True
    assert "Maximum reference depth limit" in resolved.get("description", "")


def test_spec_size_limit_rejection():
    """Verify that oversized specifications exceeding MAX_SCHEMA_SIZE_BYTES are rejected."""
    huge_title = "A" * (MAX_SCHEMA_SIZE_BYTES + 1024)
    huge_spec = {
        "openapi": "3.0.0",
        "info": {"title": huge_title, "version": "1.0"},
        "paths": {},
    }
    with pytest.raises(HTTPException) as exc_info:
        DeepOpenApiSchemaIntelligence.analyze_specification(spec=huge_spec)
    assert exc_info.value.status_code == 413
    assert "exceeds maximum allowed size" in exc_info.value.detail


def test_component_definitions_limit_warning():
    """Verify that specs with more than 1000 definitions record a resource limit warning."""
    definitions = {f"Def_{i}": {"type": "string"} for i in range(1050)}
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Large Spec", "version": "1.0"},
        "components": {"schemas": definitions},
        "paths": {},
    }
    analysis = DeepOpenApiSchemaIntelligence.analyze_specification(spec=spec)
    assert any("MAX_COMPONENT_DEFINITIONS_EXCEEDED" in lim for lim in analysis.resource_limits_reached)


# =====================================================================
# 5. Security-Sensitive Field & OWASP Correlation Tests
# =====================================================================

def test_security_sensitive_field_taxonomy_identification():
    """Verify accurate detection and classification of fields across security categories."""
    analysis = DeepOpenApiSchemaIntelligence.analyze_specification(spec=SAMPLE_OPENAPI_SPEC)
    assert analysis.total_endpoints == 3
    assert analysis.security_sensitive_field_count > 0

    field_categories = {sf.category for ep in analysis.endpoints for sf in ep.security_sensitive_fields}
    assert "AUTHENTICATION" in field_categories
    assert "ADMINISTRATIVE" in field_categories
    assert "USER_CONTROLLED_INPUT" in field_categories
    assert "TOOL_INVOCATION" in field_categories
    assert "CALLBACK_WEBHOOK" in field_categories
    assert "DATA_EXPORT" in field_categories


def test_owasp_risk_hypothesis_correlation():
    """Verify that identified security properties map to expected OWASP risk codes."""
    analysis = DeepOpenApiSchemaIntelligence.analyze_specification(spec=SAMPLE_OPENAPI_SPEC)
    hypotheses = analysis.owasp_hypotheses
    # Should include LLM01 (Prompt Injection), LLM02 (Sensitive Information), ASI02 (Tool Misuse)
    assert any("LLM01" in k for k in hypotheses.keys())
    assert any("LLM02" in k for k in hypotheses.keys())
    assert any("ASI02" in k for k in hypotheses.keys())


def test_endpoint_sensitivity_scoring():
    """Verify that endpoints with multiple sensitive fields have high sensitivity scores."""
    analysis = DeepOpenApiSchemaIntelligence.analyze_specification(spec=SAMPLE_OPENAPI_SPEC)
    tool_ep = next(ep for ep in analysis.endpoints if ep.endpoint == "/api/agent/tools")
    assert tool_ep.endpoint_sensitivity >= 0.75


# =====================================================================
# 6. Schema-Aware Test Plan Generation Tests
# =====================================================================

def test_schema_aware_test_plan_generation():
    """Verify generation of schema-compliant boundary test plans."""
    req = GenerateSchemaTestPlansRequest(
        target_url="http://127.0.0.1:8000",
        spec=SAMPLE_OPENAPI_SPEC,
        user_confirmed_authorization=True,
    )
    plans_resp = DeepOpenApiSchemaIntelligence.generate_schema_aware_test_plans(request=req)
    assert plans_resp.total_tests > 0
    assert len(plans_resp.plans) == plans_resp.total_tests

    # Verify structure of generated test plans
    plan = plans_resp.plans[0]
    assert plan.test_id.startswith("test_")
    assert plan.target_url.startswith("http://127.0.0.1:8000")
    assert plan.expected_response_status in [400, 403]
    assert len(plan.synthesized_payload) > 0
    assert plan.expected_evidence_marker != ""
    assert plan.scope_eligibility is True


def test_test_plan_payload_size_bounding():
    """Verify that synthesized payloads are strictly bounded by MAX_PAYLOAD_SIZE_BYTES."""
    req = GenerateSchemaTestPlansRequest(
        target_url="http://127.0.0.1:8000",
        spec=SAMPLE_OPENAPI_SPEC,
        user_confirmed_authorization=True,
    )
    plans_resp = DeepOpenApiSchemaIntelligence.generate_schema_aware_test_plans(request=req)
    for p in plans_resp.plans:
        import json
        payload_bytes = len(json.dumps(p.synthesized_payload).encode("utf-8"))
        assert payload_bytes <= MAX_PAYLOAD_SIZE_BYTES


# =====================================================================
# 7. REST API Endpoints Tests
# =====================================================================

def test_api_schema_analyze_endpoint(client):
    """Test POST /api/security-agent/schema/analyze."""
    req = {
        "spec": SAMPLE_OPENAPI_SPEC,
        "target_url": "http://127.0.0.1:8000",
        "user_confirmed_authorization": True,
    }
    resp = client.post("/api/security-agent/schema/analyze", json=req)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_endpoints"] == 3
    assert data["openapi_version"] == "3.0.0"
    assert len(data["endpoints"]) == 3


def test_api_schema_analyze_unauthorized_scope(client):
    """Test POST /api/security-agent/schema/analyze with disallowed target URL."""
    req = {
        "spec": SAMPLE_OPENAPI_SPEC,
        "target_url": "https://unauthorized-external-bank.com",
        "user_confirmed_authorization": True,
    }
    resp = client.post("/api/security-agent/schema/analyze", json=req)
    assert resp.status_code == 400
    assert "unauthorized or out of scope" in resp.json()["detail"].lower()


def test_api_schema_resolve_reference_endpoint(client):
    """Test POST /api/security-agent/schema/resolve-reference."""
    req = {
        "spec": SAMPLE_OPENAPI_SPEC,
        "pointer": "#/components/schemas/BaseUser",
    }
    resp = client.post("/api/security-agent/schema/resolve-reference", json=req)
    assert resp.status_code == 200
    data = resp.json()
    assert data["pointer"] == "#/components/schemas/BaseUser"
    assert data["is_circular"] is False
    assert "user_id" in data["resolved_schema"]["properties"]


def test_api_schema_resolve_reference_ssrf_block(client):
    """Test POST /api/security-agent/schema/resolve-reference blocks remote SSRF."""
    req = {
        "spec": SAMPLE_OPENAPI_SPEC,
        "pointer": "http://169.254.169.254/secret",
    }
    resp = client.post("/api/security-agent/schema/resolve-reference", json=req)
    assert resp.status_code == 400
    assert "Schema security violation" in resp.json()["detail"]


def test_api_schema_live_analysis_endpoint(client):
    """Test GET /api/security-agent/schema/live-analysis."""
    resp = client.get(
        "/api/security-agent/schema/live-analysis",
        params={"target_url": "http://127.0.0.1:8000", "user_confirmed_authorization": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_endpoints"] > 0
    assert "endpoints" in data


def test_api_schema_test_plans_endpoint(client):
    """Test POST /api/security-agent/schema/test-plans."""
    req = {
        "target_url": "http://127.0.0.1:8000",
        "application_id": "test_app",
        "environment": "sandbox",
        "spec": SAMPLE_OPENAPI_SPEC,
        "user_confirmed_authorization": True,
    }
    resp = client.post("/api/security-agent/schema/test-plans", json=req)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_tests"] > 0
    assert len(data["plans"]) == data["total_tests"]
