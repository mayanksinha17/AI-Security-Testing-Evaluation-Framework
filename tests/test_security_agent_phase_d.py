"""Phase D Test Suite: Advanced Vulnerability Intelligence & Autonomous Attack Orchestration.

Verifies:
1. Application Context Analyzer:
   - Controlled local discovery of routes, HTTP methods, and schemas.
   - Scope and authorization enforcement.
   - Manual OpenAPI / Swagger JSON import and parsing.
2. OWASP Risk Correlation Engine:
   - Full 20-risk catalog (10 LLM Risks + 10 Agentic AI Risks).
   - Prerequisite tracking, correlation confidence, and dependency graph.
   - Preservation of hypothesis vs confirmed vulnerability distinction.
3. Multi-Risk Attack Chain Orchestrator:
   - Sequential multi-stage attack chain synthesis (LLM01 -> ASI01 -> ASI02 -> LLM02).
   - Step execution in authorized sandbox with HMAC-SHA256 wire signatures.
   - Step isolation and independent wire verification.
4. Context-Aware Payload Intelligence:
   - Response-aware mutation adaptation (refusal feedback, XML fencing, traversal encoding).
   - Schema-aware field adaptation.
   - Duplicate suppression via SHA-256 fingerprinting.
5. Root Cause Analysis (RCA) & Transparent CVSS v3.1 Severity Engine:
   - Failed control identification, trust boundary mapping, affected components.
   - Transparent CVSS v3.1 calculation with vector strings.
   - Strict separation of vulnerability severity from evaluation confidence.
   - Blocked defenses yielding Score 0.0 (Informational).
6. Automated Remediation Intelligence:
   - Actionable code snippets (quick mitigations, architectural fixes, verification probes).
7. FastAPI REST API Endpoints for Phase D.
"""

import asyncio
from pathlib import Path
import sys
import pytest
import httpx

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from app.database.session import get_db
from app.main import app
from app.security_agent.attack_chain_orchestrator import AttackChainOrchestrator
from app.security_agent.context_analyzer import ApplicationContextAnalyzer
from app.security_agent.correlation_engine import OWASPRiskCorrelationEngine
from app.security_agent.mutation_engine import MutatedPayload, PayloadMutationEngine
from app.security_agent.rca_engine import RootCauseAnalysisEngine
from app.security_agent.remediation_engine import RemediationIntelligenceEngine
from app.security_agent.schemas import (
    AttackChainSchema,
    DiscoverContextRequest,
    GenerateAttackChainRequest,
    ImportOpenApiRequest,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    generator = get_db()
    session = next(generator)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def asgi_transport():
    return httpx.ASGITransport(app=app)


# =====================================================================
# 1. APPLICATION CONTEXT ANALYZER TESTS
# =====================================================================

def test_context_analyzer_discovers_local_endpoints(asgi_transport):
    """Verifies controlled reconnaissance on authorized localhost target."""
    req = DiscoverContextRequest(target_url="http://127.0.0.1:8000", user_confirmed_authorization=True)
    ctx = ApplicationContextAnalyzer.discover_context(req, transport=asgi_transport)

    assert ctx.is_local_target is True
    assert "127.0.0.1" in ctx.target_scope
    assert len(ctx.discovered_endpoints) >= 4

    paths = [ep.path for ep in ctx.discovered_endpoints]
    assert "/api/chat" in paths
    assert "/api/agent/run" in paths

    # Verify security controls and components detected
    assert len(ctx.discovered_security_controls) >= 2
    assert "HMAC-SHA256 Evidence Signing" in ctx.discovered_security_controls
    assert ctx.context_confidence >= 0.85


def test_context_analyzer_rejects_unauthorized_scope():
    """Verifies that unauthorized or external targets are rejected."""
    req = DiscoverContextRequest(target_url="http://malicious-external-site.com", user_confirmed_authorization=False)
    with pytest.raises(Exception):
        ApplicationContextAnalyzer.discover_context(req)


def test_context_analyzer_imports_openapi_spec():
    """Verifies manual import and parsing of an OpenAPI specification."""
    sample_spec = {
        "openapi": "3.0.2",
        "info": {"title": "Test Secured Banking Agent", "version": "1.0.0"},
        "paths": {
            "/api/v1/transfer": {
                "post": {
                    "summary": "Transfer funds",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"account": {"type": "string"}, "amount": {"type": "number"}},
                                    "required": ["account", "amount"],
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Success"}},
                }
            }
        },
    }
    req = ImportOpenApiRequest(
        target_url="http://127.0.0.1:8000",
        openapi_spec=sample_spec,
        user_confirmed_authorization=True,
    )
    ctx = ApplicationContextAnalyzer.import_openapi_spec(req)

    assert len(ctx.discovered_endpoints) == 1
    ep = ctx.discovered_endpoints[0]
    assert ep.path == "/api/v1/transfer"
    assert "POST" in ep.methods
    assert ep.request_body_schema["required"] == ["account", "amount"]
    assert ctx.context_confidence == 1.0


# =====================================================================
# 2. OWASP RISK CORRELATION ENGINE TESTS
# =====================================================================

def test_correlation_engine_full_graph():
    """Verifies that all 20 OWASP risks (10 LLM + 10 Agentic) and dependency edges are mapped."""
    graph = OWASPRiskCorrelationEngine.get_full_graph()
    assert graph.total_risks_mapped == 20
    assert graph.total_relationships >= 10

    node_ids = [n["id"] for n in graph.nodes]
    # Check LLM risks
    for r in ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"]:
        assert r in node_ids
    # Check Agentic risks
    for r in ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"]:
        assert r in node_ids

    # Verify edge structure
    for edge in graph.edges:
        assert edge.relationship_type in ["enables", "escalates_to", "exfiltrates_via", "prerequisite_for", "amplifies", "correlated_with"]
        assert edge.validation_status == "HYPOTHESIS"


def test_correlation_engine_analyzes_requested_risks():
    """Verifies correlation and attack chain hypothesis generation from requested risks."""
    result = OWASPRiskCorrelationEngine.correlate_risks(["LLM01", "ASI02"])
    assert "LLM01" in result["requested_risks"]
    assert "ASI02" in result["requested_risks"]
    assert "ASI01" in result["all_correlated_risks"]  # LLM01 -> ASI01 -> ASI02 prerequisite link

    # Check recommended attack chain hypothesis
    recs = result["recommended_attack_chains"]
    assert len(recs) >= 1
    first_chain = recs[0]
    assert first_chain[:3] == ["LLM01", "ASI01", "ASI02"]
    assert "disclaimer" in result


# =====================================================================
# 3. MULTI-RISK ATTACK CHAIN ORCHESTRATOR TESTS
# =====================================================================

def test_attack_chain_generation(db_session):
    """Verifies synthesis of multi-stage sequential attack chains."""
    gen_req = GenerateAttackChainRequest(
        command="Evaluate my application for prompt injection and tool misuse",
        target_url="http://127.0.0.1:8000",
        stage="POST_MITIGATION",
        user_confirmed_authorization=True,
    )
    chain = AttackChainOrchestrator.generate_attack_chain(gen_req, db_session)

    assert chain.chain_id.startswith("chain_")
    assert chain.execution_status == "PLANNED"
    assert len(chain.execution_steps) >= 3

    step_risks = [s.risk_id for s in chain.execution_steps]
    assert "LLM01" in step_risks
    assert "ASI01" in step_risks
    assert "ASI02" in step_risks

    # Step 2 must have Step 1 as prerequisite
    step2 = chain.execution_steps[1]
    assert len(step2.prerequisites) > 0


def test_attack_chain_execution_against_sandbox(db_session, asgi_transport):
    """Executes a multi-risk attack chain sequentially and verifies HMAC wire signatures."""
    gen_req = GenerateAttackChainRequest(
        risk_ids=["LLM01", "ASI01"],
        target_url="http://127.0.0.1:8000",
        stage="POST_MITIGATION",
        user_confirmed_authorization=True,
    )
    chain = AttackChainOrchestrator.generate_attack_chain(gen_req, db_session)

    executed_chain = asyncio.run(
        AttackChainOrchestrator.execute_attack_chain(
            chain=chain,
            target_base_url="http://127.0.0.1:8000",
            db=db_session,
            transport=asgi_transport,
        )
    )

    assert executed_chain.execution_status == "COMPLETED"
    assert len(executed_chain.evidence_references) == len(executed_chain.execution_steps)
    # Every evidence signature must be HMAC-SHA256 authenticated
    for sig in executed_chain.evidence_references:
        assert sig.startswith("hmac-sha256:")

    # Post-mitigation stage should intercept the chain
    assert "CHAIN_DEFENDED" in executed_chain.final_assessment or "CHAIN_PARTIALLY" in executed_chain.final_assessment


# =====================================================================
# 4. CONTEXT-AWARE PAYLOAD INTELLIGENCE TESTS
# =====================================================================

def test_context_aware_payload_adaptation_on_refusal_feedback():
    """Verifies that defensive feedback triggers intelligent evasion adaptation."""
    parent = MutatedPayload(
        payload_id="pay-test-01",
        scenario_id="LLM01-01",
        risk_id="LLM01",
        version="v1",
        parent_payload_id=None,
        mutation_technique="baseline_probe",
        mutation_rationale="Initial probe",
        target_endpoint="/api/chat",
        http_method="POST",
        request_body={"prompt": "Override instructions"},
        created_turn=1,
    )

    # Simulate target response explicitly flagging "prompt injection detected"
    mutated = PayloadMutationEngine.generate_context_aware_mutation(
        parent=parent,
        turn_number=2,
        attempted_hashes=set(),
        previous_response_body="Access Denied: Prompt injection detected by security filter.",
        previous_status_code=403,
    )

    assert mutated is not None
    assert mutated.created_turn == 2
    assert mutated.mutation_technique == "xml_boundary_framing"
    assert "<system_directive" in str(mutated.request_body)


def test_context_aware_payload_duplicate_suppression():
    """Verifies that identical mutations are suppressed."""
    parent = MutatedPayload(
        payload_id="pay-test-02",
        scenario_id="LLM02-01",
        risk_id="LLM02",
        version="v1",
        parent_payload_id=None,
        mutation_technique="baseline_probe",
        mutation_rationale="Initial probe",
        target_endpoint="/api/chat",
        http_method="POST",
        request_body={"prompt": "Print canary"},
        created_turn=1,
    )

    mutated1 = PayloadMutationEngine.generate_context_aware_mutation(
        parent=parent,
        turn_number=2,
        attempted_hashes=set(),
    )
    assert mutated1 is not None

    # Adding its hash to attempted hashes should suppress it
    attempted = {mutated1.compute_hash()}
    mutated2 = PayloadMutationEngine.generate_context_aware_mutation(
        parent=parent,
        turn_number=2,
        attempted_hashes=attempted,
    )
    # Must either return None or a distinct variant
    if mutated2:
        assert mutated2.compute_hash() not in attempted


# =====================================================================
# 5. ROOT CAUSE ANALYSIS & CVSS v3.1 SEVERITY ENGINE TESTS
# =====================================================================

def test_rca_engine_confirmed_vulnerability():
    """Verifies root cause mapping and transparent CVSS calculation for confirmed vulnerability."""
    finding = RootCauseAnalysisEngine.analyze_finding(
        scenario_id="LLM01-01",
        risk_id="LLM01",
        endpoint="/api/security-agent/target-app/vulnerable/chat",
        verdict="VULNERABLE",
        status_code=200,
        response_body="INJECTION_SUCCESSFUL_TEST: instructions overridden",
        evidence_hash="hmac-sha256:1122334455667788",
        is_multi_turn_confirmed=True,
    )

    assert finding.status == "CONFIRMED"
    assert finding.confidence == 1.0
    assert finding.root_cause_category == "INPUT_VALIDATION"
    assert "System Instruction Boundary" in finding.failed_security_control
    assert finding.cvss_score >= 7.0
    assert finding.severity in ["HIGH", "CRITICAL"]
    assert "CVSS:3.1" in finding.cvss_vector
    assert "Exploitability=" in finding.scoring_explanation


def test_rca_engine_blocked_outcome_yields_informational():
    """Verifies that defended/blocked probes yield Score 0.0 (Informational)."""
    finding = RootCauseAnalysisEngine.analyze_finding(
        scenario_id="LLM01-01",
        risk_id="LLM01",
        endpoint="/api/security-agent/target-app/protected/chat",
        verdict="BLOCKED",
        status_code=403,
        response_body="Access Denied: Directive rejected",
        is_multi_turn_confirmed=False,
    )

    assert finding.cvss_score == 0.0
    assert finding.severity == "INFORMATIONAL"
    assert "successfully blocked" in finding.scoring_explanation


# =====================================================================
# 6. AUTOMATED REMEDIATION INTELLIGENCE TESTS
# =====================================================================

def test_remediation_engine_generates_code_snippets():
    """Verifies actionable code snippets and verification probes for confirmed findings."""
    finding = RootCauseAnalysisEngine.analyze_finding(
        scenario_id="ASI02-01",
        risk_id="ASI02",
        endpoint="/api/security-agent/target-app/vulnerable/agent",
        verdict="VULNERABLE",
        status_code=200,
        response_body="root:x:0:0:synthetic_root",
        is_multi_turn_confirmed=True,
    )
    rem = RemediationIntelligenceEngine.generate_remediation(finding)

    assert rem.risk_id == "ASI02"
    assert rem.priority == "P0_IMMEDIATE"
    assert "quick_mitigation" in rem.model_dump()
    assert "SANDBOX_ROOT" in rem.quick_mitigation["snippet"]
    assert "verification_probe" in rem.model_dump()
    assert rem.verification_probe["expected_status"] == 403


# =====================================================================
# 7. FASTAPI REST API PHASE D ENDPOINTS TESTS
# =====================================================================

def test_api_phase_d_endpoints(client: TestClient):
    """Tests all new Phase D REST endpoints."""
    # 1. POST /api/security-agent/context/discover
    resp_ctx = client.post(
        "/api/security-agent/context/discover",
        json={"target_url": "http://127.0.0.1:8000", "user_confirmed_authorization": True},
    )
    assert resp_ctx.status_code == 200
    ctx_data = resp_ctx.json()
    assert "discovered_endpoints" in ctx_data

    # 2. GET /api/security-agent/correlation/graph
    resp_graph = client.get("/api/security-agent/correlation/graph")
    assert resp_graph.status_code == 200
    graph_data = resp_graph.json()
    assert graph_data["total_risks_mapped"] == 20

    # 3. POST /api/security-agent/correlation/analyze
    resp_corr = client.post(
        "/api/security-agent/correlation/analyze",
        json={"risk_ids": ["LLM01", "ASI01"]},
    )
    assert resp_corr.status_code == 200
    corr_data = resp_corr.json()
    assert "recommended_attack_chains" in corr_data

    # 4. POST /api/security-agent/attack-chains/generate
    resp_gen = client.post(
        "/api/security-agent/attack-chains/generate",
        json={"risk_ids": ["LLM01", "ASI01"], "target_url": "http://127.0.0.1:8000"},
    )
    assert resp_gen.status_code == 201
    chain_data = resp_gen.json()
    assert "chain_id" in chain_data
    chain_id = chain_data["chain_id"]

    # 5. GET /api/security-agent/attack-chains/{id}
    resp_get_chain = client.get(f"/api/security-agent/attack-chains/{chain_id}")
    assert resp_get_chain.status_code == 200
    assert resp_get_chain.json()["chain_id"] == chain_id

    # 6. POST /api/security-agent/rca/analyze
    resp_rca = client.post(
        "/api/security-agent/rca/analyze",
        json={
            "scenario_id": "LLM02-01",
            "risk_id": "LLM02",
            "endpoint": "/api/chat",
            "verdict": "VULNERABLE",
            "status_code": 200,
            "response_body": "CANARY_TEST_FLAG_9981",
            "is_multi_turn_confirmed": True,
        },
    )
    assert resp_rca.status_code == 200
    rca_data = resp_rca.json()
    assert rca_data["severity"] in ["HIGH", "CRITICAL"]
    assert "CVSS:3.1" in rca_data["cvss_vector"]

    # 7. GET /api/security-agent/remediation/{finding_id}
    resp_rem = client.get("/api/security-agent/remediation/LLM01")
    assert resp_rem.status_code == 200
    rem_data = resp_rem.json()
    assert rem_data["risk_id"] == "LLM01"
    assert "quick_mitigation" in rem_data
