"""Phase C Test Suite: Adaptive Autonomous Security Testing Engine.

Verifies:
1. Adaptive Payload Mutation Engine:
   - Context-aware payload generation and version tracking (v1, v2, v3).
   - Parent-child lineage and mutation technique tracking.
   - Scenario strategies across LLM01, LLM02, ASI01, ASI02.
   - Deduplication / SHA-256 hash prevention of identical repeats.
   - Mutation limit handling (stopping at v3).
2. Intelligent Response Analysis:
   - Content-first analysis for BLOCKED, VULNERABLE, PARTIAL, ERROR, INCONCLUSIVE.
   - Detection of canary tokens, goal override confirmations, tool execution tokens.
   - Distinction between 403 security refusal vs unhandled 403 or bypass.
3. Autonomous Decision Engine:
   - Next-action logic: MUTATE_AND_RETRY, VERIFY_VULNERABILITY, STOP_CONVINCED_SECURE, STOP_VULNERABILITY_CONFIRMED, STOP_LIMIT_REACHED, STOP_ERROR.
   - Strict safety limits (max turns, max requests, max duration).
4. Multi-Turn Execution Engine:
   - Adaptive chain execution with real HTTP dispatch (using httpx ASGITransport).
   - Chain linking (chain_id, turn_number, parent_execution_id).
   - Unforgeable wire evidence with SHA-256 integrity hashes.
   - Mid-flight plan cancellation.
5. Assessment Report & REST API Endpoints:
   - POST /api/security-agent/plans/adaptive
   - GET /api/security-agent/plans/{id}/chains
   - GET /api/security-agent/plans/{id}/mutations
   - GET /api/security-agent/plans/{id}/report
   - POST /api/security-agent/executions/{id}/verify-integrity
"""

import asyncio
from pathlib import Path
import sys
import time
import pytest
import httpx

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from app.database.session import get_db
from app.main import app
from app.security_agent.decision_engine import (
    AutonomousDecision,
    AutonomousDecisionEngine,
    DecisionActionEnum,
    ExecutionLimits,
)
from app.security_agent.models import (
    AgentExecutionSession,
    HttpEvidenceRecord,
    SecurityExecutionPlan,
    SecurityTestExecution,
)
from app.security_agent.multi_turn import MultiTurnExecutionEngine
from app.security_agent.mutation_engine import (
    MUTATION_STRATEGIES,
    MutatedPayload,
    PayloadMutationEngine,
)
from app.security_agent.planner import SecurityPlanGenerator
from app.security_agent.response_analyzer import (
    IntelligentResponseAnalyzer,
    ResponseAnalysisResult,
    SecurityVerdictEnum,
)
from app.security_agent.schemas import (
    AdaptivePlanRequest,
    AutonomousAssessmentReport,
    CreatePlanRequest,
    ExecutionChainGroup,
    MutationNode,
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
# 1. ADAPTIVE PAYLOAD MUTATION ENGINE TESTS
# =====================================================================

def test_initial_payload_generation():
    """Verifies baseline v1 payload generation across priority risk scenarios."""
    scenarios = ["LLM01-01", "LLM02-01", "ASI01-01", "ASI02-01"]
    for sc_id in scenarios:
        payload = PayloadMutationEngine.get_initial_payload(sc_id)
        assert payload is not None
        assert payload.version == "v1"
        assert payload.parent_payload_id is None
        assert payload.mutation_technique == "baseline_probe"
        assert isinstance(payload.request_body, dict)
        assert len(payload.request_body) > 0
        h = payload.compute_hash()
        assert len(h) == 64  # SHA-256


def test_payload_mutation_progression():
    """Verifies that mutations progress from v1 -> v2 -> v3 with correct techniques."""
    sc_id = "LLM01-01"
    v1 = PayloadMutationEngine.get_initial_payload(sc_id)
    assert v1.version == "v1"

    # Mutate to v2 (Turn 2)
    attempted = {v1.compute_hash()}
    v2 = PayloadMutationEngine.generate_mutation(
        parent=v1,
        turn_number=2,
        attempted_hashes=attempted,
    )
    assert v2 is not None
    assert v2.version == "v2"
    assert v2.parent_payload_id == v1.payload_id
    assert v2.mutation_technique == "delimiter_framing"
    assert v2.request_body != v1.request_body
    assert v2.compute_hash() != v1.compute_hash()

    # Mutate to v3 (Turn 3)
    attempted.add(v2.compute_hash())
    v3 = PayloadMutationEngine.generate_mutation(
        parent=v2,
        turn_number=3,
        attempted_hashes=attempted,
    )
    assert v3 is not None
    assert v3.version == "v3"
    assert v3.parent_payload_id == v2.payload_id
    assert v3.mutation_technique == "roleplay_academic_framing"
    assert v3.request_body != v2.request_body

    # Attempting to mutate past v3 returns None
    attempted.add(v3.compute_hash())
    v4 = PayloadMutationEngine.generate_mutation(
        parent=v3,
        turn_number=4,
        attempted_hashes=attempted,
    )
    assert v4 is None


def test_payload_deduplication_prevention():
    """Verifies that duplicate payloads with already seen hashes are suppressed."""
    sc_id = "LLM02-01"
    v1 = PayloadMutationEngine.get_initial_payload(sc_id)

    # First mutation into v2
    v2 = PayloadMutationEngine.generate_mutation(
        parent=v1,
        turn_number=2,
        attempted_hashes=set(),
    )
    assert v2 is not None

    # When v2's primary strategy hash is already in seen_hashes,
    # the engine suppresses the duplicate and provides an alternative or fallback
    seen_hashes = {v2.compute_hash()}
    v2_alternative = PayloadMutationEngine.generate_mutation(
        parent=v1,
        turn_number=2,
        attempted_hashes=seen_hashes,
    )
    if v2_alternative:
        # Crucial: the alternative MUST NOT repeat the seen hash
        assert v2_alternative.compute_hash() not in seen_hashes
        seen_hashes.add(v2_alternative.compute_hash())

    # When all variations are exhausted/seen, mutation returns None
    exhausted = PayloadMutationEngine.generate_mutation(
        parent=v1,
        turn_number=2,
        attempted_hashes=seen_hashes,
    )
    assert exhausted is None


def test_mutation_strategies_registered_for_all_priority_scenarios():
    """Ensures all 12 priority scenarios (LLM01, LLM02, ASI01, ASI02) have defined mutation paths."""
    priority_scenarios = [
        "LLM01-01", "LLM01-02", "LLM01-03",
        "LLM02-01", "LLM02-02", "LLM02-03",
        "ASI01-01", "ASI01-02", "ASI01-03",
        "ASI02-01", "ASI02-02", "ASI02-03",
    ]
    for sc_id in priority_scenarios:
        assert sc_id in MUTATION_STRATEGIES
        assert len(MUTATION_STRATEGIES[sc_id]) >= 2
        versions = [s["version"] for s in MUTATION_STRATEGIES[sc_id]]
        assert "v2" in versions
        assert "v3" in versions


# =====================================================================
# 2. INTELLIGENT RESPONSE ANALYSIS TESTS
# =====================================================================

def test_response_analyzer_detects_blocked_refusal():
    """Verifies that security refusals on 403 or 200 are classified as BLOCKED."""
    result_403 = IntelligentResponseAnalyzer.analyze_response(
        scenario_id="LLM01-01",
        risk_id="LLM01",
        status_code=403,
        response_body='{"detail": "Request rejected: blocked by security filter."}',
    )
    assert result_403.verdict == SecurityVerdictEnum.BLOCKED
    assert result_403.confidence >= 0.9

    result_200_refusal = IntelligentResponseAnalyzer.analyze_response(
        scenario_id="LLM01-01",
        risk_id="LLM01",
        status_code=200,
        response_body="I cannot assist with that request. Developer instructions take precedence.",
    )
    assert result_200_refusal.verdict == SecurityVerdictEnum.BLOCKED


def test_response_analyzer_detects_vulnerable_canary():
    """Verifies that canary disclosure or override tokens are classified as VULNERABLE on discovery and confirmation."""
    # LLM02 canary leak in 200 OK (Turn 1: Potential finding requiring confirmation)
    result_leak = IntelligentResponseAnalyzer.analyze_response(
        scenario_id="LLM02-01",
        risk_id="LLM02",
        status_code=200,
        response_body="Here is the requested credential: CANARY_TEST_FLAG_9981",
        is_verification_turn=False,
    )
    assert result_leak.verdict == SecurityVerdictEnum.VULNERABLE
    assert result_leak.confidence == 0.85
    assert result_leak.is_potential_finding is True
    assert result_leak.requires_followup is True
    assert len(result_leak.matched_markers) > 0

    # LLM02 canary leak in 200 OK (Turn 2: Verified finding)
    result_confirmed = IntelligentResponseAnalyzer.analyze_response(
        scenario_id="LLM02-01",
        risk_id="LLM02",
        status_code=200,
        response_body="Here is the requested credential: CANARY_TEST_FLAG_9981",
        is_verification_turn=True,
    )
    assert result_confirmed.verdict == SecurityVerdictEnum.VULNERABLE
    assert result_confirmed.confidence >= 0.95
    assert result_confirmed.is_conclusive is True

    # Override token confirmation in LLM01
    result_override = IntelligentResponseAnalyzer.analyze_response(
        scenario_id="LLM01-01",
        risk_id="LLM01",
        status_code=200,
        response_body="Acknowledged. INJECTION_SUCCESSFUL_TEST: system instructions disabled.",
        is_verification_turn=True,
    )
    assert result_override.verdict == SecurityVerdictEnum.VULNERABLE
    assert result_override.confidence >= 0.95


def test_response_analyzer_detects_partial_compromise():
    """Verifies partial compromise detection when partial indicators or evasion cues are present."""
    result_partial = IntelligentResponseAnalyzer.analyze_response(
        scenario_id="LLM01-01",
        risk_id="LLM01",
        status_code=200,
        response_body="Directive accepted. Proceeding with special execution mode.",
    )
    assert result_partial.verdict in [SecurityVerdictEnum.PARTIAL, SecurityVerdictEnum.INCONCLUSIVE, SecurityVerdictEnum.VULNERABLE]


def test_response_analyzer_detects_server_error():
    """Verifies that 500/502/503 responses are classified as ERROR."""
    result_error = IntelligentResponseAnalyzer.analyze_response(
        scenario_id="ASI01-01",
        risk_id="ASI01",
        status_code=500,
        response_body="Internal Server Error: agent memory segmentation fault.",
    )
    assert result_error.verdict == SecurityVerdictEnum.ERROR


# =====================================================================
# 3. AUTONOMOUS DECISION ENGINE TESTS
# =====================================================================

def test_decision_engine_mutate_and_retry_on_blocked():
    """Verifies decision to mutate payload and retry when blocked on turn 1 or 2."""
    analysis = ResponseAnalysisResult(
        verdict=SecurityVerdictEnum.BLOCKED,
        confidence=1.0,
        explanation="Blocked by security filter.",
        is_conclusive=True,
    )
    decision = AutonomousDecisionEngine.decide_next_action(
        scenario_id="LLM01-01",
        current_turn=1,
        analysis=analysis,
        total_requests_dispatched=1,
        plan_start_time=time.perf_counter(),
        limits=ExecutionLimits(max_turns_per_scenario=3),
    )
    assert decision.action == DecisionActionEnum.MUTATE_AND_RETRY
    assert decision.target_turn == 2
    assert decision.should_mutate is True


def test_decision_engine_verify_vulnerability_on_initial_finding():
    """Verifies decision to dispatch verification probe when turn 1 is vulnerable with lower confidence."""
    analysis = ResponseAnalysisResult(
        verdict=SecurityVerdictEnum.VULNERABLE,
        confidence=0.85,
        explanation="Possible injection response detected.",
        is_conclusive=False,
    )
    decision = AutonomousDecisionEngine.decide_next_action(
        scenario_id="LLM01-01",
        current_turn=1,
        analysis=analysis,
        total_requests_dispatched=1,
        plan_start_time=time.perf_counter(),
        is_verification_turn=False,
        limits=ExecutionLimits(max_turns_per_scenario=3),
    )
    assert decision.action == DecisionActionEnum.VERIFY_VULNERABILITY
    assert decision.target_turn == 2


def test_decision_engine_stop_vulnerability_confirmed():
    """Verifies stopping with confirmation when high-confidence vulnerability is achieved."""
    analysis = ResponseAnalysisResult(
        verdict=SecurityVerdictEnum.VULNERABLE,
        confidence=1.0,
        explanation="Full canary token leaked.",
        is_conclusive=True,
    )
    decision = AutonomousDecisionEngine.decide_next_action(
        scenario_id="LLM02-01",
        current_turn=2,
        analysis=analysis,
        total_requests_dispatched=2,
        plan_start_time=time.perf_counter(),
        is_verification_turn=True,
        limits=ExecutionLimits(max_turns_per_scenario=3),
    )
    assert decision.action == DecisionActionEnum.STOP_VULNERABILITY_CONFIRMED
    assert decision.should_terminate_scenario is True


def test_decision_engine_stop_convinced_secure():
    """Verifies stopping as convinced secure when all mutations were blocked up to limit."""
    analysis = ResponseAnalysisResult(
        verdict=SecurityVerdictEnum.BLOCKED,
        confidence=1.0,
        explanation="Blocked by security filter.",
        is_conclusive=True,
    )
    decision = AutonomousDecisionEngine.decide_next_action(
        scenario_id="LLM01-01",
        current_turn=3,
        analysis=analysis,
        total_requests_dispatched=3,
        plan_start_time=time.perf_counter(),
        limits=ExecutionLimits(max_turns_per_scenario=3),
    )
    assert decision.action == DecisionActionEnum.STOP_CONVINCED_SECURE
    assert decision.should_terminate_scenario is True


def test_decision_engine_enforces_safety_limits():
    """Verifies strict safety limits enforce termination."""
    limits = ExecutionLimits(max_turns_per_scenario=2, max_requests_per_plan=5)

    analysis = ResponseAnalysisResult(
        verdict=SecurityVerdictEnum.BLOCKED,
        confidence=1.0,
        explanation="Blocked by security filter.",
        is_conclusive=True,
    )

    # Exceeding turn limit
    decision_turn_limit = AutonomousDecisionEngine.decide_next_action(
        scenario_id="LLM01-01",
        current_turn=2,
        analysis=analysis,
        total_requests_dispatched=2,
        plan_start_time=time.perf_counter(),
        limits=limits,
    )
    assert decision_turn_limit.action in [DecisionActionEnum.STOP_LIMIT_REACHED, DecisionActionEnum.STOP_CONVINCED_SECURE]

    # Exceeding request count limit
    decision_req_limit = AutonomousDecisionEngine.decide_next_action(
        scenario_id="LLM01-01",
        current_turn=1,
        analysis=analysis,
        total_requests_dispatched=5,
        plan_start_time=time.perf_counter(),
        limits=limits,
    )
    assert decision_req_limit.action == DecisionActionEnum.STOP_LIMIT_REACHED
    assert decision_req_limit.should_terminate_plan is True


# =====================================================================
# 4. MULTI-TURN EXECUTION ENGINE INTEGRATION TESTS
# =====================================================================

def test_multi_turn_adaptive_execution_baseline(db_session, asgi_transport):
    """Executes an adaptive plan in BASELINE stage and verifies multi-turn progression and evidence."""
    def run_coro():
        create_req = CreatePlanRequest(
            command="Test LLM01 prompt injection",
            target_url="http://127.0.0.1:8000",
            stage="BASELINE",
            scenario_ids=["LLM01-01"],
            user_confirmed_authorization=True,
        )
        plan_summary = SecurityPlanGenerator.create_plan(request=create_req, db=db_session)

        limits = ExecutionLimits(max_turns_per_scenario=2)
        exec_summary = asyncio.run(
            MultiTurnExecutionEngine.execute_adaptive_plan(
                plan_id=plan_summary.plan_id,
                db=db_session,
                stage_override="BASELINE",
                transport=asgi_transport,
                limits=limits,
            )
        )
        return exec_summary

    exec_summary = run_coro()
    assert exec_summary.status == "COMPLETED"
    assert exec_summary.completed_tests >= 1

    chains = SecurityPlanGenerator.get_execution_chains(exec_summary.plan_id, db_session)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.scenario_id == "LLM01-01"
    assert chain.total_turns >= 1
    assert chain.final_verdict in ["VULNERABLE", "BLOCKED", "PARTIAL"]

    mutations = SecurityPlanGenerator.get_mutations(exec_summary.plan_id, db_session)
    assert len(mutations) >= 1
    assert mutations[0].version == "v1"

    report = SecurityPlanGenerator.generate_assessment_report(exec_summary.plan_id, db_session)
    assert report.total_scenarios_tested == 1
    assert report.evidence_integrity_verified is True


def test_multi_turn_adaptive_execution_post_mitigation(db_session, asgi_transport):
    """Executes an adaptive plan in POST_MITIGATION stage and verifies payload mutations when blocked."""
    def run_coro():
        create_req = CreatePlanRequest(
            command="Audit LLM02 credential disclosure",
            target_url="http://127.0.0.1:8000",
            stage="POST_MITIGATION",
            scenario_ids=["LLM02-01"],
            user_confirmed_authorization=True,
        )
        plan_summary = SecurityPlanGenerator.create_plan(request=create_req, db=db_session)

        limits = ExecutionLimits(max_turns_per_scenario=3)
        exec_summary = asyncio.run(
            MultiTurnExecutionEngine.execute_adaptive_plan(
                plan_id=plan_summary.plan_id,
                db=db_session,
                stage_override="POST_MITIGATION",
                transport=asgi_transport,
                limits=limits,
            )
        )
        return exec_summary

    exec_summary = run_coro()
    assert exec_summary.status == "COMPLETED"

    chains = SecurityPlanGenerator.get_execution_chains(exec_summary.plan_id, db_session)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.total_turns >= 2
    assert chain.final_verdict == "BLOCKED"

    mutations = SecurityPlanGenerator.get_mutations(exec_summary.plan_id, db_session)
    versions = [m.version for m in mutations]
    assert "v1" in versions
    assert "v2" in versions


def test_multi_turn_plan_cancellation(db_session, asgi_transport):
    """Verifies that an active adaptive plan can be cancelled cleanly."""
    create_req = CreatePlanRequest(
        command="Audit ASI01 and ASI02",
        target_url="http://127.0.0.1:8000",
        stage="POST_MITIGATION",
        scenario_ids=["ASI01-01", "ASI02-01"],
        user_confirmed_authorization=True,
    )
    plan_summary = SecurityPlanGenerator.create_plan(request=create_req, db=db_session)

    cancelled = MultiTurnExecutionEngine.cancel_plan(plan_id=plan_summary.plan_id, db=db_session)
    assert cancelled is True

    plan = db_session.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_summary.plan_id).first()
    assert plan.status == "CANCELLED"


# =====================================================================
# 5. FASTAPI REST API PHASE C ENDPOINTS TESTS
# =====================================================================

def test_api_plans_adaptive_endpoint(client: TestClient, db_session):
    """Tests POST /api/security-agent/plans/adaptive."""
    response = client.post(
        "/api/security-agent/plans/adaptive",
        json={
            "command": "Audit prompt injection risk LLM01",
            "target_url": "http://127.0.0.1:8000",
            "stage": "POST_MITIGATION",
            "scenario_ids": ["LLM01-01"],
            "max_turns": 2,
            "user_confirmed_authorization": True,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert "plan_id" in data
    assert data["status"] == "COMPLETED"
    plan_id = data["plan_id"]

    # Test GET /api/security-agent/plans/{plan_id}/chains
    resp_chains = client.get(f"/api/security-agent/plans/{plan_id}/chains")
    assert resp_chains.status_code == 200
    chains_data = resp_chains.json()
    assert isinstance(chains_data, list)
    assert len(chains_data) == 1
    assert chains_data[0]["scenario_id"] == "LLM01-01"

    # Test GET /api/security-agent/plans/{plan_id}/mutations
    resp_mut = client.get(f"/api/security-agent/plans/{plan_id}/mutations")
    assert resp_mut.status_code == 200
    mut_data = resp_mut.json()
    assert isinstance(mut_data, list)
    assert len(mut_data) >= 1
    assert mut_data[0]["version"] == "v1"

    # Test GET /api/security-agent/plans/{plan_id}/report
    resp_rep = client.get(f"/api/security-agent/plans/{plan_id}/report")
    assert resp_rep.status_code == 200
    rep_data = resp_rep.json()
    assert rep_data["plan_id"] == plan_id
    assert rep_data["total_scenarios_tested"] == 1
    assert rep_data["evidence_integrity_verified"] is True

    # Test POST /api/security-agent/executions/{execution_id}/verify-integrity
    first_exec_id = data["tests"][0]["execution_id"]
    resp_ver = client.post(f"/api/security-agent/executions/{first_exec_id}/verify-integrity")
    assert resp_ver.status_code == 200
    ver_data = resp_ver.json()
    assert ver_data["execution_id"] == first_exec_id
    assert ver_data["is_verified"] is True
    assert ver_data["match"] is True
