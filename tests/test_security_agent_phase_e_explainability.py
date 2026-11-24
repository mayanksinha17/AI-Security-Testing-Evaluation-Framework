"""Dedicated Automated Test Suite for ApexShield Phase E7 — Explainable Security Decision Engine.

Tests:
1. DecisionType enum completeness (7 mandatory decision types).
2. ConfidenceCalculator base weights for all 7 decision types.
3. Rejection of default 1.0 confidence bias (clamping at 0.98).
4. Preservation of uncertainty: missing evidence capped at 0.65.
5. Inconclusive outcome capped at 0.40.
6. Deterministic evidence and alternatives additive bonuses.
7. DecisionRedactor: JWT bearer tokens in free text.
8. DecisionRedactor: API keys and passwords in free text.
9. DecisionRedactor: Basic auth credentials in URL and headers.
10. DecisionRedactor: RSA/EC Private key PEM blocks.
11. DecisionRedactor: Recursive redaction in nested dicts and lists.
12. DecisionRedactor: Sensitive key names masking.
13. Engine: Record RISK_SELECTION decision.
14. Engine: Record TEST_PLANNING decision.
15. Engine: Record PAYLOAD_MUTATION decision.
16. Engine: Record CHAIN_TERMINATION decision.
17. Engine: Record VERDICT_CLASSIFICATION decision.
18. Engine: Record SEVERITY_SCORING decision.
19. Engine: Record REMEDIATION_DIRECTIVE decision.
20. Pre-storage credential sanitization verification in database.
21. Traceability & Rejected alternatives validation.
22. Zero-cascade survival on session deletion (ON DELETE SET NULL).
23. Zero-cascade survival on finding deletion (ON DELETE SET NULL).
24. REST API: POST /api/security-agent/decisions.
25. REST API: POST /api/security-agent/decisions/log.
26. REST API: GET /api/security-agent/decisions list & filtering.
27. REST API: GET /api/security-agent/decisions/{id} (200 & 404).
28. Legacy E4 schema & records backward compatibility.
29. Canonical database baseline records untouched (786 / 138 / 693 / 96).
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

backend_dir = Path(__file__).resolve().parent.parent / "backend"
if not (backend_dir / "app").exists():
    backend_dir = Path(__file__).resolve().parent.parent / "ai-security-poc-phase1" / "backend"
sys.path.insert(0, str(backend_dir))

from app.database.session import SessionLocal
from app.main import app
from app.security_agent.explainability_engine import (
    ConfidenceCalculator,
    DecisionExplainabilityEngine,
    DecisionRedactor,
    DecisionType,
)
from app.security_agent.models import (
    AgentExecutionSession,
    SecurityDecision,
    SecurityFinding,
)


@pytest.fixture
def db_session():
    """Provides a transactional database session for tests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


# =============================================================================
# 1. DECISION TYPES & CONFIDENCE CALCULATOR TESTS
# =============================================================================

def test_decision_types_complete_enum():
    """Verifies all 7 mandatory decision types are present in DecisionType enum."""
    expected = {
        "RISK_SELECTION",
        "TEST_PLANNING",
        "PAYLOAD_MUTATION",
        "CHAIN_TERMINATION",
        "VERDICT_CLASSIFICATION",
        "SEVERITY_SCORING",
        "REMEDIATION_DIRECTIVE",
    }
    actual = {d.value for d in DecisionType}
    assert expected.issubset(actual), f"Missing decision types: {expected - actual}"


def test_confidence_calculator_base_weights():
    """Verifies base confidence weights for each decision type when no extra evidence is present."""
    calc = ConfidenceCalculator()
    for dt in DecisionType:
        score = calc.calculate_confidence(
            decision_type=dt.value,
            evidence_count=1,
            outcome_conclusive=True,
            alternatives_count=0,
        )
        assert 0.0 < score <= 0.98
        assert score >= calc.BASE_CONFIDENCE.get(dt.value, 0.65)


def test_confidence_calculator_rejects_default_1_0():
    """Verifies that confidence calculation never yields 1.0 even with maximum inputs."""
    calc = ConfidenceCalculator()
    score = calc.calculate_confidence(
        decision_type=DecisionType.VERDICT_CLASSIFICATION.value,
        evidence_count=50,
        outcome_conclusive=True,
        alternatives_count=10,
        explicit_confidence=1.0,
    )
    assert score < 1.0, f"Confidence bias failed: score is {score}"
    assert score <= 0.98, "Confidence must be bounded at <= 0.98"


def test_confidence_calculator_missing_evidence_capped():
    """Verifies that missing supporting evidence caps confidence at 0.65."""
    calc = ConfidenceCalculator()
    score = calc.calculate_confidence(
        decision_type=DecisionType.VERDICT_CLASSIFICATION.value,
        evidence_count=0,  # Missing evidence
        outcome_conclusive=True,
        alternatives_count=5,
    )
    assert score <= 0.65, f"Missing evidence cap violated: {score}"


def test_confidence_calculator_inconclusive_outcome_capped():
    """Verifies that inconclusive outcome caps confidence at 0.40."""
    calc = ConfidenceCalculator()
    score = calc.calculate_confidence(
        decision_type=DecisionType.PAYLOAD_MUTATION.value,
        evidence_count=10,
        outcome_conclusive=False,  # Inconclusive outcome
        alternatives_count=3,
    )
    assert score <= 0.40, f"Inconclusive outcome cap violated: {score}"


def test_confidence_calculator_evidence_and_alternatives_bonuses():
    """Verifies deterministic addition of bonuses for evidence and alternatives."""
    calc = ConfidenceCalculator()
    base = calc.calculate_confidence(
        decision_type=DecisionType.TEST_PLANNING.value,
        evidence_count=1,
        outcome_conclusive=True,
        alternatives_count=0,
    )
    boosted = calc.calculate_confidence(
        decision_type=DecisionType.TEST_PLANNING.value,
        evidence_count=3,
        outcome_conclusive=True,
        alternatives_count=2,
    )
    assert boosted > base
    assert boosted <= 0.98


# =============================================================================
# 2. SENSITIVE DATA & CREDENTIAL REDACTION TESTS
# =============================================================================

def test_redactor_jwt_bearer_token():
    """Verifies Bearer JWT tokens in text are sanitized."""
    jwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    text = f"Using authorization header {jwt} to probe endpoint"
    redacted = DecisionRedactor.redact_text(text)
    assert "eyJhbGci" not in redacted
    assert "[REDACTED_BEARER_TOKEN]" in redacted


def test_redactor_api_keys_and_passwords():
    """Verifies API keys and passwords in text strings are redacted."""
    raw = "Failed attempt with api_key=ak_live_998877665544332211 and password=SuperSecretPassword123!"
    redacted = DecisionRedactor.redact_text(raw)
    assert "ak_live_998877665544332211" not in redacted
    assert "SuperSecretPassword123!" not in redacted
    assert "[REDACTED_API_KEY]" in redacted
    assert "[REDACTED_PASSWORD]" in redacted


def test_redactor_basic_auth():
    """Verifies Basic auth in headers and URLs is redacted."""
    raw = "Request dispatched to http://admin:superSecret123@internal.corp.com/v1"
    redacted = DecisionRedactor.redact_text(raw)
    assert "admin:superSecret123@" not in redacted
    assert "[REDACTED_BASIC_AUTH]" in redacted


def test_redactor_private_key_pem():
    """Verifies private key PEM blocks are redacted."""
    raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3...\n-----END RSA PRIVATE KEY-----"
    redacted = DecisionRedactor.redact_text(raw)
    assert "MIIEowIBAAKCAQEA0Y3" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted


def test_redactor_nested_structures():
    """Verifies recursive redaction inside nested dicts and lists."""
    struct = {
        "headers": {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret.signature",
            "X-API-Key": "secret_key_abcdef1234567890",
        },
        "payloads": [
            "Normal query",
            {"nested_cred": "password=MyDatabasePassword1!"},
        ],
    }
    cleaned = DecisionRedactor.redact_structure(struct)
    assert "eyJhbGci" not in str(cleaned)
    assert "secret_key_abcdef1234567890" not in str(cleaned)
    assert "MyDatabasePassword1!" not in str(cleaned)


def test_redactor_sensitive_key_names_masked():
    """Verifies dict keys matching sensitive keywords have their values masked."""
    struct = {
        "client_secret": "raw_secret_value_12345",
        "api_key": "some_random_api_key_str",
    }
    cleaned = DecisionRedactor.redact_structure(struct)
    assert cleaned["client_secret"] == "[REDACTED]"
    assert cleaned["api_key"] == "[REDACTED]"


# =============================================================================
# 3. ENGINE RECORDING & PERSISTENCE TESTS (ALL 7 DECISION TYPES)
# =============================================================================

def test_engine_record_risk_selection_decision(db_session):
    """Verifies recording a RISK_SELECTION decision."""
    engine = DecisionExplainabilityEngine(db_session)
    dec = engine.record_decision(
        decision_type=DecisionType.RISK_SELECTION.value,
        input_context={"target_url": "http://127.0.0.1:8000/api/chat", "model": "gpt-4o"},
        selected_action="Target OWASP-LLM-01: Direct Prompt Injection",
        reasoning_summary="Selected high priority risk based on conversational interface scope.",
        rejected_alternatives=[
            {"action": "Target LLM-07 (Insecure Plugins)", "reason": "No plugins exposed on target"}
        ],
        evidence_references=["scan_artifact_01.json"],
        safety_constraints="Rate limit to 10 req/min",
        provenance="autonomous_engine_v1",
    )
    assert dec["decision_type"] == DecisionType.RISK_SELECTION.value
    assert dec["decision_id"].startswith("DEC-")
    assert dec["confidence"] > 0.0 and dec["confidence"] <= 0.98
    assert len(dec["rejected_alternatives"]) == 1


def test_engine_record_test_planning_decision(db_session):
    """Verifies recording a TEST_PLANNING decision."""
    engine = DecisionExplainabilityEngine(db_session)
    dec = engine.record_decision(
        decision_type=DecisionType.TEST_PLANNING.value,
        input_context={"risk": "OWASP-LLM-01"},
        selected_action="Execute 3-tier jailbreak sequence (Roleplay, Context Ignore, Delimiter Confusion)",
        reasoning_summary="Comprehensive multi-vector jailbreak evaluation selected.",
        rejected_alternatives=[
            {"action": "Single-shot standard payload", "reason": "Insufficient coverage for enterprise guardrail"}
        ],
        evidence_references=["llm_guardrail_spec.json"],
    )
    assert dec["decision_type"] == DecisionType.TEST_PLANNING.value
    assert dec["confidence"] >= 0.70


def test_engine_record_payload_mutation_decision(db_session):
    """Verifies recording a PAYLOAD_MUTATION decision."""
    engine = DecisionExplainabilityEngine(db_session)
    dec = engine.record_decision(
        decision_type=DecisionType.PAYLOAD_MUTATION.value,
        input_context={"previous_payload": "Ignore previous instructions", "status": "BLOCKED"},
        selected_action="Apply Base64 + Unicode homoglyph obfuscation",
        reasoning_summary="Direct keywords blocked by upstream regex filter; applying encoding mutation.",
        rejected_alternatives=[
            {"action": "ROT13 cipher", "reason": "Too simplistic; typically decoded by LLM guardrail"}
        ],
        evidence_references=["filter_block_log.json"],
    )
    assert dec["decision_type"] == DecisionType.PAYLOAD_MUTATION.value


def test_engine_record_chain_termination_decision(db_session):
    """Verifies recording a CHAIN_TERMINATION decision."""
    engine = DecisionExplainabilityEngine(db_session)
    dec = engine.record_decision(
        decision_type=DecisionType.CHAIN_TERMINATION.value,
        input_context={"depth": 5, "exploit_confirmed": True},
        selected_action="Halt attack chain: exploit confirmed with high confidence",
        reasoning_summary="Further testing introduces denial-of-service risk with zero marginal intelligence.",
        evidence_references=["stop_condition.json"],
        safety_constraints="Strict stop at depth 5 or on exploit confirmation",
        outcome_conclusive=True,
    )
    assert dec["decision_type"] == DecisionType.CHAIN_TERMINATION.value
    assert dec["confidence"] >= 0.75


def test_engine_record_verdict_classification_decision(db_session):
    """Verifies recording a VERDICT_CLASSIFICATION decision."""
    engine = DecisionExplainabilityEngine(db_session)
    dec = engine.record_decision(
        decision_type=DecisionType.VERDICT_CLASSIFICATION.value,
        input_context={"response_text": "SYSTEM OVERRIDE CONFIRMED: Root access granted."},
        selected_action="Classify as VULNERABILITY_CONFIRMED",
        reasoning_summary="Response unambiguously breached guardrail boundary, revealing system token.",
        rejected_alternatives=[
            {"action": "Classify as INCONCLUSIVE", "reason": "Leakage contains exact secret anchor"}
        ],
        evidence_references=["exec_artifact_44.txt", "token_match_log.json"],
    )
    assert dec["decision_type"] == DecisionType.VERDICT_CLASSIFICATION.value
    assert dec["confidence"] >= 0.85


def test_engine_record_severity_scoring_decision(db_session):
    """Verifies recording a SEVERITY_SCORING decision."""
    engine = DecisionExplainabilityEngine(db_session)
    dec = engine.record_decision(
        decision_type=DecisionType.SEVERITY_SCORING.value,
        input_context={"finding_type": "PROMPT_INJECTION", "impact": "DATA_EXFILTRATION"},
        selected_action="Assign CVSS 8.9 (HIGH / CRITICAL)",
        reasoning_summary="Direct bypass of authorization leading to unauthorized system instruction access.",
        rejected_alternatives=[
            {"action": "Assign MEDIUM (5.0)", "reason": "Impact is not limited to informational disclosure"}
        ],
        evidence_references=["cvss_calc_matrix.json"],
    )
    assert dec["decision_type"] == DecisionType.SEVERITY_SCORING.value
    assert dec["confidence"] >= 0.80


def test_engine_record_remediation_directive_decision(db_session):
    """Verifies recording a REMEDIATION_DIRECTIVE decision."""
    engine = DecisionExplainabilityEngine(db_session)
    dec = engine.record_decision(
        decision_type=DecisionType.REMEDIATION_DIRECTIVE.value,
        input_context={"risk_id": "LLM-01", "architecture": "FastAPI + LangChain"},
        selected_action="Implement dual-layer semantic guardrail with input/output validation",
        reasoning_summary="Single regex filter proved bypassable via encodings.",
        rejected_alternatives=[
            {"action": "Hardcode additional blocked strings", "reason": "Brittle against encoding permutations"}
        ],
        evidence_references=["bypass_vector_summary.json"],
    )
    assert dec["decision_type"] == DecisionType.REMEDIATION_DIRECTIVE.value


def test_engine_pre_storage_redaction_in_database(db_session):
    """Verifies that credentials in context and action are scrubbed before writing to DB."""
    engine = DecisionExplainabilityEngine(db_session)
    raw_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.topsecret.signature"
    raw_key = "ak_live_1234567890abcdef"

    dec = engine.record_decision(
        decision_type=DecisionType.TEST_PLANNING.value,
        input_context={"auth": raw_token, "key": raw_key},
        selected_action=f"Dispatch request with header {raw_token}",
        reasoning_summary=f"Redact test with {raw_key}",
    )
    # Check returned dictionary
    assert "eyJhbGci" not in json.dumps(dec["input_context"])
    assert "ak_live" not in json.dumps(dec["input_context"])

    # Query DB directly via raw SQL
    row = db_session.query(SecurityDecision).filter_by(decision_id=dec["decision_id"]).first()
    assert row is not None
    assert "eyJhbGci" not in (row.input_context or "")
    assert "ak_live" not in (row.input_context or "")
    assert "eyJhbGci" not in (row.selected_action or "")
    assert "ak_live" not in (row.decision_reason or "")


def test_engine_traceability_and_rejected_alternatives(db_session):
    """Verifies that selected_action, rejected_alternatives, and reasons are completely preserved."""
    engine = DecisionExplainabilityEngine(db_session)
    alts = [
        {"action": "Option A", "reason": "Too slow for real-time evaluation"},
        {"action": "Option B", "reason": "Incompatible with target API schema"},
    ]
    dec = engine.record_decision(
        decision_type=DecisionType.TEST_PLANNING.value,
        input_context={"param": "test"},
        selected_action="Option C (Adaptive Genetic Fuzzing)",
        reasoning_summary="Balances speed and semantic divergence.",
        rejected_alternatives=alts,
        safety_constraints="Timeout 30s",
        provenance="planner_module_v2",
    )
    assert len(dec["rejected_alternatives"]) == 2
    assert dec["rejected_alternatives"][0]["reason"] == "Too slow for real-time evaluation"
    assert dec["safety_constraints"] == "Timeout 30s"
    assert dec["provenance"] == "planner_module_v2"


# =============================================================================
# 4. ZERO-CASCADE SURVIVAL & ARCHIVAL INDEPENDENCE
# =============================================================================

def test_engine_zero_cascade_session_deletion(db_session):
    """Verifies that deleting an AgentExecutionSession sets session_id=NULL on decisions (ON DELETE SET NULL)."""
    db_session.execute(text("PRAGMA foreign_keys = ON;"))
    try:
        # 1. Create a dummy session
        session_id = f"test-sess-{uuid.uuid4().hex[:8]}"
        sess = AgentExecutionSession(id=session_id, command="Security testing session", status="ACTIVE")
        db_session.add(sess)
        db_session.commit()

        # 2. Record a decision referencing this session
        engine = DecisionExplainabilityEngine(db_session)
        dec = engine.record_decision(
            decision_type=DecisionType.RISK_SELECTION.value,
            input_context={"test": True},
            selected_action="Test action",
            session_id=session_id,
        )
        dec_id = dec["decision_id"]

        # 3. Delete the session
        db_session.delete(sess)
        db_session.commit()

        # 4. Verify decision survives with session_id set to None
        persisted = db_session.query(SecurityDecision).filter_by(decision_id=dec_id).first()
        assert persisted is not None, "Decision was cascade-deleted when session was removed!"
        assert persisted.session_id is None, "session_id was not set to NULL upon session deletion!"
    finally:
        db_session.execute(text("PRAGMA foreign_keys = OFF;"))
        db_session.commit()


def test_engine_zero_cascade_finding_deletion(db_session):
    """Verifies that deleting a SecurityFinding sets finding_id=NULL on decisions (ON DELETE SET NULL)."""
    db_session.execute(text("PRAGMA foreign_keys = ON;"))
    try:
        # 1. Create a session and finding
        sess_id = f"test-sess-f-{uuid.uuid4().hex[:8]}"
        sess = AgentExecutionSession(id=sess_id, command="Finding deletion test session", status="COMPLETED")
        db_session.add(sess)
        db_session.commit()

        f_id = f"FIND-DEL-{uuid.uuid4().hex[:6]}"
        finding = SecurityFinding(
            id=str(uuid.uuid4()),
            session_id=sess_id,
            finding_id=f_id,
            scenario_id="SCEN-001",
            title="Test Finding For Deletion",
            risk_id="LLM-01",
            affected_endpoint="/api/query",
            severity="HIGH",
            lifecycle_status="CONFIRMED",
        )
        db_session.add(finding)
        db_session.commit()

        # 2. Record decision linking to finding
        engine = DecisionExplainabilityEngine(db_session)
        dec = engine.record_decision(
            decision_type=DecisionType.VERDICT_CLASSIFICATION.value,
            input_context={"evidence": "test"},
            selected_action="Classify finding",
            finding_id=f_id,
        )
        dec_id = dec["decision_id"]

        # 3. Delete finding
        db_session.delete(finding)
        db_session.commit()

        # 4. Verify decision survives with finding_id set to None
        persisted = db_session.query(SecurityDecision).filter_by(decision_id=dec_id).first()
        assert persisted is not None, "Decision was cascade-deleted when finding was removed!"
        assert persisted.finding_id is None, "finding_id was not set to NULL upon finding deletion!"
    finally:
        db_session.execute(text("PRAGMA foreign_keys = OFF;"))
        db_session.commit()


# =============================================================================
# 5. REST API ENDPOINT TESTS
# =============================================================================

def test_api_post_decision(client):
    """Verifies POST /api/security-agent/decisions creates a decision and returns 201."""
    payload = {
        "decision_type": "RISK_SELECTION",
        "input_context": {"endpoint": "/api/v1/generate"},
        "selected_action": "Target system prompt extraction",
        "reasoning_summary": "High value attack target.",
        "rejected_alternatives": [{"action": "Skip", "reason": "Not acceptable"}],
        "evidence_references": ["artifact_1.json"],
        "safety_constraints": "Max 5 attempts",
        "provenance": "rest_api_test",
    }
    resp = client.post("/api/security-agent/decisions", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["decision_id"].startswith("DEC-")
    assert data["decision_type"] == "RISK_SELECTION"
    assert data["confidence"] > 0.0


def test_api_post_decision_log_alias(client):
    """Verifies POST /api/security-agent/decisions/log creates a decision."""
    payload = {
        "decision_type": "PAYLOAD_MUTATION",
        "input_context": {"input": "test payload"},
        "selected_action": "Apply Unicode Leetspeak",
        "reasoning_summary": "Bypass lexical filters.",
    }
    resp = client.post("/api/security-agent/decisions/log", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["decision_id"].startswith("DEC-")
    assert data["decision_type"] == "PAYLOAD_MUTATION"


def test_api_get_decisions_list_and_filters(client):
    """Verifies GET /api/security-agent/decisions returns paginated list and respects filters."""
    # Create test decision with unique provenance
    prov = f"test_filter_{uuid.uuid4().hex[:6]}"
    client.post("/api/security-agent/decisions", json={
        "decision_type": "SEVERITY_SCORING",
        "input_context": {"filter_marker": prov},
        "selected_action": "Score 7.5",
        "reasoning_summary": "Filter test",
        "provenance": prov,
    })

    # Query with decision_type filter
    resp = client.get("/api/security-agent/decisions?decision_type=SEVERITY_SCORING&limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "decisions" in data
    assert "total" in data
    assert any(d["decision_type"] == "SEVERITY_SCORING" for d in data["decisions"])


def test_api_get_decision_by_id_and_404(client):
    """Verifies GET /api/security-agent/decisions/{decision_id} returns 200 for valid and 404 for missing."""
    # 1. Create a decision
    create_resp = client.post("/api/security-agent/decisions", json={
        "decision_type": "REMEDIATION_DIRECTIVE",
        "input_context": {"check": "by_id"},
        "selected_action": "Apply patch",
        "reasoning_summary": "Test by id",
    })
    dec_id = create_resp.json()["decision_id"]

    # 2. Retrieve existing
    get_resp = client.get(f"/api/security-agent/decisions/{dec_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["decision_id"] == dec_id

    # 3. Retrieve non-existent
    bad_resp = client.get("/api/security-agent/decisions/DEC-NONEXISTENT-999")
    assert bad_resp.status_code == 404


def test_backward_compatibility_existing_decisions(db_session):
    """Verifies that query_decisions and DB models handle legacy Phase E4 records without errors."""
    engine = DecisionExplainabilityEngine(db_session)
    res = engine.query_decisions(limit=50)
    assert res["total"] >= 10, f"Expected at least 10 pre-existing decisions, found {res['total']}"
    # Verify legacy decisions format cleanly
    for dec in res["decisions"]:
        assert "decision_id" in dec
        assert "decision_type" in dec
        assert "confidence" in dec
        assert isinstance(dec["rejected_alternatives"], list)


# =============================================================================
# 6. CANONICAL DATABASE BASELINE IMMUTABILITY
# =============================================================================

def test_canonical_database_records_untouched():
    """Guarantees that canonical baseline records in ai_security_poc.db remain untouched."""
    db_candidates = [
        Path("_backups/canonical_db/ai_security_poc.db").resolve(),
        Path("ai-security-poc-phase1/_backups/canonical_db/ai_security_poc.db").resolve(),
        Path("../ai_security_poc.db").resolve(),
        Path("ai_security_poc.db").resolve(),
    ]
    db_path = next((p for p in db_candidates if p.exists() and "canonical_db" in str(p)), None)
    if not db_path:
        db_path = next((p for p in db_candidates if p.exists()), None)

    uri = f"file:{db_path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    cursor = conn.cursor()

    cursor.execute("SELECT count(*) FROM attack_results;")
    c_attack = cursor.fetchone()[0]

    cursor.execute("SELECT count(*) FROM model_comparisons;")
    c_models = cursor.fetchone()[0]

    cursor.execute("SELECT count(*) FROM security_audit_logs;")
    c_logs = cursor.fetchone()[0]

    cursor.execute("SELECT count(*) FROM evaluation_runs;")
    c_eval = cursor.fetchone()[0]

    conn.close()

    assert c_attack == 786, f"Expected 786 attack_results, got {c_attack}"
    assert c_models == 138, f"Expected 138 model_comparisons, got {c_models}"
    assert c_logs == 693, f"Expected 693 security_audit_logs, got {c_logs}"
    assert c_eval == 96, f"Expected 96 evaluation_runs, got {c_eval}"

# =============================================================================
# 7. SEC-E7-001 REMEDIATION REGRESSION TESTS (MANDATORY 10 TESTS)
# =============================================================================

def test_remediation_sec_e7_001_external_provenance_tagged(client):
    """1. External provenance is automatically prefixed with 'external_api:' or tagged 'external_api:unspecified'."""
    # Test custom external provenance
    resp1 = client.post("/api/security-agent/decisions", json={
        "decision_type": "RISK_SELECTION",
        "selected_action": "Target boundary probe",
        "reasoning_summary": "Assessing external API prefixing.",
        "provenance": "third_party_scanner",
    })
    assert resp1.status_code == 201
    assert resp1.json()["provenance"] == "external_api:third_party_scanner"

    # Test missing / empty provenance
    resp2 = client.post("/api/security-agent/decisions", json={
        "decision_type": "RISK_SELECTION",
        "selected_action": "Target boundary probe",
        "reasoning_summary": "Assessing unspecified external API tagging.",
    })
    assert resp2.status_code == 201
    assert resp2.json()["provenance"] == "external_api:unspecified"


def test_remediation_sec_e7_001_internal_provenance_cannot_be_impersonated(client):
    """2. Internal provenance names (AutonomousSecurityAgent, ExplainabilityEngine_v1, etc.) cannot be impersonated via public API."""
    spoofed_names = [
        "AutonomousSecurityAgent",
        "ExplainabilityEngine_v1",
        "autonomous_agent_v1",
        "Autonomous_Scanner",
        "internal",
    ]
    for spoofed in spoofed_names:
        resp = client.post("/api/security-agent/decisions", json={
            "decision_type": "PAYLOAD_MUTATION",
            "selected_action": "Mutate payload",
            "reasoning_summary": "Testing impersonation prevention.",
            "provenance": spoofed,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["provenance"] == "external_api:unspecified", f"Spoofed provenance '{spoofed}' was not sanitized!"


def test_remediation_sec_e7_001_client_high_confidence_cannot_bypass_verification(client):
    """3. Client-supplied high confidence cannot bypass verification without verified evidence."""
    resp = client.post("/api/security-agent/decisions", json={
        "decision_type": "VERDICT_CLASSIFICATION",
        "selected_action": "Classify critical vulnerability",
        "reasoning_summary": "Claiming maximum confidence without DB evidence.",
        "confidence": 0.99,
        "evidence_references": ["non_existent_wire_evidence_123"],
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["confidence"] <= 0.50, f"Client high confidence bypassed verification! Got {data['confidence']}"


def test_remediation_sec_e7_001_unverified_external_confidence_capped_at_050(client):
    """4. Unverified external confidence is strictly capped at 0.50."""
    resp = client.post("/api/security-agent/decisions", json={
        "decision_type": "SEVERITY_SCORING",
        "selected_action": "Assign critical severity 9.8",
        "reasoning_summary": "External caller with unverified evidence list.",
        "confidence": 0.85,
        "evidence_references": ["fake_evidence_ref_a", "fake_evidence_ref_b"],
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["confidence"] <= 0.50


def test_remediation_sec_e7_001_verified_evidence_follows_legitimate_confidence_calculation(db_session, client):
    """5. Verified evidence in DB allows legitimate confidence calculation above 0.50."""
    from app.security_agent.models import HttpEvidenceRecord
    ev_id = f"ev_test_{uuid.uuid4().hex[:8]}"
    ev_record = HttpEvidenceRecord(
        id=ev_id,
        execution_id=f"exec_{uuid.uuid4().hex[:8]}",
        target_url="http://test-service/api/login",
        http_method="POST",
        evidence_sha256="abc123sha256hashdummy",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(ev_record)
    db_session.commit()

    try:
        resp = client.post("/api/security-agent/decisions", json={
            "decision_type": "VERDICT_CLASSIFICATION",
            "selected_action": "Confirm SQLi vulnerability",
            "reasoning_summary": "Confirmed with verified DB evidence.",
            "evidence_references": [ev_id],
            "alternatives_considered": ["Alternative benign"],
            "rejection_reasons": {"Alternative benign": "Payload caused SQL error"},
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["confidence"] > 0.50, f"Expected verified confidence > 0.50, got {data['confidence']}"
    finally:
        db_session.delete(ev_record)
        db_session.commit()


def test_remediation_sec_e7_001_missing_evidence_preserves_uncertainty(client):
    """6. Ingested decision with missing evidence preserves uncertainty (capped at <= 0.50)."""
    resp = client.post("/api/security-agent/decisions", json={
        "decision_type": "CHAIN_TERMINATION",
        "selected_action": "Halt attack chain",
        "reasoning_summary": "Missing evidence requires uncertainty preservation.",
        "evidence_references": [],
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["confidence"] <= 0.50


def test_remediation_sec_e7_001_inconclusive_outcomes_retain_confidence_cap(db_session):
    """7. Inconclusive outcomes retain their confidence cap (<= 0.40)."""
    decision = DecisionExplainabilityEngine.record_decision(
        db=db_session,
        decision_type="TEST_PLANNING",
        selected_action="Probe inconclusive behavior",
        reasoning_summary="Outcome was inconclusive.",
        outcome_conclusive=False,
        is_external=True,
    )
    assert decision.confidence <= 0.40, f"Inconclusive outcome exceeded 0.40 cap: {decision.confidence}"


def test_remediation_sec_e7_001_both_public_ingestion_endpoints_enforce_protections(client):
    """8. Both public endpoints (POST /decisions and POST /decisions/log) enforce identical provenance & confidence protections."""
    endpoints = ["/api/security-agent/decisions", "/api/security-agent/decisions/log"]
    for ep in endpoints:
        resp = client.post(ep, json={
            "decision_type": "RISK_SELECTION",
            "selected_action": "Select risk target",
            "reasoning_summary": f"Testing endpoint parity on {ep}.",
            "provenance": "AutonomousSecurityAgent",
            "confidence": 0.95,
        })
        assert resp.status_code == 201, f"{ep} failed with status {resp.status_code}"
        data = resp.json()
        assert data["provenance"] == "external_api:unspecified", f"{ep} failed to sanitize provenance!"
        assert data["confidence"] <= 0.50, f"{ep} failed to cap unverified confidence! Got {data['confidence']}"


def test_remediation_sec_e7_001_existing_historical_decisions_remain_readable(db_session, client):
    """9. Existing historical decisions remain readable with preserved provenance and confidence."""
    hist_id = f"DEC-HIST-{uuid.uuid4().hex[:8]}"
    hist_dec = SecurityDecision(
        decision_id=hist_id,
        decision_type="SEVERITY_SCORING",
        selected_action="Legacy historical rating",
        decision_reason="Historical decision created prior to remediation.",
        confidence=0.92,
        provenance="AutonomousSecurityAgent",
        decision_timestamp=datetime.now(timezone.utc),
    )
    db_session.add(hist_dec)
    db_session.commit()

    try:
        resp = client.get(f"/api/security-agent/decisions/{hist_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision_id"] == hist_id
        assert data["confidence"] == 0.92, "Historical confidence was corrupted!"
        assert data["provenance"] == "AutonomousSecurityAgent", "Historical provenance was corrupted!"
    finally:
        db_session.delete(hist_dec)
        db_session.commit()


def test_remediation_sec_e7_001_existing_e4_decision_lifecycle_intact(db_session):
    """10. Internal callers (AutonomousSecurityAgent) continue to compute legitimate uninhibited confidence."""
    internal_dec = DecisionExplainabilityEngine.record_decision(
        db=db_session,
        decision_type=DecisionType.TEST_PLANNING,
        selected_action="Internal autonomous plan execution",
        reasoning_summary="Autonomous internal security agent execution.",
        evidence_references=["internal_trace_1", "internal_trace_2"],
        alternatives_considered=["Direct exploit", "Stealth probe"],
        rejection_reasons={"Direct exploit": "Too noisy", "Stealth probe": "Slower coverage"},
        provenance="AutonomousSecurityAgent",
        is_external=False,
    )
    assert internal_dec.provenance == "AutonomousSecurityAgent"
    assert internal_dec.confidence > 0.50, f"Internal confidence was incorrectly capped! Got {internal_dec.confidence}"

