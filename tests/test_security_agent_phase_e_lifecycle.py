"""Phase E4: Vulnerability & Evidence Lifecycle Test Suite.

Verifies:
1. Formal 11-State Vulnerability Lifecycle State Machine:
   - Permitted transitions across all 11 states:
     DETECTED, TRIAGE, POTENTIAL, CONFIRMED, REMEDIATION_PLANNED,
     REMEDIATION_IN_PROGRESS, READY_FOR_RETEST, REMEDIATION_VERIFIED,
     REFUTED, INCONCLUSIVE, CLOSED.
   - Rejection of illegal transitions with InvalidLifecycleTransitionError.
2. Transition Guards & Secondary Confirmation:
   - CONFIRMED requires independent secondary probe confirmation + evidence reference.
   - REMEDIATION_VERIFIED requires retest verification evidence reference.
   - CLOSED requires explicit administrative justification / explanation.
3. Preservation & Refutation Integrity:
   - REFUTED preserves the finding record and all evidence intact (never deletes).
   - INCONCLUSIVE is never treated as secure or remediated.
4. Regression Re-opening:
   - Reopening REMEDIATION_VERIFIED or CLOSED finding to DETECTED with regression evidence.
5. Evidence Registry & Decision Explainability:
   - Cryptographic evidence authenticity verification.
   - Explainable decision traces (decision_type, rationale, confidence, alternatives).
6. REST API Endpoints:
   - GET /api/security-agent/findings
   - GET /api/security-agent/findings/{finding_id}
   - POST /api/security-agent/findings
   - POST /api/security-agent/findings/{finding_id}/transition
   - GET /api/security-agent/findings/{finding_id}/history
   - GET /api/security-agent/lifecycle/board
   - POST /api/security-agent/decisions
   - POST /api/security-agent/findings/{finding_id}/reopen
"""

from pathlib import Path
import sys
import uuid
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from app.database.session import SessionLocal, get_db
from app.main import app
from app.security_agent.evidence_registry import EvidenceRegistry
from app.security_agent.finding_lifecycle import (
    FindingLifecycleEngine,
    InvalidLifecycleTransitionError,
    PERMITTED_TRANSITIONS,
)
from app.security_agent.models import (
    HttpEvidenceRecord,
    SecurityDecision,
    SecurityFinding,
    SecurityFindingHistory,
    SecurityTestExecution,
)
from app.security_agent.schemas import (
    FindingLifecycleStatusEnum,
    FindingSeverityEnum,
    SecurityDecisionCreate,
    SecurityFindingCreate,
    SecurityFindingUpdate,
    TransitionFindingStateRequest,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def create_test_authenticated_evidence(
    db,
    target_url="http://127.0.0.1:8000/api/chat",
    method="POST",
    execution_id=None,
    request_body='{"message": "test"}',
    response_body='{"status": "ok"}',
    status_code=200,
) -> HttpEvidenceRecord:
    from app.security_agent.crypto import compute_evidence_signature
    exec_id = execution_id or str(uuid.uuid4())
    canonical = f"{target_url}|{method}|{request_body}|{status_code}|{response_body}"
    sig = compute_evidence_signature(canonical)
    ev = HttpEvidenceRecord(
        id=f"ev_{uuid.uuid4().hex[:12]}",
        execution_id=exec_id,
        target_url=target_url,
        http_method=method,
        request_body=request_body,
        response_body=response_body,
        response_status_code=status_code,
        evidence_sha256=sig,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


# =====================================================================
# 1. Finding Creation & Initial Status Tests
# =====================================================================

def test_create_finding_detected_state(db):
    """Test creating a new security finding with initial DETECTED state."""
    req = SecurityFindingCreate(
        scenario_id="LLM01-01",
        risk_id="LLM01",
        title="Direct Prompt Injection Vulnerability in Chatbot",
        description="System prompt boundary override observed in primary chat prompt.",
        affected_endpoint="/api/chat",
        http_method="POST",
        initial_status=FindingLifecycleStatusEnum.DETECTED,
        severity=FindingSeverityEnum.HIGH,
        confidence=0.85,
        cvss_score=7.5,
    )
    finding = FindingLifecycleEngine.create_finding(db=db, data=req)
    assert finding.finding_id.startswith("FIND-LLM01-")
    assert finding.lifecycle_status == FindingLifecycleStatusEnum.DETECTED.value
    assert finding.severity == "HIGH"

    # Verify initial history event recorded
    history = db.query(SecurityFindingHistory).filter(SecurityFindingHistory.finding_id == finding.finding_id).all()
    assert len(history) == 1
    assert history[0].previous_state == "INITIAL"
    assert history[0].new_state == FindingLifecycleStatusEnum.DETECTED.value


def test_create_finding_potential_state(db):
    """Test creating a finding with POTENTIAL status."""
    req = SecurityFindingCreate(
        scenario_id="ASI01-01",
        risk_id="ASI01",
        title="Agent Goal Hijack Anomaly",
        affected_endpoint="/api/agent/run",
        initial_status=FindingLifecycleStatusEnum.POTENTIAL,
        severity=FindingSeverityEnum.CRITICAL,
    )
    finding = FindingLifecycleEngine.create_finding(db=db, data=req)
    assert finding.lifecycle_status == FindingLifecycleStatusEnum.POTENTIAL.value


def test_create_finding_confirmed_requires_evidence(db):
    """Test that creating a finding directly with CONFIRMED without evidence references is blocked."""
    req = SecurityFindingCreate(
        scenario_id="LLM02-01",
        risk_id="LLM02",
        title="Canary Token Disclosure",
        affected_endpoint="/api/chat",
        initial_status=FindingLifecycleStatusEnum.CONFIRMED,
        evidence_references=[],  # No evidence provided!
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        FindingLifecycleEngine.create_finding(db=db, data=req)
    assert "CONFIRMED status requires verified cryptographic evidence" in str(exc_info.value)


# =====================================================================
# 2. Guarded State Machine Transitions Tests
# =====================================================================

def test_valid_transition_detected_to_triage(db):
    """Test transition from DETECTED to TRIAGE."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-02",
            risk_id="LLM01",
            title="Markdown Delimiter Injection",
            affected_endpoint="/api/chat",
        ),
    )
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.TRIAGE,
        transition_reason="Under initial analyst review for reproducibility",
        actor="SecurityAnalyst",
    )
    updated = FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.TRIAGE.value

    # Verify history audit
    hist = db.query(SecurityFindingHistory).filter(SecurityFindingHistory.finding_id == finding.finding_id).all()
    assert len(hist) == 2
    assert hist[1].previous_state == FindingLifecycleStatusEnum.DETECTED.value
    assert hist[1].new_state == FindingLifecycleStatusEnum.TRIAGE.value
    assert hist[1].actor == "SecurityAnalyst"


def test_valid_transition_triage_to_potential(db):
    """Test transition from TRIAGE to POTENTIAL."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-03",
            risk_id="LLM01",
            title="Pseudo-System Framing",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.TRIAGE,
        ),
    )
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.POTENTIAL,
        transition_reason="Observed canary token echo in Turn 1 execution wire probe",
        actor="AutonomousSecurityAgent",
    )
    updated = FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.POTENTIAL.value


def test_potential_to_confirmed_guard_requires_secondary_confirmation(db):
    """Verify that POTENTIAL -> CONFIRMED strictly requires is_secondary_confirmed=True."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-04",
            risk_id="LLM01",
            title="Instruction Override",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.POTENTIAL,
        ),
    )
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Primary probe observed canary",
        evidence_reference="ev_sha256_mock_12345",
        is_secondary_confirmed=False,  # Single-turn anomaly!
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert "requires independent secondary probe confirmation" in str(exc_info.value)


def test_potential_to_confirmed_guard_requires_evidence(db):
    """Verify that POTENTIAL -> CONFIRMED requires a non-empty evidence reference."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-05",
            risk_id="LLM01",
            title="Instruction Override",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.POTENTIAL,
        ),
    )
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Secondary probe confirmed",
        evidence_reference=None,  # No evidence!
        is_secondary_confirmed=True,
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert "requires an attached cryptographic wire evidence reference" in str(exc_info.value)


def test_potential_to_confirmed_success_with_secondary_and_evidence(db):
    """Verify successful transition from POTENTIAL to CONFIRMED when all guards pass."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-06",
            risk_id="LLM01",
            title="Instruction Override",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.POTENTIAL,
        ),
    )
    ev = create_test_authenticated_evidence(db, target_url="http://127.0.0.1:8000/api/chat", method="POST")
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Secondary confirmation probe confirmed full directive hijack with HMAC wire evidence",
        evidence_reference=ev.id,
        is_secondary_confirmed=True,
    )
    updated = FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value
    assert ev.id in updated.evidence_references


def test_confirmed_remediation_lifecycle_progression(db):
    """Verify progression through REMEDIATION_PLANNED -> REMEDIATION_IN_PROGRESS -> READY_FOR_RETEST."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-07",
            risk_id="LLM01",
            title="Prompt Injection",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.POTENTIAL,
        ),
    )
    ev = create_test_authenticated_evidence(db, target_url="http://127.0.0.1:8000/api/chat", method="POST")
    # 1. Confirm
    FindingLifecycleEngine.transition_state(
        db=db,
        finding_id=finding.finding_id,
        request=TransitionFindingStateRequest(
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Confirmed via 2nd probe",
            evidence_reference=ev.id,
            is_secondary_confirmed=True,
        ),
    )
    # 2. Remediation Planned
    FindingLifecycleEngine.transition_state(
        db=db,
        finding_id=finding.finding_id,
        request=TransitionFindingStateRequest(
            target_state=FindingLifecycleStatusEnum.REMEDIATION_PLANNED,
            transition_reason="Architectural delimiter fence directive generated",
        ),
    )
    # 3. Remediation In Progress
    FindingLifecycleEngine.transition_state(
        db=db,
        finding_id=finding.finding_id,
        request=TransitionFindingStateRequest(
            target_state=FindingLifecycleStatusEnum.REMEDIATION_IN_PROGRESS,
            transition_reason="Developer applying input sanitization patch",
        ),
    )
    # 4. Ready For Retest
    updated = FindingLifecycleEngine.transition_state(
        db=db,
        finding_id=finding.finding_id,
        request=TransitionFindingStateRequest(
            target_state=FindingLifecycleStatusEnum.READY_FOR_RETEST,
            transition_reason="Patch deployed to sandbox, ready for verification probe",
        ),
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.READY_FOR_RETEST.value


def test_ready_for_retest_to_remediation_verified_requires_evidence(db):
    """Verify that READY_FOR_RETEST -> REMEDIATION_VERIFIED requires retest evidence."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-08",
            risk_id="LLM01",
            title="Prompt Injection",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.READY_FOR_RETEST,
        ),
    )
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.REMEDIATION_VERIFIED,
        transition_reason="Probe failed to exploit",
        evidence_reference=None,  # Missing evidence!
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert "requires a verified post-mitigation retest evidence reference" in str(exc_info.value)


def test_ready_for_retest_to_remediation_verified_success(db):
    """Verify successful verification of remediation with wire retest evidence."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-09",
            risk_id="LLM01",
            title="Prompt Injection",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.READY_FOR_RETEST,
        ),
    )
    retest_ev = create_test_authenticated_evidence(db, target_url="http://127.0.0.1:8000/api/chat", method="POST")
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.REMEDIATION_VERIFIED,
        transition_reason="Retest execution HTTP probe returned 403 Forbidden with SecurityViolation marker",
        evidence_reference=retest_ev.id,
    )
    updated = FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.REMEDIATION_VERIFIED.value


def test_remediation_verified_to_closed_requires_reason(db):
    """Verify that closing a verified finding requires explicit justification."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-10",
            risk_id="LLM01",
            title="Prompt Injection",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.REMEDIATION_VERIFIED,
        ),
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        FindingLifecycleEngine.validate_transition(
            current_state=FindingLifecycleStatusEnum.REMEDIATION_VERIFIED,
            target_state=FindingLifecycleStatusEnum.CLOSED,
            reason="  ",  # Whitespace / empty reason
        )
    assert "Closure requires an explicit administrative justification" in str(exc_info.value)


def test_remediation_verified_to_closed_success(db):
    """Verify closing a verified finding with formal auditor justification."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-11",
            risk_id="LLM01",
            title="Prompt Injection",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.REMEDIATION_VERIFIED,
        ),
    )
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.CLOSED,
        transition_reason="Formal auditor sign-off: patch verified against complete attack scenario suite",
        actor="LeadSecurityAuditor",
    )
    updated = FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CLOSED.value


# =====================================================================
# 3. Refutation, Inconclusive & Preservation Integrity Tests
# =====================================================================

def test_refuted_transition_preserves_finding_record(db):
    """Verify that transitioning to REFUTED keeps the finding record and history intact (never deletes)."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="ASI02-01",
            risk_id="ASI02",
            title="Suspected Sandbox Escape",
            affected_endpoint="/api/agent/tools",
            initial_status=FindingLifecycleStatusEnum.POTENTIAL,
            evidence_references=["primary_probe_ev_001"],
        ),
    )
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.REFUTED,
        transition_reason="Secondary confirmation probe proved that path traversal was safely neutralized by filesystem jail",
        actor="AutonomousSecurityAgent",
        evidence_reference="refutation_probe_ev_002",
    )
    updated = FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.REFUTED.value

    # Finding record MUST still exist in database
    retrieved = db.query(SecurityFinding).filter(SecurityFinding.finding_id == finding.finding_id).first()
    assert retrieved is not None
    assert retrieved.finding_id == finding.finding_id
    assert "refutation_probe_ev_002" in retrieved.evidence_references

    # History audit trail intact
    hist = db.query(SecurityFindingHistory).filter(SecurityFindingHistory.finding_id == finding.finding_id).all()
    assert len(hist) == 2
    assert hist[1].new_state == FindingLifecycleStatusEnum.REFUTED.value


def test_inconclusive_state_never_treated_as_secure(db):
    """Verify that INCONCLUSIVE is properly tracked and not treated as remediated or closed."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM04-01",
            risk_id="LLM04",
            title="Model Poisoning Probe",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.POTENTIAL,
        ),
    )
    req = TransitionFindingStateRequest(
        target_state=FindingLifecycleStatusEnum.INCONCLUSIVE,
        transition_reason="Target gateway timed out (HTTP 504 Gateway Timeout) during secondary confirmation probe",
    )
    updated = FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.INCONCLUSIVE.value
    assert updated.lifecycle_status != FindingLifecycleStatusEnum.REMEDIATION_VERIFIED.value
    assert updated.lifecycle_status != FindingLifecycleStatusEnum.CLOSED.value


# =====================================================================
# 4. Prohibited State Transitions Tests
# =====================================================================

@pytest.mark.parametrize("from_st, to_st", [
    (FindingLifecycleStatusEnum.DETECTED, FindingLifecycleStatusEnum.CONFIRMED),
    (FindingLifecycleStatusEnum.DETECTED, FindingLifecycleStatusEnum.CLOSED),
    (FindingLifecycleStatusEnum.DETECTED, FindingLifecycleStatusEnum.REMEDIATION_VERIFIED),
    (FindingLifecycleStatusEnum.CONFIRMED, FindingLifecycleStatusEnum.READY_FOR_RETEST),
    (FindingLifecycleStatusEnum.READY_FOR_RETEST, FindingLifecycleStatusEnum.CLOSED),
    (FindingLifecycleStatusEnum.CLOSED, FindingLifecycleStatusEnum.CONFIRMED),
])
def test_illegal_transitions_rejected(db, from_st, to_st):
    """Verify that non-permitted transitions raise InvalidLifecycleTransitionError."""
    ev_list = []
    if from_st == FindingLifecycleStatusEnum.CONFIRMED:
        ev = create_test_authenticated_evidence(db, target_url="http://127.0.0.1:8000/api/chat", method="POST")
        ev_list = [ev.id]

    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-99",
            risk_id="LLM01",
            title="Test Finding",
            affected_endpoint="/api/chat",
            initial_status=from_st,
            evidence_references=ev_list,
        ),
    )
    req = TransitionFindingStateRequest(
        target_state=to_st,
        transition_reason="Attempting illegal leap",
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        FindingLifecycleEngine.transition_state(db=db, finding_id=finding.finding_id, request=req)
    assert "Transition is not permitted by formal lifecycle graph" in str(exc_info.value)


# =====================================================================
# 5. Regression Re-opening Tests
# =====================================================================

def test_reopen_finding_on_regression(db):
    """Verify that a REMEDIATION_VERIFIED or CLOSED finding can be reopened to DETECTED upon regression."""
    finding = FindingLifecycleEngine.create_finding(
        db=db,
        data=SecurityFindingCreate(
            scenario_id="LLM01-12",
            risk_id="LLM01",
            title="Prompt Injection",
            affected_endpoint="/api/chat",
            initial_status=FindingLifecycleStatusEnum.REMEDIATION_VERIFIED,
        ),
    )
    reopened = FindingLifecycleEngine.reopen_finding_on_regression(
        db=db,
        finding_id=finding.finding_id,
        regression_evidence_ref="regression_run_ev_digest_99",
        actor="RegressionExecutionRunner",
    )
    assert reopened.lifecycle_status == FindingLifecycleStatusEnum.DETECTED.value
    assert "regression_run_ev_digest_99" in reopened.evidence_references

    # Verify history event
    hist = db.query(SecurityFindingHistory).filter(SecurityFindingHistory.finding_id == finding.finding_id).all()
    assert hist[-1].previous_state == FindingLifecycleStatusEnum.REMEDIATION_VERIFIED.value
    assert hist[-1].new_state == FindingLifecycleStatusEnum.DETECTED.value
    assert "Regression detected" in hist[-1].transition_reason


# =====================================================================
# 6. Explainable Security Decision Logging Tests
# =====================================================================

def test_explainable_security_decision_logging(db):
    """Verify recording structured, explainable security decisions."""
    dec_data = SecurityDecisionCreate(
        finding_id="FIND-LLM01-test",
        decision_type="DISPATCH_SECONDARY_CONFIRMATION",
        decision_reason="Primary Turn 1 canary disclosure observed. Dispatching secondary confirmation probe.",
        confidence=0.92,
        selected_action="CONFIRMATION_PROBE_MUTATION",
        evidence_references=["ev_wire_digest_001"],
        alternatives_considered=["TERMINATE_AS_POTENTIAL", "FLAG_AS_INCONCLUSIVE"],
        rejection_reasons={"TERMINATE_AS_POTENTIAL": "Insufficient confirmation rigor under E0 policy"},
    )
    dec = FindingLifecycleEngine.record_decision(db=db, data=dec_data)
    assert dec.decision_id.startswith("DEC-")
    assert dec.decision_type == "DISPATCH_SECONDARY_CONFIRMATION"
    assert dec.confidence == 0.92


# =====================================================================
# 7. REST API Endpoints Tests
# =====================================================================

def test_api_create_finding(client):
    """Test POST /api/security-agent/findings."""
    payload = {
        "scenario_id": "API-01",
        "risk_id": "LLM01",
        "title": "API Registered Finding",
        "affected_endpoint": "/api/chat",
        "initial_status": "DETECTED",
        "severity": "HIGH",
    }
    resp = client.post("/api/security-agent/findings", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["finding_id"].startswith("FIND-LLM01-")
    assert data["lifecycle_status"] == "DETECTED"


def test_api_list_findings_filtering(client):
    """Test GET /api/security-agent/findings with status filter."""
    resp = client.get("/api/security-agent/findings", params={"lifecycle_status": "DETECTED"})
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data
    assert "total_count" in data


def test_api_get_finding_by_id(client):
    """Test GET /api/security-agent/findings/{finding_id}."""
    # Create first
    payload = {
        "scenario_id": "API-02",
        "risk_id": "ASI01",
        "title": "Goal Hijacking Finding",
        "affected_endpoint": "/api/agent/run",
        "initial_status": "TRIAGE",
        "severity": "CRITICAL",
    }
    create_resp = client.post("/api/security-agent/findings", json=payload)
    f_id = create_resp.json()["finding_id"]

    resp = client.get(f"/api/security-agent/findings/{f_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["finding_id"] == f_id
    assert len(data["history"]) >= 1


def test_api_transition_finding(client):
    """Test POST /api/security-agent/findings/{finding_id}/transition."""
    # Create
    payload = {
        "scenario_id": "API-03",
        "risk_id": "LLM01",
        "title": "Transition Test",
        "affected_endpoint": "/api/chat",
        "initial_status": "DETECTED",
    }
    create_resp = client.post("/api/security-agent/findings", json=payload)
    f_id = create_resp.json()["finding_id"]

    # Transition to TRIAGE
    tr_payload = {
        "target_state": "TRIAGE",
        "transition_reason": "API transition test under analyst triage",
        "actor": "APITester",
    }
    tr_resp = client.post(f"/api/security-agent/findings/{f_id}/transition", json=tr_payload)
    assert tr_resp.status_code == 200
    assert tr_resp.json()["lifecycle_status"] == "TRIAGE"


def test_api_transition_rejection_error_handling(client):
    """Test POST /api/security-agent/findings/{finding_id}/transition rejects invalid jump."""
    # Create
    payload = {
        "scenario_id": "API-04",
        "risk_id": "LLM01",
        "title": "Illegal Jump Test",
        "affected_endpoint": "/api/chat",
        "initial_status": "DETECTED",
    }
    create_resp = client.post("/api/security-agent/findings", json=payload)
    f_id = create_resp.json()["finding_id"]

    # Attempt illegal transition DETECTED -> CONFIRMED
    tr_payload = {
        "target_state": "CONFIRMED",
        "transition_reason": "Skipping stages",
    }
    tr_resp = client.post(f"/api/security-agent/findings/{f_id}/transition", json=tr_payload)
    assert tr_resp.status_code == 400
    assert "Invalid transition" in tr_resp.json()["detail"]


def test_api_lifecycle_board(client):
    """Test GET /api/security-agent/lifecycle/board."""
    resp = client.get("/api/security-agent/lifecycle/board")
    assert resp.status_code == 200
    data = resp.json()
    assert "columns" in data
    assert len(data["columns"]) == 11
    assert "DETECTED" in data["columns"]
    assert "CONFIRMED" in data["columns"]
    assert "REMEDIATION_VERIFIED" in data["columns"]
    assert "REFUTED" in data["columns"]


def test_api_record_decision(client):
    """Test POST /api/security-agent/decisions."""
    payload = {
        "decision_type": "AUTONOMOUS_CONFIRMATION",
        "decision_reason": "Empirical confirmation probe threshold exceeded",
        "confidence": 0.95,
        "selected_action": "PROMOTE_TO_CONFIRMED",
    }
    resp = client.post("/api/security-agent/decisions", json=payload)
    assert resp.status_code == 201
    assert resp.json()["decision_id"].startswith("DEC-")


def test_api_reopen_on_regression(client):
    """Test POST /api/security-agent/findings/{finding_id}/reopen."""
    payload = {
        "scenario_id": "API-05",
        "risk_id": "LLM01",
        "title": "Reopen Test Finding",
        "affected_endpoint": "/api/chat",
        "initial_status": "REMEDIATION_VERIFIED",
    }
    create_resp = client.post("/api/security-agent/findings", json=payload)
    f_id = create_resp.json()["finding_id"]

    resp = client.post(
        f"/api/security-agent/findings/{f_id}/reopen",
        params={"regression_evidence_ref": "reg_sha_12345", "actor": "NightlyRegressionBot"},
    )
    assert resp.status_code == 200
    assert resp.json()["lifecycle_status"] == "DETECTED"
