"""Phase E4 Authorized Security Defect Remediation Test Suite.

Verifies remediation of all four security defects:
1. SEC-E4-001: Missing Evidence Existence & Cryptographic HMAC Verification
   - Repository existence verification of evidence references.
   - Enforce trust_level == HMAC_VERIFIED via constant-time verification.
   - Reject fabricated, missing, or tampered evidence.
   - Reject unkeyed legacy SHA-256 evidence for confirmation.
   - Primary evidence cryptographic HMAC verification.

2. SEC-E4-002: Missing Finding-to-Evidence Metadata Correlation
   - Target identity / host normalization and matching.
   - Affected endpoint path matching.
   - HTTP method matching.
   - Risk identifier matching.
   - Application context (application_id, environment) matching.
   - Enforce distinct executions (primary_execution_id != secondary_execution_id).

3. SEC-E4-003: Concurrent Lifecycle Transition Race Condition (Optimistic Locking)
   - version_id monotonic tracking on SecurityFinding.
   - Atomic conditional UPDATE checking version_id and current state.
   - Raise ConcurrencyConflictError (HTTP 409 Conflict) on concurrent/stale requests.
   - History entry recorded in the exact same transaction as the state transition.
   - Rollback atomicity on concurrency conflict.

4. SEC-E4-004: Missing Database-Level Audit History Immutability
   - SQLite triggers: prevent_history_update and prevent_history_delete on security_finding_history.
   - Direct raw SQL UPDATE aborted by database engine with error.
   - Direct raw SQL DELETE aborted by database engine with error.
   - Append-only INSERT permitted.
   - Idempotent schema migration.
"""

from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Optional
import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from app.database.session import SessionLocal
from app.main import app
from app.security_agent.crypto import EvidenceTrustLevel, compute_evidence_signature
from app.security_agent.finding_lifecycle import (
    FindingLifecycleEngine,
    InvalidLifecycleTransitionError,
    ConcurrencyConflictError,
)
from app.security_agent.models import (
    AgentExecutionSession,
    HttpEvidenceRecord,
    SecurityDecision,
    SecurityExecutionPlan,
    SecurityFinding,
    SecurityFindingHistory,
    SecurityTestExecution,
    migrate_phase_e4_schema,
)
from app.security_agent.schemas import (
    FindingLifecycleStatusEnum,
    FindingSeverityEnum,
    SecurityFindingCreate,
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


def create_authenticated_evidence(
    db,
    target_url="http://127.0.0.1:8000/api/chat",
    method="POST",
    execution_id=None,
    request_body='{"message": "remediation-test"}',
    response_body='{"status": "exploited"}',
    status_code=200,
) -> HttpEvidenceRecord:
    """Helper to create cryptographically authentic HMAC-SHA256 evidence."""
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


def create_legacy_sha256_evidence(
    db,
    target_url="http://127.0.0.1:8000/api/chat",
    method="POST",
    execution_id=None,
    request_body='{"message": "legacy-test"}',
    response_body='{"status": "exploited"}',
    status_code=200,
) -> HttpEvidenceRecord:
    """Helper to create legacy unkeyed SHA-256 evidence record."""
    exec_id = execution_id or str(uuid.uuid4())
    canonical = f"{target_url}|{method}|{request_body}|{status_code}|{response_body}"
    digest = sha256(canonical.encode("utf-8")).hexdigest()
    ev = HttpEvidenceRecord(
        id=f"ev_legacy_{uuid.uuid4().hex[:10]}",
        execution_id=exec_id,
        target_url=target_url,
        http_method=method,
        request_body=request_body,
        response_body=response_body,
        response_status_code=status_code,
        evidence_sha256=digest,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


def create_test_finding_with_primary_evidence(
    db,
    target_url="http://127.0.0.1:8000/api/chat",
    endpoint="/api/chat",
    method="POST",
    risk_id="LLM01",
    application_id="default",
    environment="sandbox",
    tamper_primary=False,
):
    """Helper to create a finding in POTENTIAL state with valid or tampered primary execution evidence."""
    primary_exec_id = str(uuid.uuid4())
    primary_ev = create_authenticated_evidence(
        db,
        target_url=target_url,
        method=method,
        execution_id=primary_exec_id,
        request_body='{"prompt": "primary attack probe"}',
        response_body='{"result": "unauthorized leak"}',
    )
    if tamper_primary:
        # Tamper with the signature to simulate invalid HMAC
        primary_ev.evidence_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
        db.commit()

    req = SecurityFindingCreate(
        scenario_id="LLM01-REM",
        risk_id=risk_id,
        title="Test Prompt Injection Finding",
        description="Vulnerability under remediation testing.",
        affected_endpoint=endpoint,
        http_method=method,
        target_identity=target_url,
        application_id=application_id,
        environment=environment,
        initial_status=FindingLifecycleStatusEnum.POTENTIAL,
        severity=FindingSeverityEnum.HIGH,
        confidence=0.88,
        cvss_score=8.2,
        execution_id=primary_exec_id,
        evidence_reference=primary_ev.id,
    )
    finding = FindingLifecycleEngine.create_finding(db=db, data=req)
    return finding, primary_ev


def transition_finding(
    db,
    finding_id: str,
    target_state: FindingLifecycleStatusEnum,
    actor: str = "SecurityAgentRemediationVerifier",
    transition_reason: str = "Remediation state transition",
    evidence_reference: Optional[str] = None,
    secondary_execution_id: Optional[str] = None,
    is_secondary_confirmed: bool = False,
    expected_version: Optional[int] = None,
):
    """Helper to perform lifecycle state transition with TransitionFindingStateRequest."""
    req = TransitionFindingStateRequest(
        target_state=target_state,
        actor=actor,
        transition_reason=transition_reason,
        evidence_reference=evidence_reference,
        secondary_execution_id=secondary_execution_id,
        is_secondary_confirmed=is_secondary_confirmed,
        expected_version=expected_version,
    )
    return FindingLifecycleEngine.transition_state(db=db, finding_id=finding_id, request=req)


# =====================================================================
# SECTION 1: SEC-E4-001 — Cryptographic Evidence Authenticity & Verification
# =====================================================================

def test_sec_e4_001_valid_hmac_evidence_confirms_successfully(db):
    """Verify that cryptographically authentic HMAC-SHA256 evidence permits confirmation."""
    finding, _ = create_test_finding_with_primary_evidence(db)
    
    # Create valid secondary evidence with distinct execution ID
    secondary_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db,
        target_url=finding.target_identity,
        method=finding.http_method,
        execution_id=secondary_exec_id,
    )

    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Secondary probe confirmed with authentic HMAC-SHA256 signature.",
        evidence_reference=sec_ev.id,
        secondary_execution_id=secondary_exec_id,
        is_secondary_confirmed=True,
    )

    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value
    assert updated.version_id == 2
    assert updated.secondary_execution_id == secondary_exec_id


def test_sec_e4_001_nonexistent_evidence_reference_rejected(db):
    """Verify that transitioning to CONFIRMED with a non-existent evidence ID is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(db)
    fabricated_id = f"ev_fabricated_{uuid.uuid4().hex[:8]}"

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation with fabricated evidence ID.",
            evidence_reference=fabricated_id,
            secondary_execution_id=str(uuid.uuid4()),
            is_secondary_confirmed=True,
        )

    assert "does not exist in repository" in str(exc_info.value)
    # Ensure state was not modified
    db.refresh(finding)
    assert finding.lifecycle_status == FindingLifecycleStatusEnum.POTENTIAL.value


def test_sec_e4_001_empty_missing_evidence_reference_rejected(db):
    """Verify that transitioning to CONFIRMED without an evidence reference is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(db)

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Missing evidence reference.",
            evidence_reference=None,
            secondary_execution_id=str(uuid.uuid4()),
            is_secondary_confirmed=True,
        )

    assert "requires an attached cryptographic wire evidence reference" in str(exc_info.value)


def test_sec_e4_001_invalid_hmac_signature_rejected(db):
    """Verify that evidence with an invalid/forged HMAC signature is classified as INVALID and rejected."""
    finding, _ = create_test_finding_with_primary_evidence(db)

    # Insert evidence with a forged signature
    secondary_exec_id = str(uuid.uuid4())
    sec_ev = HttpEvidenceRecord(
        id=f"ev_forged_{uuid.uuid4().hex[:8]}",
        execution_id=secondary_exec_id,
        target_url=finding.target_identity,
        http_method=finding.http_method,
        request_body='{"prompt": "attack"}',
        response_body='{"status": "compromised"}',
        response_status_code=200,
        evidence_sha256="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    )
    db.add(sec_ev)
    db.commit()

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation with forged signature.",
            evidence_reference=sec_ev.id,
            secondary_execution_id=secondary_exec_id,
            is_secondary_confirmed=True,
        )

    assert "Requires cryptographically authenticated HMAC-SHA256 evidence" in str(exc_info.value)
    assert "INVALID" in str(exc_info.value)


def test_sec_e4_001_legacy_sha256_rejected_for_confirmation(db):
    """Verify that legacy unkeyed SHA-256 evidence is classified as LEGACY_SHA256_VERIFIED and rejected for CONFIRMED."""
    finding, _ = create_test_finding_with_primary_evidence(db)

    sec_exec_id = str(uuid.uuid4())
    legacy_ev = create_legacy_sha256_evidence(
        db,
        target_url=finding.target_identity,
        method=finding.http_method,
        execution_id=sec_exec_id,
    )

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation with legacy SHA-256.",
            evidence_reference=legacy_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )

    assert "Requires cryptographically authenticated HMAC-SHA256 evidence" in str(exc_info.value)
    assert "LEGACY_SHA256_VERIFIED" in str(exc_info.value)


def test_sec_e4_001_tampered_payload_fails_hmac_verification(db):
    """Verify that tampering with request or response body invalidates HMAC verification and rejects transition."""
    finding, _ = create_test_finding_with_primary_evidence(db)
    
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db,
        target_url=finding.target_identity,
        method=finding.http_method,
        execution_id=sec_exec_id,
        response_body='{"original": "payload"}',
    )

    # Tamper with the response body in the database without recomputing the HMAC
    sec_ev.response_body = '{"tampered": "attacker payload"}'
    db.commit()

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation with tampered payload.",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )

    assert "Requires cryptographically authenticated HMAC-SHA256 evidence" in str(exc_info.value)
    assert "INVALID" in str(exc_info.value)


def test_sec_e4_001_primary_evidence_tampered_rejected(db):
    """Verify that if the primary probe evidence HMAC verification fails, transition to CONFIRMED is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(db, tamper_primary=True)

    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db,
        target_url=finding.target_identity,
        method=finding.http_method,
        execution_id=sec_exec_id,
    )

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation when primary evidence is tampered.",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )

    assert "Primary probe evidence cryptographic verification failed" in str(exc_info.value)


# =====================================================================
# SECTION 2: SEC-E4-002 — Metadata Correlation & Distinct Execution Verification
# =====================================================================

def test_sec_e4_002_identical_primary_and_secondary_execution_rejected(db):
    """Verify that secondary confirmation fails if secondary execution equals primary execution."""
    finding, primary_ev = create_test_finding_with_primary_evidence(db)

    # Attempt to confirm using primary execution ID as secondary execution ID
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting self-confirmation with same execution ID.",
            evidence_reference=primary_ev.id,
            secondary_execution_id=finding.execution_id,
            is_secondary_confirmed=True,
        )

    assert "Independent confirmation requires distinct executions" in str(exc_info.value)


def test_sec_e4_002_mismatched_target_host_rejected(db):
    """Verify that evidence with an unrelated target host is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(
        db,
        target_url="http://127.0.0.1:8000/api/chat",
    )

    sec_exec_id = str(uuid.uuid4())
    unrelated_ev = create_authenticated_evidence(
        db,
        target_url="http://attacker.example.com/api/chat",
        method=finding.http_method,
        execution_id=sec_exec_id,
    )

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation with mismatched host.",
            evidence_reference=unrelated_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )

    assert "Evidence target host" in str(exc_info.value)
    assert "does not match finding target identity" in str(exc_info.value)


def test_sec_e4_002_mismatched_endpoint_path_rejected(db):
    """Verify that evidence with a mismatched endpoint path is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(
        db,
        target_url="http://127.0.0.1:8000/api/chat",
        endpoint="/api/chat",
    )

    sec_exec_id = str(uuid.uuid4())
    different_endpoint_ev = create_authenticated_evidence(
        db,
        target_url="http://127.0.0.1:8000/api/admin/system",
        method=finding.http_method,
        execution_id=sec_exec_id,
    )

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation with mismatched endpoint.",
            evidence_reference=different_endpoint_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )

    assert "Evidence endpoint '/api/admin/system' does not match finding affected endpoint '/api/chat'" in str(exc_info.value)


def test_sec_e4_002_mismatched_http_method_rejected(db):
    """Verify that evidence with a mismatched HTTP method is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(
        db,
        method="POST",
    )

    sec_exec_id = str(uuid.uuid4())
    get_ev = create_authenticated_evidence(
        db,
        target_url=finding.target_identity,
        method="GET",
        execution_id=sec_exec_id,
    )

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation with mismatched HTTP method.",
            evidence_reference=get_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )

    assert "Evidence HTTP method 'GET' does not match finding HTTP method 'POST'" in str(exc_info.value)


def test_sec_e4_002_mismatched_risk_id_rejected(db):
    """Verify that evidence execution linked to a different risk ID is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(
        db,
        risk_id="LLM01",
    )

    sec_exec_id = str(uuid.uuid4())
    session = AgentExecutionSession(
        command="test",
        user_confirmed_authorization=True,
    )
    db.add(session)
    db.commit()

    plan = SecurityExecutionPlan(
        session_id=session.id,
        target_url=finding.target_identity,
    )
    db.add(plan)
    db.commit()

    sec_exec = SecurityTestExecution(
        id=sec_exec_id,
        plan_id=plan.id,
        scenario_id="LLM02-01",
        risk_id="LLM02",
        risk_name="Insecure Output Handling",
        category="OWASP_LLM",
        test_type="injection",
        target_endpoint="/api/chat",
        http_method="POST",
        payload_id="p1",
        status="CONFIRMED",
    )
    db.add(sec_exec)
    db.commit()

    sec_ev = create_authenticated_evidence(
        db,
        target_url=finding.target_identity,
        method="POST",
        execution_id=sec_exec_id,
    )

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation with mismatched risk ID.",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )

    assert "Evidence execution risk 'LLM02' does not match finding risk 'LLM01'" in str(exc_info.value)


def test_sec_e4_002_mismatched_application_context_rejected(db):
    """Verify that evidence execution from a different application context is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(
        db,
        application_id="app_rag_assistant",
        environment="staging",
    )

    session = AgentExecutionSession(
        command="test",
        user_confirmed_authorization=True,
    )
    db.add(session)
    db.commit()

    plan = SecurityExecutionPlan(
        session_id=session.id,
        target_url=finding.target_identity,
        plan_metadata=json.dumps({"application_id": "app_finance_service", "environment": "staging"}),
    )
    db.add(plan)
    db.commit()

    sec_exec_id = str(uuid.uuid4())
    sec_exec = SecurityTestExecution(
        id=sec_exec_id,
        plan_id=plan.id,
        scenario_id="LLM01-01",
        risk_id=finding.risk_id,
        risk_name="Prompt Injection",
        category="OWASP_LLM",
        test_type="injection",
        target_endpoint="/api/chat",
        http_method="POST",
        payload_id="p1",
        status="CONFIRMED",
    )
    db.add(sec_exec)
    db.commit()

    sec_ev = create_authenticated_evidence(
        db,
        target_url=finding.target_identity,
        method="POST",
        execution_id=sec_exec_id,
    )

    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Attempting confirmation with mismatched application context.",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )

    assert "Evidence application ID 'app_finance_service' does not match finding application ID 'app_rag_assistant'" in str(exc_info.value)


# ---------------------------------------------------------------------
# SEC-E4-002-A: Strict URL Scheme Validation Tests
# ---------------------------------------------------------------------

def test_sec_e4_002a_http_finding_https_evidence_rejected(db):
    """Verify HTTP finding rejects HTTPS evidence (cross-protocol replay prevention)."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="http://127.0.0.1:8000/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="https://127.0.0.1:8000/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Testing HTTP/HTTPS scheme mismatch",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "Evidence URL scheme 'https' does not match finding target scheme 'http'" in str(exc_info.value)


def test_sec_e4_002a_https_finding_http_evidence_rejected(db):
    """Verify HTTPS finding rejects HTTP evidence."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="https://example.com/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="http://example.com/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Testing HTTPS/HTTP scheme mismatch",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "Evidence URL scheme 'http' does not match finding target scheme 'https'" in str(exc_info.value)


def test_sec_e4_002a_https_finding_https_evidence_success(db):
    """Verify HTTPS finding accepts matching HTTPS evidence."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="https://example.com/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="https://example.com/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Valid HTTPS confirmation",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


def test_sec_e4_002a_missing_scheme_rejected(db):
    """Verify evidence target without scheme is rejected with controlled error."""
    finding, _ = create_test_finding_with_primary_evidence(db)
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="//example.com/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Missing scheme test",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "Missing URL scheme" in str(exc_info.value)


def test_sec_e4_002a_unsupported_scheme_rejected(db):
    """Verify evidence target with unsupported scheme (e.g. ftp) is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(db)
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="ftp://example.com/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Unsupported scheme test",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "Unsupported scheme 'ftp'" in str(exc_info.value)


# ---------------------------------------------------------------------
# SEC-E4-002-B: Safe Application Context Extraction Tests
# ---------------------------------------------------------------------

def test_sec_e4_002b_context_matching_valid_json(db):
    """Verify valid JSON metadata with matching application_id and environment succeeds."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, application_id="app_rag", environment="staging"
    )
    session = AgentExecutionSession(command="audit test", user_confirmed_authorization=True)
    db.add(session)
    db.commit()
    plan = SecurityExecutionPlan(
        session_id=session.id,
        target_url=finding.target_identity,
        plan_metadata=json.dumps({"application_id": "app_rag", "environment": "staging"}),
    )
    db.add(plan)
    db.commit()
    sec_exec_id = str(uuid.uuid4())
    sec_exec = SecurityTestExecution(
        id=sec_exec_id,
        plan_id=plan.id,
        scenario_id="LLM01-01",
        risk_id=finding.risk_id,
        risk_name="Prompt Injection",
        category="OWASP_LLM",
        test_type="injection",
        target_endpoint="/api/chat",
        http_method="POST",
        payload_id="p1",
        status="CONFIRMED",
    )
    db.add(sec_exec)
    db.commit()
    sec_ev = create_authenticated_evidence(
        db, target_url=finding.target_identity, method="POST", execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Matching JSON context",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


def test_sec_e4_002b_context_matching_valid_dict(db):
    """Verify dictionary metadata in memory matches safely."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, application_id="app_rag", environment="staging"
    )
    # Direct extraction check
    mock_plan = type("MockPlan", (), {"plan_metadata": {"application_id": "app_rag", "environment": "staging", "app_version": "2.0"}})()
    app_id, env, ver = FindingLifecycleEngine._extract_plan_context(mock_plan)
    assert app_id == "app_rag"
    assert env == "staging"
    assert ver == "2.0"

    # Validation through validate_transition with in-memory dict plan
    session = AgentExecutionSession(command="audit test", user_confirmed_authorization=True)
    db.add(session)
    db.commit()
    plan = SecurityExecutionPlan(
        session_id=session.id,
        target_url=finding.target_identity,
        plan_metadata=json.dumps({"placeholder": True}),
    )
    db.add(plan)
    db.commit()
    sec_exec_id = str(uuid.uuid4())
    sec_exec = SecurityTestExecution(
        id=sec_exec_id,
        plan_id=plan.id,
        scenario_id="LLM01-01",
        risk_id=finding.risk_id,
        risk_name="Prompt Injection",
        category="OWASP_LLM",
        test_type="injection",
        target_endpoint="/api/chat",
        http_method="POST",
        payload_id="p1",
        status="CONFIRMED",
    )
    db.add(sec_exec)
    db.commit()

    sec_ev = create_authenticated_evidence(
        db, target_url=finding.target_identity, method="POST", execution_id=sec_exec_id
    )
    plan.plan_metadata = {"application_id": "app_rag", "environment": "staging"}
    FindingLifecycleEngine.validate_transition(
        db=db,
        current_state=FindingLifecycleStatusEnum(finding.lifecycle_status),
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        finding=finding,
        reason="Testing dict context",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )


def test_sec_e4_002b_context_mismatched_environment_rejected(db):
    """Verify mismatched environment in plan metadata is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, application_id="app_rag", environment="staging"
    )
    session = AgentExecutionSession(command="audit test", user_confirmed_authorization=True)
    db.add(session)
    db.commit()
    plan = SecurityExecutionPlan(
        session_id=session.id,
        target_url=finding.target_identity,
        plan_metadata=json.dumps({"application_id": "app_rag", "environment": "production"}),
    )
    db.add(plan)
    db.commit()
    sec_exec_id = str(uuid.uuid4())
    sec_exec = SecurityTestExecution(
        id=sec_exec_id,
        plan_id=plan.id,
        scenario_id="LLM01-01",
        risk_id=finding.risk_id,
        risk_name="Prompt Injection",
        category="OWASP_LLM",
        test_type="injection",
        target_endpoint="/api/chat",
        http_method="POST",
        payload_id="p1",
        status="CONFIRMED",
    )
    db.add(sec_exec)
    db.commit()
    sec_ev = create_authenticated_evidence(
        db, target_url=finding.target_identity, method="POST", execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Mismatched environment test",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "Evidence execution plan environment 'production' does not match finding environment 'staging'" in str(exc_info.value)


def test_sec_e4_002b_context_missing_metadata_fails_closed(db):
    """Verify execution plan with missing metadata fails closed when finding requires context."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, application_id="app_rag", environment="staging"
    )
    session = AgentExecutionSession(command="audit test", user_confirmed_authorization=True)
    db.add(session)
    db.commit()
    plan = SecurityExecutionPlan(
        session_id=session.id,
        target_url=finding.target_identity,
        plan_metadata=None,  # Missing metadata!
    )
    db.add(plan)
    db.commit()
    sec_exec_id = str(uuid.uuid4())
    sec_exec = SecurityTestExecution(
        id=sec_exec_id,
        plan_id=plan.id,
        scenario_id="LLM01-01",
        risk_id=finding.risk_id,
        risk_name="Prompt Injection",
        category="OWASP_LLM",
        test_type="injection",
        target_endpoint="/api/chat",
        http_method="POST",
        payload_id="p1",
        status="CONFIRMED",
    )
    db.add(sec_exec)
    db.commit()
    sec_ev = create_authenticated_evidence(
        db, target_url=finding.target_identity, method="POST", execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Missing metadata test",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "is missing or has invalid application context metadata ('application_id')" in str(exc_info.value)


def test_sec_e4_002b_context_invalid_json_fails_closed(db):
    """Verify execution plan with malformed JSON fails closed without raising unhandled exception."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, application_id="app_rag", environment="staging"
    )
    session = AgentExecutionSession(command="audit test", user_confirmed_authorization=True)
    db.add(session)
    db.commit()
    plan = SecurityExecutionPlan(
        session_id=session.id,
        target_url=finding.target_identity,
        plan_metadata="{invalid_json: true, unterminated",
    )
    db.add(plan)
    db.commit()
    sec_exec_id = str(uuid.uuid4())
    sec_exec = SecurityTestExecution(
        id=sec_exec_id,
        plan_id=plan.id,
        scenario_id="LLM01-01",
        risk_id=finding.risk_id,
        risk_name="Prompt Injection",
        category="OWASP_LLM",
        test_type="injection",
        target_endpoint="/api/chat",
        http_method="POST",
        payload_id="p1",
        status="CONFIRMED",
    )
    db.add(sec_exec)
    db.commit()
    sec_ev = create_authenticated_evidence(
        db, target_url=finding.target_identity, method="POST", execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Invalid JSON metadata test",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "is missing or has invalid application context metadata ('application_id')" in str(exc_info.value)


def test_sec_e4_002b_context_unexpected_metadata_structure_fails_closed(db):
    """Verify execution plan with non-dict JSON (e.g. list or int) fails closed safely."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, application_id="app_rag", environment="staging"
    )
    session = AgentExecutionSession(command="audit test", user_confirmed_authorization=True)
    db.add(session)
    db.commit()
    plan = SecurityExecutionPlan(
        session_id=session.id,
        target_url=finding.target_identity,
        plan_metadata=json.dumps([1, 2, 3, "unexpected"]),
    )
    db.add(plan)
    db.commit()
    sec_exec_id = str(uuid.uuid4())
    sec_exec = SecurityTestExecution(
        id=sec_exec_id,
        plan_id=plan.id,
        scenario_id="LLM01-01",
        risk_id=finding.risk_id,
        risk_name="Prompt Injection",
        category="OWASP_LLM",
        test_type="injection",
        target_endpoint="/api/chat",
        http_method="POST",
        payload_id="p1",
        status="CONFIRMED",
    )
    db.add(sec_exec)
    db.commit()
    sec_ev = create_authenticated_evidence(
        db, target_url=finding.target_identity, method="POST", execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Unexpected structure metadata test",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "is missing or has invalid application context metadata ('application_id')" in str(exc_info.value)


def test_sec_e4_002b_context_plan_absent_handled_safely(db):
    """Verify that when plan is absent, execution proceeds without AttributeError."""
    finding, _ = create_test_finding_with_primary_evidence(db)
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url=finding.target_identity, method="POST", execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Plan absent test",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


# ---------------------------------------------------------------------
# SEC-E4-002-C: Correct Default Port Normalization Tests
# ---------------------------------------------------------------------

def test_sec_e4_002c_default_http_port_80_matches_implicit(db):
    """Verify http://example.com:80 matches http://example.com."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="http://example.com:80/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="http://example.com/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Default HTTP port 80 normalization test",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


def test_sec_e4_002c_default_https_port_443_matches_implicit(db):
    """Verify https://example.com:443 matches https://example.com."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="https://example.com:443/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="https://example.com/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Default HTTPS port 443 normalization test",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


def test_sec_e4_002c_non_default_ports_remain_distinct(db):
    """Verify non-default ports http://example.com:8080 != http://example.com:9090."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="http://example.com:8080/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="http://example.com:9090/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Non-default port distinction test",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "Evidence target host authority 'example.com:9090' does not match finding target identity 'example.com:8080'" in str(exc_info.value)


def test_sec_e4_002c_non_default_https_port_distinct_from_443(db):
    """Verify non-default HTTPS port https://example.com:8443 != https://example.com."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="https://example.com:8443/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="https://example.com/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Non-default HTTPS port distinction test",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "Evidence target host authority 'example.com:443' does not match finding target identity 'example.com:8443'" in str(exc_info.value)


def test_sec_e4_002c_hostname_case_normalization(db):
    """Verify hostname case normalization (http://LOCALHOST:8000 == http://localhost:8000)."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="http://LOCALHOST:8000/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="http://localhost:8000/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Hostname case normalization test",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


def test_sec_e4_002c_endpoint_trailing_slash_normalization(db):
    """Verify endpoint trailing slash normalization (/api/chat/ matches /api/chat)."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="http://127.0.0.1:8000/api/chat/", endpoint="/api/chat/"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="http://127.0.0.1:8000/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Trailing slash normalization test",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


def test_sec_e4_002c_endpoint_query_string_stripped(db):
    """Verify endpoint query strings are stripped during endpoint comparison."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="http://127.0.0.1:8000/api/chat?env=test", endpoint="/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="http://127.0.0.1:8000/api/chat?token=xyz", method=finding.http_method, execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="Query string stripped test",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


def test_sec_e4_002c_endpoint_url_encoded_path(db):
    """Verify URL-encoded path normalization (%20 decoded)."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="http://127.0.0.1:8000/api/chat%20model", endpoint="/api/chat model"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="http://127.0.0.1:8000/api/chat%20model", method=finding.http_method, execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="URL encoded path normalization test",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


def test_sec_e4_002c_invalid_port_range_rejected(db):
    """Verify port value outside valid range (1-65535) is rejected."""
    finding, _ = create_test_finding_with_primary_evidence(db)
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="http://127.0.0.1:99999/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.CONFIRMED,
            transition_reason="Invalid port range test",
            evidence_reference=sec_ev.id,
            secondary_execution_id=sec_exec_id,
            is_secondary_confirmed=True,
        )
    assert "Invalid port value" in str(exc_info.value) or "Port 99999 out of valid TCP range" in str(exc_info.value)


def test_sec_e4_002c_ipv4_and_ipv6_parsing(db):
    """Verify IPv4 and IPv6 URL parsing works correctly without crash."""
    finding, _ = create_test_finding_with_primary_evidence(
        db, target_url="http://[::1]:8000/api/chat"
    )
    sec_exec_id = str(uuid.uuid4())
    sec_ev = create_authenticated_evidence(
        db, target_url="http://[::1]:8000/api/chat", method=finding.http_method, execution_id=sec_exec_id
    )
    updated = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.CONFIRMED,
        transition_reason="IPv6 parsing test",
        evidence_reference=sec_ev.id,
        secondary_execution_id=sec_exec_id,
        is_secondary_confirmed=True,
    )
    assert updated.lifecycle_status == FindingLifecycleStatusEnum.CONFIRMED.value


# =====================================================================
# SECTION 3: SEC-E4-003 — Concurrent Lifecycle Transition Race Condition
# =====================================================================

def test_sec_e4_003_optimistic_locking_prevents_concurrent_overwrite(db):
    """Verify that concurrent conflicting transitions targeting the same expected_version are rejected with ConcurrencyConflictError."""
    req = SecurityFindingCreate(
        scenario_id="LLM01-CONC",
        risk_id="LLM01",
        title="Concurrency Race Condition Test",
        description="Testing optimistic concurrency control.",
        affected_endpoint="/api/chat",
        http_method="POST",
        initial_status=FindingLifecycleStatusEnum.TRIAGE,
    )
    finding = FindingLifecycleEngine.create_finding(db=db, data=req)
    assert finding.version_id == 1

    # Transition 1: advances from TRIAGE -> POTENTIAL, expecting version 1
    t1 = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.POTENTIAL,
        expected_version=1,
        actor="Worker-1",
        transition_reason="Promoted to POTENTIAL by Worker 1",
    )
    assert t1.version_id == 2
    assert t1.lifecycle_status == FindingLifecycleStatusEnum.POTENTIAL.value

    # Transition 2 (concurrent worker): also thought finding was at version 1 and TRIAGE
    with pytest.raises(ConcurrencyConflictError) as exc_info:
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.REFUTED,
            expected_version=1,
            actor="Worker-2",
            transition_reason="Worker 2 trying to refute based on stale state",
        )

    assert "Optimistic lock conflict" in str(exc_info.value)
    assert "expected version 1" in str(exc_info.value)

    # Verify state remains at version 2, POTENTIAL
    db.refresh(finding)
    assert finding.version_id == 2
    assert finding.lifecycle_status == FindingLifecycleStatusEnum.POTENTIAL.value


def test_sec_e4_003_version_id_increments_monotonically(db):
    """Verify that version_id increments strictly by 1 across multiple lifecycle state changes."""
    finding, _ = create_test_finding_with_primary_evidence(db)
    initial_ver = finding.version_id
    assert initial_ver == 1

    # Transition 1: POTENTIAL -> REFUTED
    f1 = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.REFUTED,
        actor="Analyst",
        transition_reason="Refuted during preliminary probe",
    )
    assert f1.version_id == 2

    # Transition 2: REFUTED -> TRIAGE
    f2 = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.TRIAGE,
        actor="LeadAnalyst",
        transition_reason="Re-evaluating refuted finding",
    )
    assert f2.version_id == 3

    # Transition 3: TRIAGE -> POTENTIAL
    f3 = transition_finding(
        db=db,
        finding_id=finding.finding_id,
        target_state=FindingLifecycleStatusEnum.POTENTIAL,
        actor="LeadAnalyst",
        transition_reason="Moved back to potential",
    )
    assert f3.version_id == 4

    # Verify history event count and chronological order
    history = db.query(SecurityFindingHistory).filter(SecurityFindingHistory.finding_id == finding.finding_id).all()
    assert len(history) == 4  # 1 INITIAL + 3 transitions


def test_sec_e4_003_atomic_rollback_on_conflict(db):
    """Verify that a rejected transition performs full rollback leaving no orphaned history."""
    req = SecurityFindingCreate(
        scenario_id="LLM01-ATOMIC",
        risk_id="LLM01",
        title="Atomicity Rollback Test",
        description="Verify rollback on concurrency conflict.",
        affected_endpoint="/api/chat",
        http_method="POST",
        initial_status=FindingLifecycleStatusEnum.TRIAGE,
    )
    finding = FindingLifecycleEngine.create_finding(db=db, data=req)
    
    # Capture initial history count
    initial_hist_count = db.query(SecurityFindingHistory).filter(
        SecurityFindingHistory.finding_id == finding.finding_id
    ).count()

    # Attempt transition with wrong expected_version
    with pytest.raises(ConcurrencyConflictError):
        transition_finding(
            db=db,
            finding_id=finding.finding_id,
            target_state=FindingLifecycleStatusEnum.POTENTIAL,
            expected_version=999,  # Mismatched version
            actor="ErroneousWorker",
            transition_reason="Mismatched version transition",
        )

    # Verify history count did not increment
    new_hist_count = db.query(SecurityFindingHistory).filter(
        SecurityFindingHistory.finding_id == finding.finding_id
    ).count()
    assert new_hist_count == initial_hist_count


def test_sec_e4_003_api_returns_409_conflict_on_stale_version(client, db):
    """Verify that the REST API returns HTTP 409 Conflict when expected_version does not match."""
    finding, _ = create_test_finding_with_primary_evidence(db)
    
    response = client.post(
        f"/api/security-agent/findings/{finding.finding_id}/transition",
        json={
            "target_state": "REFUTED",
            "actor": "APIClient",
            "transition_reason": "Testing API 409 concurrency conflict.",
            "expected_version": 9999,  # Stale version
        },
    )

    assert response.status_code == 409
    body = response.json()
    assert "detail" in body
    assert "Optimistic lock conflict" in body["detail"]


# =====================================================================
# SECTION 4: SEC-E4-004 — Database-Level Audit History Immutability
# =====================================================================

def test_sec_e4_004_sqlite_triggers_installed_in_database(db):
    """Verify that SQLite triggers prevent_history_update and prevent_history_delete exist on security_finding_history."""
    triggers = db.execute(
        text("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'security_finding_history'")
    ).fetchall()

    trigger_names = [t[0] for t in triggers]
    assert "prevent_history_update" in trigger_names
    assert "prevent_history_delete" in trigger_names


def test_sec_e4_004_direct_sql_update_on_history_aborted_by_trigger(db):
    """Verify that direct raw SQL UPDATE on security_finding_history is aborted by database trigger."""
    req = SecurityFindingCreate(
        scenario_id="LLM01-TRIG",
        risk_id="LLM01",
        title="Trigger Immutability Test",
        description="Verify raw SQL UPDATE abort.",
        affected_endpoint="/api/chat",
        http_method="POST",
        initial_status=FindingLifecycleStatusEnum.DETECTED,
    )
    finding = FindingLifecycleEngine.create_finding(db=db, data=req)
    
    hist = db.query(SecurityFindingHistory).filter(
        SecurityFindingHistory.finding_id == finding.finding_id
    ).first()
    assert hist is not None

    # Attempt direct raw SQL UPDATE
    with pytest.raises(DBAPIError) as exc_info:
        db.execute(
            text("UPDATE security_finding_history SET transition_reason = 'tampered' WHERE id = :id"),
            {"id": hist.id},
        )
        db.commit()

    db.rollback()
    assert "security_finding_history is an immutable audit ledger: UPDATE operations are strictly prohibited" in str(exc_info.value)


def test_sec_e4_004_direct_sql_delete_on_history_aborted_by_trigger(db):
    """Verify that direct raw SQL DELETE on security_finding_history is aborted by database trigger."""
    req = SecurityFindingCreate(
        scenario_id="LLM01-TRIG2",
        risk_id="LLM01",
        title="Trigger Immutability Test 2",
        description="Verify raw SQL DELETE abort.",
        affected_endpoint="/api/chat",
        http_method="POST",
        initial_status=FindingLifecycleStatusEnum.DETECTED,
    )
    finding = FindingLifecycleEngine.create_finding(db=db, data=req)
    
    hist = db.query(SecurityFindingHistory).filter(
        SecurityFindingHistory.finding_id == finding.finding_id
    ).first()
    assert hist is not None

    # Attempt direct raw SQL DELETE
    with pytest.raises(DBAPIError) as exc_info:
        db.execute(
            text("DELETE FROM security_finding_history WHERE id = :id"),
            {"id": hist.id},
        )
        db.commit()

    db.rollback()
    assert "security_finding_history is an immutable audit ledger: DELETE operations are strictly prohibited" in str(exc_info.value)


def test_sec_e4_004_migration_idempotency(db):
    """Verify that migrate_phase_e4_schema can be safely re-run multiple times without errors."""
    engine = db.get_bind()
    
    # Run migration twice to verify idempotent trigger and column additions
    migrate_phase_e4_schema(engine)
    migrate_phase_e4_schema(engine)

    # Verify triggers are still present
    triggers = db.execute(
        text("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'security_finding_history'")
    ).fetchall()
    trigger_names = [t[0] for t in triggers]
    assert "prevent_history_update" in trigger_names
    assert "prevent_history_delete" in trigger_names
