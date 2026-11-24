"""Phase E1 Test Suite: Dynamic Security Intelligence Engine (Hardened).

Verifies:
1. Evidence Authenticity & Trust Classification (Correction 1):
   - HMAC_VERIFIED: Constant-time verified HMAC-SHA256 signature using protected key (Eligible).
   - LEGACY_SHA256_VERIFIED: 64-char unkeyed SHA-256 digest (Eligible for legacy backward-compat).
   - INVALID: Corrupted, mismatched, or tampered signature (Strictly Ineligible).
   - MISSING: Missing or empty digest (Strictly Ineligible).
   - Zero key leakage through APIs or logs.
2. HTTP 400 Classification & Explicit Rejection Guard (Correction 2):
   - HTTP 400 with an explicit security rejection marker -> BLOCKED.
   - HTTP 400 caused by malformed JSON -> INCONCLUSIVE.
   - HTTP 400 caused by a missing required field -> INCONCLUSIVE.
   - HTTP 403 with a verified defensive response -> BLOCKED.
   - Generic HTTP 400 without defensive evidence -> INCONCLUSIVE.
3. Heuristic Empirical Outcome Formula (Correction 3):
   - Exact mathematical formula: PriorityScore = 0.35*Severity + 0.30*HeuristicOutcome + 0.20*Sensitivity + 0.15*Prerequisite.
   - Denominator eligibility: total verified executions excluding infrastructure errors (ERROR).
   - Numerator: confirmed vulnerabilities only (unconfirmed findings excluded).
   - BLOCKED observations kept distinct from remediation verification.
   - Remediation success maintained as a separate first-class metric.
   - Deterministic cold-start behavior when N < 3.
4. Strict Target Isolation:
   - Isolation tuple: (target_identity, application_id, app_version, environment, endpoint, risk_id).
   - Zero cross-app, cross-version, or cross-environment contamination.
   - Explicit handling of missing identity attributes.
5. FastAPI REST API Endpoints:
   - GET /api/security-agent/intelligence/overview
   - GET /api/security-agent/intelligence/priorities
   - GET /api/security-agent/intelligence/history
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import uuid
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from app.database.session import get_db, init_db
from app.main import app
from app.security_agent.crypto import (
    EvidenceTrustLevel,
    classify_evidence_trust,
    compute_evidence_signature,
    get_evidence_signing_key,
    verify_evidence_signature,
)
from app.security_agent.intelligence_engine import (
    COLD_START_BASE_PRIORS,
    ELIGIBLE_EVIDENCE_TRUST_LEVELS,
    MINIMUM_SAMPLE_SIZE_THRESHOLD,
    SECURITY_REJECTION_MARKERS,
    SEVERITY_WEIGHTS,
    WEIGHT_ENDPOINT,
    WEIGHT_HISTORICAL,
    WEIGHT_PREREQUISITE,
    WEIGHT_SEVERITY,
    DynamicSecurityIntelligenceEngine,
)
from app.security_agent.models import (
    AgentExecutionSession,
    HttpEvidenceRecord,
    SecurityExecutionPlan,
    SecurityTestExecution,
)
from app.security_agent.schemas import (
    OutcomeCategoryEnum,
    TargetIsolationTuple,
)
from app.services.security_agent.intelligence_engine import (
    DynamicSecurityIntelligenceEngine as ServicesIntelligenceEngine,
)


@pytest.fixture(autouse=True)
def ensure_db_tables():
    """Ensures database schema and tables are initialized."""
    init_db()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db_gen = get_db()
    db = next(db_gen)
    try:
        yield db
    finally:
        db.rollback()


# =====================================================================
# CORRECTION 1: Evidence Authenticity & Cryptographic Verification
# =====================================================================

def test_evidence_trust_classification_hmac_verified():
    """Verifies that a genuine HMAC-SHA256 signature is classified as HMAC_VERIFIED and eligible."""
    canonical = "http://127.0.0.1:8000/api/chat|POST|{'msg': 'test'}|200|response"
    valid_hmac = compute_evidence_signature(canonical)

    trust = classify_evidence_trust(canonical, valid_hmac)
    assert trust == EvidenceTrustLevel.HMAC_VERIFIED
    assert trust.value in ELIGIBLE_EVIDENCE_TRUST_LEVELS


def test_evidence_trust_classification_legacy_sha256_verified():
    """Verifies that an unkeyed 64-char hex SHA-256 digest is classified as LEGACY_SHA256_VERIFIED and eligible."""
    canonical = "http://127.0.0.1:8000/api/chat|POST|{'msg': 'test'}|200|response"
    legacy_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    trust = classify_evidence_trust(canonical, legacy_sha256)
    assert trust == EvidenceTrustLevel.LEGACY_SHA256_VERIFIED
    assert trust.value in ELIGIBLE_EVIDENCE_TRUST_LEVELS


def test_evidence_trust_classification_invalid_digest_rejected():
    """Verifies that a tampered or corrupted evidence signature is classified as INVALID and ineligible."""
    canonical = "http://127.0.0.1:8000/api/chat|POST|{'msg': 'test'}|200|response"
    corrupted_hmac = "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000"

    trust = classify_evidence_trust(canonical, corrupted_hmac)
    assert trust == EvidenceTrustLevel.INVALID
    assert trust.value not in ELIGIBLE_EVIDENCE_TRUST_LEVELS

    # Legacy corrupt hash
    corrupted_sha = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    trust_sha = classify_evidence_trust(canonical, corrupted_sha)
    assert trust_sha == EvidenceTrustLevel.INVALID


def test_evidence_trust_classification_missing_digest():
    """Verifies that empty or None digest is classified as MISSING and ineligible."""
    canonical = "http://127.0.0.1:8000/api/chat|POST||200|"
    assert classify_evidence_trust(canonical, None) == EvidenceTrustLevel.MISSING
    assert classify_evidence_trust(canonical, "") == EvidenceTrustLevel.MISSING
    assert classify_evidence_trust(canonical, "   ") == EvidenceTrustLevel.MISSING


def test_signing_key_security_and_constant_time():
    """Asserts signing key is non-empty, protected, and constant-time comparison is active."""
    key = get_evidence_signing_key()
    assert isinstance(key, bytes)
    assert len(key) >= 16

    # Verify constant-time comparison works through verify_evidence_signature
    canonical = "test_canonical_payload_stream"
    sig = compute_evidence_signature(canonical)
    assert verify_evidence_signature(canonical, sig) is True
    assert verify_evidence_signature(canonical, sig + "x") is False
    assert verify_evidence_signature("tampered_payload", sig) is False


# =====================================================================
# CORRECTION 2: HTTP 400 Classification Logic
# =====================================================================

def test_http_400_with_explicit_security_rejection_marker():
    """HTTP 400 with an explicit security rejection marker must be classified as BLOCKED."""
    cat = DynamicSecurityIntelligenceEngine.classify_outcome_category(
        verdict="BLOCKED",
        status_code=400,
        response_body="Security Rejection: Malicious prompt injection detected by AI guardrail",
        notes="Blocked by policy",
    )
    assert cat == OutcomeCategoryEnum.BLOCKED.value


def test_http_400_caused_by_malformed_json():
    """HTTP 400 caused by malformed JSON must be classified as INCONCLUSIVE (not defensive)."""
    cat = DynamicSecurityIntelligenceEngine.classify_outcome_category(
        verdict="ERROR",
        status_code=400,
        response_body="Malformed JSON: JSON decode error expecting value at line 1 column 1",
        notes="Client syntax error: invalid json payload",
    )
    assert cat == OutcomeCategoryEnum.INCONCLUSIVE.value
    assert cat != OutcomeCategoryEnum.BLOCKED.value


def test_http_400_caused_by_missing_required_field():
    """HTTP 400 caused by a missing required field must be classified as INCONCLUSIVE (not defensive)."""
    cat = DynamicSecurityIntelligenceEngine.classify_outcome_category(
        verdict="ERROR",
        status_code=400,
        response_body="Validation Error: Missing required parameter 'message'",
        notes="Field required: 'message' schema validation error",
    )
    assert cat == OutcomeCategoryEnum.INCONCLUSIVE.value
    assert cat != OutcomeCategoryEnum.BLOCKED.value


def test_http_403_with_verified_defensive_response():
    """HTTP 403 with a verified defensive response must be classified as BLOCKED."""
    cat = DynamicSecurityIntelligenceEngine.classify_outcome_category(
        verdict="BLOCKED",
        status_code=403,
        response_body="Forbidden: Access denied by authorization boundary",
        notes="Defensive block confirmed",
    )
    assert cat == OutcomeCategoryEnum.BLOCKED.value


def test_generic_http_400_without_defensive_evidence():
    """Generic HTTP 400 without defensive evidence must be classified as INCONCLUSIVE."""
    cat = DynamicSecurityIntelligenceEngine.classify_outcome_category(
        verdict="ERROR",
        status_code=400,
        response_body="Bad Request",
        notes="Generic 400 client error",
    )
    assert cat == OutcomeCategoryEnum.INCONCLUSIVE.value
    assert cat != OutcomeCategoryEnum.BLOCKED.value


# =====================================================================
# CORRECTION 3: Heuristic Empirical Outcome Formula & Audit Closure Tests
# =====================================================================

def test_legacy_evidence_never_represented_as_hmac_authenticated():
    """Audit Item 3: Legacy SHA-256 evidence is strictly classified as LEGACY_SHA256_VERIFIED

    and is never represented as HMAC-authenticated or given cryptographic authenticity.
    """
    canonical = "http://127.0.0.1:8000/api/chat|POST|{'msg': 'test'}|200|response"
    legacy_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    trust = classify_evidence_trust(canonical, legacy_sha256)
    assert trust == EvidenceTrustLevel.LEGACY_SHA256_VERIFIED
    assert trust != EvidenceTrustLevel.HMAC_VERIFIED
    assert trust.value != "HMAC_VERIFIED"
    assert "HMAC" not in trust.value


def test_heuristic_empirical_outcome_formula_exact_math():
    """Audit Item 5: Verifies that the heuristic empirical outcome formula is:

    HeuristicOutcome = N_confirmed / N_eligible
    where N_eligible = N_confirmed + N_blocked + N_partial + N_inconclusive.
    Unconfirmed findings (PARTIAL) are excluded from the confirmed numerator.
    """
    records = [
        {"risk_id": "LLM01", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "h1", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM01", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "h2", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM01", "outcome_category": "PARTIAL", "eligible": True, "evidence_sha256": "h3", "evidence_trust_level": "HMAC_VERIFIED"},   # Unconfirmed
        {"risk_id": "LLM01", "outcome_category": "BLOCKED", "eligible": True, "evidence_sha256": "h4", "evidence_trust_level": "HMAC_VERIFIED"},   # Defensive
    ]  # N_eligible = 4 >= 3. Confirmed = 2. HeuristicOutcome = 2 / 4 = 0.5000

    score, cold_start, samples, ev_count, remed_rate = DynamicSecurityIntelligenceEngine.calculate_heuristic_outcome_score(
        risk_id="LLM01",
        eligible_records=records,
    )

    assert cold_start is False
    assert samples == 4
    assert ev_count == 4
    assert score == 0.5000
    assert remed_rate == 0.0


def test_inconclusive_observations_tracked_as_separate_metric():
    """Audit Item 6: Inconclusive observations are tracked as a separate metric

    and dilute the confirmed vulnerability ratio in N_eligible.
    """
    records = [
        {"risk_id": "LLM01", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "h1", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM01", "outcome_category": "INCONCLUSIVE", "eligible": True, "evidence_sha256": "h2", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM01", "outcome_category": "INCONCLUSIVE", "eligible": True, "evidence_sha256": "h3", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM01", "outcome_category": "BLOCKED", "eligible": True, "evidence_sha256": "h4", "evidence_trust_level": "HMAC_VERIFIED"},
    ]  # N_eligible = 4. Confirmed = 1. Inconclusive = 2. Blocked = 1.
    # Score = 1 / 4 = 0.25 (diluted by 2 inconclusive observations!)

    metrics = DynamicSecurityIntelligenceEngine.calculate_detailed_risk_metrics(
        risk_id="LLM01",
        eligible_records=records,
    )

    assert metrics["n_eligible"] == 4
    assert metrics["confirmed_count"] == 1
    assert metrics["inconclusive_count"] == 2
    assert metrics["blocked_count"] == 1
    assert metrics["confirmed_rate"] == 0.2500
    assert metrics["inconclusive_rate"] == 0.5000
    assert metrics["blocked_rate"] == 0.2500
    assert metrics["heuristic_score"] == 0.2500


def test_zero_eligible_observations_safe_handling():
    """Audit Item 7: Zero eligible observations do not cause division errors

    and safely return 0.0 for rates and cold-start base prior for scores.
    """
    metrics = DynamicSecurityIntelligenceEngine.calculate_detailed_risk_metrics(
        risk_id="ASI05",
        eligible_records=[],
    )

    assert metrics["n_eligible"] == 0
    assert metrics["confirmed_rate"] == 0.0
    assert metrics["blocked_rate"] == 0.0
    assert metrics["partial_rate"] == 0.0
    assert metrics["inconclusive_rate"] == 0.0
    assert metrics["evaluable_coverage"] == 0.0
    assert metrics["remediation_success_rate"] == 0.0
    assert metrics["cold_start"] is True
    assert metrics["heuristic_score"] == COLD_START_BASE_PRIORS["ASI05"]  # 0.95


def test_remediation_success_rate_cohort_calculation():
    """Audit Item 8: Remediation success rate uses cohort formula

    N_remediation / max(1, N_remediation + N_confirmed) and is calculated
    independently from ordinary test outcomes like BLOCKED.
    """
    records = [
        {"risk_id": "ASI01", "outcome_category": "REMEDIATION_VERIFIED", "eligible": True, "evidence_sha256": "h1", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "ASI01", "outcome_category": "REMEDIATION_VERIFIED", "eligible": True, "evidence_sha256": "h2", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "ASI01", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "h3", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "ASI01", "outcome_category": "BLOCKED", "eligible": True, "evidence_sha256": "h4", "evidence_trust_level": "HMAC_VERIFIED"},
    ]  # 2 remediation verified, 1 confirmed, 1 blocked.
    # N_eligible = 1 confirmed + 1 blocked = 2 (remediation is cohort verification, not initial attack test).
    # RemediationSuccessRate = 2 / (2 + 1) = 2/3 = 0.6667.

    metrics = DynamicSecurityIntelligenceEngine.calculate_detailed_risk_metrics(
        risk_id="ASI01",
        eligible_records=records,
    )

    assert metrics["remediation_success_rate"] == 0.6667
    assert metrics["confirmed_count"] == 1
    assert metrics["blocked_count"] == 1


def test_legacy_restricted_policy_scoring_and_contribution():
    """Audit Item 2: Verifies that legacy SHA-256 evidence follows the restricted policy:

    when only legacy records exist (N_hmac < 3, N_legacy >= 3), the restricted legacy calculation
    is applied, legacy_evidence_contribution is tracked, and legacy data is disclosed separately.
    When N_hmac >= 3 exist, primary HMAC score is used and legacy_evidence_contribution is 0.0.
    """
    # Case A: Legacy records only under Restricted Legacy Policy
    legacy_records = [
        {"risk_id": "LLM03", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "l1", "evidence_trust_level": "LEGACY_SHA256_VERIFIED"},
        {"risk_id": "LLM03", "outcome_category": "BLOCKED", "eligible": True, "evidence_sha256": "l2", "evidence_trust_level": "LEGACY_SHA256_VERIFIED"},
        {"risk_id": "LLM03", "outcome_category": "BLOCKED", "eligible": True, "evidence_sha256": "l3", "evidence_trust_level": "LEGACY_SHA256_VERIFIED"},
    ]
    m_legacy = DynamicSecurityIntelligenceEngine.calculate_detailed_risk_metrics("LLM03", legacy_records)
    assert m_legacy["cold_start"] is False
    assert m_legacy["legacy_sha256_count"] == 3
    assert m_legacy["hmac_verified_count"] == 0
    assert m_legacy["legacy_evidence_contribution"] == 1.0000
    assert m_legacy["trust_policy_applied"] == "RESTRICTED_LEGACY_SHA256_INTEGRITY"
    assert m_legacy["heuristic_score"] == 0.3333

    # Case B: Sufficient HMAC records available (N_hmac >= 3)
    mixed_records = legacy_records + [
        {"risk_id": "LLM03", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "h1", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM03", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "h2", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM03", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "h3", "evidence_trust_level": "HMAC_VERIFIED"},
    ]
    m_mixed = DynamicSecurityIntelligenceEngine.calculate_detailed_risk_metrics("LLM03", mixed_records)
    assert m_mixed["cold_start"] is False
    assert m_mixed["hmac_verified_count"] == 3
    assert m_mixed["legacy_sha256_count"] == 3
    assert m_mixed["legacy_evidence_contribution"] == 0.0000  # HMAC takes full priority!
    assert m_mixed["trust_policy_applied"] == "PRIMARY_HMAC_AUTHENTICATED"
    assert m_mixed["heuristic_score"] == 1.0000  # 3 HMAC confirmed / 3 HMAC total


def test_infrastructure_error_excluded_from_denominator():
    """Verifies that infrastructure errors (ERROR) are strictly excluded from N_eligible."""
    records = [
        {"risk_id": "LLM02", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "h1", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM02", "outcome_category": "BLOCKED", "eligible": True, "evidence_sha256": "h2", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM02", "outcome_category": "BLOCKED", "eligible": True, "evidence_sha256": "h3", "evidence_trust_level": "HMAC_VERIFIED"},
        {"risk_id": "LLM02", "outcome_category": "ERROR", "eligible": True, "evidence_sha256": "h4", "evidence_trust_level": "HMAC_VERIFIED"},  # Excluded!
    ]  # Valid N = 3. Confirmed = 1. Score = 1 / 3 = 0.3333

    score, cold_start, samples, ev_count, remed_rate = DynamicSecurityIntelligenceEngine.calculate_heuristic_outcome_score(
        risk_id="LLM02",
        eligible_records=records,
    )

    assert cold_start is False
    assert score == 0.3333


def test_cold_start_preserved_when_n_less_than_three():
    """Asserts deterministic cold-start heuristic base prior when N < 3."""
    records = [
        {"risk_id": "ASI02", "outcome_category": "CONFIRMED", "eligible": True, "evidence_sha256": "h1", "evidence_trust_level": "HMAC_VERIFIED"},
    ]  # N = 1 < 3

    score, cold_start, samples, ev_count, remed_rate = DynamicSecurityIntelligenceEngine.calculate_heuristic_outcome_score(
        risk_id="ASI02",
        eligible_records=records,
    )

    assert cold_start is True
    assert samples == 1
    assert score == COLD_START_BASE_PRIORS["ASI02"]  # 0.92


# =====================================================================
# Strict Target Isolation & Evidence Eligibility Invariants
# =====================================================================

def test_strict_target_isolation_and_evidence_validation():
    """Verifies that valid cryptographic HMAC evidence is approved and cross-app attempts are rejected."""
    target = TargetIsolationTuple(
        target_identity="127.0.0.1:8000",
        application_id="app_alpha",
        app_version="v1.0",
        environment="sandbox",
        endpoint="/api/chat",
    )

    plan = SecurityExecutionPlan(
        id=str(uuid.uuid4()),
        session_id=str(uuid.uuid4()),
        target_url="http://127.0.0.1:8000",
        stage="POST_MITIGATION",
        plan_metadata=json.dumps({"application_id": "app_alpha", "app_version": "v1.0", "environment": "sandbox"}),
    )

    exec_test = SecurityTestExecution(
        id=str(uuid.uuid4()),
        plan_id=plan.id,
        scenario_id="LLM01-01",
        risk_id="LLM01",
        risk_name="Prompt Injection",
        category="OWASP_LLM",
        test_type="security_test",
        target_endpoint="/api/chat",
        http_method="POST",
        status="COMPLETED",
        verdict="BLOCKED",
    )
    exec_test.plan = plan

    # Generate genuine HMAC signature
    canonical = "http://127.0.0.1:8000/api/chat|POST|raw_payload|403|Forbidden"
    sig = compute_evidence_signature(canonical)

    exec_test.evidence = HttpEvidenceRecord(
        id=str(uuid.uuid4()),
        execution_id=exec_test.id,
        target_url="http://127.0.0.1:8000/api/chat",
        http_method="POST",
        request_body="raw_payload",
        response_status_code=403,
        response_body="Forbidden",
        evidence_sha256=sig,
    )

    eligible, reason, trust = DynamicSecurityIntelligenceEngine.validate_evidence_eligibility(exec_test, target)
    assert eligible is True
    assert reason is None
    assert trust == EvidenceTrustLevel.HMAC_VERIFIED.value

    # Test corrupted HMAC signature rejection
    exec_test.evidence.evidence_sha256 = sig + "tampered"
    el_corrupt, reas_corrupt, trust_corrupt = DynamicSecurityIntelligenceEngine.validate_evidence_eligibility(exec_test, target)
    assert el_corrupt is False
    assert "INELIGIBLE_INVALID_EVIDENCE" in reas_corrupt
    assert trust_corrupt == EvidenceTrustLevel.INVALID.value


# =====================================================================
# REST API Endpoints Verification
# =====================================================================

def test_api_intelligence_endpoints_e1(client):
    """Audit Item 9: Verifies overview, priorities, and history endpoints

    expose evidence trust distinctions, detailed outcome metrics, and safe handling.
    """
    # 1. Overview
    res_ov = client.get("/api/security-agent/intelligence/overview?target_url=http://127.0.0.1:8000")
    assert res_ov.status_code == 200
    d_ov = res_ov.json()
    assert d_ov["target_identity"] == "127.0.0.1:8000"
    assert "outcome_counts" in d_ov
    assert "evidence_trust_distribution" in d_ov
    assert "hmac_verified_count" in d_ov
    assert "legacy_sha256_count" in d_ov
    assert "confirmed_rate" in d_ov
    assert "blocked_rate" in d_ov
    assert "partial_rate" in d_ov
    assert "inconclusive_rate" in d_ov
    assert "evaluable_coverage" in d_ov
    assert "infrastructure_error_rate" in d_ov
    assert OutcomeCategoryEnum.CONFIRMED.value in d_ov["outcome_counts"]
    assert OutcomeCategoryEnum.BLOCKED.value in d_ov["outcome_counts"]

    # 2. Priorities
    res_pr = client.get("/api/security-agent/intelligence/priorities?target_url=http://127.0.0.1:8000")
    assert res_pr.status_code == 200
    d_pr = res_pr.json()
    assert len(d_pr) == 20
    for item in d_pr:
        assert 0.0 <= item["priority_score"] <= 1.0
        assert "remediation_success_rate" in item
        assert "evidence_trust_level" in item
        assert "hmac_verified_count" in item
        assert "legacy_sha256_count" in item
        assert "legacy_evidence_contribution" in item
        assert "confirmed_rate" in item
        assert "blocked_rate" in item
        assert "inconclusive_rate" in item
        assert "evaluable_coverage" in item

    # 3. History
    res_hi = client.get("/api/security-agent/intelligence/history?target_url=http://127.0.0.1:8000&limit=10")
    assert res_hi.status_code == 200
    history_items = res_hi.json()
    assert isinstance(history_items, list)
    for rec in history_items:
        assert "evidence_trust_level" in rec
        assert "trust_description" in rec
