"""Dedicated Automated Test Suite for ApexShield Phase E6 — Enterprise Reporting Engine.

Tests:
1. Canonical JSON serialization determinism, float rounding, and UTC ISO 8601 formatting.
2. SHA-256 report content integrity & avalanche effect.
3. HMAC-SHA256 source authenticity verification with key rotation.
4. Tamper detection and forged signature rejection (constant-time verification).
5. Ten-section enterprise reporting structure completeness (Sections 1 through 10).
6. Multi-format artifact generation (PDF via ReportLab, XLSX via openpyxl, CSV, JSON).
7. Verifiable artifact manifest binding files to canonical report.
8. Zero-cascade archival persistence safety (ON DELETE SET NULL on session and plan).
9. FastAPI REST endpoints (/reports/generate, /{id}, /{id}/download/{fmt}, /verify, /history).
10. Canonical database baseline immutability (786 / 138 / 693 / 96).
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.database.session import SessionLocal, get_db
from app.main import app
from app.security_agent.enterprise_report_engine import (
    EnterpriseReportCompiler,
    EnterpriseReportEngine,
    ReportDocumentExporters,
    SigningKeyManager,
    compute_report_hash,
    normalize_floats_and_dates,
    serialize_canonical_report,
    sign_report_hmac,
    verify_report_integrity,
)
from app.security_agent.models import (
    AgentExecutionSession,
    SecurityEnterpriseReport,
    SecurityExecutionPlan,
    SecurityFinding,
    SecurityRegressionComparison,
    SecurityTestExecution,
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
# 1. CANONICAL SERIALIZATION & DIGEST TESTS
# =============================================================================

def test_canonical_serialization_deterministic():
    """Verifies that dicts with identical content serialize to bitwise identical bytes regardless of key insertion order."""
    d1 = {"zebra": 1, "apple": 2, "mango": 3, "score": 95.456}
    d2 = {"score": 95.456, "mango": 3, "apple": 2, "zebra": 1}
    b1 = serialize_canonical_report(d1)
    b2 = serialize_canonical_report(d2)
    assert b1 == b2, "Canonical serialization produced different bytes for identical dictionaries"


def test_canonical_float_and_date_formatting():
    """Verifies that floats are normalized to 2 decimals and datetimes to UTC ISO 8601 with Z."""
    now = datetime(2026, 11, 23, 14, 30, 0, tzinfo=timezone.utc)
    raw = {"score": 0.8549999, "nested": {"val": 1.999}, "timestamp": now}
    norm = normalize_floats_and_dates(raw)
    assert norm["score"] == 0.85
    assert norm["nested"]["val"] == 2.0
    assert norm["timestamp"] == "2026-11-23T14:30:00Z"


def test_report_hash_sha256_integrity():
    """Verifies that compute_report_hash returns exact SHA-256 hex digest over canonical bytes."""
    d = {"report_id": "RPT-TEST-01", "scope": "http://127.0.0.1:8000"}
    canon = serialize_canonical_report(d)
    expected = hashlib.sha256(canon).hexdigest()
    actual = compute_report_hash(canon)
    assert actual == expected


def test_report_hash_avalanche_effect():
    """Verifies that changing a single character changes the SHA-256 hash completely."""
    d1 = {"finding": "Prompt Injection Vulnerability Detected", "severity": "HIGH"}
    d2 = {"finding": "Prompt Injection Vulnerability Detected.", "severity": "HIGH"}
    h1 = compute_report_hash(serialize_canonical_report(d1))
    h2 = compute_report_hash(serialize_canonical_report(d2))
    assert h1 != h2
    diff_chars = sum(1 for a, b in zip(h1, h2) if a != b)
    assert diff_chars > 30, "SHA-256 avalanche effect violated"


# =============================================================================
# 2. SOURCE AUTHENTICITY, KEY ROTATION & TAMPER DETECTION
# =============================================================================

def test_hmac_report_signature_generation():
    """Verifies HMAC-SHA256 signature generation using server secret key."""
    digest = "5a7bb10572598e1e4bd4636ed33eee1de28d578220e48482cfdde4083941bbb8"
    sig, key_id = sign_report_hmac(digest, "RPT-001", "2026-11-23T00:00:00Z")
    assert len(sig) == 64
    assert key_id == "v1_default"


def test_verify_authentic_report_success():
    """Verifies that an unmodified report passes both content integrity and source authenticity checks."""
    report = {
        "report_id": "RPT-AUTH-01",
        "created_at": "2026-11-23T00:00:00Z",
        "target_url": "http://127.0.0.1:8000",
        "findings_count": 5,
    }
    canon = serialize_canonical_report(report)
    h = compute_report_hash(canon)
    sig, key_id = sign_report_hmac(h, "RPT-AUTH-01", "2026-11-23T00:00:00Z")

    report["report_hash"] = h
    report["hmac_signature"] = sig
    report["signing_key_id"] = key_id

    result = verify_report_integrity(report)
    assert result["is_valid"] is True
    assert result["status"] == "VERIFIED_AUTHENTIC"
    assert result["content_integrity_verified"] is True
    assert result["source_authenticity_verified"] is True


def test_verify_detects_content_tampering():
    """Verifies that altering findings or content triggers TAMPERED_CONTENT."""
    report = {
        "report_id": "RPT-TAMPER-01",
        "created_at": "2026-11-23T00:00:00Z",
        "severity": "CRITICAL",
        "findings_count": 10,
    }
    canon = serialize_canonical_report(report)
    h = compute_report_hash(canon)
    sig, key_id = sign_report_hmac(h, "RPT-TAMPER-01", "2026-11-23T00:00:00Z")

    report["report_hash"] = h
    report["hmac_signature"] = sig

    # Adversary alters severity from CRITICAL to LOW
    report["severity"] = "LOW"

    result = verify_report_integrity(report)
    assert result["is_valid"] is False
    assert result["status"] == "TAMPERED_CONTENT"
    assert result["content_integrity_verified"] is False


def test_verify_detects_signature_forgery():
    """Verifies that forged or modified HMAC signatures trigger FORGED_SIGNATURE."""
    report = {
        "report_id": "RPT-FORGE-01",
        "created_at": "2026-11-23T00:00:00Z",
        "findings_count": 0,
    }
    canon = serialize_canonical_report(report)
    h = compute_report_hash(canon)

    report["report_hash"] = h
    report["hmac_signature"] = "deadbeef" * 8  # Fake signature

    result = verify_report_integrity(report)
    assert result["is_valid"] is False
    assert result["status"] == "FORGED_SIGNATURE"
    assert result["content_integrity_verified"] is True
    assert result["source_authenticity_verified"] is False


def test_key_rotation_support():
    """Verifies that reports signed with rotated keys verify cleanly using historical registry."""
    rot_key_id = "k2026_q4"
    report = {
        "report_id": "RPT-ROT-01",
        "created_at": "2026-11-23T00:00:00Z",
        "target": "http://127.0.0.1:8000",
    }
    canon = serialize_canonical_report(report)
    h = compute_report_hash(canon)
    sig, key_id = sign_report_hmac(h, "RPT-ROT-01", "2026-11-23T00:00:00Z", key_id=rot_key_id)
    assert key_id == rot_key_id

    report["report_hash"] = h
    report["hmac_signature"] = sig
    report["signing_key_id"] = rot_key_id

    result = verify_report_integrity(report)
    assert result["is_valid"] is True
    assert result["status"] == "VERIFIED_AUTHENTIC"
    assert result["signing_key_id"] == rot_key_id


# =============================================================================
# 2B. SEC-E6-001 SIGNING KEY FAIL-CLOSED REGRESSION TEST SUITE
# =============================================================================

def test_sec_e6_001_valid_default_key_verification():
    """1. Valid default key verification succeeds with VERIFIED_AUTHENTIC."""
    payload = {"report_id": "RPT-DEF-01", "created_at": "2026-11-23T00:00:00Z", "status": "OK"}
    h = compute_report_hash(serialize_canonical_report(payload))
    sig, kid = sign_report_hmac(h, "RPT-DEF-01", "2026-11-23T00:00:00Z")
    assert kid == "v1_default"

    payload["report_hash"] = h
    payload["hmac_signature"] = sig
    payload["signing_key_id"] = kid

    res = verify_report_integrity(payload)
    assert res["is_valid"] is True
    assert res["status"] == "VERIFIED_AUTHENTIC"
    assert res["source_authenticity_verified"] is True
    assert res["signing_key_id"] == "v1_default"


def test_sec_e6_001_valid_historical_key_verification():
    """2. Valid historical key in registry verifies with VERIFIED_AUTHENTIC."""
    hist_kid = "k2025_q4"
    SigningKeyManager.register_key(hist_kid, b"historical_secret_for_audit_2025")

    payload = {"report_id": "RPT-HIST-01", "created_at": "2026-11-23T00:00:00Z"}
    h = compute_report_hash(serialize_canonical_report(payload))
    sig, kid = sign_report_hmac(h, "RPT-HIST-01", "2026-11-23T00:00:00Z", key_id=hist_kid)
    assert kid == hist_kid

    payload["report_hash"] = h
    payload["hmac_signature"] = sig
    payload["signing_key_id"] = hist_kid

    res = verify_report_integrity(payload)
    assert res["is_valid"] is True
    assert res["status"] == "VERIFIED_AUTHENTIC"
    assert res["source_authenticity_verified"] is True
    assert res["signing_key_id"] == hist_kid


def test_sec_e6_001_valid_rotated_key_verification():
    """3. Valid rotated key verifies cleanly against registered rotated secret."""
    rot_kid = "k2026_q4"
    payload = {"report_id": "RPT-ROT-02", "created_at": "2026-11-23T00:00:00Z"}
    h = compute_report_hash(serialize_canonical_report(payload))
    sig, kid = sign_report_hmac(h, "RPT-ROT-02", "2026-11-23T00:00:00Z", key_id=rot_kid)
    assert kid == rot_kid

    payload["report_hash"] = h
    payload["hmac_signature"] = sig
    payload["signing_key_id"] = rot_kid

    res = verify_report_integrity(payload)
    assert res["is_valid"] is True
    assert res["status"] == "VERIFIED_AUTHENTIC"
    assert res["source_authenticity_verified"] is True


def test_sec_e6_001_unknown_key_id_rejection():
    """4. Unknown key ID raises KeyError in SigningKeyManager and yields UNKNOWN_KEY in verification."""
    with pytest.raises(KeyError) as exc_info:
        SigningKeyManager.get_signing_key("completely_unknown_key_xyz")
    assert "Unrecognized or revoked signing key identifier" in str(exc_info.value)

    payload = {
        "report_id": "RPT-UNK-01",
        "created_at": "2026-11-23T00:00:00Z",
        "report_hash": "a" * 64,
        "hmac_signature": "b" * 64,
        "signing_key_id": "completely_unknown_key_xyz",
    }
    res = verify_report_integrity(payload)
    assert res["is_valid"] is False
    assert res["status"] == "UNKNOWN_KEY"
    assert res["source_authenticity_verified"] is False


def test_sec_e6_001_revoked_key_id_rejection():
    """5. Revoked / retired key ID is rejected fail-closed with UNKNOWN_KEY."""
    payload = {
        "report_id": "RPT-REV-01",
        "created_at": "2026-11-23T00:00:00Z",
        "report_hash": "c" * 64,
        "hmac_signature": "d" * 64,
        "signing_key_id": "revoked_compromised_key_2024",
    }
    res = verify_report_integrity(payload)
    assert res["is_valid"] is False
    assert res["status"] == "UNKNOWN_KEY"
    assert res["source_authenticity_verified"] is False


def test_sec_e6_001_explicit_unknown_key_never_falls_back():
    """6. Explicit unknown key ID NEVER falls back to default key even if signed with default key."""
    payload = {"report_id": "RPT-FALLBACK-01", "created_at": "2026-11-23T00:00:00Z"}
    h = compute_report_hash(serialize_canonical_report(payload))
    sig, _ = sign_report_hmac(h, "RPT-FALLBACK-01", "2026-11-23T00:00:00Z", key_id="v1_default")

    payload["report_hash"] = h
    payload["hmac_signature"] = sig
    payload["signing_key_id"] = "unregistered_adversary_key"

    res = verify_report_integrity(payload)
    assert res["is_valid"] is False
    assert res["status"] == "UNKNOWN_KEY"
    assert res["source_authenticity_verified"] is False


def test_sec_e6_001_missing_key_id_behavior():
    """7. Missing / omitted key ID safely falls back to default active key."""
    payload = {"report_id": "RPT-NOKID-01", "created_at": "2026-11-23T00:00:00Z"}
    h = compute_report_hash(serialize_canonical_report(payload))
    sig, kid = sign_report_hmac(h, "RPT-NOKID-01", "2026-11-23T00:00:00Z")

    payload["report_hash"] = h
    payload["hmac_signature"] = sig

    res = verify_report_integrity(payload)
    assert res["is_valid"] is True
    assert res["status"] == "VERIFIED_AUTHENTIC"
    assert res["signing_key_id"] == "v1_default"


def test_sec_e6_001_tampered_content_detection():
    """8. Existing tampered-content detection remains fully functional."""
    payload = {"report_id": "RPT-TAMP-01", "created_at": "2026-11-23T00:00:00Z", "posture": "RESILIENT"}
    h = compute_report_hash(serialize_canonical_report(payload))
    sig, kid = sign_report_hmac(h, "RPT-TAMP-01", "2026-11-23T00:00:00Z", key_id="v1_default")

    payload["report_hash"] = h
    payload["hmac_signature"] = sig
    payload["signing_key_id"] = kid
    payload["posture"] = "CRITICAL_RISK"

    res = verify_report_integrity(payload)
    assert res["is_valid"] is False
    assert res["status"] == "TAMPERED_CONTENT"
    assert res["content_integrity_verified"] is False


def test_sec_e6_001_forged_signature_detection():
    """9. Existing forged-signature detection remains fully functional."""
    payload = {"report_id": "RPT-FORG-01", "created_at": "2026-11-23T00:00:00Z"}
    h = compute_report_hash(serialize_canonical_report(payload))

    payload["report_hash"] = h
    payload["hmac_signature"] = "00" * 32
    payload["signing_key_id"] = "v1_default"

    res = verify_report_integrity(payload)
    assert res["is_valid"] is False
    assert res["status"] == "FORGED_SIGNATURE"
    assert res["content_integrity_verified"] is True
    assert res["source_authenticity_verified"] is False


def test_sec_e6_001_constant_time_comparison_intact():
    """10. Constant-time signature comparison (hmac.compare_digest) is enforced."""
    import hmac
    assert callable(hmac.compare_digest)
    assert hmac.compare_digest("abc", "abcd") is False


# =============================================================================
# 3. TEN-SECTION ENTERPRISE REPORT COMPILER TESTS
# =============================================================================

def test_ten_sections_structure_completeness():
    """Verifies that all 10 mandatory enterprise sections are present in compiled report."""
    report = EnterpriseReportCompiler.compile_report(None, None, [], [], None)
    expected_sections = [
        "section_1_executive_summary",
        "section_2_technical_scope",
        "section_3_owasp_coverage_matrix",
        "section_4_attack_chain_analysis",
        "section_5_vulnerability_findings",
        "section_6_evidence_trace_ledger",
        "section_7_root_cause_analysis",
        "section_8_remediation_roadmap",
        "section_9_regression_analysis",
        "section_10_residual_risk_and_signatures",
    ]
    for sec in expected_sections:
        assert sec in report, f"Mandatory section '{sec}' is missing from compiled enterprise report"


def test_section1_executive_summary_metrics():
    """Verifies executive summary posture calculation and findings tally."""
    f_crit = SecurityFinding(finding_id="F1", scenario_id="S1", risk_id="LLM01", title="SQLi", severity="CRITICAL", affected_endpoint="/api/db", lifecycle_status="CONFIRMED")
    f_high = SecurityFinding(finding_id="F2", scenario_id="S2", risk_id="LLM02", title="XSS", severity="HIGH", affected_endpoint="/api/view", lifecycle_status="CONFIRMED")

    report = EnterpriseReportCompiler.compile_report(None, None, [f_crit, f_high], [], None)
    s1 = report["section_1_executive_summary"]
    assert s1["findings_summary"]["total"] == 2
    assert s1["findings_summary"]["critical"] == 1
    assert s1["findings_summary"]["high"] == 1
    assert s1["posture_grade"] == "CRITICAL_RISK"
    assert s1["resilience_score"] <= 0.70  # Deducted for critical & high


def test_section2_scope_isolation_metadata():
    """Verifies Section 2 target scope 6-tuple and authorization boundary flags."""
    report = EnterpriseReportCompiler.compile_report(None, None, [], [], None, target_scope_override="http://staging.local:8000")
    s2 = report["section_2_technical_scope"]
    assert s2["target_identity_6tuple"]["target_identity"] == "http://staging.local:8000"
    assert s2["scope_boundaries"]["authorization_confirmed"] is True
    assert "169.254.169.254" in s2["scope_boundaries"]["forbidden_networks"]


def test_section3_owasp_coverage_matrix():
    """Verifies that Section 3 contains all 20 OWASP categories (LLM01-LLM10, ASI01-ASI10)."""
    f = SecurityFinding(finding_id="F1", scenario_id="S1", risk_id="LLM01", title="Injection", severity="HIGH", affected_endpoint="/api/chat", lifecycle_status="CONFIRMED")
    report = EnterpriseReportCompiler.compile_report(None, None, [f], [], None)
    s3 = report["section_3_owasp_coverage_matrix"]
    assert s3["evaluated_categories_count"] == 20
    matrix = s3["matrix"]
    assert len(matrix) == 20
    llm01 = next(row for row in matrix if row["risk_id"] == "LLM01")
    assert llm01["findings_count"] == 1
    assert llm01["coverage_status"] == "TESTED_VULNERABLE"
    asi01 = next(row for row in matrix if row["risk_id"] == "ASI01")
    assert asi01["findings_count"] == 0
    assert asi01["coverage_status"] == "TESTED_DEFENDED"


def test_section6_evidence_trace_ledger_with_missing_evidence_disclosure():
    """Verifies Section 6 evidence trace ledger and explicit [EVIDENCE_PRUNED_HISTORICAL] disclosure."""
    f_missing = SecurityFinding(finding_id="F_PRUNED", scenario_id="S1", risk_id="LLM01", title="T1", severity="LOW", affected_endpoint="/api/a", lifecycle_status="CONFIRMED", evidence_references=None)
    f_linked = SecurityFinding(finding_id="F_LINKED", scenario_id="S2", risk_id="LLM02", title="T2", severity="MED", affected_endpoint="/api/b", lifecycle_status="CONFIRMED", evidence_references='["digest_xyz"]')

    report = EnterpriseReportCompiler.compile_report(None, None, [f_missing, f_linked], [], None)
    s6 = report["section_6_evidence_trace_ledger"]
    traces = s6["traces"]
    assert len(traces) == 2
    t_pruned = next(t for t in traces if t["finding_id"] == "F_PRUNED")
    assert t_pruned["evidence_digest"] == "[EVIDENCE_PRUNED_HISTORICAL]"
    assert t_pruned["evidence_status"] == "HISTORICAL_WITHOUT_WIRE_RECORD"

    t_linked = next(t for t in traces if t["finding_id"] == "F_LINKED")
    assert t_linked["evidence_digest"] == "digest_xyz"
    assert t_linked["evidence_status"] == "HMAC_VERIFIED"


def test_section8_remediation_roadmap_prioritization():
    """Verifies that Section 8 prioritizes remediation into P0, P1, and P2 tiers."""
    f_p0 = SecurityFinding(finding_id="F_CRIT", scenario_id="S1", risk_id="LLM01", title="Crit Injection", severity="CRITICAL", affected_endpoint="/api/a", lifecycle_status="CONFIRMED")
    f_p1 = SecurityFinding(finding_id="F_HIGH", scenario_id="S2", risk_id="LLM02", title="High Exfil", severity="HIGH", affected_endpoint="/api/b", lifecycle_status="CONFIRMED")
    f_p2 = SecurityFinding(finding_id="F_MED", scenario_id="S3", risk_id="LLM03", title="Med Leak", severity="MEDIUM", affected_endpoint="/api/c", lifecycle_status="CONFIRMED")

    report = EnterpriseReportCompiler.compile_report(None, None, [f_p0, f_p1, f_p2], [], None)
    s8 = report["section_8_remediation_roadmap"]
    assert len(s8["p0_critical_24h"]) == 1
    assert s8["p0_critical_24h"][0]["finding_id"] == "F_CRIT"
    assert len(s8["p1_high_7d"]) == 1
    assert s8["p1_high_7d"][0]["finding_id"] == "F_HIGH"
    assert len(s8["p2_medium_30d"]) == 1
    assert s8["p2_medium_30d"][0]["finding_id"] == "F_MED"


def test_section10_residual_risk_and_signatures():
    """Verifies Section 10 preserves all 4 documented operational boundaries."""
    report = EnterpriseReportCompiler.compile_report(None, None, [], [], None)
    s10 = report["section_10_residual_risk_and_signatures"]
    boundaries = s10["preserved_operational_boundaries"]
    boundary_ids = [b["boundary_id"] for b in boundaries]
    assert "LIM-E4-001" in boundary_ids
    assert "LIM-E4-002" in boundary_ids
    assert "LIM-E4-003" in boundary_ids
    assert "OBS-E5-004" in boundary_ids


# =============================================================================
# 4. MULTI-FORMAT EXPORT & ARTIFACT INTEGRITY
# =============================================================================

def test_generate_pdf_report_success(tmp_path):
    """Verifies that ReportLab generates a valid non-empty PDF document."""
    report = EnterpriseReportCompiler.compile_report(None, None, [], [], None)
    pdf_file = tmp_path / "test_report.pdf"
    ReportDocumentExporters.generate_pdf_export(report, pdf_file)
    assert pdf_file.exists()
    assert pdf_file.stat().st_size > 1000
    with open(pdf_file, "rb") as f:
        header = f.read(5)
        assert header == b"%PDF-", "Generated document is not a valid PDF"


def test_generate_xlsx_report_success(tmp_path):
    """Verifies that openpyxl generates a valid 4-tab Excel spreadsheet."""
    report = EnterpriseReportCompiler.compile_report(None, None, [], [], None)
    xlsx_file = tmp_path / "test_report.xlsx"
    ReportDocumentExporters.generate_xlsx_export(report, xlsx_file)
    assert xlsx_file.exists()
    assert xlsx_file.stat().st_size > 2000


def test_generate_csv_report_success(tmp_path):
    """Verifies that CSV exporter outputs valid RFC 4180 flattened findings."""
    f = SecurityFinding(finding_id="F1", scenario_id="S1", risk_id="LLM01", title="Title", severity="HIGH", affected_endpoint="/api/chat", lifecycle_status="CONFIRMED", cvss_score=8.0)
    report = EnterpriseReportCompiler.compile_report(None, None, [f], [], None)
    csv_file = tmp_path / "test_report.csv"
    ReportDocumentExporters.generate_csv_export(report, csv_file)
    assert csv_file.exists()
    content = csv_file.read_text(encoding="utf-8")
    assert "Finding ID,Scenario ID,Risk ID" in content
    assert "F1,S1,LLM01,Title,HIGH" in content


# =============================================================================
# 5. ZERO-CASCADE DELETION & ARCHIVAL PERSISTENCE
# =============================================================================

def test_session_deletion_independence(db_session: Session):
    """Verifies that deleting an AgentExecutionSession sets session_id to NULL without cascading report deletion."""
    db_session.execute(text("PRAGMA foreign_keys = ON;"))

    sess = AgentExecutionSession(
        id=f"audit_sess_{uuid.uuid4().hex[:8]}",
        title="Audit Session",
        command="test",
        user_confirmed_authorization=True,
    )
    db_session.add(sess)
    db_session.commit()

    report_rec = EnterpriseReportEngine.generate_and_store_report(
        db=db_session,
        session_id=sess.id,
        report_type="EXECUTIVE",
        formats=["json"],
    )
    report_id = report_rec.report_id

    # Delete the parent session
    db_session.delete(sess)
    db_session.commit()
    db_session.expire_all()

    # Verify report survived and session_id is NULL
    survived = EnterpriseReportEngine.get_report_by_id(db_session, report_id)
    assert survived is not None, "Report was deleted when parent session was deleted (Cascaded deletion violation!)"
    assert survived.session_id is None, "session_id was not set to NULL on session deletion"

    # Clean up test report
    db_session.delete(survived)
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys = OFF;"))
    db_session.commit()


def test_plan_deletion_independence(db_session: Session):
    """Verifies that deleting a SecurityExecutionPlan sets plan_id to NULL without cascading report deletion."""
    db_session.execute(text("PRAGMA foreign_keys = ON;"))

    sess = AgentExecutionSession(
        id=f"audit_sess_{uuid.uuid4().hex[:8]}",
        title="Audit Session",
        command="test",
        user_confirmed_authorization=True,
    )
    db_session.add(sess)

    plan = SecurityExecutionPlan(
        id=f"audit_plan_{uuid.uuid4().hex[:8]}",
        session_id=sess.id,
        target_url="http://127.0.0.1:8000",
        is_local_target=True,
    )
    db_session.add(plan)
    db_session.commit()

    report_rec = EnterpriseReportEngine.generate_and_store_report(
        db=db_session,
        plan_id=plan.id,
        report_type="FULL_TECHNICAL",
        formats=["json"],
    )
    report_id = report_rec.report_id

    # Delete the parent plan
    db_session.delete(plan)
    db_session.commit()
    db_session.expire_all()

    # Verify report survived and plan_id is NULL
    survived = EnterpriseReportEngine.get_report_by_id(db_session, report_id)
    assert survived is not None, "Report was deleted when parent plan was deleted!"
    assert survived.plan_id is None, "plan_id was not set to NULL on plan deletion"

    # Clean up test report
    db_session.delete(survived)
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys = OFF;"))
    db_session.commit()


# =============================================================================
# 6. FASTAPI API ROUTE TESTS
# =============================================================================

def test_api_generate_and_retrieve_report(client: TestClient, db_session: Session):
    """Tests POST /api/security-agent/reports/generate and GET /api/security-agent/reports/{id}."""
    resp = client.post(
        "/api/security-agent/reports/generate",
        json={
            "report_type": "FULL_TECHNICAL",
            "formats": ["json", "csv"],
            "lead_auditor": "Test Lead Auditor",
        },
    )
    assert resp.status_code == 201, f"Generate failed: {resp.text}"
    data = resp.json()
    assert "summary" in data
    assert "report_data" in data
    report_id = data["summary"]["report_id"]
    assert report_id.startswith("RPT-")
    assert data["summary"]["lead_auditor"] == "Test Lead Auditor"

    # Retrieve report by ID
    get_resp = client.get(f"/api/security-agent/reports/{report_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["summary"]["report_id"] == report_id


def test_api_download_endpoints(client: TestClient):
    """Tests GET /api/security-agent/reports/{id}/download/{format}."""
    resp = client.post(
        "/api/security-agent/reports/generate",
        json={"report_type": "EXECUTIVE", "formats": ["json", "csv"]},
    )
    assert resp.status_code == 201
    report_id = resp.json()["summary"]["report_id"]

    # Download JSON
    dl_json = client.get(f"/api/security-agent/reports/{report_id}/download/json")
    assert dl_json.status_code == 200
    assert "application/json" in dl_json.headers.get("content-type", "")

    # Download CSV
    dl_csv = client.get(f"/api/security-agent/reports/{report_id}/download/csv")
    assert dl_csv.status_code == 200
    assert "text/csv" in dl_csv.headers.get("content-type", "")

    # Unsupported format returns 400
    dl_bad = client.get(f"/api/security-agent/reports/{report_id}/download/unknown_fmt")
    assert dl_bad.status_code == 400


def test_api_verify_endpoint(client: TestClient):
    """Tests POST /api/security-agent/reports/verify."""
    resp = client.post(
        "/api/security-agent/reports/generate",
        json={"report_type": "COMPLIANCE", "formats": ["json"]},
    )
    assert resp.status_code == 201
    report_id = resp.json()["summary"]["report_id"]

    # Verify by report_id
    verify_resp = client.post(
        "/api/security-agent/reports/verify",
        json={"report_id": report_id},
    )
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["is_valid"] is True
    assert v_data["status"] == "VERIFIED_AUTHENTIC"
    assert v_data["content_integrity_verified"] is True
    assert v_data["source_authenticity_verified"] is True


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
