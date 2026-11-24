"""Phase E5: Security Regression Intelligence Test Suite.

Verifies:
1. Canonical Finding Correlation:
   - Key tuple: (affected_endpoint, risk_id, http_method, category)
   - Scheme-aware normalization, path percent-decoding, default port mapping,
     trailing slash normalization, and query-string stripping.
   - Preserves distinction between different endpoints.
2. Five Finding Delta Classifications:
   - NEW_VULNERABILITY
   - RESOLVED_VULNERABILITY
   - PERSISTENT_VULNERABILITY
   - REOPENED_VULNERABILITY (supported by historical lifecycle proof)
   - REGRESSION_DETECTED (deterioration of previously blocked control)
   - Mutually exclusive classification with deterministic precedence (zero double-counting).
3. Population Discrepancy Intelligence:
   - Common intersection population (I = S_base ∩ S_curr).
   - Intersection Resilience Score (inconclusive/untested never classified as secure).
   - Attack surface expansion factor.
   - Mandatory Population Caveat Disclosure when populations diverge.
   - Zero-population boundary behavior.
4. Target Isolation Enforcement:
   - Rejection of cross-target comparison without explicit flag.
   - Rejection of cross-environment comparison without explicit flag.
5. Database Persistence & Immutability:
   - Additive table `security_regression_comparisons`.
   - Safe ON DELETE SET NULL foreign keys.
   - Verification that historical tables (786/138/693/96) remain untouched.
6. REST API Contracts:
   - POST /api/security-agent/regression/compare
   - GET /api/security-agent/regression/{comparison_id}
   - GET /api/security-agent/regression/history
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import uuid
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from app.database.session import SessionLocal, get_db
from app.main import app
from app.security_agent.finding_lifecycle import FindingLifecycleEngine
from app.security_agent.models import (
    AgentExecutionSession,
    SecurityExecutionPlan,
    SecurityFinding,
    SecurityFindingHistory,
    SecurityRegressionComparison,
    SecurityTestExecution,
)
from app.security_agent.regression_engine import (
    SecurityRegressionEngine,
    TargetIsolationViolationError,
)
from app.security_agent.schemas import (
    PopulationDisclosure,
    RegressionCompareRequest,
    RegressionComparisonResponse,
    RegressionFindingDelta,
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


def create_test_session_and_plan(
    db,
    target_url="http://127.0.0.1:8000",
    stage="BASELINE",
    environment="sandbox",
    application_id="app_test",
    app_version="v1.0",
) -> SecurityExecutionPlan:
    """Helper to create a test session and plan in database."""
    session = AgentExecutionSession(
        id=f"sess_{uuid.uuid4().hex[:12]}",
        title="Regression Test Session",
        command="Run regression assessment",
        user_confirmed_authorization=True,
        status="COMPLETED",
    )
    db.add(session)
    db.commit()

    meta = {
        "application_id": application_id,
        "environment": environment,
        "app_version": app_version,
    }
    plan = SecurityExecutionPlan(
        id=f"plan_{uuid.uuid4().hex[:12]}",
        session_id=session.id,
        target_url=target_url,
        is_local_target=True,
        stage=stage,
        total_tests=0,
        completed_tests=0,
        status="COMPLETED",
        plan_metadata=json.dumps(meta),
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


def add_execution_to_plan(
    db,
    plan_id: str,
    scenario_id: str,
    risk_id: str,
    endpoint: str,
    verdict: str,
    http_method: str = "POST",
    category: str = "OWASP_LLM",
) -> SecurityTestExecution:
    """Helper to attach an execution to a plan."""
    ex = SecurityTestExecution(
        id=f"exec_{uuid.uuid4().hex[:12]}",
        plan_id=plan_id,
        scenario_id=scenario_id,
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        category=category,
        test_type="PROBE",
        target_endpoint=endpoint,
        http_method=http_method,
        payload_id="p1",
        status="COMPLETED",
        verdict=verdict,
        confidence=0.9,
    )
    db.add(ex)
    db.commit()
    db.refresh(ex)
    return ex


# =====================================================================
# 1. Canonical Key Normalization Tests
# =====================================================================

def test_canonical_key_basic_formatting():
    """Verify canonical correlation key generation."""
    key = SecurityRegressionEngine.build_canonical_key(
        endpoint="/api/v1/chat",
        risk_id="llm01",
        http_method="post",
        category="owasp_llm",
    )
    assert key == "/api/v1/chat:LLM01:POST:OWASP_LLM"


def test_canonical_key_endpoint_normalization():
    """Verify endpoint normalizations: slashes, case, query-string stripping, percent-decoding."""
    # Slashes and query stripping
    key1 = SecurityRegressionEngine.build_canonical_key(
        endpoint="/api/v1/chat/?user=123#frag",
        risk_id="LLM01",
    )
    assert key1 == "/api/v1/chat:LLM01:POST:OWASP_LLM"

    # Percent decoding
    key2 = SecurityRegressionEngine.build_canonical_key(
        endpoint="/api%2Fv1%2Fchat",
        risk_id="LLM01",
    )
    assert key2 == "/api/v1/chat:LLM01:POST:OWASP_LLM"

    # Full URL path extraction
    key3 = SecurityRegressionEngine.build_canonical_key(
        endpoint="http://127.0.0.1:8000/api/v1/chat",
        risk_id="LLM01",
    )
    assert key3 == "/api/v1/chat:LLM01:POST:OWASP_LLM"


def test_canonical_key_distinct_endpoints_preserved():
    """Distinct endpoints and methods must not collide."""
    key_chat = SecurityRegressionEngine.build_canonical_key("/api/chat", "LLM01", "POST")
    key_prompt = SecurityRegressionEngine.build_canonical_key("/api/prompt", "LLM01", "POST")
    key_get = SecurityRegressionEngine.build_canonical_key("/api/chat", "LLM01", "GET")
    key_llm02 = SecurityRegressionEngine.build_canonical_key("/api/chat", "LLM02", "POST")

    assert key_chat != key_prompt
    assert key_chat != key_get
    assert key_chat != key_llm02


# =====================================================================
# 2. Five Finding Delta Classification Tests
# =====================================================================

def test_classify_new_vulnerability():
    """Absent in baseline, vulnerable in current -> NEW_VULNERABILITY."""
    delta = SecurityRegressionEngine.classify_delta(
        canonical_key="/api/chat:LLM01:POST:OWASP_LLM",
        baseline_record=None,
        current_record={
            "endpoint": "/api/chat",
            "risk_id": "LLM01",
            "http_method": "POST",
            "category": "OWASP_LLM",
            "status": "CONFIRMED",
            "severity": "CRITICAL",
            "cvss_score": 9.3,
        },
    )
    assert delta is not None
    assert delta.delta_type == "NEW_VULNERABILITY"
    assert delta.baseline_status == "UNTESTED"
    assert delta.current_status == "CONFIRMED"
    assert delta.severity == "CRITICAL"


def test_classify_resolved_vulnerability():
    """Vulnerable in baseline, blocked/mitigated in current -> RESOLVED_VULNERABILITY."""
    delta = SecurityRegressionEngine.classify_delta(
        canonical_key="/api/chat:LLM01:POST:OWASP_LLM",
        baseline_record={
            "endpoint": "/api/chat",
            "risk_id": "LLM01",
            "status": "CONFIRMED",
        },
        current_record={
            "endpoint": "/api/chat",
            "risk_id": "LLM01",
            "status": "BLOCKED",
            "severity": "HIGH",
        },
    )
    assert delta is not None
    assert delta.delta_type == "RESOLVED_VULNERABILITY"
    assert delta.baseline_status == "CONFIRMED"
    assert delta.current_status == "BLOCKED"


def test_classify_persistent_vulnerability():
    """Vulnerable in baseline, vulnerable in current -> PERSISTENT_VULNERABILITY."""
    delta = SecurityRegressionEngine.classify_delta(
        canonical_key="/api/chat:LLM01:POST:OWASP_LLM",
        baseline_record={
            "endpoint": "/api/chat",
            "risk_id": "LLM01",
            "status": "VULNERABLE",
        },
        current_record={
            "endpoint": "/api/chat",
            "risk_id": "LLM01",
            "status": "CONFIRMED",
            "severity": "CRITICAL",
        },
    )
    assert delta is not None
    assert delta.delta_type == "PERSISTENT_VULNERABILITY"
    assert delta.baseline_status == "VULNERABLE"
    assert delta.current_status == "CONFIRMED"


def test_classify_regression_detected_overrides_when_previously_blocked():
    """Previously BLOCKED/REFUTED in baseline, now VULNERABLE in current -> REGRESSION_DETECTED."""
    delta = SecurityRegressionEngine.classify_delta(
        canonical_key="/api/chat:LLM01:POST:OWASP_LLM",
        baseline_record={
            "endpoint": "/api/chat",
            "risk_id": "LLM01",
            "status": "BLOCKED",
        },
        current_record={
            "endpoint": "/api/chat",
            "risk_id": "LLM01",
            "status": "VULNERABLE",
            "severity": "HIGH",
        },
    )
    assert delta is not None
    assert delta.delta_type == "REGRESSION_DETECTED"
    assert delta.baseline_status == "BLOCKED"
    assert delta.current_status == "VULNERABLE"


def test_classify_reopened_vulnerability_with_historical_proof(db):
    """Vulnerability confirmed in current, with historical resolution proof -> REOPENED_VULNERABILITY."""
    finding_id = f"FIND-REOPEN-{uuid.uuid4().hex[:6]}"
    finding = SecurityFinding(
        id=str(uuid.uuid4()),
        finding_id=finding_id,
        scenario_id="LLM02-01",
        risk_id="LLM02",
        title="Sensitive Info Leak",
        affected_endpoint="/api/leak",
        http_method="POST",
        lifecycle_status="REMEDIATION_VERIFIED",
        severity="HIGH",
        confidence=0.9,
    )
    db.add(finding)
    db.commit()

    # Record history transition to REMEDIATION_VERIFIED
    hist = SecurityFindingHistory(
        id=str(uuid.uuid4()),
        history_id=f"HIST-{uuid.uuid4().hex[:6]}",
        finding_id=finding_id,
        previous_state="REMEDIATION_PLANNED",
        new_state="REMEDIATION_VERIFIED",
        transition_reason="Verified mitigated by auditor",
    )
    db.add(hist)
    db.commit()

    delta = SecurityRegressionEngine.classify_delta(
        canonical_key="/api/leak:LLM02:POST:OWASP_LLM",
        baseline_record=None,  # Not in immediate baseline, but has historical proof
        current_record={
            "endpoint": "/api/leak",
            "risk_id": "LLM02",
            "status": "CONFIRMED",
            "severity": "HIGH",
            "finding_obj": finding,
        },
        db=db,
        linked_finding=finding,
    )
    assert delta is not None
    assert delta.delta_type == "REOPENED_VULNERABILITY"
    assert delta.current_status == "CONFIRMED"


def test_classify_stable_defense_not_treated_as_vulnerability():
    """Blocked in both baseline and current returns None (not an alert delta)."""
    delta = SecurityRegressionEngine.classify_delta(
        canonical_key="/api/chat:LLM01:POST:OWASP_LLM",
        baseline_record={
            "endpoint": "/api/chat",
            "risk_id": "LLM01",
            "status": "BLOCKED",
        },
        current_record={
            "endpoint": "/api/chat",
            "risk_id": "LLM01",
            "status": "BLOCKED",
        },
    )
    assert delta is None


# =====================================================================
# 3. Population Discrepancy & Mathematical Metrics Tests
# =====================================================================

def test_population_metrics_identical_populations():
    """When both runs test identical scenarios and all are defended."""
    keys = {"/api/1:LLM01:POST:OWASP_LLM", "/api/2:LLM02:POST:OWASP_LLM"}
    records = {
        "/api/1:LLM01:POST:OWASP_LLM": {"status": "BLOCKED"},
        "/api/2:LLM02:POST:OWASP_LLM": {"status": "BLOCKED"},
    }
    (
        base_res,
        curr_res,
        inter_res,
        drift,
        expansion,
        disclosure,
    ) = SecurityRegressionEngine.compute_population_metrics(
        baseline_keys=keys,
        current_keys=keys,
        current_records=records,
        baseline_records=records,
    )

    assert base_res == 1.0
    assert curr_res == 1.0
    assert inter_res == 1.0
    assert drift == 0.0
    assert expansion == 1.0
    assert disclosure.has_population_discrepancy is False
    assert disclosure.intersection_scenarios_count == 2
    assert disclosure.warning_message is None


def test_population_metrics_expansion_and_caveat_disclosure():
    """Baseline tests 2 scenarios; Current expands to 4 scenarios."""
    base_keys = {"/api/1:LLM01:POST:OWASP_LLM", "/api/2:LLM02:POST:OWASP_LLM"}
    curr_keys = {
        "/api/1:LLM01:POST:OWASP_LLM",
        "/api/2:LLM02:POST:OWASP_LLM",
        "/api/3:ASI01:POST:OWASP_LLM",
        "/api/4:ASI02:POST:OWASP_LLM",
    }
    base_records = {
        "/api/1:LLM01:POST:OWASP_LLM": {"status": "BLOCKED"},
        "/api/2:LLM02:POST:OWASP_LLM": {"status": "CONFIRMED"},  # 1 of 2 defended -> 0.5
    }
    curr_records = {
        "/api/1:LLM01:POST:OWASP_LLM": {"status": "BLOCKED"},
        "/api/2:LLM02:POST:OWASP_LLM": {"status": "BLOCKED"},  # now both common defended -> 1.0
        "/api/3:ASI01:POST:OWASP_LLM": {"status": "CONFIRMED"},
        "/api/4:ASI02:POST:OWASP_LLM": {"status": "CONFIRMED"},
    }

    (
        base_res,
        curr_res,
        inter_res,
        drift,
        expansion,
        disclosure,
    ) = SecurityRegressionEngine.compute_population_metrics(
        baseline_keys=base_keys,
        current_keys=curr_keys,
        current_records=curr_records,
        baseline_records=base_records,
    )

    assert base_res == 0.5
    assert curr_res == 0.5  # 2 of 4 defended
    assert inter_res == 1.0  # Over common 2 scenarios, both are now blocked!
    assert drift == 0.5  # Posture over common set improved from 0.5 to 1.0
    assert expansion == 2.0  # 4 / 2
    assert disclosure.has_population_discrepancy is True
    assert disclosure.current_only_count == 2
    assert disclosure.baseline_only_count == 0
    assert "Population discrepancy detected" in disclosure.warning_message


def test_inconclusive_endpoints_never_classified_as_secure():
    """Untested or inconclusive endpoints are never counted as defended."""
    keys = {"/api/1:LLM01:POST:OWASP_LLM", "/api/2:LLM02:POST:OWASP_LLM"}
    records = {
        "/api/1:LLM01:POST:OWASP_LLM": {"status": "BLOCKED"},
        "/api/2:LLM02:POST:OWASP_LLM": {"status": "INCONCLUSIVE"},
    }
    (
        base_res,
        curr_res,
        inter_res,
        drift,
        expansion,
        disclosure,
    ) = SecurityRegressionEngine.compute_population_metrics(
        baseline_keys=keys,
        current_keys=keys,
        current_records=records,
        baseline_records=records,
    )

    # 1 defended out of (1 evaluable + 1 inconclusive) -> 1 / 2 = 0.5
    assert curr_res == 0.5
    assert inter_res == 0.5


def test_zero_intersection_population_behavior():
    """When baseline and current test completely disjoint attack surfaces."""
    base_keys = {"/api/a:LLM01:POST:OWASP_LLM"}
    curr_keys = {"/api/b:LLM02:POST:OWASP_LLM"}
    base_records = {"/api/a:LLM01:POST:OWASP_LLM": {"status": "BLOCKED"}}
    curr_records = {"/api/b:LLM02:POST:OWASP_LLM": {"status": "BLOCKED"}}

    (
        base_res,
        curr_res,
        inter_res,
        drift,
        expansion,
        disclosure,
    ) = SecurityRegressionEngine.compute_population_metrics(
        baseline_keys=base_keys,
        current_keys=curr_keys,
        current_records=curr_records,
        baseline_records=base_records,
    )

    assert inter_res == 1.0  # Default neutral
    assert drift == 0.0
    assert disclosure.has_population_discrepancy is True
    assert disclosure.intersection_scenarios_count == 0


# =====================================================================
# 4. Target Isolation Enforcement Tests
# =====================================================================

def test_target_isolation_mismatched_target_rejected():
    """Cross-target comparison fails closed with TargetIsolationViolationError."""
    with pytest.raises(TargetIsolationViolationError) as exc_info:
        SecurityRegressionEngine.compare_datasets(
            baseline_records_list=[],
            current_records_list=[],
            baseline_meta={"target_url": "http://127.0.0.1:8000"},
            current_meta={"target_url": "http://127.0.0.1:9000"},
            allow_cross_target=False,
        )
    assert "Cross-target comparison prohibited" in str(exc_info.value)


def test_target_isolation_mismatched_target_permitted_with_flag():
    """Cross-target comparison succeeds when allow_cross_target=True."""
    res = SecurityRegressionEngine.compare_datasets(
        baseline_records_list=[],
        current_records_list=[],
        baseline_meta={"target_url": "http://127.0.0.1:8000"},
        current_meta={"target_url": "http://127.0.0.1:9000"},
        allow_cross_target=True,
    )
    assert res.regression_verdict == "PASSED_NO_REGRESSIONS"


def test_target_isolation_mismatched_environment_rejected():
    """Cross-environment comparison fails closed when flag is False."""
    with pytest.raises(TargetIsolationViolationError) as exc_info:
        SecurityRegressionEngine.compare_datasets(
            baseline_records_list=[],
            current_records_list=[],
            baseline_meta={"target_url": "http://127.0.0.1:8000", "environment": "staging"},
            current_meta={"target_url": "http://127.0.0.1:8000", "environment": "production"},
            allow_cross_environment=False,
        )
    assert "Cross-environment comparison prohibited" in str(exc_info.value)


def test_target_isolation_mismatched_environment_permitted_with_flag():
    """Cross-environment comparison succeeds when allow_cross_environment=True."""
    res = SecurityRegressionEngine.compare_datasets(
        baseline_records_list=[],
        current_records_list=[],
        baseline_meta={"target_url": "http://127.0.0.1:8000", "environment": "staging"},
        current_meta={"target_url": "http://127.0.0.1:8000", "environment": "production"},
        allow_cross_environment=True,
    )
    assert res.regression_verdict == "PASSED_NO_REGRESSIONS"


# =====================================================================
# 5. Database Plan-to-Plan Comparison & Safe Deletion Tests
# =====================================================================

def test_compare_plans_in_database(db):
    """Create two plans in DB and execute full regression comparison."""
    plan_base = create_test_session_and_plan(db, stage="BASELINE")
    plan_curr = create_test_session_and_plan(db, stage="POST_MITIGATION")

    # Baseline: 1 blocked, 1 vulnerable
    add_execution_to_plan(db, plan_base.id, "LLM01-01", "LLM01", "/api/chat", "BLOCKED")
    add_execution_to_plan(db, plan_base.id, "LLM02-01", "LLM02", "/api/leak", "VULNERABLE")

    # Current: LLM01 regressed to VULNERABLE, LLM02 resolved to BLOCKED
    add_execution_to_plan(db, plan_curr.id, "LLM01-01", "LLM01", "/api/chat", "VULNERABLE")
    add_execution_to_plan(db, plan_curr.id, "LLM02-01", "LLM02", "/api/leak", "BLOCKED")

    comparison = SecurityRegressionEngine.compare_plans(
        db=db,
        baseline_plan_id=plan_base.id,
        current_plan_id=plan_curr.id,
    )

    assert comparison.regression_verdict == "REGRESSIONS_DETECTED"
    assert comparison.regression_findings_count == 1
    assert comparison.resolved_findings_count == 1
    assert comparison.new_findings_count == 0

    # Verify persistent database record in security_regression_comparisons
    stored = (
        db.query(SecurityRegressionComparison)
        .filter(SecurityRegressionComparison.comparison_id == comparison.comparison_id)
        .first()
    )
    assert stored is not None
    assert stored.regression_verdict == "REGRESSIONS_DETECTED"
    assert stored.baseline_plan_id == plan_base.id
    assert stored.current_plan_id == plan_curr.id


def test_safe_foreign_key_deletion(db):
    """Deleting a referenced execution plan sets foreign key to NULL without deleting comparison."""
    from sqlalchemy import text
    try:
        db.execute(text("PRAGMA foreign_keys = ON;"))
        plan_base = create_test_session_and_plan(db)
        plan_curr = create_test_session_and_plan(db)

        add_execution_to_plan(db, plan_base.id, "SCEN-01", "LLM01", "/api/test", "BLOCKED")
        add_execution_to_plan(db, plan_curr.id, "SCEN-01", "LLM01", "/api/test", "BLOCKED")

        comp = SecurityRegressionEngine.compare_plans(db, plan_base.id, plan_curr.id)
        comp_id = comp.comparison_id

        # Delete baseline plan
        db.delete(plan_base)
        db.commit()
        db.expire_all()

        # Comparison record must still exist with baseline_plan_id set to NULL
        stored = (
            db.query(SecurityRegressionComparison)
            .filter(SecurityRegressionComparison.comparison_id == comp_id)
            .first()
        )
        assert stored is not None
        assert stored.baseline_plan_id is None
        assert stored.current_plan_id == plan_curr.id
    finally:
        db.execute(text("PRAGMA foreign_keys = OFF;"))
        db.commit()


def test_canonical_database_records_untouched():
    """Regression operations must never alter canonical baseline tables."""
    import sqlite3
    db_candidates = [
        Path("ai_security_poc.db"),
        Path("ai-security-poc-phase1/_backups/canonical_db/ai_security_poc.db"),
    ]
    canonical_path = None
    for cand in db_candidates:
        if cand.exists():
            canonical_path = cand
            break

    assert canonical_path is not None, "Canonical database file must exist"
    conn = sqlite3.connect(f"file:{canonical_path.resolve().as_posix()}?mode=ro", uri=True)
    c = conn.cursor()
    c_attack = c.execute("SELECT COUNT(*) FROM attack_results;").fetchone()[0]
    c_model = c.execute("SELECT COUNT(*) FROM model_comparisons;").fetchone()[0]
    c_audit = c.execute("SELECT COUNT(*) FROM security_audit_logs;").fetchone()[0]
    c_eval = c.execute("SELECT COUNT(*) FROM evaluation_runs;").fetchone()[0]
    conn.close()

    assert c_attack == 786
    assert c_model == 138
    assert c_audit == 693
    assert c_eval == 96


# =====================================================================
# 6. REST API Endpoint Tests
# =====================================================================

def test_api_compare_success(client, db):
    """POST /api/security-agent/regression/compare returns 200 with full metrics."""
    plan_base = create_test_session_and_plan(db)
    plan_curr = create_test_session_and_plan(db)

    add_execution_to_plan(db, plan_base.id, "SCEN-01", "LLM01", "/api/chat", "VULNERABLE")
    add_execution_to_plan(db, plan_curr.id, "SCEN-01", "LLM01", "/api/chat", "BLOCKED")

    payload = {
        "baseline_plan_id": plan_base.id,
        "current_plan_id": plan_curr.id,
    }
    res = client.post("/api/security-agent/regression/compare", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["regression_verdict"] == "IMPROVED_ALL_RESOLVED"
    assert data["resolved_findings_count"] == 1
    assert data["regression_findings_count"] == 0
    assert len(data["finding_deltas"]) == 1
    assert data["finding_deltas"][0]["delta_type"] == "RESOLVED_VULNERABILITY"


def test_api_compare_missing_plans_404(client):
    """POST /api/security-agent/regression/compare with nonexistent plan returns 404."""
    payload = {
        "baseline_plan_id": "nonexistent_base",
        "current_plan_id": "nonexistent_curr",
    }
    res = client.post("/api/security-agent/regression/compare", json=payload)
    assert res.status_code == 404


def test_api_compare_cross_target_rejection_400(client, db):
    """POST /api/security-agent/regression/compare with mismatched target without flag returns 400."""
    plan_base = create_test_session_and_plan(db, target_url="http://127.0.0.1:8000")
    plan_curr = create_test_session_and_plan(db, target_url="http://127.0.0.1:9000")

    payload = {
        "baseline_plan_id": plan_base.id,
        "current_plan_id": plan_curr.id,
        "allow_cross_target": False,
    }
    res = client.post("/api/security-agent/regression/compare", json=payload)
    assert res.status_code == 400
    assert "Cross-target comparison prohibited" in res.json()["detail"]


def test_api_get_comparison_by_id(client, db):
    """GET /api/security-agent/regression/{comparison_id} retrieves comparison."""
    plan_base = create_test_session_and_plan(db)
    plan_curr = create_test_session_and_plan(db)

    add_execution_to_plan(db, plan_base.id, "SCEN-01", "LLM01", "/api/chat", "BLOCKED")
    add_execution_to_plan(db, plan_curr.id, "SCEN-01", "LLM01", "/api/chat", "BLOCKED")

    comp = SecurityRegressionEngine.compare_plans(db, plan_base.id, plan_curr.id)
    comp_id = comp.comparison_id

    res = client.get(f"/api/security-agent/regression/{comp_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["comparison_id"] == comp_id
    assert data["regression_verdict"] == "PASSED_NO_REGRESSIONS"


def test_api_get_comparison_not_found(client):
    """GET /api/security-agent/regression/invalid_id returns 404."""
    res = client.get("/api/security-agent/regression/nonexistent_comp_id")
    assert res.status_code == 404


def test_api_list_regression_history(client, db):
    """GET /api/security-agent/regression/history returns historical runs."""
    plan_base = create_test_session_and_plan(db)
    plan_curr = create_test_session_and_plan(db)

    add_execution_to_plan(db, plan_base.id, "SCEN-01", "LLM01", "/api/chat", "BLOCKED")
    add_execution_to_plan(db, plan_curr.id, "SCEN-01", "LLM01", "/api/chat", "BLOCKED")

    SecurityRegressionEngine.compare_plans(db, plan_base.id, plan_curr.id)

    res = client.get("/api/security-agent/regression/history?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "comparisons" in data
    assert data["total_count"] >= 1
    assert len(data["comparisons"]) >= 1
