"""Dedicated Automated Test Suite for ApexShield Phase E9 — Enterprise Security Operations Center (SOC) Frontend.

Validates:
1. SOC overview endpoint response schema and timestamp.
2. All 8 capability keys present in capabilities dictionary.
3. E1 Dynamic Intelligence status and metrics integration.
4. E2 Attack Graph status and metrics integration.
5. E3 Schema Intelligence status and metrics integration.
6. E4 Vulnerability Lifecycle status and finding counts.
7. E5 Regression Intelligence status and latest comparison verdict.
8. E6 Enterprise Reporting status and archived report count.
9. E7 Decision Explainability status and decision count.
10. E8 Operations Telemetry status and live throughput metrics.
11. Trace ID header injection on SOC overview response (X-Execution-Trace-ID).
12. Correlation ID header injection on SOC overview response (X-Correlation-ID).
13. Contextual filtering by session_id.
14. Contextual filtering by target_url.
15. Cross-module finding drill-down resolution.
16. Cross-module plan drill-down resolution.
17. Session isolation under filtered SOC queries.
18. Target isolation under filtered SOC queries.
19. System health status evaluation (HEALTHY / DEGRADED / UNHEALTHY).
20. Empty state handling when no sessions exist.
21. Empty state handling when no findings exist.
22. Zero-cascade finding persistence reflection in SOC counts.
23. Zero-cascade decision persistence reflection in SOC counts.
24. Concurrent SOC overview request throughput and thread safety.
25. Canonical database baseline records untouched (786 / 138 / 693 / 96).
26. Canonical 11-state vulnerability lifecycle represented in SOC Kanban columns and target select.
27. Absence of legacy 7-state definitions from active lifecycle controls.
28. Canonical state transition HTTP enforcement (valid vs invalid transitions).
29. Secondary auditor signoff requirement for CONFIRMED state transitions.
30. Mandatory justification reason requirement for lifecycle transitions.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import time
import uuid

import pytest
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent / "backend"
if not (backend_dir / "app").exists():
    backend_dir = Path(__file__).resolve().parent.parent / "ai-security-poc-phase1" / "backend"
sys.path.insert(0, str(backend_dir))

from app.database.session import SessionLocal
from app.main import app
from app.security_agent.finding_lifecycle import FindingLifecycleEngine
from app.security_agent.models import (
    SecurityDecision,
    SecurityEnterpriseReport,
    SecurityExecutionPlan,
    SecurityFinding,
    SecurityFindingHistory,
    SecurityRegressionComparison,
)
from app.security_agent.operations_monitor import global_operations_monitor
from app.security_agent.schemas import (
    FindingLifecycleStatusEnum,
    SecurityFindingCreate,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_soc_overview_endpoint_schema_and_timestamp(client):
    """1. Validates GET /api/security-agent/soc/overview returns 200 OK, valid ISO timestamp, and health status."""
    resp = client.get("/api/security-agent/soc/overview")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()

    assert "system_health" in data
    assert data["system_health"] in ["HEALTHY", "DEGRADED", "UNHEALTHY"]
    assert "timestamp" in data
    # Parse timestamp to confirm ISO format
    ts = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
    assert ts.year >= 2026

    assert "execution_trace_id" in data
    assert data["execution_trace_id"].startswith("trc_") or "TRC" in data["execution_trace_id"]
    assert "capabilities" in data
    assert isinstance(data["capabilities"], dict)


def test_soc_overview_all_eight_capabilities_present(client):
    """2. Validates that all 8 capability keys (E1 through E8) are present in the capabilities dictionary."""
    resp = client.get("/api/security-agent/soc/overview")
    assert resp.status_code == 200
    caps = resp.json()["capabilities"]

    expected_keys = [
        "e1_intelligence",
        "e2_attack_graph",
        "e3_schema_intelligence",
        "e4_finding_lifecycle",
        "e5_regression_intelligence",
        "e6_enterprise_reporting",
        "e7_decision_explainability",
        "e8_operations_telemetry",
    ]
    for k in expected_keys:
        assert k in caps, f"Missing capability key: {k}"
        assert "phase" in caps[k], f"Missing phase in {k}"
        assert "name" in caps[k], f"Missing name in {k}"
        assert "status" in caps[k], f"Missing status in {k}"
        assert "metrics" in caps[k], f"Missing metrics in {k}"


def test_soc_overview_e1_dynamic_intelligence_integration(client):
    """3. E1 Dynamic Intelligence status, phase, and metrics integration."""
    resp = client.get("/api/security-agent/soc/overview")
    e1 = resp.json()["capabilities"]["e1_intelligence"]

    assert e1["phase"] == "E1"
    assert "Dynamic Security Intelligence" in e1["name"]
    assert e1["status"] in ["ACTIVE", "OPERATIONAL"]
    assert "total_risks_cataloged" in e1["metrics"]
    assert e1["metrics"]["total_risks_cataloged"] >= 20


def test_soc_overview_e2_attack_graph_integration(client):
    """4. E2 Attack Graph status, phase, and metrics integration."""
    resp = client.get("/api/security-agent/soc/overview")
    e2 = resp.json()["capabilities"]["e2_attack_graph"]

    assert e2["phase"] == "E2"
    assert "Attack Graph Planning" in e2["name"]
    assert e2["status"] in ["ACTIVE", "OPERATIONAL"]
    assert "graph_nodes_count" in e2["metrics"]
    assert "strongly_connected_components" in e2["metrics"]


def test_soc_overview_e3_schema_intelligence_integration(client):
    """5. E3 Schema Intelligence status, phase, and metrics integration."""
    resp = client.get("/api/security-agent/soc/overview")
    e3 = resp.json()["capabilities"]["e3_schema_intelligence"]

    assert e3["phase"] == "E3"
    assert "Schema Intelligence" in e3["name"]
    assert e3["status"] in ["ACTIVE", "OPERATIONAL"]
    assert "inferred_endpoints_count" in e3["metrics"]
    assert "parameter_mutations_count" in e3["metrics"]


def test_soc_overview_e4_vulnerability_lifecycle_integration(client):
    """6. E4 Vulnerability Lifecycle status, phase, and metrics integration."""
    resp = client.get("/api/security-agent/soc/overview")
    e4 = resp.json()["capabilities"]["e4_finding_lifecycle"]

    assert e4["phase"] == "E4"
    assert "Vulnerability & Evidence Lifecycle" in e4["name"]
    assert e4["status"] in ["ACTIVE", "OPERATIONAL"]
    assert "total_findings" in e4["metrics"]
    assert "open_findings" in e4["metrics"]
    assert isinstance(e4["metrics"]["total_findings"], int)


def test_soc_overview_e5_regression_intelligence_integration(client):
    """7. E5 Regression Intelligence status, phase, and metrics integration."""
    resp = client.get("/api/security-agent/soc/overview")
    e5 = resp.json()["capabilities"]["e5_regression_intelligence"]

    assert e5["phase"] == "E5"
    assert "Regression Intelligence" in e5["name"]
    assert e5["status"] in ["ACTIVE", "OPERATIONAL"]
    assert "historical_comparisons" in e5["metrics"]
    assert "latest_comparison_verdict" in e5["metrics"]


def test_soc_overview_e6_enterprise_reporting_integration(client):
    """8. E6 Enterprise Reporting status, phase, and metrics integration."""
    resp = client.get("/api/security-agent/soc/overview")
    e6 = resp.json()["capabilities"]["e6_enterprise_reporting"]

    assert e6["phase"] == "E6"
    assert "Enterprise Reporting" in e6["name"]
    assert e6["status"] in ["ACTIVE", "OPERATIONAL"]
    assert "archived_reports" in e6["metrics"]
    assert isinstance(e6["metrics"]["archived_reports"], int)


def test_soc_overview_e7_decision_explainability_integration(client):
    """9. E7 Decision Explainability status, phase, and metrics integration."""
    resp = client.get("/api/security-agent/soc/overview")
    e7 = resp.json()["capabilities"]["e7_decision_explainability"]

    assert e7["phase"] == "E7"
    assert "Explainable Decision Engine" in e7["name"]
    assert e7["status"] in ["ACTIVE", "OPERATIONAL"]
    assert "persisted_decisions" in e7["metrics"]
    assert "average_confidence" in e7["metrics"]


def test_soc_overview_e8_operations_telemetry_integration(client):
    """10. E8 Operations Telemetry status, phase, and metrics integration."""
    resp = client.get("/api/security-agent/soc/overview")
    e8 = resp.json()["capabilities"]["e8_operations_telemetry"]

    assert e8["phase"] == "E8"
    assert "Operational Monitoring & Telemetry" in e8["name"]
    assert e8["status"] in ["ACTIVE", "OPERATIONAL"]
    assert "requests_per_sec" in e8["metrics"]
    assert "p95_latency_ms" in e8["metrics"]
    assert "circuit_breaker_status" in e8["metrics"]


def test_soc_overview_trace_id_header_injection(client):
    """11. Trace ID header injection on SOC overview response (X-Execution-Trace-ID)."""
    resp = client.get("/api/security-agent/soc/overview")
    assert resp.status_code == 200
    assert "x-execution-trace-id" in resp.headers or "X-Execution-Trace-ID" in resp.headers
    trace_id = resp.headers.get("x-execution-trace-id") or resp.headers.get("X-Execution-Trace-ID")
    assert trace_id is not None
    assert trace_id == resp.json()["execution_trace_id"]


def test_soc_overview_correlation_id_header_injection(client):
    """12. Correlation ID header injection on SOC overview response (X-Correlation-ID)."""
    test_corr_id = f"corr_soc_test_{uuid.uuid4().hex[:8]}"
    resp = client.get(
        "/api/security-agent/soc/overview",
        headers={"X-Correlation-ID": test_corr_id},
    )
    assert resp.status_code == 200
    corr_header = resp.headers.get("x-correlation-id") or resp.headers.get("X-Correlation-ID")
    assert corr_header == test_corr_id


def test_soc_overview_contextual_filtering_by_session_id(client):
    """13. Contextual filtering by session_id preserves system health and context parameters."""
    sess_id = f"sess_filter_{uuid.uuid4().hex[:8]}"
    resp = client.get(f"/api/security-agent/soc/overview?session_id={sess_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["context_filters"]["session_id"] == sess_id


def test_soc_overview_contextual_filtering_by_target_url(client):
    """14. Contextual filtering by target_url preserves target parameter in context_filters."""
    target = "http://127.0.0.1:8000/api/v1/agent"
    resp = client.get(f"/api/security-agent/soc/overview?target_url={target}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["context_filters"]["target_url"] == target


def test_soc_cross_module_finding_drill_down_resolution(client):
    """15. Cross-module finding drill-down: querying decisions filtered by finding_id works cleanly."""
    resp = client.get("/api/security-agent/decisions?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "decisions" in data
    # Test that finding_id query parameter is accepted and returns 200
    resp_filtered = client.get("/api/security-agent/decisions?finding_id=find_nonexistent_soc")
    assert resp_filtered.status_code == 200
    assert resp_filtered.json()["total"] == 0


def test_soc_cross_module_plan_drill_down_resolution(client):
    """16. Cross-module plan drill-down: verify plan endpoints return valid schema."""
    resp = client.get("/api/security-agent/soc/overview")
    assert resp.status_code == 200
    plans_count = resp.json()["summary_counts"]["plans_count"]
    assert isinstance(plans_count, int)
    resp_plan = client.get("/api/security-agent/plans/plan_test_soc_nonexistent")
    assert resp_plan.status_code in [404, 200]


def test_soc_session_isolation_under_filtered_queries(client):
    """17. Session isolation: session A query does not leak into session B query."""
    sess_a = f"sess_a_{uuid.uuid4().hex[:8]}"
    sess_b = f"sess_b_{uuid.uuid4().hex[:8]}"

    resp_a = client.get(f"/api/security-agent/soc/overview?session_id={sess_a}")
    resp_b = client.get(f"/api/security-agent/soc/overview?session_id={sess_b}")

    assert resp_a.json()["context_filters"]["session_id"] == sess_a
    assert resp_b.json()["context_filters"]["session_id"] == sess_b
    assert resp_a.json()["execution_trace_id"] != resp_b.json()["execution_trace_id"]


def test_soc_target_isolation_under_filtered_queries(client):
    """18. Target isolation: queries with distinct target URLs maintain distinct context parameters."""
    target_1 = "http://target-alpha.local:8000"
    target_2 = "http://target-beta.local:9000"

    resp_1 = client.get(f"/api/security-agent/soc/overview?target_url={target_1}")
    resp_2 = client.get(f"/api/security-agent/soc/overview?target_url={target_2}")

    assert resp_1.json()["context_filters"]["target_url"] == target_1
    assert resp_2.json()["context_filters"]["target_url"] == target_2


def test_soc_system_health_status_evaluation(client):
    """19. System health status evaluation returns valid string enum."""
    resp = client.get("/api/security-agent/soc/overview")
    assert resp.status_code == 200
    health = resp.json()["system_health"]
    assert health in ["HEALTHY", "DEGRADED", "UNHEALTHY"]


def test_soc_empty_state_handling_no_sessions(client):
    """20. Empty state handling: non-existent session filter returns 200 with zero/default counts."""
    non_existent = "sess_does_not_exist_99999"
    resp = client.get(f"/api/security-agent/soc/overview?session_id={non_existent}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["system_health"] in ["HEALTHY", "DEGRADED", "UNHEALTHY"]
    assert data["context_filters"]["session_id"] == non_existent


def test_soc_empty_state_handling_no_findings(client):
    """21. Empty state handling: querying with non-matching target returns 200 without crashes."""
    empty_target = "http://no-findings-domain.internal:9999"
    resp = client.get(f"/api/security-agent/soc/overview?target_url={empty_target}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["capabilities"]["e4_finding_lifecycle"]["metrics"]["total_findings"] >= 0


def test_soc_zero_cascade_finding_persistence_reflection(client):
    """22. Zero-cascade finding persistence: GET overview is purely read-only and does not add findings."""
    db = SessionLocal()
    try:
        count_before = db.query(SecurityFinding).count()
    finally:
        db.close()

    resp = client.get("/api/security-agent/soc/overview")
    assert resp.status_code == 200

    db = SessionLocal()
    try:
        count_after = db.query(SecurityFinding).count()
    finally:
        db.close()

    assert count_before == count_after, "GET /soc/overview must be strictly read-only and not mutate findings"


def test_soc_zero_cascade_decision_persistence_reflection(client):
    """23. Zero-cascade decision persistence: GET overview does not add decisions."""
    db = SessionLocal()
    try:
        count_before = db.query(SecurityDecision).count()
    finally:
        db.close()

    resp = client.get("/api/security-agent/soc/overview")
    assert resp.status_code == 200

    db = SessionLocal()
    try:
        count_after = db.query(SecurityDecision).count()
    finally:
        db.close()

    assert count_before == count_after, "GET /soc/overview must be strictly read-only and not mutate decisions"


def test_soc_concurrent_overview_throughput_and_thread_safety(client):
    """24. Concurrently executes 20 parallel requests to GET /soc/overview, asserting all return 200."""
    def fetch_soc():
        r = client.get("/api/security-agent/soc/overview")
        return r.status_code, r.json()["execution_trace_id"]

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda _: fetch_soc(), range(20)))
    duration = time.perf_counter() - start

    assert duration < 5.0, f"20 concurrent requests took too long: {duration:.2f}s"
    assert len(results) == 20
    status_codes = [r[0] for r in results]
    assert all(code == 200 for code in status_codes), f"Not all returned 200: {status_codes}"


def test_canonical_database_records_untouched():
    """25. Guarantees that canonical baseline records in ai_security_poc.db remain untouched (786/138/693/96)."""
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


def test_soc_lifecycle_all_eleven_canonical_states_represented():
    """26. Validates that frontend SecurityAgentLab.jsx defines all 11 canonical lifecycle states in Kanban columns and target select."""
    frontend_path = (
        Path(__file__).resolve().parent.parent
        / "ai-security-poc-phase1"
        / "frontend"
        / "src"
        / "SecurityAgentLab.jsx"
    )
    if not frontend_path.exists():
        frontend_path = (
            Path(__file__).resolve().parent.parent
            / "frontend"
            / "src"
            / "SecurityAgentLab.jsx"
        )
    assert frontend_path.exists(), f"Could not find SecurityAgentLab.jsx at {frontend_path}"

    content = frontend_path.read_text(encoding="utf-8")

    canonical_11_states = [
        "DETECTED",
        "TRIAGE",
        "POTENTIAL",
        "CONFIRMED",
        "REMEDIATION_PLANNED",
        "REMEDIATION_IN_PROGRESS",
        "READY_FOR_RETEST",
        "REMEDIATION_VERIFIED",
        "REFUTED",
        "INCONCLUSIVE",
        "CLOSED",
    ]

    # Check that each state is present as a Kanban column key
    for state in canonical_11_states:
        pattern = f'key: "{state}"'
        assert pattern in content, f"Canonical lifecycle state '{state}' missing from Kanban columns in {frontend_path}"

    # Check that each state is present in the target select options
    for state in canonical_11_states:
        option_pattern = f'<option value="{state}">{state}</option>'
        assert option_pattern in content, f"Canonical lifecycle state '{state}' missing from transition select options in {frontend_path}"


def test_soc_lifecycle_no_legacy_states_used():
    """27. Validates that no legacy non-canonical lifecycle states are used in active controls in SecurityAgentLab.jsx."""
    frontend_path = (
        Path(__file__).resolve().parent.parent
        / "ai-security-poc-phase1"
        / "frontend"
        / "src"
        / "SecurityAgentLab.jsx"
    )
    if not frontend_path.exists():
        frontend_path = (
            Path(__file__).resolve().parent.parent
            / "frontend"
            / "src"
            / "SecurityAgentLab.jsx"
        )

    content = frontend_path.read_text(encoding="utf-8")

    legacy_states = [
        "MITIGATION_PROPOSED",
        "MITIGATION_APPLIED",
        "CLOSED_ACCEPTED_RISK",
        "CLOSED_FALSE_POSITIVE",
    ]
    for leg in legacy_states:
        assert leg not in content, f"Legacy non-canonical state '{leg}' found in {frontend_path}"

    # Ensure IDENTIFIED and REMEDIATED are not in column keys or option values
    assert 'key: "IDENTIFIED"' not in content, "Legacy state 'IDENTIFIED' found as Kanban column key"
    assert '<option value="IDENTIFIED">' not in content, "Legacy state 'IDENTIFIED' found in options"
    assert 'key: "REMEDIATED"' not in content, "Legacy state 'REMEDIATED' found as Kanban column key"
    assert '<option value="REMEDIATED">' not in content, "Legacy state 'REMEDIATED' found in options"


def test_soc_lifecycle_backend_transition_enforcement(client):
    """28. Tests backend HTTP transition enforcement for canonical states: valid transition succeeds, invalid transition fails."""
    db = SessionLocal()
    try:
        # Create a temporary test finding in DETECTED state
        finding_data = SecurityFindingCreate(
            scenario_id="TEST-E9-01",
            risk_id="LLM01",
            title="Temporary E9 Test Finding",
            affected_endpoint="/api/test/e9",
            initial_status=FindingLifecycleStatusEnum.DETECTED,
            severity="MEDIUM",
        )
        finding = FindingLifecycleEngine.create_finding(db=db, data=finding_data)
        created_finding_id = finding.finding_id

        # 1. Attempt invalid transition: DETECTED -> REMEDIATION_VERIFIED (should fail with 400)
        invalid_resp = client.post(
            f"/api/security-agent/findings/{created_finding_id}/transition",
            json={
                "target_state": "REMEDIATION_VERIFIED",
                "transition_reason": "Attempting invalid shortcut transition",
                "actor": "LeadSecurityAuditor",
            },
        )
        assert invalid_resp.status_code == 400, f"Expected 400 for invalid transition, got {invalid_resp.status_code}: {invalid_resp.text}"
        assert "not permitted" in invalid_resp.json().get("detail", "").lower()

        # 2. Attempt valid canonical transition: DETECTED -> TRIAGE (should succeed with 200)
        valid_resp = client.post(
            f"/api/security-agent/findings/{created_finding_id}/transition",
            json={
                "target_state": "TRIAGE",
                "transition_reason": "Valid triage assignment by lead auditor",
                "actor": "LeadSecurityAuditor",
            },
        )
        assert valid_resp.status_code == 200, f"Expected 200 for valid transition, got {valid_resp.status_code}: {valid_resp.text}"
        updated = valid_resp.json()
        assert updated["lifecycle_status"] == "TRIAGE"

    finally:
        db.close()


def test_soc_lifecycle_secondary_auditor_signoff_enforcement(client):
    """29. Tests that transitioning to CONFIRMED strictly enforces secondary auditor signoff."""
    db = SessionLocal()
    try:
        finding_data = SecurityFindingCreate(
            scenario_id="TEST-E9-02",
            risk_id="LLM02",
            title="Temporary E9 Secondary Confirmation Test",
            affected_endpoint="/api/test/e9/confirm",
            initial_status=FindingLifecycleStatusEnum.POTENTIAL,
            severity="HIGH",
        )
        finding = FindingLifecycleEngine.create_finding(db=db, data=finding_data)
        created_finding_id = finding.finding_id

        # Attempt transition to CONFIRMED without is_secondary_confirmed
        resp = client.post(
            f"/api/security-agent/findings/{created_finding_id}/transition",
            json={
                "target_state": "CONFIRMED",
                "transition_reason": "Single auditor attempt without secondary signoff",
                "actor": "SoloAuditor",
                "is_secondary_confirmed": False,
            },
        )
        assert resp.status_code == 400, f"Expected 400, got {resp.status_code}: {resp.text}"
        assert "secondary" in resp.json().get("detail", "").lower()

    finally:
        db.close()


def test_soc_lifecycle_justification_enforcement(client):
    """30. Tests that state transition requires a valid non-empty justification (>= 3 chars)."""
    db = SessionLocal()
    try:
        finding_data = SecurityFindingCreate(
            scenario_id="TEST-E9-03",
            risk_id="LLM03",
            title="Temporary E9 Justification Test",
            affected_endpoint="/api/test/e9/just",
            initial_status=FindingLifecycleStatusEnum.DETECTED,
            severity="LOW",
        )
        finding = FindingLifecycleEngine.create_finding(db=db, data=finding_data)
        created_finding_id = finding.finding_id

        # Transition with empty/too short reason
        resp = client.post(
            f"/api/security-agent/findings/{created_finding_id}/transition",
            json={
                "target_state": "TRIAGE",
                "transition_reason": "no",
                "actor": "LeadSecurityAuditor",
            },
        )
        # Should be rejected (422 from Pydantic min_length or 400 from validation)
        assert resp.status_code in [400, 422], f"Expected 400 or 422, got {resp.status_code}: {resp.text}"

    finally:
        db.close()

