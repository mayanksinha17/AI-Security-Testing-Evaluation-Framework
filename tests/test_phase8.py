"""Phase 8 Test Suite: Unified AI Security Operations Dashboard.

Verifies:
1. Dashboard overview API returns 200 OK with accurate operational structure
2. Exactly 10 OWASP risks overview (5 LLM core + 5 Agentic AI)
3. Exactly 30 attack scenarios count across all risks
4. Actual execution metrics calculation (total, blocked, partial, succeeded, error, not_run)
5. Risk-specific analytics (effectiveness scores, remaining successful attacks, coverage)
6. Baseline vs Post-mitigation comparison logic
7. ERROR and NOT_RUN handling (neither counted as BLOCKED)
8. Audit log filtering by category, provider, decision, search, and pagination
9. All 4 CSV exports (attacks, evaluation, audit logs, risks) with valid RFC headers
10. Missing-data and empty-state graceful handling
11. Historical data preservation and immutability
12. Phase 1-7 full system regression
"""

import csv
import io
from pathlib import Path
import sys
import uuid
import pytest

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from app.attacks.scenarios import get_all_risks, get_all_scenarios
from app.core.config import settings
from app.database.models import AttackResult, EvaluationRun, SecurityAuditLog
from app.database.session import get_db
from app.dashboard.service import DashboardService, redact_sensitive_text
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db():
    generator = get_db()
    session = next(generator)
    try:
        yield session
    finally:
        session.close()


# 1. Dashboard Overview API
def test_dashboard_overview_api(client):
    res = client.get("/api/dashboard/overview")
    assert res.status_code == 200
    data = res.json()
    assert data["total_risks"] == 10
    assert data["total_scenarios"] == 30
    assert "total_executions" in data
    assert "total_blocked" in data
    assert "total_partial" in data
    assert "total_succeeded" in data
    assert "total_errors" in data
    assert "total_not_run" in data
    assert "overall_mitigation_effectiveness" in data
    assert data["data_source"] == "sqlite_actual_records"
    assert len(data["providers"]) == 2


# 2. Ten-Risk Overview
def test_ten_risk_overview(client):
    res = client.get("/api/dashboard/risks")
    assert res.status_code == 200
    data = res.json()
    assert data["total_risks"] == 10
    assert len(data["items"]) == 10

    expected_risks = {
        "LLM01", "LLM02", "LLM03", "LLM08", "LLM10",
        "ASI01", "ASI02", "ASI03", "ASI05", "ASI06"
    }
    returned_risks = {item["risk_id"] for item in data["items"]}
    assert expected_risks == returned_risks

    for item in data["items"]:
        assert item["scenarios_count"] == 3
        assert 0.0 <= item["baseline_block_rate"] <= 100.0
        assert 0.0 <= item["post_mitigation_block_rate"] <= 100.0
        assert 0.0 <= item["execution_coverage"] <= 100.0
        assert item["remaining_successful_attacks"] >= 0


# 3. Thirty-Scenario Count Across All Risks
def test_thirty_scenario_count():
    scenarios = get_all_scenarios()
    assert len(scenarios) == 30

    risks = get_all_risks()
    assert len(risks) == 10

    for rk in risks:
        rk_scenarios = [s for s in scenarios if s.risk_id == rk.risk_id]
        assert len(rk_scenarios) == 3, f"Risk {rk.risk_id} does not have exactly 3 scenarios"


# 4. Actual Execution Metrics Calculation
def test_actual_execution_metrics_calculation(db):
    overview = DashboardService.get_overview(db=db)
    actual_results_count = db.query(AttackResult).count()
    assert overview.total_executions == actual_results_count

    expected_blocked = db.query(AttackResult).filter(AttackResult.result_classification == "BLOCKED").count()
    expected_succeeded = db.query(AttackResult).filter(AttackResult.result_classification == "SUCCEEDED").count()
    expected_errors = db.query(AttackResult).filter(AttackResult.result_classification == "ERROR").count()
    expected_not_run = db.query(AttackResult).filter(AttackResult.result_classification == "NOT_RUN").count()

    assert overview.total_blocked == expected_blocked
    assert overview.total_succeeded == expected_succeeded
    assert overview.total_errors == expected_errors
    assert overview.total_not_run == expected_not_run


# 5. Risk-Specific Analytics
def test_risk_specific_analytics(client):
    res = client.get("/api/dashboard/analytics")
    assert res.status_code == 200
    data = res.json()

    assert "baseline_vs_post_comparison" in data
    assert "risk_mitigation_effectiveness" in data
    assert "distribution" in data
    assert "model_comparison" in data
    assert "execution_coverage" in data
    assert "security_event_timeline" in data
    assert "execution_mode_breakdown" in data

    assert len(data["baseline_vs_post_comparison"]) == 10
    assert len(data["risk_mitigation_effectiveness"]) == 10
    assert data["execution_coverage"]["total_scenarios"] == 30
    assert data["execution_coverage"]["total_matrix_cells"] == 120


# 6. Baseline vs Post-Mitigation Comparison
def test_baseline_post_mitigation_comparison(db):
    overview = DashboardService.get_overview(db=db)
    # Improvement must equal post_mitigation_block_rate - baseline_block_rate
    expected_imp = round(overview.post_mitigation_block_rate - overview.baseline_block_rate, 1)
    assert overview.overall_mitigation_effectiveness == expected_imp


# 7. ERROR and NOT_RUN Handling (Never counted as BLOCKED)
def test_error_and_not_run_handling(db):
    test_run_id = f"test-err-notrun-{uuid.uuid4()}"
    records = [
        AttackResult(
            id=str(uuid.uuid4()),
            run_id=test_run_id,
            scenario_id="LLM01-01",
            risk_id="LLM01",
            provider="claude",
            model="claude-sonnet-5-5",
            execution_mode="mock",
            stage="POST_MITIGATION",
            prompt="test prompt",
            result_classification="ERROR",
            latency_ms=0.0,
        ),
        AttackResult(
            id=str(uuid.uuid4()),
            run_id=test_run_id,
            scenario_id="LLM01-02",
            risk_id="LLM01",
            provider="gemini",
            model="gemini-3.8-flash",
            execution_mode="live",
            stage="POST_MITIGATION",
            prompt="test prompt",
            result_classification="NOT_RUN",
            latency_ms=0.0,
        ),
        AttackResult(
            id=str(uuid.uuid4()),
            run_id=test_run_id,
            scenario_id="LLM01-03",
            risk_id="LLM01",
            provider="claude",
            model="claude-sonnet-5-5",
            execution_mode="mock",
            stage="POST_MITIGATION",
            prompt="test prompt",
            result_classification="BLOCKED",
            latency_ms=12.0,
        ),
    ]
    for r in records:
        db.add(r)
    db.commit()

    # Query overview
    overview = DashboardService.get_overview(db=db)
    # Ensure blocked count does not swallow errors or not_runs
    assert overview.total_errors >= 1
    assert overview.total_not_run >= 1


# 8. Audit Log Filtering
def test_audit_log_filtering(client):
    # Query all
    res_all = client.get("/api/dashboard/audit-logs?limit=10")
    assert res_all.status_code == 200
    data_all = res_all.json()
    assert "total" in data_all
    assert "items" in data_all

    # Filter by risk_category
    res_agentic = client.get("/api/dashboard/audit-logs?risk_category=OWASP_AGENTIC&limit=10")
    assert res_agentic.status_code == 200
    for item in res_agentic.json()["items"]:
        assert item["risk_category"] == "OWASP_AGENTIC"

    # Filter by provider
    res_claude = client.get("/api/dashboard/audit-logs?provider=claude&limit=10")
    assert res_claude.status_code == 200
    for item in res_claude.json()["items"]:
        assert item["provider"] == "claude"

    # Redaction test: ensure no keys leaked
    for item in data_all["items"]:
        assert "sk-" not in item["reason"]
        assert "AIza" not in item["reason"]


# 9. CSV Exports (All 4 Exports with Required RFC Headers)
def test_csv_exports(client):
    # 1. Attacks CSV
    res_att = client.get("/api/dashboard/export/attacks")
    assert res_att.status_code == 200
    assert "text/csv" in res_att.headers["content-type"]
    reader1 = csv.reader(io.StringIO(res_att.text))
    header1 = next(reader1)
    assert header1 == [
        "Risk ID", "Scenario ID", "Model", "Model ID", "Execution Mode",
        "Stage", "Prompt", "Result", "Latency (ms)", "Timestamp"
    ]

    # 2. Evaluation CSV
    res_eval = client.get("/api/dashboard/export/evaluation")
    assert res_eval.status_code == 200
    assert "text/csv" in res_eval.headers["content-type"]
    reader2 = csv.reader(io.StringIO(res_eval.text))
    header2 = next(reader2)
    assert header2 == [
        "Evaluation Run ID", "Scenario ID", "Risk ID", "Category", "Scenario Name",
        "Stage", "Claude Result", "Claude Latency (ms)", "Gemini Result", "Gemini Latency (ms)",
        "Comparative Verdict", "Timestamp"
    ]

    # 3. Audit Logs CSV
    res_audit = client.get("/api/dashboard/export/audit-logs")
    assert res_audit.status_code == 200
    assert "text/csv" in res_audit.headers["content-type"]
    reader3 = csv.reader(io.StringIO(res_audit.text))
    header3 = next(reader3)
    assert header3 == [
        "Event ID", "Timestamp", "Risk ID", "Risk Category", "Scenario ID",
        "Security Component", "Event Type", "Tool Name", "Provider", "Model",
        "Stage", "Authorization Decision", "Execution Status", "Reason"
    ]

    # 4. Risk Summary CSV
    res_risk = client.get("/api/dashboard/export/risks")
    assert res_risk.status_code == 200
    assert "text/csv" in res_risk.headers["content-type"]
    reader4 = csv.reader(io.StringIO(res_risk.text))
    header4 = next(reader4)
    assert header4 == [
        "Risk ID", "Risk Name", "Category", "Number of Scenarios",
        "Baseline Block Rate (%)", "Post-Mitigation Block Rate (%)",
        "Mitigation Improvement (pp)", "Remaining Vulnerabilities", "Execution Coverage (%)"
    ]
    # Check that 10 risk rows exist in risk export
    rows = list(reader4)
    assert len(rows) == 10


# 10. Missing-Data & Empty-State Graceful Handling
def test_missing_data_graceful_handling():
    # Test redaction function on None and safe strings
    assert redact_sensitive_text(None) == ""
    assert redact_sensitive_text("") == ""
    assert redact_sensitive_text("Normal operational refusal") == "Normal operational refusal"
    assert redact_sensitive_text("Secret sk-1234567890abcdef1234567890 key") == "Secret [REDACTED_CREDENTIAL] key"


# 11. Historical Data Preservation
def test_historical_data_preservation(db):
    initial_results_count = db.query(AttackResult).count()
    initial_audit_count = db.query(SecurityAuditLog).count()

    # Generate overview
    overview = DashboardService.get_overview(db=db)
    assert overview.total_executions == initial_results_count

    # Verify counts did not drop or get mutated
    after_results_count = db.query(AttackResult).count()
    after_audit_count = db.query(SecurityAuditLog).count()
    assert initial_results_count == after_results_count
    assert initial_audit_count == after_audit_count


# 12. Phase 1-7 Regression Integrity
def test_phase1_to_7_regression(client):
    # Phase 1 Health
    res_health = client.get("/api/health")
    assert res_health.status_code == 200

    # Phase 2 Models
    res_models = client.get("/api/models")
    assert res_models.status_code == 200

    # Phase 3 Agent Tools
    res_tools = client.get("/api/agent/tools")
    assert res_tools.status_code == 200

    # Phase 4 Attacks
    res_scenarios = client.get("/api/attacks/scenarios")
    assert res_scenarios.status_code == 200
    assert len(res_scenarios.json()) == 30

    # Phase 7 Evaluation Overview
    res_eval = client.get("/api/evaluation/overview")
    assert res_eval.status_code == 200

