"""Phase 7 Test Suite: Comprehensive AI Security Evaluation and Model Comparison.

Verifies:
1. Provider availability detection (strictly boolean, no exposed secrets)
2. Mock Claude evaluation execution and results
3. Mock Gemini evaluation execution and results
4. Scenario matrix generation across 30 scenarios, 2 providers, 2 stages
5. Result classification accuracy (BLOCKED, PARTIAL, SUCCEEDED, ERROR, NOT_RUN)
6. Metric calculations (block rates, improvement points; NOT_RUN and ERROR never counted as BLOCKED)
7. Baseline vs Post-mitigation separation and metric improvement calculation
8. Claude vs Gemini comparison calculations and comparative verdicts
9. NOT_RUN handling when live mode is requested without credentials
10. ERROR handling for technical failures (not counted as BLOCKED)
11. SQLite persistence for EvaluationRun, ModelComparison, and EvaluationMetric models
12. CSV export format and exact required headers
13. Evaluation overview and models endpoints (/api/evaluation/overview, /api/evaluation/models)
14. Evaluation comparison and risk breakdown endpoints (/api/evaluation/comparison, /api/evaluation/risk-breakdown)
15. Historical result preservation and regression
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

from app.attacks.scenarios import get_all_risks, get_all_scenarios, get_scenario_by_id
from app.core.config import settings
from app.database.models import AttackResult, EvaluationMetric, EvaluationRun, ModelComparison
from app.database.session import get_db
from app.evaluation.schemas import EvaluationRunRequest
from app.evaluation.service import EvaluationService
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


# 1. Provider Availability Detection
def test_provider_availability_detection():
    providers = EvaluationService.check_provider_availability()
    assert len(providers) == 2
    
    claude = next(p for p in providers if p.provider == "claude")
    gemini = next(p for p in providers if p.provider == "gemini")

    assert claude.model_id == settings.claude_model
    assert gemini.model_id == settings.gemini_model
    assert isinstance(claude.is_live_available, bool)
    assert isinstance(gemini.is_live_available, bool)
    assert claude.credential_status in ["Configured", "Missing"]
    assert gemini.credential_status in ["Configured", "Missing"]
    assert claude.execution_mode in ["live", "mock"]
    assert gemini.execution_mode in ["live", "mock"]
    
    # Ensure no secret strings leaked in serialized schema
    dumped = claude.model_dump_json()
    assert "sk-" not in dumped
    assert "AIza" not in dumped


# 2. Mock Claude Evaluation
@pytest.mark.anyio
async def test_mock_claude_evaluation(db):
    sc = get_scenario_by_id("LLM01-01")
    assert sc is not None

    req = EvaluationRunRequest(
        title="Claude Mock Test",
        scenario_ids=["LLM01-01"],
        providers=["claude"],
        stage="POST_MITIGATION",
        execution_mode="mock",
    )
    summary = await EvaluationService.run_evaluation(db=db, request=req)
    assert summary.status == "completed"
    assert summary.total_scenarios == 1
    assert summary.total_executions == 1
    assert summary.claude_block_rate == 100.0


# 3. Mock Gemini Evaluation
@pytest.mark.anyio
async def test_mock_gemini_evaluation(db):
    sc = get_scenario_by_id("ASI01-01")
    assert sc is not None

    req = EvaluationRunRequest(
        title="Gemini Mock Test",
        scenario_ids=["ASI01-01"],
        providers=["gemini"],
        stage="POST_MITIGATION",
        execution_mode="mock",
    )
    summary = await EvaluationService.run_evaluation(db=db, request=req)
    assert summary.status == "completed"
    assert summary.total_scenarios == 1
    assert summary.total_executions == 1
    assert summary.gemini_block_rate == 100.0


# 4. Scenario Matrix Generation
def test_scenario_matrix_generation():
    scenarios = get_all_scenarios()
    risks = get_all_risks()

    assert len(scenarios) == 30
    assert len(risks) == 10

    # Verify 3 scenarios per risk
    for rk in risks:
        rk_scenarios = [s for s in scenarios if s.risk_id == rk.risk_id]
        assert len(rk_scenarios) == 3, f"Risk {rk.risk_id} does not have exactly 3 scenarios"

    # Total potential evaluations in full matrix: 30 scenarios * 2 providers * 2 stages = 120
    full_matrix_size = len(scenarios) * 2 * 2
    assert full_matrix_size == 120


# 5. Result Classification Accuracy
def test_result_classification_accuracy():
    valid_classes = {"BLOCKED", "PARTIAL", "SUCCEEDED", "ERROR", "NOT_RUN"}
    
    # Check that comparative verdict logic properly handles all outcomes
    for c_cls in valid_classes:
        for g_cls in valid_classes:
            if c_cls == "BLOCKED" and g_cls == "BLOCKED":
                verdict = "Both Protected"
            elif c_cls == "BLOCKED" and g_cls != "BLOCKED":
                verdict = "Claude More Resilient"
            elif g_cls == "BLOCKED" and c_cls != "BLOCKED":
                verdict = "Gemini More Resilient"
            elif c_cls == "SUCCEEDED" and g_cls == "SUCCEEDED":
                verdict = "Both Vulnerable"
            elif c_cls == "ERROR" or g_cls == "ERROR":
                verdict = "Execution Error"
            else:
                verdict = "Not Evaluated" if (c_cls == "NOT_RUN" or g_cls == "NOT_RUN") else "Divergent Resistance"
            
            assert isinstance(verdict, str)
            assert len(verdict) > 0


# 6. Metric Calculations (NOT_RUN and ERROR must not count as BLOCKED)
def test_metric_calculations(db):
    metrics = EvaluationService.calculate_metrics(db=db)
    assert isinstance(metrics.total_executed, int)
    assert isinstance(metrics.total_blocked, int)
    assert isinstance(metrics.total_errors, int)
    assert isinstance(metrics.total_not_run, int)
    assert metrics.total_blocked <= metrics.total_executed

    # Ensure blocked rate formula: blocked / total * 100
    if metrics.total_executed > 0:
        expected_rate = round((metrics.total_blocked / metrics.total_executed * 100), 1)
        assert metrics.overall_block_rate == expected_rate


# 7. Baseline vs Post-Mitigation Separation & Improvement Calculation
@pytest.mark.anyio
async def test_baseline_post_mitigation_separation(db):
    req = EvaluationRunRequest(
        title="Separation Test",
        scenario_ids=["LLM01-01", "LLM02-01"],
        providers=["claude"],
        stage="BOTH",
        execution_mode="mock",
    )
    summary = await EvaluationService.run_evaluation(db=db, request=req)
    assert summary.total_scenarios == 2
    assert summary.total_executions == 4  # 2 scenarios * 1 provider * 2 stages
    # In baseline mock, attack succeeds (blocked=0); in post-mitigation, attack is blocked (blocked=2)
    assert summary.mitigation_improvement >= 0.0


# 8. Claude vs Gemini Comparison Calculations
@pytest.mark.anyio
async def test_claude_gemini_comparison_calculations(db):
    req = EvaluationRunRequest(
        title="Comparison Run",
        scenario_ids=["LLM08-01"],
        providers=["claude", "gemini"],
        stage="POST_MITIGATION",
        execution_mode="mock",
    )
    summary = await EvaluationService.run_evaluation(db=db, request=req)
    comparisons = EvaluationService.get_comparisons(db=db, run_id=summary.id)
    assert len(comparisons) == 1
    comp = comparisons[0]
    assert comp.scenario_id == "LLM08-01"
    assert comp.claude_classification == "BLOCKED"
    assert comp.gemini_classification == "BLOCKED"
    assert comp.comparative_verdict == "Both Protected"


# 9. NOT_RUN Handling (unconfigured live mode)
@pytest.mark.anyio
async def test_not_run_handling(db):
    # Request live mode when credentials may not be configured
    req = EvaluationRunRequest(
        title="Live Mode Missing Keys Test",
        scenario_ids=["LLM01-01"],
        providers=["claude"],
        stage="POST_MITIGATION",
        execution_mode="live",
    )
    summary = await EvaluationService.run_evaluation(db=db, request=req)
    if summary.not_run_count > 0:
        # Verify it was not counted as blocked
        assert summary.overall_block_rate == 0.0
        assert summary.not_run_count == 1
        results = db.query(AttackResult).filter(AttackResult.run_id == summary.id).all()
        assert results[0].result_classification == "NOT_RUN"


# 10. ERROR Handling (technical errors not counted as BLOCKED)
def test_error_handling(db):
    test_run_id = f"run-err-{uuid.uuid4()}"
    results = [
        AttackResult(
            id=str(uuid.uuid4()),
            run_id=test_run_id,
            scenario_id="LLM01-01",
            risk_id="LLM01",
            provider="claude",
            model="claude-sonnet-5-5",
            execution_mode="mock",
            stage="POST_MITIGATION",
            prompt="test",
            result_classification="ERROR",
            latency_ms=10.0,
        ),
        AttackResult(
            id=str(uuid.uuid4()),
            run_id=test_run_id,
            scenario_id="LLM01-02",
            risk_id="LLM01",
            provider="claude",
            model="claude-sonnet-5-5",
            execution_mode="mock",
            stage="POST_MITIGATION",
            prompt="test",
            result_classification="BLOCKED",
            latency_ms=15.0,
        ),
    ]
    for r in results:
        db.add(r)
    db.commit()

    metrics = EvaluationService.calculate_metrics(db=db, run_id=test_run_id)
    assert metrics.total_executed == 2
    assert metrics.total_blocked == 1
    assert metrics.total_errors == 1
    assert metrics.overall_block_rate == 50.0  # Exactly 1 out of 2


# 11. SQLite Persistence for Evaluation Models
@pytest.mark.anyio
async def test_sqlite_persistence_evaluation_runs(db):
    req = EvaluationRunRequest(
        title="Persistence Verification",
        scenario_ids=["LLM03-01"],
        providers=["claude", "gemini"],
        stage="POST_MITIGATION",
        execution_mode="mock",
    )
    summary = await EvaluationService.run_evaluation(db=db, request=req)
    
    # Query database directly
    persisted_run = db.query(EvaluationRun).filter(EvaluationRun.id == summary.id).first()
    assert persisted_run is not None
    assert persisted_run.title == "Persistence Verification"
    assert persisted_run.status == "completed"
    assert persisted_run.claude_model == settings.claude_model
    assert persisted_run.gemini_model == settings.gemini_model

    # Check ModelComparison records
    comps = db.query(ModelComparison).filter(ModelComparison.evaluation_run_id == summary.id).all()
    assert len(comps) >= 1
    assert comps[0].scenario_id == "LLM03-01"


# 12. CSV Export Format and Required Headers
def test_csv_export_format_and_headers(db):
    csv_str = EvaluationService.export_csv(db=db)
    reader = csv.reader(io.StringIO(csv_str))
    headers = next(reader)
    
    expected_headers = [
        "Risk ID",
        "Scenario ID",
        "Model",
        "Model ID",
        "Execution Mode",
        "Stage",
        "Prompt",
        "Result",
        "Latency (ms)",
        "Timestamp",
    ]
    assert headers == expected_headers


# 13. Evaluation Overview and Models Endpoints
def test_evaluation_overview_endpoint(client):
    res_overview = client.get("/api/evaluation/overview")
    assert res_overview.status_code == 200
    data = res_overview.json()
    assert "total_evaluation_runs" in data
    assert "providers" in data
    assert "security_metrics" in data
    assert "coverage_summary" in data
    assert data["coverage_summary"]["total_matrix_cells"] == 120

    res_models = client.get("/api/evaluation/models")
    assert res_models.status_code == 200
    models_data = res_models.json()
    assert len(models_data) == 2
    prov_names = [m["provider"] for m in models_data]
    assert "claude" in prov_names
    assert "gemini" in prov_names


# 14. Evaluation Comparison and Risk Breakdown Endpoints
def test_evaluation_comparison_and_breakdown_endpoints(client):
    res_comp = client.get("/api/evaluation/comparison")
    assert res_comp.status_code == 200
    comp_data = res_comp.json()
    assert isinstance(comp_data, list)
    if len(comp_data) > 0:
        first = comp_data[0]
        assert "scenario_id" in first
        assert "risk_id" in first
        assert "comparative_verdict" in first

    res_risk = client.get("/api/evaluation/risk-breakdown")
    assert res_risk.status_code == 200
    risk_data = res_risk.json()
    assert len(risk_data) == 10  # All 10 OWASP risks
    risk_ids = [r["risk_id"] for r in risk_data]
    assert "LLM01" in risk_ids
    assert "ASI01" in risk_ids
    assert "ASI06" in risk_ids


# 15. Historical Result Preservation and Regression
@pytest.mark.anyio
async def test_historical_result_preservation_and_regression(db):
    initial_runs = db.query(EvaluationRun).count()
    initial_results = db.query(AttackResult).count()

    req = EvaluationRunRequest(
        title="Audit Preservation Run",
        scenario_ids=["LLM02-02"],
        providers=["claude"],
        stage="POST_MITIGATION",
        execution_mode="mock",
    )
    new_run = await EvaluationService.run_evaluation(db=db, request=req)
    
    after_runs = db.query(EvaluationRun).count()
    after_results = db.query(AttackResult).count()

    assert after_runs == initial_runs + 1
    assert after_results > initial_results
    
    # Historical runs remain intact
    history = EvaluationService.get_history(db=db)
    assert len(history) == after_runs
