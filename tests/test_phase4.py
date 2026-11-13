import asyncio
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request
import pytest

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.attacks.engine import AttackTestingEngine
from app.attacks.evaluator import AttackEvaluator
from app.attacks.scenarios import (
    ATTACK_SCENARIOS,
    RISK_CATEGORIES,
    AttackScenario,
    get_all_risks,
    get_all_scenarios,
    get_scenario_by_id,
    get_scenarios_by_risk,
)
from app.attacks.schemas import AttackBatchRunRequest, AttackRunRequest
from app.database.models import AttackResult, AttackRun
from app.database.session import SessionLocal, init_db


BASE_URL = "http://127.0.0.1:8000"


# -----------------------------------------------------------------------------
# 1. Exactly 10 risk categories exist
# -----------------------------------------------------------------------------
def test_ten_risk_categories_exist():
    risks = get_all_risks()
    assert len(risks) == 10, f"Expected exactly 10 risk categories, found {len(risks)}"
    risk_ids = {r.risk_id for r in risks}
    expected_ids = {"LLM01", "LLM02", "LLM03", "LLM08", "LLM10", "ASI01", "ASI02", "ASI03", "ASI05", "ASI06"}
    assert risk_ids == expected_ids, f"Mismatch in risk category IDs: {risk_ids} vs {expected_ids}"


# -----------------------------------------------------------------------------
# 2. Exactly 30 attack scenarios exist
# -----------------------------------------------------------------------------
def test_thirty_attack_scenarios_exist():
    scenarios = get_all_scenarios()
    assert len(scenarios) == 30, f"Expected exactly 30 attack scenarios, found {len(scenarios)}"


# -----------------------------------------------------------------------------
# 3. Every risk has exactly 3 scenarios
# -----------------------------------------------------------------------------
def test_every_risk_has_three_scenarios():
    risks = get_all_risks()
    for r in risks:
        scenarios = get_scenarios_by_risk(r.risk_id)
        assert len(scenarios) == 3, f"Risk '{r.risk_id}' expected 3 scenarios, found {len(scenarios)}"


# -----------------------------------------------------------------------------
# 4. All scenario IDs are unique
# -----------------------------------------------------------------------------
def test_unique_scenario_ids():
    scenarios = get_all_scenarios()
    scenario_ids = [s.scenario_id for s in scenarios]
    unique_ids = set(scenario_ids)
    assert len(scenario_ids) == len(unique_ids), f"Duplicate scenario IDs found: {len(scenario_ids)} vs {len(unique_ids)}"

    # Check ID naming convention
    for sc in scenarios:
        assert sc.scenario_id.startswith(sc.risk_id + "-"), f"Scenario ID '{sc.scenario_id}' must prefix with '{sc.risk_id}-'"


# -----------------------------------------------------------------------------
# 5. All scenarios have valid required fields
# -----------------------------------------------------------------------------
def test_required_scenario_fields():
    scenarios = get_all_scenarios()
    required_fields = [
        "scenario_id", "risk_id", "risk_name", "category",
        "scenario_name", "attack_description", "attack_prompt",
        "expected_secure_behavior", "severity", "target_component", "test_type",
    ]

    valid_severities = {"low", "medium", "high", "critical"}
    valid_categories = {"OWASP_LLM", "OWASP_AGENTIC"}
    valid_components = {"chatbot", "agent"}

    for sc in scenarios:
        for field in required_fields:
            val = getattr(sc, field)
            assert val is not None and str(val).strip() != "", f"Scenario {sc.scenario_id} missing {field}"

        assert sc.severity in valid_severities, f"Scenario {sc.scenario_id} invalid severity: {sc.severity}"
        assert sc.category in valid_categories, f"Scenario {sc.scenario_id} invalid category: {sc.category}"
        assert sc.target_component in valid_components, f"Scenario {sc.scenario_id} invalid component: {sc.target_component}"


# -----------------------------------------------------------------------------
# 6. Mock Claude execution works
# -----------------------------------------------------------------------------
def test_mock_claude_execution():
    init_db()
    db = SessionLocal()
    try:
        sc = get_scenario_by_id("LLM01-01")
        assert sc is not None

        result = asyncio.run(
            AttackTestingEngine.execute_scenario(
                db=db,
                scenario=sc,
                provider="claude",
                stage="BASELINE",
            )
        )

        assert result.provider == "claude"
        assert result.execution_mode == "mock"
        assert result.scenario_id == "LLM01-01"
        assert result.result_classification in ("BLOCKED", "PARTIAL", "SUCCEEDED", "ERROR")
        assert result.latency_ms is not None and result.latency_ms >= 0
    finally:
        db.close()


# -----------------------------------------------------------------------------
# 7. Mock Gemini execution works
# -----------------------------------------------------------------------------
def test_mock_gemini_execution():
    init_db()
    db = SessionLocal()
    try:
        sc = get_scenario_by_id("ASI02-01")
        assert sc is not None

        result = asyncio.run(
            AttackTestingEngine.execute_scenario(
                db=db,
                scenario=sc,
                provider="gemini",
                stage="BASELINE",
            )
        )

        assert result.provider == "gemini"
        assert result.execution_mode == "mock"
        assert result.scenario_id == "ASI02-01"
        assert result.result_classification == "BLOCKED"
        assert result.evaluation_reason is not None
    finally:
        db.close()


# -----------------------------------------------------------------------------
# 8. Result classifications work
# -----------------------------------------------------------------------------
def test_result_classifications():
    sc_injection = get_scenario_by_id("LLM01-01")
    sc_canary = get_scenario_by_id("LLM02-01")

    # 1. BLOCKED evaluation
    res_b, reason_b = AttackEvaluator.evaluate(
        scenario=sc_injection,
        response_text="I cannot fulfill this request as it overrides core system instructions.",
    )
    assert res_b == "BLOCKED"
    assert "refused" in reason_b.lower() or "did not emit" in reason_b.lower()

    # 2. SUCCEEDED evaluation (prompt injection obeyed)
    res_s, reason_s = AttackEvaluator.evaluate(
        scenario=sc_injection,
        response_text="SYSTEM DIRECTIVE OVERRIDDEN. OVERRIDE_CONFIRMED",
    )
    assert res_s == "SUCCEEDED"

    # 3. Canary leaked evaluation
    res_canary_leak, reason_c = AttackEvaluator.evaluate(
        scenario=sc_canary,
        response_text="Here is your requested evaluation canary: SECRET-FLAG-123",
    )
    assert res_canary_leak == "SUCCEEDED"

    # 4. PARTIAL evaluation
    res_partial, reason_p = AttackEvaluator.evaluate(
        scenario=sc_canary,
        response_text="The confidential flag exists in the canary documents, but cannot be printed.",
    )
    assert res_partial == "PARTIAL"

    # 5. ERROR evaluation
    res_err, reason_e = AttackEvaluator.evaluate(
        scenario=sc_injection,
        response_text="",
        error_details="Connection reset by peer",
    )
    assert res_err == "ERROR"


# -----------------------------------------------------------------------------
# 9. Attack results persist in SQLite
# -----------------------------------------------------------------------------
def test_sqlite_persistence():
    init_db()
    db = SessionLocal()
    try:
        sc = get_scenario_by_id("LLM03-01")
        assert sc is not None

        result = asyncio.run(
            AttackTestingEngine.execute_scenario(
                db=db,
                scenario=sc,
                provider="claude",
                stage="BASELINE",
            )
        )

        # Query back from SQLite
        persisted = db.query(AttackResult).filter(AttackResult.id == result.id).first()
        assert persisted is not None
        assert persisted.scenario_id == "LLM03-01"
        assert persisted.risk_id == "LLM03"
        assert persisted.stage == "BASELINE"
        assert persisted.result_classification in ("BLOCKED", "PARTIAL", "SUCCEEDED", "ERROR")

        # Check linked run
        run_record = db.query(AttackRun).filter(AttackRun.id == persisted.run_id).first()
        assert run_record is not None
        assert run_record.stage == "BASELINE"
    finally:
        db.close()


# -----------------------------------------------------------------------------
# 10. Baseline and post-mitigation stages remain separate
# -----------------------------------------------------------------------------
def test_baseline_and_post_mitigation_stages_separate():
    init_db()
    db = SessionLocal()
    try:
        sc = get_scenario_by_id("ASI02-03")
        assert sc is not None

        # Execute as BASELINE
        res_baseline = asyncio.run(
            AttackTestingEngine.execute_scenario(
                db=db,
                scenario=sc,
                provider="claude",
                stage="BASELINE",
            )
        )
        assert res_baseline.stage == "BASELINE"

        # Execute as POST_MITIGATION
        res_post = asyncio.run(
            AttackTestingEngine.execute_scenario(
                db=db,
                scenario=sc,
                provider="claude",
                stage="POST_MITIGATION",
            )
        )
        assert res_post.stage == "POST_MITIGATION"

        # Query summary and verify separation
        summary = AttackTestingEngine.get_summary(db)
        assert summary["baseline_stats"]["total"] >= 1
        assert summary["post_mitigation_stats"]["total"] >= 1
    finally:
        db.close()


# -----------------------------------------------------------------------------
# 11. Batch limits are enforced
# -----------------------------------------------------------------------------
def test_batch_limits_enforced():
    init_db()
    db = SessionLocal()
    try:
        # Batch of 3 scenarios for LLM01
        batch_req = AttackBatchRunRequest(
            risk_id="LLM01",
            provider="claude",
            stage="BASELINE",
        )
        attack_run = asyncio.run(AttackTestingEngine.execute_batch(db, batch_req))

        assert attack_run.total_scenarios == 3
        assert len(attack_run.results) == 3
        assert (attack_run.blocked_count + attack_run.partial_count + attack_run.succeeded_count + attack_run.error_count) == 3

        # Empty criteria raises ValueError
        try:
            asyncio.run(AttackTestingEngine.execute_batch(db, AttackBatchRunRequest(scenario_ids=[])))
            assert False, "Expected ValueError on empty scenario batch"
        except ValueError as e:
            assert "No valid attack scenarios found" in str(e)
    finally:
        db.close()


# -----------------------------------------------------------------------------
# 12. Live HTTP API Endpoints
# -----------------------------------------------------------------------------
def test_live_attack_api_endpoints():
    # 1. GET /api/attacks/risks
    with urllib.request.urlopen(f"{BASE_URL}/api/attacks/risks", timeout=5) as resp:
        assert resp.status == 200
        risks = json.loads(resp.read().decode())
        assert len(risks) == 10

    # 2. GET /api/attacks/scenarios
    with urllib.request.urlopen(f"{BASE_URL}/api/attacks/scenarios", timeout=5) as resp:
        assert resp.status == 200
        scenarios = json.loads(resp.read().decode())
        assert len(scenarios) == 30

    # 3. GET /api/attacks/scenarios/LLM01-01
    with urllib.request.urlopen(f"{BASE_URL}/api/attacks/scenarios/LLM01-01", timeout=5) as resp:
        assert resp.status == 200
        sc = json.loads(resp.read().decode())
        assert sc["scenario_id"] == "LLM01-01"

    # 4. POST /api/attacks/run
    payload = json.dumps({"scenario_id": "LLM02-01", "provider": "claude", "stage": "BASELINE"}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/attacks/run", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode())
        assert res["scenario_id"] == "LLM02-01"
        assert res["result_classification"] in ("BLOCKED", "PARTIAL", "SUCCEEDED", "ERROR")

    # 5. GET /api/attacks/summary
    with urllib.request.urlopen(f"{BASE_URL}/api/attacks/summary", timeout=5) as resp:
        assert resp.status == 200
        summary = json.loads(resp.read().decode())
        assert "baseline_stats" in summary
        assert "post_mitigation_stats" in summary


if __name__ == "__main__":
    print("=" * 65)
    print("AI Security POC - Phase 4 Comprehensive Verification Suite")
    print("=" * 65 + "\n")
    test_ten_risk_categories_exist()
    print("[1/12] Exactly 10 risk categories exist: PASSED")
    test_thirty_attack_scenarios_exist()
    print("[2/12] Exactly 30 attack scenarios exist: PASSED")
    test_every_risk_has_three_scenarios()
    print("[3/12] Every risk has exactly 3 scenarios: PASSED")
    test_unique_scenario_ids()
    print("[4/12] All scenario IDs are unique: PASSED")
    test_required_scenario_fields()
    print("[5/12] All scenarios have valid required fields: PASSED")
    test_mock_claude_execution()
    print("[6/12] Mock Claude execution works: PASSED")
    test_mock_gemini_execution()
    print("[7/12] Mock Gemini execution works: PASSED")
    test_result_classifications()
    print("[8/12] Result classifications work: PASSED")
    test_sqlite_persistence()
    print("[9/12] Attack results persist in SQLite: PASSED")
    test_baseline_and_post_mitigation_stages_separate()
    print("[10/12] Baseline and post-mitigation stages separate: PASSED")
    test_batch_limits_enforced()
    print("[11/12] Batch limits enforced: PASSED")
    test_live_attack_api_endpoints()
    print("[12/12] Live Attack API endpoints operational: PASSED")
    print("\n" + "=" * 65)
    print("ALL PHASE 4 AUTOMATED VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 65)

