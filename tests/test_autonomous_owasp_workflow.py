import io
import csv
import json
from pathlib import Path
import sys
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app
from app.database.session import init_db

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


def test_stakeholder_natural_language_interpretation():
    """Requirement 1: Verify extraction of multiple LLM and ASI risk codes from natural language."""
    cmd = "Test my application for OWASP risks LLM01, LLM02, ASI01 and ASI02."
    res = client.post("/api/security-agent/interpret", json={"command": cmd})
    assert res.status_code == 200, res.text
    data = res.json()

    extracted_risk_ids = [r["risk_id"] for r in data["identified_risks"]]
    assert "LLM01" in extracted_risk_ids
    assert "LLM02" in extracted_risk_ids
    assert "ASI01" in extracted_risk_ids
    assert "ASI02" in extracted_risk_ids
    assert len(extracted_risk_ids) == 4

    # Distinguishes LLM risks from Agentic AI risks
    categories = {r["risk_id"]: r["category"] for r in data["identified_risks"]}
    assert categories["LLM01"] == "OWASP_LLM"
    assert categories["LLM02"] == "OWASP_LLM"
    assert categories["ASI01"] == "OWASP_AGENTIC"
    assert categories["ASI02"] == "OWASP_AGENTIC"

    # Mapped scenarios in plan preview list
    assert data["is_ready_for_execution"] is True
    assert len(data["blocking_reasons"]) == 0
    assert len(data["plan_preview"]) == 12


def test_invalid_risk_guardrail_and_rejection():
    """Requirement 2: Verify detection of unsupported risk IDs (e.g. LLM99) and prevention of execution."""
    cmd = "Test my application for LLM99 and ASI99."
    # 1. Interpretation detects invalid risks
    res = client.post("/api/security-agent/interpret", json={"command": cmd})
    assert res.status_code == 200
    data = res.json()
    assert data["is_ready_for_execution"] is False
    assert len(data["blocking_reasons"]) > 0
    assert any("LLM99" in reason for reason in data["blocking_reasons"])
    assert any("ASI99" in reason for reason in data["blocking_reasons"])

    # 2. Plan creation is rejected with HTTP 400 Bad Request
    plan_res = client.post(
        "/api/security-agent/plans/adaptive",
        json={
            "command": cmd,
            "target_url": "http://127.0.0.1:8000",
            "user_confirmed_authorization": True,
        },
    )
    assert plan_res.status_code == 400
    err_data = plan_res.json()
    assert "LLM99" in err_data["detail"]


def test_command_authority_over_stale_ui_pills():
    """Requirement 3: Verify natural language command takes precedence over default UI risk pills."""
    cmd = "Perform prompt injection security audit for LLM01 only."
    # Even if UI passes stale default pills [LLM01, LLM02, ASI01, ASI02], command specifies LLM01 only
    res = client.post(
        "/api/security-agent/plans/adaptive",
        json={
            "command": cmd,
            "target_url": "http://127.0.0.1:8000",
            "stage": "POST_MITIGATION",
            "risk_ids": ["LLM01", "LLM02", "ASI01", "ASI02"],
            "max_turns": 1,
            "user_confirmed_authorization": True,
        },
    )
    assert res.status_code == 201, res.text
    plan = res.json()
    # Authoritative command restricts execution to LLM01 (3 scenarios)
    assert plan["total_tests"] == 3
    assert plan["completed_tests"] == 3
    executed_risks = {t["risk_id"] for t in plan["tests"]}
    assert executed_risks == {"LLM01"}


def test_scope_authorization_enforcement():
    """Requirement 4: Verify external target requires authorization and blocked when unconfirmed."""
    res = client.post(
        "/api/security-agent/plans/adaptive",
        json={
            "command": "Test external app for LLM01",
            "target_url": "http://external-unauthorized-target.com",
            "user_confirmed_authorization": False,
        },
    )
    assert res.status_code == 400
    assert "scope" in res.json()["detail"].lower() or "authorization" in res.json()["detail"].lower()


def test_full_autonomous_owasp_workflow_execution():
    """Requirement 5: Full end-to-end execution of Mehul Sir's command with wire evidence, remediations & reports."""
    cmd = "Test my application for OWASP risks LLM01, LLM02, ASI01 and ASI02."
    res = client.post(
        "/api/security-agent/plans/adaptive",
        json={
            "command": cmd,
            "target_url": "http://127.0.0.1:8000",
            "stage": "POST_MITIGATION",
            "max_turns": 1,
            "user_confirmed_authorization": True,
        },
    )
    assert res.status_code == 201, res.text
    plan = res.json()
    plan_id = plan["plan_id"]

    # 1. Metrics & execution validation
    assert plan["total_tests"] == 12
    assert plan["completed_tests"] == 12
    assert len(plan["tests"]) == 12
    assert all(t["verdict"] == "BLOCKED" for t in plan["tests"])

    assert plan["report_id"] is not None
    assert plan["download_urls"] is not None
    assert "pdf" in plan["download_urls"]
    assert "xlsx" in plan["download_urls"]
    assert "csv" in plan["download_urls"]
    assert "json" in plan["download_urls"]

    # 2. Executive report validation
    rep_summary_res = client.get(f"/api/security-agent/plans/{plan_id}/report")
    assert rep_summary_res.status_code == 200
    rep_summary = rep_summary_res.json()
    assert rep_summary["overall_resilience_score_percent"] == 100.0
    assert rep_summary["total_vulnerabilities_confirmed"] == 0
    assert rep_summary["evidence_integrity_verified"] is True

    # 3. Chains and wire evidence verification
    chains_res = client.get(f"/api/security-agent/plans/{plan_id}/chains")
    assert chains_res.status_code == 200
    chains = chains_res.json()
    assert len(chains) == 12

    first_turn = chains[0]["turns"][0]
    exec_id = first_turn["execution_id"]
    evidence_res = client.get(f"/api/security-agent/executions/{exec_id}/evidence")
    assert evidence_res.status_code == 200
    ev = evidence_res.json()
    assert "http://127.0.0.1:8000" in ev["target_url"]
    assert ev["evidence_sha256"].startswith("hmac-sha256:")

    # Cryptographic HMAC verification
    verify_res = client.post(f"/api/security-agent/executions/{exec_id}/verify-integrity")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["is_verified"] is True
    assert v_data["algorithm"] == "HMAC-SHA256"

    # 4. Automated actionable code remediations
    for risk_code in ["LLM01", "LLM02", "ASI01", "ASI02"]:
        rem_res = client.get(f"/api/security-agent/remediation/finding_{risk_code}?risk_id={risk_code}")
        assert rem_res.status_code == 200
        rem = rem_res.json()
        assert rem["risk_id"] == risk_code
        assert len(rem["title"]) > 5
        # Quick mitigation details
        assert "description" in rem["quick_mitigation"] or isinstance(rem["quick_mitigation"], str)
        # Architectural fix snippet
        assert "snippet" in rem["architectural_fix"] or "snippet" in rem["quick_mitigation"]

    # 5. Enterprise Report downloads
    rep_id = plan["report_id"]

    # PDF download
    pdf_res = client.get(f"/api/security-agent/reports/{rep_id}/download/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")

    # Excel (XLSX) download
    xlsx_res = client.get(f"/api/security-agent/reports/{rep_id}/download/xlsx")
    assert xlsx_res.status_code == 200
    assert "spreadsheetml" in xlsx_res.headers["content-type"] or "octet-stream" in xlsx_res.headers["content-type"]
    assert len(xlsx_res.content) > 1000

    # CSV download
    csv_res = client.get(f"/api/security-agent/reports/{rep_id}/download/csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert "Finding ID" in csv_res.text
    assert "Scenario ID" in csv_res.text
    assert "Risk ID" in csv_res.text

    # JSON download
    json_res = client.get(f"/api/security-agent/reports/{rep_id}/download/json")
    assert json_res.status_code == 200
    assert "application/json" in json_res.headers["content-type"]
    rep_json = json_res.json()
    assert rep_json["report_id"] == rep_id
    assert "section_1_executive_summary" in rep_json
    assert "section_3_owasp_coverage_matrix" in rep_json
