import csv
import io
from pathlib import Path
import sys
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app
from app.database.session import SessionLocal, init_db
from app.database.models import AttackRun

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


def test_batch_export_llm01_csv_and_pdf():
    # 1. Execute LLM01 batch
    res = client.post("/api/attacks/run-batch", json={"risk_id": "LLM01", "provider": "claude", "stage": "BASELINE"})
    assert res.status_code == 200
    data = res.json()
    run_id = data["id"]
    assert data["total_scenarios"] == 3
    assert len(data["results"]) == 3

    # 2. Test CSV export
    csv_res = client.get(f"/api/attacks/runs/{run_id}/export/csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert f'filename="ApexShield_LLM01_Results_{run_id}.csv"' in csv_res.headers["content-disposition"]

    reader = list(csv.DictReader(io.StringIO(csv_res.text)))
    assert len(reader) == 3, f"Expected 3 scenarios, found {len(reader)}"
    for row in reader:
        assert row["Run ID"] == run_id
        assert row["OWASP Risk"] == "LLM01"
        assert row["Scenario ID"].startswith("LLM01-")
        assert row["Outcome"] in ("BLOCKED", "PARTIAL", "SUCCEEDED", "ERROR")
        assert float(row["Latency (ms)"]) >= 0

    # 3. Test PDF export
    pdf_res = client.get(f"/api/attacks/runs/{run_id}/export/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert f'filename="ApexShield_LLM01_Assessment_{run_id}.pdf"' in pdf_res.headers["content-disposition"]
    assert pdf_res.content.startswith(b"%PDF"), "Response is not a valid PDF document"
    assert len(pdf_res.content) > 1000


def test_batch_export_llm02_csv_and_pdf():
    # 1. Execute LLM02 batch
    res = client.post("/api/attacks/run-batch", json={"risk_id": "LLM02", "provider": "claude", "stage": "BASELINE"})
    assert res.status_code == 200
    data = res.json()
    run_id = data["id"]
    assert data["total_scenarios"] == 3
    assert len(data["results"]) == 3

    # 2. Test CSV export
    csv_res = client.get(f"/api/attacks/runs/{run_id}/export/csv")
    assert csv_res.status_code == 200
    assert f'filename="ApexShield_LLM02_Results_{run_id}.csv"' in csv_res.headers["content-disposition"]

    reader = list(csv.DictReader(io.StringIO(csv_res.text)))
    assert len(reader) == 3
    for row in reader:
        assert row["Run ID"] == run_id
        assert row["OWASP Risk"] == "LLM02"
        assert row["Scenario ID"].startswith("LLM02-")

    # 3. Test PDF export
    pdf_res = client.get(f"/api/attacks/runs/{run_id}/export/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert f'filename="ApexShield_LLM02_Assessment_{run_id}.pdf"' in pdf_res.headers["content-disposition"]
    assert pdf_res.content.startswith(b"%PDF")
    assert len(pdf_res.content) > 1000


def test_batch_export_all_30_csv_and_pdf():
    # 1. Execute All 30 scenarios batch
    res = client.post("/api/attacks/run-batch", json={"risk_id": None, "provider": "claude", "stage": "BASELINE"})
    assert res.status_code == 200
    data = res.json()
    run_id = data["id"]
    assert data["total_scenarios"] == 30
    assert len(data["results"]) == 30

    # 2. Test CSV export
    csv_res = client.get(f"/api/attacks/runs/{run_id}/export/csv")
    assert csv_res.status_code == 200
    assert f'filename="ApexShield_ALL_Results_{run_id}.csv"' in csv_res.headers["content-disposition"]

    reader = list(csv.DictReader(io.StringIO(csv_res.text)))
    assert len(reader) == 30, f"Expected 30 scenarios, found {len(reader)}"
    for row in reader:
        assert row["Run ID"] == run_id

    # 3. Test PDF export
    pdf_res = client.get(f"/api/attacks/runs/{run_id}/export/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert f'filename="ApexShield_ALL_Assessment_{run_id}.pdf"' in pdf_res.headers["content-disposition"]
    assert pdf_res.content.startswith(b"%PDF")
    assert len(pdf_res.content) > 5000


def test_batch_export_isolation():
    # Execute batch 1 (LLM01)
    res1 = client.post("/api/attacks/run-batch", json={"risk_id": "LLM01", "provider": "claude", "stage": "BASELINE"})
    run_id_1 = res1.json()["id"]

    # Execute batch 2 (LLM02)
    res2 = client.post("/api/attacks/run-batch", json={"risk_id": "LLM02", "provider": "claude", "stage": "BASELINE"})
    run_id_2 = res2.json()["id"]

    # CSV for run 1 must not contain run 2
    csv1 = list(csv.DictReader(io.StringIO(client.get(f"/api/attacks/runs/{run_id_1}/export/csv").text)))
    assert len(csv1) == 3
    assert all(r["Run ID"] == run_id_1 for r in csv1)
    assert not any(r["Run ID"] == run_id_2 for r in csv1)

    # CSV for run 2 must not contain run 1
    csv2 = list(csv.DictReader(io.StringIO(client.get(f"/api/attacks/runs/{run_id_2}/export/csv").text)))
    assert len(csv2) == 3
    assert all(r["Run ID"] == run_id_2 for r in csv2)
    assert not any(r["Run ID"] == run_id_1 for r in csv2)


def test_batch_export_invalid_run_id_404():
    res = client.get("/api/attacks/runs/non-existent-uuid/export/pdf")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()

    res_csv = client.get("/api/attacks/runs/non-existent-uuid/export/csv")
    assert res_csv.status_code == 404
    assert "not found" in res_csv.json()["detail"].lower()
