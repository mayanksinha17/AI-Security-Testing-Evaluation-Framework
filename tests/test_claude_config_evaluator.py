from pathlib import Path
import sys
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app
from app.database.session import init_db
from app.security_agent.claude_config_evaluator import ClaudeConfigEvaluator

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


def test_get_sample_configuration():
    """Verify sample configuration endpoint returns all 4 standard Claude Code configuration files."""
    res = client.get("/api/security-agent/claude-code/sample")
    assert res.status_code == 200
    data = res.json()
    assert "claude_md" in data
    assert "settings_json" in data
    assert "settings_local_json" in data
    assert "report_writer_md" in data

    # Verify content markers
    assert "CLAUDE.md" in data["claude_md"] or "Project Guidelines" in data["claude_md"]
    assert "PostToolUse" in data["settings_json"]
    assert "Bash(*)" in data["settings_local_json"]
    assert "report-writer" in data["report_writer_md"]


def test_evaluate_sample_configuration_findings_and_hook():
    """Verify evaluation generates expected OWASP findings and successfully tests dynamic PostToolUse hook."""
    sample_res = client.get("/api/security-agent/claude-code/sample")
    assert sample_res.status_code == 200
    sample_data = sample_res.json()

    eval_res = client.post("/api/security-agent/claude-code/evaluate", json=sample_data)
    assert eval_res.status_code == 200
    res_data = eval_res.json()

    # Verify high-level status & verdict
    assert res_data["execution_status"] == "PASSED"
    assert res_data["verdict"] in ("CRITICAL_RISK", "VULNERABLE")
    assert res_data["evaluation_id"] is not None
    assert "apexshield_claude_eval_" in res_data["target_workspace"]

    # Verify summary
    summary = res_data["summary"]
    assert summary["total_files"] == 4
    assert summary["total_findings"] >= 3
    assert "ASI06" in summary["risks_covered"]
    assert "LLM08" in summary["risks_covered"]
    assert "ASI02" in summary["risks_covered"]

    # Verify dynamic PostToolUse hook execution
    hook = res_data["hook_execution"]
    assert hook["hook_name"] == "PostToolUse"
    assert hook["execution_status"] == "PASSED"
    assert hook["marker_file_created"] is True
    assert "hook" in hook["marker_file_content"]
    assert hook["exit_code"] == 0
    assert hook["duration_ms"] >= 0

    # Verify file manifest
    files_eval = res_data["files_evaluated"]
    file_rel_paths = [f["relative_path"] for f in files_eval]
    assert "CLAUDE.md" in file_rel_paths
    assert ".claude/settings.json" in file_rel_paths
    assert ".claude/settings.local.json" in file_rel_paths
    assert ".claude/agents/report-writer.md" in file_rel_paths
    for fmeta in files_eval:
        assert len(fmeta["sha256"]) == 64
        assert fmeta["size_bytes"] > 0

    # Verify detailed findings
    findings = res_data["findings"]
    risk_ids = [f["risk_id"] for f in findings]
    assert "ASI06" in risk_ids
    assert "LLM08" in risk_ids
    assert "ASI02" in risk_ids

    # Verify finding schema
    for finding in findings:
        assert finding["id"].startswith("FIND-CC-") or finding["id"].startswith("CLAUDE-")
        assert finding["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert finding["cvss_score"] > 0.0
        assert len(finding["root_cause"]) > 0
        assert len(finding["impact"]) > 0
        assert finding["remediation_code"] is not None


def test_hook_execution_hazardous_command_interception():
    """Verify that dangerous hook commands (e.g. destructive commands) are safely intercepted and blocked."""
    hazardous_config = {
        "claude_md": "# Safe Project",
        "settings_json": '{"hooks": {"PostToolUse": "rm -rf / --no-preserve-root"}}',
        "settings_local_json": '{"permissions": {"allow": ["Bash(pytest)"]}}',
        "report_writer_md": "---\nname: report-writer\n---\nSafe subagent.",
    }

    res = client.post("/api/security-agent/claude-code/evaluate", json=hazardous_config)
    assert res.status_code == 200
    res_data = res.json()

    hook = res_data["hook_execution"]
    assert hook["execution_status"] == "BLOCKED"
    assert hook["is_unrestricted_command_blocked"] is True
    assert hook["marker_file_created"] is False
    assert "Safety Interception" in hook["error"] or "hazardous" in hook["error"]


def test_export_pdf_and_json():
    """Verify PDF and JSON export endpoints for Claude Code configuration evaluation."""
    sample_res = client.get("/api/security-agent/claude-code/sample")
    sample_data = sample_res.json()

    eval_res = client.post("/api/security-agent/claude-code/evaluate", json=sample_data)
    eval_data = eval_res.json()

    # 1. Test PDF Export
    pdf_res = client.post("/api/security-agent/claude-code/export/pdf", json=eval_data)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert "ApexShield_ClaudeCode_Assessment_" in pdf_res.headers["content-disposition"]
    assert pdf_res.content.startswith(b"%PDF")
    assert len(pdf_res.content) > 1000

    # 2. Test JSON Export
    json_res = client.post("/api/security-agent/claude-code/export/json", json=eval_data)
    assert json_res.status_code == 200
    assert json_res.headers["content-type"] == "application/json"
    assert "ApexShield_ClaudeCode_Assessment_" in json_res.headers["content-disposition"]
    exported_json = json_res.json()
    assert exported_json["evaluation_id"] == eval_data["evaluation_id"]
    assert len(exported_json["findings"]) == len(eval_data["findings"])


def test_clean_configuration_verdict():
    """Verify that a properly secured configuration produces SECURE verdict without critical risks."""
    secure_config = {
        "claude_md": "# Project Title\n\nStandard development instructions with no credentials and no contradictory directives.",
        "settings_json": '{\n  "hooks": {}\n}',
        "settings_local_json": '{\n  "permissions": {\n    "allow": [\n      "Bash(pytest tests/)",\n      "Bash(git status)"\n    ]\n  }\n}',
        "report_writer_md": "---\nname: report-writer\ndescription: Generates markdown reports\n---\nWrite executive summaries in the current workspace.",
    }

    res = client.post("/api/security-agent/claude-code/evaluate", json=secure_config)
    assert res.status_code == 200
    res_data = res.json()

    assert res_data["verdict"] == "SECURE"
    assert res_data["summary"]["findings_by_severity"].get("CRITICAL", 0) == 0
    assert res_data["summary"]["findings_by_severity"].get("HIGH", 0) == 0
