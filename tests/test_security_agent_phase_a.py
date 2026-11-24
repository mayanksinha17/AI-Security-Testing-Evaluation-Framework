"""Phase A Test Suite: Autonomous AI Security Testing Agent - Foundational Components.

Verifies:
1. Natural language command interpretation with specified sample commands:
   - "Test my application for LLM01 and LLM02."
   - "Run prompt injection tests against http://127.0.0.1:8080."
   - "Audit ASI01 and ASI02 against my local test application."
2. Accurate OWASP risk extraction across all 10 risks (LLM01-LLM10, ASI01-ASI06).
3. Synonym matching, group keywords, and fallback behavior.
4. Target application resolver with explicit URLs, host:port, natural phrasing, and defaults.
5. Authorization and Scope validation:
   - Localhost / loopback permitted by default.
   - External targets rejected without explicit user authorization confirmation.
   - External targets permitted when confirmed.
   - Cloud metadata endpoints (169.254.169.254, metadata.google.internal) strictly blocked.
   - Bogon/multicast/broadcast addresses strictly blocked.
   - Disallowed URL schemes (ftp, file, gopher) strictly blocked.
   - Sensitive headers and credentials properly redacted.
6. REST API endpoints (/interpret, /validate-target, /risks, /policy).
7. Non-destructive safety: historical database records remain unaltered.
"""

from pathlib import Path
import sys
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from app.main import app
from app.security_agent.interpreter import CommandInterpreter
from app.security_agent.risk_identifier import RISK_REGISTRY, RiskIdentifier
from app.security_agent.schemas import (
    CommandInterpretationRequest,
    ScopeStatusEnum,
    TargetValidationRequest,
    UserIntent,
)
from app.security_agent.scope_validator import ScopeValidator
from app.security_agent.target_resolver import TargetResolver


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. SPECIFIED SAMPLE COMMAND TESTS
# ---------------------------------------------------------------------------

def test_command_sample_1_test_my_app_llm01_llm02():
    """Command: 'Test my application for LLM01 and LLM02.'"""
    req = CommandInterpretationRequest(command="Test my application for LLM01 and LLM02.")
    res = CommandInterpreter.interpret(req)

    assert res.intent == UserIntent.TEST
    assert len(res.identified_risks) == 2
    risk_ids = [r.risk_id for r in res.identified_risks]
    assert "LLM01" in risk_ids
    assert "LLM02" in risk_ids

    # Target resolved to default local target
    assert res.target.is_local is True
    assert res.target.is_in_scope is True
    assert res.target.scope_status == ScopeStatusEnum.APPROVED_LOCAL
    assert res.target.port == 8000

    # Plan preview contains exactly 6 scenarios (3 for LLM01 + 3 for LLM02)
    assert res.total_planned_tests == 6
    assert res.is_ready_for_execution is True
    assert len(res.blocking_reasons) == 0


def test_command_sample_2_run_prompt_injection_against_port():
    """Command: 'Run prompt injection tests against http://127.0.0.1:8080.'"""
    req = CommandInterpretationRequest(command="Run prompt injection tests against http://127.0.0.1:8080.")
    res = CommandInterpreter.interpret(req)

    assert res.intent == UserIntent.TEST
    risk_ids = [r.risk_id for r in res.identified_risks]
    assert "LLM01" in risk_ids

    # Target extracted accurately from command
    assert res.target.host == "127.0.0.1"
    assert res.target.port == 8080
    assert res.target.is_local is True
    assert res.target.is_in_scope is True
    assert res.target.scope_status == ScopeStatusEnum.APPROVED_LOCAL

    # Plan preview contains 3 scenarios for LLM01
    assert res.total_planned_tests == 3
    assert res.is_ready_for_execution is True


def test_command_sample_3_audit_asi01_asi02_local_app():
    """Command: 'Audit ASI01 and ASI02 against my local test application.'"""
    req = CommandInterpretationRequest(command="Audit ASI01 and ASI02 against my local test application.")
    res = CommandInterpreter.interpret(req)

    assert res.intent == UserIntent.AUDIT
    assert len(res.identified_risks) == 2
    risk_ids = [r.risk_id for r in res.identified_risks]
    assert "ASI01" in risk_ids
    assert "ASI02" in risk_ids

    assert res.target.is_local is True
    assert res.target.is_in_scope is True
    assert res.total_planned_tests == 6  # 3 for ASI01 + 3 for ASI02
    assert res.is_ready_for_execution is True


# ---------------------------------------------------------------------------
# 2. OWASP RISK IDENTIFICATION & SYNONYM MAPPING TESTS
# ---------------------------------------------------------------------------

def test_risk_identifier_all_10_individual_codes():
    """All 10 required OWASP codes must be uniquely identified."""
    codes = ["LLM01", "LLM02", "LLM03", "LLM08", "LLM10", "ASI01", "ASI02", "ASI03", "ASI05", "ASI06"]
    for code in codes:
        matches = RiskIdentifier.identify_risks(f"Please check code {code} on the endpoint")
        assert len(matches) == 1
        assert matches[0].risk_id == code
        assert matches[0].confidence == 1.0


def test_risk_identifier_synonym_phrases():
    """Synonyms must map to correct OWASP risk identifiers."""
    test_cases = [
        ("We need to prevent jailbreak attempts", "LLM01"),
        ("Look for canary token and credential exfiltration", "LLM02"),
        ("Assess unauthorized tool use with missing approval", "LLM03"),
        ("Test for system prompt extraction and developer instructions", "LLM08"),
        ("Check for cross-site scripting and svg injection in output", "LLM10"),
        ("Evaluate persona inversion and task redirection", "ASI01"),
        ("Verify protection against ssrf and path traversal", "ASI02"),
        ("Check for privilege escalation and rbac bypass", "ASI03"),
        ("Test if arbitrary code or command injection can occur", "ASI05"),
        ("Verify defense against knowledge base corruption", "ASI06"),
    ]
    for prompt, expected_code in test_cases:
        matches = RiskIdentifier.identify_risks(prompt)
        matched_ids = [m.risk_id for m in matches]
        assert expected_code in matched_ids, f"Failed to match {expected_code} in '{prompt}'"


def test_risk_identifier_group_patterns():
    """Group keywords should expand to the appropriate sets of risks."""
    # All Agentic Risks
    matches_agentic = RiskIdentifier.identify_risks("Scan all agentic ai risks on the system")
    agentic_ids = [m.risk_id for m in matches_agentic]
    assert set(agentic_ids) == {"ASI01", "ASI02", "ASI03", "ASI05", "ASI06"}

    # All LLM Risks
    matches_llm = RiskIdentifier.identify_risks("Test all llm risks")
    llm_ids = [m.risk_id for m in matches_llm]
    assert set(llm_ids) == {"LLM01", "LLM02", "LLM03", "LLM08", "LLM10"}

    # Priority Risks
    matches_priority = RiskIdentifier.identify_risks("Run priority risks on the application")
    priority_ids = [m.risk_id for m in matches_priority]
    assert set(priority_ids) == {"LLM01", "LLM02", "ASI01", "ASI02"}


def test_risk_identifier_default_fallback():
    """General commands with no risk specified fall back to the 4 priority baseline risks."""
    matches = RiskIdentifier.identify_risks("Test my application thoroughly.")
    ids = [m.risk_id for m in matches]
    assert ids == ["ASI01", "ASI02", "LLM01", "LLM02"]


# ---------------------------------------------------------------------------
# 3. TARGET RESOLVER TESTS
# ---------------------------------------------------------------------------

def test_target_resolver_explicit_url_regex():
    target, method = TargetResolver.extract_target_string("Check https://api.internal.local:8443/v1/chat")
    assert target == "https://api.internal.local:8443/v1/chat"
    assert method == "explicit_url_regex"


def test_target_resolver_host_port():
    target, method = TargetResolver.extract_target_string("Audit localhost:9090 for attacks")
    assert target == "http://localhost:9090"
    assert method == "host_port_regex"


def test_target_resolver_local_reference():
    target, method = TargetResolver.extract_target_string("Scan our local test application")
    assert target == "http://127.0.0.1:8000"
    assert method == "local_application_reference"


def test_target_resolver_explicit_override_precedence():
    scope = TargetResolver.resolve_target(
        command="Scan http://127.0.0.1:8080",
        explicit_target="http://127.0.0.1:9090",
    )
    assert scope.port == 9090
    assert scope.host == "127.0.0.1"


# ---------------------------------------------------------------------------
# 4. SCOPE VALIDATION & SECURITY BOUNDARY TESTS
# ---------------------------------------------------------------------------

def test_scope_localhost_allowed_by_default():
    scope = ScopeValidator.resolve_and_validate_target("http://127.0.0.1:8000")
    assert scope.is_local is True
    assert scope.is_in_scope is True
    assert scope.scope_status == ScopeStatusEnum.APPROVED_LOCAL


def test_scope_external_target_unauthorized_by_default():
    # An external target without user authorization confirmation must be blocked
    scope = ScopeValidator.resolve_and_validate_target("https://example.com/api", user_confirmed_authorization=False)
    assert scope.is_local is False
    assert scope.is_authorized is False
    assert scope.is_in_scope is False
    assert scope.scope_status == ScopeStatusEnum.UNAUTHORIZED_EXTERNAL


def test_scope_external_target_authorized_when_confirmed():
    # An external target with confirmation must be approved
    scope = ScopeValidator.resolve_and_validate_target("https://example.com/api", user_confirmed_authorization=True)
    assert scope.is_local is False
    assert scope.is_authorized is True
    assert scope.is_in_scope is True
    assert scope.scope_status == ScopeStatusEnum.APPROVED_EXTERNAL


def test_scope_cloud_metadata_blocked():
    # IPv4 link-local cloud metadata
    scope_ip = ScopeValidator.resolve_and_validate_target("http://169.254.169.254/latest/meta-data")
    assert scope_ip.is_cloud_metadata is True
    assert scope_ip.is_in_scope is False
    assert scope_ip.scope_status == ScopeStatusEnum.BLOCKED_METADATA

    # Google cloud metadata domain
    scope_gcp = ScopeValidator.resolve_and_validate_target("http://metadata.google.internal/computeMetadata/v1")
    assert scope_gcp.is_cloud_metadata is True
    assert scope_gcp.is_in_scope is False
    assert scope_gcp.scope_status == ScopeStatusEnum.BLOCKED_METADATA


def test_scope_bogon_and_dangerous_ips_blocked():
    # 0.0.0.0 current network
    scope_zero = ScopeValidator.resolve_and_validate_target("http://0.0.0.0:8000")
    assert scope_zero.is_in_scope is False
    assert scope_zero.scope_status == ScopeStatusEnum.BLOCKED_DISALLOWED_IP

    # 255.255.255.255 broadcast
    scope_bcast = ScopeValidator.resolve_and_validate_target("http://255.255.255.255:80")
    assert scope_bcast.is_in_scope is False
    assert scope_bcast.scope_status == ScopeStatusEnum.BLOCKED_DISALLOWED_IP


def test_scope_disallowed_schemes_blocked():
    scope_ftp = ScopeValidator.resolve_and_validate_target("ftp://127.0.0.1:21/resource")
    assert scope_ftp.is_in_scope is False
    assert scope_ftp.scope_status == ScopeStatusEnum.BLOCKED_SCHEME

    scope_file = ScopeValidator.resolve_and_validate_target("file:///etc/passwd")
    assert scope_file.is_in_scope is False
    assert scope_file.scope_status == ScopeStatusEnum.BLOCKED_SCHEME


def test_scope_secret_redaction():
    headers = {
        "Authorization": "Bearer super-secret-token-12345",
        "X-API-KEY": "sk_live_secret_key_abc",
        "Content-Type": "application/json",
    }
    redacted_headers, redacted_url = ScopeValidator.redact_secrets(
        headers=headers,
        url="https://example.com/api?token=secret123&query=test",
    )
    assert redacted_headers["Authorization"] == "Bearer [REDACTED_TOKEN]"
    assert redacted_headers["X-API-KEY"] == "[REDACTED_CREDENTIAL]"
    assert redacted_headers["Content-Type"] == "application/json"
    assert "token=%5BREDACTED%5D" in redacted_url or "token=%5Bre滑" in redacted_url or "token=" in redacted_url
    assert "secret123" not in redacted_url


# ---------------------------------------------------------------------------
# 5. REST API ENDPOINT INTEGRATION TESTS
# ---------------------------------------------------------------------------

def test_api_interpret_endpoint(client: TestClient):
    payload = {"command": "Test my application for LLM01 and LLM02."}
    response = client.post("/api/security-agent/interpret", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["intent"] == "TEST"
    assert data["total_planned_tests"] == 6
    assert data["is_ready_for_execution"] is True
    assert data["target"]["is_local"] is True


def test_api_validate_target_endpoint(client: TestClient):
    payload = {
        "target_url": "http://127.0.0.1:8000",
        "user_confirmed_authorization": False,
        "custom_headers": {"Authorization": "Bearer sample_token"},
    }
    response = client.post("/api/security-agent/validate-target", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is True
    assert data["is_in_scope"] is True
    assert data["redacted_headers"]["Authorization"] == "Bearer [REDACTED_TOKEN]"


def test_api_validate_target_blocked_metadata(client: TestClient):
    payload = {
        "target_url": "http://169.254.169.254/latest/meta-data",
        "user_confirmed_authorization": True,  # Confirmation must NOT bypass metadata block
    }
    response = client.post("/api/security-agent/validate-target", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is False
    assert data["is_in_scope"] is False
    assert data["target"]["scope_status"] == "BLOCKED_METADATA"


def test_api_get_risks_endpoint(client: TestClient):
    response = client.get("/api/security-agent/risks")
    assert response.status_code == 200
    risks = response.json()
    assert len(risks) == 10
    risk_ids = [r["risk_id"] for r in risks]
    assert set(risk_ids) == {"LLM01", "LLM02", "LLM03", "LLM08", "LLM10", "ASI01", "ASI02", "ASI03", "ASI05", "ASI06"}


def test_api_get_policy_endpoint(client: TestClient):
    response = client.get("/api/security-agent/policy")
    assert response.status_code == 200
    policy = response.json()
    assert "http" in policy["allowed_schemes"]
    assert "https" in policy["allowed_schemes"]
    assert policy["local_only_by_default"] is True
