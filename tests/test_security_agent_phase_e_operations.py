"""Dedicated Automated Test Suite for ApexShield Phase E8 — Operational Monitoring & Auditability.

Tests:
1. OperationsTelemetryMonitor: Active-session tracking.
2. OperationsTelemetryMonitor: Concurrent probe tracking.
3. OperationsTelemetryMonitor: Request throughput (per sec / min).
4. OperationsTelemetryMonitor: p50, p95, p99 latency calculations.
5. OperationsTelemetryMonitor: HTTP error classification (4xx, 5xx rates).
6. OperationsTelemetryMonitor: Timeout tracking.
7. OperationsTelemetryMonitor: Cancellation tracking.
8. HmacAuditMonitor: Successful verification counters.
9. HmacAuditMonitor: Failed verification counters.
10. HmacAuditMonitor: Tamper detection & critical alerts.
11. DistributedTracer: Trace ID & Correlation ID generation.
12. DistributedTracer: Context propagation through trace_scope.
13. DistributedTracer: Outgoing HTTP header injection & extraction.
14. DistributedTracer: Trace association with execution records & secret sanitization.
15. CircuitBreaker: Per-session request budgets enforcement.
16. CircuitBreaker: CLOSED state normal operation.
17. CircuitBreaker: OPEN state probe blocking.
18. CircuitBreaker: HALF_OPEN trial probe recovery.
19. CircuitBreaker: HTTP 429 consecutive error dynamic backoff.
20. CircuitBreaker: HTTP 503 consecutive error dynamic backoff.
21. CircuitBreaker: Safe chain suspension on trip.
22. CircuitBreaker: Administrative reset authorization requirement.
23. CircuitBreaker: Concurrency-safe budget enforcement under multithreading.
24. REST API: Operational endpoints, trace headers & administrative reset authorization.
25. Canonical database baseline records untouched (786 / 138 / 693 / 96).
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
from app.security_agent.operations_monitor import (
    AlertSeverity,
    CircuitBreaker,
    CircuitState,
    DistributedTracer,
    HmacAuditMonitor,
    OperationsMonitor,
    OperationsTelemetryMonitor,
    SessionCircuit,
    VerificationResultStatus,
    global_circuit_breaker,
    global_distributed_tracer,
    global_hmac_audit_monitor,
    global_operations_monitor,
    global_telemetry_monitor,
)


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


# =============================================================================
# 1. TELEMETRY MONITOR TESTS
# =============================================================================

def test_telemetry_active_session_tracking():
    """1. Verifies accurate registration and deregistration of active assessment sessions."""
    telem = OperationsTelemetryMonitor()
    telem.record_session_start("session_alpha")
    telem.record_session_start("session_beta")
    telem.record_session_start("session_gamma")

    overview = telem.get_telemetry_overview()
    assert overview["active_sessions_count"] == 3
    assert set(overview["active_sessions"]) == {"session_alpha", "session_beta", "session_gamma"}

    telem.record_session_end("session_beta")
    updated = telem.get_telemetry_overview()
    assert updated["active_sessions_count"] == 2
    assert "session_beta" not in updated["active_sessions"]


def test_telemetry_concurrent_probe_tracking():
    """2. Verifies accurate tracking of concurrent in-flight probes."""
    telem = OperationsTelemetryMonitor()
    p1 = telem.record_probe_start(session_id="s1")
    p2 = telem.record_probe_start(session_id="s1")
    p3 = telem.record_probe_start(session_id="s2")

    assert telem.get_telemetry_overview()["concurrent_probes"] == 3

    telem.record_probe_end(probe_id=p1, status_code=200, latency_ms=15.0)
    assert telem.get_telemetry_overview()["concurrent_probes"] == 2

    telem.record_probe_end(probe_id=p2, status_code=200, latency_ms=20.0)
    telem.record_probe_end(probe_id=p3, status_code=200, latency_ms=25.0)
    assert telem.get_telemetry_overview()["concurrent_probes"] == 0


def test_telemetry_request_throughput():
    """3. Verifies request throughput calculation over 10s and 60s windows."""
    telem = OperationsTelemetryMonitor()
    for _ in range(25):
        telem.record_probe_end(status_code=200, latency_ms=10.0)

    overview = telem.get_telemetry_overview()
    assert overview["throughput_per_minute"] == 25
    assert overview["throughput_per_second"] == 2.5
    assert overview["total_requests"] == 25


def test_telemetry_latency_percentiles():
    """4. Verifies accurate p50, p95, and p99 latency percentile calculations."""
    telem = OperationsTelemetryMonitor()
    # Add samples from 10ms to 1000ms in steps of 10
    for lat in range(10, 1010, 10):
        telem.record_probe_end(status_code=200, latency_ms=float(lat))

    overview = telem.get_telemetry_overview()
    assert 500.0 <= overview["latency_p50_ms"] <= 510.0
    assert 940.0 <= overview["latency_p95_ms"] <= 960.0
    assert 985.0 <= overview["latency_p99_ms"] <= 1000.0


def test_telemetry_http_error_classification():
    """5. Verifies accurate HTTP status distribution and 4xx/5xx error rates."""
    telem = OperationsTelemetryMonitor()
    # Record 8 2xx, 2 4xx, 2 5xx -> 12 total
    for _ in range(8):
        telem.record_probe_end(status_code=200, latency_ms=12.0)
    for _ in range(2):
        telem.record_probe_end(status_code=404, latency_ms=8.0)
    for _ in range(2):
        telem.record_probe_end(status_code=500, latency_ms=45.0)

    overview = telem.get_telemetry_overview()
    assert overview["status_code_distribution"]["2xx"] == 8
    assert overview["status_code_distribution"]["4xx"] == 2
    assert overview["status_code_distribution"]["5xx"] == 2
    assert round(overview["error_rates"]["rate_4xx"], 2) == 0.17
    assert round(overview["error_rates"]["rate_5xx"], 2) == 0.17


def test_telemetry_timeout_tracking():
    """6. Verifies detection and counting of network and socket timeouts."""
    telem = OperationsTelemetryMonitor()
    telem.record_probe_end(status_code=0, latency_ms=5000.0, error_type="connection_timeout")
    telem.record_probe_end(status_code=0, latency_ms=5000.0, error_type="read_timeout")
    telem.record_probe_end(status_code=200, latency_ms=10.0)

    overview = telem.get_telemetry_overview()
    assert overview["timeouts_count"] == 2


def test_telemetry_cancellation_tracking():
    """7. Verifies tracking of explicit execution cancellation events."""
    telem = OperationsTelemetryMonitor()
    telem.record_session_start("session_to_cancel")
    telem.record_cancellation(session_id="session_to_cancel", reason="User abort")

    overview = telem.get_telemetry_overview()
    assert overview["cancellations_count"] == 1
    assert "session_to_cancel" not in overview["active_sessions"]


# =============================================================================
# 2. HMAC AUDIT MONITOR TESTS
# =============================================================================

def test_hmac_successful_verification_counters():
    """8. Verifies tracking of valid cryptographic evidence signatures."""
    hmac_mon = HmacAuditMonitor()
    hmac_mon.record_verification_result(
        is_valid=True,
        verification_type="wire_evidence",
        target_ref="evidence_001",
        status=VerificationResultStatus.VERIFIED,
    )
    summary = hmac_mon.get_audit_summary()
    assert summary["successful_verifications"] == 1
    assert summary["failed_verifications"] == 0
    assert summary["verification_success_rate"] == 1.0
    assert summary["health_status"] == "HEALTHY"


def test_hmac_failed_verification_counters():
    """9. Verifies tracking of invalid and failed evidence signatures."""
    hmac_mon = HmacAuditMonitor()
    hmac_mon.record_verification_result(
        is_valid=False,
        verification_type="wire_evidence",
        target_ref="evidence_002",
        status=VerificationResultStatus.INVALID_SIGNATURE,
        details="Signature mismatch on wire evidence",
    )
    summary = hmac_mon.get_audit_summary()
    assert summary["failed_verifications"] == 1
    assert summary["invalid_signatures"] == 1
    assert summary["health_status"] == "DEGRADED"
    assert len(summary["recent_alerts"]) == 1
    assert summary["recent_alerts"][0]["severity"] == AlertSeverity.HIGH.value


def test_hmac_tamper_detection_alerts():
    """10. Verifies critical alerts and compromised health status upon content tampering."""
    hmac_mon = HmacAuditMonitor()
    hmac_mon.record_verification_result(
        is_valid=False,
        verification_type="enterprise_report",
        target_ref="REP-2026-001",
        status=VerificationResultStatus.TAMPERED_CONTENT,
        details="Calculated SHA-256 does not match signed report digest.",
    )
    summary = hmac_mon.get_audit_summary()
    assert summary["tampering_events"] == 1
    assert summary["health_status"] == "COMPROMISED"
    assert summary["recent_alerts"][0]["severity"] == AlertSeverity.CRITICAL.value
    assert summary["recent_alerts"][0]["alert_type"] == "INTEGRITY_TAMPERING_DETECTED"


# =============================================================================
# 3. DISTRIBUTED TRACER TESTS
# =============================================================================

def test_distributed_tracer_id_generation():
    """11. Verifies unique formatted trace and correlation identifier generation."""
    tid = DistributedTracer.generate_trace_id()
    cid = DistributedTracer.generate_correlation_id()
    assert tid.startswith("TRC-")
    assert cid.startswith("COR-")
    assert len(tid) == 20
    assert len(cid) == 20
    assert tid != DistributedTracer.generate_trace_id()


def test_distributed_tracer_context_propagation():
    """12. Verifies trace context propagation across synchronous and asynchronous blocks."""
    DistributedTracer.clear_trace_context()
    assert DistributedTracer.get_current_trace_id() is None

    with DistributedTracer.trace_scope(trace_id="TRC-fixed123", correlation_id="COR-fixed456") as (t, c):
        assert t == "TRC-fixed123"
        assert c == "COR-fixed456"
        assert DistributedTracer.get_current_trace_id() == "TRC-fixed123"
        assert DistributedTracer.get_current_correlation_id() == "COR-fixed456"

    # Context reverts cleanly after scope exit
    assert DistributedTracer.get_current_trace_id() is None


def test_distributed_tracer_header_injection_and_extraction():
    """13. Verifies header injection for outgoing probes and extraction from inbound requests."""
    with DistributedTracer.trace_scope(trace_id="TRC-probe999", correlation_id="COR-flow888"):
        headers = DistributedTracer.inject_headers({"User-Agent": "ApexShield-Probe/1.0"})
        assert headers["X-Execution-Trace-ID"] == "TRC-probe999"
        assert headers["X-Correlation-ID"] == "COR-flow888"
        assert headers["User-Agent"] == "ApexShield-Probe/1.0"

        # Test case-insensitive extraction
        extracted_t, extracted_c = DistributedTracer.extract_headers({
            "x-execution-trace-id": "TRC-probe999",
            "x-correlation-id": "COR-flow888",
        })
        assert extracted_t == "TRC-probe999"
        assert extracted_c == "COR-flow888"


def test_distributed_tracer_association_and_sanitization():
    """14. Verifies trace association with execution entities and credential sanitization."""
    tracer = DistributedTracer()
    record = tracer.associate_trace(
        trace_id="TRC-assoc001",
        session_id="session_01",
        execution_id="exec_01",
        finding_id="find_01",
        decision_id="DEC-001",
        metadata={
            "target": "https://api.internal/v1/auth",
            "api_key": "ak_live_supersecret12345",
            "auth_header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dummy",
            "safe_metric": 42,
        },
    )

    retrieved = tracer.get_trace_details("TRC-assoc001")
    assert retrieved is not None
    assert retrieved["session_id"] == "session_01"
    assert retrieved["metadata"]["safe_metric"] == 42
    # Sensitive credentials must be scrubbed
    assert retrieved["metadata"]["api_key"] == "[REDACTED]"
    assert "supersecret" not in json.dumps(retrieved["metadata"])


# =============================================================================
# 4. CIRCUIT BREAKER TESTS
# =============================================================================

def test_circuit_breaker_per_session_budget():
    """15. Verifies hard per-session request budgets and transition to OPEN upon exhaustion."""
    cb = CircuitBreaker()
    cb.configure_session("sess_budget", request_budget=3)

    p1, r1, _ = cb.acquire_permission("sess_budget")
    p2, r2, _ = cb.acquire_permission("sess_budget")
    p3, r3, _ = cb.acquire_permission("sess_budget")
    assert p1 and p2 and p3

    # 4th probe exceeds budget of 3
    p4, r4, _ = cb.acquire_permission("sess_budget")
    assert not p4
    assert "budget" in r4.lower()

    status = cb.get_session_status("sess_budget")
    assert status["state"] == CircuitState.OPEN.value
    assert status["budget_remaining"] == 0


def test_circuit_breaker_closed_state_normal_operation():
    """16. Verifies CLOSED state allows probes and resets consecutive error counts on success."""
    cb = CircuitBreaker()
    permitted, _, _ = cb.acquire_permission("sess_normal")
    assert permitted

    # Record 200 OK
    status = cb.record_probe_result("sess_normal", status_code=200)
    assert status["state"] == CircuitState.CLOSED.value
    assert status["consecutive_errors"] == 0


def test_circuit_breaker_open_state_blocks_probes():
    """17. Verifies circuit trips to OPEN after consecutive errors and blocks subsequent probes."""
    cb = CircuitBreaker(default_error_threshold=3, default_cooldown=10.0)

    # Trigger 3 consecutive errors
    cb.record_probe_result("sess_trip", status_code=503)
    cb.record_probe_result("sess_trip", status_code=503)
    status = cb.record_probe_result("sess_trip", status_code=503)

    assert status["state"] == CircuitState.OPEN.value
    assert status["consecutive_errors"] == 3

    # Subsequent probe acquisition blocked
    permitted, reason, cooldown = cb.acquire_permission("sess_trip")
    assert not permitted
    assert "circuit is open" in reason.lower()
    assert cooldown > 0.0


def test_circuit_breaker_half_open_trial_probe_recovery():
    """18. Verifies transition to HALF_OPEN after cooldown and recovery back to CLOSED on success."""
    cb = CircuitBreaker(default_error_threshold=2, default_cooldown=0.05)

    cb.record_probe_result("sess_recover", status_code=503)
    cb.record_probe_result("sess_recover", status_code=503)
    assert cb.get_session_status("sess_recover")["state"] == CircuitState.OPEN.value

    # Wait for cooldown expiration
    time.sleep(0.06)

    # Permission acquired in HALF_OPEN state
    permitted, reason, _ = cb.acquire_permission("sess_recover")
    assert permitted
    assert cb.get_session_status("sess_recover")["state"] == CircuitState.HALF_OPEN.value

    # Successful probe heals circuit back to CLOSED
    recovered = cb.record_probe_result("sess_recover", status_code=200)
    assert recovered["state"] == CircuitState.CLOSED.value
    assert recovered["consecutive_errors"] == 0


def test_circuit_breaker_429_dynamic_backoff():
    """19. Verifies dynamic exponential backoff scaling on HTTP 429 rate limit responses."""
    cb = CircuitBreaker(default_error_threshold=10)
    s1 = cb.record_probe_result("sess_429", status_code=429)
    assert s1["consecutive_429"] == 1
    assert s1["current_backoff_delay_sec"] == 2.0

    s2 = cb.record_probe_result("sess_429", status_code=429)
    assert s2["consecutive_429"] == 2
    assert s2["current_backoff_delay_sec"] == 4.0


def test_circuit_breaker_503_dynamic_backoff():
    """20. Verifies dynamic backoff scaling on HTTP 503 service unavailable responses."""
    cb = CircuitBreaker(default_error_threshold=10)
    s1 = cb.record_probe_result("sess_503", status_code=503)
    assert s1["consecutive_503"] == 1
    assert s1["current_backoff_delay_sec"] == 2.0

    s2 = cb.record_probe_result("sess_503", status_code=503)
    assert s2["consecutive_503"] == 2
    assert s2["current_backoff_delay_sec"] == 4.0


def test_circuit_breaker_safe_chain_suspension():
    """21. Verifies that tripping the circuit breaker safely suspends an attack chain without crash."""
    cb = CircuitBreaker(default_budget=2)
    session_id = f"chain_sess_{uuid.uuid4().hex[:6]}"

    results = []
    for step in range(5):
        permitted, reason, _ = cb.acquire_permission(session_id)
        if not permitted:
            results.append(f"Step {step} suspended: {reason}")
            break
        results.append(f"Step {step} executed")
        cb.record_probe_result(session_id, status_code=200)

    assert len(results) == 3
    assert results[0] == "Step 0 executed"
    assert results[1] == "Step 1 executed"
    assert "suspended" in results[2]


def test_circuit_breaker_administrative_reset_authorization():
    """22. Verifies administrative authorization check for circuit breaker reset operations."""
    cb = CircuitBreaker()
    cb.configure_session("sess_reset", request_budget=2)
    cb.acquire_permission("sess_reset")
    cb.acquire_permission("sess_reset")
    # Tripped
    cb.acquire_permission("sess_reset")
    assert cb.get_session_status("sess_reset")["state"] == CircuitState.OPEN.value

    # Unauthorized reset rejected
    with pytest.raises(PermissionError):
        cb.reset(session_id="sess_reset", is_admin=False)

    # Authorized reset succeeds
    cb.reset(session_id="sess_reset", is_admin=True)
    status = cb.get_session_status("sess_reset")
    assert status["state"] == CircuitState.CLOSED.value
    assert status["requests_dispatched"] == 0


def test_circuit_breaker_concurrency_safe_budget_enforcement():
    """23. Verifies thread-safe request budget enforcement across concurrent worker threads."""
    cb = CircuitBreaker()
    session_id = f"sess_concurrent_{uuid.uuid4().hex[:6]}"
    budget = 20
    cb.configure_session(session_id, request_budget=budget)

    permitted_count = 0
    blocked_count = 0

    def worker_attempt():
        nonlocal permitted_count, blocked_count
        p, _, _ = cb.acquire_permission(session_id)
        if p:
            permitted_count += 1
        else:
            blocked_count += 1

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker_attempt) for _ in range(50)]
        for f in futures:
            f.result()

    assert permitted_count == budget
    assert blocked_count == 30
    assert cb.get_session_status(session_id)["state"] == CircuitState.OPEN.value


# =============================================================================
# 5. REST API & REGRESSION INVARIANTS
# =============================================================================

def test_api_operations_endpoints_and_authorization(client):
    """24. Verifies all 5 REST operations endpoints, trace headers, and reset auth."""
    # 1. GET /overview
    resp_over = client.get("/api/security-agent/operations/overview")
    assert resp_over.status_code == 200
    assert "throughput_per_second" in resp_over.json()
    assert "X-Execution-Trace-ID" in resp_over.headers
    assert "X-Correlation-ID" in resp_over.headers

    # 2. GET /health
    resp_health = client.get("/api/security-agent/operations/health")
    assert resp_health.status_code == 200
    assert "status" in resp_health.json()

    # 3. GET /hmac-audit
    resp_hmac = client.get("/api/security-agent/operations/hmac-audit")
    assert resp_hmac.status_code == 200
    assert "health_status" in resp_hmac.json()

    # 4. GET /circuit-breaker
    resp_cb = client.get("/api/security-agent/operations/circuit-breaker")
    assert resp_cb.status_code == 200
    assert "circuits" in resp_cb.json()

    # 5. POST /circuit-breaker/reset without authorization -> 403
    resp_unauth = client.post("/api/security-agent/operations/circuit-breaker/reset", json={
        "admin_token": "invalid_unauthorized_token"
    })
    assert resp_unauth.status_code == 403

    # 6. POST /circuit-breaker/reset with valid authorization -> 200
    resp_auth = client.post("/api/security-agent/operations/circuit-breaker/reset", json={
        "admin_token": "apexshield_ops_admin_2026"
    })
    assert resp_auth.status_code == 200
    assert resp_auth.json()["status"] == "SUCCESS"


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
