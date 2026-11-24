"""
ApexShield Phase E8 — Operational Monitoring & Auditability Engine
`backend/app/security_agent/operations_monitor.py`

Provides real-time operational telemetry, HMAC evidence audit monitoring,
distributed execution tracing (X-Execution-Trace-ID, X-Correlation-ID),
and concurrency-safe per-session circuit breakers with dynamic backoff.
"""

from collections import deque
from contextlib import contextmanager
import contextvars
from datetime import datetime, timezone
from enum import Enum
import math
import re
import threading
import time
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, Union
import uuid

# =============================================================================
# CONTEXT VARIABLES FOR DISTRIBUTED ASYNC TRACING
# =============================================================================

_trace_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("trace_id", default=None)
_correlation_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("correlation_id", default=None)


# =============================================================================
# ENUMS & CONSTANTS
# =============================================================================

class CircuitState(str, Enum):
    """Lifecycle states of the per-session execution circuit breaker."""
    CLOSED = "CLOSED"          # Normal execution; probes permitted
    OPEN = "OPEN"              # Tripped; probes blocked during cooldown
    HALF_OPEN = "HALF_OPEN"    # Testing recovery; single probe trial permitted


class AlertSeverity(str, Enum):
    """Severity ratings for operational integrity and security alerts."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class VerificationResultStatus(str, Enum):
    """Cryptographic verification status categories."""
    VERIFIED = "VERIFIED"
    TAMPERED_CONTENT = "TAMPERED_CONTENT"
    FORGED_SIGNATURE = "FORGED_SIGNATURE"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    MISSING_SIGNATURE = "MISSING_SIGNATURE"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    ERROR = "ERROR"


# Redaction patterns for trace metadata sanitization
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|bearer|auth|credential|private[_-]?key)"
)
_TOKEN_VALUE_PATTERN = re.compile(
    r"(?i)(Bearer\s+[A-Za-z0-9_\-\.=]+|ak_live_[0-9a-zA-Z]{16,}|ghp_[0-9a-zA-Z]{36,})"
)


def _sanitize_trace_metadata(data: Any) -> Any:
    """Recursively redacts sensitive credentials from trace metadata."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if _SENSITIVE_KEY_PATTERN.search(str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = _sanitize_trace_metadata(v)
        return sanitized
    elif isinstance(data, list):
        return [_sanitize_trace_metadata(item) for item in data]
    elif isinstance(data, str):
        return _TOKEN_VALUE_PATTERN.sub("[REDACTED_CREDENTIAL]", data)
    return data


# =============================================================================
# 1. OPERATIONS TELEMETRY MONITOR
# =============================================================================

class OperationsTelemetryMonitor:
    """Tracks live assessment sessions, concurrent HTTP probes, throughput,
    latency percentiles (p50, p95, p99), error distributions, and worker status.
    
    Uses thread-safe bounded sliding windows to avoid unbounded memory usage.
    """

    def __init__(self, max_samples: int = 10000, window_seconds: float = 60.0):
        self.max_samples = max_samples
        self.window_seconds = window_seconds
        self._lock = threading.RLock()

        # Active state tracking
        self._active_sessions: Set[str] = set()
        self._concurrent_probes: int = 0
        self._in_flight_probes: Dict[str, float] = {}  # probe_id -> start_time

        # Bounded event metrics: deque of (timestamp, latency_ms, status_code, error_type)
        self._events: deque = deque(maxlen=max_samples)

        # Cumulative counters
        self._total_requests: int = 0
        self._count_2xx: int = 0
        self._count_3xx: int = 0
        self._count_4xx: int = 0
        self._count_5xx: int = 0
        self._timeouts_count: int = 0
        self._connection_failures_count: int = 0
        self._cancellations_count: int = 0

        # Worker status map: worker_id -> Dict[str, Any]
        self._workers: Dict[str, Dict[str, Any]] = {}

    def record_session_start(self, session_id: str) -> None:
        """Registers a newly activated security assessment session."""
        with self._lock:
            self._active_sessions.add(session_id)

    def record_session_end(self, session_id: str) -> None:
        """Deregisters a completed or terminated security assessment session."""
        with self._lock:
            self._active_sessions.discard(session_id)

    def record_probe_start(self, session_id: Optional[str] = None, probe_id: Optional[str] = None) -> str:
        """Records the dispatch of a new in-flight HTTP probe."""
        pid = probe_id or f"PRB-{uuid.uuid4().hex[:12]}"
        now = time.time()
        with self._lock:
            if session_id:
                self._active_sessions.add(session_id)
            self._concurrent_probes += 1
            self._in_flight_probes[pid] = now
        return pid

    def record_probe_end(
        self,
        probe_id: Optional[str] = None,
        session_id: Optional[str] = None,
        status_code: int = 200,
        latency_ms: Optional[float] = None,
        error_type: Optional[str] = None,
    ) -> None:
        """Records completion of an HTTP probe with its status, latency, and error classification."""
        now = time.time()
        with self._lock:
            # Reconcile in-flight probe
            if probe_id and probe_id in self._in_flight_probes:
                start_time = self._in_flight_probes.pop(probe_id)
                if latency_ms is None:
                    latency_ms = max(0.1, (now - start_time) * 1000.0)
            elif latency_ms is None:
                latency_ms = 1.0

            if self._concurrent_probes > 0:
                self._concurrent_probes -= 1

            self._total_requests += 1

            # Categorize HTTP status codes
            if 200 <= status_code < 300:
                self._count_2xx += 1
            elif 300 <= status_code < 400:
                self._count_3xx += 1
            elif 400 <= status_code < 500:
                self._count_4xx += 1
            elif status_code >= 500:
                self._count_5xx += 1

            # Categorize errors
            if error_type:
                err_lower = error_type.lower()
                if "timeout" in err_lower:
                    self._timeouts_count += 1
                elif "connection" in err_lower or "connect" in err_lower:
                    self._connection_failures_count += 1
                elif "cancel" in err_lower:
                    self._cancellations_count += 1

            self._events.append((now, float(latency_ms), int(status_code), error_type))

    def record_cancellation(self, session_id: Optional[str] = None, reason: str = "") -> None:
        """Records an explicit cancellation event."""
        with self._lock:
            self._cancellations_count += 1
            if session_id:
                self._active_sessions.discard(session_id)

    def record_worker_status(
        self,
        worker_id: str,
        status: str,
        active_task: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Updates the operational status of a security assessment worker."""
        with self._lock:
            self._workers[worker_id] = {
                "worker_id": worker_id,
                "status": status,
                "active_task": active_task,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "metadata": metadata or {},
            }

    @staticmethod
    def _calculate_percentile(sorted_samples: List[float], percentile: float) -> float:
        """Computes accurate percentile value from a sorted sample array."""
        if not sorted_samples:
            return 0.0
        n = len(sorted_samples)
        if n == 1:
            return round(sorted_samples[0], 2)
        k = (n - 1) * (percentile / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return round(sorted_samples[int(k)], 2)
        d0 = sorted_samples[int(f)] * (c - k)
        d1 = sorted_samples[int(c)] * (k - f)
        return round(d0 + d1, 2)

    def get_telemetry_overview(self) -> Dict[str, Any]:
        """Calculates and returns real-time operational telemetry metrics."""
        now = time.time()
        cutoff_sec = now - 10.0
        cutoff_min = now - 60.0

        with self._lock:
            # Filter samples within window
            recent_latencies: List[float] = []
            requests_last_10s = 0
            requests_last_60s = 0

            for ts, lat, sc, err in self._events:
                if ts >= cutoff_min:
                    requests_last_60s += 1
                    recent_latencies.append(lat)
                if ts >= cutoff_sec:
                    requests_last_10s += 1

            recent_latencies.sort()

            # Latency percentiles
            p50 = self._calculate_percentile(recent_latencies, 50.0)
            p95 = self._calculate_percentile(recent_latencies, 95.0)
            p99 = self._calculate_percentile(recent_latencies, 99.0)

            # Throughput
            throughput_per_sec = round(requests_last_10s / 10.0, 2)
            throughput_per_min = requests_last_60s

            # Error rates
            total_req = self._total_requests
            rate_4xx = round(self._count_4xx / total_req, 4) if total_req > 0 else 0.0
            rate_5xx = round(self._count_5xx / total_req, 4) if total_req > 0 else 0.0

            return {
                "active_sessions_count": len(self._active_sessions),
                "active_sessions": sorted(list(self._active_sessions)),
                "concurrent_probes": self._concurrent_probes,
                "throughput_per_second": throughput_per_sec,
                "throughput_per_minute": throughput_per_min,
                "latency_p50_ms": p50,
                "latency_p95_ms": p95,
                "latency_p99_ms": p99,
                "total_requests": self._total_requests,
                "status_code_distribution": {
                    "2xx": self._count_2xx,
                    "3xx": self._count_3xx,
                    "4xx": self._count_4xx,
                    "5xx": self._count_5xx,
                },
                "error_rates": {
                    "rate_4xx": rate_4xx,
                    "rate_5xx": rate_5xx,
                },
                "timeouts_count": self._timeouts_count,
                "connection_failures_count": self._connection_failures_count,
                "cancellations_count": self._cancellations_count,
                "workers": list(self._workers.values()),
                "sample_window_size": len(recent_latencies),
            }


# =============================================================================
# 2. HMAC AUDIT MONITOR
# =============================================================================

class HmacAuditMonitor:
    """Monitors cryptographic evidence verification and enterprise report signing.
    
    Tracks valid vs invalid signatures, content tampering events, missing signatures,
    and raises structured security alerts for verification anomalies.
    Reuses existing Phase E6 cryptographic verifiers without duplication.
    """

    def __init__(self, max_alerts: int = 100):
        self._lock = threading.RLock()
        self.max_alerts = max_alerts

        self._successful_verifications: int = 0
        self._failed_verifications: int = 0
        self._tampering_events: int = 0
        self._invalid_signatures: int = 0
        self._missing_signatures: int = 0
        self._unknown_keys: int = 0

        self._alerts: deque = deque(maxlen=max_alerts)
        self._verification_history: deque = deque(maxlen=500)

    def record_verification_result(
        self,
        is_valid: bool,
        verification_type: str = "wire_evidence",
        target_ref: str = "",
        status: Union[VerificationResultStatus, str] = VerificationResultStatus.VERIFIED.value,
        details: Optional[str] = None,
        key_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Records a cryptographic verification event and generates alerts on failures."""
        now = datetime.now(timezone.utc)
        status_str = status.value if isinstance(status, VerificationResultStatus) else str(status)

        with self._lock:
            if is_valid:
                self._successful_verifications += 1
            else:
                self._failed_verifications += 1

                # Classify failure type and generate alert
                alert_id = f"ALT-HMAC-{uuid.uuid4().hex[:8].upper()}"
                alert_severity = AlertSeverity.HIGH.value

                if status_str == VerificationResultStatus.TAMPERED_CONTENT.value or "tamper" in status_str.lower():
                    self._tampering_events += 1
                    alert_severity = AlertSeverity.CRITICAL.value
                    alert_type = "INTEGRITY_TAMPERING_DETECTED"
                elif status_str == VerificationResultStatus.MISSING_SIGNATURE.value or "missing" in status_str.lower():
                    self._missing_signatures += 1
                    alert_severity = AlertSeverity.MEDIUM.value
                    alert_type = "MISSING_SIGNATURE"
                elif status_str == VerificationResultStatus.UNKNOWN_KEY.value or "unknown" in status_str.lower():
                    self._unknown_keys += 1
                    alert_severity = AlertSeverity.HIGH.value
                    alert_type = "UNKNOWN_SIGNING_KEY"
                else:
                    self._invalid_signatures += 1
                    alert_severity = AlertSeverity.HIGH.value
                    alert_type = "INVALID_SIGNATURE"

                alert = {
                    "alert_id": alert_id,
                    "timestamp": now.isoformat(),
                    "alert_type": alert_type,
                    "severity": alert_severity,
                    "verification_type": verification_type,
                    "target_ref": target_ref,
                    "status": status_str,
                    "key_id": key_id,
                    "details": details or f"Cryptographic integrity verification failed for {target_ref}",
                }
                self._alerts.appendleft(alert)

            entry = {
                "timestamp": now.isoformat(),
                "is_valid": is_valid,
                "verification_type": verification_type,
                "target_ref": target_ref,
                "status": status_str,
                "key_id": key_id,
            }
            self._verification_history.appendleft(entry)
            return entry

    def verify_and_record_evidence(
        self,
        evidence_record: Any,
        expected_signature: Optional[str] = None,
        key: Optional[bytes] = None,
    ) -> bool:
        """Verifies wire evidence signature using crypto module and records result."""
        try:
            from app.security_agent.crypto import verify_evidence_signature
            target_ref = getattr(evidence_record, "id", None) or getattr(evidence_record, "execution_id", "unknown_evidence")
            sig = expected_signature or getattr(evidence_record, "evidence_sha256", None)
            
            if not sig:
                self.record_verification_result(
                    is_valid=False,
                    verification_type="wire_evidence",
                    target_ref=str(target_ref),
                    status=VerificationResultStatus.MISSING_SIGNATURE,
                    details="Evidence record contains no signature or SHA-256 digest.",
                )
                return False

            is_valid = verify_evidence_signature(evidence_record=evidence_record, signature=sig, key=key)
            status = VerificationResultStatus.VERIFIED if is_valid else VerificationResultStatus.INVALID_SIGNATURE
            self.record_verification_result(
                is_valid=is_valid,
                verification_type="wire_evidence",
                target_ref=str(target_ref),
                status=status,
                details="Verified wire evidence record HMAC signature." if is_valid else "HMAC signature mismatch on wire evidence.",
            )
            return is_valid
        except Exception as ex:
            self.record_verification_result(
                is_valid=False,
                verification_type="wire_evidence",
                target_ref=str(getattr(evidence_record, "id", "unknown")),
                status=VerificationResultStatus.ERROR,
                details=f"Verification exception: {str(ex)}",
            )
            return False

    def verify_and_record_report(
        self,
        report_data: Union[Dict[str, Any], str],
        expected_hash: Optional[str] = None,
        expected_signature: Optional[str] = None,
        key_id: Optional[str] = None,
        report_id: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verifies enterprise report integrity using E6 verifier and records result."""
        try:
            from app.security_agent.enterprise_report_engine import verify_report_integrity
            result = verify_report_integrity(
                report_data=report_data,
                expected_hash=expected_hash,
                expected_signature=expected_signature,
                key_id=key_id,
                report_id=report_id,
                created_at=created_at,
            )
            is_valid = bool(result.get("is_valid", False))
            status_val = result.get("status", "UNKNOWN")
            target = report_id or result.get("report_id") or "report_payload"

            self.record_verification_result(
                is_valid=is_valid,
                verification_type="enterprise_report",
                target_ref=str(target),
                status=status_val,
                details=result.get("details"),
                key_id=result.get("signing_key_id") or key_id,
            )
            return result
        except Exception as ex:
            res = {
                "is_valid": False,
                "status": "ERROR",
                "content_integrity_verified": False,
                "source_authenticity_verified": False,
                "details": str(ex),
            }
            self.record_verification_result(
                is_valid=False,
                verification_type="enterprise_report",
                target_ref=str(report_id or "unknown_report"),
                status=VerificationResultStatus.ERROR,
                details=str(ex),
                key_id=key_id,
            )
            return res

    def get_audit_summary(self) -> Dict[str, Any]:
        """Returns comprehensive cryptographic verification statistics and active alerts."""
        with self._lock:
            total = self._successful_verifications + self._failed_verifications
            success_rate = round(self._successful_verifications / total, 4) if total > 0 else 1.0

            # Determine operational health status
            if self._tampering_events > 0:
                health_status = "COMPROMISED"
            elif self._failed_verifications > 0:
                health_status = "DEGRADED"
            else:
                health_status = "HEALTHY"

            return {
                "total_verifications": total,
                "successful_verifications": self._successful_verifications,
                "failed_verifications": self._failed_verifications,
                "verification_success_rate": success_rate,
                "tampering_events": self._tampering_events,
                "invalid_signatures": self._invalid_signatures,
                "missing_signatures": self._missing_signatures,
                "unknown_keys": self._unknown_keys,
                "health_status": health_status,
                "recent_alerts": list(self._alerts)[:20],
                "recent_history": list(self._verification_history)[:20],
            }


# =============================================================================
# 3. DISTRIBUTED TRACER
# =============================================================================

class DistributedTracer:
    """Manages distributed request tracing with X-Execution-Trace-ID and X-Correlation-ID.
    
    Provides thread/async-safe context propagation, outgoing HTTP header injection,
    and trace correlation linking sessions, executions, findings, and E7 decisions.
    Sanitizes credentials so sensitive data never enters trace metadata.
    """

    HEADER_TRACE_ID = "X-Execution-Trace-ID"
    HEADER_CORRELATION_ID = "X-Correlation-ID"

    def __init__(self, max_registry_size: int = 5000):
        self._lock = threading.RLock()
        self.max_registry_size = max_registry_size
        self._trace_registry: deque = deque(maxlen=max_registry_size)
        self._trace_lookup: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def generate_trace_id(cls) -> str:
        """Generates a secure, prefixed execution trace identifier."""
        return f"TRC-{uuid.uuid4().hex[:16]}"

    @classmethod
    def generate_correlation_id(cls) -> str:
        """Generates a secure, prefixed correlation identifier."""
        return f"COR-{uuid.uuid4().hex[:16]}"

    @classmethod
    def get_current_trace_id(cls) -> Optional[str]:
        """Retrieves the active trace ID from the async context."""
        return _trace_id_ctx.get()

    @classmethod
    def get_current_correlation_id(cls) -> Optional[str]:
        """Retrieves the active correlation ID from the async context."""
        return _correlation_id_ctx.get()

    @classmethod
    def set_trace_context(
        cls,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Sets trace and correlation IDs in the current context."""
        tid = trace_id or cls.generate_trace_id()
        cid = correlation_id or cls.generate_correlation_id()
        _trace_id_ctx.set(tid)
        _correlation_id_ctx.set(cid)
        return tid, cid

    @classmethod
    def clear_trace_context(cls) -> None:
        """Clears active trace context variables."""
        _trace_id_ctx.set(None)
        _correlation_id_ctx.set(None)

    @classmethod
    @contextmanager
    def trace_scope(
        cls,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Generator[Tuple[str, str], None, None]:
        """Context manager for scoping execution traces within async or sync blocks."""
        prev_tid = _trace_id_ctx.get()
        prev_cid = _correlation_id_ctx.get()

        tid = trace_id or cls.generate_trace_id()
        cid = correlation_id or prev_cid or cls.generate_correlation_id()

        token_t = _trace_id_ctx.set(tid)
        token_c = _correlation_id_ctx.set(cid)
        try:
            yield tid, cid
        finally:
            _trace_id_ctx.reset(token_t)
            _correlation_id_ctx.reset(token_c)

    @classmethod
    def inject_headers(cls, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Injects X-Execution-Trace-ID and X-Correlation-ID into an HTTP header dictionary."""
        out = dict(headers or {})
        tid = _trace_id_ctx.get() or cls.generate_trace_id()
        cid = _correlation_id_ctx.get() or cls.generate_correlation_id()

        out[cls.HEADER_TRACE_ID] = tid
        out[cls.HEADER_CORRELATION_ID] = cid
        return out

    @classmethod
    def extract_headers(cls, headers: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
        """Extracts trace and correlation IDs from case-insensitive request headers."""
        tid: Optional[str] = None
        cid: Optional[str] = None

        for k, v in headers.items():
            k_lower = k.lower()
            if k_lower == cls.HEADER_TRACE_ID.lower():
                tid = v
            elif k_lower == cls.HEADER_CORRELATION_ID.lower():
                cid = v

        return tid, cid

    def associate_trace(
        self,
        trace_id: str,
        correlation_id: Optional[str] = None,
        session_id: Optional[str] = None,
        execution_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Registers a trace association linking session, execution, finding, and decisions."""
        sanitized_meta = _sanitize_trace_metadata(metadata or {})
        cid = correlation_id or _correlation_id_ctx.get() or self.generate_correlation_id()

        record = {
            "trace_id": trace_id,
            "correlation_id": cid,
            "session_id": session_id,
            "execution_id": execution_id,
            "finding_id": finding_id,
            "decision_id": decision_id,
            "metadata": sanitized_meta,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            # Maintain bounded map
            if len(self._trace_lookup) >= self.max_registry_size:
                oldest = self._trace_registry.pop()
                self._trace_lookup.pop(oldest["trace_id"], None)

            self._trace_registry.appendleft(record)
            self._trace_lookup[trace_id] = record

        return record

    def get_trace_details(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves stored trace metadata by trace ID."""
        with self._lock:
            return self._trace_lookup.get(trace_id)


# =============================================================================
# 4. PER-SESSION CIRCUIT BREAKER
# =============================================================================

class SessionCircuit:
    """Encapsulates the state and budget metrics of a single session circuit breaker."""

    def __init__(
        self,
        session_id: str,
        request_budget: int = 100,
        error_threshold: int = 5,
        cooldown_seconds: float = 30.0,
        backoff_factor: float = 2.0,
    ):
        self.session_id = session_id
        self.state = CircuitState.CLOSED
        self.request_budget = request_budget
        self.requests_dispatched = 0
        self.consecutive_errors = 0
        self.error_threshold = error_threshold
        self.consecutive_429 = 0
        self.consecutive_503 = 0
        self.cooldown_seconds = cooldown_seconds
        self.backoff_factor = backoff_factor
        self.current_backoff_delay = 1.0  # seconds
        self.last_tripped_at: Optional[datetime] = None
        self.trip_reason: Optional[str] = None
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes session circuit state into a structured dictionary."""
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "request_budget": self.request_budget,
            "requests_dispatched": self.requests_dispatched,
            "budget_remaining": max(0, self.request_budget - self.requests_dispatched),
            "budget_utilization_pct": round((self.requests_dispatched / self.request_budget) * 100.0, 1) if self.request_budget > 0 else 100.0,
            "consecutive_errors": self.consecutive_errors,
            "error_threshold": self.error_threshold,
            "consecutive_429": self.consecutive_429,
            "consecutive_503": self.consecutive_503,
            "cooldown_seconds": self.cooldown_seconds,
            "current_backoff_delay_sec": round(self.current_backoff_delay, 2),
            "last_tripped_at": self.last_tripped_at.isoformat() if self.last_tripped_at else None,
            "trip_reason": self.trip_reason,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class CircuitBreaker:
    """Concurrency-safe, per-session circuit breaker with dynamic exponential backoff.
    
    Protects target systems from runaway loops and rate exhaustion by enforcing
    hard request budgets and consecutive HTTP 429/503 failure trip thresholds.
    """

    def __init__(
        self,
        default_budget: int = 100,
        default_error_threshold: int = 5,
        default_cooldown: float = 30.0,
    ):
        self._lock = threading.RLock()
        self.default_budget = default_budget
        self.default_error_threshold = default_error_threshold
        self.default_cooldown = default_cooldown
        self._circuits: Dict[str, SessionCircuit] = {}

    def _get_or_create_circuit(self, session_id: str) -> SessionCircuit:
        """Internal helper to obtain or initialize a session circuit under lock."""
        if session_id not in self._circuits:
            self._circuits[session_id] = SessionCircuit(
                session_id=session_id,
                request_budget=self.default_budget,
                error_threshold=self.default_error_threshold,
                cooldown_seconds=self.default_cooldown,
            )
        return self._circuits[session_id]

    def configure_session(
        self,
        session_id: str,
        request_budget: Optional[int] = None,
        error_threshold: Optional[int] = None,
        cooldown_seconds: Optional[float] = None,
        backoff_factor: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Customizes budget and thresholds for an individual session."""
        with self._lock:
            circuit = self._get_or_create_circuit(session_id)
            if request_budget is not None:
                circuit.request_budget = max(1, request_budget)
            if error_threshold is not None:
                circuit.error_threshold = max(1, error_threshold)
            if cooldown_seconds is not None:
                circuit.cooldown_seconds = max(1.0, cooldown_seconds)
            if backoff_factor is not None:
                circuit.backoff_factor = max(1.1, backoff_factor)
            circuit.updated_at = datetime.now(timezone.utc)
            return circuit.to_dict()

    def acquire_permission(self, session_id: str) -> Tuple[bool, str, float]:
        """Evaluates whether an HTTP probe is permitted under current circuit state.
        
        Returns:
            Tuple of (is_permitted: bool, reason: str, recommended_backoff_sec: float)
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            circuit = self._get_or_create_circuit(session_id)
            circuit.updated_at = now

            # 1. Evaluate OPEN state and cooldown recovery
            if circuit.state == CircuitState.OPEN:
                if circuit.last_tripped_at is not None:
                    elapsed = (now - circuit.last_tripped_at).total_seconds()
                    if elapsed >= circuit.cooldown_seconds:
                        # Transition to HALF_OPEN to allow trial probe
                        circuit.state = CircuitState.HALF_OPEN
                        circuit.trip_reason = "Trial probe in HALF_OPEN recovery state."
                        circuit.requests_dispatched += 1
                        return True, "Permitted trial probe in HALF_OPEN state.", 0.0
                    else:
                        remaining = round(circuit.cooldown_seconds - elapsed, 2)
                        return (
                            False,
                            f"Circuit is OPEN for session '{session_id}'. Cooldown active ({remaining}s remaining). Reason: {circuit.trip_reason}",
                            remaining,
                        )
                else:
                    return False, f"Circuit is OPEN for session '{session_id}'. Reason: {circuit.trip_reason}", circuit.cooldown_seconds

            # 2. Evaluate request budget exhaustion
            if circuit.requests_dispatched >= circuit.request_budget:
                circuit.state = CircuitState.OPEN
                circuit.trip_reason = f"Request budget exhausted ({circuit.requests_dispatched}/{circuit.request_budget})."
                circuit.last_tripped_at = now
                return (
                    False,
                    f"Session request budget ({circuit.request_budget}) exhausted. Circuit tripped to OPEN.",
                    circuit.cooldown_seconds,
                )

            # 3. CLOSED or HALF_OPEN: Probe permitted
            circuit.requests_dispatched += 1
            return True, "Probe permitted.", 0.0

    def record_probe_result(
        self,
        session_id: str,
        status_code: int = 200,
        error_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Records probe outcome, updates consecutive errors, adjusts backoff, and trips circuit if needed."""
        now = datetime.now(timezone.utc)
        with self._lock:
            circuit = self._get_or_create_circuit(session_id)
            circuit.updated_at = now

            is_rate_limit = status_code == 429
            is_service_unavailable = status_code == 503
            is_timeout = bool(error_type and "timeout" in error_type.lower())
            is_connection_err = bool(error_type and ("connect" in error_type.lower() or "failure" in error_type.lower()))

            # Check if this outcome constitutes a circuit breaker error event
            if is_rate_limit or is_service_unavailable or is_timeout or is_connection_err:
                circuit.consecutive_errors += 1

                if is_rate_limit:
                    circuit.consecutive_429 += 1
                    circuit.current_backoff_delay = min(60.0, circuit.current_backoff_delay * circuit.backoff_factor)
                elif is_service_unavailable:
                    circuit.consecutive_503 += 1
                    circuit.current_backoff_delay = min(60.0, circuit.current_backoff_delay * circuit.backoff_factor)

                # Trip condition check
                if circuit.consecutive_errors >= circuit.error_threshold or circuit.state == CircuitState.HALF_OPEN:
                    circuit.state = CircuitState.OPEN
                    circuit.last_tripped_at = now
                    trigger = f"HTTP {status_code}" if (is_rate_limit or is_service_unavailable) else (error_type or "Failure")
                    circuit.trip_reason = f"Consecutive error threshold reached ({circuit.consecutive_errors}/{circuit.error_threshold}). Trigger: {trigger}"
            else:
                # Successful or non-tripping response (2xx, 3xx, normal 4xx like 404/401)
                if circuit.state == CircuitState.HALF_OPEN:
                    # Successful probe in HALF_OPEN heals the circuit
                    circuit.state = CircuitState.CLOSED
                    circuit.consecutive_errors = 0
                    circuit.consecutive_429 = 0
                    circuit.consecutive_503 = 0
                    circuit.current_backoff_delay = 1.0
                    circuit.trip_reason = None
                elif circuit.state == CircuitState.CLOSED:
                    circuit.consecutive_errors = 0
                    circuit.consecutive_429 = 0
                    circuit.consecutive_503 = 0
                    circuit.current_backoff_delay = 1.0

            return circuit.to_dict()

    def reset(
        self,
        session_id: Optional[str] = None,
        is_admin: bool = True,
    ) -> Dict[str, Any]:
        """Administratively resets circuit state. Requires admin authorization."""
        if not is_admin:
            raise PermissionError("Administrative authorization required to reset circuit breaker.")

        now = datetime.now(timezone.utc)
        with self._lock:
            if session_id:
                circuit = self._get_or_create_circuit(session_id)
                circuit.state = CircuitState.CLOSED
                circuit.requests_dispatched = 0
                circuit.consecutive_errors = 0
                circuit.consecutive_429 = 0
                circuit.consecutive_503 = 0
                circuit.current_backoff_delay = 1.0
                circuit.last_tripped_at = None
                circuit.trip_reason = None
                circuit.updated_at = now
                return {"reset_count": 1, "session_id": session_id, "circuit": circuit.to_dict()}
            else:
                count = len(self._circuits)
                for circuit in self._circuits.values():
                    circuit.state = CircuitState.CLOSED
                    circuit.requests_dispatched = 0
                    circuit.consecutive_errors = 0
                    circuit.consecutive_429 = 0
                    circuit.consecutive_503 = 0
                    circuit.current_backoff_delay = 1.0
                    circuit.last_tripped_at = None
                    circuit.trip_reason = None
                    circuit.updated_at = now
                return {"reset_count": count, "session_id": "ALL", "status": "RESET_ALL_COMPLETED"}

    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Retrieves operational status of a single session circuit."""
        with self._lock:
            circuit = self._get_or_create_circuit(session_id)
            return circuit.to_dict()

    def get_all_circuits(self) -> List[Dict[str, Any]]:
        """Retrieves list of all session circuits."""
        with self._lock:
            return [c.to_dict() for c in self._circuits.values()]


# =============================================================================
# 5. UNIFIED OPERATIONS MONITOR (ORCHESTRATOR)
# =============================================================================

class OperationsMonitor:
    """Unified operational monitoring orchestrator aggregating telemetry, HMAC audits,
    distributed tracing, and session circuit breakers.
    """

    def __init__(
        self,
        telemetry: Optional[OperationsTelemetryMonitor] = None,
        hmac_audit: Optional[HmacAuditMonitor] = None,
        tracer: Optional[DistributedTracer] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ):
        self.telemetry = telemetry or OperationsTelemetryMonitor()
        self.hmac_audit = hmac_audit or HmacAuditMonitor()
        self.tracer = tracer or DistributedTracer()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()

    def get_health_probe(self) -> Dict[str, Any]:
        """Computes comprehensive health status across telemetry, HMAC, and circuit breakers."""
        telem = self.telemetry.get_telemetry_overview()
        hmac = self.hmac_audit.get_audit_summary()
        circuits = self.circuit_breaker.get_all_circuits()

        open_circuits = [c for c in circuits if c["state"] == CircuitState.OPEN.value]
        degraded = False
        unhealthy = False

        if hmac["tampering_events"] > 0:
            unhealthy = True
        elif hmac["failed_verifications"] > 0 or len(open_circuits) > 0 or telem["error_rates"]["rate_5xx"] > 0.05:
            degraded = True

        status = "UNHEALTHY" if unhealthy else ("DEGRADED" if degraded else "HEALTHY")

        return {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "telemetry_summary": {
                "active_sessions": telem["active_sessions_count"],
                "concurrent_probes": telem["concurrent_probes"],
                "throughput_per_sec": telem["throughput_per_second"],
                "latency_p95_ms": telem["latency_p95_ms"],
                "rate_5xx": telem["error_rates"]["rate_5xx"],
            },
            "hmac_integrity": {
                "health": hmac["health_status"],
                "tampering_events": hmac["tampering_events"],
                "verification_success_rate": hmac["verification_success_rate"],
            },
            "circuit_breaker_summary": {
                "total_circuits": len(circuits),
                "open_circuits": len(open_circuits),
            },
        }


# Global singleton instances for application runtime
global_telemetry_monitor = OperationsTelemetryMonitor()
global_hmac_audit_monitor = HmacAuditMonitor()
global_distributed_tracer = DistributedTracer()
global_circuit_breaker = CircuitBreaker()
global_operations_monitor = OperationsMonitor(
    telemetry=global_telemetry_monitor,
    hmac_audit=global_hmac_audit_monitor,
    tracer=global_distributed_tracer,
    circuit_breaker=global_circuit_breaker,
)
