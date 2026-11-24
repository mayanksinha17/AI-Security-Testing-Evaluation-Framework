"""Real HTTP Execution Engine & Evidence Collector (Phase B).

Dispatches actual HTTP requests to the target test application using httpx,
enforces strict target scope, records unforgeable execution evidence, handles
redirection & timeout security, and provides cancellation controls.
"""

from datetime import datetime, timezone
import json
import socket
import time
from typing import Any, Dict, Optional, Set
from urllib.parse import urljoin

from fastapi import HTTPException, status
import httpx
from sqlalchemy.orm import Session

from app.security_agent.crypto import compute_evidence_signature
from app.security_agent.models import (
    AgentExecutionSession,
    HttpEvidenceRecord,
    SecurityExecutionPlan,
    SecurityTestExecution,
)
from app.security_agent.payloads import evaluate_http_response, get_payload_for_scenario
from app.security_agent.planner import SecurityPlanGenerator
from app.security_agent.schemas import ExecutionPlanSummary, ScopeStatusEnum
from app.security_agent.scope_validator import ScopeValidator


class AsyncHttpExecutor:
    """Dispatches real HTTP requests to the approved target, captures evidence, and computes verdicts."""

    # Set of currently cancelled plan IDs
    _cancelled_plans: Set[str] = set()

    @classmethod
    def cancel_plan(cls, plan_id: str, db: Session) -> bool:
        """Signals cancellation of an execution plan and updates pending tests."""
        cls._cancelled_plans.add(plan_id)

        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            return False

        plan.status = "CANCELLED"
        plan.completed_at = datetime.now(timezone.utc)

        # Cancel any pending tests
        for t in plan.executions:
            if t.status in ["PENDING", "RUNNING"]:
                t.status = "CANCELLED"
                t.verdict = "CANCELLED"

        db.commit()
        return True

    @classmethod
    async def execute_plan(
        cls,
        plan_id: str,
        db: Session,
        stage_override: Optional[str] = None,
        transport: Optional[httpx.BaseTransport] = None,
        custom_client: Optional[httpx.AsyncClient] = None,
    ) -> ExecutionPlanSummary:
        """Executes an approved plan using real HTTP requests against the target.

        Supports:
        - Real network HTTP requests (via standard httpx client).
        - Direct ASGI application transport for in-process testing.
        - Strict scope enforcement (rejects disallowed schemes, bogon IPs, cloud metadata).
        - Safe request timeout (10.0s).
        - Disables automatic redirects (prevents SSRF redirect escapes).
        - Secret and token redaction before evidence persistence.
        """
        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution plan '{plan_id}' not found.",
            )

        # 1. Target Scope & Authorization Check
        scope = ScopeValidator.resolve_and_validate_target(
            raw_url=plan.target_url,
            user_confirmed_authorization=plan.session.user_confirmed_authorization if plan.session else False,
        )

        if not scope.is_in_scope:
            plan.status = "FAILED"
            for t in plan.executions:
                t.status = "BLOCKED_SCOPE"
                t.verdict = "BLOCKED"
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target execution blocked by security policy: {scope.reason}",
            )

        # Initial implementation boundary: permit testing only against approved local application
        if not scope.is_local:
            plan.status = "FAILED"
            for t in plan.executions:
                t.status = "BLOCKED_SCOPE"
                t.verdict = "BLOCKED"
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security Boundary: Initial agent testing is strictly restricted to approved local test application (127.0.0.1 / localhost).",
            )

        # 2. Stage determination
        effective_stage = (stage_override or plan.stage or "POST_MITIGATION").upper().strip()
        plan.stage = effective_stage
        plan.status = "IN_PROGRESS"
        db.commit()

        # Remove from cancelled set if re-running
        cls._cancelled_plans.discard(plan_id)

        timeout = httpx.Timeout(10.0, connect=5.0)

        # 3. Create or reuse httpx AsyncClient
        async def _run_with_client(client: httpx.AsyncClient):
            for test in plan.executions:
                # Check for cancellation
                if plan_id in cls._cancelled_plans:
                    test.status = "CANCELLED"
                    test.verdict = "CANCELLED"
                    db.commit()
                    continue

                if test.status not in ["PENDING"]:
                    continue

                test.status = "RUNNING"
                db.commit()

                payload = get_payload_for_scenario(test.scenario_id, test.risk_id)
                full_url = urljoin(plan.target_url, test.target_endpoint)

                headers = {
                    "Content-Type": "application/json",
                    "X-Security-Stage": effective_stage,
                }

                # Redact request headers & payload before storage
                redacted_req_headers, _ = ScopeValidator.redact_secrets(headers=headers)
                raw_payload_str = json.dumps(payload.request_body)

                timestamp_sent = datetime.now(timezone.utc)
                start_time = time.perf_counter()

                try:
                    # REAL HTTP REQUEST DISPATCH
                    response = await client.request(
                        method=test.http_method,
                        url=full_url,
                        headers=headers,
                        json=payload.request_body,
                    )
                    duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                    timestamp_received = datetime.now(timezone.utc)

                    status_code = response.status_code
                    raw_resp_text = response.text

                    # Redact response headers
                    resp_headers_dict = dict(response.headers)
                    redacted_resp_headers, _ = ScopeValidator.redact_secrets(headers=resp_headers_dict)

                    # Redact response body
                    redacted_resp_body = raw_resp_text
                    if "canary" in redacted_resp_body.lower() and effective_stage == "POST_MITIGATION":
                        redacted_resp_body = redacted_resp_body.replace("CANARY_TEST_FLAG_9981", "[REDACTED_CANARY]")

                    # Evaluate HTTP response against detection criteria
                    verdict, explanation = evaluate_http_response(payload, status_code, raw_resp_text)

                    test.status = "COMPLETED"
                    test.verdict = verdict
                    test.duration_ms = duration_ms
                    error_message = None

                except (httpx.TimeoutException, httpx.ConnectError, Exception) as exc:
                    duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                    timestamp_received = datetime.now(timezone.utc)
                    status_code = None
                    redacted_resp_headers = {}
                    redacted_resp_body = ""
                    test.status = "FAILED"
                    test.verdict = "ERROR"
                    test.duration_ms = duration_ms
                    error_message = f"{type(exc).__name__}: {str(exc)}"

                # Cryptographic HMAC-SHA256 evidence integrity digest
                evidence_canonical = f"{full_url}|{test.http_method}|{raw_payload_str}|{status_code}|{redacted_resp_body}"
                evidence_sha256 = compute_evidence_signature(evidence_canonical)

                # Persist HTTP evidence record
                evidence = HttpEvidenceRecord(
                    execution_id=test.id,
                    target_url=full_url,
                    http_method=test.http_method,
                    request_headers=json.dumps(redacted_req_headers),
                    request_body=raw_payload_str,
                    response_status_code=status_code,
                    response_headers=json.dumps(redacted_resp_headers),
                    response_body=redacted_resp_body,
                    response_latency_ms=duration_ms,
                    timestamp_sent=timestamp_sent,
                    timestamp_received=timestamp_received,
                    error_message=error_message,
                    evidence_sha256=evidence_sha256,
                )
                db.add(evidence)
                plan.completed_tests += 1
                db.commit()

        if custom_client:
            await _run_with_client(custom_client)
        elif transport:
            async with httpx.AsyncClient(transport=transport, base_url=plan.target_url, timeout=timeout, follow_redirects=False) as client:
                await _run_with_client(client)
        else:
            # Check if live server is reachable via TCP
            can_connect_tcp = False
            try:
                with socket.create_connection((scope.host, scope.port), timeout=0.15):
                    can_connect_tcp = True
            except Exception:
                can_connect_tcp = False

            is_internal_default = (scope.host in ["127.0.0.1", "localhost"] and scope.port in [8000, 80])

            if can_connect_tcp:
                # Live server is up and listening on TCP port
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                    await _run_with_client(client)
            elif is_internal_default:
                # In-process FastAPI ASGI transport fallback for unit tests and local execution
                from app.main import app as current_app
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=current_app),
                    base_url=plan.target_url,
                    timeout=timeout,
                    follow_redirects=False,
                ) as client:
                    await _run_with_client(client)
            else:
                # Non-default or unreachable host/port -> Real TCP client which will record ConnectError
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                    await _run_with_client(client)

        # 4. Finalize plan state
        if plan_id in cls._cancelled_plans:
            plan.status = "CANCELLED"
        else:
            plan.status = "COMPLETED"
        plan.completed_at = datetime.now(timezone.utc)

        if plan.session:
            plan.session.status = plan.status
            plan.session.updated_at = datetime.now(timezone.utc)

        db.commit()

        return SecurityPlanGenerator.get_plan(plan_id, db)
