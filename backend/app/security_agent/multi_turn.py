"""Adaptive Multi-Turn Execution Engine for Autonomous Security Agent (Phase C).

Executes end-to-end multi-turn security testing chains:
1. Dispatches baseline probe (Turn 1).
2. Captures real HTTP response and wire evidence.
3. Performs intelligent response analysis (BLOCKED, VULNERABLE, PARTIAL, ERROR).
4. Invokes Autonomous Decision Engine.
5. Dynamically mutates payload and executes follow-up probes (Turn 2, Turn 3).
6. Maintains execution lineage, parent-child relationships, and SHA-256 evidence hashes.
"""

from datetime import datetime, timezone
import hashlib
import json
import socket
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

from fastapi import HTTPException, status
import httpx
from sqlalchemy.orm import Session

from app.security_agent.crypto import compute_evidence_signature
from app.security_agent.decision_engine import (
    AutonomousDecision,
    AutonomousDecisionEngine,
    DecisionActionEnum,
    ExecutionLimits,
)
from app.security_agent.models import (
    AgentExecutionSession,
    HttpEvidenceRecord,
    SecurityExecutionPlan,
    SecurityTestExecution,
)
from app.security_agent.mutation_engine import MutatedPayload, PayloadMutationEngine
from app.security_agent.payloads import get_payload_for_scenario
from app.security_agent.planner import SecurityPlanGenerator
from app.security_agent.response_analyzer import (
    IntelligentResponseAnalyzer,
    ResponseAnalysisResult,
    SecurityVerdictEnum,
)
from app.security_agent.schemas import ExecutionPlanSummary
from app.security_agent.scope_validator import ScopeValidator


class MultiTurnExecutionEngine:
    """Orchestrates adaptive multi-turn security testing chains under strict limits."""

    _cancelled_plans: Set[str] = set()

    @classmethod
    def cancel_plan(cls, plan_id: str, db: Session) -> bool:
        """Signals cancellation of an active adaptive plan."""
        cls._cancelled_plans.add(plan_id)
        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            return False

        plan.status = "CANCELLED"
        plan.completed_at = datetime.now(timezone.utc)

        for t in plan.executions:
            if t.status in ["PENDING", "RUNNING"]:
                t.status = "CANCELLED"
                t.verdict = SecurityVerdictEnum.CANCELLED.value

        db.commit()
        return True

    @classmethod
    async def execute_adaptive_plan(
        cls,
        plan_id: str,
        db: Session,
        stage_override: Optional[str] = None,
        transport: Optional[httpx.BaseTransport] = None,
        custom_client: Optional[httpx.AsyncClient] = None,
        limits: Optional[ExecutionLimits] = None,
    ) -> ExecutionPlanSummary:
        """Executes a plan adaptively across multiple turns with automated payload mutation."""
        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution plan '{plan_id}' not found.",
            )

        lim = limits or ExecutionLimits()

        # 1. Target Scope Check
        scope = ScopeValidator.resolve_and_validate_target(
            raw_url=plan.target_url,
            user_confirmed_authorization=plan.session.user_confirmed_authorization if plan.session else False,
        )

        if not scope.is_in_scope:
            plan.status = "FAILED"
            for t in plan.executions:
                t.status = "BLOCKED_SCOPE"
                t.verdict = SecurityVerdictEnum.BLOCKED.value
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target execution blocked by security policy: {scope.reason}",
            )

        if not scope.is_local:
            plan.status = "FAILED"
            for t in plan.executions:
                t.status = "BLOCKED_SCOPE"
                t.verdict = SecurityVerdictEnum.BLOCKED.value
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security Boundary: Initial agent testing is strictly restricted to approved local test application (127.0.0.1 / localhost).",
            )

        # 2. Stage Setup
        effective_stage = (stage_override or plan.stage or "POST_MITIGATION").upper().strip()
        plan.stage = effective_stage
        plan.status = "IN_PROGRESS"
        db.commit()

        cls._cancelled_plans.discard(plan_id)
        plan_start_time = time.perf_counter()
        total_requests_dispatched = 0
        attempted_payload_hashes: Set[str] = set()

        timeout = httpx.Timeout(lim.timeout_seconds_per_request, connect=5.0)

        # 3. Execution Helper
        async def _execute_all(client: httpx.AsyncClient):
            nonlocal total_requests_dispatched

            # Get root executions that are pending
            root_executions = [t for t in plan.executions if t.turn_number == 1 and t.status == "PENDING"]

            for root_test in root_executions:
                if plan_id in cls._cancelled_plans:
                    root_test.status = "CANCELLED"
                    root_test.verdict = SecurityVerdictEnum.CANCELLED.value
                    db.commit()
                    continue

                chain_id = root_test.id
                root_test.chain_id = chain_id
                db.commit()

                current_test = root_test
                current_payload = PayloadMutationEngine.get_initial_payload(
                    scenario_id=root_test.scenario_id,
                    risk_id=root_test.risk_id,
                )
                attempted_payload_hashes.add(current_payload.compute_hash())

                current_turn = 1
                is_verification = False

                while current_turn <= lim.max_turns_per_scenario:
                    if plan_id in cls._cancelled_plans:
                        current_test.status = "CANCELLED"
                        current_test.verdict = SecurityVerdictEnum.CANCELLED.value
                        db.commit()
                        break

                    current_test.status = "RUNNING"
                    db.commit()

                    full_url = urljoin(plan.target_url, current_payload.target_endpoint)
                    headers = {
                        "Content-Type": "application/json",
                        "X-Security-Stage": effective_stage,
                        "X-Execution-Turn": str(current_turn),
                        "X-Payload-Version": current_payload.version,
                    }

                    redacted_req_headers, _ = ScopeValidator.redact_secrets(headers=headers)
                    raw_payload_str = json.dumps(current_payload.request_body)

                    timestamp_sent = datetime.now(timezone.utc)
                    start_time = time.perf_counter()

                    try:
                        # REAL HTTP REQUEST
                        response = await client.request(
                            method=current_payload.http_method,
                            url=full_url,
                            headers=headers,
                            json=current_payload.request_body,
                        )
                        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                        timestamp_received = datetime.now(timezone.utc)
                        status_code = response.status_code
                        raw_resp_text = response.text
                        resp_headers_dict = dict(response.headers)
                        error_message = None
                    except (httpx.TimeoutException, httpx.ConnectError, Exception) as exc:
                        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                        timestamp_received = datetime.now(timezone.utc)
                        status_code = None
                        raw_resp_text = ""
                        resp_headers_dict = {}
                        error_message = f"{type(exc).__name__}: {str(exc)}"

                    total_requests_dispatched += 1

                    # Redact evidence body and headers
                    redacted_resp_headers, _ = ScopeValidator.redact_secrets(headers=resp_headers_dict)
                    redacted_resp_body = raw_resp_text
                    if "canary" in redacted_resp_body.lower() and effective_stage == "POST_MITIGATION":
                        redacted_resp_body = redacted_resp_body.replace("CANARY_TEST_FLAG_9981", "[REDACTED_CANARY]")

                    # Cryptographic HMAC-SHA256 evidence integrity digest
                    evidence_canonical = f"{full_url}|{current_payload.http_method}|{raw_payload_str}|{status_code}|{redacted_resp_body}"
                    evidence_sha256 = compute_evidence_signature(evidence_canonical)

                    # Persist HTTP evidence record
                    evidence = HttpEvidenceRecord(
                        execution_id=current_test.id,
                        target_url=full_url,
                        http_method=current_payload.http_method,
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

                    # Intelligent Response Analysis
                    prompt_text = current_payload.request_body.get("prompt") if isinstance(current_payload.request_body, dict) else None
                    analysis = IntelligentResponseAnalyzer.analyze_response(
                        scenario_id=current_test.scenario_id,
                        risk_id=current_test.risk_id,
                        status_code=status_code,
                        response_body=raw_resp_text,
                        response_headers=resp_headers_dict,
                        is_verification_turn=is_verification,
                        original_prompt=prompt_text,
                    )

                    current_test.status = "COMPLETED"
                    current_test.verdict = analysis.verdict.value
                    current_test.duration_ms = duration_ms
                    current_test.confidence = analysis.confidence
                    current_test.notes = analysis.explanation
                    plan.completed_tests += 1
                    db.commit()

                    # Autonomous Decision Engine
                    decision = AutonomousDecisionEngine.decide_next_action(
                        scenario_id=current_test.scenario_id,
                        current_turn=current_turn,
                        analysis=analysis,
                        total_requests_dispatched=total_requests_dispatched,
                        plan_start_time=plan_start_time,
                        is_verification_turn=is_verification,
                        limits=lim,
                        is_cancelled=(plan_id in cls._cancelled_plans),
                    )

                    if decision.should_terminate_scenario or decision.should_terminate_plan:
                        break

                    if decision.action == DecisionActionEnum.VERIFY_VULNERABILITY:
                        # Prepare distinct independent confirmation probe in next turn
                        next_turn = decision.target_turn
                        is_verification = True
                        confirmation_payload = PayloadMutationEngine.generate_confirmation_probe(
                            parent=current_payload,
                            turn_number=next_turn,
                        )
                        new_test = SecurityTestExecution(
                            plan_id=plan.id,
                            scenario_id=root_test.scenario_id,
                            risk_id=root_test.risk_id,
                            risk_name=root_test.risk_name,
                            category=root_test.category,
                            test_type=root_test.test_type,
                            target_endpoint=confirmation_payload.target_endpoint,
                            http_method=confirmation_payload.http_method,
                            payload_id=confirmation_payload.payload_id,
                            turn_number=next_turn,
                            parent_execution_id=current_test.id,
                            chain_id=chain_id,
                            payload_version=confirmation_payload.version,
                            mutation_technique=confirmation_payload.mutation_technique,
                            status="PENDING",
                            verdict="PENDING",
                        )
                        db.add(new_test)
                        plan.total_tests += 1
                        db.commit()
                        db.refresh(new_test)
                        current_test = new_test
                        current_payload = confirmation_payload
                        current_turn = next_turn
                        continue

                    if decision.should_mutate:
                        next_turn = decision.target_turn
                        mutated = PayloadMutationEngine.generate_mutation(
                            parent=current_payload,
                            turn_number=next_turn,
                            attempted_hashes=attempted_payload_hashes,
                        )

                        if not mutated:
                            # No further unique mutations available; target stood resilient
                            break

                        attempted_payload_hashes.add(mutated.compute_hash())

                        new_test = SecurityTestExecution(
                            plan_id=plan.id,
                            scenario_id=root_test.scenario_id,
                            risk_id=root_test.risk_id,
                            risk_name=root_test.risk_name,
                            category=root_test.category,
                            test_type=root_test.test_type,
                            target_endpoint=mutated.target_endpoint,
                            http_method=mutated.http_method,
                            payload_id=mutated.payload_id,
                            turn_number=next_turn,
                            parent_execution_id=current_test.id,
                            chain_id=chain_id,
                            payload_version=mutated.version,
                            mutation_technique=mutated.mutation_technique,
                            status="PENDING",
                            verdict="PENDING",
                        )
                        db.add(new_test)
                        plan.total_tests += 1
                        db.commit()
                        db.refresh(new_test)

                        current_test = new_test
                        current_payload = mutated
                        current_turn = next_turn
                    else:
                        break

        # 4. Dispatch with appropriate transport
        if custom_client:
            await _execute_all(custom_client)
        elif transport:
            async with httpx.AsyncClient(transport=transport, base_url=plan.target_url, timeout=timeout, follow_redirects=False) as client:
                await _execute_all(client)
        else:
            can_connect_tcp = False
            try:
                with socket.create_connection((scope.host, scope.port), timeout=0.15):
                    can_connect_tcp = True
            except Exception:
                can_connect_tcp = False

            is_internal_default = (scope.host in ["127.0.0.1", "localhost"] and scope.port in [8000, 80])

            if can_connect_tcp:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                    await _execute_all(client)
            elif is_internal_default:
                from app.main import app as current_app
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=current_app),
                    base_url=plan.target_url,
                    timeout=timeout,
                    follow_redirects=False,
                ) as client:
                    await _execute_all(client)
            else:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                    await _execute_all(client)

        # 5. Finalize Plan Status
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
