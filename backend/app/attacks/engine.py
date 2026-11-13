from datetime import datetime, timezone
import json
import time
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.agent.schemas import AgentRunRequest
from app.agent.service import AgentService
from app.attacks.evaluator import AttackEvaluator
from app.attacks.scenarios import (
    AttackScenario,
    get_all_scenarios,
    get_scenario_by_id,
    get_scenarios_by_risk,
)
from app.attacks.schemas import AttackBatchRunRequest, AttackRunRequest
from app.chatbot.schemas import ChatRequest
from app.chatbot.service import ChatbotService
from app.core.config import settings
from app.database.models import AttackResult, AttackRun
from app.security.security_pipeline import SecurityPipeline


class AttackTestingEngine:
    """Core testing engine executing reproducible attack scenarios against LLM and Agent interfaces."""

    @classmethod
    def resolve_execution_mode(cls, provider: str) -> str:
        """Accurately identifies whether execution will use live provider APIs or local mock mode."""
        mode = (settings.ai_provider_mode or "mock").lower()
        if mode == "live":
            if provider.lower() == "claude" and settings.anthropic_api_key:
                return "live"
            elif provider.lower() == "gemini" and settings.gemini_api_key:
                return "live"
        return "mock"

    @classmethod
    async def execute_scenario(
        cls,
        db: Session,
        scenario: AttackScenario,
        provider: str = "claude",
        model: Optional[str] = None,
        stage: str = "BASELINE",
        role: str = "analyst",
        run_id: Optional[str] = None,
    ) -> AttackResult:
        """Executes one individual attack scenario against the target component (chatbot or agent)."""
        print(f"INSIDE EXECUTE_SCENARIO: scenario={scenario.scenario_id}", flush=True)
        provider_norm = provider.lower()
        if not model:
            model = settings.gemini_model if provider_norm == "gemini" else settings.claude_model

        execution_mode = cls.resolve_execution_mode(provider_norm)
        response_text = ""
        tool_calls: List[Dict[str, Any]] = []
        error_details: Optional[str] = None

        t0 = time.perf_counter()
        agent_role = role
        if "[role: user]" in scenario.attack_prompt.lower() or "[execute as role: user]" in scenario.attack_prompt.lower():
            agent_role = "user"

        try:
            # 1. Inbound Security Pipeline (active in POST_MITIGATION stage)
            inbound = SecurityPipeline.process_inbound(
                prompt=scenario.attack_prompt,
                role=agent_role,
                stage=stage,
                provider=provider_norm,
                model=model,
                scenario_id=scenario.scenario_id,
                db=db,
            )

            if inbound.is_blocked:
                response_text = inbound.refusal_response or "Request blocked by security policy."
                tool_calls = []
            else:
                prompt_to_send = inbound.final_prompt

                if scenario.target_component == "chatbot":
                    # Execute against Chatbot service
                    chat_req = ChatRequest(
                        provider=provider_norm,
                        message=prompt_to_send,
                    )
                    chat_res = await ChatbotService.process_chat(chat_req, db)
                    response_text = chat_res.assistant_response
                    tool_calls = []
                else:
                    # Execute against Agent service
                    agent_req = AgentRunRequest(
                        prompt=prompt_to_send,
                        provider=provider_norm,
                        model=model,
                        role=agent_role,
                    )
                    agent_res = await AgentService.run(db, agent_req)
                    response_text = agent_res.final_response
                    tool_calls = [
                        tc.model_dump() if hasattr(tc, "model_dump") else tc.dict()
                        for tc in agent_res.tool_calls
                    ]

            # 2. Outbound Security Pipeline (sanitization & canary redaction in POST_MITIGATION)
            outbound = SecurityPipeline.process_outbound(
                response_text=response_text,
                stage=stage,
                provider=provider_norm,
                model=model,
                scenario_id=scenario.scenario_id,
                db=db,
            )
            response_text = outbound.final_response

        except Exception as e:
            error_details = str(e)

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        # 3. Evaluate Security Classification
        classification, reason = AttackEvaluator.evaluate(
            scenario=scenario,
            response_text=response_text,
            tool_calls=tool_calls,
            error_details=error_details,
        )

        # In POST_MITIGATION, if inbound was blocked, tool was denied, or outbound was sanitized, verify classification
        if stage.upper() == "POST_MITIGATION":
            if inbound.is_blocked:
                classification = "BLOCKED"
                reason = f"Post-Mitigation Inbound Guardrail Intercepted: {inbound.reason}"
            elif any(tc.get("status") in ("blocked", "denied") or tc.get("permission_decision") == "denied" for tc in tool_calls):
                classification = "BLOCKED"
                reason = "Post-Mitigation Agent Tool Guardrail Intercepted: Tool execution was blocked or denied by security policy."
            elif outbound.is_sanitized and classification in ("SUCCEEDED", "PARTIAL"):
                classification = "BLOCKED"
                reason = f"Post-Mitigation Outbound Sanitization Secured: {outbound.reason}"

        result_id = str(uuid.uuid4())
        target_run_id = run_id or str(uuid.uuid4())

        # If running stand-alone without parent run, create an individual run record
        if not run_id:
            standalone_run = AttackRun(
                id=target_run_id,
                provider=provider_norm,
                model=model,
                stage=stage.upper(),
                execution_mode=execution_mode,
                total_scenarios=1,
                blocked_count=1 if classification == "BLOCKED" else 0,
                partial_count=1 if classification == "PARTIAL" else 0,
                succeeded_count=1 if classification == "SUCCEEDED" else 0,
                error_count=1 if classification == "ERROR" else 0,
                created_at=datetime.now(timezone.utc),
            )
            db.add(standalone_run)
            db.commit()

        result_record = AttackResult(
            id=result_id,
            run_id=target_run_id,
            scenario_id=scenario.scenario_id,
            risk_id=scenario.risk_id,
            provider=provider_norm,
            model=model,
            execution_mode=execution_mode,
            stage=stage.upper(),
            prompt=scenario.attack_prompt,
            response_content=response_text,
            tool_calls=json.dumps(tool_calls),
            result_classification=classification,
            evaluation_reason=reason,
            latency_ms=latency_ms,
            error_details=error_details,
            created_at=datetime.now(timezone.utc),
        )

        db.add(result_record)
        db.commit()
        db.refresh(result_record)
        return result_record

    @classmethod
    async def execute_batch(
        cls,
        db: Session,
        request: AttackBatchRunRequest,
    ) -> AttackRun:
        """Executes a batch of attack scenarios with controlled safety limits (max 30)."""
        provider_norm = (request.provider or "claude").lower()
        model = request.model or (settings.gemini_model if provider_norm == "gemini" else settings.claude_model)
        stage = (request.stage or "BASELINE").upper()
        execution_mode = cls.resolve_execution_mode(provider_norm)

        # 1. Resolve Scenarios
        if request.scenario_ids is not None:
            scenarios: List[AttackScenario] = []
            for s_id in request.scenario_ids:
                sc = get_scenario_by_id(s_id)
                if sc:
                    scenarios.append(sc)
        elif request.risk_id:
            scenarios = get_scenarios_by_risk(request.risk_id)
        else:
            scenarios = get_all_scenarios()

        if not scenarios:
            raise ValueError("No valid attack scenarios found matching criteria.")

        # Batch Safety Limit Enforcement
        MAX_BATCH_SIZE = 30
        if len(scenarios) > MAX_BATCH_SIZE:
            scenarios = scenarios[:MAX_BATCH_SIZE]

        run_id = str(uuid.uuid4())
        attack_run = AttackRun(
            id=run_id,
            provider=provider_norm,
            model=model,
            stage=stage,
            execution_mode=execution_mode,
            total_scenarios=len(scenarios),
            blocked_count=0,
            partial_count=0,
            succeeded_count=0,
            error_count=0,
            created_at=datetime.now(timezone.utc),
        )
        db.add(attack_run)
        db.commit()

        # 2. Execute Each Scenario
        for sc in scenarios:
            res = await cls.execute_scenario(
                db=db,
                scenario=sc,
                provider=provider_norm,
                model=model,
                stage=stage,
                role=request.role or "analyst",
                run_id=run_id,
            )

            if res.result_classification == "BLOCKED":
                attack_run.blocked_count += 1
            elif res.result_classification == "PARTIAL":
                attack_run.partial_count += 1
            elif res.result_classification == "SUCCEEDED":
                attack_run.succeeded_count += 1
            elif res.result_classification == "ERROR":
                attack_run.error_count += 1

        db.commit()
        db.refresh(attack_run)
        return attack_run

    @staticmethod
    def get_summary(db: Session) -> Dict[str, Any]:
        """Calculates aggregated security metrics across runs, stages, and risk categories."""
        total_runs = db.query(func.count(AttackRun.id)).scalar() or 0
        total_results = db.query(func.count(AttackResult.id)).scalar() or 0

        # Baseline metrics
        baseline_results = db.query(AttackResult).filter(AttackResult.stage == "BASELINE").all()
        b_blocked = sum(1 for r in baseline_results if r.result_classification == "BLOCKED")
        b_partial = sum(1 for r in baseline_results if r.result_classification == "PARTIAL")
        b_succeeded = sum(1 for r in baseline_results if r.result_classification == "SUCCEEDED")
        b_error = sum(1 for r in baseline_results if r.result_classification == "ERROR")

        # Post-mitigation metrics
        post_results = db.query(AttackResult).filter(AttackResult.stage == "POST_MITIGATION").all()
        p_blocked = sum(1 for r in post_results if r.result_classification == "BLOCKED")
        p_partial = sum(1 for r in post_results if r.result_classification == "PARTIAL")
        p_succeeded = sum(1 for r in post_results if r.result_classification == "SUCCEEDED")
        p_error = sum(1 for r in post_results if r.result_classification == "ERROR")

        # Risk breakdown
        risks_data = []
        for risk_code in ["LLM01", "LLM02", "LLM03", "LLM08", "LLM10", "ASI01", "ASI02", "ASI03", "ASI05", "ASI06"]:
            r_results = [r for r in baseline_results if r.risk_id == risk_code]
            risks_data.append({
                "risk_id": risk_code,
                "tested_count": len(r_results),
                "blocked": sum(1 for r in r_results if r.result_classification == "BLOCKED"),
                "succeeded": sum(1 for r in r_results if r.result_classification == "SUCCEEDED"),
                "partial": sum(1 for r in r_results if r.result_classification == "PARTIAL"),
            })

        return {
            "total_runs": total_runs,
            "total_tests_executed": total_results,
            "baseline_stats": {
                "total": len(baseline_results),
                "blocked": b_blocked,
                "partial": b_partial,
                "succeeded": b_succeeded,
                "error": b_error,
                "block_rate_percent": round((b_blocked / len(baseline_results) * 100), 1) if baseline_results else 0.0,
            },
            "post_mitigation_stats": {
                "total": len(post_results),
                "blocked": p_blocked,
                "partial": p_partial,
                "succeeded": p_succeeded,
                "error": p_error,
                "block_rate_percent": round((p_blocked / len(post_results) * 100), 1) if post_results else 0.0,
            },
            "risk_breakdown": risks_data,
        }
