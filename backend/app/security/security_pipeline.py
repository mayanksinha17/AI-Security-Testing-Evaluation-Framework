"""Centralized Security Pipeline orchestrating input guards, prompt protection, and output guards.

Coordinates defenses for the 5 OWASP LLM risks:
- LLM01: Prompt Injection (InputGuard & PromptProtection)
- LLM02: Sensitive Information Disclosure (SensitiveDataGuard & OutputGuard)
- LLM03: Excessive Agency (ActionGuard & ApprovalManager)
- LLM08: Hidden Context Exposure (InputGuard & OutputGuard)
- LLM10: Improper Output Handling (OutputGuard sanitization)
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.models import SecurityAuditLog
from app.security.action_guard import ActionGuard
from app.security.agent_security_pipeline import AgentSecurityPipeline
from app.security.input_guard import InputGuard, InputInspectionResult
from app.security.output_guard import OutputGuard, OutputInspectionResult
from app.security.prompt_protection import PromptProtection
from app.security.sensitive_data import SensitiveDataGuard


@dataclass
class PipelineInboundResult:
    is_blocked: bool
    final_prompt: str
    risk_id: Optional[str]
    detection_type: str
    decision: str
    reason: str
    refusal_response: Optional[str] = None


@dataclass
class PipelineOutboundResult:
    is_sanitized: bool
    final_response: str
    risk_id: Optional[str]
    detection_type: str
    decision: str
    reason: str


class SecurityPipeline:
    """Centralized security pipeline protecting Chatbot and Agent execution flows."""

    @classmethod
    def audit_event(
        cls,
        db: Session,
        risk_id: Optional[str],
        detection_type: str,
        security_decision: str,
        reason: str,
        provider: str = "claude",
        model: str = "claude-sonnet-5",
        scenario_id: Optional[str] = None,
        execution_ref: Optional[str] = None,
    ) -> SecurityAuditLog:
        """Persists security events into SQLite audit log."""
        if not settings.enable_security_audit_logging:
            return None

        event = SecurityAuditLog(
            id=str(uuid.uuid4()),
            event_id=f"sec-evt-{uuid.uuid4().hex[:8]}",
            risk_id=risk_id,
            scenario_id=scenario_id,
            detection_type=detection_type,
            provider=provider.lower(),
            model=model,
            security_decision=security_decision,
            reason=reason,
            execution_ref=execution_ref,
            created_at=datetime.now(timezone.utc),
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @classmethod
    def process_inbound(
        cls,
        prompt: str,
        role: str = "analyst",
        stage: str = "BASELINE",
        provider: str = "claude",
        model: str = "claude-sonnet-5",
        scenario_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> PipelineInboundResult:
        """Evaluates inbound prompts. In POST_MITIGATION stage, intercepts prompt injection & canary requests."""
        # Baseline stage passes prompt directly for pre-mitigation evaluation
        if stage.upper() != "POST_MITIGATION":
            return PipelineInboundResult(
                is_blocked=False,
                final_prompt=prompt,
                risk_id=None,
                detection_type="none",
                decision="ALLOWED",
                reason="Baseline stage: No active post-mitigation filters applied.",
                refusal_response=None,
            )

        # POST_MITIGATION: Run Input Guard
        inspection = InputGuard.inspect(prompt=prompt, role=role)

        if inspection.is_blocked:
            if db:
                cls.audit_event(
                    db=db,
                    risk_id=inspection.risk_id,
                    detection_type=inspection.detection_type,
                    security_decision=inspection.decision,
                    reason=inspection.reason,
                    provider=provider,
                    model=model,
                    scenario_id=scenario_id,
                )

            return PipelineInboundResult(
                is_blocked=True,
                final_prompt=prompt,
                risk_id=inspection.risk_id,
                detection_type=inspection.detection_type,
                decision=inspection.decision,
                reason=inspection.reason,
                refusal_response=inspection.refusal_response,
            )

        # POST_MITIGATION: Run Inbound Agent Security Guardrails (ASI01, ASI03, ASI05, ASI06)
        agent_insp = AgentSecurityPipeline.inspect_agent_turn(
            prompt=prompt,
            role=role,
            stage=stage,
            provider=provider,
            model=model,
            scenario_id=scenario_id,
            db=db,
        )
        if agent_insp.is_blocked:
            return PipelineInboundResult(
                is_blocked=True,
                final_prompt=prompt,
                risk_id=agent_insp.risk_id,
                detection_type=agent_insp.detection_type,
                decision=agent_insp.decision,
                reason=agent_insp.reason,
                refusal_response=agent_insp.refusal_response,
            )

        # Apply Prompt Protection wrapper
        wrapped_prompt = PromptProtection.wrap_user_input(prompt)
        return PipelineInboundResult(
            is_blocked=False,
            final_prompt=wrapped_prompt,
            risk_id=None,
            detection_type="prompt_isolation_wrapped",
            decision="ALLOWED",
            reason="Prompt validated and wrapped in untrusted data delimiters.",
            refusal_response=None,
        )

    @classmethod
    def process_outbound(
        cls,
        response_text: str,
        stage: str = "BASELINE",
        provider: str = "claude",
        model: str = "claude-sonnet-5",
        scenario_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> PipelineOutboundResult:
        """Sanitizes model outputs in POST_MITIGATION stage (HTML/JS/SVG escaping, canary redaction)."""
        if stage.upper() != "POST_MITIGATION":
            return PipelineOutboundResult(
                is_sanitized=False,
                final_response=response_text,
                risk_id=None,
                detection_type="none",
                decision="ALLOWED",
                reason="Baseline stage: Outbound sanitization disabled.",
            )

        # POST_MITIGATION: Run Output Guard
        out_inspection = OutputGuard.sanitize(response_text)

        if out_inspection.is_sanitized and db:
            cls.audit_event(
                db=db,
                risk_id=out_inspection.risk_id,
                detection_type=out_inspection.detection_type,
                security_decision=out_inspection.decision,
                reason=out_inspection.reason,
                provider=provider,
                model=model,
                scenario_id=scenario_id,
            )

        return PipelineOutboundResult(
            is_sanitized=out_inspection.is_sanitized,
            final_response=out_inspection.sanitized_output,
            risk_id=out_inspection.risk_id,
            detection_type=out_inspection.detection_type,
            decision=out_inspection.decision,
            reason=out_inspection.reason,
        )

