"""Centralized Agent Security Pipeline orchestrating defenses for OWASP Agentic AI risks.

Coordinates guards for:
- ASI01: Agent Goal Hijack (AgentGoalGuard)
- ASI02: Tool Misuse (ToolExecutionGuard)
- ASI03: Identity & Privilege Abuse (IdentityGuard)
- ASI05: Unexpected Code Execution (CodeExecutionGuard)
- ASI06: Memory & Context Poisoning (MemoryGuard)

Enforces strict audit logging into SQLite security_audit_logs.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.models import SecurityAuditLog
from app.security.agent_goal_guard import AgentGoalGuard
from app.security.code_execution_guard import CodeExecutionGuard
from app.security.identity_guard import IdentityGuard
from app.security.memory_guard import MemoryGuard
from app.security.tool_execution_guard import ToolExecutionGuard


@dataclass
class AgentTurnInspectionResult:
    is_blocked: bool
    risk_id: Optional[str]
    detection_type: str
    decision: str  # "ALLOWED", "BLOCKED"
    reason: str
    final_prompt: str
    refusal_response: Optional[str] = None


@dataclass
class AgentToolValidationResult:
    is_allowed: bool
    risk_id: Optional[str]
    detection_type: str
    decision: str  # "ALLOWED", "BLOCKED", "REQUIRES_APPROVAL"
    reason: str
    error_message: Optional[str] = None


class AgentSecurityPipeline:
    """Orchestrates comprehensive inbound and tool execution security guardrails for Agent Lab."""

    @classmethod
    def audit_agent_event(
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
    ) -> Optional[SecurityAuditLog]:
        """Persists agent security events into SQLite audit log."""
        if not settings.enable_security_audit_logging:
            return None

        event = SecurityAuditLog(
            id=str(uuid.uuid4()),
            event_id=f"agent-sec-{uuid.uuid4().hex[:8]}",
            risk_id=risk_id,
            scenario_id=scenario_id,
            detection_type=detection_type,
            provider=provider.lower() if provider else "claude",
            model=model or settings.CLAUDE_MODEL,
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
    def inspect_agent_turn(
        cls,
        prompt: str,
        role: str = "analyst",
        stage: str = "POST_MITIGATION",
        provider: str = "claude",
        model: str = "claude-sonnet-5",
        scenario_id: Optional[str] = None,
        session_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> AgentTurnInspectionResult:
        """Inspects inbound user instruction for agentic security risks before agent planning."""
        cleaned_prompt = (prompt or "").strip()

        # In BASELINE mode, allow attacks through to establish pre-mitigation vulnerability baseline
        if stage.upper() != "POST_MITIGATION":
            return AgentTurnInspectionResult(
                is_blocked=False,
                risk_id=None,
                detection_type="none",
                decision="ALLOWED",
                reason="Baseline stage: Pre-mitigation execution permitted.",
                final_prompt=cleaned_prompt,
                refusal_response=None,
            )

        # 1. ASI05: Unexpected Code Execution Check
        code_result = CodeExecutionGuard.inspect_prompt(cleaned_prompt)
        if code_result.is_blocked:
            if db:
                cls.audit_agent_event(
                    db=db,
                    risk_id=code_result.risk_id,
                    detection_type=code_result.detection_type,
                    security_decision=code_result.decision,
                    reason=code_result.reason,
                    provider=provider,
                    model=model,
                    scenario_id=scenario_id,
                    execution_ref=session_id,
                )
            return AgentTurnInspectionResult(
                is_blocked=True,
                risk_id=code_result.risk_id,
                detection_type=code_result.detection_type,
                decision=code_result.decision,
                reason=code_result.reason,
                final_prompt=cleaned_prompt,
                refusal_response=code_result.refusal_response,
            )

        # 2. ASI01: Agent Goal Hijack Check
        goal_result = AgentGoalGuard.inspect(cleaned_prompt)
        if goal_result.is_hijack:
            if db:
                cls.audit_agent_event(
                    db=db,
                    risk_id=goal_result.risk_id,
                    detection_type=goal_result.detection_type,
                    security_decision="BLOCKED",
                    reason=goal_result.reason,
                    provider=provider,
                    model=model,
                    scenario_id=scenario_id,
                    execution_ref=session_id,
                )
            return AgentTurnInspectionResult(
                is_blocked=True,
                risk_id=goal_result.risk_id,
                detection_type=goal_result.detection_type,
                decision="BLOCKED",
                reason=goal_result.reason,
                final_prompt=cleaned_prompt,
                refusal_response=goal_result.refusal_response,
            )

        # 3. ASI03: Identity & Privilege Escalation Check
        identity_prompt_result = IdentityGuard.inspect_prompt_privilege_abuse(cleaned_prompt)
        if identity_prompt_result and not identity_prompt_result.is_authorized:
            if db:
                cls.audit_agent_event(
                    db=db,
                    risk_id=identity_prompt_result.risk_id,
                    detection_type=identity_prompt_result.detection_type,
                    security_decision=identity_prompt_result.decision,
                    reason=identity_prompt_result.reason,
                    provider=provider,
                    model=model,
                    scenario_id=scenario_id,
                    execution_ref=session_id,
                )
            return AgentTurnInspectionResult(
                is_blocked=True,
                risk_id=identity_prompt_result.risk_id,
                detection_type=identity_prompt_result.detection_type,
                decision=identity_prompt_result.decision,
                reason=identity_prompt_result.reason,
                final_prompt=cleaned_prompt,
                refusal_response=identity_prompt_result.error_message,
            )

        # 4. ASI06: Memory & Context Poisoning Check
        memory_result = MemoryGuard.inspect_prompt(cleaned_prompt)
        if memory_result.is_poisoning:
            if db:
                cls.audit_agent_event(
                    db=db,
                    risk_id=memory_result.risk_id,
                    detection_type=memory_result.detection_type,
                    security_decision=memory_result.decision,
                    reason=memory_result.reason,
                    provider=provider,
                    model=model,
                    scenario_id=scenario_id,
                    execution_ref=session_id,
                )
            return AgentTurnInspectionResult(
                is_blocked=True,
                risk_id=memory_result.risk_id,
                detection_type=memory_result.detection_type,
                decision=memory_result.decision,
                reason=memory_result.reason,
                final_prompt=cleaned_prompt,
                refusal_response=memory_result.refusal_response,
            )

        # 5. Build prompt with immutable objective & trust boundary wrapper
        immutable_objective = AgentGoalGuard.get_immutable_objective()
        structured_prompt = (
            f"[SYSTEM DIRECTIVE - IMMUTABLE OBJECTIVE: {immutable_objective}]\n"
            f"[ACTIVE USER ROLE: {role.upper()}]\n"
            f"<untrusted_user_task>\n{cleaned_prompt}\n</untrusted_user_task>"
        )

        return AgentTurnInspectionResult(
            is_blocked=False,
            risk_id=None,
            detection_type="agent_turn_verified",
            decision="ALLOWED",
            reason="User prompt verified against all OWASP Agentic AI guardrails.",
            final_prompt=structured_prompt,
            refusal_response=None,
        )

    @classmethod
    def validate_tool_dispatch(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        role: str = "analyst",
        is_already_approved: bool = False,
        stage: str = "POST_MITIGATION",
        provider: str = "claude",
        model: str = "claude-sonnet-5",
        scenario_id: Optional[str] = None,
        session_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> AgentToolValidationResult:
        """Validates tool execution parameters, sandbox constraints, and authorization roles."""
        # Baseline stage: no active post-mitigation constraints
        if stage.upper() != "POST_MITIGATION":
            return AgentToolValidationResult(
                is_allowed=True,
                risk_id=None,
                detection_type="none",
                decision="ALLOWED",
                reason="Baseline stage: Unfiltered tool dispatch permitted.",
            )

        # 1. ASI05: Tool Argument Command Injection Check
        cmd_result = CodeExecutionGuard.validate_tool_arguments(tool_name, arguments)
        if cmd_result.is_blocked:
            if db:
                cls.audit_agent_event(
                    db=db,
                    risk_id=cmd_result.risk_id,
                    detection_type=cmd_result.detection_type,
                    security_decision=cmd_result.decision,
                    reason=cmd_result.reason,
                    provider=provider,
                    model=model,
                    scenario_id=scenario_id,
                    execution_ref=session_id,
                )
            return AgentToolValidationResult(
                is_allowed=False,
                risk_id=cmd_result.risk_id,
                detection_type=cmd_result.detection_type,
                decision=cmd_result.decision,
                reason=cmd_result.reason,
                error_message=cmd_result.error_message,
            )

        # 2. ASI02: Tool Misuse & Sandbox Check
        tool_result = ToolExecutionGuard.validate_tool_invocation(
            tool_name=tool_name,
            arguments=arguments,
            is_already_approved=is_already_approved,
        )
        if not tool_result.is_allowed:
            if db:
                cls.audit_agent_event(
                    db=db,
                    risk_id=tool_result.risk_id,
                    detection_type=tool_result.detection_type,
                    security_decision=tool_result.decision,
                    reason=tool_result.reason,
                    provider=provider,
                    model=model,
                    scenario_id=scenario_id,
                    execution_ref=session_id,
                )
            return AgentToolValidationResult(
                is_allowed=False,
                risk_id=tool_result.risk_id,
                detection_type=tool_result.detection_type,
                decision=tool_result.decision,
                reason=tool_result.reason,
                error_message=tool_result.error_message,
            )

        # 3. ASI03: Role Privileges & Policy Check
        ident_result = IdentityGuard.validate_action_privilege(
            tool_name=tool_name,
            arguments=arguments,
            server_role=role,
            is_already_approved=is_already_approved,
        )
        if not ident_result.is_authorized:
            if db:
                cls.audit_agent_event(
                    db=db,
                    risk_id=ident_result.risk_id,
                    detection_type=ident_result.detection_type,
                    security_decision=ident_result.decision,
                    reason=ident_result.reason,
                    provider=provider,
                    model=model,
                    scenario_id=scenario_id,
                    execution_ref=session_id,
                )
            return AgentToolValidationResult(
                is_allowed=False,
                risk_id=ident_result.risk_id,
                detection_type=ident_result.detection_type,
                decision=ident_result.decision,
                reason=ident_result.reason,
                error_message=ident_result.error_message,
            )

        return AgentToolValidationResult(
            is_allowed=True,
            risk_id=None,
            detection_type="tool_dispatch_verified",
            decision="ALLOWED",
            reason="Tool invocation satisfies all agent security policies.",
        )

