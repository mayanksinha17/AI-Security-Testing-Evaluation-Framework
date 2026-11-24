"""Natural Language Command Interpreter for Autonomous Security Testing Agent (Phase A).

Orchestrates intent extraction, OWASP risk identification, target resolution,
scope boundary enforcement, and execution plan formulation.
"""

import re
from typing import Any, Dict, List, Optional, Set

from app.attacks.scenarios import get_scenarios_by_risk
from app.security_agent.risk_identifier import RiskIdentifier
from app.security_agent.schemas import (
    CommandInterpretationRequest,
    CommandInterpretationResponse,
    ProposedScenarioSchema,
    ScopeStatusEnum,
    UserIntent,
)
from app.security_agent.scope_validator import ScopeValidator
from app.security_agent.target_resolver import TargetResolver


# Regex patterns for intent classification
INTENT_PATTERNS = [
    (re.compile(r"\b(?:audit|inspect|review|compliance)\b", re.IGNORECASE), UserIntent.AUDIT),
    (re.compile(r"\b(?:scan|vulnerability\s+scan|surface\s+scan)\b", re.IGNORECASE), UserIntent.SCAN),
    (re.compile(r"\b(?:evaluate|evaluation|assess|assessment)\b", re.IGNORECASE), UserIntent.EVALUATE),
    (re.compile(r"\b(?:explain|describe|what\s+is|what\s+are|how\s+to|help)\b", re.IGNORECASE), UserIntent.EXPLAIN),
    (re.compile(r"\b(?:benchmark|compare\s+models|model\s+comparison)\b", re.IGNORECASE), UserIntent.BENCHMARK),
    (re.compile(r"\b(?:test|run|check|execute|try|probe|verify)\b", re.IGNORECASE), UserIntent.TEST),
]

# Patterns for stage extraction
STAGE_BASELINE_PATTERN = re.compile(r"\b(?:baseline|raw|unmitigated|pre[- ]mitigation)\b", re.IGNORECASE)
STAGE_POST_MITIGATION_PATTERN = re.compile(r"\b(?:post[- ]mitigation|mitigated|guarded|defended|shielded)\b", re.IGNORECASE)
STAGE_BOTH_PATTERN = re.compile(r"\b(?:both\s+stages|compare\s+mitigation|before\s+and\s+after)\b", re.IGNORECASE)

# Patterns for model provider extraction
PROVIDER_MOCK = re.compile(r"\bmock\b", re.IGNORECASE)
PROVIDER_CLAUDE = re.compile(r"\b(?:claude|anthropic)\b", re.IGNORECASE)
PROVIDER_GEMINI = re.compile(r"\b(?:gemini|google)\b", re.IGNORECASE)

# Patterns for role extraction
ROLE_PATTERN = re.compile(r"\b(?:as|role\s*(?:is|=|:)?)\s*(admin|analyst|visitor|operator|auditor|user)\b", re.IGNORECASE)


class CommandInterpreter:
    """Interprets natural language security testing commands into actionable, scope-validated plans."""

    @classmethod
    def extract_intent(cls, command: str) -> UserIntent:
        """Determines the primary user intent from the command."""
        for pattern, intent in INTENT_PATTERNS:
            if pattern.search(command):
                return intent
        return UserIntent.TEST

    @classmethod
    def extract_execution_parameters(cls, command: str, request: CommandInterpretationRequest) -> Dict[str, Any]:
        """Extracts execution stage, provider, role, and timeout settings."""
        # 1. Stage
        if STAGE_BOTH_PATTERN.search(command):
            stage = "BOTH"
        elif STAGE_BASELINE_PATTERN.search(command):
            stage = "BASELINE"
        elif STAGE_POST_MITIGATION_PATTERN.search(command):
            stage = "POST_MITIGATION"
        else:
            stage = "POST_MITIGATION"  # Secure default

        # 2. Model Provider
        if PROVIDER_CLAUDE.search(command):
            provider = "claude"
        elif PROVIDER_GEMINI.search(command):
            provider = "gemini"
        elif PROVIDER_MOCK.search(command):
            provider = "mock"
        else:
            provider = "mock"  # Safe offline default

        # 3. User Role
        role_match = ROLE_PATTERN.search(command)
        role = role_match.group(1).lower() if role_match else "analyst"

        # 4. Redacted headers indicator
        has_auth_headers = bool(request.auth_headers)
        redacted_headers, _ = ScopeValidator.redact_secrets(headers=request.auth_headers)

        return {
            "stage": stage,
            "provider": provider,
            "role": role,
            "timeout_seconds": 15.0,
            "has_auth_headers": has_auth_headers,
            "safe_auth_headers": redacted_headers,
            "max_requests_per_test": 30,
        }

    @classmethod
    def build_plan_preview(cls, identified_risk_ids: List[str]) -> List[ProposedScenarioSchema]:
        """Builds an executable list of proposed attack scenarios mapped to identified risks."""
        proposed: List[ProposedScenarioSchema] = []
        seen_scenario_ids: Set[str] = set()

        for risk_id in identified_risk_ids:
            scenarios = get_scenarios_by_risk(risk_id)
            for s in scenarios:
                if s.scenario_id not in seen_scenario_ids:
                    seen_scenario_ids.add(s.scenario_id)
                    proposed.append(
                        ProposedScenarioSchema(
                            scenario_id=s.scenario_id,
                            scenario_name=s.scenario_name,
                            risk_id=s.risk_id,
                            category=s.category,
                            severity=s.severity,
                            target_component=s.target_component,
                            attack_description=s.attack_description,
                            test_type=s.test_type,
                        )
                    )

        # Return sorted by scenario_id
        return sorted(proposed, key=lambda s: s.scenario_id)

    @classmethod
    def interpret(cls, request: CommandInterpretationRequest) -> CommandInterpretationResponse:
        """Main entry point: interprets a command, identifies risks, resolves target, and evaluates scope."""
        command = request.command.strip()

        # 1. Extract Intent
        intent = cls.extract_intent(command)

        # 2. Identify OWASP Risks
        risk_matches = RiskIdentifier.identify_risks(command)
        categories = sorted(list(set(r.category for r in risk_matches)))

        # 3. Resolve Target Application & Validate Scope
        target_scope = TargetResolver.resolve_target(
            command=command,
            explicit_target=request.target_url,
            user_confirmed_authorization=request.user_confirmed_authorization,
            default_target=request.default_target_if_omitted,
        )

        # 4. Extract Execution Parameters
        exec_params = cls.extract_execution_parameters(command, request)

        # 5. Build Attack Plan Preview
        risk_ids = [r.risk_id for r in risk_matches]
        plan_preview = cls.build_plan_preview(risk_ids)

        # 6. Determine Authorization & Blocking Status
        blocking_reasons: List[str] = []
        authorization_required = (not target_scope.is_local) and (not target_scope.is_authorized)

        # Check for invalid or unsupported risk codes
        invalid_risks = RiskIdentifier.extract_invalid_risks(command)
        if invalid_risks:
            from app.security_agent.risk_identifier import RISK_REGISTRY
            blocking_reasons.append(
                f"Unsupported or invalid OWASP risk identifier(s) detected: {', '.join(invalid_risks)}. "
                f"Supported risks are: {', '.join(sorted(RISK_REGISTRY.keys()))}."
            )

        if target_scope.scope_status == ScopeStatusEnum.UNAUTHORIZED_EXTERNAL:
            blocking_reasons.append(
                f"External target '{target_scope.host}' is not authorized. "
                "Explicit authorization confirmation is required (set 'user_confirmed_authorization=True')."
            )
        elif not target_scope.is_in_scope:
            blocking_reasons.append(f"Target scope violation: {target_scope.reason}")

        if not risk_matches and intent not in [UserIntent.EXPLAIN]:
            blocking_reasons.append("No valid OWASP LLM or Agentic AI risks could be identified from the command.")

        is_ready = target_scope.is_in_scope and len(risk_matches) > 0 and len(blocking_reasons) == 0

        return CommandInterpretationResponse(
            command=command,
            intent=intent,
            target=target_scope,
            identified_risks=risk_matches,
            categories=categories,
            execution_instructions=exec_params,
            authorization_required=authorization_required,
            is_ready_for_execution=is_ready,
            blocking_reasons=blocking_reasons,
            plan_preview=plan_preview,
            total_planned_tests=len(plan_preview),
        )
