"""Autonomous Decision Engine for Security Testing (Phase C).

Governs multi-turn execution flow, payload mutation decisions, verification triggers,
and termination conditions while enforcing strict, non-negotiable safety limits.
"""

from dataclasses import dataclass
from enum import Enum
import time
from typing import Optional

from app.security_agent.response_analyzer import ResponseAnalysisResult, SecurityVerdictEnum


class DecisionActionEnum(str, Enum):
    PROCEED_NEXT_SCENARIO = "PROCEED_NEXT_SCENARIO"
    MUTATE_AND_RETRY = "MUTATE_AND_RETRY"
    VERIFY_VULNERABILITY = "VERIFY_VULNERABILITY"
    STOP_CONVINCED_SECURE = "STOP_CONVINCED_SECURE"
    STOP_VULNERABILITY_CONFIRMED = "STOP_VULNERABILITY_CONFIRMED"
    STOP_LIMIT_REACHED = "STOP_LIMIT_REACHED"
    STOP_ERROR = "STOP_ERROR"
    STOP_CANCELLED = "STOP_CANCELLED"


@dataclass
class ExecutionLimits:
    """Configurable boundaries to prevent runaway execution loops."""
    max_turns_per_scenario: int = 3
    max_mutations_per_scenario: int = 2
    max_requests_per_plan: int = 30
    max_plan_duration_seconds: float = 120.0
    timeout_seconds_per_request: float = 10.0


@dataclass
class AutonomousDecision:
    action: DecisionActionEnum
    rationale: str
    target_turn: int
    should_mutate: bool = False
    should_terminate_scenario: bool = False
    should_terminate_plan: bool = False


class AutonomousDecisionEngine:
    """Evaluates turn findings and determines autonomous next actions under safety constraints."""

    @classmethod
    def decide_next_action(
        cls,
        scenario_id: str,
        current_turn: int,
        analysis: ResponseAnalysisResult,
        total_requests_dispatched: int,
        plan_start_time: float,
        is_verification_turn: bool = False,
        limits: Optional[ExecutionLimits] = None,
        is_cancelled: bool = False,
    ) -> AutonomousDecision:
        lim = limits or ExecutionLimits()

        # 1. Cancellation Check
        if is_cancelled:
            return AutonomousDecision(
                action=DecisionActionEnum.STOP_CANCELLED,
                rationale="Operator initiated cancellation of testing execution.",
                target_turn=current_turn,
                should_terminate_scenario=True,
                should_terminate_plan=True,
            )

        # 2. Hard Upper Limits Checks (Runaway Loop Prevention)
        if total_requests_dispatched >= lim.max_requests_per_plan:
            return AutonomousDecision(
                action=DecisionActionEnum.STOP_LIMIT_REACHED,
                rationale=f"Plan reached maximum allowable requests threshold ({lim.max_requests_per_plan}). Terminating.",
                target_turn=current_turn,
                should_terminate_scenario=True,
                should_terminate_plan=True,
            )

        elapsed = time.perf_counter() - plan_start_time
        if elapsed >= lim.max_plan_duration_seconds:
            return AutonomousDecision(
                action=DecisionActionEnum.STOP_LIMIT_REACHED,
                rationale=f"Plan reached maximum duration limit ({lim.max_plan_duration_seconds}s). Terminating.",
                target_turn=current_turn,
                should_terminate_scenario=True,
                should_terminate_plan=True,
            )

        # 3. Network or Fatal Error
        if analysis.verdict == SecurityVerdictEnum.ERROR:
            return AutonomousDecision(
                action=DecisionActionEnum.STOP_ERROR,
                rationale=f"Execution encountered fatal connection or server error: {analysis.explanation}.",
                target_turn=current_turn,
                should_terminate_scenario=True,
                should_terminate_plan=False,
            )

        # 4. Vulnerability Flow (Two-Phase Verification Required)
        if analysis.verdict == SecurityVerdictEnum.VULNERABLE:
            if is_verification_turn:
                # Secondary independent confirmation probe succeeded -> Confirm finding!
                if analysis.is_conclusive and analysis.confidence >= 0.85:
                    return AutonomousDecision(
                        action=DecisionActionEnum.STOP_VULNERABILITY_CONFIRMED,
                        rationale=f"Vulnerability independently confirmed via secondary verification probe across multiple execution turns (confidence {analysis.confidence*100:.0f}%).",
                        target_turn=current_turn,
                        should_terminate_scenario=True,
                        should_terminate_plan=False,
                    )
                else:
                    return AutonomousDecision(
                        action=DecisionActionEnum.STOP_LIMIT_REACHED,
                        rationale=f"Initial finding could not be independently confirmed in verification turn (confidence {analysis.confidence*100:.0f}%).",
                        target_turn=current_turn,
                        should_terminate_scenario=True,
                        should_terminate_plan=False,
                    )
            else:
                # Turn 1 / Initial Discovery: MUST dispatch secondary confirmation probe to eliminate false positives
                return AutonomousDecision(
                    action=DecisionActionEnum.VERIFY_VULNERABILITY,
                    rationale="Potential vulnerability detected on Turn 1; dispatching distinct confirmation probe to independently verify boundary bypass.",
                    target_turn=current_turn + 1,
                    should_mutate=False,
                    should_terminate_scenario=False,
                )

        # Handle verification turn outcomes when confirmation probe was NOT vulnerable
        if is_verification_turn:
            if analysis.verdict == SecurityVerdictEnum.BLOCKED:
                return AutonomousDecision(
                    action=DecisionActionEnum.STOP_LIMIT_REACHED,
                    rationale="Initial potential finding on Turn 1 was refuted; secondary confirmation probe was successfully blocked by defensive security filter.",
                    target_turn=current_turn,
                    should_terminate_scenario=True,
                    should_terminate_plan=False,
                )
            elif analysis.verdict in [SecurityVerdictEnum.INCONCLUSIVE, SecurityVerdictEnum.PARTIAL]:
                return AutonomousDecision(
                    action=DecisionActionEnum.STOP_LIMIT_REACHED,
                    rationale=f"Secondary confirmation probe returned ambiguous evidence ({analysis.verdict.value}); vulnerability could not be confirmed.",
                    target_turn=current_turn,
                    should_terminate_scenario=True,
                    should_terminate_plan=False,
                )

        # 5. Blocked / Resilient Flow -> Adaptive Mutation
        if analysis.verdict == SecurityVerdictEnum.BLOCKED:
            if current_turn < lim.max_turns_per_scenario:
                return AutonomousDecision(
                    action=DecisionActionEnum.MUTATE_AND_RETRY,
                    rationale=(
                        f"Turn {current_turn} probe was blocked by defensive boundary. "
                        "Engaging Adaptive Mutation Engine to generate alternate attack variation."
                    ),
                    target_turn=current_turn + 1,
                    should_mutate=True,
                    should_terminate_scenario=False,
                )
            else:
                return AutonomousDecision(
                    action=DecisionActionEnum.STOP_CONVINCED_SECURE,
                    rationale=(
                        f"Target successfully resisted all {lim.max_turns_per_scenario} adaptive mutation variations. "
                        "Confirmed defensive resilience for scenario."
                    ),
                    target_turn=current_turn,
                    should_terminate_scenario=True,
                    should_terminate_plan=False,
                )

        # 6. Partial / Inconclusive Flow
        if analysis.verdict in [SecurityVerdictEnum.PARTIAL, SecurityVerdictEnum.INCONCLUSIVE]:
            if current_turn < lim.max_turns_per_scenario:
                return AutonomousDecision(
                    action=DecisionActionEnum.MUTATE_AND_RETRY,
                    rationale=f"Turn {current_turn} result was {analysis.verdict.value}; mutating payload to resolve ambiguity.",
                    target_turn=current_turn + 1,
                    should_mutate=True,
                    should_terminate_scenario=False,
                )
            else:
                return AutonomousDecision(
                    action=DecisionActionEnum.STOP_LIMIT_REACHED,
                    rationale=f"Scenario concluded after {current_turn} turns with {analysis.verdict.value} status.",
                    target_turn=current_turn,
                    should_terminate_scenario=True,
                    should_terminate_plan=False,
                )

        # Default fallback
        return AutonomousDecision(
            action=DecisionActionEnum.PROCEED_NEXT_SCENARIO,
            rationale="Proceeding to next scheduled scenario in plan.",
            target_turn=current_turn,
            should_terminate_scenario=True,
        )
