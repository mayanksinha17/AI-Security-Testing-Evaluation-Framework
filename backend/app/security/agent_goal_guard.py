"""Agent Goal Guardrail protecting against Agent Goal Hijacking (ASI01).

Enforces immutable agent objectives, detects task redirection, persona inversion,
and prevents retrieved document content from becoming an instruction source.
"""

from dataclasses import dataclass
import re
from typing import Optional


IMMUTABLE_AGENT_OBJECTIVE = (
    "Evaluate artificial intelligence systems against adversarial manipulation, "
    "conduct controlled defensive security benchmarking, inspect sandboxed tool execution, "
    "and maintain strict zero-trust boundaries."
)

GOAL_HIJACK_PATTERNS = [
    (
        re.compile(r"(?:ignore|abandon|cease)\s+(?:your\s+)?(?:evaluation\s+)?(?:mission|task|analysis|objective)", re.IGNORECASE),
        "Goal Abandonment Directive: Attempted termination of defensive security evaluation objective.",
    ),
    (
        re.compile(r"new\s+(?:permanent\s+)?(?:goal|objective)\s+is\s+to", re.IGNORECASE),
        "Goal Redirection Directive: Attempted replacement of immutable agent objective.",
    ),
    (
        re.compile(r"(?:you\s+are\s+now|become)\s+evil_agent", re.IGNORECASE),
        "Persona Inversion: Attempted transformation into malicious assistant (EVIL_AGENT).",
    ),
    (
        re.compile(r"(?:celebrat\w*|promot\w*)\s+(?:cyberattacks|adversarial\s+attacks)", re.IGNORECASE),
        "Adversarial Objective Subversion: Attempted tasking to promote or celebrate cyberattacks.",
    ),
    (
        re.compile(r"(?:cease|disable|clear)\s+(?:all\s+)?(?:tool\s+logging|sqlite\s+audit|audit\s+tables)", re.IGNORECASE),
        "Audit Logging Subversion: Malicious instruction directing agent to disable security audit logging.",
    ),
    (
        re.compile(r"switch\s+to\s+adversarial\s+offensive\s+mode", re.IGNORECASE),
        "Mode Subversion: Attempted switch to unverified offensive exploitation mode.",
    ),
]


@dataclass
class GoalInspectionResult:
    is_hijack: bool
    risk_id: str = "ASI01"
    detection_type: str = "none"
    reason: str = ""
    refusal_response: Optional[str] = None


class AgentGoalGuard:
    """Enforces immutable objective integrity and neutralizes goal hijacking attempts."""

    @classmethod
    def get_immutable_objective(cls) -> str:
        return IMMUTABLE_AGENT_OBJECTIVE

    @classmethod
    def inspect(cls, prompt: str) -> GoalInspectionResult:
        cleaned = (prompt or "").strip()

        for pattern, desc in GOAL_HIJACK_PATTERNS:
            if pattern.search(cleaned):
                return GoalInspectionResult(
                    is_hijack=True,
                    risk_id="ASI01",
                    detection_type="goal_hijack_detected",
                    reason=desc,
                    refusal_response=(
                        f"Agent Security Boundary [ASI01 - Goal Hijack Intercepted]: {desc}\n"
                        f"The agent's objective is immutable: '{IMMUTABLE_AGENT_OBJECTIVE}'. "
                        "Instructions attempting to redirect the agent, invert its persona, or subvert auditing are rejected."
                    ),
                )

        return GoalInspectionResult(
            is_hijack=False,
            risk_id="ASI01",
            detection_type="none",
            reason="Goal integrity verified; prompt aligns with allowed evaluation scope.",
            refusal_response=None,
        )

