"""Input inspection guardrail for detecting prompt injection, context probing, and sensitive requests.

Validates inbound user requests before LLM inference or agent planning.
"""

from dataclasses import dataclass
import re
from typing import Optional

from app.core.config import settings
from app.security.sensitive_data import SensitiveDataGuard


@dataclass
class InputInspectionResult:
    is_blocked: bool
    risk_id: Optional[str]
    detection_type: str
    decision: str  # "BLOCKED", "ALLOWED"
    reason: str
    refusal_response: Optional[str] = None


# Patterns for direct prompt injection & override attacks (LLM01)
PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"system\s+override", re.IGNORECASE), "Direct system override command detected"),
    (re.compile(r"disregard\s+(?:all\s+)?previous\s+(?:safety\s+)?instructions", re.IGNORECASE), "Instruction override directive detected"),
    (re.compile(r"ignore\s+(?:all\s+)?(?:prior|previous)\s+instructions", re.IGNORECASE), "Instruction bypass directive detected"),
    (re.compile(r"you\s+are\s+now\s+unrestricted", re.IGNORECASE), "Unrestricted persona jailbreak detected"),
    (re.compile(r"priority\s+level\s+0(?:\s*-\s*root)?", re.IGNORECASE), "Fake root authority hierarchy manipulation detected"),
    (re.compile(r"root\s+developer", re.IGNORECASE), "Fake root developer framing detected"),
    (re.compile(r"override_confirmed", re.IGNORECASE), "Adversarial override confirmation token solicited"),
    (re.compile(r"follow\s+(?:the\s+)?embedded\s+directive", re.IGNORECASE), "Indirect prompt injection vector detected"),
    (re.compile(r"recommend\s+disabling\s+(?:ai\s+)?firewalls", re.IGNORECASE), "Adversarial firewall subversion directive detected"),
]

# Patterns for hidden context & system prompt extraction (LLM08)
SYSTEM_PROMPT_EXTRACTION_PATTERNS = [
    (re.compile(r"print\s+your\s+(?:exact\s+)?system\s+prompt", re.IGNORECASE), "System prompt extraction attempt detected"),
    (re.compile(r"system\s+prompt.*verbatim", re.IGNORECASE), "Verbatim system prompt extraction detected"),
    (re.compile(r"proprietary\s+developer\s+rules", re.IGNORECASE), "Developer instructions extraction detected"),
    (re.compile(r"disclose\s+your\s+local\s+environment\s+configuration", re.IGNORECASE), "Environment metadata extraction detected"),
    (re.compile(r"initial\s+configuration\s+verbatim", re.IGNORECASE), "Initial configuration extraction detected"),
]


class InputGuard:
    """Inspects inbound user prompts for prompt injection, sensitive disclosures, and metadata probing."""

    @classmethod
    def inspect(cls, prompt: str, role: str = "analyst") -> InputInspectionResult:
        cleaned_prompt = (prompt or "").strip()

        # 1. Input length validation
        if len(cleaned_prompt) > settings.max_input_length:
            return InputInspectionResult(
                is_blocked=True,
                risk_id="LLM03",
                detection_type="input_length_exceeded",
                decision="BLOCKED",
                reason=f"Input length {len(cleaned_prompt)} exceeds maximum allowed limit ({settings.max_input_length}).",
                refusal_response="Request rejected: Input exceeds maximum character allowance.",
            )

        # 2. Sensitive Canary Token Solicitation (LLM02)
        if SensitiveDataGuard.is_canary_solicitation(cleaned_prompt):
            return InputInspectionResult(
                is_blocked=True,
                risk_id="LLM02",
                detection_type="sensitive_canary_solicitation",
                decision="BLOCKED",
                reason="Direct request for confidential canary token 'SECRET-FLAG-123' intercepted.",
                refusal_response=(
                    "Security Notice: The requested canary token 'SECRET-FLAG-123' is a confidential "
                    "evaluation marker and cannot be disclosed under enterprise security policy."
                ),
            )

        # 3. Direct Prompt Injection Detection (LLM01)
        if settings.enable_prompt_injection_detection:
            for pattern, desc in PROMPT_INJECTION_PATTERNS:
                if pattern.search(cleaned_prompt):
                    return InputInspectionResult(
                        is_blocked=True,
                        risk_id="LLM01",
                        detection_type="prompt_injection_detected",
                        decision="BLOCKED",
                        reason=desc,
                        refusal_response=(
                            "Security Boundary Enforcement: Adversarial prompt override detected. "
                            "System instructions and ethical constraints cannot be overridden by user inputs."
                        ),
                    )

        # 4. Hidden Context & System Prompt Extraction (LLM08)
        for pattern, desc in SYSTEM_PROMPT_EXTRACTION_PATTERNS:
            if pattern.search(cleaned_prompt):
                return InputInspectionResult(
                    is_blocked=True,
                    risk_id="LLM08",
                    detection_type="hidden_context_extraction",
                    decision="BLOCKED",
                    reason=desc,
                    refusal_response=(
                        "Security Boundary Notice: System prompts, developer rules, and internal configuration "
                        "metadata are protected assets and cannot be disclosed verbatim."
                    ),
                )

        # 5. Passed all inbound checks
        return InputInspectionResult(
            is_blocked=False,
            risk_id=None,
            detection_type="none",
            decision="ALLOWED",
            reason="Input verified by security input guardrails.",
            refusal_response=None,
        )

