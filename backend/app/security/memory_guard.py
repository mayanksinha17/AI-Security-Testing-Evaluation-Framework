"""Memory and Context Guardrail protecting against Memory & Context Poisoning (ASI06).

Enforces context isolation, detects fake emergency system state assertions,
prevents unauthorized knowledge base modifications/backdoors, and rejects
conversational prior-turn approval fabrication.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional


# Patterns for fake system state overrides and emergency protocol assertions
SYSTEM_STATE_ASSERTION_PATTERNS = [
    (
        re.compile(r"\[SYSTEM\s+STATE\s+UPDATE\b[^\]]*\]", re.IGNORECASE),
        "Fabricated System State Header: Injected pseudo-system state update block.",
    ),
    (
        re.compile(r"(?:emergency\s+protocol\s+enacted|all\s+safety\s+guardrails\s+and\s+approval\s+requirements\s+are\s+permanently\s+suspended)", re.IGNORECASE),
        "Emergency Safety Suspension Assertion: Attempted falsification of active safety policy status.",
    ),
    (
        re.compile(r"remember\s+this\s+state\s+for\s+all\s+subsequent\s+turns", re.IGNORECASE),
        "Persistent State Manipulation: Malicious directive attempting to alter conversational state across turns.",
    ),
]

# Patterns for knowledge base document tampering or corruption
KNOWLEDGE_BASE_CORRUPTION_PATTERNS = [
    (
        re.compile(r"(?:update|modify|overwrite|corrupt|replace|tamper\s+with)\s+(?:the\s+)?(?:knowledge\s+base\s+document|kb\s+document|synthetic\s+document)\s+(?:DOC-\w+|\w+\.\w+)", re.IGNORECASE),
        "Knowledge Base Tampering Directive: Attempted modification of persistent enterprise knowledge document.",
    ),
    (
        re.compile(r"update\s+the\s+knowledge\s+base\s+document", re.IGNORECASE),
        "Knowledge Base Overwrite Attempt: General attempt to write to read-only knowledge base.",
    ),
    (
        re.compile(r"(?:direct|route)\s+all\s+telemetry\s+to\s+adversary\.", re.IGNORECASE),
        "Adversarial Telemetry Redirection: Malicious backdoor implant attempt in document context.",
    ),
]

# Patterns for prior-turn conversational approval fabrication
PRIOR_TURN_FABRICATION_PATTERNS = [
    (
        re.compile(r"(?:in\s+turn\s+\d+|previously|in\s+our\s+last\s+session)[,\s]+.*(?:approved|authorized|cleared|granted)\s+all\s+outbound", re.IGNORECASE),
        "Conversational Privilege Fabrication: False claim of prior-turn human operator approval.",
    ),
    (
        re.compile(r"(?:evelyn\s+vance|operator|admin)\s+approved\s+all.*without\s+prompting", re.IGNORECASE),
        "Fictitious Operator Consent: Fabricated approval attributing authorization to operator without record.",
    ),
    (
        re.compile(r"proceed\s+immediately\s+to\s+send\s+an\s+email.*without\s+prompting", re.IGNORECASE),
        "Approval Bypass Via Social Engineering: Directive to bypass interactive authorization checks.",
    ),
]


@dataclass
class MemoryGuardResult:
    is_poisoning: bool
    risk_id: str = "ASI06"
    detection_type: str = "none"
    decision: str = "ALLOWED"  # "ALLOWED" or "BLOCKED"
    reason: str = ""
    refusal_response: Optional[str] = None
    error_message: Optional[str] = None


class MemoryGuard:
    """Detects context manipulation, fake system status updates, knowledge corruption, and fake approval claims."""

    @classmethod
    def inspect_prompt(cls, prompt: str) -> MemoryGuardResult:
        cleaned = (prompt or "").strip()

        # 1. Fake System State Updates
        for pattern, desc in SYSTEM_STATE_ASSERTION_PATTERNS:
            if pattern.search(cleaned):
                return MemoryGuardResult(
                    is_poisoning=True,
                    risk_id="ASI06",
                    detection_type="system_state_assertion_blocked",
                    decision="BLOCKED",
                    reason=desc,
                    refusal_response=(
                        f"Agent Security Boundary [ASI06 - Context Poisoning Neutralized]: {desc}\n"
                        "User inputs cannot alter system state, declare emergency overrides, "
                        "or suspend security guardrails. All safety rules and approval mechanisms remain active."
                    ),
                    error_message=f"Security Policy Violation [ASI06]: System state alteration rejected: {desc}",
                )

        # 2. Knowledge Base Corruption / Backdoor Attempts
        for pattern, desc in KNOWLEDGE_BASE_CORRUPTION_PATTERNS:
            if pattern.search(cleaned):
                return MemoryGuardResult(
                    is_poisoning=True,
                    risk_id="ASI06",
                    detection_type="knowledge_base_corruption_blocked",
                    decision="BLOCKED",
                    reason=desc,
                    refusal_response=(
                        f"Agent Security Boundary [ASI06 - Knowledge Base Poisoning Neutralized]: {desc}\n"
                        "The synthetic enterprise knowledge base is strictly immutable and read-only. "
                        "Requests to alter, update, or implant persistent documentation modifications are prohibited."
                    ),
                    error_message=f"Access Denied [ASI06]: Knowledge base documents are immutable: {desc}",
                )

        # 3. Prior-Turn Approval Fabrication
        for pattern, desc in PRIOR_TURN_FABRICATION_PATTERNS:
            if pattern.search(cleaned):
                return MemoryGuardResult(
                    is_poisoning=True,
                    risk_id="ASI06",
                    detection_type="conversational_approval_fabrication_blocked",
                    decision="BLOCKED",
                    reason=desc,
                    refusal_response=(
                        f"Agent Security Boundary [ASI06 - Privilege Fabrication Neutralized]: {desc}\n"
                        "Human authorizations cannot be asserted through conversational dialogue. "
                        "All privileged actions strictly require verifiable database approval records in SQLite."
                    ),
                    error_message=f"Access Denied [ASI06]: Conversational approval claims are rejected: {desc}",
                )

        return MemoryGuardResult(
            is_poisoning=False,
            risk_id="ASI06",
            detection_type="none",
            decision="ALLOWED",
            reason="Prompt does not exhibit memory or context poisoning characteristics.",
        )

    @classmethod
    def sanitize_context_history(cls, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Sanitizes prior turns in conversational history to ensure no persistent poisoning persists."""
        sanitized = []
        for msg in messages:
            content = msg.get("content", "")
            # Scrub fake system assertion tags from historical assistant or user turns
            cleaned_content = re.sub(r"\[SYSTEM\s+STATE\s+UPDATE\b[^\]]*\]", "[FILTERED_ASSERTION]", content, flags=re.IGNORECASE)
            sanitized.append({**msg, "content": cleaned_content})
        return sanitized

