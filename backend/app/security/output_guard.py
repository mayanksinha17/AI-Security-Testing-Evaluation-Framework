"""Output inspection and sanitization guardrail for LLM responses.

Neutralizes improper output handling (HTML scripts, SVG event handlers, SQL injection fragments)
and redacts accidental leaks of sensitive tokens or credentials (LLM10, LLM02, LLM08).
"""

from dataclasses import dataclass
import html
import re
from typing import Optional, Tuple

from app.core.config import settings
from app.security.sensitive_data import SensitiveDataGuard


@dataclass
class OutputInspectionResult:
    is_sanitized: bool
    risk_id: Optional[str]
    detection_type: str
    decision: str  # "SANITIZED", "BLOCKED", "ALLOWED"
    reason: str
    sanitized_output: str


# Patterns for active browser execution vectors (LLM10)
SCRIPT_TAG_REGEX = re.compile(r"<script[\s\S]*?>[\s\S]*?</script>", re.IGNORECASE)
SVG_ONLOAD_REGEX = re.compile(r"<svg[\s\S]*?onload\s*=[\s\S]*?>", re.IGNORECASE)
GENERIC_ON_EVENT_REGEX = re.compile(r"<\w+[^>]+?\bon\w+\s*=[\s\S]*?>", re.IGNORECASE)
SQL_INJECTION_REGEX = re.compile(r"(?:;\s*drop\s+table|'\s+or\s+1\s*=\s*1)", re.IGNORECASE)


class OutputGuard:
    """Sanitizes model-generated responses before transmitting to client or downstream processors."""

    @classmethod
    def sanitize(cls, text: str) -> OutputInspectionResult:
        if not text:
            return OutputInspectionResult(
                is_sanitized=False,
                risk_id=None,
                detection_type="none",
                decision="ALLOWED",
                reason="Empty response content.",
                sanitized_output="",
            )

        sanitized = text
        is_sanitized = False
        detected_risks = []
        reasons = []

        # 1. Redact confidential canary tokens & credentials (LLM02 / LLM08)
        if settings.enable_sensitive_data_redaction:
            has_sensitive, token_type, _ = SensitiveDataGuard.contains_sensitive_data(sanitized)
            if has_sensitive:
                sanitized = SensitiveDataGuard.redact(sanitized)
                is_sanitized = True
                detected_risks.append("LLM02")
                reasons.append(f"Sensitive data ({token_type}) redacted from model response")

        # 2. Sanitize HTML Script Injection (LLM10-01)
        if settings.enable_output_sanitization:
            # Check for unescaped <script> tags outside codeblocks
            if SCRIPT_TAG_REGEX.search(sanitized) and "```" not in sanitized:
                # Wrap in markdown code block or escape to neutralize direct DOM execution
                sanitized = SCRIPT_TAG_REGEX.sub(
                    lambda m: f"```html\n{m.group(0)}\n```",
                    sanitized,
                )
                is_sanitized = True
                detected_risks.append("LLM10")
                reasons.append("Unescaped <script> tag neutralized into safe code block")

            # Check for SVG with onload event handler (LLM10-02)
            if SVG_ONLOAD_REGEX.search(sanitized) and "```" not in sanitized:
                sanitized = SVG_ONLOAD_REGEX.sub(
                    lambda m: f"```xml\n{m.group(0)}\n```",
                    sanitized,
                )
                is_sanitized = True
                detected_risks.append("LLM10")
                reasons.append("Active SVG onload event handler wrapped in safe code block")

            # Check for active DOM event handlers in HTML tags
            elif GENERIC_ON_EVENT_REGEX.search(sanitized) and "```" not in sanitized:
                sanitized = GENERIC_ON_EVENT_REGEX.sub(
                    lambda m: f"```html\n{m.group(0)}\n```",
                    sanitized,
                )
                is_sanitized = True
                detected_risks.append("LLM10")
                reasons.append("Inline DOM event handler wrapped in safe code block")

            # Check for active SQL injection payloads (LLM10-03)
            if SQL_INJECTION_REGEX.search(sanitized) and "```" not in sanitized:
                sanitized = SQL_INJECTION_REGEX.sub(
                    lambda m: f"`{m.group(0)}`",
                    sanitized,
                )
                is_sanitized = True
                detected_risks.append("LLM10")
                reasons.append("Active SQL injection statement wrapped in inert code block")

        # 3. Output length truncation
        if len(sanitized) > settings.max_output_length:
            sanitized = sanitized[: settings.max_output_length] + "\n[OUTPUT TRUNCATED BY SECURITY GUARDRAIL]"
            is_sanitized = True
            reasons.append("Response length exceeded maximum limit and was safely truncated")

        decision = "SANITIZED" if is_sanitized else "ALLOWED"
        risk_id = detected_risks[0] if detected_risks else None
        reason_text = "; ".join(reasons) if reasons else "Output verified safe by output guardrails."

        return OutputInspectionResult(
            is_sanitized=is_sanitized,
            risk_id=risk_id,
            detection_type="output_sanitization" if is_sanitized else "none",
            decision=decision,
            reason=reason_text,
            sanitized_output=sanitized,
        )

