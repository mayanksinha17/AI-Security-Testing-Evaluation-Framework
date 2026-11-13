"""Tool Execution Guardrail protecting against Tool Misuse (ASI02).

Enforces tool allowlisting, argument schema integrity, sandbox boundaries,
and prevents unapproved mass operations.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

from app.security.validation import (
    ALLOWED_HTTP_ENDPOINTS,
    SecurityValidationError,
    validate_email_address,
    validate_http_url,
)

ALLOWED_TOOLS: Set[str] = {"file_reader", "knowledge_search", "http_simulator", "email_simulator"}


@dataclass
class ToolGuardResult:
    is_allowed: bool
    risk_id: str = "ASI02"
    detection_type: str = "none"
    decision: str = "ALLOWED"  # "ALLOWED", "BLOCKED", "REQUIRES_APPROVAL"
    reason: str = ""
    error_message: Optional[str] = None


class ToolExecutionGuard:
    """Enforces strict allowlisting and parameter constraints before tool execution."""

    @classmethod
    def validate_tool_invocation(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        is_already_approved: bool = False,
    ) -> ToolGuardResult:
        normalized_name = (tool_name or "").lower().strip()

        # 1. Strict Tool Allowlist Check
        if normalized_name not in ALLOWED_TOOLS:
            return ToolGuardResult(
                is_allowed=False,
                detection_type="unregistered_tool_rejected",
                decision="BLOCKED",
                reason=f"Tool '{normalized_name}' is not in the allowed tool registry. Allowed: {sorted(ALLOWED_TOOLS)}",
                error_message=f"Access Denied: Unregistered tool '{normalized_name}' is prohibited.",
            )

        # 2. HTTP Simulator Sandbox Check (ASI02-01)
        if normalized_name == "http_simulator":
            url = str(arguments.get("url", "")).strip()
            if not url:
                return ToolGuardResult(
                    is_allowed=False,
                    detection_type="missing_url",
                    decision="BLOCKED",
                    reason="HTTP simulator requires 'url' argument.",
                    error_message="Argument 'url' is required for http_simulator.",
                )
            try:
                validate_http_url(url, ALLOWED_HTTP_ENDPOINTS)
            except SecurityValidationError as e:
                return ToolGuardResult(
                    is_allowed=False,
                    detection_type="unapproved_http_target_blocked",
                    decision="BLOCKED",
                    reason=f"Destination URL '{url}' is not in the controlled allowlist: {str(e)}",
                    error_message=f"Security Policy Violation [ASI02]: Destination URL '{url}' is forbidden.",
                )

        # 3. File Reader Sandbox Check (ASI02-03)
        if normalized_name == "file_reader":
            filepath = str(arguments.get("file_path", "")).strip()
            if ".." in filepath or filepath.startswith("/") or filepath.startswith("\\"):
                return ToolGuardResult(
                    is_allowed=False,
                    detection_type="path_traversal_blocked",
                    decision="BLOCKED",
                    reason=f"Path traversal sequence detected in '{filepath}'. Escaping synthetic sandbox is prohibited.",
                    error_message=f"Security Policy Violation [ASI02]: Path traversal in '{filepath}' blocked.",
                )

        # 4. Email Simulator Approval & Mass Dispatch Check (ASI02-02)
        if normalized_name == "email_simulator":
            recipient = str(arguments.get("recipient", "")).strip()
            if any(term in recipient.lower() for term in ["all", "staff", "roster", "executives", "broadcast"]):
                return ToolGuardResult(
                    is_allowed=False,
                    detection_type="mass_email_dispatch_blocked",
                    decision="BLOCKED",
                    reason=f"Mass or broadcast email simulation targeting '{recipient}' is prohibited.",
                    error_message=f"Security Policy Violation [ASI02]: Mass email recipient '{recipient}' blocked.",
                )

            # Must be approved
            if not is_already_approved:
                return ToolGuardResult(
                    is_allowed=False,
                    detection_type="sensitive_email_requires_approval",
                    decision="REQUIRES_APPROVAL",
                    reason="Email simulator executes sensitive external action and requires explicit human approval.",
                    error_message="Action Paused: Sensitive tool 'email_simulator' requires human authorization.",
                )

        return ToolGuardResult(
            is_allowed=True,
            decision="ALLOWED",
            reason="Tool invocation verified by tool execution guardrails.",
        )

