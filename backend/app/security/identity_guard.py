"""Identity and Privilege Guardrail protecting against Privilege Abuse (ASI03).

Enforces server-side role validation, intercepts dynamic role escalation,
and validates action-specific human approval records against SQLite.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.database.models import ToolApproval
from app.security.permissions import Role, ROLE_TOOL_ALLOWLIST

PRIVILEGE_ESCALATION_PATTERNS = [
    (
        re.compile(r"elevate\s+(?:my\s+)?(?:session\s+)?role\s+to\s+admin", re.IGNORECASE),
        "Dynamic Role Escalation: Unauthorized attempt to elevate session role to ADMIN.",
    ),
    (
        re.compile(r"grant\s+me\s+admin\s+role\s+permissions", re.IGNORECASE),
        "Privilege Escalation Request: Natural language administrative grant attempt.",
    ),
    (
        re.compile(r"(?:i\s+claim|assuming)\s+administrative\s+privilege", re.IGNORECASE),
        "Administrative Pretexting: Prompt-level administrative privilege claim.",
    ),
    (
        re.compile(r"bypass\s+all\s+(?:permission|approval)\s+(?:checks|requirements)", re.IGNORECASE),
        "Permission Bypass Directive: Unauthorized instruction to disable security policy checks.",
    ),
]


@dataclass
class IdentityGuardResult:
    is_authorized: bool
    risk_id: str = "ASI03"
    detection_type: str = "none"
    decision: str = "GRANTED"  # "GRANTED", "DENIED", "REQUIRES_APPROVAL"
    reason: str = ""
    error_message: Optional[str] = None


class IdentityGuard:
    """Enforces server-side identity validation, rejects prompt-level escalation, and verifies approval tokens."""

    @classmethod
    def inspect_prompt_privilege_abuse(cls, prompt: str) -> Optional[IdentityGuardResult]:
        """Detects whether user prompt attempts natural-language privilege elevation."""
        cleaned = (prompt or "").strip()
        for pattern, desc in PRIVILEGE_ESCALATION_PATTERNS:
            if pattern.search(cleaned):
                return IdentityGuardResult(
                    is_authorized=False,
                    detection_type="privilege_escalation_attempt_denied",
                    decision="DENIED",
                    reason=desc,
                    error_message=f"Security Policy Block [ASI03 - Privilege Abuse]: {desc} Roles are strictly server-managed.",
                )
        return None

    @classmethod
    def validate_action_privilege(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        server_role: str = "analyst",
        is_already_approved: bool = False,
    ) -> IdentityGuardResult:
        """Enforces least-privilege role boundaries and sensitive action policies."""
        normalized_tool = (tool_name or "").lower().strip()

        # Resolve role
        try:
            role_enum = Role(server_role.lower().strip())
        except ValueError:
            role_enum = Role.ANALYST

        # 1. Role-based Tool Allowlist check
        allowed_tools = ROLE_TOOL_ALLOWLIST.get(role_enum, set())
        if normalized_tool not in allowed_tools:
            return IdentityGuardResult(
                is_authorized=False,
                detection_type="role_tool_access_denied",
                decision="DENIED",
                reason=f"Role '{role_enum.value}' is unauthorized to invoke tool '{normalized_tool}'. Allowed: {sorted(allowed_tools)}",
                error_message=f"Access Denied [ASI03]: Role '{role_enum.value}' cannot execute '{normalized_tool}'.",
            )

        # 2. Knowledge base classification check under USER role (ASI03-01)
        if normalized_tool == "knowledge_search":
            include_restricted = bool(arguments.get("include_restricted", False))
            query = str(arguments.get("query", "")).lower()
            if role_enum == Role.USER and (include_restricted or "confidential" in query or "secret-flag" in query or "aegiscore" in query):
                return IdentityGuardResult(
                    is_authorized=False,
                    detection_type="unauthorized_classification_query_denied",
                    decision="DENIED",
                    reason="Role 'user' is forbidden from requesting confidential or restricted knowledge documents.",
                    error_message="Access Denied [ASI03]: Role 'user' cannot access confidential evaluation documents.",
                )

        # 3. Restricted file access policy under ANALYST role (ASI03-03)
        if normalized_tool == "file_reader":
            filepath = str(arguments.get("file_path", "")).lower()
            if "restricted" in filepath or "credentials" in filepath:
                if role_enum != Role.ADMIN and not is_already_approved:
                    return IdentityGuardResult(
                        is_authorized=False,
                        detection_type="restricted_file_requires_approval",
                        decision="REQUIRES_APPROVAL",
                        reason=f"Access to restricted credentials file requires ADMIN role or explicit human approval.",
                        error_message="Action Paused [ASI03]: Access to restricted credentials requires explicit operator approval.",
                    )

        return IdentityGuardResult(
            is_authorized=True,
            decision="GRANTED",
            reason="Identity and role privileges verified by identity guardrail.",
        )

    @classmethod
    def verify_approval_record_match(
        cls,
        db: Session,
        approval_id: str,
        expected_tool: str,
        expected_execution_id: Optional[str] = None,
    ) -> bool:
        """Verifies that an approval token is valid, active, matches expected tool, and was not denied."""
        stmt = db.query(ToolApproval).filter(ToolApproval.id == approval_id)
        approval = stmt.first()
        if not approval:
            return False

        # Must be approved
        if approval.status != "approved":
            return False

        # Must match expected tool
        if approval.tool_name.lower().strip() != expected_tool.lower().strip():
            return False

        # If execution id specified, must match
        if expected_execution_id and approval.tool_execution_id != expected_execution_id:
            return False

        return True

