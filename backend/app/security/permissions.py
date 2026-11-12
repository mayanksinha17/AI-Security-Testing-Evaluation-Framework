from enum import Enum
from typing import Any, Dict, NamedTuple, Optional, Set


class Role(str, Enum):
    USER = "user"
    ANALYST = "analyst"
    ADMIN = "admin"


class PermissionDecision(str, Enum):
    GRANTED = "granted"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"


class PermissionCheckResult(NamedTuple):
    decision: PermissionDecision
    reason: str
    tool_name: str
    requires_approval: bool = False


# Role-based Tool Allowlist mapping
ROLE_TOOL_ALLOWLIST: Dict[Role, Set[str]] = {
    Role.USER: {"knowledge_search"},
    Role.ANALYST: {"file_reader", "knowledge_search", "http_simulator", "email_simulator"},
    Role.ADMIN: {"file_reader", "knowledge_search", "http_simulator", "email_simulator"},
}

# Tools and actions requiring human approval
APPROVAL_REQUIRED_TOOLS: Set[str] = {"email_simulator"}


class PermissionManager:
    """Centralized enforcement engine governing tool invocation and human-in-the-loop approval."""

    @classmethod
    def evaluate_tool_permission(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        user_role: str = "analyst",
        is_already_approved: bool = False,
    ) -> PermissionCheckResult:
        normalized_tool = (tool_name or "").lower().strip()

        # 1. Resolve role safely
        try:
            role = Role(user_role.lower().strip())
        except ValueError:
            role = Role.ANALYST

        # 2. Check Role-based Tool Allowlist
        allowed_tools = ROLE_TOOL_ALLOWLIST.get(role, set())
        if normalized_tool not in allowed_tools:
            return PermissionCheckResult(
                decision=PermissionDecision.DENIED,
                reason=f"Role '{role.value}' is not authorized to execute tool '{normalized_tool}'. Allowed tools: {sorted(allowed_tools)}",
                tool_name=normalized_tool,
            )

        # 3. Check if tool requires human approval
        if normalized_tool in APPROVAL_REQUIRED_TOOLS and not is_already_approved:
            # Sensitive operations (e.g. simulated outbound emails) require explicit human approval
            return PermissionCheckResult(
                decision=PermissionDecision.REQUIRES_APPROVAL,
                reason=f"Tool '{normalized_tool}' performs a sensitive external action and requires human approval before execution.",
                tool_name=normalized_tool,
                requires_approval=True,
            )

        # 4. Argument-specific permission checks
        if normalized_tool == "file_reader":
            filepath = str(arguments.get("file_path", "")).lower()
            if "restricted" in filepath or "confidential" in filepath:
                if role != Role.ADMIN and not is_already_approved:
                    return PermissionCheckResult(
                        decision=PermissionDecision.REQUIRES_APPROVAL,
                        reason=f"Access to restricted file '{filepath}' requires explicit approval for role '{role.value}'.",
                        tool_name=normalized_tool,
                        requires_approval=True,
                    )

        if normalized_tool == "knowledge_search":
            include_restricted = bool(arguments.get("include_restricted", False))
            if include_restricted and role == Role.USER:
                return PermissionCheckResult(
                    decision=PermissionDecision.DENIED,
                    reason="Role 'user' is forbidden from requesting restricted knowledge base documents.",
                    tool_name=normalized_tool,
                )

        # 5. Access Granted
        return PermissionCheckResult(
            decision=PermissionDecision.GRANTED,
            reason="Tool invocation verified and authorized by policy engine.",
            tool_name=normalized_tool,
        )

