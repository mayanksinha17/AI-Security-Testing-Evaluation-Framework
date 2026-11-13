"""Action guardrail enforcing least privilege and human-in-the-loop authorizations (LLM03).

Prevents autonomous execution of sensitive operations and blocks conversational approval fabrication.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.security.approval import ApprovalManager
from app.security.permissions import PermissionDecision, PermissionManager


@dataclass
class ActionGuardResult:
    is_allowed: bool
    requires_approval: bool
    decision: str  # "GRANTED", "DENIED", "REQUIRES_APPROVAL"
    reason: str


class ActionGuard:
    """Validates tool execution requests against role permissions and database approval state."""

    @classmethod
    def validate_action(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        user_role: str = "analyst",
        is_already_approved: bool = False,
    ) -> ActionGuardResult:
        """Enforces least privilege and flags operations requiring human approval."""
        perm = PermissionManager.evaluate_tool_permission(
            tool_name=tool_name,
            arguments=arguments,
            user_role=user_role,
            is_already_approved=is_already_approved,
        )

        return ActionGuardResult(
            is_allowed=perm.decision == PermissionDecision.GRANTED,
            requires_approval=perm.decision == PermissionDecision.REQUIRES_APPROVAL,
            decision=perm.decision.value,
            reason=perm.reason,
        )

    @classmethod
    def verify_approval_record(cls, db: Session, approval_id: str) -> bool:
        """Verifies that an approval token exists in the database and was approved by an operator."""
        approval = ApprovalManager.get_approval(db, approval_id)
        return bool(approval and approval.status == "approved")

