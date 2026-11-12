from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import ToolApproval, ToolExecution


class ApprovalManager:
    """Manages the lifecycle of sensitive tool approvals (pending, approved, denied)."""

    @staticmethod
    def create_approval_request(
        db: Session,
        tool_execution_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> ToolApproval:
        approval_id = str(uuid.uuid4())
        approval = ToolApproval(
            id=approval_id,
            tool_execution_id=tool_execution_id,
            tool_name=tool_name,
            tool_arguments=json.dumps(arguments) if not isinstance(arguments, str) else arguments,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        db.add(approval)
        db.commit()
        db.refresh(approval)
        return approval

    @staticmethod
    def get_approval(db: Session, approval_id: str) -> Optional[ToolApproval]:
        stmt = select(ToolApproval).where(ToolApproval.id == approval_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def approve_action(db: Session, approval_id: str) -> Optional[ToolApproval]:
        approval = ApprovalManager.get_approval(db, approval_id)
        if not approval:
            return None
        approval.status = "approved"
        approval.decided_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(approval)
        return approval

    @staticmethod
    def deny_action(db: Session, approval_id: str, reason: str = "Denied by user") -> Optional[ToolApproval]:
        approval = ApprovalManager.get_approval(db, approval_id)
        if not approval:
            return None
        approval.status = "denied"
        approval.decision_reason = reason
        approval.decided_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(approval)
        return approval

