from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.agent.controller import AgentController
from app.agent.schemas import (
    AgentMessageSchema,
    AgentRunRequest,
    AgentRunResponse,
    AgentSessionSchema,
    ApproveRequest,
    DenyRequest,
    ToolApprovalSchema,
    ToolExecutionSchema,
)
from app.core.config import settings
from app.database.models import AgentMessage, AgentSession, ToolApproval, ToolExecution


class AgentService:
    """Service layer coordinating sessions, agent turns, tool executions, and audit records."""

    @staticmethod
    def get_or_create_session(
        db: Session,
        session_id: Optional[str] = None,
        provider: str = "claude",
        model: Optional[str] = None,
        role: str = "analyst",
    ) -> AgentSession:
        if session_id:
            session = db.query(AgentSession).filter(AgentSession.id == session_id).first()
            if session:
                if role:
                    session.role = role.lower()
                if provider:
                    session.provider = provider.lower()
                if model:
                    session.model = model
                db.commit()
                return session

        # Resolve model name
        if not model:
            if provider.lower() == "gemini":
                model = settings.GEMINI_MODEL
            else:
                model = settings.CLAUDE_MODEL

        new_session = AgentSession(
            id=str(uuid.uuid4()),
            title="Agent Lab Session",
            provider=provider.lower(),
            model=model,
            role=role.lower(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(new_session)
        db.commit()
        db.refresh(new_session)
        return new_session

    @classmethod
    async def run(cls, db: Session, req: AgentRunRequest) -> AgentRunResponse:
        session = cls.get_or_create_session(
            db=db,
            session_id=req.session_id,
            provider=req.provider or "claude",
            model=req.model,
            role=req.role or "analyst",
        )

        controller = AgentController(provider=session.provider, model=session.model)
        result = await controller.execute_turn(
            db=db,
            session=session,
            user_prompt=req.prompt,
            role=session.role,
        )

        return AgentRunResponse(**result)

    @classmethod
    async def approve(cls, db: Session, req: ApproveRequest) -> AgentRunResponse:
        approval = db.query(ToolApproval).filter(ToolApproval.id == req.approval_id).first()
        if not approval:
            raise ValueError(f"Approval with ID '{req.approval_id}' not found.")

        exec_record = db.query(ToolExecution).filter(ToolExecution.id == approval.tool_execution_id).first()
        session = db.query(AgentSession).filter(AgentSession.id == exec_record.session_id).first() if exec_record else None

        controller = AgentController(
            provider=session.provider if session else "claude",
            model=session.model if session else settings.CLAUDE_MODEL,
        )
        result = await controller.execute_approved(db=db, approval_id=req.approval_id)
        return AgentRunResponse(**result)

    @classmethod
    async def deny(cls, db: Session, req: DenyRequest) -> AgentRunResponse:
        approval = db.query(ToolApproval).filter(ToolApproval.id == req.approval_id).first()
        if not approval:
            raise ValueError(f"Approval with ID '{req.approval_id}' not found.")

        exec_record = db.query(ToolExecution).filter(ToolExecution.id == approval.tool_execution_id).first()
        session = db.query(AgentSession).filter(AgentSession.id == exec_record.session_id).first() if exec_record else None

        controller = AgentController(
            provider=session.provider if session else "claude",
            model=session.model if session else settings.CLAUDE_MODEL,
        )
        result = await controller.execute_denied(db=db, approval_id=req.approval_id, reason=req.reason)
        return AgentRunResponse(**result)

    @staticmethod
    def list_sessions(db: Session, limit: int = 50) -> List[Dict[str, Any]]:
        sessions = (
            db.query(AgentSession)
            .order_by(desc(AgentSession.updated_at))
            .limit(limit)
            .all()
        )
        out = []
        for s in sessions:
            out.append({
                "id": s.id,
                "title": s.title,
                "provider": s.provider,
                "model": s.model,
                "role": s.role,
                "created_at": s.created_at.isoformat() if s.created_at else "",
                "updated_at": s.updated_at.isoformat() if s.updated_at else "",
                "message_count": len(s.messages),
                "tool_execution_count": len(s.tool_executions),
            })
        return out

    @staticmethod
    def get_session(db: Session, session_id: str) -> Optional[AgentSessionSchema]:
        session = db.query(AgentSession).filter(AgentSession.id == session_id).first()
        if not session:
            return None

        messages_schema = [
            AgentMessageSchema(
                id=m.id,
                session_id=m.session_id,
                role=m.role,
                content=m.content,
                tool_name=m.tool_name,
                tool_call_id=m.tool_call_id,
                created_at=m.created_at.isoformat() if m.created_at else "",
            )
            for m in session.messages
        ]

        tool_execs_schema = []
        for t in session.tool_executions:
            try:
                args = json.loads(t.tool_arguments)
            except Exception:
                args = {"raw": t.tool_arguments}
            try:
                res = json.loads(t.result) if t.result else None
            except Exception:
                res = t.result

            tool_execs_schema.append(
                ToolExecutionSchema(
                    id=t.id,
                    session_id=t.session_id,
                    tool_name=t.tool_name,
                    tool_arguments=args,
                    result=res,
                    status=t.status,
                    permission_decision=t.permission_decision,
                    execution_time_ms=t.execution_time_ms,
                    created_at=t.created_at.isoformat() if t.created_at else "",
                )
            )

        return AgentSessionSchema(
            id=session.id,
            title=session.title,
            provider=session.provider,
            model=session.model,
            role=session.role,
            created_at=session.created_at.isoformat() if session.created_at else "",
            updated_at=session.updated_at.isoformat() if session.updated_at else "",
            messages=messages_schema,
            tool_executions=tool_execs_schema,
        )

    @staticmethod
    def get_history(db: Session, limit: int = 100) -> List[ToolExecutionSchema]:
        records = (
            db.query(ToolExecution)
            .order_by(desc(ToolExecution.created_at))
            .limit(limit)
            .all()
        )
        out = []
        for t in records:
            try:
                args = json.loads(t.tool_arguments)
            except Exception:
                args = {"raw": t.tool_arguments}
            try:
                res = json.loads(t.result) if t.result else None
            except Exception:
                res = t.result

            out.append(
                ToolExecutionSchema(
                    id=t.id,
                    session_id=t.session_id,
                    tool_name=t.tool_name,
                    tool_arguments=args,
                    result=res,
                    status=t.status,
                    permission_decision=t.permission_decision,
                    execution_time_ms=t.execution_time_ms,
                    created_at=t.created_at.isoformat() if t.created_at else "",
                )
            )
        return out

    @staticmethod
    def reset(db: Session, session_id: Optional[str] = None) -> Dict[str, Any]:
        if session_id:
            session = db.query(AgentSession).filter(AgentSession.id == session_id).first()
            if session:
                db.delete(session)
                db.commit()
                return {"status": "success", "message": f"Session '{session_id}' cleared."}
            return {"status": "not_found", "message": f"Session '{session_id}' not found."}

        # Clear all agent sessions and executions
        db.query(ToolApproval).delete()
        db.query(ToolExecution).delete()
        db.query(AgentMessage).delete()
        db.query(AgentSession).delete()
        db.commit()
        return {"status": "success", "message": "All agent sessions and tool logs cleared."}

