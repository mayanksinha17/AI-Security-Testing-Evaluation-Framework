from datetime import datetime, timezone
import json
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy.orm import Session

from app.agent.planner import AgentPlan, AgentPlanner, ToolCallPlan
from app.agent.schemas import ToolApprovalSchema, ToolExecutionSchema
from app.database.models import AgentMessage, AgentSession, ToolApproval, ToolExecution
from app.security.approval import ApprovalManager
from app.security.permissions import PermissionDecision, PermissionManager
from app.tools.registry import tool_registry


MAX_AGENT_ITERATIONS = 5


class AgentController:
    """Manages the full Agent execution lifecycle, enforcing security policies and human approval."""

    def __init__(self, provider: str = "claude", model: Optional[str] = None):
        self.provider = provider
        self.model = model
        self.planner = AgentPlanner(provider_name=provider, model=model)

    async def execute_turn(
        self,
        db: Session,
        session: AgentSession,
        user_prompt: str,
        role: str = "analyst",
    ) -> Dict[str, Any]:
        """Executes one user turn through planning, permission checks, tool runs, and response synthesis."""
        # 1. Record user message in DB
        user_msg = AgentMessage(
            session_id=session.id,
            role="user",
            content=user_prompt,
            created_at=datetime.now(timezone.utc),
        )
        db.add(user_msg)
        db.commit()

        # 2. Plan tool requirements
        plan = await self.planner.plan(prompt=user_prompt, role=role)

        # 3. If no tools are required, synthesize direct answer
        if not plan.needs_tool or not plan.tool_calls:
            assistant_text = self._synthesize_direct_answer(user_prompt, plan.direct_thought)
            asst_msg = AgentMessage(
                session_id=session.id,
                role="assistant",
                content=assistant_text,
                created_at=datetime.now(timezone.utc),
            )
            db.add(asst_msg)
            session.updated_at = datetime.now(timezone.utc)
            db.commit()

            return {
                "session_id": session.id,
                "provider": session.provider,
                "model": session.model,
                "execution_mode": "mock",
                "tool_calls": [],
                "pending_approval": None,
                "final_response": assistant_text,
                "status": "completed",
            }

        # 4. Process tool calls with permission enforcement
        executed_tool_schemas: List[ToolExecutionSchema] = []
        pending_approval_schema: Optional[ToolApprovalSchema] = None
        final_response_text = ""
        overall_status = "completed"

        for tool_call in plan.tool_calls[:MAX_AGENT_ITERATIONS]:
            tool = tool_registry.get_tool(tool_call.tool_name)
            if not tool:
                # Tool doesn't exist
                exec_id = str(uuid.uuid4())
                exec_record = ToolExecution(
                    id=exec_id,
                    session_id=session.id,
                    tool_name=tool_call.tool_name,
                    tool_arguments=json.dumps(tool_call.arguments),
                    result=json.dumps({"error": f"Tool '{tool_call.tool_name}' not found."}),
                    status="failed",
                    permission_decision="denied",
                    execution_time_ms=0.0,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(exec_record)
                db.commit()
                continue

            # Permission Check
            perm_result = PermissionManager.evaluate_tool_permission(
                tool_name=tool.name,
                arguments=tool_call.arguments,
                user_role=role,
                is_already_approved=False,
            )

            # Case A: Requires Human Approval
            if perm_result.decision == PermissionDecision.REQUIRES_APPROVAL:
                exec_id = str(uuid.uuid4())
                exec_record = ToolExecution(
                    id=exec_id,
                    session_id=session.id,
                    tool_name=tool.name,
                    tool_arguments=json.dumps(tool_call.arguments),
                    result=None,
                    status="pending_approval",
                    permission_decision=perm_result.decision.value,
                    execution_time_ms=0.0,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(exec_record)
                db.commit()

                # Create Approval Record
                approval = ApprovalManager.create_approval_request(
                    db=db,
                    tool_execution_id=exec_id,
                    tool_name=tool.name,
                    arguments=tool_call.arguments,
                )

                pending_approval_schema = ToolApprovalSchema(
                    id=approval.id,
                    tool_execution_id=exec_id,
                    tool_name=tool.name,
                    tool_arguments=tool_call.arguments,
                    status=approval.status,
                    decision_reason=approval.decision_reason,
                    created_at=approval.created_at.isoformat(),
                    decided_at=approval.decided_at.isoformat() if approval.decided_at else None,
                )

                tool_schema = ToolExecutionSchema(
                    id=exec_id,
                    session_id=session.id,
                    tool_name=tool.name,
                    tool_arguments=tool_call.arguments,
                    result=None,
                    status="pending_approval",
                    permission_decision=perm_result.decision.value,
                    execution_time_ms=0.0,
                    created_at=exec_record.created_at.isoformat(),
                )
                executed_tool_schemas.append(tool_schema)

                final_response_text = (
                    f"ACTION PAUSED FOR APPROVAL:\n"
                    f"The agent planned to execute sensitive tool '{tool.name}' with arguments: "
                    f"{json.dumps(tool_call.arguments)}. "
                    f"Reason: {perm_result.reason}\n"
                    f"Please approve or deny this operation to proceed."
                )
                overall_status = "pending_approval"

                asst_msg = AgentMessage(
                    session_id=session.id,
                    role="assistant",
                    content=final_response_text,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(asst_msg)
                db.commit()
                break

            # Case B: Denied by Role or Security Policy
            elif perm_result.decision == PermissionDecision.DENIED:
                exec_id = str(uuid.uuid4())
                exec_record = ToolExecution(
                    id=exec_id,
                    session_id=session.id,
                    tool_name=tool.name,
                    tool_arguments=json.dumps(tool_call.arguments),
                    result=json.dumps({"error": perm_result.reason, "denied": True}),
                    status="denied",
                    permission_decision=perm_result.decision.value,
                    execution_time_ms=0.0,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(exec_record)
                db.commit()

                tool_schema = ToolExecutionSchema(
                    id=exec_id,
                    session_id=session.id,
                    tool_name=tool.name,
                    tool_arguments=tool_call.arguments,
                    result={"error": perm_result.reason, "denied": True},
                    status="denied",
                    permission_decision=perm_result.decision.value,
                    execution_time_ms=0.0,
                    created_at=exec_record.created_at.isoformat(),
                )
                executed_tool_schemas.append(tool_schema)

                final_response_text = f"Security Policy Block: {perm_result.reason}"
                overall_status = "completed"

                asst_msg = AgentMessage(
                    session_id=session.id,
                    role="assistant",
                    content=final_response_text,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(asst_msg)
                db.commit()
                break

            # Case C: Granted - Execute Tool
            else:
                t0 = time.perf_counter()
                tool_result = await tool.execute(tool_call.arguments, context={"role": role})
                duration_ms = round((time.perf_counter() - t0) * 1000, 2)

                status_val = "success" if tool_result.success else "failed"
                if not tool_result.success and tool_result.metadata.get("blocked"):
                    status_val = "blocked"

                exec_id = str(uuid.uuid4())
                exec_record = ToolExecution(
                    id=exec_id,
                    session_id=session.id,
                    tool_name=tool.name,
                    tool_arguments=json.dumps(tool_call.arguments),
                    result=json.dumps(tool_result.output if tool_result.success else {"error": tool_result.error}),
                    status=status_val,
                    permission_decision=perm_result.decision.value,
                    execution_time_ms=duration_ms,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(exec_record)
                db.commit()

                tool_schema = ToolExecutionSchema(
                    id=exec_id,
                    session_id=session.id,
                    tool_name=tool.name,
                    tool_arguments=tool_call.arguments,
                    result=tool_result.output if tool_result.success else {"error": tool_result.error},
                    status=status_val,
                    permission_decision=perm_result.decision.value,
                    execution_time_ms=duration_ms,
                    created_at=exec_record.created_at.isoformat(),
                )
                executed_tool_schemas.append(tool_schema)

                # Synthesize response from tool result
                final_response_text = self._synthesize_tool_response(
                    user_prompt=user_prompt,
                    tool_name=tool.name,
                    tool_result=tool_result,
                )

                asst_msg = AgentMessage(
                    session_id=session.id,
                    role="assistant",
                    content=final_response_text,
                    tool_name=tool.name,
                    tool_call_id=tool_call.call_id,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(asst_msg)
                db.commit()

        session.updated_at = datetime.now(timezone.utc)
        db.commit()

        return {
            "session_id": session.id,
            "provider": session.provider,
            "model": session.model,
            "execution_mode": "mock",
            "tool_calls": executed_tool_schemas,
            "pending_approval": pending_approval_schema,
            "final_response": final_response_text,
            "status": overall_status,
        }

    async def execute_approved(self, db: Session, approval_id: str) -> Dict[str, Any]:
        """Resumes and executes a previously paused action that has been granted approval."""
        approval = ApprovalManager.get_approval(db, approval_id)
        if not approval:
            raise ValueError(f"Approval with ID '{approval_id}' not found.")

        # Mark approval as approved in DB
        ApprovalManager.approve_action(db, approval_id)

        # Get the associated execution
        stmt = db.query(ToolExecution).filter(ToolExecution.id == approval.tool_execution_id)
        exec_record = stmt.first()
        if not exec_record:
            raise ValueError(f"Execution with ID '{approval.tool_execution_id}' not found.")

        session = db.query(AgentSession).filter(AgentSession.id == exec_record.session_id).first()
        args = json.loads(approval.tool_arguments)
        tool = tool_registry.get_tool(approval.tool_name)

        if not tool:
            raise ValueError(f"Tool '{approval.tool_name}' not found.")

        t0 = time.perf_counter()
        tool_result = await tool.execute(args, context={"role": session.role if session else "analyst"})
        duration_ms = round((time.perf_counter() - t0) * 1000, 2)

        exec_record.status = "success" if tool_result.success else "failed"
        exec_record.result = json.dumps(tool_result.output if tool_result.success else {"error": tool_result.error})
        exec_record.execution_time_ms = duration_ms
        db.commit()

        final_response_text = (
            f"[APPROVED & EXECUTED]\n"
            f"Tool '{tool.name}' was approved and executed successfully.\n"
            f"Result: {json.dumps(tool_result.output, indent=2)}"
        )

        asst_msg = AgentMessage(
            session_id=session.id if session else "default",
            role="assistant",
            content=final_response_text,
            tool_name=tool.name,
            created_at=datetime.now(timezone.utc),
        )
        db.add(asst_msg)
        db.commit()

        tool_schema = ToolExecutionSchema(
            id=exec_record.id,
            session_id=exec_record.session_id,
            tool_name=exec_record.tool_name,
            tool_arguments=args,
            result=tool_result.output if tool_result.success else {"error": tool_result.error},
            status=exec_record.status,
            permission_decision="granted",
            execution_time_ms=duration_ms,
            created_at=exec_record.created_at.isoformat(),
        )

        return {
            "session_id": exec_record.session_id,
            "provider": session.provider if session else self.provider,
            "model": session.model if session else self.model,
            "execution_mode": "mock",
            "tool_calls": [tool_schema],
            "pending_approval": None,
            "final_response": final_response_text,
            "status": "completed",
        }

    async def execute_denied(self, db: Session, approval_id: str, reason: str = "Denied by user") -> Dict[str, Any]:
        """Handles human rejection of a sensitive tool action."""
        approval = ApprovalManager.get_approval(db, approval_id)
        if not approval:
            raise ValueError(f"Approval with ID '{approval_id}' not found.")

        ApprovalManager.deny_action(db, approval_id, reason=reason)

        exec_record = db.query(ToolExecution).filter(ToolExecution.id == approval.tool_execution_id).first()
        if exec_record:
            exec_record.status = "denied"
            exec_record.result = json.dumps({"denied": True, "reason": reason})
            db.commit()

        session = db.query(AgentSession).filter(AgentSession.id == exec_record.session_id).first() if exec_record else None

        final_response_text = (
            f"[ACTION DENIED]\n"
            f"Execution of tool '{approval.tool_name}' was explicitly denied by human operator.\n"
            f"Reason: {reason}"
        )

        if session:
            asst_msg = AgentMessage(
                session_id=session.id,
                role="assistant",
                content=final_response_text,
                tool_name=approval.tool_name,
                created_at=datetime.now(timezone.utc),
            )
            db.add(asst_msg)
            db.commit()

        tool_schema = ToolExecutionSchema(
            id=exec_record.id if exec_record else str(uuid.uuid4()),
            session_id=exec_record.session_id if exec_record else "",
            tool_name=approval.tool_name,
            tool_arguments=json.loads(approval.tool_arguments),
            result={"denied": True, "reason": reason},
            status="denied",
            permission_decision="denied",
            execution_time_ms=0.0,
            created_at=exec_record.created_at.isoformat() if exec_record else datetime.now(timezone.utc).isoformat(),
        )

        return {
            "session_id": exec_record.session_id if exec_record else "",
            "provider": session.provider if session else self.provider,
            "model": session.model if session else self.model,
            "execution_mode": "mock",
            "tool_calls": [tool_schema],
            "pending_approval": None,
            "final_response": final_response_text,
            "status": "completed",
        }

    def _synthesize_direct_answer(self, user_prompt: str, thought: str) -> str:
        return (
            f"I have reviewed your request: '{user_prompt}'.\n\n"
            f"Evaluation notes: {thought}\n"
            f"Available security testing tools: file_reader, knowledge_search, http_simulator, email_simulator. "
            f"You can instruct me to read synthetic files, query internal documents, simulate HTTP calls, or test email alerts."
        )

    def _synthesize_tool_response(self, user_prompt: str, tool_name: str, tool_result: Any) -> str:
        if not tool_result.success:
            return (
                f"Tool '{tool_name}' execution was unsuccessful or blocked by policy.\n"
                f"Details: {tool_result.error}"
            )

        if tool_name == "file_reader":
            data = tool_result.output
            return (
                f"Successfully read file '{data.get('file_name')}' ({data.get('size_bytes')} bytes):\n\n"
                f"{data.get('content')}"
            )
        elif tool_name == "knowledge_search":
            data = tool_result.output
            results = data.get("results", [])
            lines = [f"Found {len(results)} relevant knowledge document(s) for '{data.get('query')}':\n"]
            for r in results:
                lines.append(f"• [{r.get('id')}] {r.get('title')} (Classification: {r.get('classification')}):")
                lines.append(f"  {r.get('content')}\n")
            return "\n".join(lines)
        elif tool_name == "http_simulator":
            data = tool_result.output
            return (
                f"Simulated HTTP {data.get('method')} to '{data.get('url')}':\n"
                f"Status: {data.get('status_code')}\n"
                f"Response body: {json.dumps(data.get('body'), indent=2)}"
            )
        elif tool_name == "email_simulator":
            data = tool_result.output
            return (
                f"Simulated email delivery completed:\n"
                f"To: {data.get('recipient')}\n"
                f"Subject: {data.get('subject')}\n"
                f"Delivery ID: {data.get('delivery_id')}\n"
                f"Status: {data.get('status')}"
            )

        return f"Tool '{tool_name}' completed: {json.dumps(tool_result.output)}"

