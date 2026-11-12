from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ToolExecutionSchema(BaseModel):
    id: str
    session_id: str
    tool_name: str
    tool_arguments: Dict[str, Any]
    result: Optional[Any] = None
    status: str
    permission_decision: str
    execution_time_ms: Optional[float] = None
    created_at: str


class ToolApprovalSchema(BaseModel):
    id: str
    tool_execution_id: str
    tool_name: str
    tool_arguments: Dict[str, Any]
    status: str
    decision_reason: Optional[str] = None
    created_at: str
    decided_at: Optional[str] = None


class AgentMessageSchema(BaseModel):
    id: int
    session_id: str
    role: str
    content: str
    tool_name: Optional[str] = None
    tool_call_id: Optional[str] = None
    created_at: str


class AgentSessionSchema(BaseModel):
    id: str
    title: str
    provider: str
    model: str
    role: str
    created_at: str
    updated_at: str
    messages: List[AgentMessageSchema] = []
    tool_executions: List[ToolExecutionSchema] = []


class AgentRunRequest(BaseModel):
    prompt: str = Field(..., description="User prompt or instruction for the agent")
    provider: Optional[str] = Field("claude", description="AI provider: 'claude' or 'gemini'")
    model: Optional[str] = Field(None, description="Model identifier override")
    session_id: Optional[str] = Field(None, description="Existing agent session ID to resume")
    role: Optional[str] = Field("analyst", description="Security role: 'user', 'analyst', or 'admin'")


class AgentRunResponse(BaseModel):
    session_id: str
    provider: str
    model: str
    execution_mode: str
    tool_calls: List[ToolExecutionSchema] = []
    pending_approval: Optional[ToolApprovalSchema] = None
    final_response: str
    status: str  # "completed", "pending_approval", "error"


class ApproveRequest(BaseModel):
    approval_id: str = Field(..., description="ID of the pending tool approval")


class DenyRequest(BaseModel):
    approval_id: str = Field(..., description="ID of the pending tool approval")
    reason: Optional[str] = Field("Denied by user", description="Reason for denying execution")


class ResetRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Optional session ID to reset; if None, resets current active state")

