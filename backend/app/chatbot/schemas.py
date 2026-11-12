from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TokenUsageSchema(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatRequest(BaseModel):
    provider: str = Field(..., description="Target AI provider ('claude' or 'gemini')")
    message: str = Field(..., min_length=1, max_length=4000, description="User message text")
    session_id: Optional[str] = Field(None, description="Active session ID or null to start a new session")
    model_id: Optional[str] = Field(None, description="Optional custom model override")


class ChatResponse(BaseModel):
    session_id: str
    provider: str
    model: str
    user_message: str
    assistant_response: str
    response_time_ms: float
    token_usage: Optional[TokenUsageSchema] = None
    execution_mode: str  # "mock" or "live"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ClearChatRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Session ID to clear; if omitted, clears all sessions")


class ClearChatResponse(BaseModel):
    status: str = "ok"
    message: str
    cleared_session_id: Optional[str] = None


class ModelInfo(BaseModel):
    id: str
    name: str
    model: str
    is_live_available: bool
    execution_mode: str
    description: str


class ModelsResponse(BaseModel):
    models: List[ModelInfo]
    default_provider: str = "claude"
    ai_provider_mode: str


class ChatHealthResponse(BaseModel):
    status: str = "ok"
    ai_provider_mode: str
    providers: List[ModelInfo]
    database_connected: bool


class MessageDetail(BaseModel):
    id: int
    role: str
    content: str
    execution_mode: str
    response_time_ms: Optional[float] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    created_at: datetime


class SessionSummary(BaseModel):
    id: str
    title: str
    provider: str
    model: str
    created_at: datetime
    updated_at: datetime
    message_count: int


class SessionDetailResponse(BaseModel):
    session_id: str
    title: str
    provider: str
    model: str
    created_at: datetime
    updated_at: datetime
    messages: List[MessageDetail]

