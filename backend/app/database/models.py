from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database.session import Base


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False, default="New Conversation")
    provider = Column(String(50), nullable=False, default="claude")
    model = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    messages = relationship(
        "ChatMessage",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="ChatMessage.created_at.asc()",
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(20), nullable=False)  # "user", "assistant", "system"
    content = Column(Text, nullable=False)
    execution_mode = Column(String(20), nullable=False, default="mock")  # "mock" or "live"
    response_time_ms = Column(Float, nullable=True)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    session = relationship("ChatSession", back_populates="messages")


# =====================================================================
# Phase 3: Agentic AI & Tool Execution Models
# =====================================================================

class AgentSession(Base):
    __tablename__ = "agent_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False, default="New Agent Session")
    provider = Column(String(50), nullable=False, default="claude")
    model = Column(String(100), nullable=False)
    role = Column(String(50), nullable=False, default="analyst")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    messages = relationship(
        "AgentMessage",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="AgentMessage.created_at.asc()",
    )
    tool_executions = relationship(
        "ToolExecution",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="ToolExecution.created_at.asc()",
    )


class AgentMessage(Base):
    __tablename__ = "agent_messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(20), nullable=False)  # "user", "assistant", "system", "tool"
    content = Column(Text, nullable=False)
    tool_name = Column(String(100), nullable=True)
    tool_call_id = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    session = relationship("AgentSession", back_populates="messages")


class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(36), ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False)
    tool_arguments = Column(Text, nullable=False)  # JSON-encoded
    result = Column(Text, nullable=True)
    status = Column(String(30), nullable=False)  # "success", "failed", "denied", "pending_approval", "blocked"
    permission_decision = Column(String(30), nullable=False)  # "granted", "denied", "requires_approval"
    execution_time_ms = Column(Float, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    session = relationship("AgentSession", back_populates="tool_executions")
    approvals = relationship("ToolApproval", back_populates="execution", cascade="all, delete-orphan")


class ToolApproval(Base):
    __tablename__ = "tool_approvals"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False)
    tool_arguments = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="pending")  # "pending", "approved", "denied"
    decision_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    decided_at = Column(DateTime, nullable=True)

    execution = relationship("ToolExecution", back_populates="approvals")



# =====================================================================
# Phase 4: Attack Testing Engine Models
# =====================================================================

class AttackScenarioRecord(Base):
    __tablename__ = "attack_scenarios"

    id = Column(String(50), primary_key=True)  # e.g. "LLM01-01"
    risk_id = Column(String(20), nullable=False, index=True)  # e.g. "LLM01"
    risk_name = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)  # "OWASP_LLM" or "OWASP_AGENTIC"
    scenario_name = Column(String(200), nullable=False)
    attack_description = Column(Text, nullable=False)
    attack_prompt = Column(Text, nullable=False)
    expected_secure_behavior = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="medium")  # "low", "medium", "high", "critical"
    target_component = Column(String(50), nullable=False, default="agent")  # "chatbot" or "agent"
    test_type = Column(String(50), nullable=False, default="direct_prompt")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class AttackRun(Base):
    __tablename__ = "attack_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    provider = Column(String(50), nullable=False, default="claude")
    model = Column(String(100), nullable=False)
    stage = Column(String(30), nullable=False, default="BASELINE")  # "BASELINE" or "POST_MITIGATION"
    execution_mode = Column(String(20), nullable=False, default="mock")  # "mock" or "live"
    total_scenarios = Column(Integer, nullable=False, default=0)
    blocked_count = Column(Integer, nullable=False, default=0)
    partial_count = Column(Integer, nullable=False, default=0)
    succeeded_count = Column(Integer, nullable=False, default=0)
    error_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    results = relationship(
        "AttackResult",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="AttackResult.created_at.asc()",
    )


class AttackResult(Base):
    __tablename__ = "attack_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(String(36), ForeignKey("attack_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    scenario_id = Column(String(50), nullable=False, index=True)
    risk_id = Column(String(20), nullable=False, index=True)
    provider = Column(String(50), nullable=False)
    model = Column(String(100), nullable=False)
    execution_mode = Column(String(20), nullable=False, default="mock")
    stage = Column(String(30), nullable=False, default="BASELINE")
    prompt = Column(Text, nullable=False)
    response_content = Column(Text, nullable=True)
    tool_calls = Column(Text, nullable=True)  # JSON-encoded
    result_classification = Column(String(30), nullable=False)  # "BLOCKED", "PARTIAL", "SUCCEEDED", "ERROR"
    evaluation_reason = Column(Text, nullable=True)
    latency_ms = Column(Float, nullable=True)
    error_details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    run = relationship("AttackRun", back_populates="results")


# =====================================================================
# Phase 5: Security Audit Log Models
# =====================================================================

class SecurityAuditLog(Base):
    __tablename__ = "security_audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(50), nullable=False, index=True)
    risk_id = Column(String(20), nullable=True, index=True)
    scenario_id = Column(String(50), nullable=True, index=True)
    detection_type = Column(String(50), nullable=False)
    provider = Column(String(50), nullable=False, default="claude")
    model = Column(String(100), nullable=False)
    security_decision = Column(String(30), nullable=False)  # "BLOCKED", "SANITIZED", "MONITORED", "ALLOWED"
    security_component = Column(String(100), nullable=True, default="SecurityPipeline")
    tool_name = Column(String(100), nullable=True, default="N/A")
    execution_stage = Column(String(30), nullable=True, default="POST_MITIGATION")
    execution_status = Column(String(30), nullable=True, default="BLOCKED")
    authorization_decision = Column(String(30), nullable=True, default="BLOCKED")
    reason = Column(Text, nullable=False)
    execution_ref = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


# =====================================================================
# Phase 7: Evaluation Framework & Model Comparison Models
# =====================================================================

class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False, default="Comprehensive AI Security Evaluation")
    status = Column(String(30), nullable=False, default="completed")  # "completed", "running", "failed"
    execution_mode = Column(String(20), nullable=False, default="mock")  # "mock" or "live"
    claude_model = Column(String(100), nullable=False, default="claude-sonnet-5-5")
    gemini_model = Column(String(100), nullable=False, default="gemini-3.8-flash")
    total_scenarios = Column(Integer, nullable=False, default=30)
    total_executions = Column(Integer, nullable=False, default=0)

    # Claude baseline & post-mitigation counts
    claude_baseline_blocked = Column(Integer, nullable=False, default=0)
    claude_baseline_partial = Column(Integer, nullable=False, default=0)
    claude_baseline_succeeded = Column(Integer, nullable=False, default=0)
    claude_baseline_errors = Column(Integer, nullable=False, default=0)
    claude_post_blocked = Column(Integer, nullable=False, default=0)
    claude_post_partial = Column(Integer, nullable=False, default=0)
    claude_post_succeeded = Column(Integer, nullable=False, default=0)
    claude_post_errors = Column(Integer, nullable=False, default=0)

    # Gemini baseline & post-mitigation counts
    gemini_baseline_blocked = Column(Integer, nullable=False, default=0)
    gemini_baseline_partial = Column(Integer, nullable=False, default=0)
    gemini_baseline_succeeded = Column(Integer, nullable=False, default=0)
    gemini_baseline_errors = Column(Integer, nullable=False, default=0)
    gemini_post_blocked = Column(Integer, nullable=False, default=0)
    gemini_post_partial = Column(Integer, nullable=False, default=0)
    gemini_post_succeeded = Column(Integer, nullable=False, default=0)
    gemini_post_errors = Column(Integer, nullable=False, default=0)

    # General totals
    not_run_count = Column(Integer, nullable=False, default=0)
    claude_block_rate = Column(Float, nullable=False, default=0.0)
    gemini_block_rate = Column(Float, nullable=False, default=0.0)
    overall_block_rate = Column(Float, nullable=False, default=0.0)
    mitigation_improvement = Column(Float, nullable=False, default=0.0)
    average_latency_ms = Column(Float, nullable=False, default=0.0)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)

    comparisons = relationship(
        "ModelComparison",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="ModelComparison.created_at.asc()",
    )
    metrics = relationship(
        "EvaluationMetric",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="EvaluationMetric.risk_id.asc()",
    )


class ModelComparison(Base):
    __tablename__ = "model_comparisons"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evaluation_run_id = Column(String(36), ForeignKey("evaluation_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    scenario_id = Column(String(50), nullable=False, index=True)
    risk_id = Column(String(20), nullable=False, index=True)
    category = Column(String(50), nullable=False)  # "OWASP_LLM" or "OWASP_AGENTIC"
    scenario_name = Column(String(200), nullable=False)
    stage = Column(String(30), nullable=False, default="BASELINE")  # "BASELINE" or "POST_MITIGATION"
    
    # Claude execution outcome
    claude_classification = Column(String(30), nullable=False)  # "BLOCKED", "PARTIAL", "SUCCEEDED", "ERROR", "NOT_RUN"
    claude_latency_ms = Column(Float, nullable=True)
    claude_reason = Column(Text, nullable=True)
    
    # Gemini execution outcome
    gemini_classification = Column(String(30), nullable=False)
    gemini_latency_ms = Column(Float, nullable=True)
    gemini_reason = Column(Text, nullable=True)
    
    comparative_verdict = Column(String(100), nullable=False)  # "Both Protected", "Claude More Resilient", etc.
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    run = relationship("EvaluationRun", back_populates="comparisons")


class EvaluationMetric(Base):
    __tablename__ = "evaluation_metrics"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evaluation_run_id = Column(String(36), ForeignKey("evaluation_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    risk_id = Column(String(20), nullable=False, index=True)
    risk_name = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)
    stage = Column(String(30), nullable=False)  # "BASELINE" or "POST_MITIGATION"
    provider = Column(String(50), nullable=False)  # "claude", "gemini", or "all"
    model = Column(String(100), nullable=False)
    tested_count = Column(Integer, nullable=False, default=0)
    blocked_count = Column(Integer, nullable=False, default=0)
    partial_count = Column(Integer, nullable=False, default=0)
    succeeded_count = Column(Integer, nullable=False, default=0)
    error_count = Column(Integer, nullable=False, default=0)
    not_run_count = Column(Integer, nullable=False, default=0)
    block_rate_percent = Column(Float, nullable=False, default=0.0)
    avg_latency_ms = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    run = relationship("EvaluationRun", back_populates="metrics")
