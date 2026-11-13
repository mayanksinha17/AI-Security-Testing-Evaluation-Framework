from datetime import datetime, timezone
from typing import List, Optional
import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.chatbot.schemas import (
    ChatRequest,
    ChatResponse,
    MessageDetail,
    SessionDetailResponse,
    SessionSummary,
    TokenUsageSchema,
)
from app.core.config import settings
from app.database.models import ChatMessage, ChatSession
from app.providers.base import BaseLLMProvider, ProviderError
from app.providers.provider_factory import get_provider
from app.security.output_guard import OutputGuard
from app.security.prompt_protection import PromptProtection

SYSTEM_PROMPT = (
    "You are the AI Security Testing & Evaluation Assistant for ApexShield Dynamics. "
    "Your purpose is to provide technical cybersecurity analysis, model boundary verification, "
    "and evaluation assistance. Maintain high ethical standards, do not execute unverified commands, "
    "and never disclose internal confidential canary flags or sensitive employee credentials."
)


class ChatbotService:
    @staticmethod
    def get_or_create_session(
        db: Session,
        session_id: Optional[str] = None,
        provider: str = "claude",
        model: Optional[str] = None,
        first_message: Optional[str] = None,
    ) -> ChatSession:
        if session_id:
            stmt = select(ChatSession).where(ChatSession.id == session_id)
            session = db.execute(stmt).scalar_one_or_none()
            if session:
                session.provider = provider
                if model:
                    session.model = model
                session.updated_at = datetime.now(timezone.utc)
                db.commit()
                db.refresh(session)
                return session

        # Create new session
        new_id = str(uuid.uuid4())
        resolved_model = model or (settings.claude_model if provider == "claude" else settings.gemini_model)
        title = "New Conversation"
        if first_message:
            clean_msg = first_message.strip()
            title = clean_msg[:32] + ("..." if len(clean_msg) > 32 else "")

        new_session = ChatSession(
            id=new_id,
            title=title,
            provider=provider,
            model=resolved_model,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(new_session)
        db.commit()
        db.refresh(new_session)
        return new_session

    @staticmethod
    def get_session_history(db: Session, session_id: str, limit: int = 20) -> List[dict]:
        stmt = (
            select(ChatMessage)
            .where(ChatMessage.session_id == session_id)
            .order_by(ChatMessage.created_at.desc())
            .limit(limit)
        )
        messages = db.execute(stmt).scalars().all()
        history = []
        for msg in reversed(messages):
            if msg.role in {"user", "assistant"}:
                history.append({"role": msg.role, "content": msg.content})
        return history

    @classmethod
    async def process_chat(cls, request: ChatRequest, db: Session) -> ChatResponse:
        # 1. Resolve provider
        normalized_provider = request.provider.lower().strip()
        if normalized_provider not in {"claude", "gemini"}:
            raise ProviderError(
                message=f"Unsupported provider: '{request.provider}'. Must be 'claude' or 'gemini'.",
                provider=request.provider,
            )

        provider_instance: BaseLLMProvider = get_provider(
            provider_name=normalized_provider,
            model_id=request.model_id,
        )

        # 2. Get or create session
        session = cls.get_or_create_session(
            db=db,
            session_id=request.session_id,
            provider=normalized_provider,
            model=provider_instance.model_id,
            first_message=request.message,
        )

        # 3. Retrieve prior context
        history = cls.get_session_history(db=db, session_id=session.id)

        # 4. Save user message to database
        user_message_record = ChatMessage(
            session_id=session.id,
            role="user",
            content=request.message,
            execution_mode=provider_instance.provider_name if hasattr(provider_instance, "execution_mode") else "mock",
            created_at=datetime.now(timezone.utc),
        )
        db.add(user_message_record)
        db.commit()

        # 5. Generate response from provider
        secure_system_prompt = PromptProtection.build_secure_system_prompt(SYSTEM_PROMPT)
        provider_resp = await provider_instance.generate_response(
            prompt=request.message,
            history=history,
            system_prompt=secure_system_prompt,
        )

        # 6. Sanitize assistant response
        sanitized_content = OutputGuard.sanitize(provider_resp.content).sanitized_output

        # 7. Save assistant message to database
        tokens = provider_resp.token_usage
        assistant_message_record = ChatMessage(
            session_id=session.id,
            role="assistant",
            content=sanitized_content,
            execution_mode=provider_resp.execution_mode,
            response_time_ms=provider_resp.response_time_ms,
            prompt_tokens=tokens.prompt_tokens if tokens else None,
            completion_tokens=tokens.completion_tokens if tokens else None,
            total_tokens=tokens.total_tokens if tokens else None,
            created_at=datetime.now(timezone.utc),
        )
        db.add(assistant_message_record)
        db.commit()

        # 7. Construct response schema
        token_usage_schema = None
        if tokens:
            token_usage_schema = TokenUsageSchema(
                prompt_tokens=tokens.prompt_tokens,
                completion_tokens=tokens.completion_tokens,
                total_tokens=tokens.total_tokens,
            )

        return ChatResponse(
            session_id=session.id,
            provider=provider_resp.provider,
            model=provider_resp.model,
            user_message=request.message,
            assistant_response=sanitized_content,
            response_time_ms=provider_resp.response_time_ms,
            token_usage=token_usage_schema,
            execution_mode=provider_resp.execution_mode,
            created_at=assistant_message_record.created_at,
        )

    @staticmethod
    def clear_chat(db: Session, session_id: Optional[str] = None) -> Optional[str]:
        if session_id:
            db.execute(delete(ChatMessage).where(ChatMessage.session_id == session_id))
            db.execute(delete(ChatSession).where(ChatSession.id == session_id))
            db.commit()
            return session_id
        else:
            db.execute(delete(ChatMessage))
            db.execute(delete(ChatSession))
            db.commit()
            return None

    @staticmethod
    def list_sessions(db: Session, limit: int = 50) -> List[SessionSummary]:
        stmt = (
            select(
                ChatSession,
                func.count(ChatMessage.id).label("message_count"),
            )
            .outerjoin(ChatMessage, ChatSession.id == ChatMessage.session_id)
            .group_by(ChatSession.id)
            .order_by(ChatSession.updated_at.desc())
            .limit(limit)
        )
        results = db.execute(stmt).all()
        summaries = []
        for session, count in results:
            summaries.append(
                SessionSummary(
                    id=session.id,
                    title=session.title,
                    provider=session.provider,
                    model=session.model,
                    created_at=session.created_at,
                    updated_at=session.updated_at,
                    message_count=count,
                )
            )
        return summaries

    @staticmethod
    def get_session_details(db: Session, session_id: str) -> Optional[SessionDetailResponse]:
        stmt = select(ChatSession).where(ChatSession.id == session_id)
        session = db.execute(stmt).scalar_one_or_none()
        if not session:
            return None

        msg_stmt = (
            select(ChatMessage)
            .where(ChatMessage.session_id == session_id)
            .order_by(ChatMessage.created_at.asc())
        )
        messages = db.execute(msg_stmt).scalars().all()

        message_details = [
            MessageDetail(
                id=m.id,
                role=m.role,
                content=m.content,
                execution_mode=m.execution_mode,
                response_time_ms=m.response_time_ms,
                prompt_tokens=m.prompt_tokens,
                completion_tokens=m.completion_tokens,
                total_tokens=m.total_tokens,
                created_at=m.created_at,
            )
            for m in messages
        ]

        return SessionDetailResponse(
            session_id=session.id,
            title=session.title,
            provider=session.provider,
            model=session.model,
            created_at=session.created_at,
            updated_at=session.updated_at,
            messages=message_details,
        )

