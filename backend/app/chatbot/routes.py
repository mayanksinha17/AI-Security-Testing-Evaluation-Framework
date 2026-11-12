from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.chatbot.schemas import (
    ChatHealthResponse,
    ChatRequest,
    ChatResponse,
    ClearChatRequest,
    ClearChatResponse,
    ModelInfo,
    ModelsResponse,
    SessionDetailResponse,
    SessionSummary,
)
from app.chatbot.service import ChatbotService
from app.core.config import settings
from app.database.session import get_db
from app.providers.base import (
    ProviderAuthenticationError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.providers.provider_factory import list_available_providers

router = APIRouter(prefix="/api", tags=["chatbot"])


@router.get("/models", response_model=ModelsResponse)
def get_available_models() -> ModelsResponse:
    """Return available LLM providers, model identifiers, and current operating mode."""
    provider_data = list_available_providers()
    models = [ModelInfo(**item) for item in provider_data]
    return ModelsResponse(
        models=models,
        default_provider="claude",
        ai_provider_mode=settings.ai_provider_mode,
    )


@router.post("/chat", response_model=ChatResponse)
async def post_chat_message(
    request: ChatRequest,
    db: Session = Depends(get_db),
) -> ChatResponse:
    """Process a chat interaction turn against the specified LLM provider."""
    # Enforce maximum message length
    if len(request.message) > settings.max_message_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Message length exceeds maximum allowable limit of {settings.max_message_length} characters.",
        )

    try:
        response = await ChatbotService.process_chat(request=request, db=db)
        return response
    except ProviderUnavailableError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=e.message,
        )
    except ProviderAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
        )
    except ProviderTimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=e.message,
        )
    except ProviderError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chat processing encountered an unexpected internal error: {str(e)}",
        )


@router.get("/chat/health", response_model=ChatHealthResponse)
def get_chat_health(db: Session = Depends(get_db)) -> ChatHealthResponse:
    """Check chatbot module health, database connectivity, and provider readiness."""
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    provider_data = list_available_providers()
    models = [ModelInfo(**item) for item in provider_data]

    return ChatHealthResponse(
        status="ok" if db_ok else "degraded",
        ai_provider_mode=settings.ai_provider_mode,
        providers=models,
        database_connected=db_ok,
    )


@router.post("/chat/clear", response_model=ClearChatResponse)
def clear_chat_history(
    request: ClearChatRequest = ClearChatRequest(),
    db: Session = Depends(get_db),
) -> ClearChatResponse:
    """Clear chat messages for a specific session or purge all conversations."""
    try:
        cleared_id = ChatbotService.clear_chat(db=db, session_id=request.session_id)
        if cleared_id:
            msg = f"Session '{cleared_id}' cleared successfully."
        else:
            msg = "All chat sessions and messages cleared successfully."
        return ClearChatResponse(status="ok", message=msg, cleared_session_id=cleared_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear chat history: {str(e)}",
        )


@router.get("/chat/sessions", response_model=List[SessionSummary])
def list_chat_sessions(
    limit: int = 50,
    db: Session = Depends(get_db),
) -> List[SessionSummary]:
    """List recent conversation sessions for sidebar navigation."""
    return ChatbotService.list_sessions(db=db, limit=limit)


@router.get("/chat/sessions/{session_id}", response_model=SessionDetailResponse)
def get_session_details(
    session_id: str,
    db: Session = Depends(get_db),
) -> SessionDetailResponse:
    """Retrieve full conversation history for a specific session."""
    session_data = ChatbotService.get_session_details(db=db, session_id=session_id)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Chat session '{session_id}' not found.",
        )
    return session_data

