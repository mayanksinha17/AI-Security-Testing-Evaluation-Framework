from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.agent.schemas import (
    AgentRunRequest,
    AgentRunResponse,
    AgentSessionSchema,
    ApproveRequest,
    DenyRequest,
    ResetRequest,
    ToolExecutionSchema,
)
from app.agent.service import AgentService
from app.database.session import get_db
from app.tools.registry import tool_registry

router = APIRouter(prefix="/agent", tags=["Agentic AI"])


@router.post("/run", response_model=AgentRunResponse, status_code=status.HTTP_200_OK)
async def run_agent(
    request: AgentRunRequest,
    db: Session = Depends(get_db),
) -> AgentRunResponse:
    """Execute an agent instruction turn with tool selection, permission evaluation, and execution."""
    try:
        return await AgentService.run(db=db, req=request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent execution failed: {str(e)}",
        )


@router.get("/tools", response_model=List[Dict[str, Any]])
def list_available_tools() -> List[Dict[str, Any]]:
    """List all registered tools available to the agent with parameter schemas and security requirements."""
    return tool_registry.list_tools()


@router.get("/sessions", response_model=List[Dict[str, Any]])
def list_agent_sessions(
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """List recent agent sessions."""
    return AgentService.list_sessions(db=db, limit=limit)


@router.get("/sessions/{session_id}", response_model=AgentSessionSchema)
def get_agent_session(
    session_id: str,
    db: Session = Depends(get_db),
) -> AgentSessionSchema:
    """Retrieve full details of an agent session, including conversation messages and tool executions."""
    session_data = AgentService.get_session(db=db, session_id=session_id)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent session '{session_id}' not found.",
        )
    return session_data


@router.get("/history", response_model=List[ToolExecutionSchema])
def get_agent_history(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> List[ToolExecutionSchema]:
    """Retrieve tool execution logs across sessions for audit trail and timeline display."""
    return AgentService.get_history(db=db, limit=limit)


@router.post("/approve", response_model=AgentRunResponse)
async def approve_tool_execution(
    request: ApproveRequest,
    db: Session = Depends(get_db),
) -> AgentRunResponse:
    """Approve a paused sensitive action and resume execution."""
    try:
        return await AgentService.approve(db=db, req=request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute approved action: {str(e)}",
        )


@router.post("/deny", response_model=AgentRunResponse)
async def deny_tool_execution(
    request: DenyRequest,
    db: Session = Depends(get_db),
) -> AgentRunResponse:
    """Deny a paused sensitive action and return agent rejection response."""
    try:
        return await AgentService.deny(db=db, req=request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process denial: {str(e)}",
        )


@router.post("/reset", response_model=Dict[str, Any])
def reset_agent_state(
    request: Optional[ResetRequest] = None,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Reset a specific agent session or all agent evaluation states."""
    session_id = request.session_id if request else None
    return AgentService.reset(db=db, session_id=session_id)

