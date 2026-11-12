from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["system"])


class HealthResponse(BaseModel):
    status: str
    application: str
    timestamp: datetime


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        application="AI Security POC",
        timestamp=datetime.now(timezone.utc),
    )
