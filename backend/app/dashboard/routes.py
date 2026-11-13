"""FastAPI routes for Phase 8 Unified AI Security Operations Dashboard."""

from typing import Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dashboard.schemas import (
    AuditLogListResponse,
    DashboardOverviewResponse,
    RiskOverviewResponse,
    SecurityAnalyticsResponse,
)
from app.dashboard.service import DashboardService

router = APIRouter(prefix="/api/dashboard", tags=["Security Operations Dashboard"])


@router.get("/overview", response_model=DashboardOverviewResponse)
def get_dashboard_overview(db: Session = Depends(get_db)):
    """Unified operations overview: 10 risks, 30 scenarios, total executions, BLOCKED/PARTIAL/SUCCEEDED, live/mock."""
    return DashboardService.get_overview(db=db)


@router.get("/risks", response_model=RiskOverviewResponse)
def get_risks_overview(db: Session = Depends(get_db)):
    """Risk overview across all 10 OWASP risks with baseline/post block rates and improvements."""
    return DashboardService.get_risks_overview(db=db)


@router.get("/analytics", response_model=SecurityAnalyticsResponse)
def get_security_analytics(db: Session = Depends(get_db)):
    """Analytical visualizations: baseline vs post, distribution, Claude vs Gemini, timeline, coverage."""
    return DashboardService.get_analytics(db=db)


@router.get("/audit-logs", response_model=AuditLogListResponse)
def get_audit_logs(
    risk_category: Optional[str] = Query(None, description="Filter by risk category (OWASP_LLM or OWASP_AGENTIC)"),
    risk_id: Optional[str] = Query(None, description="Filter by risk ID (e.g. LLM01, ASI02)"),
    provider: Optional[str] = Query(None, description="Filter by model provider"),
    stage: Optional[str] = Query(None, description="Filter by execution stage"),
    decision: Optional[str] = Query(None, description="Filter by security decision (BLOCKED, ALLOWED, etc.)"),
    search: Optional[str] = Query(None, description="Free-text search across reasons and events"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Searchable audit log interface with strict redaction of sensitive credentials and keys."""
    return DashboardService.get_audit_logs(
        db=db,
        risk_category=risk_category,
        risk_id=risk_id,
        provider=provider,
        stage=stage,
        decision=decision,
        search=search,
        limit=limit,
        offset=offset,
    )


# =====================================================================
# CSV Export Endpoints
# =====================================================================

@router.get("/export/attacks")
def export_attacks_csv(db: Session = Depends(get_db)):
    """Exports actual attack execution results to RFC-4180 CSV."""
    csv_data = DashboardService.export_attacks_csv(db=db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="attack_results.csv"'},
    )


@router.get("/export/evaluation")
def export_evaluation_csv(db: Session = Depends(get_db)):
    """Exports model comparison and evaluation results to RFC-4180 CSV."""
    csv_data = DashboardService.export_evaluation_csv(db=db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="evaluation_results.csv"'},
    )


@router.get("/export/audit-logs")
def export_audit_logs_csv(db: Session = Depends(get_db)):
    """Exports security audit records to RFC-4180 CSV with secrets redacted."""
    csv_data = DashboardService.export_audit_logs_csv(db=db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="security_audit_logs.csv"'},
    )


@router.get("/export/risks")
def export_risks_csv(db: Session = Depends(get_db)):
    """Exports risk-by-risk performance summary across all 10 OWASP risks to RFC-4180 CSV."""
    csv_data = DashboardService.export_risks_csv(db=db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="owasp_risk_summary.csv"'},
    )

