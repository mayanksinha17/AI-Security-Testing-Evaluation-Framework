"""FastAPI routes for Phase 7 Comprehensive AI Security Evaluation & Model Comparison."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.evaluation.schemas import (
    DetailedEvaluationRunResponse,
    EvaluationOverviewResponse,
    EvaluationRunRequest,
    EvaluationRunSummarySchema,
    ModelComparisonItemSchema,
    ModelMetricSchema,
    ProviderAvailabilitySchema,
    RiskBreakdownItemSchema,
    SecurityMetricsSchema,
)
from app.evaluation.service import EvaluationService

router = APIRouter(prefix="/api/evaluation", tags=["Evaluation & Model Comparison"])


@router.get("/overview", response_model=EvaluationOverviewResponse)
def get_evaluation_overview(db: Session = Depends(get_db)):
    """Summary of evaluation status, provider live availability, overall block rates, and coverage."""
    return EvaluationService.get_overview(db=db)


@router.get("/models", response_model=List[ProviderAvailabilitySchema])
def get_models_status():
    """Provider availability status, model IDs, credentials presence (boolean only), and descriptions."""
    return EvaluationService.get_models_status()


@router.get("/metrics", response_model=SecurityMetricsSchema)
def get_evaluation_metrics(
    run_id: Optional[str] = Query(None, description="Optional evaluation run UUID to filter metrics"),
    db: Session = Depends(get_db),
):
    """Deep-dive metrics: total attacks, blocked, partial, succeeded, errors, not_run, improvement."""
    return EvaluationService.calculate_metrics(db=db, run_id=run_id)


@router.get("/comparison", response_model=List[ModelComparisonItemSchema])
def get_model_comparisons(
    run_id: Optional[str] = Query(None, description="Optional evaluation run UUID"),
    stage: Optional[str] = Query(None, description="Optional stage filter (BASELINE or POST_MITIGATION)"),
    db: Session = Depends(get_db),
):
    """Scenario-by-scenario comparative matrix across Claude and Gemini for all 30 scenarios."""
    return EvaluationService.get_comparisons(db=db, run_id=run_id, stage=stage)


@router.get("/risk-breakdown", response_model=List[RiskBreakdownItemSchema])
def get_risk_breakdown(
    run_id: Optional[str] = Query(None, description="Optional evaluation run UUID"),
    db: Session = Depends(get_db),
):
    """Breakdown of results across the 10 OWASP risks comparing Claude and Gemini block rates and improvements."""
    return EvaluationService.get_risk_breakdown(db=db, run_id=run_id)


@router.get("/history", response_model=List[EvaluationRunSummarySchema])
def get_evaluation_history(db: Session = Depends(get_db)):
    """List of all past evaluation runs with summary statistics and timestamps."""
    return EvaluationService.get_history(db=db)


@router.post("/run", response_model=EvaluationRunSummarySchema)
async def run_evaluation(
    request: EvaluationRunRequest,
    db: Session = Depends(get_db),
):
    """Executes a reproducible evaluation run comparing Claude and Gemini across scenarios."""
    try:
        return await EvaluationService.run_evaluation(db=db, request=request)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/run/{run_id}", response_model=DetailedEvaluationRunResponse)
def get_evaluation_run_detail(
    run_id: str,
    db: Session = Depends(get_db),
):
    """Detailed results, metrics, and comparisons for a specific evaluation run."""
    try:
        return EvaluationService.get_run_detail(db=db, run_id=run_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/export")
def export_evaluation_results_csv(
    run_id: Optional[str] = Query(None, description="Optional run UUID filter"),
    stage: Optional[str] = Query(None, description="Optional stage filter"),
    provider: Optional[str] = Query(None, description="Optional provider filter"),
    db: Session = Depends(get_db),
):
    """Exports actual evaluation results to standard CSV."""
    csv_content = EvaluationService.export_csv(db=db, run_id=run_id, stage=stage, provider=provider)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="ai_security_evaluation_results.csv"',
        },
    )

