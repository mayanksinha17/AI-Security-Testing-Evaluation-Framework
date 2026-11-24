import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.attacks.engine import AttackTestingEngine
from app.attacks.export import generate_batch_csv, generate_batch_pdf, resolve_risk_info
from app.attacks.scenarios import (
    get_all_risks,
    get_all_scenarios,
    get_scenario_by_id,
    get_scenarios_by_risk,
)
from app.attacks.schemas import (
    AttackBatchRunRequest,
    AttackResultSchema,
    AttackRunRequest,
    AttackRunResponse,
    AttackScenarioSchema,
    AttackSummaryStats,
    RiskCategorySchema,
)
from app.database.models import AttackResult, AttackRun
from app.database.session import get_db

router = APIRouter(prefix="/attacks", tags=["Attack Testing Engine"])


def _format_result(r: AttackResult) -> AttackResultSchema:
    tool_calls_data = []
    if r.tool_calls:
        try:
            tool_calls_data = json.loads(r.tool_calls)
        except Exception:
            tool_calls_data = [{"raw": r.tool_calls}]

    return AttackResultSchema(
        id=r.id,
        run_id=r.run_id,
        scenario_id=r.scenario_id,
        risk_id=r.risk_id,
        provider=r.provider,
        model=r.model,
        execution_mode=r.execution_mode,
        stage=r.stage,
        prompt=r.prompt,
        response_content=r.response_content,
        tool_calls=tool_calls_data,
        result_classification=r.result_classification,
        evaluation_reason=r.evaluation_reason,
        latency_ms=r.latency_ms,
        error_details=r.error_details,
        created_at=r.created_at.isoformat() if r.created_at else "",
    )


@router.get("/risks", response_model=List[RiskCategorySchema])
def list_risks() -> List[RiskCategorySchema]:
    """Returns all 10 OWASP risk categories (5 LLM Risks + 5 Agentic AI Risks)."""
    risks = get_all_risks()
    return [
        RiskCategorySchema(
            risk_id=r.risk_id,
            risk_name=r.risk_name,
            category=r.category,
            description=r.description,
        )
        for r in risks
    ]


@router.get("/scenarios", response_model=List[AttackScenarioSchema])
def list_scenarios(risk_id: Optional[str] = Query(None, description="Filter by risk code (e.g. 'LLM01')")) -> List[AttackScenarioSchema]:
    """Returns all 30 attack scenarios or filtered by risk code."""
    if risk_id:
        scenarios = get_scenarios_by_risk(risk_id)
    else:
        scenarios = get_all_scenarios()

    return [AttackScenarioSchema(**s.to_dict()) for s in scenarios]


@router.get("/scenarios/{scenario_id}", response_model=AttackScenarioSchema)
def get_scenario(scenario_id: str) -> AttackScenarioSchema:
    """Retrieves full specification of an attack scenario by ID."""
    sc = get_scenario_by_id(scenario_id)
    if not sc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack scenario '{scenario_id}' not found.",
        )
    return AttackScenarioSchema(**sc.to_dict())


@router.post("/run", response_model=AttackResultSchema)
async def run_single_attack(
    request: AttackRunRequest,
    db: Session = Depends(get_db),
) -> AttackResultSchema:
    """Executes a single attack scenario against Claude or Gemini, evaluating security behavior."""
    sc = get_scenario_by_id(request.scenario_id)
    if not sc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack scenario '{request.scenario_id}' not found.",
        )

    result = await AttackTestingEngine.execute_scenario(
        db=db,
        scenario=sc,
        provider=request.provider or "claude",
        model=request.model,
        stage=request.stage or "BASELINE",
        role=request.role or "analyst",
    )
    return _format_result(result)


@router.post("/run-batch", response_model=AttackRunResponse)
async def run_batch_attacks(
    request: AttackBatchRunRequest,
    db: Session = Depends(get_db),
) -> AttackRunResponse:
    """Executes a controlled batch of attack scenarios with safety limit enforcement."""
    try:
        attack_run = await AttackTestingEngine.execute_batch(db=db, request=request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch execution failed: {str(e)}",
        )

    results_formatted = [_format_result(r) for r in attack_run.results]
    total_duration = round(sum((r.latency_ms or 0.0) for r in attack_run.results), 2)
    return AttackRunResponse(
        id=attack_run.id,
        provider=attack_run.provider,
        model=attack_run.model,
        stage=attack_run.stage,
        execution_mode=attack_run.execution_mode,
        total_scenarios=attack_run.total_scenarios,
        blocked_count=attack_run.blocked_count,
        partial_count=attack_run.partial_count,
        succeeded_count=attack_run.succeeded_count,
        error_count=attack_run.error_count,
        created_at=attack_run.created_at.isoformat() if attack_run.created_at else "",
        risk_id=request.risk_id,
        duration_ms=total_duration,
        results=results_formatted,
    )


@router.get("/results", response_model=List[AttackResultSchema])
def list_results(
    limit: int = Query(50, ge=1, le=200),
    stage: Optional[str] = Query(None, description="'BASELINE' or 'POST_MITIGATION'"),
    risk_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> List[AttackResultSchema]:
    """Lists recent individual attack results with optional filtering."""
    query = db.query(AttackResult)
    if stage:
        query = query.filter(AttackResult.stage == stage.upper())
    if risk_id:
        query = query.filter(AttackResult.risk_id == risk_id.upper())
    if provider:
        query = query.filter(AttackResult.provider == provider.lower())

    results = query.order_by(desc(AttackResult.created_at)).limit(limit).all()
    return [_format_result(r) for r in results]


@router.get("/results/{run_id}", response_model=AttackRunResponse)
def get_run_results(
    run_id: str,
    db: Session = Depends(get_db),
) -> AttackRunResponse:
    """Retrieves full details and scenario results of a specific attack run."""
    run = db.query(AttackRun).filter(AttackRun.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack run '{run_id}' not found.",
        )

    results_formatted = [_format_result(r) for r in run.results]
    return AttackRunResponse(
        id=run.id,
        provider=run.provider,
        model=run.model,
        stage=run.stage,
        execution_mode=run.execution_mode,
        total_scenarios=run.total_scenarios,
        blocked_count=run.blocked_count,
        partial_count=run.partial_count,
        succeeded_count=run.succeeded_count,
        error_count=run.error_count,
        created_at=run.created_at.isoformat() if run.created_at else "",
        results=results_formatted,
    )


@router.get("/runs/{run_id}/export/pdf")
@router.get("/results/{run_id}/export/pdf")
def export_run_pdf(
    run_id: str,
    db: Session = Depends(get_db),
):
    """Generates and downloads a professional ReportLab PDF assessment report for a specific AttackRun."""
    run = db.query(AttackRun).filter(AttackRun.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack run '{run_id}' not found.",
        )

    risk_code, _ = resolve_risk_info(run.results)
    safe_risk = risk_code.replace(" ", "_")
    filename = f"ApexShield_{safe_risk}_Assessment_{run.id}.pdf"

    pdf_bytes = generate_batch_pdf(run)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


@router.get("/runs/{run_id}/export/csv")
@router.get("/results/{run_id}/export/csv")
def export_run_csv(
    run_id: str,
    db: Session = Depends(get_db),
):
    """Exports only the scenarios belonging to the selected AttackRun in RFC-4180 CSV format."""
    run = db.query(AttackRun).filter(AttackRun.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack run '{run_id}' not found.",
        )

    risk_code, _ = resolve_risk_info(run.results)
    safe_risk = risk_code.replace(" ", "_")
    filename = f"ApexShield_{safe_risk}_Results_{run.id}.csv"

    csv_data = generate_batch_csv(run)
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


@router.get("/summary", response_model=AttackSummaryStats)
def get_attack_summary(db: Session = Depends(get_db)) -> AttackSummaryStats:
    """Returns aggregated attack evaluation metrics across baseline and post-mitigation stages."""
    data = AttackTestingEngine.get_summary(db=db)
    return AttackSummaryStats(**data)

