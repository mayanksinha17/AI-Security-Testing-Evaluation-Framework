"""Evaluation Service coordinating model comparison across all 30 attack scenarios.

Executes and benchmarks:
30 attack scenarios × 2 providers (Claude, Gemini) × 2 stages (BASELINE, POST_MITIGATION)
= up to 120 execution records.

Calculates security metrics, model comparative resilience, risk breakdowns,
and provides CSV export functionality.
"""

import csv
from datetime import datetime, timezone
import io
import json
from typing import Any, Dict, List, Optional, Tuple
import uuid
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.attacks.engine import AttackTestingEngine
from app.attacks.evaluator import AttackEvaluator
from app.attacks.scenarios import (
    AttackScenario,
    get_all_risks,
    get_all_scenarios,
    get_scenario_by_id,
    get_scenarios_by_risk,
)
from app.core.config import settings
from app.database.models import (
    AttackResult,
    AttackRun,
    EvaluationMetric,
    EvaluationRun,
    ModelComparison,
    SecurityAuditLog,
)
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


class EvaluationService:
    """Core evaluation and model comparison service for Phase 7."""

    @classmethod
    def check_provider_availability(cls) -> List[ProviderAvailabilitySchema]:
        """Verifies API key availability without printing or exposing key values."""
        has_claude = bool(settings.anthropic_api_key and settings.anthropic_api_key.strip())
        has_gemini = bool(settings.gemini_api_key and settings.gemini_api_key.strip())
        mode = (settings.ai_provider_mode or "mock").lower().strip()

        claude_status = "Configured" if has_claude else "Missing"
        gemini_status = "Configured" if has_gemini else "Missing"

        claude_mode = "live" if (mode == "live" and has_claude) else "mock"
        gemini_mode = "live" if (mode == "live" and has_gemini) else "mock"

        return [
            ProviderAvailabilitySchema(
                provider="claude",
                name="Anthropic Claude",
                model_id=settings.claude_model,
                is_live_available=has_claude,
                execution_mode=claude_mode,
                credential_status=claude_status,
                description="Anthropic Claude Sonnet 5.5 reasoning provider",
            ),
            ProviderAvailabilitySchema(
                provider="gemini",
                name="Google Gemini",
                model_id=settings.gemini_model,
                is_live_available=has_gemini,
                execution_mode=gemini_mode,
                credential_status=gemini_status,
                description="Google Gemini 3.8 Flash high-performance multimodal provider",
            ),
        ]

    @classmethod
    def get_models_status(cls) -> List[ProviderAvailabilitySchema]:
        return cls.check_provider_availability()

    @classmethod
    def get_overview(cls, db: Session) -> EvaluationOverviewResponse:
        """Retrieves high-level evaluation metrics, comparison summaries, and coverage."""
        providers = cls.check_provider_availability()
        total_eval_runs = db.query(func.count(EvaluationRun.id)).scalar() or 0

        latest_run = (
            db.query(EvaluationRun)
            .order_by(EvaluationRun.created_at.desc())
            .first()
        )

        metrics = cls.calculate_metrics(db=db, run_id=latest_run.id if latest_run else None)
        model_metrics = cls.calculate_model_metrics(db=db, run_id=latest_run.id if latest_run else None)

        all_scenarios = get_all_scenarios()
        all_risks = get_all_risks()

        coverage = {
            "total_defined_scenarios": len(all_scenarios),
            "total_defined_risks": len(all_risks),
            "total_matrix_cells": len(all_scenarios) * 2 * 2,  # 30 scenarios * 2 models * 2 stages = 120
            "scenarios_evaluated": metrics.total_executed,
            "coverage_percentage": round((metrics.total_executed / 120.0 * 100), 1) if metrics.total_executed else 0.0,
            "mock_mode_operational": True,
            "live_mode_available": any(p.is_live_available for p in providers),
        }

        return EvaluationOverviewResponse(
            total_evaluation_runs=total_eval_runs,
            latest_run_id=latest_run.id if latest_run else None,
            execution_mode=latest_run.execution_mode if latest_run else settings.ai_provider_mode,
            providers=providers,
            security_metrics=metrics,
            model_comparison=model_metrics,
            coverage_summary=coverage,
        )

    @classmethod
    def calculate_metrics(cls, db: Session, run_id: Optional[str] = None) -> SecurityMetricsSchema:
        """Calculates security metrics adhering to Phase 7 guidelines (NOT_RUN & ERROR not counted as BLOCKED)."""
        query = db.query(AttackResult)
        if run_id:
            query = query.filter(AttackResult.run_id == run_id)

        results = query.all()
        if not results:
            # Fallback to general attack results in database
            results = db.query(AttackResult).all()

        if not results:
            return SecurityMetricsSchema()

        total = len(results)
        blocked = sum(1 for r in results if r.result_classification == "BLOCKED")
        partial = sum(1 for r in results if r.result_classification == "PARTIAL")
        succeeded = sum(1 for r in results if r.result_classification == "SUCCEEDED")
        errors = sum(1 for r in results if r.result_classification == "ERROR")
        not_run = sum(1 for r in results if r.result_classification == "NOT_RUN")

        baseline_results = [r for r in results if r.stage == "BASELINE"]
        post_results = [r for r in results if r.stage == "POST_MITIGATION"]

        base_blocked = sum(1 for r in baseline_results if r.result_classification == "BLOCKED")
        post_blocked = sum(1 for r in post_results if r.result_classification == "BLOCKED")

        base_rate = round((base_blocked / len(baseline_results) * 100), 1) if baseline_results else 0.0
        post_rate = round((post_blocked / len(post_results) * 100), 1) if post_results else 0.0
        overall_rate = round((blocked / total * 100), 1) if total else 0.0

        improvement = round(post_rate - base_rate, 1)

        return SecurityMetricsSchema(
            total_executed=total,
            total_blocked=blocked,
            total_partial=partial,
            total_succeeded=succeeded,
            total_errors=errors,
            total_not_run=not_run,
            overall_block_rate=overall_rate,
            baseline_block_rate=base_rate,
            post_mitigation_block_rate=post_rate,
            mitigation_improvement=improvement,
        )

    @classmethod
    def calculate_model_metrics(cls, db: Session, run_id: Optional[str] = None) -> Dict[str, ModelMetricSchema]:
        """Calculates performance and resilience metrics broken down by model provider."""
        query = db.query(AttackResult)
        if run_id:
            query = query.filter(AttackResult.run_id == run_id)

        all_results = query.all()
        if not all_results:
            all_results = db.query(AttackResult).all()

        metrics_map: Dict[str, ModelMetricSchema] = {}
        for provider_id, model_name in [("claude", settings.claude_model), ("gemini", settings.gemini_model)]:
            prov_results = [r for r in all_results if r.provider.lower() == provider_id]
            total_prov = len(prov_results)

            if total_prov == 0:
                metrics_map[provider_id] = ModelMetricSchema(
                    provider=provider_id,
                    model_id=model_name,
                    execution_mode="mock",
                    tested_count=0,
                )
                continue

            base_res = [r for r in prov_results if r.stage == "BASELINE"]
            post_res = [r for r in prov_results if r.stage == "POST_MITIGATION"]

            base_blocked = sum(1 for r in base_res if r.result_classification == "BLOCKED")
            post_blocked = sum(1 for r in post_res if r.result_classification == "BLOCKED")
            overall_blocked = sum(1 for r in prov_results if r.result_classification == "BLOCKED")
            partial_count = sum(1 for r in prov_results if r.result_classification == "PARTIAL")
            succeeded_count = sum(1 for r in prov_results if r.result_classification == "SUCCEEDED")
            error_count = sum(1 for r in prov_results if r.result_classification == "ERROR")

            latencies = [r.latency_ms for r in prov_results if r.latency_ms is not None]
            avg_lat = round(sum(latencies) / len(latencies), 1) if latencies else 0.0

            metrics_map[provider_id] = ModelMetricSchema(
                provider=provider_id,
                model_id=model_name,
                execution_mode="mock" if not prov_results else prov_results[0].execution_mode,
                tested_count=total_prov,
                baseline_blocked=base_blocked,
                baseline_block_rate=round((base_blocked / len(base_res) * 100), 1) if base_res else 0.0,
                post_blocked=post_blocked,
                post_block_rate=round((post_blocked / len(post_res) * 100), 1) if post_res else 0.0,
                overall_block_rate=round((overall_blocked / total_prov * 100), 1),
                partial_rate=round((partial_count / total_prov * 100), 1),
                succeeded_rate=round((succeeded_count / total_prov * 100), 1),
                error_rate=round((error_count / total_prov * 100), 1),
                avg_latency_ms=avg_lat,
            )

        return metrics_map

    @classmethod
    def get_comparisons(
        cls,
        db: Session,
        run_id: Optional[str] = None,
        stage: Optional[str] = None,
    ) -> List[ModelComparisonItemSchema]:
        """Returns scenario-by-scenario comparative matrix across Claude and Gemini."""
        if run_id:
            comparisons = (
                db.query(ModelComparison)
                .filter(ModelComparison.evaluation_run_id == run_id)
                .order_by(ModelComparison.scenario_id.asc())
                .all()
            )
            if comparisons:
                items = []
                for c in comparisons:
                    if stage and c.stage != stage.upper():
                        continue
                    items.append(
                        ModelComparisonItemSchema(
                            scenario_id=c.scenario_id,
                            risk_id=c.risk_id,
                            category=c.category,
                            scenario_name=c.scenario_name,
                            stage=c.stage,
                            claude_classification=c.claude_classification,
                            claude_latency_ms=c.claude_latency_ms,
                            claude_reason=c.claude_reason,
                            gemini_classification=c.gemini_classification,
                            gemini_latency_ms=c.gemini_latency_ms,
                            gemini_reason=c.gemini_reason,
                            comparative_verdict=c.comparative_verdict,
                        )
                    )
                return items

        # Synthesize comparisons dynamically from available AttackResults
        all_scenarios = get_all_scenarios()
        all_results = db.query(AttackResult).all()

        comparisons_out: List[ModelComparisonItemSchema] = []
        target_stages = [stage.upper()] if stage else ["BASELINE", "POST_MITIGATION"]

        for stg in target_stages:
            for sc in all_scenarios:
                c_res = next(
                    (r for r in all_results if r.scenario_id == sc.scenario_id and r.provider.lower() == "claude" and r.stage == stg),
                    None,
                )
                g_res = next(
                    (r for r in all_results if r.scenario_id == sc.scenario_id and r.provider.lower() == "gemini" and r.stage == stg),
                    None,
                )

                claude_cls = c_res.result_classification if c_res else "NOT_RUN"
                gemini_cls = g_res.result_classification if g_res else "NOT_RUN"

                # Calculate comparative verdict
                if claude_cls == "BLOCKED" and gemini_cls == "BLOCKED":
                    verdict = "Both Protected"
                elif claude_cls == "BLOCKED" and gemini_cls != "BLOCKED":
                    verdict = "Claude More Resilient"
                elif gemini_cls == "BLOCKED" and claude_cls != "BLOCKED":
                    verdict = "Gemini More Resilient"
                elif claude_cls == "SUCCEEDED" and gemini_cls == "SUCCEEDED":
                    verdict = "Both Vulnerable"
                elif claude_cls == "ERROR" or gemini_cls == "ERROR":
                    verdict = "Execution Error"
                else:
                    verdict = "Not Evaluated" if (claude_cls == "NOT_RUN" or gemini_cls == "NOT_RUN") else "Divergent Resistance"

                comparisons_out.append(
                    ModelComparisonItemSchema(
                        scenario_id=sc.scenario_id,
                        risk_id=sc.risk_id,
                        category=sc.category,
                        scenario_name=sc.scenario_name,
                        stage=stg,
                        claude_classification=claude_cls,
                        claude_latency_ms=c_res.latency_ms if c_res else None,
                        claude_reason=c_res.evaluation_reason if c_res else None,
                        gemini_classification=gemini_cls,
                        gemini_latency_ms=g_res.latency_ms if g_res else None,
                        gemini_reason=g_res.evaluation_reason if g_res else None,
                        comparative_verdict=verdict,
                    )
                )

        return comparisons_out

    @classmethod
    def get_risk_breakdown(cls, db: Session, run_id: Optional[str] = None) -> List[RiskBreakdownItemSchema]:
        """Calculates risk-specific performance and improvements across all 10 OWASP risks."""
        risks = get_all_risks()
        all_results = db.query(AttackResult).all()
        if run_id:
            all_results = [r for r in all_results if r.run_id == run_id]

        breakdown: List[RiskBreakdownItemSchema] = []

        for rk in risks:
            r_results = [r for r in all_results if r.risk_id == rk.risk_id]
            c_base = [r for r in r_results if r.provider.lower() == "claude" and r.stage == "BASELINE"]
            c_post = [r for r in r_results if r.provider.lower() == "claude" and r.stage == "POST_MITIGATION"]
            g_base = [r for r in r_results if r.provider.lower() == "gemini" and r.stage == "BASELINE"]
            g_post = [r for r in r_results if r.provider.lower() == "gemini" and r.stage == "POST_MITIGATION"]

            cb_blocked = sum(1 for r in c_base if r.result_classification == "BLOCKED")
            cp_blocked = sum(1 for r in c_post if r.result_classification == "BLOCKED")
            gb_blocked = sum(1 for r in g_base if r.result_classification == "BLOCKED")
            gp_blocked = sum(1 for r in g_post if r.result_classification == "BLOCKED")

            total_c = len(c_base) + len(c_post)
            total_g = len(g_base) + len(g_post)

            c_rate = round((cp_blocked / len(c_post) * 100), 1) if c_post else 0.0
            g_rate = round((gp_blocked / len(g_post) * 100), 1) if g_post else 0.0

            # Baseline vs Post improvement points (average between both models)
            c_base_rate = (cb_blocked / len(c_base) * 100) if c_base else 0.0
            g_base_rate = (gb_blocked / len(g_base) * 100) if g_base else 0.0
            avg_base_rate = (c_base_rate + g_base_rate) / 2.0
            avg_post_rate = (c_rate + g_rate) / 2.0
            improvement = round(avg_post_rate - avg_base_rate, 1)

            breakdown.append(
                RiskBreakdownItemSchema(
                    risk_id=rk.risk_id,
                    risk_name=rk.risk_name,
                    category=rk.category,
                    tested_count=len(r_results),
                    claude_baseline_blocked=cb_blocked,
                    claude_post_blocked=cp_blocked,
                    gemini_baseline_blocked=gb_blocked,
                    gemini_post_blocked=gp_blocked,
                    claude_block_rate=c_rate,
                    gemini_block_rate=g_rate,
                    improvement_points=improvement,
                )
            )

        return breakdown

    @classmethod
    def get_history(cls, db: Session) -> List[EvaluationRunSummarySchema]:
        """Returns past evaluation runs in reverse chronological order."""
        runs = db.query(EvaluationRun).order_by(EvaluationRun.created_at.desc()).all()
        return [
            EvaluationRunSummarySchema(
                id=r.id,
                title=r.title,
                status=r.status,
                execution_mode=r.execution_mode,
                claude_model=r.claude_model,
                gemini_model=r.gemini_model,
                total_scenarios=r.total_scenarios,
                total_executions=r.total_executions,
                overall_block_rate=r.overall_block_rate,
                claude_block_rate=r.claude_block_rate,
                gemini_block_rate=r.gemini_block_rate,
                mitigation_improvement=r.mitigation_improvement,
                average_latency_ms=r.average_latency_ms,
                not_run_count=r.not_run_count,
                created_at=r.created_at.isoformat(),
                completed_at=r.completed_at.isoformat() if r.completed_at else None,
                notes=r.notes,
            )
            for r in runs
        ]

    @classmethod
    def get_run_detail(cls, db: Session, run_id: str) -> DetailedEvaluationRunResponse:
        """Returns complete granular details, comparisons, and metrics for a specific evaluation run."""
        run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
        if not run:
            raise ValueError(f"EvaluationRun '{run_id}' not found.")

        summary = EvaluationRunSummarySchema(
            id=run.id,
            title=run.title,
            status=run.status,
            execution_mode=run.execution_mode,
            claude_model=run.claude_model,
            gemini_model=run.gemini_model,
            total_scenarios=run.total_scenarios,
            total_executions=run.total_executions,
            overall_block_rate=run.overall_block_rate,
            claude_block_rate=run.claude_block_rate,
            gemini_block_rate=run.gemini_block_rate,
            mitigation_improvement=run.mitigation_improvement,
            average_latency_ms=run.average_latency_ms,
            not_run_count=run.not_run_count,
            created_at=run.created_at.isoformat(),
            completed_at=run.completed_at.isoformat() if run.completed_at else None,
            notes=run.notes,
        )

        metrics = cls.calculate_metrics(db=db, run_id=run.id)
        model_metrics = cls.calculate_model_metrics(db=db, run_id=run.id)
        comparisons = cls.get_comparisons(db=db, run_id=run.id)
        breakdown = cls.get_risk_breakdown(db=db, run_id=run.id)

        return DetailedEvaluationRunResponse(
            run_summary=summary,
            security_metrics=metrics,
            model_metrics=model_metrics,
            comparisons=comparisons,
            risk_breakdown=breakdown,
        )

    @classmethod
    async def run_evaluation(cls, db: Session, request: EvaluationRunRequest) -> EvaluationRunSummarySchema:
        """Executes a complete reproducible evaluation matrix across Claude and Gemini."""
        run_id = str(uuid.uuid4())
        created_time = datetime.now(timezone.utc)

        # 1. Resolve Scenarios
        if request.scenario_ids:
            scenarios: List[AttackScenario] = []
            for s_id in request.scenario_ids:
                sc = get_scenario_by_id(s_id)
                if sc:
                    scenarios.append(sc)
        else:
            scenarios = get_all_scenarios()

        if not scenarios:
            raise ValueError("No attack scenarios found matching evaluation criteria.")

        # Batch limit: max 30 scenarios per evaluation
        MAX_SCENARIOS = 30
        scenarios = scenarios[:MAX_SCENARIOS]

        # 2. Check Providers and Live Availability
        providers_req = [p.lower().strip() for p in (request.providers or ["claude", "gemini"])]
        availability = {p.provider: p for p in cls.check_provider_availability()}

        is_live_requested = request.execution_mode.lower() == "live"
        exec_mode = "live" if is_live_requested else "mock"

        # 3. Determine Stages
        req_stage = (request.stage or "BOTH").upper()
        stages_to_run = ["BASELINE", "POST_MITIGATION"] if req_stage == "BOTH" else [req_stage]

        # Tracking accumulators
        claude_cb = {"blocked": 0, "partial": 0, "succeeded": 0, "error": 0}
        claude_cp = {"blocked": 0, "partial": 0, "succeeded": 0, "error": 0}
        gemini_cb = {"blocked": 0, "partial": 0, "succeeded": 0, "error": 0}
        gemini_cp = {"blocked": 0, "partial": 0, "succeeded": 0, "error": 0}
        not_run_count = 0
        total_executions = 0
        all_latencies: List[float] = []

        # 4. Execute Matrix: Scenarios × Providers × Stages
        for stg in stages_to_run:
            for sc in scenarios:
                stage_claude_res = None
                stage_gemini_res = None

                for prov in providers_req:
                    # Check if live mode was requested without credentials
                    if is_live_requested and not availability.get(prov, False).is_live_available:
                        # Mark as NOT_RUN per instructions
                        res_rec = AttackResult(
                            id=str(uuid.uuid4()),
                            run_id=run_id,
                            scenario_id=sc.scenario_id,
                            risk_id=sc.risk_id,
                            provider=prov,
                            model=settings.claude_model if prov == "claude" else settings.gemini_model,
                            execution_mode="live",
                            stage=stg,
                            prompt=sc.attack_prompt,
                            response_content=None,
                            tool_calls="[]",
                            result_classification="NOT_RUN",
                            evaluation_reason=f"Live API credentials for {prov.title()} are not configured.",
                            latency_ms=0.0,
                            created_at=datetime.now(timezone.utc),
                        )
                        db.add(res_rec)
                        not_run_count += 1
                        total_executions += 1
                        if prov == "claude":
                            stage_claude_res = res_rec
                        else:
                            stage_gemini_res = res_rec
                        continue

                    # Execute scenario via AttackTestingEngine
                    result = await AttackTestingEngine.execute_scenario(
                        db=db,
                        scenario=sc,
                        provider=prov,
                        stage=stg,
                        run_id=run_id,
                    )
                    total_executions += 1
                    if result.latency_ms is not None:
                        all_latencies.append(result.latency_ms)

                    cls_name = result.result_classification
                    if prov == "claude":
                        stage_claude_res = result
                        acc = claude_cp if stg == "POST_MITIGATION" else claude_cb
                        if cls_name == "BLOCKED":
                            acc["blocked"] += 1
                        elif cls_name == "PARTIAL":
                            acc["partial"] += 1
                        elif cls_name == "SUCCEEDED":
                            acc["succeeded"] += 1
                        elif cls_name == "ERROR":
                            acc["error"] += 1
                    elif prov == "gemini":
                        stage_gemini_res = result
                        acc = gemini_cp if stg == "POST_MITIGATION" else gemini_cb
                        if cls_name == "BLOCKED":
                            acc["blocked"] += 1
                        elif cls_name == "PARTIAL":
                            acc["partial"] += 1
                        elif cls_name == "SUCCEEDED":
                            acc["succeeded"] += 1
                        elif cls_name == "ERROR":
                            acc["error"] += 1

                # Create ModelComparison record for this scenario
                c_cls = stage_claude_res.result_classification if stage_claude_res else "NOT_RUN"
                g_cls = stage_gemini_res.result_classification if stage_gemini_res else "NOT_RUN"

                if c_cls == "BLOCKED" and g_cls == "BLOCKED":
                    verdict = "Both Protected"
                elif c_cls == "BLOCKED" and g_cls != "BLOCKED":
                    verdict = "Claude More Resilient"
                elif g_cls == "BLOCKED" and c_cls != "BLOCKED":
                    verdict = "Gemini More Resilient"
                elif c_cls == "SUCCEEDED" and g_cls == "SUCCEEDED":
                    verdict = "Both Vulnerable"
                elif c_cls == "ERROR" or g_cls == "ERROR":
                    verdict = "Execution Error"
                else:
                    verdict = "Not Evaluated" if (c_cls == "NOT_RUN" or g_cls == "NOT_RUN") else "Divergent Resistance"

                comp_rec = ModelComparison(
                    id=str(uuid.uuid4()),
                    evaluation_run_id=run_id,
                    scenario_id=sc.scenario_id,
                    risk_id=sc.risk_id,
                    category=sc.category,
                    scenario_name=sc.scenario_name,
                    stage=stg,
                    claude_classification=c_cls,
                    claude_latency_ms=stage_claude_res.latency_ms if stage_claude_res else None,
                    claude_reason=stage_claude_res.evaluation_reason if stage_claude_res else None,
                    gemini_classification=g_cls,
                    gemini_latency_ms=stage_gemini_res.latency_ms if stage_gemini_res else None,
                    gemini_reason=stage_gemini_res.evaluation_reason if stage_gemini_res else None,
                    comparative_verdict=verdict,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(comp_rec)

        db.commit()

        # 5. Calculate Final Rates & Improvement
        c_total = sum(claude_cb.values()) + sum(claude_cp.values())
        g_total = sum(gemini_cb.values()) + sum(gemini_cp.values())
        c_blocked_total = claude_cb["blocked"] + claude_cp["blocked"]
        g_blocked_total = gemini_cb["blocked"] + gemini_cp["blocked"]

        c_rate = round((c_blocked_total / c_total * 100), 1) if c_total else 0.0
        g_rate = round((g_blocked_total / g_total * 100), 1) if g_total else 0.0
        overall_blocked = c_blocked_total + g_blocked_total
        all_executed = total_executions - not_run_count
        overall_rate = round((overall_blocked / all_executed * 100), 1) if all_executed else 0.0

        # Calculate mitigation improvement in percentage points
        base_blocked = claude_cb["blocked"] + gemini_cb["blocked"]
        base_total = sum(claude_cb.values()) + sum(gemini_cb.values())
        post_blocked = claude_cp["blocked"] + gemini_cp["blocked"]
        post_total = sum(claude_cp.values()) + sum(gemini_cp.values())

        base_rate = (base_blocked / base_total * 100) if base_total else 0.0
        post_rate = (post_blocked / post_total * 100) if post_total else 0.0
        improvement = round(post_rate - base_rate, 1)

        avg_lat = round(sum(all_latencies) / len(all_latencies), 1) if all_latencies else 0.0

        notes = (
            f"Evaluated {len(scenarios)} scenarios across {len(providers_req)} providers in {req_stage} stage(s). "
            f"Execution Mode: {exec_mode.upper()}."
        )
        if not_run_count > 0:
            notes += f" Note: {not_run_count} live scenario(s) marked as NOT_RUN due to missing API credentials."

        # 6. Save EvaluationRun Record
        eval_run = EvaluationRun(
            id=run_id,
            title=request.title or f"Evaluation Run {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}",
            status="completed",
            execution_mode=exec_mode,
            claude_model=settings.claude_model,
            gemini_model=settings.gemini_model,
            total_scenarios=len(scenarios),
            total_executions=total_executions,
            claude_baseline_blocked=claude_cb["blocked"],
            claude_baseline_partial=claude_cb["partial"],
            claude_baseline_succeeded=claude_cb["succeeded"],
            claude_baseline_errors=claude_cb["error"],
            claude_post_blocked=claude_cp["blocked"],
            claude_post_partial=claude_cp["partial"],
            claude_post_succeeded=claude_cp["succeeded"],
            claude_post_errors=claude_cp["error"],
            gemini_baseline_blocked=gemini_cb["blocked"],
            gemini_baseline_partial=gemini_cb["partial"],
            gemini_baseline_succeeded=gemini_cb["succeeded"],
            gemini_baseline_errors=gemini_cb["error"],
            gemini_post_blocked=gemini_cp["blocked"],
            gemini_post_partial=gemini_cp["partial"],
            gemini_post_succeeded=gemini_cp["succeeded"],
            gemini_post_errors=gemini_cp["error"],
            not_run_count=not_run_count,
            claude_block_rate=c_rate,
            gemini_block_rate=g_rate,
            overall_block_rate=overall_rate,
            mitigation_improvement=improvement,
            average_latency_ms=avg_lat,
            notes=notes,
            created_at=created_time,
            completed_at=datetime.now(timezone.utc),
        )
        db.add(eval_run)
        db.commit()
        db.refresh(eval_run)

        return EvaluationRunSummarySchema(
            id=eval_run.id,
            title=eval_run.title,
            status=eval_run.status,
            execution_mode=eval_run.execution_mode,
            claude_model=eval_run.claude_model,
            gemini_model=eval_run.gemini_model,
            total_scenarios=eval_run.total_scenarios,
            total_executions=eval_run.total_executions,
            overall_block_rate=eval_run.overall_block_rate,
            claude_block_rate=eval_run.claude_block_rate,
            gemini_block_rate=eval_run.gemini_block_rate,
            mitigation_improvement=eval_run.mitigation_improvement,
            average_latency_ms=eval_run.average_latency_ms,
            not_run_count=eval_run.not_run_count,
            created_at=eval_run.created_at.isoformat(),
            completed_at=eval_run.completed_at.isoformat() if eval_run.completed_at else None,
            notes=eval_run.notes,
        )

    @classmethod
    def export_csv(
        cls,
        db: Session,
        run_id: Optional[str] = None,
        stage: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> str:
        """Generates standard CSV output reflecting database records."""
        query = db.query(AttackResult)
        if run_id:
            query = query.filter(AttackResult.run_id == run_id)
        if stage:
            query = query.filter(AttackResult.stage == stage.upper())
        if provider:
            query = query.filter(AttackResult.provider == provider.lower())

        results = query.order_by(AttackResult.created_at.asc()).all()

        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")

        # Required headers per Phase 7 specification:
        # Risk ID, Scenario ID, Model, Model ID, Execution Mode, Stage, Prompt, Result, Latency (ms), Timestamp
        writer.writerow([
            "Risk ID",
            "Scenario ID",
            "Model",
            "Model ID",
            "Execution Mode",
            "Stage",
            "Prompt",
            "Result",
            "Latency (ms)",
            "Timestamp",
        ])

        for r in results:
            writer.writerow([
                r.risk_id,
                r.scenario_id,
                r.provider.title(),
                r.model,
                r.execution_mode.upper(),
                r.stage,
                r.prompt,
                r.result_classification,
                f"{r.latency_ms:.2f}" if r.latency_ms is not None else "0.00",
                r.created_at.isoformat() if r.created_at else "",
            ])

        return output.getvalue()

