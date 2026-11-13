"""Pydantic schemas for Phase 7 Comprehensive AI Security Evaluation Framework."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProviderAvailabilitySchema(BaseModel):
    provider: str
    name: str
    model_id: str
    is_live_available: bool
    execution_mode: str
    credential_status: str  # "Configured" or "Missing"
    description: str


class SecurityMetricsSchema(BaseModel):
    total_executed: int = 0
    total_blocked: int = 0
    total_partial: int = 0
    total_succeeded: int = 0
    total_errors: int = 0
    total_not_run: int = 0
    overall_block_rate: float = 0.0
    baseline_block_rate: float = 0.0
    post_mitigation_block_rate: float = 0.0
    mitigation_improvement: float = 0.0  # Percentage points (Post - Baseline)


class ModelMetricSchema(BaseModel):
    provider: str
    model_id: str
    execution_mode: str
    tested_count: int = 0
    baseline_blocked: int = 0
    baseline_block_rate: float = 0.0
    post_blocked: int = 0
    post_block_rate: float = 0.0
    overall_block_rate: float = 0.0
    partial_rate: float = 0.0
    succeeded_rate: float = 0.0
    error_rate: float = 0.0
    avg_latency_ms: float = 0.0


class ModelComparisonItemSchema(BaseModel):
    scenario_id: str
    risk_id: str
    category: str
    scenario_name: str
    stage: str
    claude_classification: str
    claude_latency_ms: Optional[float] = None
    claude_reason: Optional[str] = None
    gemini_classification: str
    gemini_latency_ms: Optional[float] = None
    gemini_reason: Optional[str] = None
    comparative_verdict: str


class RiskBreakdownItemSchema(BaseModel):
    risk_id: str
    risk_name: str
    category: str
    tested_count: int
    claude_baseline_blocked: int
    claude_post_blocked: int
    gemini_baseline_blocked: int
    gemini_post_blocked: int
    claude_block_rate: float
    gemini_block_rate: float
    improvement_points: float


class EvaluationRunRequest(BaseModel):
    title: Optional[str] = "Comprehensive AI Security Evaluation - Claude vs Gemini"
    stage: Optional[str] = "BOTH"  # "BASELINE", "POST_MITIGATION", or "BOTH"
    providers: Optional[List[str]] = ["claude", "gemini"]
    execution_mode: Optional[str] = "mock"  # "mock" or "live"
    scenario_ids: Optional[List[str]] = None


class EvaluationRunSummarySchema(BaseModel):
    id: str
    title: str
    status: str
    execution_mode: str
    claude_model: str
    gemini_model: str
    total_scenarios: int
    total_executions: int
    overall_block_rate: float
    claude_block_rate: float
    gemini_block_rate: float
    mitigation_improvement: float
    average_latency_ms: float
    not_run_count: int
    created_at: str
    completed_at: Optional[str] = None
    notes: Optional[str] = None


class EvaluationOverviewResponse(BaseModel):
    total_evaluation_runs: int
    latest_run_id: Optional[str] = None
    execution_mode: str
    providers: List[ProviderAvailabilitySchema]
    security_metrics: SecurityMetricsSchema
    model_comparison: Dict[str, ModelMetricSchema]
    coverage_summary: Dict[str, Any]


class DetailedEvaluationRunResponse(BaseModel):
    run_summary: EvaluationRunSummarySchema
    security_metrics: SecurityMetricsSchema
    model_metrics: Dict[str, ModelMetricSchema]
    comparisons: List[ModelComparisonItemSchema]
    risk_breakdown: List[RiskBreakdownItemSchema]

