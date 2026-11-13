"""Pydantic schemas for Phase 8 Unified AI Security Operations Dashboard."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProviderStatusSchema(BaseModel):
    provider: str
    name: str
    model_id: str
    is_live_available: bool
    execution_mode: str
    credential_status: str


class DashboardOverviewResponse(BaseModel):
    total_risks: int = 10
    total_scenarios: int = 30
    total_executions: int = 0
    total_blocked: int = 0
    total_partial: int = 0
    total_succeeded: int = 0
    total_errors: int = 0
    total_not_run: int = 0
    overall_mitigation_effectiveness: float = 0.0  # Improvement in percentage points
    overall_block_rate: float = 0.0
    baseline_block_rate: float = 0.0
    post_mitigation_block_rate: float = 0.0
    live_vs_mock_status: str = "mock"
    providers: List[ProviderStatusSchema] = Field(default_factory=list)
    data_source: str = "sqlite_actual_records"


class RiskOverviewItem(BaseModel):
    risk_id: str
    risk_name: str
    category: str  # "OWASP_LLM" or "OWASP_AGENTIC"
    scenarios_count: int = 3
    baseline_block_rate: float = 0.0
    post_mitigation_block_rate: float = 0.0
    improvement: float = 0.0  # Percentage points
    remaining_successful_attacks: int = 0
    execution_coverage: float = 0.0  # Percentage of scenarios executed (out of 3)


class RiskOverviewResponse(BaseModel):
    total_risks: int = 10
    items: List[RiskOverviewItem] = Field(default_factory=list)


class RiskBlockRateComparison(BaseModel):
    risk_id: str
    risk_name: str
    category: str
    baseline_rate: float
    post_rate: float
    improvement: float


class RiskEffectivenessItem(BaseModel):
    risk_id: str
    risk_name: str
    effectiveness_score: float  # Post-mitigation block rate %
    improvement_points: float


class ClassificationDistribution(BaseModel):
    blocked: int = 0
    partial: int = 0
    succeeded: int = 0
    error: int = 0
    not_run: int = 0
    total: int = 0


class CoverageMetrics(BaseModel):
    scenarios_tested: int = 0
    total_scenarios: int = 30
    coverage_percentage: float = 0.0
    matrix_cells_tested: int = 0
    total_matrix_cells: int = 120
    matrix_coverage_percentage: float = 0.0


class ModelAnalyticsSummary(BaseModel):
    provider: str
    model_id: str
    tested_count: int = 0
    baseline_block_rate: float = 0.0
    post_block_rate: float = 0.0
    overall_block_rate: float = 0.0
    partial_rate: float = 0.0
    succeeded_rate: float = 0.0
    error_rate: float = 0.0
    avg_latency_ms: float = 0.0


class TimelineEventItem(BaseModel):
    id: str
    event_id: str
    timestamp: str
    event_type: str
    risk_id: Optional[str] = None
    scenario_id: Optional[str] = None
    security_component: str
    security_decision: str
    provider: str
    reason: str


class SecurityAnalyticsResponse(BaseModel):
    baseline_vs_post_comparison: List[RiskBlockRateComparison] = Field(default_factory=list)
    risk_mitigation_effectiveness: List[RiskEffectivenessItem] = Field(default_factory=list)
    distribution: ClassificationDistribution = Field(default_factory=ClassificationDistribution)
    model_comparison: Dict[str, ModelAnalyticsSummary] = Field(default_factory=dict)
    execution_coverage: CoverageMetrics = Field(default_factory=CoverageMetrics)
    security_event_timeline: List[TimelineEventItem] = Field(default_factory=list)
    execution_mode_breakdown: Dict[str, int] = Field(default_factory=dict)


class AuditLogItemResponse(BaseModel):
    id: str
    event_id: str
    timestamp: str
    risk_id: Optional[str] = None
    risk_category: Optional[str] = None
    scenario_id: Optional[str] = None
    security_component: str
    event_type: str
    tool_name: str
    provider: str
    model: str
    execution_stage: str
    authorization_decision: str
    execution_status: str
    reason: str
    execution_ref: Optional[str] = None


class AuditLogListResponse(BaseModel):
    total: int = 0
    limit: int = 50
    offset: int = 0
    items: List[AuditLogItemResponse] = Field(default_factory=list)

