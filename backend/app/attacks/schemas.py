from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskCategorySchema(BaseModel):
    risk_id: str
    risk_name: str
    category: str
    description: str


class AttackScenarioSchema(BaseModel):
    scenario_id: str
    risk_id: str
    risk_name: str
    category: str
    scenario_name: str
    attack_description: str
    attack_prompt: str
    expected_secure_behavior: str
    severity: str
    target_component: str
    test_type: str


class AttackRunRequest(BaseModel):
    scenario_id: str = Field(..., description="ID of scenario to execute (e.g. 'LLM01-01')")
    provider: Optional[str] = Field("claude", description="'claude' or 'gemini'")
    model: Optional[str] = Field(None, description="Optional model ID override")
    stage: Optional[str] = Field("BASELINE", description="'BASELINE' or 'POST_MITIGATION'")
    role: Optional[str] = Field("analyst", description="Security role context ('user', 'analyst', 'admin')")


class AttackBatchRunRequest(BaseModel):
    scenario_ids: Optional[List[str]] = Field(None, description="List of scenario IDs to run (max 30)")
    risk_id: Optional[str] = Field(None, description="Optional filter by risk ID (e.g. 'LLM01')")
    provider: Optional[str] = Field("claude", description="'claude' or 'gemini'")
    model: Optional[str] = Field(None, description="Optional model ID override")
    stage: Optional[str] = Field("BASELINE", description="'BASELINE' or 'POST_MITIGATION'")
    role: Optional[str] = Field("analyst", description="Security role context")


class AttackResultSchema(BaseModel):
    id: str
    run_id: str
    scenario_id: str
    risk_id: str
    provider: str
    model: str
    execution_mode: str
    stage: str
    prompt: str
    response_content: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    result_classification: str  # "BLOCKED", "PARTIAL", "SUCCEEDED", "ERROR"
    evaluation_reason: Optional[str] = None
    latency_ms: Optional[float] = None
    error_details: Optional[str] = None
    created_at: str


class AttackRunResponse(BaseModel):
    id: str
    provider: str
    model: str
    stage: str
    execution_mode: str
    total_scenarios: int
    blocked_count: int
    partial_count: int
    succeeded_count: int
    error_count: int
    created_at: str
    results: List[AttackResultSchema] = []


class AttackSummaryStats(BaseModel):
    total_runs: int
    total_tests_executed: int
    baseline_stats: Dict[str, Any]
    post_mitigation_stats: Dict[str, Any]
    risk_breakdown: List[Dict[str, Any]]

