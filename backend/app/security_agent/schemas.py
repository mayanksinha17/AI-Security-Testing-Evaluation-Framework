"""Pydantic schemas for the Autonomous Security Testing Agent (Phase A).

Defines data contracts for natural language command interpretation,
OWASP risk identification, target resolution, and scope authorization.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, HttpUrl


class UserIntent(str, Enum):
    TEST = "TEST"
    AUDIT = "AUDIT"
    SCAN = "SCAN"
    EVALUATE = "EVALUATE"
    EXPLAIN = "EXPLAIN"
    BENCHMARK = "BENCHMARK"
    UNKNOWN = "UNKNOWN"


class RiskCategoryEnum(str, Enum):
    OWASP_LLM = "OWASP_LLM"
    OWASP_AGENTIC = "OWASP_AGENTIC"
    ALL = "ALL"


class ScopeStatusEnum(str, Enum):
    APPROVED_LOCAL = "APPROVED_LOCAL"
    APPROVED_EXTERNAL = "APPROVED_EXTERNAL"
    BLOCKED_DISALLOWED_IP = "BLOCKED_DISALLOWED_IP"
    BLOCKED_METADATA = "BLOCKED_METADATA"
    BLOCKED_SCHEME = "BLOCKED_SCHEME"
    UNAUTHORIZED_EXTERNAL = "UNAUTHORIZED_EXTERNAL"
    INVALID_URL = "INVALID_URL"
    UNRESOLVABLE_HOST = "UNRESOLVABLE_HOST"


class TargetScopeSchema(BaseModel):
    raw_url: str
    normalized_url: str
    scheme: str
    host: str
    port: int
    path: str
    resolved_ip: Optional[str] = None
    all_resolved_ips: List[str] = Field(default_factory=list)
    is_local: bool = False
    is_cloud_metadata: bool = False
    is_authorized: bool = False
    is_in_scope: bool = False
    scope_status: ScopeStatusEnum
    reason: str


class RiskMatchSchema(BaseModel):
    risk_id: str = Field(..., description="OWASP Risk Code (e.g. LLM01, ASI02)")
    risk_name: str = Field(..., description="Canonical Risk Name")
    category: str = Field(..., description="OWASP_LLM or OWASP_AGENTIC")
    matched_phrase: str = Field(..., description="Phrase or token that triggered the match")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    severity: str = Field(default="high")
    description: str = Field(default="")


class ProposedScenarioSchema(BaseModel):
    scenario_id: str
    scenario_name: str
    risk_id: str
    category: str
    severity: str
    target_component: str
    attack_description: str
    test_type: str


class CommandInterpretationRequest(BaseModel):
    command: str = Field(..., min_length=2, max_length=2000, description="Natural language security command")
    target_url: Optional[str] = Field(None, description="Explicit target URL override")
    user_confirmed_authorization: bool = Field(
        default=False,
        description="Explicit user confirmation of authorization to test the specified target",
    )
    auth_headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional authentication headers (e.g. Bearer token, X-API-Key)",
    )
    default_target_if_omitted: Optional[str] = Field(
        default="http://127.0.0.1:8000",
        description="Default local target used when command omits an explicit URL",
    )


class CommandInterpretationResponse(BaseModel):
    command: str
    intent: UserIntent
    target: TargetScopeSchema
    identified_risks: List[RiskMatchSchema]
    categories: List[str]
    execution_instructions: Dict[str, Any] = Field(default_factory=dict)
    authorization_required: bool
    is_ready_for_execution: bool
    blocking_reasons: List[str] = Field(default_factory=list)
    plan_preview: List[ProposedScenarioSchema] = Field(default_factory=list)
    total_planned_tests: int = 0


class TargetValidationRequest(BaseModel):
    target_url: str = Field(..., description="Target URL to validate")
    user_confirmed_authorization: bool = Field(
        default=False,
        description="Explicit user confirmation of authorization to test",
    )
    custom_headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Custom headers (e.g. Authorization, API keys)",
    )


class TargetValidationResponse(BaseModel):
    is_valid: bool
    is_in_scope: bool
    target: TargetScopeSchema
    redacted_headers: Dict[str, str] = Field(default_factory=dict)
    reason: str
    warnings: List[str] = Field(default_factory=list)


class ScopePolicySchema(BaseModel):
    allowed_schemes: List[str]
    local_only_by_default: bool
    allow_external_with_authorization: bool
    blocked_ip_ranges: List[str]
    blocked_domains: List[str]
    max_requests_per_test: int
    default_timeout_seconds: float


# =====================================================================
# Phase B: Dynamic Planner, Execution & Evidence Schemas
# =====================================================================

class CreatePlanRequest(BaseModel):
    command: Optional[str] = Field(None, description="Natural language security testing command")
    target_url: Optional[str] = Field("http://127.0.0.1:8000", description="Target base URL")
    stage: str = Field("POST_MITIGATION", description="Execution stage: BASELINE or POST_MITIGATION")
    risk_ids: Optional[List[str]] = Field(None, description="Explicit list of OWASP risk codes")
    scenario_ids: Optional[List[str]] = Field(None, description="Explicit list of scenario IDs")
    user_confirmed_authorization: bool = Field(False, description="Explicit user confirmation for target authorization")
    auth_headers: Optional[Dict[str, str]] = Field(None, description="Optional authentication headers")


class TestExecutionSummary(BaseModel):
    execution_id: str
    plan_id: str
    scenario_id: str
    risk_id: str
    risk_name: str
    category: str
    test_type: str
    target_endpoint: str
    http_method: str
    payload_id: str
    status: str
    verdict: str
    duration_ms: Optional[float] = None
    created_at: datetime
    turn_number: int = 1
    parent_execution_id: Optional[str] = None
    chain_id: Optional[str] = None
    payload_version: str = "v1"
    mutation_technique: Optional[str] = None
    confidence: float = 1.0
    notes: Optional[str] = None


class ExecutionPlanSummary(BaseModel):
    plan_id: str
    session_id: str
    target_url: str
    is_local_target: bool
    stage: str
    total_tests: int
    completed_tests: int
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    tests: List[TestExecutionSummary] = Field(default_factory=list)
    report_id: Optional[str] = None
    download_urls: Optional[Dict[str, str]] = None


class ExecutePlanRequest(BaseModel):
    stage: Optional[str] = Field(None, description="Override stage (BASELINE or POST_MITIGATION)")
    user_confirmed_authorization: bool = Field(False, description="User authorization confirmation")


class ExecutionEvidenceSummary(BaseModel):
    execution_id: str
    scenario_id: str
    risk_id: str
    target_url: str
    http_method: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_status_code: Optional[int] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    response_latency_ms: Optional[float] = None
    timestamp_sent: Optional[datetime] = None
    timestamp_received: Optional[datetime] = None
    error_message: Optional[str] = None
    verdict: str
    evidence_sha256: Optional[str] = Field(None, description="Cryptographic SHA-256 evidence integrity hash")
    is_integrity_verified: bool = Field(True, description="Indicates evidence payload integrity is verified")


class PlanFindingsSummary(BaseModel):
    plan_id: str
    target_url: str
    stage: str
    status: str
    total_tests: int
    completed_tests: int
    vulnerable_count: int
    blocked_count: int
    error_count: int
    cancelled_count: int
    vulnerability_rate_percent: float
    block_rate_percent: float
    risk_breakdown: Dict[str, Dict[str, Any]]
    evidence_records_count: int


# =====================================================================
# Phase C: Adaptive Multi-Turn Execution & Reporting Schemas
# =====================================================================

class AdaptivePlanRequest(BaseModel):
    command: Optional[str] = Field(None, description="Natural language security testing command")
    target_url: Optional[str] = Field("http://127.0.0.1:8000", description="Target base URL")
    stage: str = Field("POST_MITIGATION", description="BASELINE or POST_MITIGATION")
    risk_ids: Optional[List[str]] = Field(None, description="Explicit list of OWASP risk codes")
    scenario_ids: Optional[List[str]] = Field(None, description="Explicit list of scenario IDs")
    max_turns: int = Field(3, ge=1, le=5, description="Maximum adaptive turns per scenario")
    user_confirmed_authorization: bool = Field(False, description="User authorization confirmation")
    auth_headers: Optional[Dict[str, str]] = Field(None, description="Optional custom headers")


class ExecutionChainGroup(BaseModel):
    chain_id: str
    scenario_id: str
    scenario_name: str
    risk_id: str
    total_turns: int
    final_verdict: str
    final_confidence: float
    turns: List[TestExecutionSummary] = Field(default_factory=list)


class MutationNode(BaseModel):
    payload_id: str
    version: str
    parent_payload_id: Optional[str] = None
    scenario_id: str
    risk_id: str
    mutation_technique: str
    mutation_rationale: str
    turn_number: int
    verdict: str


class AutonomousAssessmentReport(BaseModel):
    plan_id: str
    target_url: str
    stage: str
    status: str
    total_scenarios_tested: int
    total_turns_dispatched: int
    total_vulnerabilities_confirmed: int
    overall_resilience_score_percent: float
    evaluable_scenarios: int = 0
    blocked_scenarios: int = 0
    vulnerable_scenarios: int = 0
    partial_scenarios: int = 0
    error_scenarios: int = 0
    inconclusive_scenarios: int = 0
    not_run_scenarios: int = 0
    cancelled_scenarios: int = 0
    infrastructure_error_rate_percent: float = 0.0
    evaluable_coverage_percent: float = 0.0
    resilience_formula: str = "BLOCKED / (BLOCKED + VULNERABLE + PARTIAL) * 100"
    risk_assessments: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    remediation_recommendations: List[Dict[str, str]] = Field(default_factory=list)
    evidence_integrity_verified: bool = True
    generated_at: datetime


# =====================================================================
# Phase D: Advanced Intelligence & Attack Orchestration Schemas
# =====================================================================

class EndpointDiscoverySchema(BaseModel):
    path: str
    methods: List[str]
    description: Optional[str] = None
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None
    response_schemas: Dict[str, Any] = Field(default_factory=dict)
    auth_required: bool = False
    is_tested_surface: bool = False


class ApplicationContext(BaseModel):
    application_id: str
    target_scope: str
    is_local_target: bool = True
    discovered_endpoints: List[EndpointDiscoverySchema] = Field(default_factory=list)
    endpoint_methods: Dict[str, List[str]] = Field(default_factory=dict)
    authentication_requirements: Dict[str, Any] = Field(default_factory=dict)
    request_schema: Dict[str, Any] = Field(default_factory=dict)
    response_schema: Dict[str, Any] = Field(default_factory=dict)
    identified_components: List[str] = Field(default_factory=list)
    discovered_security_controls: List[str] = Field(default_factory=list)
    context_confidence: float = 1.0
    discovery_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DiscoverContextRequest(BaseModel):
    target_url: str = Field("http://127.0.0.1:8000", description="Authorized target URL")
    user_confirmed_authorization: bool = Field(True, description="Explicit authorization confirmation")
    probe_local_endpoints: bool = Field(True, description="Probe known controlled endpoints")


class ImportOpenApiRequest(BaseModel):
    target_url: str = Field("http://127.0.0.1:8000", description="Authorized target URL")
    openapi_spec: Dict[str, Any] = Field(..., description="OpenAPI 3.0 or Swagger 2.0 JSON schema")
    user_confirmed_authorization: bool = Field(True, description="Explicit authorization confirmation")


class RiskRelationshipSchema(BaseModel):
    source_risk: str
    related_risk: str
    relationship_type: str  # enables, escalates_to, exfiltrates_via, prerequisite_for, amplifies, correlated_with
    prerequisite: Optional[str] = None
    rationale: str
    correlation_confidence: float = 0.90
    validation_status: str = "HYPOTHESIS"  # HYPOTHESIS, TESTED, CONFIRMED, REFUTED


class RiskCorrelationGraphSchema(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[RiskRelationshipSchema]
    total_risks_mapped: int
    total_relationships: int


class AttackChainStepSchema(BaseModel):
    step_id: str
    scenario_id: str
    risk_id: str
    step_order: int
    target_endpoint: str
    http_method: str
    payload_description: str
    payload_body: Dict[str, Any]
    prerequisites: List[str] = Field(default_factory=list)
    expected_behavior: str
    actual_behavior: Optional[str] = None
    execution_status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED, SKIPPED
    verdict: Optional[str] = None
    evidence_sha256: Optional[str] = None
    execution_id: Optional[str] = None


class AttackChainSchema(BaseModel):
    chain_id: str
    chain_name: str
    description: str
    associated_risks: List[str]
    stage: str = "POST_MITIGATION"
    execution_steps: List[AttackChainStepSchema]
    prerequisites: List[str] = Field(default_factory=list)
    expected_behavior: str
    actual_behavior: Optional[str] = None
    execution_status: str = "PLANNED"  # PLANNED, RUNNING, COMPLETED, BROKEN, CANCELLED
    evidence_references: List[str] = Field(default_factory=list)
    final_assessment: str = "PENDING"
    chain_findings: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GenerateAttackChainRequest(BaseModel):
    command: Optional[str] = Field(None, description="Natural language attack chain directive")
    target_url: str = Field("http://127.0.0.1:8000", description="Target base URL")
    risk_ids: Optional[List[str]] = Field(None, description="Explicit list of OWASP risk codes to chain")
    stage: str = Field("POST_MITIGATION", description="BASELINE or POST_MITIGATION")
    user_confirmed_authorization: bool = Field(True, description="Explicit user confirmation for target authorization")


class RootCauseFinding(BaseModel):
    finding_id: str
    scenario_id: str
    associated_risk: str
    risk_name: str
    affected_endpoint: str
    affected_component: str
    root_cause_category: str  # INPUT_VALIDATION, OUTPUT_HANDLING, PERMISSION_ENFORCEMENT, TRUST_BOUNDARY, STATE_MANAGEMENT, TOOL_AUTHORIZATION
    triggering_condition: str
    failed_security_control: str
    trust_boundary_crossed: str
    evidence_references: List[str] = Field(default_factory=list)
    status: str = "CONFIRMED"  # CONFIRMED, PROBABLE, INSUFFICIENT_EVIDENCE
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    cvss_score: float
    cvss_vector: str
    confidence: float
    scoring_explanation: str
    explanation: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RemediationDirective(BaseModel):
    finding_id: str
    risk_id: str
    title: str
    summary: str
    quick_mitigation: Dict[str, Any]  # snippet, description, location
    architectural_fix: Dict[str, Any]  # snippet, pattern, best_practice
    verification_probe: Dict[str, Any]  # test_payload, expected_status, verification_method
    remediation_effort: str  # LOW, MEDIUM, HIGH
    priority: str  # P0_IMMEDIATE, P1_HIGH, P2_MEDIUM, P3_LOW


# =====================================================================
# Phase E1: Dynamic Security Intelligence Schemas
# =====================================================================

class OutcomeCategoryEnum(str, Enum):
    CONFIRMED = "CONFIRMED"
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    REMEDIATION_VERIFIED = "REMEDIATION_VERIFIED"


class TargetIsolationTuple(BaseModel):
    target_identity: str = Field(..., description="Normalized host / IP identity")
    application_id: str = Field("default", description="Application or microservice identifier")
    app_version: str = Field("v1.0", description="Semantic application version")
    environment: str = Field("sandbox", description="Deployment environment tier (sandbox, staging, production)")
    endpoint: str = Field("/api/chat", description="API route under assessment")
    risk_id: Optional[str] = Field(None, description="Optional target OWASP risk code")


class ComponentScoresSchema(BaseModel):
    severity: float = Field(..., ge=0.0, le=1.0, description="Normalized risk severity weight (0.35)")
    historical_outcome: float = Field(..., ge=0.0, le=1.0, description="Empirical historical outcome rate or cold prior (0.30)")
    endpoint_sensitivity: float = Field(..., ge=0.0, le=1.0, description="Normalized endpoint sensitivity score (0.20)")
    prerequisite_status: float = Field(..., ge=0.0, le=1.0, description="Prerequisite satisfaction readiness score (0.15)")


class RiskPrioritizationItem(BaseModel):
    risk_id: str
    risk_name: str
    category: str
    target_identity: str
    application_id: str
    application_version: str
    environment: str
    endpoint: str
    priority_score: float = Field(..., ge=0.0, le=1.0, description="Calculated priority score (0.0 - 1.0)")
    component_scores: ComponentScoresSchema
    historical_sample_count: int = Field(0, description="Total historical attempts evaluated")
    eligible_evidence_count: int = Field(0, description="Count of cryptographically verified eligible evidence records")
    cold_start: bool = Field(True, description="True if fewer than 3 verified executions exist")
    correlation_confidence: float = Field(..., ge=0.0, le=1.0, description="Theoretical correlation confidence from risk catalog")
    test_confidence: float = Field(..., ge=0.0, le=1.0, description="Diagnostic reliability of scenario probes")
    finding_confidence: float = Field(..., ge=0.0, le=1.0, description="Heuristic certainty that anomaly is verified vulnerability")
    remediation_confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in remediation guidance effectiveness")
    remediation_success_rate: float = Field(0.0, ge=0.0, le=1.0, description="Empirical remediation verification success rate")
    evidence_trust_level: str = Field("HMAC_VERIFIED", description="Primary cryptographic evidence trust level")
    hmac_verified_count: int = Field(0, description="Count of authentic HMAC-SHA256 verified records")
    legacy_sha256_count: int = Field(0, description="Count of legacy SHA-256 integrity-only records")
    legacy_evidence_contribution: float = Field(0.0, ge=0.0, le=1.0, description="Separately disclosed legacy evidence contribution ratio")
    confirmed_rate: float = Field(0.0, ge=0.0, le=1.0, description="N_confirmed / N_eligible for this risk")
    blocked_rate: float = Field(0.0, ge=0.0, le=1.0, description="N_blocked / N_eligible for this risk")
    partial_rate: float = Field(0.0, ge=0.0, le=1.0, description="N_partial / N_eligible for this risk")
    inconclusive_rate: float = Field(0.0, ge=0.0, le=1.0, description="N_inconclusive / N_eligible for this risk")
    evaluable_coverage: float = Field(0.0, ge=0.0, le=1.0, description="(N_confirmed + N_blocked) / max(1, N_eligible)")
    evidence_trust_distribution: Dict[str, int] = Field(default_factory=dict, description="Count per trust level for this risk")
    cvss_score: Optional[float] = Field(None, description="CVSS v3.1 base score (0.0 - 10.0), decoupled from confidence")
    cvss_severity: Optional[str] = Field(None, description="CVSS v3.1 severity rating")
    prioritization_explanation: str = Field(..., description="Concise explainable selection rationale")
    evidence_references: List[str] = Field(default_factory=list, description="Linked cryptographic evidence hashes")
    remaining_uncertainties: List[str] = Field(default_factory=list, description="Unverified environmental or probe assumptions")


class IntelligenceOverviewResponse(BaseModel):
    target_identity: str
    application_id: str
    application_version: str
    environment: str
    endpoint: Optional[str] = None
    total_executions_evaluated: int
    eligible_evidence_count: int
    hmac_verified_count: int = Field(0, description="Count of authentic HMAC-SHA256 verified evidence records")
    legacy_sha256_count: int = Field(0, description="Count of legacy SHA-256 integrity-checked records (content integrity only)")
    invalid_count: int = Field(0, description="Count of invalid or tampered evidence records")
    missing_count: int = Field(0, description="Count of missing evidence records")
    confirmed_rate: float = Field(0.0, ge=0.0, le=1.0, description="N_confirmed / N_eligible across target")
    blocked_rate: float = Field(0.0, ge=0.0, le=1.0, description="N_blocked / N_eligible across target")
    partial_rate: float = Field(0.0, ge=0.0, le=1.0, description="N_partial / N_eligible across target")
    inconclusive_rate: float = Field(0.0, ge=0.0, le=1.0, description="N_inconclusive / N_eligible across target")
    infrastructure_error_rate: float = Field(0.0, ge=0.0, le=1.0, description="N_error / max(1, N_total)")
    evaluable_coverage: float = Field(0.0, ge=0.0, le=1.0, description="(N_confirmed + N_blocked) / max(1, N_eligible)")
    evidence_trust_distribution: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Distribution of evidence by trust level")
    outcome_counts: Dict[str, int]
    top_prioritized_risks: List[RiskPrioritizationItem]
    cold_start_ratio: float = Field(..., ge=0.0, le=1.0)
    isolation_tuple: Dict[str, str]
    notes: str


class IntelligenceHistoryRecord(BaseModel):
    execution_id: str
    plan_id: str
    target_url: str
    target_endpoint: str
    risk_id: str
    scenario_id: str
    verdict: str
    outcome_category: str
    status_code: Optional[int] = None
    evidence_sha256: Optional[str] = None
    evidence_trust_level: str = Field("HMAC_VERIFIED", description="Cryptographic evidence trust level: HMAC_VERIFIED, LEGACY_SHA256_VERIFIED, INVALID, MISSING")
    trust_description: str = Field("HMAC Authenticated", description="Human-readable trust description")
    timestamp: datetime
    eligible: bool
    ineligibility_reason: Optional[str] = None
    classification_rationale: Optional[str] = Field(None, description="Detailed outcome classification rationale")


# =====================================================================
# Phase E2: Advanced Attack Graph Planning Schemas
# =====================================================================

class AttackGraphNodeSchema(BaseModel):
    id: str
    risk_id: str
    risk_name: str
    category: str
    severity: str
    endpoint: str = "/api/chat"
    priority_score: float = Field(0.5, ge=0.0, le=1.0)
    historical_outcome_score: float = Field(0.5, ge=0.0, le=1.0)
    evidence_trust_level: str = "HMAC_VERIFIED"
    is_entry_vector: bool = False
    is_impact_sink: bool = False
    prerequisites_satisfied: bool = False
    description: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackGraphEdgeSchema(BaseModel):
    source: str
    target: str
    relationship_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    prerequisite: Optional[str] = None
    rationale: str = ""
    is_cyclic: bool = False
    evidence_status: str = "THEORETICAL"  # THEORETICAL, HYPOTHESIS, CONFIRMED_DEPENDENCY


class StronglyConnectedComponentSchema(BaseModel):
    component_id: str
    node_ids: List[str]
    size: int
    is_cyclic: bool
    explanation: str
    internal_relationships: List[str] = Field(default_factory=list)
    is_executable_chain: bool = False
    independent_verification_required: bool = True


class CondensedDagEdgeSchema(BaseModel):
    source_component: str
    target_component: str
    edge_count: int
    relationships: List[str] = Field(default_factory=list)


class AttackGraphAnalysisResponse(BaseModel):
    nodes: List[AttackGraphNodeSchema]
    edges: List[AttackGraphEdgeSchema]
    sccs: List[StronglyConnectedComponentSchema]
    cyclic_components: List[StronglyConnectedComponentSchema]
    condensed_dag_edges: List[CondensedDagEdgeSchema]
    total_nodes: int
    total_edges: int
    total_sccs: int
    cyclic_count: int
    analysis_duration_ms: float
    resource_limits_reached: List[str] = Field(default_factory=list)
    disclaimer: str = "Attack graphs represent structural risk dependencies and must never be interpreted as observed or confirmed compromise."


class CandidateAttackPathStepSchema(BaseModel):
    step_number: int
    risk_id: str
    risk_name: str
    category: str
    severity: str
    endpoint: str
    relationship_from_prior: Optional[str] = None
    relationship_semantic: Optional[str] = None  # STRUCTURAL_PREREQUISITE, CAPABILITY_ENABLING, IMPACT_AMPLIFICATION, EXFILTRATION_VECTOR, THEORETICAL_CORRELATION
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    prerequisite: Optional[str] = None
    is_hard_prerequisite: bool = False
    prerequisite_satisfied: bool = False
    step_priority_score: float = Field(0.5, ge=0.0, le=1.0)
    independent_verification_status: str = "PENDING_EXECUTION"


class CandidateAttackPathSchema(BaseModel):
    path_id: str
    chain_id: str
    target_identity: str
    application_id: str
    environment: str
    source_risk: str
    destination_risk: str
    path_length: int
    cumulative_priority_score: float = Field(..., ge=0.0, le=1.0)
    cumulative_confidence: float = Field(..., ge=0.0, le=1.0)
    ordered_steps: List[CandidateAttackPathStepSchema]
    relationship_types: List[str] = Field(default_factory=list)
    hard_prerequisites: List[str] = Field(default_factory=list)
    satisfied_prerequisites: List[str] = Field(default_factory=list)
    unsatisfied_prerequisites: List[str] = Field(default_factory=list)
    theoretical_dependencies: List[str] = Field(default_factory=list)
    execution_eligibility: bool
    rejection_reasons: List[str] = Field(default_factory=list)
    rejection_reason: Optional[str] = None
    selection_rationale: str
    evidence_trust_level: str = "HMAC_VERIFIED"
    trust_policy_applied: str = "PRIMARY_HMAC_AUTHENTICATED"
    target_isolation_verified: bool = True
    resource_limits: Dict[str, Any] = Field(default_factory=dict)
    current_status: str = "PLANNED"  # PLANNED, READY, INELIGIBLE, EXECUTING, COMPLETED
    disclaimer: str = "Proposed candidate attack path. Must never be presented as an observed compromise. Each step requires independent verification."


class GenerateCandidatePathsRequest(BaseModel):
    target_url: str = Field("http://127.0.0.1:8000", description="Target base URL")
    application_id: str = Field("default", description="Application identifier")
    app_version: str = Field("v1.0", description="Application version")
    environment: str = Field("sandbox", description="Deployment environment tier")
    endpoint: str = Field("/api/chat", description="Primary API route under test")
    source_risks: Optional[List[str]] = Field(None, description="Optional entry vector filter (e.g. ['LLM01', 'ASI06'])")
    target_sinks: Optional[List[str]] = Field(None, description="Optional impact sink filter (e.g. ['ASI05', 'LLM02'])")
    max_paths: int = Field(20, ge=1, le=20, description="Max candidate paths (capped at 20)")
    max_length: int = Field(5, ge=2, le=5, description="Max path length (capped at 5)")
    user_confirmed_authorization: bool = Field(True, description="Explicit authorization confirmation")


class GenerateCandidatePathsResponse(BaseModel):
    paths: List[CandidateAttackPathSchema]
    total_candidate_paths: int
    target_identity: str
    application_id: str
    environment: str
    analysis_duration_ms: float
    resource_limits_reached: List[str] = Field(default_factory=list)
    disclaimer: str = "Candidate attack paths represent planning hypotheses and must never be interpreted as observed compromises."


# =====================================================================
# Phase E3: Deep OpenAPI Schema Intelligence Schemas
# =====================================================================

class SchemaSecurityField(BaseModel):
    field_name: str
    field_path: str
    category: str  # AUTHENTICATION, ADMINISTRATIVE, SENSITIVE_DATA, USER_CONTROLLED_INPUT, TOOL_INVOCATION, FILE_AND_URL, OBJECT_IDENTIFIER, TENANT_IDENTIFIER, CALLBACK_WEBHOOK, DATA_EXPORT
    inferred_type: str = "string"
    description: Optional[str] = None
    owasp_hypothesis: str
    sensitivity_weight: float = Field(0.5, ge=0.0, le=1.0)


class SchemaCompositionDetails(BaseModel):
    composition_type: str = "none"  # none, allOf, oneOf, anyOf, not
    branch_count: int = 0
    participating_refs: List[str] = Field(default_factory=list)
    merged_properties: List[str] = Field(default_factory=list)
    required_union: List[str] = Field(default_factory=list)


class ResolvedEndpointSchema(BaseModel):
    endpoint: str
    method: str
    summary: Optional[str] = None
    description: Optional[str] = None
    operation_id: Optional[str] = None
    auth_required: bool = False
    security_schemes: List[str] = Field(default_factory=list)
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    raw_request_schema: Optional[Dict[str, Any]] = None
    resolved_request_schema: Optional[Dict[str, Any]] = None
    request_composition: Optional[SchemaCompositionDetails] = None
    response_schemas: Dict[str, Any] = Field(default_factory=dict)
    security_sensitive_fields: List[SchemaSecurityField] = Field(default_factory=list)
    endpoint_sensitivity: float = Field(0.5, ge=0.0, le=1.0)
    has_recursive_structure: bool = False
    recursive_pointers: List[str] = Field(default_factory=list)
    owasp_risk_mappings: List[str] = Field(default_factory=list)


class DeepOpenApiAnalysisResponse(BaseModel):
    openapi_version: str = "3.0.0"
    title: str = "Application API"
    version: str = "1.0.0"
    total_endpoints: int = 0
    total_operations: int = 0
    total_component_schemas: int = 0
    resolved_reference_count: int = 0
    circular_reference_count: int = 0
    composed_schema_count: int = 0
    security_sensitive_field_count: int = 0
    endpoints: List[ResolvedEndpointSchema] = Field(default_factory=list)
    security_fields_summary: Dict[str, int] = Field(default_factory=dict)
    owasp_hypotheses: Dict[str, List[str]] = Field(default_factory=dict)
    analysis_duration_ms: float = 0.0
    resource_limits_reached: List[str] = Field(default_factory=list)
    schema_warnings: List[str] = Field(default_factory=list)
    disclaimer: str = "OpenAPI schema observations and OWASP risk correlations represent test planning hypotheses and do not confirm the presence of vulnerabilities."


class AnalyzeOpenApiSchemaRequest(BaseModel):
    spec: Optional[Dict[str, Any]] = Field(None, description="Raw OpenAPI 3.0 or Swagger 2.0 specification dictionary")
    target_url: Optional[str] = Field("http://127.0.0.1:8000", description="Target base URL")
    user_confirmed_authorization: bool = Field(True, description="Explicit target authorization confirmation")


class ResolveReferenceRequest(BaseModel):
    spec: Dict[str, Any]
    pointer: str


class ResolveReferenceResponse(BaseModel):
    pointer: str
    resolved_schema: Dict[str, Any] = Field(default_factory=dict)
    is_circular: bool = False
    depth_reached: int = 1
    composition_type: str = "none"
    error: Optional[str] = None


class SchemaAwareTestPlanItem(BaseModel):
    test_id: str
    endpoint: str
    method: str
    target_url: str
    application_id: str
    environment: str
    required_fields: List[str] = Field(default_factory=list)
    optional_fields: List[str] = Field(default_factory=list)
    field_data_types: Dict[str, str] = Field(default_factory=dict)
    validation_constraints: Dict[str, Any] = Field(default_factory=dict)
    security_hypothesis: str
    owasp_risk_id: str
    owasp_risk_name: str
    synthesized_payload: Dict[str, Any] = Field(default_factory=dict)
    expected_defensive_behavior: str
    expected_response_status: int = 403
    expected_evidence_marker: str
    scope_eligibility: bool = True
    rejection_reasons: List[str] = Field(default_factory=list)
    disclaimer: str = "Proposed schema-aware security test plan item. Must never be treated as an observed compromise."


class GenerateSchemaTestPlansRequest(BaseModel):
    target_url: str = Field("http://127.0.0.1:8000", description="Target base URL")
    application_id: str = Field("default", description="Application identifier")
    app_version: str = Field("v1.0", description="Application version")
    environment: str = Field("sandbox", description="Deployment environment tier")
    spec: Optional[Dict[str, Any]] = Field(None, description="Optional raw OpenAPI specification dictionary")
    endpoint_filter: Optional[List[str]] = Field(None, description="Optional list of specific endpoints to plan")
    risk_filter: Optional[List[str]] = Field(None, description="Optional list of OWASP risk IDs to target")
    user_confirmed_authorization: bool = Field(True, description="Explicit authorization confirmation")


class GenerateSchemaTestPlansResponse(BaseModel):
    plans: List[SchemaAwareTestPlanItem] = Field(default_factory=list)
    total_tests: int = 0
    target_identity: str
    application_id: str
    environment: str
    analysis_duration_ms: float = 0.0
    resource_limits_reached: List[str] = Field(default_factory=list)
    disclaimer: str = "Schema-aware test plans represent structured test hypotheses for defensive evaluation."


# =====================================================================
# Phase E4: Vulnerability & Evidence Lifecycle Schemas
# =====================================================================

class FindingLifecycleStatusEnum(str, Enum):
    DETECTED = "DETECTED"
    TRIAGE = "TRIAGE"
    POTENTIAL = "POTENTIAL"
    CONFIRMED = "CONFIRMED"
    REMEDIATION_PLANNED = "REMEDIATION_PLANNED"
    REMEDIATION_IN_PROGRESS = "REMEDIATION_IN_PROGRESS"
    READY_FOR_RETEST = "READY_FOR_RETEST"
    REMEDIATION_VERIFIED = "REMEDIATION_VERIFIED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CLOSED = "CLOSED"


class FindingSeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class SecurityFindingCreate(BaseModel):
    scenario_id: str
    risk_id: str
    title: str
    description: Optional[str] = None
    category: str = "OWASP_LLM"
    affected_endpoint: str
    http_method: str = "POST"
    target_identity: str = "http://127.0.0.1:8000"
    application_id: str = "default"
    app_version: str = "v1.0"
    environment: str = "sandbox"
    initial_status: FindingLifecycleStatusEnum = FindingLifecycleStatusEnum.DETECTED
    severity: FindingSeverityEnum = FindingSeverityEnum.MEDIUM
    confidence: float = Field(0.85, ge=0.0, le=1.0)
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    root_cause_category: Optional[str] = None
    failed_security_control: Optional[str] = None
    trust_boundary_crossed: Optional[str] = None
    remediation_title: Optional[str] = None
    remediation_snippet: Optional[str] = None
    verification_procedure: Optional[str] = None
    session_id: Optional[str] = None
    execution_id: Optional[str] = None
    secondary_execution_id: Optional[str] = None
    version_id: int = 1
    evidence_references: List[str] = Field(default_factory=list)
    initial_reason: Optional[str] = "Initial security finding discovery"
    actor: str = "AutonomousSecurityAgent"


class SecurityFindingUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[FindingSeverityEnum] = None
    confidence: Optional[float] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    root_cause_category: Optional[str] = None
    failed_security_control: Optional[str] = None
    trust_boundary_crossed: Optional[str] = None
    remediation_title: Optional[str] = None
    remediation_snippet: Optional[str] = None
    verification_procedure: Optional[str] = None


class TransitionFindingStateRequest(BaseModel):
    target_state: FindingLifecycleStatusEnum
    transition_reason: str = Field(..., min_length=3, description="Required justification for the lifecycle transition")
    actor: str = Field("AutonomousSecurityAgent", description="User or agent actor initiating transition")
    evidence_reference: Optional[str] = Field(None, description="SHA-256 hash or evidence ID required for confirmation or retest verification")
    is_secondary_confirmed: bool = Field(False, description="Whether secondary independent probe succeeded (mandatory for CONFIRMED)")
    expected_version: Optional[int] = Field(None, description="Expected version_id of finding for optimistic concurrency control (SEC-E4-003)")
    secondary_execution_id: Optional[str] = Field(None, description="Secondary execution ID for independent confirmation verification (SEC-E4-002)")
    metadata_snapshot: Optional[Dict[str, Any]] = Field(None, description="Optional snapshot of execution metrics or context")


class SecurityFindingHistoryResponse(BaseModel):
    id: str
    history_id: str
    finding_id: str
    previous_state: str
    new_state: str
    transition_reason: str
    actor: str
    event_timestamp: datetime
    evidence_reference: Optional[str] = None
    metadata_snapshot: Optional[str] = None


class SecurityDecisionCreate(BaseModel):
    finding_id: Optional[str] = None
    session_id: Optional[str] = None
    execution_id: Optional[str] = None
    decision_type: str
    decision_reason: Optional[str] = None
    reasoning_summary: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    selected_action: str
    evidence_references: List[str] = Field(default_factory=list)
    input_context: Optional[Dict[str, Any]] = None
    alternatives_considered: List[str] = Field(default_factory=list)
    rejection_reasons: Dict[str, str] = Field(default_factory=dict)
    rejected_alternatives: Optional[List[Any]] = Field(default_factory=list)
    safety_constraints: Optional[Union[Dict[str, Any], str, List[Any]]] = None
    provenance: Optional[str] = "ExplainabilityEngine_v1"


class SecurityDecisionResponse(BaseModel):
    id: str
    decision_id: str
    finding_id: Optional[str] = None
    session_id: Optional[str] = None
    execution_id: Optional[str] = None
    decision_type: str
    decision_reason: str
    reasoning_summary: Optional[str] = None
    confidence: float
    selected_action: str
    evidence_references: List[str] = Field(default_factory=list)
    input_context: Optional[Dict[str, Any]] = None
    alternatives_considered: List[str] = Field(default_factory=list)
    rejection_reasons: Dict[str, str] = Field(default_factory=dict)
    rejected_alternatives: Optional[List[Any]] = Field(default_factory=list)
    safety_constraints: Optional[Union[Dict[str, Any], str, List[Any]]] = None
    provenance: Optional[str] = "ExplainabilityEngine_v1"
    decision_timestamp: Union[datetime, str]


class SecurityDecisionListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    decisions: List[SecurityDecisionResponse] = Field(default_factory=list)


class SecurityFindingResponse(BaseModel):
    id: str
    finding_id: str
    scenario_id: str
    risk_id: str
    title: str
    description: Optional[str] = None
    category: str
    affected_endpoint: str
    http_method: str
    target_identity: str
    application_id: str
    app_version: str
    environment: str
    lifecycle_status: FindingLifecycleStatusEnum
    severity: FindingSeverityEnum
    confidence: float
    cvss_score: float
    cvss_vector: Optional[str] = None
    root_cause_category: Optional[str] = None
    failed_security_control: Optional[str] = None
    trust_boundary_crossed: Optional[str] = None
    remediation_title: Optional[str] = None
    remediation_snippet: Optional[str] = None
    verification_procedure: Optional[str] = None
    session_id: Optional[str] = None
    execution_id: Optional[str] = None
    secondary_execution_id: Optional[str] = None
    version_id: int = 1
    evidence_references: List[str] = Field(default_factory=list)
    first_detected_at: datetime
    last_observed_at: datetime
    created_at: datetime
    updated_at: datetime
    history: List[SecurityFindingHistoryResponse] = Field(default_factory=list)
    decisions: List[SecurityDecisionResponse] = Field(default_factory=list)


class FindingListResponse(BaseModel):
    findings: List[SecurityFindingResponse]
    total_count: int
    page: int = 1
    page_size: int = 50


class LifecycleBoardColumn(BaseModel):
    state: FindingLifecycleStatusEnum
    count: int
    findings: List[SecurityFindingResponse] = Field(default_factory=list)


class LifecycleBoardResponse(BaseModel):
    target_identity: str
    application_id: str
    environment: str
    columns: Dict[str, LifecycleBoardColumn]
    total_findings: int
    active_findings: int
    remediated_findings: int
    refuted_findings: int


# =====================================================================
# Phase E5: Security Regression Intelligence Schemas
# =====================================================================

class RegressionDeltaTypeEnum(str, Enum):
    NEW_VULNERABILITY = "NEW_VULNERABILITY"
    RESOLVED_VULNERABILITY = "RESOLVED_VULNERABILITY"
    PERSISTENT_VULNERABILITY = "PERSISTENT_VULNERABILITY"
    REOPENED_VULNERABILITY = "REOPENED_VULNERABILITY"
    REGRESSION_DETECTED = "REGRESSION_DETECTED"
    STABLE_DEFENSE = "STABLE_DEFENSE"


class RegressionFindingDelta(BaseModel):
    correlation_key: str = Field(..., description="Canonical key: (affected_endpoint, risk_id, http_method, category)")
    affected_endpoint: str
    risk_id: str
    http_method: str
    category: str
    delta_type: str = Field(..., description="One of: NEW_VULNERABILITY, RESOLVED_VULNERABILITY, PERSISTENT_VULNERABILITY, REOPENED_VULNERABILITY, REGRESSION_DETECTED, STABLE_DEFENSE")
    baseline_status: Optional[str] = Field(None, description="Status/verdict in baseline run or 'UNTESTED'")
    current_status: Optional[str] = Field(None, description="Status/verdict in current run")
    severity: str = "MEDIUM"
    cvss_score: float = 0.0
    title: str = ""
    details: str = ""
    evidence_references: List[str] = Field(default_factory=list)


class PopulationDisclosure(BaseModel):
    has_population_discrepancy: bool = False
    baseline_total_scenarios: int = 0
    current_total_scenarios: int = 0
    intersection_scenarios_count: int = 0
    baseline_only_count: int = 0
    current_only_count: int = 0
    expansion_factor: float = 1.0
    warning_message: Optional[str] = None


class RegressionCompareRequest(BaseModel):
    baseline_plan_id: Optional[str] = Field(None, description="ID of baseline SecurityExecutionPlan")
    current_plan_id: Optional[str] = Field(None, description="ID of current SecurityExecutionPlan")
    baseline_session_id: Optional[str] = Field(None, description="ID of baseline AgentExecutionSession")
    current_session_id: Optional[str] = Field(None, description="ID of current AgentExecutionSession")
    allow_cross_environment: bool = Field(False, description="Set True to permit comparing across environments")
    allow_cross_target: bool = Field(False, description="Set True to permit comparing across targets")


class RegressionComparisonResponse(BaseModel):
    id: str
    comparison_id: str
    baseline_plan_id: Optional[str] = None
    current_plan_id: Optional[str] = None
    baseline_target: str
    current_target: str
    baseline_environment: Optional[str] = None
    current_environment: Optional[str] = None
    baseline_app_version: Optional[str] = None
    current_app_version: Optional[str] = None
    regression_verdict: str
    new_findings_count: int = 0
    resolved_findings_count: int = 0
    persistent_findings_count: int = 0
    reopened_findings_count: int = 0
    regression_findings_count: int = 0
    baseline_resilience_score: float = 1.0
    current_resilience_score: float = 1.0
    intersection_resilience_score: float = 1.0
    resilience_drift: float = 0.0
    expansion_factor: float = 1.0
    population_disclosure: PopulationDisclosure
    finding_deltas: List[RegressionFindingDelta] = Field(default_factory=list)
    created_at: datetime


class RegressionRunSummary(BaseModel):
    id: str
    comparison_id: str
    baseline_plan_id: Optional[str] = None
    current_plan_id: Optional[str] = None
    baseline_target: str
    current_target: str
    baseline_environment: Optional[str] = None
    current_environment: Optional[str] = None
    regression_verdict: str
    new_findings_count: int = 0
    resolved_findings_count: int = 0
    persistent_findings_count: int = 0
    reopened_findings_count: int = 0
    regression_findings_count: int = 0
    intersection_resilience_score: float = 1.0
    resilience_drift: float = 0.0
    expansion_factor: float = 1.0
    created_at: datetime


class RegressionHistoryResponse(BaseModel):
    comparisons: List[RegressionRunSummary] = Field(default_factory=list)
    total_count: int = 0


# =============================================================================
# PHASE E6: ENTERPRISE REPORTING SCHEMAS
# =============================================================================

class EnterpriseReportGenerateRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Optional ID of AgentExecutionSession")
    plan_id: Optional[str] = Field(None, description="Optional ID of SecurityExecutionPlan")
    report_type: str = Field("FULL_TECHNICAL", description="EXECUTIVE, FULL_TECHNICAL, or COMPLIANCE")
    formats: List[str] = Field(default_factory=lambda: ["json", "pdf", "xlsx", "csv"], description="Target export formats")
    lead_auditor: str = Field("ApexShield Security Engine", description="Designated lead auditor name")
    target_scope_override: Optional[str] = Field(None, description="Optional custom target scope URL")


class EnterpriseReportSummary(BaseModel):
    id: str
    report_id: str
    report_title: str
    report_type: str
    target_scope: str
    lead_auditor: str
    resilience_score: float = 1.0
    total_findings_count: int = 0
    critical_findings_count: int = 0
    high_findings_count: int = 0
    medium_findings_count: int = 0
    low_findings_count: int = 0
    report_hash: str
    hmac_signature: str
    signing_key_id: str = "v1_default"
    signing_algorithm: str = "HMAC-SHA256"
    has_pdf: bool = False
    has_excel: bool = False
    has_csv: bool = False
    has_json: bool = False
    created_at: datetime


class EnterpriseReportDetailResponse(BaseModel):
    summary: EnterpriseReportSummary
    report_data: Dict[str, Any]
    artifact_manifest: Dict[str, Any] = Field(default_factory=dict)
    download_urls: Dict[str, str] = Field(default_factory=dict)


class EnterpriseReportVerifyRequest(BaseModel):
    report_id: Optional[str] = Field(None, description="Optional ID of stored database report to verify")
    report_data: Optional[Dict[str, Any]] = Field(None, description="Optional raw report JSON dictionary to verify")
    expected_hash: Optional[str] = Field(None, description="Optional expected SHA-256 content digest")
    expected_signature: Optional[str] = Field(None, description="Optional expected HMAC-SHA256 signature")
    key_id: Optional[str] = Field(None, description="Optional signing key ID")


class EnterpriseReportVerifyResponse(BaseModel):
    is_valid: bool
    status: str
    content_integrity_verified: bool = False
    source_authenticity_verified: bool = False
    report_id: Optional[str] = None
    computed_hash: Optional[str] = None
    expected_hash: Optional[str] = None
    computed_signature: Optional[str] = None
    expected_signature: Optional[str] = None
    signing_key_id: Optional[str] = None
    details: Optional[str] = None


class EnterpriseReportHistoryResponse(BaseModel):
    reports: List[EnterpriseReportSummary] = Field(default_factory=list)
    total_count: int = 0


# =============================================================================
# PHASE E8: OPERATIONAL MONITORING & AUDITABILITY SCHEMAS
# =============================================================================

class OperationsOverviewResponse(BaseModel):
    active_sessions_count: int
    active_sessions: List[str] = Field(default_factory=list)
    concurrent_probes: int
    throughput_per_second: float
    throughput_per_minute: int
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    total_requests: int
    status_code_distribution: Dict[str, int] = Field(default_factory=dict)
    error_rates: Dict[str, float] = Field(default_factory=dict)
    timeouts_count: int
    connection_failures_count: int
    cancellations_count: int
    workers: List[Dict[str, Any]] = Field(default_factory=list)
    sample_window_size: int = 0


class OperationsHealthResponse(BaseModel):
    status: str
    timestamp: str
    telemetry_summary: Dict[str, Any]
    hmac_integrity: Dict[str, Any]
    circuit_breaker_summary: Dict[str, Any]


class HmacAuditResponse(BaseModel):
    total_verifications: int
    successful_verifications: int
    failed_verifications: int
    verification_success_rate: float
    tampering_events: int
    invalid_signatures: int
    missing_signatures: int
    unknown_keys: int
    health_status: str
    recent_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    recent_history: List[Dict[str, Any]] = Field(default_factory=list)


class CircuitBreakerStatusResponse(BaseModel):
    circuits: List[Dict[str, Any]] = Field(default_factory=list)
    total_circuits: int = 0
    open_circuits_count: int = 0


class CircuitBreakerResetRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Specific session ID to reset, or null to reset all circuits")
    admin_token: Optional[str] = Field(None, description="Administrative authorization credential")


class CircuitBreakerResetResponse(BaseModel):
    status: str
    message: str
    reset_count: int
    session_id: Optional[str] = None
    reset_timestamp: str


# =============================================================================
# PHASE E9: ENTERPRISE SECURITY OPERATIONS CENTER (SOC) SCHEMAS
# =============================================================================

class SocCapabilitySummary(BaseModel):
    name: str
    phase: str
    status: str
    metrics: Dict[str, Any] = Field(default_factory=dict)
    endpoint: str


class SocOverviewResponse(BaseModel):
    timestamp: str
    system_health: str
    execution_trace_id: Optional[str] = None
    active_target: Optional[str] = None
    active_session_id: Optional[str] = None
    context_filters: Dict[str, Optional[str]] = Field(default_factory=dict)
    capabilities: Dict[str, SocCapabilitySummary] = Field(default_factory=dict)
    summary_counts: Dict[str, int] = Field(default_factory=dict)






