"""Autonomous AI Security Testing Agent package (Phase A, Phase B & Phase C).

Exports components for command interpretation, risk identification,
target resolution, authorization/scope validation, dynamic test planning,
real HTTP execution, adaptive payload mutation, intelligent response analysis,
autonomous decision engine, and multi-turn execution.
"""

from app.security_agent.attack_graph_engine import AttackGraphEngine
from app.security_agent.decision_engine import AutonomousDecisionEngine, ExecutionLimits
from app.security_agent.evidence_registry import EvidenceRegistry
from app.security_agent.executor import AsyncHttpExecutor
from app.security_agent.finding_lifecycle import FindingLifecycleEngine, InvalidLifecycleTransitionError
from app.security_agent.intelligence_engine import DynamicSecurityIntelligenceEngine
from app.security_agent.interpreter import CommandInterpreter
from app.security_agent.multi_turn import MultiTurnExecutionEngine
from app.security_agent.mutation_engine import PayloadMutationEngine
from app.security_agent.planner import SecurityPlanGenerator
from app.security_agent.response_analyzer import IntelligentResponseAnalyzer, SecurityVerdictEnum
from app.security_agent.risk_identifier import RiskIdentifier
from app.security_agent.routes import router as security_agent_router
from app.security_agent.schemas import FindingLifecycleStatusEnum, FindingSeverityEnum
from app.security_agent.schema_intelligence import DeepOpenApiSchemaIntelligence, SchemaSecurityViolation
from app.security_agent.scope_validator import ScopeValidator
from app.security_agent.target_resolver import TargetResolver

__all__ = [
    "CommandInterpreter",
    "RiskIdentifier",
    "TargetResolver",
    "ScopeValidator",
    "SecurityPlanGenerator",
    "AsyncHttpExecutor",
    "MultiTurnExecutionEngine",
    "PayloadMutationEngine",
    "IntelligentResponseAnalyzer",
    "AutonomousDecisionEngine",
    "ExecutionLimits",
    "SecurityVerdictEnum",
    "DynamicSecurityIntelligenceEngine",
    "AttackGraphEngine",
    "DeepOpenApiSchemaIntelligence",
    "SchemaSecurityViolation",
    "FindingLifecycleEngine",
    "EvidenceRegistry",
    "InvalidLifecycleTransitionError",
    "FindingLifecycleStatusEnum",
    "FindingSeverityEnum",
    "security_agent_router",
]

