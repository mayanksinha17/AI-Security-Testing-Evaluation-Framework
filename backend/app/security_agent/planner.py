"""Autonomous Security Test Plan Generator (Phase B & Phase C).

Transforms natural language interpretations or explicit risk selections into
persisted, structured execution plans with mapped payloads and individual test records.
Supports multi-turn execution chain grouping, mutation inspection, and final assessment reporting.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.attacks.scenarios import get_all_scenarios, get_scenarios_by_risk
from app.security_agent.crypto import verify_evidence_signature
from app.security_agent.interpreter import CommandInterpreter
from app.security_agent.models import (
    AgentExecutionSession,
    HttpEvidenceRecord,
    SecurityExecutionPlan,
    SecurityTestExecution,
)
from app.security_agent.mutation_engine import MUTATION_STRATEGIES, PayloadMutationEngine
from app.security_agent.payloads import get_payload_for_scenario
from app.security_agent.schemas import (
    AutonomousAssessmentReport,
    CommandInterpretationRequest,
    CreatePlanRequest,
    ExecutionChainGroup,
    ExecutionPlanSummary,
    MutationNode,
    PlanFindingsSummary,
    ScopeStatusEnum,
    TestExecutionSummary,
)
from app.security_agent.scope_validator import ScopeValidator
from app.security_agent.target_resolver import TargetResolver


def _build_test_summary(t: SecurityTestExecution) -> TestExecutionSummary:
    return TestExecutionSummary(
        execution_id=t.id,
        plan_id=t.plan_id,
        scenario_id=t.scenario_id,
        risk_id=t.risk_id,
        risk_name=t.risk_name,
        category=t.category,
        test_type=t.test_type,
        target_endpoint=t.target_endpoint,
        http_method=t.http_method,
        payload_id=t.payload_id,
        status=t.status,
        verdict=t.verdict,
        duration_ms=t.duration_ms,
        created_at=t.created_at,
        turn_number=t.turn_number or 1,
        parent_execution_id=t.parent_execution_id,
        chain_id=t.chain_id or t.id,
        payload_version=t.payload_version or "v1",
        mutation_technique=t.mutation_technique,
        confidence=t.confidence if t.confidence is not None else 1.0,
        notes=t.notes,
    )


class SecurityPlanGenerator:
    """Generates, tracks, and inspects dynamic security execution plans."""

    @classmethod
    def create_plan(
        cls,
        request: CreatePlanRequest,
        db: Session,
    ) -> ExecutionPlanSummary:
        """Creates and persists an execution plan with test executions in PENDING state."""
        command_text = request.command or "Targeted automated security plan"
        target_url = request.target_url or "http://127.0.0.1:8000"
        stage = request.stage.upper() if request.stage else "POST_MITIGATION"

        # 1. Natural language command interpretation if command is provided
        if request.command and request.command.strip():
            from app.security_agent.risk_identifier import RISK_REGISTRY, RiskIdentifier
            invalid_risks = RiskIdentifier.extract_invalid_risks(request.command)
            if invalid_risks:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"Unsupported or invalid OWASP risk identifier(s) detected: {', '.join(invalid_risks)}. "
                        f"Supported risks are: {', '.join(sorted(RISK_REGISTRY.keys()))}."
                    ),
                )

            interpretation = CommandInterpreter.interpret(
                CommandInterpretationRequest(
                    command=request.command,
                    target_url=request.target_url,
                    user_confirmed_authorization=request.user_confirmed_authorization,
                    auth_headers=request.auth_headers,
                )
            )

            if not interpretation.target.is_in_scope:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Target URL is out of scope or blocked: {interpretation.target.reason}",
                )

            target_url = interpretation.target.normalized_url
            target_is_local = interpretation.target.is_local
            stage = interpretation.execution_instructions.get("stage", stage)
            if stage == "BOTH":
                stage = "POST_MITIGATION"

            # When command contains specific risk instructions, it is the authoritative source
            if interpretation.plan_preview:
                selected_scenario_ids = [p.scenario_id for p in interpretation.plan_preview]
            elif request.scenario_ids:
                selected_scenario_ids = request.scenario_ids
            elif request.risk_ids:
                selected_scenario_ids = []
                for r_id in request.risk_ids:
                    scenarios = get_scenarios_by_risk(r_id)
                    selected_scenario_ids.extend([s.scenario_id for s in scenarios])
            else:
                selected_scenario_ids = []
                for r_id in ["LLM01", "LLM02", "ASI01", "ASI02"]:
                    scenarios = get_scenarios_by_risk(r_id)
                    selected_scenario_ids.extend([s.scenario_id for s in scenarios])
        else:
            target_scope = ScopeValidator.resolve_and_validate_target(
                raw_url=target_url,
                user_confirmed_authorization=request.user_confirmed_authorization,
            )
            if not target_scope.is_in_scope:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Target URL is out of scope or blocked: {target_scope.reason}",
                )
            target_url = target_scope.normalized_url
            target_is_local = target_scope.is_local

            if request.scenario_ids:
                selected_scenario_ids = request.scenario_ids
            elif request.risk_ids:
                selected_scenario_ids = []
                for r_id in request.risk_ids:
                    scenarios = get_scenarios_by_risk(r_id)
                    selected_scenario_ids.extend([s.scenario_id for s in scenarios])
            else:
                selected_scenario_ids = []
                for r_id in ["LLM01", "LLM02", "ASI01", "ASI02"]:
                    scenarios = get_scenarios_by_risk(r_id)
                    selected_scenario_ids.extend([s.scenario_id for s in scenarios])

        unique_scenario_ids = list(dict.fromkeys(selected_scenario_ids))

        all_known_scenarios = {s.scenario_id: s for s in get_all_scenarios()}
        planned_test_records: List[SecurityTestExecution] = []

        session_record = AgentExecutionSession(
            title=f"Security Plan for {len(unique_scenario_ids)} Scenarios",
            command=command_text,
            user_confirmed_authorization=request.user_confirmed_authorization,
            status="PLANNED",
        )
        db.add(session_record)
        db.flush()

        plan_record = SecurityExecutionPlan(
            session_id=session_record.id,
            target_url=target_url,
            is_local_target=target_is_local,
            stage=stage,
            total_tests=len(unique_scenario_ids),
            completed_tests=0,
            status="PENDING",
            plan_metadata=json.dumps({
                "command": command_text,
                "stage": stage,
                "target_url": target_url,
                "scenarios": unique_scenario_ids,
            }),
        )
        db.add(plan_record)
        db.flush()

        for sc_id in unique_scenario_ids:
            sc_meta = all_known_scenarios.get(sc_id)
            risk_id = sc_meta.risk_id if sc_meta else sc_id.split("-")[0]
            risk_name = sc_meta.risk_name if sc_meta else f"Risk {risk_id}"
            category = sc_meta.category if sc_meta else "OWASP_LLM"
            test_type = sc_meta.test_type if sc_meta else "security_test"

            init_payload = PayloadMutationEngine.get_initial_payload(sc_id, risk_id)

            test_exec = SecurityTestExecution(
                plan_id=plan_record.id,
                scenario_id=sc_id,
                risk_id=risk_id,
                risk_name=risk_name,
                category=category,
                test_type=test_type,
                target_endpoint=init_payload.target_endpoint,
                http_method=init_payload.http_method,
                payload_id=init_payload.payload_id,
                status="PENDING",
                verdict="PENDING",
                turn_number=1,
                payload_version="v1",
                mutation_technique="baseline_probe",
            )
            db.add(test_exec)
            db.flush()
            test_exec.chain_id = test_exec.id  # Set chain_id to root test ID
            planned_test_records.append(test_exec)

        db.commit()
        db.refresh(plan_record)

        test_summaries = [_build_test_summary(t) for t in planned_test_records]

        return ExecutionPlanSummary(
            plan_id=plan_record.id,
            session_id=session_record.id,
            target_url=plan_record.target_url,
            is_local_target=plan_record.is_local_target,
            stage=plan_record.stage,
            total_tests=plan_record.total_tests,
            completed_tests=plan_record.completed_tests,
            status=plan_record.status,
            created_at=plan_record.created_at,
            completed_at=plan_record.completed_at,
            tests=test_summaries,
        )

    @classmethod
    def get_plan(cls, plan_id: str, db: Session) -> ExecutionPlanSummary:
        """Retrieves an existing execution plan and its tests by ID."""
        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution plan '{plan_id}' not found.",
            )

        test_summaries = [_build_test_summary(t) for t in plan.executions]

        return ExecutionPlanSummary(
            plan_id=plan.id,
            session_id=plan.session_id,
            target_url=plan.target_url,
            is_local_target=plan.is_local_target,
            stage=plan.stage,
            total_tests=plan.total_tests,
            completed_tests=plan.completed_tests,
            status=plan.status,
            created_at=plan.created_at,
            completed_at=plan.completed_at,
            tests=test_summaries,
        )

    @classmethod
    def get_findings(cls, plan_id: str, db: Session) -> PlanFindingsSummary:
        """Calculates consolidated findings, metrics, and risk breakdowns for a plan."""
        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution plan '{plan_id}' not found.",
            )

        executions = plan.executions
        total_tests = len(executions)
        vulnerable_count = sum(1 for e in executions if e.verdict == "VULNERABLE")
        blocked_count = sum(1 for e in executions if e.verdict == "BLOCKED")
        error_count = sum(1 for e in executions if e.verdict == "ERROR")
        cancelled_count = sum(1 for e in executions if e.verdict == "CANCELLED")

        completed_count = vulnerable_count + blocked_count + error_count
        evaluable_total = vulnerable_count + blocked_count

        block_rate = round((blocked_count / evaluable_total * 100.0), 1) if evaluable_total > 0 else 0.0
        vuln_rate = round((vulnerable_count / evaluable_total * 100.0), 1) if evaluable_total > 0 else 0.0

        risk_breakdown: Dict[str, Dict[str, Any]] = {}
        for e in executions:
            if e.risk_id not in risk_breakdown:
                risk_breakdown[e.risk_id] = {
                    "risk_id": e.risk_id,
                    "risk_name": e.risk_name,
                    "total": 0,
                    "vulnerable": 0,
                    "blocked": 0,
                    "error": 0,
                }
            risk_breakdown[e.risk_id]["total"] += 1
            if e.verdict == "VULNERABLE":
                risk_breakdown[e.risk_id]["vulnerable"] += 1
            elif e.verdict == "BLOCKED":
                risk_breakdown[e.risk_id]["blocked"] += 1
            elif e.verdict == "ERROR":
                risk_breakdown[e.risk_id]["error"] += 1

        evidence_count = (
            db.query(HttpEvidenceRecord)
            .join(SecurityTestExecution, HttpEvidenceRecord.execution_id == SecurityTestExecution.id)
            .filter(SecurityTestExecution.plan_id == plan_id)
            .count()
        )

        return PlanFindingsSummary(
            plan_id=plan.id,
            target_url=plan.target_url,
            stage=plan.stage,
            status=plan.status,
            total_tests=total_tests,
            completed_tests=completed_count,
            vulnerable_count=vulnerable_count,
            blocked_count=blocked_count,
            error_count=error_count,
            cancelled_count=cancelled_count,
            vulnerability_rate_percent=vuln_rate,
            block_rate_percent=block_rate,
            risk_breakdown=risk_breakdown,
            evidence_records_count=evidence_count,
        )

    @classmethod
    def get_execution_chains(cls, plan_id: str, db: Session) -> List[ExecutionChainGroup]:
        """Groups multi-turn executions by chain ID with progression details."""
        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution plan '{plan_id}' not found.",
            )

        chains_dict: Dict[str, List[SecurityTestExecution]] = {}
        for test in plan.executions:
            chain_key = test.chain_id or test.scenario_id
            if chain_key not in chains_dict:
                chains_dict[chain_key] = []
            chains_dict[chain_key].append(test)

        chain_groups: List[ExecutionChainGroup] = []
        for chain_key, tests in chains_dict.items():
            sorted_tests = sorted(tests, key=lambda t: t.turn_number or 1)
            final_test = sorted_tests[-1]
            root_test = sorted_tests[0]

            chain_groups.append(
                ExecutionChainGroup(
                    chain_id=chain_key,
                    scenario_id=root_test.scenario_id,
                    scenario_name=root_test.risk_name,
                    risk_id=root_test.risk_id,
                    total_turns=len(sorted_tests),
                    final_verdict=final_test.verdict,
                    final_confidence=final_test.confidence if final_test.confidence is not None else 1.0,
                    turns=[_build_test_summary(t) for t in sorted_tests],
                )
            )

        return chain_groups

    @classmethod
    def get_mutations(cls, plan_id: str, db: Session) -> List[MutationNode]:
        """Returns the payload mutation history across all scenarios in the plan."""
        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution plan '{plan_id}' not found.",
            )

        nodes: List[MutationNode] = []
        for test in plan.executions:
            rationale = "Initial baseline probe"
            if test.turn_number and test.turn_number > 1:
                strategies = MUTATION_STRATEGIES.get(test.scenario_id, [])
                for s in strategies:
                    if s["version"] == test.payload_version:
                        rationale = s["rationale"]
                        break

            nodes.append(
                MutationNode(
                    payload_id=test.payload_id,
                    version=test.payload_version or "v1",
                    parent_payload_id=test.parent_execution_id,
                    scenario_id=test.scenario_id,
                    risk_id=test.risk_id,
                    mutation_technique=test.mutation_technique or "baseline_probe",
                    mutation_rationale=rationale,
                    turn_number=test.turn_number or 1,
                    verdict=test.verdict,
                )
            )
        return nodes

    @classmethod
    def generate_assessment_report(cls, plan_id: str, db: Session) -> AutonomousAssessmentReport:
        """Generates an executive cybersecurity assessment report with verified HMAC-SHA256 integrity."""
        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution plan '{plan_id}' not found.",
            )

        chains = cls.get_execution_chains(plan_id, db)
        total_scenarios = len(chains)
        total_turns = sum(c.total_turns for c in chains)

        # Granular outcome classification across all scenario chains
        blocked_scenarios = sum(1 for c in chains if c.final_verdict == "BLOCKED")
        vulnerable_scenarios = sum(1 for c in chains if c.final_verdict == "VULNERABLE")
        partial_scenarios = sum(1 for c in chains if c.final_verdict == "PARTIAL")
        error_scenarios = sum(1 for c in chains if c.final_verdict == "ERROR")
        inconclusive_scenarios = sum(1 for c in chains if c.final_verdict == "INCONCLUSIVE")
        not_run_scenarios = sum(1 for c in chains if c.final_verdict == "NOT_RUN")
        cancelled_scenarios = sum(1 for c in chains if c.final_verdict == "CANCELLED")

        evaluable_scenarios = blocked_scenarios + vulnerable_scenarios + partial_scenarios

        # Exact Evaluable Resilience Formula (Phase C.1):
        # Resilience = BLOCKED / (BLOCKED + VULNERABLE + PARTIAL) * 100
        # When evaluable_scenarios == 0, score is strictly 0.0% (not inflated 100%)
        if evaluable_scenarios > 0:
            resilience_score = round((blocked_scenarios / evaluable_scenarios * 100.0), 1)
        else:
            resilience_score = 0.0

        infrastructure_error_rate_percent = (
            round((error_scenarios / total_scenarios * 100.0), 1)
            if total_scenarios > 0
            else 0.0
        )
        evaluable_coverage_percent = (
            round((evaluable_scenarios / total_scenarios * 100.0), 1)
            if total_scenarios > 0
            else 0.0
        )

        risk_assessments: Dict[str, Dict[str, Any]] = {}
        for c in chains:
            if c.risk_id not in risk_assessments:
                risk_assessments[c.risk_id] = {
                    "risk_id": c.risk_id,
                    "scenarios_tested": 0,
                    "blocked_scenarios": 0,
                    "vulnerable_scenarios": 0,
                    "partial_scenarios": 0,
                    "error_scenarios": 0,
                    "inconclusive_scenarios": 0,
                    "status": "SECURE",
                    "severity": "HIGH",
                }
            risk_assessments[c.risk_id]["scenarios_tested"] += 1
            if c.final_verdict == "VULNERABLE":
                risk_assessments[c.risk_id]["vulnerable_scenarios"] += 1
                risk_assessments[c.risk_id]["status"] = "VULNERABLE_CONFIRMED"
            elif c.final_verdict == "BLOCKED":
                risk_assessments[c.risk_id]["blocked_scenarios"] += 1
            elif c.final_verdict == "PARTIAL":
                risk_assessments[c.risk_id]["partial_scenarios"] += 1
            elif c.final_verdict == "ERROR":
                risk_assessments[c.risk_id]["error_scenarios"] += 1
            elif c.final_verdict == "INCONCLUSIVE":
                risk_assessments[c.risk_id]["inconclusive_scenarios"] += 1

        remediations: List[Dict[str, str]] = []
        for r_id, assessment in risk_assessments.items():
            if assessment["vulnerable_scenarios"] > 0:
                if r_id == "LLM01":
                    remediations.append({
                        "risk_id": "LLM01",
                        "title": "Enforce Strict System Prompt Delimiters & Secondary Input Stripping",
                        "remediation": "Deploy input sanitization filters and strict markdown/xml boundary fences to prevent prompt injection overrides.",
                    })
                elif r_id == "LLM02":
                    remediations.append({
                        "risk_id": "LLM02",
                        "title": "Implement Output Redaction Filters for Synthetic Credentials",
                        "remediation": "Apply regular expression egress filters and token guards to intercept canary and credential disclosure in model outputs.",
                    })
                elif r_id == "ASI01":
                    remediations.append({
                        "risk_id": "ASI01",
                        "title": "Establish Immutable Goal Verification & State Auditing",
                        "remediation": "Pin the agent core mission into immutable read-only storage and require out-of-band operator signatures for task redirection.",
                    })
                elif r_id == "ASI02":
                    remediations.append({
                        "risk_id": "ASI02",
                        "title": "Enforce Strict Tool Allowlisting & Path Traversal Canonicalization",
                        "remediation": "Reject unapproved tool identifiers and resolve canonical file paths within an unprivileged sandbox jail.",
                    })

        # Verify integrity of all stored evidence hashes via HMAC-SHA256 constant-time verification
        all_integrity_verified = True
        evidence_records = (
            db.query(HttpEvidenceRecord)
            .join(SecurityTestExecution, HttpEvidenceRecord.execution_id == SecurityTestExecution.id)
            .filter(SecurityTestExecution.plan_id == plan_id)
            .all()
        )
        for ev in evidence_records:
            if ev.evidence_sha256:
                raw_payload = (
                    f"{ev.target_url}|{ev.http_method}|{ev.request_body}|"
                    f"{ev.response_status_code}|{ev.response_body}"
                )
                if not verify_evidence_signature(raw_payload, ev.evidence_sha256):
                    all_integrity_verified = False
                    break

        return AutonomousAssessmentReport(
            plan_id=plan.id,
            target_url=plan.target_url,
            stage=plan.stage,
            status=plan.status,
            total_scenarios_tested=total_scenarios,
            total_turns_dispatched=total_turns,
            total_vulnerabilities_confirmed=vulnerable_scenarios,
            overall_resilience_score_percent=resilience_score,
            evaluable_scenarios=evaluable_scenarios,
            blocked_scenarios=blocked_scenarios,
            vulnerable_scenarios=vulnerable_scenarios,
            partial_scenarios=partial_scenarios,
            error_scenarios=error_scenarios,
            inconclusive_scenarios=inconclusive_scenarios,
            not_run_scenarios=not_run_scenarios,
            cancelled_scenarios=cancelled_scenarios,
            infrastructure_error_rate_percent=infrastructure_error_rate_percent,
            evaluable_coverage_percent=evaluable_coverage_percent,
            resilience_formula="BLOCKED / (BLOCKED + VULNERABLE + PARTIAL) * 100",
            risk_assessments=risk_assessments,
            remediation_recommendations=remediations,
            evidence_integrity_verified=all_integrity_verified,
            generated_at=datetime.now(timezone.utc),
        )
