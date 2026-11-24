"""Vulnerability & Evidence Lifecycle Engine (Phase E4).

Implements a formal 11-state vulnerability lifecycle state machine with guarded transitions,
immutable audit history tracking, secondary confirmation enforcement, and explainable decision traces.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse
import uuid
from sqlalchemy.orm import Session

from app.security_agent.crypto import EvidenceTrustLevel
from app.security_agent.evidence_registry import EvidenceRegistry
from app.security_agent.models import (
    HttpEvidenceRecord,
    SecurityDecision,
    SecurityFinding,
    SecurityFindingHistory,
    SecurityTestExecution,
)
from app.security_agent.schemas import (
    FindingLifecycleStatusEnum,
    FindingListResponse,
    FindingSeverityEnum,
    LifecycleBoardColumn,
    LifecycleBoardResponse,
    SecurityDecisionCreate,
    SecurityDecisionResponse,
    SecurityFindingCreate,
    SecurityFindingHistoryResponse,
    SecurityFindingResponse,
    SecurityFindingUpdate,
    TransitionFindingStateRequest,
)

logger = logging.getLogger(__name__)


class InvalidLifecycleTransitionError(Exception):
    """Raised when an illegal or unguarded vulnerability lifecycle state transition is attempted."""
    def __init__(
        self,
        from_state: str = "UNKNOWN",
        to_state: str = "UNKNOWN",
        reason: str = "",
        permitted: Optional[List[str]] = None,
    ):
        self.from_state = from_state
        self.to_state = to_state
        self.reason = reason
        self.permitted = permitted or []
        if from_state != "UNKNOWN" or to_state != "UNKNOWN":
            msg = f"Invalid transition from '{from_state}' to '{to_state}': {reason}"
        else:
            msg = reason
        if self.permitted:
            msg += f" (Permitted next states: {', '.join(self.permitted)})"
        super().__init__(msg)


class ConcurrencyConflictError(Exception):
    """Raised when an optimistic concurrency collision occurs during a finding state transition (SEC-E4-003)."""
    def __init__(self, finding_id: str, current_version: int, expected_version: int, message: Optional[str] = None):
        self.finding_id = finding_id
        self.current_version = current_version
        self.expected_version = expected_version
        msg = message or f"Optimistic lock conflict on finding '{finding_id}': expected version {expected_version}, but finding is currently at version {current_version}."
        super().__init__(msg)


# Formal 11-State Permitted Transition Graph
PERMITTED_TRANSITIONS: Dict[FindingLifecycleStatusEnum, Set[FindingLifecycleStatusEnum]] = {
    FindingLifecycleStatusEnum.DETECTED: {
        FindingLifecycleStatusEnum.TRIAGE,
        FindingLifecycleStatusEnum.POTENTIAL,
        FindingLifecycleStatusEnum.REFUTED,
        FindingLifecycleStatusEnum.INCONCLUSIVE,
    },
    FindingLifecycleStatusEnum.TRIAGE: {
        FindingLifecycleStatusEnum.POTENTIAL,
        FindingLifecycleStatusEnum.REFUTED,
        FindingLifecycleStatusEnum.INCONCLUSIVE,
        FindingLifecycleStatusEnum.CLOSED,
    },
    FindingLifecycleStatusEnum.POTENTIAL: {
        FindingLifecycleStatusEnum.CONFIRMED,
        FindingLifecycleStatusEnum.REFUTED,
        FindingLifecycleStatusEnum.INCONCLUSIVE,
    },
    FindingLifecycleStatusEnum.CONFIRMED: {
        FindingLifecycleStatusEnum.REMEDIATION_PLANNED,
        FindingLifecycleStatusEnum.REMEDIATION_IN_PROGRESS,
        FindingLifecycleStatusEnum.REFUTED,
        FindingLifecycleStatusEnum.CLOSED,
    },
    FindingLifecycleStatusEnum.REMEDIATION_PLANNED: {
        FindingLifecycleStatusEnum.REMEDIATION_IN_PROGRESS,
        FindingLifecycleStatusEnum.READY_FOR_RETEST,
        FindingLifecycleStatusEnum.CONFIRMED,
    },
    FindingLifecycleStatusEnum.REMEDIATION_IN_PROGRESS: {
        FindingLifecycleStatusEnum.READY_FOR_RETEST,
        FindingLifecycleStatusEnum.REMEDIATION_PLANNED,
    },
    FindingLifecycleStatusEnum.READY_FOR_RETEST: {
        FindingLifecycleStatusEnum.REMEDIATION_VERIFIED,
        FindingLifecycleStatusEnum.CONFIRMED,
        FindingLifecycleStatusEnum.INCONCLUSIVE,
    },
    FindingLifecycleStatusEnum.REMEDIATION_VERIFIED: {
        FindingLifecycleStatusEnum.CLOSED,
        FindingLifecycleStatusEnum.DETECTED,  # Reopened on regression run
    },
    FindingLifecycleStatusEnum.REFUTED: {
        FindingLifecycleStatusEnum.TRIAGE,
        FindingLifecycleStatusEnum.DETECTED,
        FindingLifecycleStatusEnum.CLOSED,
    },
    FindingLifecycleStatusEnum.INCONCLUSIVE: {
        FindingLifecycleStatusEnum.TRIAGE,
        FindingLifecycleStatusEnum.READY_FOR_RETEST,
        FindingLifecycleStatusEnum.CLOSED,
    },
    FindingLifecycleStatusEnum.CLOSED: {
        FindingLifecycleStatusEnum.DETECTED,  # Reopened on regression run
    },
}


class FindingLifecycleEngine:
    """Formal Vulnerability Lifecycle Engine with transition guards and audit logging."""

    @staticmethod
    def _parse_and_normalize_target_authority(
        raw_url: str,
        label: str = "target URL",
        from_state: str = "UNKNOWN",
        to_state: str = "UNKNOWN",
    ) -> Tuple[str, str, int]:
        """Parses and normalizes target URL into (scheme, hostname, port).
        
        Enforces:
        - Exact scheme validation (only 'http' and 'https' permitted)
        - Hostname normalization (lowercase, stripped IPv6 brackets)
        - Scheme-aware default port normalization (HTTP:80, HTTPS:443)
        - Bounded port validation (1-65535)
        - Controlled InvalidLifecycleTransitionError on missing or invalid components
        """
        if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
            raise InvalidLifecycleTransitionError(
                from_state=from_state,
                to_state=to_state,
                reason=f"Invalid {label}: URL string is empty or missing.",
            )
        clean = raw_url.strip()
        try:
            parsed = urlparse(clean)
        except Exception as ex:
            raise InvalidLifecycleTransitionError(
                from_state=from_state,
                to_state=to_state,
                reason=f"Malformed {label} '{clean}': {ex}",
            )

        scheme = (parsed.scheme or "").lower()
        if not scheme:
            raise InvalidLifecycleTransitionError(
                from_state=from_state,
                to_state=to_state,
                reason=f"Invalid {label} '{clean}': Missing URL scheme (must be 'http' or 'https').",
            )
        if scheme not in ("http", "https"):
            raise InvalidLifecycleTransitionError(
                from_state=from_state,
                to_state=to_state,
                reason=f"Invalid {label} '{clean}': Unsupported scheme '{scheme}'. Only 'http' and 'https' are permitted.",
            )

        hostname = parsed.hostname
        if not hostname:
            raise InvalidLifecycleTransitionError(
                from_state=from_state,
                to_state=to_state,
                reason=f"Invalid {label} '{clean}': Missing or unparseable host authority.",
            )
        hostname = hostname.lower()

        try:
            port = parsed.port
        except ValueError as ex:
            raise InvalidLifecycleTransitionError(
                from_state=from_state,
                to_state=to_state,
                reason=f"Invalid {label} '{clean}': Invalid port value ({ex}).",
            )

        if port is None:
            port = 80 if scheme == "http" else 443
        elif port <= 0 or port > 65535:
            raise InvalidLifecycleTransitionError(
                from_state=from_state,
                to_state=to_state,
                reason=f"Invalid {label} '{clean}': Port {port} out of valid TCP range (1-65535).",
            )

        return scheme, hostname, port

    @staticmethod
    def _normalize_endpoint_path(raw_path_or_url: str) -> str:
        """Normalizes an endpoint path for strict comparison:
        - Strips scheme, host, query string, and fragment if full URL
        - Decodes URL-encoded path characters (unquote)
        - Normalizes leading and trailing slashes
        """
        if not raw_path_or_url or not isinstance(raw_path_or_url, str):
            return "/"
        clean = raw_path_or_url.strip()
        parsed = urlparse(clean)
        path = parsed.path if parsed.path else clean.split("?")[0].split("#")[0]
        unquoted = unquote(path)
        normalized = "/" + unquoted.strip("/") if unquoted.strip("/") else "/"
        return normalized

    @staticmethod
    def _extract_plan_context(plan: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Safely extracts (application_id, environment, app_version) from a SecurityExecutionPlan.
        
        Supports:
        - Dictionary-based metadata
        - Valid JSON-serialized metadata string
        - Existing model attributes if present
        - Never raises AttributeError, ValueError, or unhandled exceptions
        """
        if plan is None:
            return None, None, None

        raw_meta = getattr(plan, "plan_metadata", None)
        meta: Dict[str, Any] = {}
        if isinstance(raw_meta, dict):
            meta = raw_meta
        elif isinstance(raw_meta, str) and raw_meta.strip():
            try:
                parsed = json.loads(raw_meta.strip())
                if isinstance(parsed, dict):
                    meta = parsed
                else:
                    meta = {}
            except Exception:
                meta = {}

        app_id = meta.get("application_id")
        if app_id is None:
            app_id = getattr(plan, "application_id", None)

        env = meta.get("environment")
        if env is None:
            env = getattr(plan, "environment", None)

        ver = meta.get("app_version")
        if ver is None:
            ver = getattr(plan, "app_version", None)

        app_id_str = str(app_id).strip() if app_id is not None else None
        env_str = str(env).strip() if env is not None else None
        ver_str = str(ver).strip() if ver is not None else None

        return app_id_str, env_str, ver_str

    @classmethod
    def validate_transition(
        cls,
        current_state: FindingLifecycleStatusEnum,
        target_state: FindingLifecycleStatusEnum,
        evidence_reference: Optional[str] = None,
        secondary_execution_id: Optional[str] = None,
        actor: str = "AutonomousSecurityAgent",
        reason: Optional[str] = None,
        is_secondary_confirmed: bool = False,
        db: Optional[Session] = None,
        finding: Optional[SecurityFinding] = None,
    ) -> None:
        """Validates whether a transition from current_state to target_state is permitted and meets guard conditions.
        
        Enforces:
        - Structural transition matrix (PERMITTED_TRANSITIONS)
        - SEC-E4-001: Mandatory Cryptographic HMAC-SHA256 evidence verification & repository existence
        - SEC-E4-002: Cross-entity metadata correlation (target, endpoint, method, risk, assessment context) and distinct executions
        - Post-mitigation retest evidence for REMEDIATION_VERIFIED
        - Administrative justification for CLOSED
        """
        permitted = PERMITTED_TRANSITIONS.get(current_state, set())
        permitted_names = [s.value for s in permitted]

        # 1. Structural Transition Matrix Check
        if target_state not in permitted:
            raise InvalidLifecycleTransitionError(
                from_state=current_state.value,
                to_state=target_state.value,
                reason="Transition is not permitted by formal lifecycle graph.",
                permitted=permitted_names,
            )

        # 2. Guard: CONFIRMED requires independent secondary confirmation probe & HMAC evidence
        if target_state == FindingLifecycleStatusEnum.CONFIRMED:
            if not is_secondary_confirmed:
                raise InvalidLifecycleTransitionError(
                    from_state=current_state.value,
                    to_state=target_state.value,
                    reason="Confirmation requires independent secondary probe confirmation (single-turn anomalies cannot confirm).",
                    permitted=permitted_names,
                )
            if not evidence_reference or not evidence_reference.strip():
                raise InvalidLifecycleTransitionError(
                    from_state=current_state.value,
                    to_state=target_state.value,
                    reason="Confirmation requires an attached cryptographic wire evidence reference.",
                    permitted=permitted_names,
                )

            # SEC-E4-001 & SEC-E4-002: Deep Evidence Authenticity and Metadata Correlation
            if db is not None:
                sec_ev = EvidenceRegistry.get_evidence_by_id_or_hash(db, evidence_reference.strip())
                if not sec_ev:
                    raise InvalidLifecycleTransitionError(
                        from_state=current_state.value,
                        to_state=target_state.value,
                        reason=f"Confirmation rejected: Referenced secondary evidence '{evidence_reference}' does not exist in repository.",
                        permitted=permitted_names,
                    )

                # SEC-E4-001: Cryptographic HMAC Verification (reject legacy SHA256, invalid, or missing digests)
                trust_level, is_valid, details_msg = EvidenceRegistry.verify_evidence_authenticity(sec_ev)
                if trust_level != EvidenceTrustLevel.HMAC_VERIFIED or not is_valid:
                    raise InvalidLifecycleTransitionError(
                        from_state=current_state.value,
                        to_state=target_state.value,
                        reason=f"Confirmation rejected: Requires cryptographically authenticated HMAC-SHA256 evidence. Trust level: {trust_level.value} ({details_msg}).",
                        permitted=permitted_names,
                    )

                # SEC-E4-002: Cross-Entity Metadata & Execution Correlation
                if finding is not None:
                    # 1. Primary and Secondary Execution Distinctness
                    sec_exec_id = secondary_execution_id or sec_ev.execution_id
                    primary_exec_id = finding.execution_id

                    if primary_exec_id and sec_exec_id:
                        if str(primary_exec_id).strip() == str(sec_exec_id).strip():
                            raise InvalidLifecycleTransitionError(
                                from_state=current_state.value,
                                to_state=target_state.value,
                                reason=f"Confirmation rejected: Independent confirmation requires distinct executions. Primary execution '{primary_exec_id}' cannot equal secondary confirmation execution '{sec_exec_id}'.",
                                permitted=permitted_names,
                            )

                    # 2. Verify Primary Evidence Authenticity if linked
                    if primary_exec_id:
                        primary_ev = db.query(HttpEvidenceRecord).filter(HttpEvidenceRecord.execution_id == primary_exec_id).first()
                        if primary_ev:
                            p_trust, p_valid, p_msg = EvidenceRegistry.verify_evidence_authenticity(primary_ev)
                            if p_trust != EvidenceTrustLevel.HMAC_VERIFIED or not p_valid:
                                raise InvalidLifecycleTransitionError(
                                    from_state=current_state.value,
                                    to_state=target_state.value,
                                    reason=f"Confirmation rejected: Primary probe evidence cryptographic verification failed: {p_trust.value} ({p_msg}).",
                                    permitted=permitted_names,
                                )

                    # 3. Target Scheme, Host & Port Normalization & Validation (SEC-E4-002-A & SEC-E4-002-C)
                    if sec_ev.target_url and finding.target_identity:
                        sec_scheme, sec_host, sec_port = cls._parse_and_normalize_target_authority(
                            sec_ev.target_url,
                            label="evidence target URL",
                            from_state=current_state.value,
                            to_state=target_state.value,
                        )
                        find_scheme, find_host, find_port = cls._parse_and_normalize_target_authority(
                            finding.target_identity,
                            label="finding target identity",
                            from_state=current_state.value,
                            to_state=target_state.value,
                        )
                        if sec_scheme != find_scheme:
                            raise InvalidLifecycleTransitionError(
                                from_state=current_state.value,
                                to_state=target_state.value,
                                reason=f"Confirmation rejected: Evidence URL scheme '{sec_scheme}' does not match finding target scheme '{find_scheme}'.",
                                permitted=permitted_names,
                            )
                        if sec_host != find_host or sec_port != find_port:
                            raise InvalidLifecycleTransitionError(
                                from_state=current_state.value,
                                to_state=target_state.value,
                                reason=f"Confirmation rejected: Evidence target host authority '{sec_host}:{sec_port}' does not match finding target identity '{find_host}:{find_port}'.",
                                permitted=permitted_names,
                            )

                    # 4. Endpoint Path Normalization & Validation (SEC-E4-002-C)
                    if sec_ev.target_url and finding.affected_endpoint:
                        ev_endpoint = cls._normalize_endpoint_path(sec_ev.target_url)
                        find_endpoint = cls._normalize_endpoint_path(finding.affected_endpoint)
                        if ev_endpoint != find_endpoint:
                            raise InvalidLifecycleTransitionError(
                                from_state=current_state.value,
                                to_state=target_state.value,
                                reason=f"Confirmation rejected: Evidence endpoint '{ev_endpoint}' does not match finding affected endpoint '{find_endpoint}'.",
                                permitted=permitted_names,
                            )

                    # 5. HTTP Method Validation
                    if sec_ev.http_method and finding.http_method:
                        if sec_ev.http_method.upper() != finding.http_method.upper():
                            raise InvalidLifecycleTransitionError(
                                from_state=current_state.value,
                                to_state=target_state.value,
                                reason=f"Confirmation rejected: Evidence HTTP method '{sec_ev.http_method.upper()}' does not match finding HTTP method '{finding.http_method.upper()}'.",
                                permitted=permitted_names,
                            )

                    # 6. Risk Identifier Validation
                    sec_exec = db.query(SecurityTestExecution).filter(SecurityTestExecution.id == sec_exec_id).first() if sec_exec_id else None
                    if sec_exec and sec_exec.risk_id and finding.risk_id:
                        if sec_exec.risk_id.upper() != finding.risk_id.upper():
                            raise InvalidLifecycleTransitionError(
                                from_state=current_state.value,
                                to_state=target_state.value,
                                reason=f"Confirmation rejected: Evidence execution risk '{sec_exec.risk_id.upper()}' does not match finding risk '{finding.risk_id.upper()}'.",
                                permitted=permitted_names,
                            )

                    # 7. Safe Assessment Context Validation (SEC-E4-002-B)
                    if sec_exec and sec_exec.plan:
                        plan = sec_exec.plan
                        plan_app_id, plan_env, plan_ver = cls._extract_plan_context(plan)

                        # Validate application_id
                        if finding.application_id and finding.application_id.strip():
                            if not plan_app_id:
                                raise InvalidLifecycleTransitionError(
                                    from_state=current_state.value,
                                    to_state=target_state.value,
                                    reason=f"Confirmation rejected: Evidence execution plan is missing or has invalid application context metadata ('application_id'). Required: '{finding.application_id}'.",
                                    permitted=permitted_names,
                                )
                            if plan_app_id != finding.application_id:
                                raise InvalidLifecycleTransitionError(
                                    from_state=current_state.value,
                                    to_state=target_state.value,
                                    reason=f"Confirmation rejected: Evidence application ID '{plan_app_id}' does not match finding application ID '{finding.application_id}'.",
                                    permitted=permitted_names,
                                )

                        # Validate environment
                        if finding.environment and finding.environment.strip():
                            if not plan_env:
                                raise InvalidLifecycleTransitionError(
                                    from_state=current_state.value,
                                    to_state=target_state.value,
                                    reason=f"Confirmation rejected: Evidence execution plan is missing or has invalid environment context metadata ('environment'). Required: '{finding.environment}'.",
                                    permitted=permitted_names,
                                )
                            if plan_env.lower() != finding.environment.lower():
                                raise InvalidLifecycleTransitionError(
                                    from_state=current_state.value,
                                    to_state=target_state.value,
                                    reason=f"Confirmation rejected: Evidence execution plan environment '{plan_env}' does not match finding environment '{finding.environment}'.",
                                    permitted=permitted_names,
                                )

                        # Validate app_version if specified
                        if getattr(finding, "app_version", None) and finding.app_version.strip() and plan_ver:
                            if plan_ver != finding.app_version:
                                raise InvalidLifecycleTransitionError(
                                    from_state=current_state.value,
                                    to_state=target_state.value,
                                    reason=f"Confirmation rejected: Evidence execution plan version '{plan_ver}' does not match finding version '{finding.app_version}'.",
                                    permitted=permitted_names,
                                )

        # 3. Guard: REMEDIATION_VERIFIED requires retest verification evidence
        if target_state == FindingLifecycleStatusEnum.REMEDIATION_VERIFIED:
            if not evidence_reference or not evidence_reference.strip():
                raise InvalidLifecycleTransitionError(
                    from_state=current_state.value,
                    to_state=target_state.value,
                    reason="Remediation verification requires a verified post-mitigation retest evidence reference.",
                    permitted=permitted_names,
                )
            if db is not None:
                retest_ev = EvidenceRegistry.get_evidence_by_id_or_hash(db, evidence_reference.strip())
                if not retest_ev:
                    raise InvalidLifecycleTransitionError(
                        from_state=current_state.value,
                        to_state=target_state.value,
                        reason=f"Remediation verification rejected: Retest evidence '{evidence_reference}' does not exist in repository.",
                        permitted=permitted_names,
                    )
                t_level, is_valid, msg = EvidenceRegistry.verify_evidence_authenticity(retest_ev)
                if not is_valid or t_level == EvidenceTrustLevel.INVALID:
                    raise InvalidLifecycleTransitionError(
                        from_state=current_state.value,
                        to_state=target_state.value,
                        reason=f"Remediation verification rejected: Retest evidence verification failed: {msg}.",
                        permitted=permitted_names,
                    )
                if finding is not None and retest_ev.target_url and finding.target_identity:
                    sec_scheme, sec_host, sec_port = cls._parse_and_normalize_target_authority(
                        retest_ev.target_url,
                        label="retest evidence target URL",
                        from_state=current_state.value,
                        to_state=target_state.value,
                    )
                    find_scheme, find_host, find_port = cls._parse_and_normalize_target_authority(
                        finding.target_identity,
                        label="finding target identity",
                        from_state=current_state.value,
                        to_state=target_state.value,
                    )
                    if sec_scheme != find_scheme or sec_host != find_host or sec_port != find_port:
                        raise InvalidLifecycleTransitionError(
                            from_state=current_state.value,
                            to_state=target_state.value,
                            reason=f"Remediation verification rejected: Retest evidence target '{sec_scheme}://{sec_host}:{sec_port}' does not match finding target identity '{find_scheme}://{find_host}:{find_port}'.",
                            permitted=permitted_names,
                        )

        # 4. Guard: CLOSED requires explicit justification
        if target_state == FindingLifecycleStatusEnum.CLOSED:
            if not reason or len(reason.strip()) < 3:
                raise InvalidLifecycleTransitionError(
                    from_state=current_state.value,
                    to_state=target_state.value,
                    reason="Closure requires an explicit administrative justification or auditor sign-off explanation.",
                    permitted=permitted_names,
                )

    @classmethod
    def create_finding(
        cls,
        db: Session,
        data: SecurityFindingCreate,
        actor: str = "AutonomousSecurityAgent",
    ) -> SecurityFinding:
        """Creates a new security finding with initial status and records initial history event."""
        # Enforce secondary confirmation guard if initial status is CONFIRMED
        if data.initial_status == FindingLifecycleStatusEnum.CONFIRMED:
            if not data.evidence_references:
                raise InvalidLifecycleTransitionError(
                    from_state="NONE",
                    to_state=data.initial_status.value,
                    reason="Initial CONFIRMED status requires verified cryptographic evidence references.",
                )
            # Verify evidence exists and is HMAC authenticated
            primary_ref = data.evidence_references[0]
            sec_ev = EvidenceRegistry.get_evidence_by_id_or_hash(db, primary_ref)
            if not sec_ev:
                raise InvalidLifecycleTransitionError(
                    from_state="NONE",
                    to_state=data.initial_status.value,
                    reason=f"Initial CONFIRMED status rejected: Referenced evidence '{primary_ref}' does not exist in repository.",
                )
            trust_level, is_valid, msg = EvidenceRegistry.verify_evidence_authenticity(sec_ev)
            if trust_level != EvidenceTrustLevel.HMAC_VERIFIED or not is_valid:
                raise InvalidLifecycleTransitionError(
                    from_state="NONE",
                    to_state=data.initial_status.value,
                    reason=f"Initial CONFIRMED status rejected: Evidence trust level '{trust_level.value}' is not HMAC_VERIFIED ({msg}).",
                )

        finding_id = f"FIND-{data.risk_id.upper()}-{uuid.uuid4().hex[:8]}"

        finding = SecurityFinding(
            id=str(uuid.uuid4()),
            finding_id=finding_id,
            execution_id=data.execution_id,
            session_id=data.session_id,
            scenario_id=data.scenario_id,
            risk_id=data.risk_id.upper(),
            title=data.title,
            description=data.description,
            category=data.category,
            affected_endpoint=data.affected_endpoint,
            http_method=data.http_method.upper(),
            target_identity=data.target_identity,
            application_id=data.application_id,
            app_version=data.app_version,
            environment=data.environment,
            lifecycle_status=data.initial_status.value,
            severity=data.severity.value,
            confidence=data.confidence,
            cvss_score=data.cvss_score,
            cvss_vector=data.cvss_vector,
            root_cause_category=data.root_cause_category,
            failed_security_control=data.failed_security_control,
            trust_boundary_crossed=data.trust_boundary_crossed,
            evidence_references=json.dumps(data.evidence_references) if data.evidence_references else "[]",
            remediation_title=data.remediation_title,
            remediation_snippet=data.remediation_snippet,
            verification_procedure=data.verification_procedure,
            version_id=1,
            first_detected_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc),
        )

        db.add(finding)
        db.flush()

        # Record initial history event
        history = SecurityFindingHistory(
            id=str(uuid.uuid4()),
            history_id=f"HIST-{uuid.uuid4().hex[:8]}",
            finding_id=finding.finding_id,
            previous_state="INITIAL",
            new_state=data.initial_status.value,
            transition_reason=data.initial_reason or "Initial finding registration",
            actor=actor or data.actor,
            event_timestamp=datetime.now(timezone.utc),
            evidence_reference=data.evidence_references[0] if data.evidence_references else None,
        )
        db.add(history)
        db.commit()
        db.refresh(finding)
        return finding

    @classmethod
    def transition_state(
        cls,
        db: Session,
        finding_id: str,
        request: TransitionFindingStateRequest,
    ) -> SecurityFinding:
        """Transitions a finding's lifecycle state with strict guard checks, atomic optimistic locking, and immutable history logging."""
        finding = db.query(SecurityFinding).filter(SecurityFinding.finding_id == finding_id).first()
        if not finding:
            raise ValueError(f"Security finding '{finding_id}' not found.")

        # SEC-E4-003: Optimistic concurrency control check
        if request.expected_version is not None and finding.version_id != request.expected_version:
            raise ConcurrencyConflictError(
                finding_id=finding_id,
                current_version=finding.version_id,
                expected_version=request.expected_version,
                message=f"Optimistic lock conflict: Finding '{finding_id}' is at version {finding.version_id}, but request expected version {request.expected_version}.",
            )

        current_enum = FindingLifecycleStatusEnum(finding.lifecycle_status)
        target_enum = request.target_state
        previous_state = finding.lifecycle_status
        expected_ver = request.expected_version if request.expected_version is not None else finding.version_id

        # Validate transition guards, HMAC evidence authenticity (SEC-E4-001), and metadata correlation (SEC-E4-002)
        cls.validate_transition(
            current_state=current_enum,
            target_state=target_enum,
            evidence_reference=request.evidence_reference,
            secondary_execution_id=request.secondary_execution_id,
            actor=request.actor,
            reason=request.transition_reason,
            is_secondary_confirmed=request.is_secondary_confirmed,
            db=db,
            finding=finding,
        )

        # Prepare atomic update payload
        update_values: Dict[Any, Any] = {
            SecurityFinding.lifecycle_status: target_enum.value,
            SecurityFinding.version_id: SecurityFinding.version_id + 1,
            SecurityFinding.last_observed_at: datetime.now(timezone.utc),
            SecurityFinding.updated_at: datetime.now(timezone.utc),
        }
        if request.secondary_execution_id:
            update_values[SecurityFinding.secondary_execution_id] = request.secondary_execution_id

        # Append new evidence reference if provided
        if request.evidence_reference:
            current_refs = []
            if finding.evidence_references:
                try:
                    current_refs = json.loads(finding.evidence_references)
                except Exception:
                    current_refs = []
            if request.evidence_reference not in current_refs:
                current_refs.append(request.evidence_reference)
                update_values[SecurityFinding.evidence_references] = json.dumps(current_refs)

        # SEC-E4-003: Atomic conditional update verifying version_id and state
        rows = db.query(SecurityFinding).filter(
            SecurityFinding.finding_id == finding_id,
            SecurityFinding.lifecycle_status == previous_state,
            SecurityFinding.version_id == expected_ver,
        ).update(update_values, synchronize_session=False)

        if rows == 0:
            db.rollback()
            curr = db.query(SecurityFinding).filter(SecurityFinding.finding_id == finding_id).first()
            actual_ver = curr.version_id if curr else expected_ver
            raise ConcurrencyConflictError(
                finding_id=finding_id,
                current_version=actual_ver,
                expected_version=expected_ver,
                message=f"Concurrent modification collision: Finding '{finding_id}' was updated concurrently by another transaction.",
            )

        # Log immutable history record within the exact same database transaction
        history = SecurityFindingHistory(
            id=str(uuid.uuid4()),
            history_id=f"HIST-{uuid.uuid4().hex[:8]}",
            finding_id=finding.finding_id,
            previous_state=previous_state,
            new_state=target_enum.value,
            transition_reason=request.transition_reason,
            actor=request.actor,
            event_timestamp=datetime.now(timezone.utc),
            evidence_reference=request.evidence_reference,
            metadata_snapshot=json.dumps(request.metadata_snapshot) if request.metadata_snapshot else None,
        )
        db.add(history)
        db.commit()

        db.expire_all()
        return db.query(SecurityFinding).filter(SecurityFinding.finding_id == finding_id).first()

    @classmethod
    def update_finding_details(
        cls,
        db: Session,
        finding_id: str,
        update_data: SecurityFindingUpdate,
    ) -> SecurityFinding:
        """Updates finding metadata (severity, remediation snippet, etc.) without altering state."""
        finding = db.query(SecurityFinding).filter(SecurityFinding.finding_id == finding_id).first()
        if not finding:
            raise ValueError(f"Security finding '{finding_id}' not found.")

        for k, v in update_data.model_dump(exclude_unset=True).items():
            if hasattr(finding, k):
                if k == "severity" and v:
                    setattr(finding, k, v.value if hasattr(v, "value") else v)
                else:
                    setattr(finding, k, v)

        finding.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(finding)
        return finding

    @classmethod
    def record_decision(
        cls,
        db: Session,
        data: SecurityDecisionCreate,
    ) -> SecurityDecision:
        """Records an explainable automated decision associated with a finding or session."""
        decision = SecurityDecision(
            id=str(uuid.uuid4()),
            decision_id=f"DEC-{uuid.uuid4().hex[:8]}",
            finding_id=data.finding_id,
            session_id=data.session_id,
            decision_type=data.decision_type,
            decision_reason=data.decision_reason,
            confidence=data.confidence,
            selected_action=data.selected_action,
            evidence_references=json.dumps(data.evidence_references) if data.evidence_references else "[]",
            input_context=json.dumps(data.input_context) if data.input_context else None,
            alternatives_considered=json.dumps(data.alternatives_considered) if data.alternatives_considered else "[]",
            rejection_reasons=json.dumps(data.rejection_reasons) if data.rejection_reasons else "{}",
            decision_timestamp=datetime.now(timezone.utc),
        )
        db.add(decision)
        db.commit()
        db.refresh(decision)
        return decision

    @classmethod
    def reopen_finding_on_regression(
        cls,
        db: Session,
        finding_id: str,
        regression_evidence_ref: str,
        actor: str = "RegressionTestEngine",
    ) -> SecurityFinding:
        """Transitions a REMEDIATION_VERIFIED or CLOSED finding back to DETECTED upon regression recurrence."""
        req = TransitionFindingStateRequest(
            target_state=FindingLifecycleStatusEnum.DETECTED,
            transition_reason="Regression detected: vulnerability re-observed on identical target during subsequent execution.",
            actor=actor,
            evidence_reference=regression_evidence_ref,
            is_secondary_confirmed=False,
        )
        return cls.transition_state(db=db, finding_id=finding_id, request=req)

    @classmethod
    def get_finding(
        cls,
        db: Session,
        finding_id: str,
    ) -> Optional[SecurityFinding]:
        """Retrieves a single security finding by its finding_id."""
        return db.query(SecurityFinding).filter(SecurityFinding.finding_id == finding_id).first()

    @classmethod
    def list_findings(
        cls,
        db: Session,
        lifecycle_status: Optional[str] = None,
        risk_id: Optional[str] = None,
        severity: Optional[str] = None,
        target_identity: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> FindingListResponse:
        """Retrieves paginated findings matching specified lifecycle, risk, or severity filters."""
        query = db.query(SecurityFinding)

        if lifecycle_status:
            query = query.filter(SecurityFinding.lifecycle_status == lifecycle_status.upper())
        if risk_id:
            query = query.filter(SecurityFinding.risk_id == risk_id.upper())
        if severity:
            query = query.filter(SecurityFinding.severity == severity.upper())
        if target_identity:
            query = query.filter(SecurityFinding.target_identity.like(f"%{target_identity}%"))

        total_count = query.count()
        offset = max(0, (page - 1) * page_size)
        items = query.order_by(SecurityFinding.created_at.desc()).offset(offset).limit(page_size).all()

        finding_responses = [cls._to_finding_response(item) for item in items]

        return FindingListResponse(
            findings=finding_responses,
            total_count=total_count,
            page=page,
            page_size=page_size,
        )

    @classmethod
    def get_lifecycle_board(
        cls,
        db: Session,
        target_identity: str = "http://127.0.0.1:8000",
        application_id: str = "default",
        environment: str = "sandbox",
    ) -> LifecycleBoardResponse:
        """Aggregates all findings into an 11-column lifecycle Kanban board."""
        findings = db.query(SecurityFinding).all()

        columns: Dict[str, LifecycleBoardColumn] = {}
        for state in FindingLifecycleStatusEnum:
            columns[state.value] = LifecycleBoardColumn(state=state, count=0, findings=[])

        total = 0
        active = 0
        remediated = 0
        refuted = 0

        for f in findings:
            total += 1
            st = f.lifecycle_status
            if st in columns:
                resp = cls._to_finding_response(f)
                columns[st].findings.append(resp)
                columns[st].count += 1

            if st in ["DETECTED", "TRIAGE", "POTENTIAL", "CONFIRMED", "REMEDIATION_PLANNED", "REMEDIATION_IN_PROGRESS", "READY_FOR_RETEST"]:
                active += 1
            elif st == "REMEDIATION_VERIFIED":
                remediated += 1
            elif st == "REFUTED":
                refuted += 1

        return LifecycleBoardResponse(
            target_identity=target_identity,
            application_id=application_id,
            environment=environment,
            columns=columns,
            total_findings=total,
            active_findings=active,
            remediated_findings=remediated,
            refuted_findings=refuted,
        )

    @classmethod
    def _to_finding_response(cls, item: SecurityFinding) -> SecurityFindingResponse:
        """Transforms a SecurityFinding model to a SecurityFindingResponse schema."""
        ev_refs = []
        if item.evidence_references:
            try:
                ev_refs = json.loads(item.evidence_references)
            except Exception:
                ev_refs = []

        history_resp = [
            SecurityFindingHistoryResponse(
                id=h.id,
                history_id=h.history_id,
                finding_id=h.finding_id,
                previous_state=h.previous_state,
                new_state=h.new_state,
                transition_reason=h.transition_reason,
                actor=h.actor,
                event_timestamp=h.event_timestamp,
                evidence_reference=h.evidence_reference,
                metadata_snapshot=h.metadata_snapshot,
            )
            for h in item.history
        ]

        decision_resp = [
            SecurityDecisionResponse(
                id=d.id,
                decision_id=d.decision_id,
                finding_id=d.finding_id,
                session_id=d.session_id,
                decision_type=d.decision_type,
                decision_reason=d.decision_reason,
                confidence=d.confidence,
                selected_action=d.selected_action,
                evidence_references=json.loads(d.evidence_references) if d.evidence_references else [],
                input_context=json.loads(d.input_context) if d.input_context else None,
                alternatives_considered=json.loads(d.alternatives_considered) if d.alternatives_considered else [],
                rejection_reasons=json.loads(d.rejection_reasons) if d.rejection_reasons else {},
                decision_timestamp=d.decision_timestamp,
            )
            for d in item.decisions
        ]

        return SecurityFindingResponse(
            id=item.id,
            finding_id=item.finding_id,
            scenario_id=item.scenario_id,
            risk_id=item.risk_id,
            title=item.title,
            description=item.description,
            category=item.category,
            affected_endpoint=item.affected_endpoint,
            http_method=item.http_method,
            target_identity=item.target_identity,
            application_id=item.application_id,
            app_version=item.app_version,
            environment=item.environment,
            lifecycle_status=FindingLifecycleStatusEnum(item.lifecycle_status),
            severity=FindingSeverityEnum(item.severity),
            confidence=item.confidence,
            cvss_score=item.cvss_score,
            cvss_vector=item.cvss_vector,
            root_cause_category=item.root_cause_category,
            failed_security_control=item.failed_security_control,
            trust_boundary_crossed=item.trust_boundary_crossed,
            remediation_title=item.remediation_title,
            remediation_snippet=item.remediation_snippet,
            verification_procedure=item.verification_procedure,
            session_id=item.session_id,
            execution_id=item.execution_id,
            secondary_execution_id=getattr(item, "secondary_execution_id", None),
            version_id=getattr(item, "version_id", 1),
            evidence_references=ev_refs,
            first_detected_at=item.first_detected_at,
            last_observed_at=item.last_observed_at,
            created_at=item.created_at,
            updated_at=item.updated_at,
            history=history_resp,
            decisions=decision_resp,
        )
