"""ApexShield Phase E7: Explainable Security Decision Engine.

Provides transparent, auditable decision traces for all autonomous actions:
1. RISK_SELECTION: Choice of target OWASP category and risk ID.
2. TEST_PLANNING: Choice of endpoints, sequence, and candidate cut paths.
3. PAYLOAD_MUTATION: Choice of mutation technique following defensive refusals.
4. CHAIN_TERMINATION: Reason for chain conclusion or pruning.
5. VERDICT_CLASSIFICATION: Mapping of observed probe results to 11-state lifecycle.
6. SEVERITY_SCORING: Calculation of CVSS v3.1 vector and environmental score.
7. REMEDIATION_DIRECTIVE: Prioritization and mitigation guidance assignment.

Guarantees:
- Pre-storage credential and PII redaction across recursive structures and free text.
- Explicit, deterministic confidence calculation (0.0 to 1.0) with zero default-1.0 bias.
- Preservation of uncertainty, alternative actions considered, and rejection reasons.
- Safe persistence with ON DELETE SET NULL surviving session and finding deletion.
- Integration with historical E4 records without data loss.
"""

from datetime import datetime, timezone
from enum import Enum
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from sqlalchemy import desc
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# =============================================================================
# 1. STANDARDIZED DECISION TYPES
# =============================================================================

class DecisionType(str, Enum):
    """The seven standardized decision classes defined by the Phase E0 roadmap."""
    RISK_SELECTION = "RISK_SELECTION"
    TEST_PLANNING = "TEST_PLANNING"
    PAYLOAD_MUTATION = "PAYLOAD_MUTATION"
    CHAIN_TERMINATION = "CHAIN_TERMINATION"
    VERDICT_CLASSIFICATION = "VERDICT_CLASSIFICATION"
    SEVERITY_SCORING = "SEVERITY_SCORING"
    REMEDIATION_DIRECTIVE = "REMEDIATION_DIRECTIVE"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        return value in cls._value2member_map_


# =============================================================================
# 2. CREDENTIAL & PII REDACTION ENGINE
# =============================================================================

class DecisionRedactor:
    """Pre-storage credential sanitizer preventing secrets from entering audit logs.
    
    Operates recursively over dicts, lists, and free-text strings.
    Never overwrites original raw HTTP evidence files.
    """

    PATTERNS: List[Tuple[re.Pattern, str]] = [
        # Private Keys (RSA, EC, Generic)
        (
            re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----'),
            "[REDACTED_PRIVATE_KEY]",
        ),
        # Basic Auth in URLs (http://user:pass@host)
        (
            re.compile(r'(?i)(https?://)[^:\s]+:[^@\s]+@'),
            r'\1[REDACTED_BASIC_AUTH]@',
        ),
        # Basic Auth Header
        (
            re.compile(r'(?i)basic\s+[A-Za-z0-9+/=]{8,}'),
            "Basic [REDACTED_BASIC_AUTH]",
        ),
        # JWT Bearer tokens
        (
            re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+(?:\.[A-Za-z0-9\-_=]*)?'),
            "Bearer [REDACTED_BEARER_TOKEN]",
        ),
        # Specific live API keys
        (
            re.compile(r'ak_live_[a-zA-Z0-9_\-]{8,}'),
            "[REDACTED_API_KEY]",
        ),
        # API Keys & Secret Tokens assignments
        (
            re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{8,}["\']?'),
            r'\1=[REDACTED_API_KEY]',
        ),
        # Passwords in JSON / query / text
        (
            re.compile(r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?[^"\'\s,;}]+["\']?'),
            r'\1=[REDACTED_PASSWORD]',
        ),
        # Authorization header fields in JSON
        (
            re.compile(r'(?i)"authorization"\s*:\s*"[^"]*"'),
            '"authorization": "[REDACTED_AUTH_HEADER]"',
        ),
    ]

    SENSITIVE_KEY_NAMES = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "auth_token",
        "private_key",
        "client_secret",
        "authorization",
    }

    @classmethod
    def redact_text(cls, text: str) -> str:
        """Applies regex sanitization patterns to a free-text string."""
        if not text or not isinstance(text, str):
            return text
        sanitized = text
        for pattern, replacement in cls.PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    @classmethod
    def redact(cls, data: Any) -> Any:
        """Recursively traverses nested dictionaries, lists, and strings to redact secrets."""
        if data is None:
            return None
        if isinstance(data, str):
            return cls.redact_text(data)
        elif isinstance(data, dict):
            redacted_dict = {}
            for k, v in data.items():
                k_str = str(k).lower().strip().replace("-", "_")
                if any(secret_kw in k_str for secret_kw in cls.SENSITIVE_KEY_NAMES):
                    redacted_dict[k] = "[REDACTED]"
                else:
                    redacted_dict[k] = cls.redact(v)
            return redacted_dict
        elif isinstance(data, list):
            return [cls.redact(elem) for elem in data]
        elif isinstance(data, tuple):
            return tuple(cls.redact(elem) for elem in data)
        return data

    @classmethod
    def redact_structure(cls, data: Any) -> Any:
        """Alias for redact() for structural compatibility."""
        return cls.redact(data)

    @classmethod
    def sanitize_decision_data(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convenience method to sanitize an entire decision dictionary."""
        return cls.redact(data)


# =============================================================================
# 3. DETERMINISTIC CONFIDENCE CALCULATOR
# =============================================================================

class ConfidenceCalculator:
    """Calculates explicit, evidence-backed confidence scores (0.0 to 1.0).
    
    Rejects uncalculated default confidence of 1.0.
    Preserves uncertainty: missing evidence or inconclusive outcomes cap confidence.
    """

    BASE_CONFIDENCE: Dict[str, float] = {
        DecisionType.RISK_SELECTION.value: 0.70,
        DecisionType.TEST_PLANNING.value: 0.75,
        DecisionType.PAYLOAD_MUTATION.value: 0.65,
        DecisionType.CHAIN_TERMINATION.value: 0.80,
        DecisionType.VERDICT_CLASSIFICATION.value: 0.85,
        DecisionType.SEVERITY_SCORING.value: 0.80,
        DecisionType.REMEDIATION_DIRECTIVE.value: 0.75,
    }

    @classmethod
    def calculate_confidence(
        cls,
        decision_type: Union[DecisionType, str],
        evidence_count: int = 1,
        outcome_conclusive: bool = True,
        alternatives_count: int = 0,
        custom_evidence_weights: Optional[Dict[str, float]] = None,
        context: Optional[Dict[str, Any]] = None,
        evidence_references: Optional[List[str]] = None,
        explicit_confidence: Optional[float] = None,
    ) -> float:
        """Computes deterministic confidence score bounded in [0.05, 0.98]."""
        if isinstance(decision_type, DecisionType):
            dtype_key = decision_type.value
        else:
            dtype_key = str(decision_type)

        ctx = context or {}
        if evidence_references is not None and evidence_count == 1:
            evidence_count = len(evidence_references)

        # Handle explicit caller-provided confidence
        if explicit_confidence is not None:
            # Reject default 1.0 bias
            if abs(explicit_confidence - 1.0) < 1e-6:
                return 0.98
            return round(max(0.05, min(0.98, explicit_confidence)), 2)

        base = cls.BASE_CONFIDENCE.get(dtype_key, 0.70)
        score = base

        # Additive bonuses
        evidence_bonus = min(0.15, max(0, evidence_count - 1) * 0.05) if evidence_count > 0 else 0.0
        alts_bonus = min(0.05, max(0, alternatives_count) * 0.02)
        score += evidence_bonus + alts_bonus

        # Preservation of uncertainty caps
        if evidence_count == 0:
            score = min(score, 0.65)
        if not outcome_conclusive:
            score = min(score, 0.40)

        return round(max(0.05, min(0.98, score)), 2)

    @classmethod
    def calculate(
        cls,
        decision_type: Union[DecisionType, str],
        context: Optional[Dict[str, Any]] = None,
        evidence_references: Optional[List[str]] = None,
        explicit_confidence: Optional[float] = None,
    ) -> float:
        """Adapter for context-based confidence evaluation."""
        ctx = context or {}
        ev_refs = evidence_references or []
        outcome_conclusive = ctx.get("outcome_conclusive", True)
        alts_count = ctx.get("alternatives_count", 0)

        return cls.calculate_confidence(
            decision_type=decision_type,
            evidence_count=len(ev_refs),
            outcome_conclusive=outcome_conclusive,
            alternatives_count=alts_count,
            context=ctx,
            evidence_references=ev_refs,
            explicit_confidence=explicit_confidence,
        )

    def __call__(self, *args, **kwargs) -> float:
        return self.calculate_confidence(*args, **kwargs)


# =============================================================================
# 4. DECISION WRAPPER OBJECT (SUPPORTS ATTRIBUTE & DICT ACCESS)
# =============================================================================

class FormattedDecision(dict):
    """Dictionary subclass that provides attribute-style access for backwards compatibility."""
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'FormattedDecision' object has no attribute '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


class DecisionQueryResult(dict):
    """Dictionary subclass that supports both dict indexing and tuple unpacking (decisions, total)."""
    def __iter__(self):
        yield self["decisions"]
        yield self["total"]


class HybridMethod:
    """Descriptor enabling a method to be called either on an instance (using self.db)
    or on the class directly (passing db as an argument)."""
    def __init__(self, func):
        self.func = func

    def __get__(self, instance, owner):
        def wrapper(*args, **kwargs):
            if instance is not None:
                return self.func(instance, *args, **kwargs)
            return self.func(owner, *args, **kwargs)
        return wrapper


# =============================================================================
# 5. EXPLAINABLE DECISION ENGINE CORE
# =============================================================================

class DecisionExplainabilityEngine:
    """Orchestrates creation, querying, and auditing of explainable security decisions."""

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    @HybridMethod
    def record_decision(
        target,
        db: Optional[Session] = None,
        decision_type: Union[DecisionType, str] = DecisionType.TEST_PLANNING.value,
        selected_action: str = "",
        reasoning_summary: str = "",
        input_context: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        finding_id: Optional[Union[str, int]] = None,
        execution_id: Optional[str] = None,
        evidence_references: Optional[List[str]] = None,
        alternatives_considered: Optional[List[str]] = None,
        rejection_reasons: Optional[Dict[str, str]] = None,
        rejected_alternatives: Optional[List[Dict[str, str]]] = None,
        safety_constraints: Optional[Union[Dict[str, Any], str, List[Any]]] = None,
        explicit_confidence: Optional[float] = None,
        confidence: Optional[float] = None,
        outcome_conclusive: bool = True,
        provenance: str = "ExplainabilityEngine_v1",
        is_external: bool = False,
        **extra_kwargs,
    ) -> FormattedDecision:
        """Records an auditable, redacted security decision in the database."""
        from app.security_agent.models import SecurityDecision

        if isinstance(target, DecisionExplainabilityEngine):
            actual_db = target.db or db or extra_kwargs.get("db")
            cls = target.__class__
        else:
            cls = target
            actual_db = db or extra_kwargs.get("db")

        if actual_db is None:
            raise ValueError("Database session 'db' is required to record a decision.")

        # Harmonize rejected_alternatives and alternatives_considered
        alts_list = list(alternatives_considered or [])
        rejections_dict = dict(rejection_reasons or {})

        if rejected_alternatives:
            for alt in rejected_alternatives:
                if isinstance(alt, dict):
                    act = alt.get("action", "")
                    rsn = alt.get("reason", "")
                    if act and act not in alts_list:
                        alts_list.append(act)
                    if act and rsn:
                        rejections_dict[act] = rsn
                elif isinstance(alt, str) and alt not in alts_list:
                    alts_list.append(alt)

        # Harmonize safety_constraints
        constraints_obj = safety_constraints
        if isinstance(safety_constraints, str):
            constraints_obj = {"constraint": safety_constraints}
        elif safety_constraints is None:
            constraints_obj = {}

        # Validate decision type
        dtype_str = decision_type.value if isinstance(decision_type, DecisionType) else str(decision_type)
        if not DecisionType.is_valid(dtype_str):
            logger.warning(f"Non-standard decision_type '{dtype_str}' recorded. Standard types: {[d.value for d in DecisionType]}")

        # Apply recursive pre-storage redaction
        redacted_context = DecisionRedactor.redact(input_context)
        redacted_reasoning = DecisionRedactor.redact_text(reasoning_summary)
        redacted_action = DecisionRedactor.redact_text(selected_action)
        redacted_alternatives = DecisionRedactor.redact(alts_list)
        redacted_rejections = DecisionRedactor.redact(rejections_dict)
        redacted_constraints = DecisionRedactor.redact(constraints_obj)

        # SEC-E7-001 Remediation: Distinguish external ingestion vs internal agent execution
        is_ext = is_external or extra_kwargs.get("is_external", False) or (isinstance(provenance, str) and provenance.startswith("external_api:"))

        if is_ext:
            # For external submissions, verify evidence references against database records
            verified_evidence_count = 0
            if evidence_references and actual_db is not None:
                try:
                    from app.security_agent.models import HttpEvidenceRecord
                    verified_evidence_count = (
                        actual_db.query(HttpEvidenceRecord)
                        .filter(
                            (HttpEvidenceRecord.id.in_(evidence_references))
                            | (HttpEvidenceRecord.execution_id.in_(evidence_references))
                        )
                        .count()
                    )
                except Exception:
                    verified_evidence_count = 0

            # Compute legitimate confidence from verified evidence only (never trust client explicit confidence)
            calculated_conf = ConfidenceCalculator.calculate_confidence(
                decision_type=dtype_str,
                evidence_count=verified_evidence_count,
                outcome_conclusive=outcome_conclusive,
                alternatives_count=len(alts_list),
                context=redacted_context,
                evidence_references=evidence_references if verified_evidence_count > 0 else [],
                explicit_confidence=None,
            )

            # Cap unverified external confidence strictly at 0.50
            if verified_evidence_count == 0:
                calculated_conf = min(0.50, calculated_conf)

            if not outcome_conclusive:
                calculated_conf = min(0.40, calculated_conf)

            # If external caller claimed lower confidence, respect their lower self-assessment
            conf_input = explicit_confidence if explicit_confidence is not None else confidence
            if conf_input is not None and conf_input < calculated_conf:
                calculated_conf = round(max(0.05, conf_input), 2)
        else:
            # Trusted internal Python caller
            conf_input = explicit_confidence if explicit_confidence is not None else confidence
            calculated_conf = ConfidenceCalculator.calculate_confidence(
                decision_type=dtype_str,
                evidence_count=len(evidence_references or []),
                outcome_conclusive=outcome_conclusive,
                alternatives_count=len(alts_list),
                context=redacted_context,
                evidence_references=evidence_references,
                explicit_confidence=conf_input,
            )

        decision_id = f"DEC-{uuid.uuid4().hex[:12]}"

        decision_record = SecurityDecision(
            id=str(uuid.uuid4()),
            decision_id=decision_id,
            finding_id=finding_id,
            session_id=session_id,
            decision_type=dtype_str,
            decision_reason=redacted_reasoning,
            confidence=calculated_conf,
            selected_action=redacted_action,
            evidence_references=json.dumps(evidence_references or []),
            input_context=json.dumps(redacted_context) if redacted_context else None,
            alternatives_considered=json.dumps(redacted_alternatives),
            rejection_reasons=json.dumps(redacted_rejections),
            decision_timestamp=datetime.now(timezone.utc),
        )

        if hasattr(decision_record, "execution_id"):
            setattr(decision_record, "execution_id", execution_id)
        if hasattr(decision_record, "safety_constraints"):
            setattr(decision_record, "safety_constraints", json.dumps(redacted_constraints) if redacted_constraints else None)
        if hasattr(decision_record, "provenance"):
            setattr(decision_record, "provenance", provenance)

        actual_db.add(decision_record)
        actual_db.commit()
        actual_db.refresh(decision_record)
        logger.info(f"Recorded explainable decision {decision_id} [{dtype_str}] (confidence: {calculated_conf})")

        return cls._format_decision_dict(decision_record)

    @HybridMethod
    def get_decision_by_id(
        target,
        db: Optional[Session] = None,
        decision_id: str = "",
        **extra_kwargs,
    ) -> Optional[FormattedDecision]:
        """Retrieves and deserializes a single decision trace by unique decision_id."""
        from app.security_agent.models import SecurityDecision

        if isinstance(target, DecisionExplainabilityEngine):
            actual_db = target.db or db or extra_kwargs.get("db")
            cls = target.__class__
            target_id = decision_id or extra_kwargs.get("decision_id", "")
        else:
            cls = target
            actual_db = db or extra_kwargs.get("db")
            target_id = decision_id or extra_kwargs.get("decision_id", "")

        if actual_db is None:
            raise ValueError("Database session 'db' is required to get a decision.")

        record = (
            actual_db.query(SecurityDecision)
            .filter(
                (SecurityDecision.decision_id == target_id) | (SecurityDecision.id == target_id)
            )
            .first()
        )
        if not record:
            return None
        return cls._format_decision_dict(record)

    @HybridMethod
    def query_decisions(
        target,
        db: Optional[Session] = None,
        session_id: Optional[str] = None,
        decision_type: Optional[str] = None,
        finding_id: Optional[str] = None,
        min_confidence: Optional[float] = None,
        limit: int = 50,
        offset: int = 0,
        **extra_kwargs,
    ) -> DecisionQueryResult:
        """Queries decision traces with flexible filtering, pagination, and total count."""
        from app.security_agent.models import SecurityDecision

        if isinstance(target, DecisionExplainabilityEngine):
            actual_db = target.db or db or extra_kwargs.get("db")
            cls = target.__class__
        else:
            cls = target
            actual_db = db or extra_kwargs.get("db")

        if actual_db is None:
            raise ValueError("Database session 'db' is required to query decisions.")

        query = actual_db.query(SecurityDecision)

        if session_id:
            query = query.filter(SecurityDecision.session_id == session_id)
        if decision_type:
            query = query.filter(SecurityDecision.decision_type == decision_type)
        if finding_id:
            query = query.filter(SecurityDecision.finding_id == finding_id)
        if min_confidence is not None:
            query = query.filter(SecurityDecision.confidence >= min_confidence)

        total_count = query.count()
        records = (
            query.order_by(desc(SecurityDecision.decision_timestamp))
            .offset(max(0, offset))
            .limit(min(200, max(1, limit)))
            .all()
        )

        formatted_list = [cls._format_decision_dict(r) for r in records]
        return DecisionQueryResult({
            "decisions": formatted_list,
            "total": total_count,
        })

    @classmethod
    def _format_decision_dict(cls, record: Any) -> FormattedDecision:
        """Deserializes JSON columns safely for API response models and unit tests."""
        def safe_json_loads(val: Any, default: Any) -> Any:
            if not val:
                return default
            if isinstance(val, (dict, list)):
                return val
            try:
                return json.loads(val)
            except Exception:
                return default

        if isinstance(record, dict):
            # Already formatted dict
            return FormattedDecision(record)

        alts = safe_json_loads(record.alternatives_considered, [])
        rejections = safe_json_loads(record.rejection_reasons, {})
        rejected_alts = [
            {"action": alt, "reason": rejections.get(alt, "")} for alt in alts
        ]

        raw_constraints = getattr(record, "safety_constraints", None)
        loaded_constraints = safe_json_loads(raw_constraints, {})
        constraints_str = loaded_constraints.get("constraint") if isinstance(loaded_constraints, dict) and "constraint" in loaded_constraints else (str(loaded_constraints) if loaded_constraints else "")

        ts_str = (
            record.decision_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
            if getattr(record, "decision_timestamp", None)
            else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        )

        d = FormattedDecision({
            "id": str(record.id),
            "decision_id": str(record.decision_id),
            "finding_id": str(record.finding_id) if record.finding_id is not None else None,
            "session_id": str(record.session_id) if record.session_id is not None else None,
            "execution_id": str(getattr(record, "execution_id", "")) if getattr(record, "execution_id", None) else None,
            "decision_type": str(record.decision_type),
            "decision_reason": str(record.decision_reason or ""),
            "reasoning_summary": str(record.decision_reason or ""),
            "confidence": float(record.confidence or 0.0),
            "selected_action": str(record.selected_action or ""),
            "evidence_references": safe_json_loads(record.evidence_references, []),
            "input_context": safe_json_loads(record.input_context, None),
            "alternatives_considered": alts,
            "rejection_reasons": rejections,
            "rejected_alternatives": rejected_alts,
            "safety_constraints": constraints_str or loaded_constraints,
            "provenance": getattr(record, "provenance", "ExplainabilityEngine_v1"),
            "decision_timestamp": ts_str,
        })
        return d

    # Instance method delegates for when initialized with db
    def record(self, **kwargs) -> FormattedDecision:
        return self.record_decision(db=self.db, **kwargs)

    def get(self, decision_id: str) -> Optional[FormattedDecision]:
        return self.get_decision_by_id(db=self.db, decision_id=decision_id)

    def query(self, **kwargs) -> Dict[str, Any]:
        return self.query_decisions(db=self.db, **kwargs)

    def __getattr__(self, name: str):
        # Support calling classmethods on instances seamlessly
        if hasattr(self.__class__, name):
            attr = getattr(self.__class__, name)
            if callable(attr):
                def wrapper(*args, **kwargs):
                    if "db" not in kwargs and (not args or not isinstance(args[0], Session)):
                        return attr(db=self.db, *args, **kwargs)
                    return attr(*args, **kwargs)
                return wrapper
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
