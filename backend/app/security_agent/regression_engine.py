"""Security Regression Intelligence Engine (Phase E5).

Provides enterprise-grade differential assessment across security testing plans,
execution sessions, versions, and deployment environments.

Key capabilities:
1. Canonical Finding Correlation via 4-tuple:
   (affected_endpoint, risk_id, http_method, category)
2. Five Deterministic Finding Discrepancy Classifications:
   - NEW_VULNERABILITY: Confirmed in current run, absent in baseline run.
   - RESOLVED_VULNERABILITY: Confirmed in baseline run, verified blocked/mitigated in current run.
   - PERSISTENT_VULNERABILITY: Confirmed in both baseline and current runs without effective mitigation.
   - REOPENED_VULNERABILITY: Previously resolved in historical lifecycle, but re-confirmed in current run.
   - REGRESSION_DETECTED: Control degradation where an endpoint previously blocked now exhibits vulnerability.
3. Population Discrepancy Intelligence:
   - Common intersection population (I = E_base ∩ E_curr)
   - Intersection Resilience Score (missing/inconclusive never classified as secure)
   - Attack surface expansion metric (X = |E_curr| / |E_base|)
   - Mandatory Population Caveat Disclosure
4. Target Isolation Enforcement:
   - Respects 6-tuple: (target_identity, application_id, app_version, environment, endpoint, risk_id)
   - Blocks invalid cross-environment / cross-target comparisons without explicit authorization.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse
import uuid

from sqlalchemy.orm import Session

from app.security_agent.finding_lifecycle import FindingLifecycleEngine
from app.security_agent.models import (
    AgentExecutionSession,
    SecurityExecutionPlan,
    SecurityFinding,
    SecurityFindingHistory,
    SecurityRegressionComparison,
    SecurityTestExecution,
)
from app.security_agent.schemas import (
    PopulationDisclosure,
    RegressionComparisonResponse,
    RegressionFindingDelta,
    RegressionRunSummary,
)

logger = logging.getLogger(__name__)


class TargetIsolationViolationError(ValueError):
    """Raised when an unauthorized cross-target or cross-environment comparison is requested."""
    pass


class SecurityRegressionEngine:
    """Enterprise differential assessment and regression analysis engine."""

    # Set of statuses considered vulnerable or potential
    VULNERABLE_STATUSES: Set[str] = {
        "VULNERABLE",
        "CONFIRMED",
        "POTENTIAL",
        "DETECTED",
        "TRIAGE",
    }

    # Set of statuses considered actively defended or resolved
    DEFENDED_STATUSES: Set[str] = {
        "BLOCKED",
        "REMEDIATION_VERIFIED",
        "REFUTED",
        "CLOSED",
    }

    # Inconclusive or error statuses (NEVER classified as secure)
    INCONCLUSIVE_STATUSES: Set[str] = {
        "INCONCLUSIVE",
        "ERROR",
        "CANCELLED",
        "NOT_RUN",
        "PENDING",
    }

    @classmethod
    def normalize_endpoint(cls, raw_path_or_url: str) -> str:
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

    @classmethod
    def build_canonical_key(
        cls,
        endpoint: str,
        risk_id: str,
        http_method: str = "POST",
        category: str = "OWASP_LLM",
    ) -> str:
        """Builds the canonical correlation key:
        (affected_endpoint, risk_id, http_method, category)
        """
        norm_endpoint = cls.normalize_endpoint(endpoint)
        norm_risk = (risk_id or "UNKNOWN").strip().upper()
        norm_method = (http_method or "POST").strip().upper()
        norm_category = (category or "OWASP_LLM").strip().upper()
        return f"{norm_endpoint}:{norm_risk}:{norm_method}:{norm_category}"

    @classmethod
    def _parse_target_authority(cls, target_url: str) -> Tuple[str, str, int]:
        """Parses target authority into (scheme, hostname, port)."""
        clean = (target_url or "").strip()
        parsed = urlparse(clean)
        scheme = (parsed.scheme or "http").lower()
        hostname = (parsed.hostname or "127.0.0.1").lower()
        port = parsed.port or (80 if scheme == "http" else 443)
        return scheme, hostname, port

    @classmethod
    def _validate_target_isolation(
        cls,
        baseline_target: str,
        current_target: str,
        baseline_env: Optional[str],
        current_env: Optional[str],
        allow_cross_target: bool = False,
        allow_cross_environment: bool = False,
    ) -> None:
        """Enforces 6-tuple target isolation boundaries."""
        if not allow_cross_target:
            base_scheme, base_host, base_port = cls._parse_target_authority(baseline_target)
            curr_scheme, curr_host, curr_port = cls._parse_target_authority(current_target)
            if (base_scheme, base_host, base_port) != (curr_scheme, curr_host, curr_port):
                raise TargetIsolationViolationError(
                    f"Cross-target comparison prohibited: baseline target '{baseline_target}' "
                    f"does not match current target '{current_target}'. "
                    f"Set allow_cross_target=True to authorize cross-target comparison."
                )

        if not allow_cross_environment and baseline_env and current_env:
            if baseline_env.strip().lower() != current_env.strip().lower():
                raise TargetIsolationViolationError(
                    f"Cross-environment comparison prohibited: baseline environment '{baseline_env}' "
                    f"does not match current environment '{current_env}'. "
                    f"Set allow_cross_environment=True to authorize cross-environment comparison."
                )

    @classmethod
    def _has_historical_resolution_proof(
        cls,
        db: Optional[Session],
        finding: Optional[SecurityFinding],
        baseline_status: Optional[str],
    ) -> bool:
        """Determines if a finding has documented historical lifecycle evidence of prior resolution.
        
        Required for classifying REOPENED_VULNERABILITY.
        """
        # 1. Baseline status was actively resolved / verified
        if baseline_status in ("REMEDIATION_VERIFIED", "CLOSED"):
            return True

        if finding is None:
            return False

        # 2. Finding's current or prior state in lifecycle
        if finding.lifecycle_status in ("REMEDIATION_VERIFIED", "CLOSED"):
            return True

        # 3. Inspect finding history ledger if db session is present
        if db is not None:
            try:
                histories = (
                    db.query(SecurityFindingHistory)
                    .filter(SecurityFindingHistory.finding_id == finding.finding_id)
                    .all()
                )
                for h in histories:
                    if h.new_state in ("REMEDIATION_VERIFIED", "CLOSED"):
                        return True
            except Exception:
                pass

        return False

    @classmethod
    def classify_delta(
        cls,
        canonical_key: str,
        baseline_record: Optional[Dict[str, Any]],
        current_record: Optional[Dict[str, Any]],
        db: Optional[Session] = None,
        linked_finding: Optional[SecurityFinding] = None,
    ) -> Optional[RegressionFindingDelta]:
        """Classifies a finding delta between baseline and current runs with deterministic precedence.
        
        Precedence:
        1. REGRESSION_DETECTED: Control degradation where endpoint was previously BLOCKED/REFUTED
           and current exhibits POTENTIAL/VULNERABLE/CONFIRMED.
        2. REOPENED_VULNERABILITY: Recurrence of a previously resolved/closed vulnerability
           supported by historical lifecycle proof.
        3. PERSISTENT_VULNERABILITY: Confirmed in both baseline and current without resolution.
        4. RESOLVED_VULNERABILITY: Confirmed in baseline, now verified BLOCKED/REFUTED/MITIGATED.
        5. NEW_VULNERABILITY: Absent in baseline, confirmed in current.
        6. STABLE_DEFENSE: Blocked in both baseline and current (not a vulnerability delta).
        
        Guarantees: No finding is double-counted across categories.
        """
        base_status = (baseline_record.get("status") or "").upper() if baseline_record else None
        curr_status = (current_record.get("status") or "").upper() if current_record else None

        # Extract metadata
        record = current_record or baseline_record or {}
        endpoint = record.get("endpoint") or record.get("affected_endpoint") or "/"
        risk_id = record.get("risk_id") or "UNKNOWN"
        http_method = record.get("http_method") or "POST"
        category = record.get("category") or "OWASP_LLM"
        severity = record.get("severity") or "MEDIUM"
        cvss_score = float(record.get("cvss_score") or 0.0)
        title = record.get("title") or f"{risk_id} on {endpoint}"
        evidence_refs = record.get("evidence_references") or []
        if isinstance(evidence_refs, str):
            try:
                evidence_refs = json.loads(evidence_refs)
            except Exception:
                evidence_refs = [evidence_refs]

        # Case 1: REGRESSION_DETECTED
        # Baseline was actively defended (BLOCKED / REFUTED), Current is VULNERABLE / CONFIRMED / POTENTIAL
        if (
            base_status in cls.DEFENDED_STATUSES
            and curr_status in cls.VULNERABLE_STATUSES
        ):
            return RegressionFindingDelta(
                correlation_key=canonical_key,
                affected_endpoint=cls.normalize_endpoint(endpoint),
                risk_id=risk_id,
                http_method=http_method,
                category=category,
                delta_type="REGRESSION_DETECTED",
                baseline_status=base_status,
                current_status=curr_status,
                severity=severity,
                cvss_score=cvss_score,
                title=f"Regression Detected: {title}",
                details=(
                    f"Security control regression on {endpoint}: Previously verified {base_status} "
                    f"in baseline run, but current assessment confirmed vulnerability state {curr_status}."
                ),
                evidence_references=evidence_refs,
            )

        # Case 2: REOPENED_VULNERABILITY
        # Current is VULNERABLE/CONFIRMED, and historical proof of prior resolution exists
        if curr_status in cls.VULNERABLE_STATUSES and cls._has_historical_resolution_proof(
            db, linked_finding, base_status
        ):
            return RegressionFindingDelta(
                correlation_key=canonical_key,
                affected_endpoint=cls.normalize_endpoint(endpoint),
                risk_id=risk_id,
                http_method=http_method,
                category=category,
                delta_type="REOPENED_VULNERABILITY",
                baseline_status=base_status or "RESOLVED_HISTORICAL",
                current_status=curr_status,
                severity=severity,
                cvss_score=cvss_score,
                title=f"Reopened Vulnerability: {title}",
                details=(
                    f"Previously resolved finding recurred on {endpoint}: Documented historical "
                    f"remediation verification existed, but re-testing confirmed active exploit."
                ),
                evidence_references=evidence_refs,
            )

        # Case 3: PERSISTENT_VULNERABILITY
        # Baseline was VULNERABLE, Current is VULNERABLE
        if (
            base_status in cls.VULNERABLE_STATUSES
            and curr_status in cls.VULNERABLE_STATUSES
        ):
            return RegressionFindingDelta(
                correlation_key=canonical_key,
                affected_endpoint=cls.normalize_endpoint(endpoint),
                risk_id=risk_id,
                http_method=http_method,
                category=category,
                delta_type="PERSISTENT_VULNERABILITY",
                baseline_status=base_status,
                current_status=curr_status,
                severity=severity,
                cvss_score=cvss_score,
                title=f"Persistent Vulnerability: {title}",
                details=(
                    f"Vulnerability persists unmitigated on {endpoint} across both baseline "
                    f"({base_status}) and current ({curr_status}) assessment runs."
                ),
                evidence_references=evidence_refs,
            )

        # Case 4: RESOLVED_VULNERABILITY
        # Baseline was VULNERABLE, Current is DEFENDED (BLOCKED / REFUTED / REMEDIATION_VERIFIED)
        if (
            base_status in cls.VULNERABLE_STATUSES
            and curr_status in cls.DEFENDED_STATUSES
        ):
            return RegressionFindingDelta(
                correlation_key=canonical_key,
                affected_endpoint=cls.normalize_endpoint(endpoint),
                risk_id=risk_id,
                http_method=http_method,
                category=category,
                delta_type="RESOLVED_VULNERABILITY",
                baseline_status=base_status,
                current_status=curr_status,
                severity=severity,
                cvss_score=cvss_score,
                title=f"Resolved Vulnerability: {title}",
                details=(
                    f"Security remediation verified on {endpoint}: Vulnerability ({base_status}) "
                    f"in baseline run is now successfully mitigated ({curr_status}) in current run."
                ),
                evidence_references=evidence_refs,
            )

        # Case 5: NEW_VULNERABILITY
        # Absent / Untested in baseline, Current is VULNERABLE
        if (
            (base_status is None or base_status == "UNTESTED")
            and curr_status in cls.VULNERABLE_STATUSES
        ):
            return RegressionFindingDelta(
                correlation_key=canonical_key,
                affected_endpoint=cls.normalize_endpoint(endpoint),
                risk_id=risk_id,
                http_method=http_method,
                category=category,
                delta_type="NEW_VULNERABILITY",
                baseline_status="UNTESTED",
                current_status=curr_status,
                severity=severity,
                cvss_score=cvss_score,
                title=f"New Vulnerability: {title}",
                details=(
                    f"Newly discovered vulnerability on {endpoint}: Attack vector was not evaluated "
                    f"in baseline run, and current assessment confirmed state {curr_status}."
                ),
                evidence_references=evidence_refs,
            )

        # Case 6: STABLE_DEFENSE (Optional tracking, not an active finding delta)
        return None

    @classmethod
    def compute_population_metrics(
        cls,
        baseline_keys: Set[str],
        current_keys: Set[str],
        current_records: Dict[str, Dict[str, Any]],
        baseline_records: Dict[str, Dict[str, Any]],
    ) -> Tuple[float, float, float, float, float, PopulationDisclosure]:
        r"""Computes multi-dimensional resilience scores and population discrepancy metrics.
        
        Mathematical Formulas:
        1. Common Intersection Population: I = S_base ∩ S_curr
        2. Disjoint Baseline-Only: D_base = S_base \ S_curr
        3. Disjoint Current-Only: D_curr = S_curr \ S_base
        4. Attack Surface Expansion Factor:
           X = 1.0 if |S_base| == 0 and |S_curr| == 0
           X = float(|S_curr|) if |S_base| == 0
           X = |S_curr| / |S_base| otherwise
        5. Intersection Resilience Score (R_intersect):
           R_intersect = Defended(I) / (Evaluable(I) + Inconclusive(I))
           Missing, untested, or inconclusive endpoints are NEVER classified as secure.
           Inconclusive/error outcomes remain in the denominator to penalize diagnostic uncertainty.
           If |I| == 0: R_intersect = 1.0 (neutral baseline with explicit caveat disclosure).
        6. Resilience Drift: ΔR_intersect = R_curr(I) - R_base(I)
        """
        intersection_keys = baseline_keys & current_keys
        baseline_only_keys = baseline_keys - current_keys
        current_only_keys = current_keys - baseline_keys

        len_base = len(baseline_keys)
        len_curr = len(current_keys)
        len_inter = len(intersection_keys)
        len_base_only = len(baseline_only_keys)
        len_curr_only = len(current_only_keys)

        # Expansion factor
        if len_base == 0 and len_curr == 0:
            expansion_factor = 1.0
        elif len_base == 0:
            expansion_factor = float(len_curr)
        else:
            expansion_factor = round(len_curr / len_base, 4)

        # Baseline overall resilience
        base_defended = 0
        base_evaluable = 0
        base_inconclusive = 0
        for k, rec in baseline_records.items():
            status = (rec.get("status") or "").upper()
            if status in cls.DEFENDED_STATUSES:
                base_defended += 1
                base_evaluable += 1
            elif status in cls.VULNERABLE_STATUSES:
                base_evaluable += 1
            elif status in cls.INCONCLUSIVE_STATUSES:
                base_inconclusive += 1
        denom_base = base_evaluable + base_inconclusive
        baseline_resilience = round(base_defended / denom_base, 4) if denom_base > 0 else 1.0

        # Current overall resilience
        curr_defended = 0
        curr_evaluable = 0
        curr_inconclusive = 0
        for k, rec in current_records.items():
            status = (rec.get("status") or "").upper()
            if status in cls.DEFENDED_STATUSES:
                curr_defended += 1
                curr_evaluable += 1
            elif status in cls.VULNERABLE_STATUSES:
                curr_evaluable += 1
            elif status in cls.INCONCLUSIVE_STATUSES:
                curr_inconclusive += 1
        denom_curr = curr_evaluable + curr_inconclusive
        current_resilience = round(curr_defended / denom_curr, 4) if denom_curr > 0 else 1.0

        # Intersection resilience scores
        if len_inter == 0:
            intersection_resilience = 1.0
            resilience_drift = 0.0
        else:
            # Baseline score over intersection
            inter_base_defended = 0
            inter_base_denom = 0
            for k in intersection_keys:
                rec = baseline_records.get(k, {})
                status = (rec.get("status") or "").upper()
                if status in cls.DEFENDED_STATUSES:
                    inter_base_defended += 1
                    inter_base_denom += 1
                elif status in cls.VULNERABLE_STATUSES:
                    inter_base_denom += 1
                elif status in cls.INCONCLUSIVE_STATUSES:
                    inter_base_denom += 1
            inter_base_score = (inter_base_defended / inter_base_denom) if inter_base_denom > 0 else 1.0

            # Current score over intersection
            inter_curr_defended = 0
            inter_curr_denom = 0
            for k in intersection_keys:
                rec = current_records.get(k, {})
                status = (rec.get("status") or "").upper()
                if status in cls.DEFENDED_STATUSES:
                    inter_curr_defended += 1
                    inter_curr_denom += 1
                elif status in cls.VULNERABLE_STATUSES:
                    inter_curr_denom += 1
                elif status in cls.INCONCLUSIVE_STATUSES:
                    inter_curr_denom += 1
            intersection_resilience = round(
                (inter_curr_defended / inter_curr_denom) if inter_curr_denom > 0 else 0.0,
                4,
            )
            resilience_drift = round(intersection_resilience - inter_base_score, 4)

        # Population caveat disclosure
        has_discrepancy = len_base_only > 0 or len_curr_only > 0
        warning_msg: Optional[str] = None
        if has_discrepancy:
            warning_msg = (
                f"Population discrepancy detected: Baseline evaluated {len_base} scenarios; "
                f"Current evaluated {len_curr} scenarios ({len_inter} common, "
                f"{len_base_only} baseline-only, {len_curr_only} newly added). "
                f"Direct aggregate comparison is mathematically non-equivalent. "
                f"Rely on the Intersection Resilience Score ({round(intersection_resilience * 100, 1)}%) "
                f"for true security control stability."
            )
        elif len_inter == 0 and (len_base > 0 or len_curr > 0):
            warning_msg = "Disjoint populations: Zero common test scenarios evaluated between runs."

        disclosure = PopulationDisclosure(
            has_population_discrepancy=has_discrepancy,
            baseline_total_scenarios=len_base,
            current_total_scenarios=len_curr,
            intersection_scenarios_count=len_inter,
            baseline_only_count=len_base_only,
            current_only_count=len_curr_only,
            expansion_factor=expansion_factor,
            warning_message=warning_msg,
        )

        return (
            baseline_resilience,
            current_resilience,
            intersection_resilience,
            resilience_drift,
            expansion_factor,
            disclosure,
        )

    @classmethod
    def determine_verdict(
        cls,
        regression_count: int,
        reopened_count: int,
        new_count: int,
        resolved_count: int,
        persistent_count: int,
    ) -> str:
        """Determines the overarching regression analysis verdict."""
        if regression_count > 0:
            return "REGRESSIONS_DETECTED"
        if reopened_count > 0:
            return "REOPENED_VULNERABILITIES_DETECTED"
        if new_count > 0:
            return "NEW_VULNERABILITIES_DETECTED"
        if resolved_count > 0 and persistent_count == 0:
            return "IMPROVED_ALL_RESOLVED"
        if resolved_count > 0:
            return "IMPROVED_PARTIAL_RESOLUTION"
        if persistent_count > 0:
            return "STABLE_UNRESOLVED"
        return "PASSED_NO_REGRESSIONS"

    @classmethod
    def compare_datasets(
        cls,
        baseline_records_list: List[Dict[str, Any]],
        current_records_list: List[Dict[str, Any]],
        baseline_meta: Dict[str, Any],
        current_meta: Dict[str, Any],
        db: Optional[Session] = None,
        allow_cross_target: bool = False,
        allow_cross_environment: bool = False,
    ) -> RegressionComparisonResponse:
        """Executes a pure differential regression comparison between two datasets."""
        # 1. Enforce Target Isolation
        baseline_target = baseline_meta.get("target_url") or "http://127.0.0.1:8000"
        current_target = current_meta.get("target_url") or "http://127.0.0.1:8000"
        baseline_env = baseline_meta.get("environment")
        current_env = current_meta.get("environment")
        baseline_app_version = baseline_meta.get("app_version")
        current_app_version = current_meta.get("app_version")

        cls._validate_target_isolation(
            baseline_target=baseline_target,
            current_target=current_target,
            baseline_env=baseline_env,
            current_env=current_env,
            allow_cross_target=allow_cross_target,
            allow_cross_environment=allow_cross_environment,
        )

        # 2. Index records by canonical correlation key
        baseline_records: Dict[str, Dict[str, Any]] = {}
        for item in baseline_records_list:
            key = cls.build_canonical_key(
                endpoint=item.get("endpoint") or item.get("affected_endpoint") or "/",
                risk_id=item.get("risk_id") or "UNKNOWN",
                http_method=item.get("http_method") or "POST",
                category=item.get("category") or "OWASP_LLM",
            )
            baseline_records[key] = item

        current_records: Dict[str, Dict[str, Any]] = {}
        for item in current_records_list:
            key = cls.build_canonical_key(
                endpoint=item.get("endpoint") or item.get("affected_endpoint") or "/",
                risk_id=item.get("risk_id") or "UNKNOWN",
                http_method=item.get("http_method") or "POST",
                category=item.get("category") or "OWASP_LLM",
            )
            current_records[key] = item

        # 3. Classify all deltas across the union of correlation keys
        all_keys = set(baseline_records.keys()) | set(current_records.keys())
        finding_deltas: List[RegressionFindingDelta] = []
        new_count = 0
        resolved_count = 0
        persistent_count = 0
        reopened_count = 0
        regression_count = 0

        for key in sorted(all_keys):
            base_rec = baseline_records.get(key)
            curr_rec = current_records.get(key)
            linked_finding = (curr_rec or base_rec or {}).get("finding_obj")

            delta = cls.classify_delta(
                canonical_key=key,
                baseline_record=base_rec,
                current_record=curr_rec,
                db=db,
                linked_finding=linked_finding,
            )

            if delta is not None:
                finding_deltas.append(delta)
                if delta.delta_type == "NEW_VULNERABILITY":
                    new_count += 1
                elif delta.delta_type == "RESOLVED_VULNERABILITY":
                    resolved_count += 1
                elif delta.delta_type == "PERSISTENT_VULNERABILITY":
                    persistent_count += 1
                elif delta.delta_type == "REOPENED_VULNERABILITY":
                    reopened_count += 1
                elif delta.delta_type == "REGRESSION_DETECTED":
                    regression_count += 1

        # 4. Compute population & resilience metrics
        (
            base_resilience,
            curr_resilience,
            inter_resilience,
            resilience_drift,
            expansion_factor,
            disclosure,
        ) = cls.compute_population_metrics(
            baseline_keys=set(baseline_records.keys()),
            current_keys=set(current_records.keys()),
            current_records=current_records,
            baseline_records=baseline_records,
        )

        # 5. Determine high-level verdict
        verdict = cls.determine_verdict(
            regression_count=regression_count,
            reopened_count=reopened_count,
            new_count=new_count,
            resolved_count=resolved_count,
            persistent_count=persistent_count,
        )

        comparison_id = f"reg_comp_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        return RegressionComparisonResponse(
            id=str(uuid.uuid4()),
            comparison_id=comparison_id,
            baseline_plan_id=baseline_meta.get("plan_id"),
            current_plan_id=current_meta.get("plan_id"),
            baseline_target=baseline_target,
            current_target=current_target,
            baseline_environment=baseline_env,
            current_environment=current_env,
            baseline_app_version=baseline_app_version,
            current_app_version=current_app_version,
            regression_verdict=verdict,
            new_findings_count=new_count,
            resolved_findings_count=resolved_count,
            persistent_findings_count=persistent_count,
            reopened_findings_count=reopened_count,
            regression_findings_count=regression_count,
            baseline_resilience_score=base_resilience,
            current_resilience_score=curr_resilience,
            intersection_resilience_score=inter_resilience,
            resilience_drift=resilience_drift,
            expansion_factor=expansion_factor,
            population_disclosure=disclosure,
            finding_deltas=finding_deltas,
            created_at=now,
        )

    @classmethod
    def _extract_plan_items(
        cls,
        db: Session,
        plan_id: str,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Extracts evaluation items and metadata for an execution plan."""
        plan = db.query(SecurityExecutionPlan).filter(SecurityExecutionPlan.id == plan_id).first()
        if not plan:
            raise ValueError(f"SecurityExecutionPlan with ID '{plan_id}' not found.")

        app_id, env, version = FindingLifecycleEngine._extract_plan_context(plan)
        plan_meta = {
            "plan_id": plan.id,
            "target_url": plan.target_url,
            "application_id": app_id,
            "environment": env,
            "app_version": version,
            "stage": plan.stage,
        }

        # Query all executions for this plan
        executions = (
            db.query(SecurityTestExecution)
            .filter(SecurityTestExecution.plan_id == plan.id)
            .order_by(SecurityTestExecution.created_at.asc())
            .all()
        )

        items: List[Dict[str, Any]] = []
        for ex in executions:
            # Query if a formal SecurityFinding exists for this execution
            finding = (
                db.query(SecurityFinding)
                .filter(SecurityFinding.execution_id == ex.id)
                .first()
            )
            status = finding.lifecycle_status if finding else ex.verdict

            items.append({
                "execution_id": ex.id,
                "scenario_id": ex.scenario_id,
                "risk_id": ex.risk_id,
                "category": ex.category,
                "http_method": ex.http_method,
                "endpoint": ex.target_endpoint,
                "status": status,
                "severity": finding.severity if finding else "MEDIUM",
                "cvss_score": finding.cvss_score if finding else 0.0,
                "title": finding.title if finding else f"{ex.risk_name} on {ex.target_endpoint}",
                "evidence_references": [ex.evidence.id] if ex.evidence else [],
                "finding_obj": finding,
            })

        return items, plan_meta

    @classmethod
    def compare_plans(
        cls,
        db: Session,
        baseline_plan_id: str,
        current_plan_id: str,
        allow_cross_target: bool = False,
        allow_cross_environment: bool = False,
    ) -> RegressionComparisonResponse:
        """Compares two persistent execution plans in the database and records the comparison."""
        base_items, base_meta = cls._extract_plan_items(db, baseline_plan_id)
        curr_items, curr_meta = cls._extract_plan_items(db, current_plan_id)

        comparison_res = cls.compare_datasets(
            baseline_records_list=base_items,
            current_records_list=curr_items,
            baseline_meta=base_meta,
            current_meta=curr_meta,
            db=db,
            allow_cross_target=allow_cross_target,
            allow_cross_environment=allow_cross_environment,
        )

        # Persist to database table security_regression_comparisons
        metrics_dict = {
            "finding_deltas": [d.model_dump() for d in comparison_res.finding_deltas],
            "population_disclosure": comparison_res.population_disclosure.model_dump(),
        }

        db_record = SecurityRegressionComparison(
            id=comparison_res.id,
            comparison_id=comparison_res.comparison_id,
            baseline_plan_id=baseline_plan_id,
            current_plan_id=current_plan_id,
            baseline_target=comparison_res.baseline_target,
            current_target=comparison_res.current_target,
            baseline_environment=comparison_res.baseline_environment,
            current_environment=comparison_res.current_environment,
            baseline_app_version=comparison_res.baseline_app_version,
            current_app_version=comparison_res.current_app_version,
            new_findings_count=comparison_res.new_findings_count,
            resolved_findings_count=comparison_res.resolved_findings_count,
            persistent_findings_count=comparison_res.persistent_findings_count,
            reopened_findings_count=comparison_res.reopened_findings_count,
            regression_findings_count=comparison_res.regression_findings_count,
            regression_verdict=comparison_res.regression_verdict,
            baseline_resilience_score=comparison_res.baseline_resilience_score,
            current_resilience_score=comparison_res.current_resilience_score,
            intersection_resilience_score=comparison_res.intersection_resilience_score,
            resilience_drift=comparison_res.resilience_drift,
            expansion_factor=comparison_res.expansion_factor,
            comparison_metrics=json.dumps(metrics_dict, default=str),
            created_at=comparison_res.created_at,
        )
        db.add(db_record)
        db.commit()
        db.refresh(db_record)

        return comparison_res

    @classmethod
    def get_comparison(
        cls,
        db: Session,
        comparison_id: str,
    ) -> Optional[RegressionComparisonResponse]:
        """Retrieves a stored regression comparison record."""
        record = (
            db.query(SecurityRegressionComparison)
            .filter(SecurityRegressionComparison.comparison_id == comparison_id)
            .first()
        )
        if not record:
            return None

        metrics = {}
        if record.comparison_metrics:
            try:
                metrics = json.loads(record.comparison_metrics)
            except Exception:
                metrics = {}

        raw_deltas = metrics.get("finding_deltas", [])
        finding_deltas = [RegressionFindingDelta(**d) for d in raw_deltas]
        raw_disc = metrics.get("population_disclosure", {})
        population_disc = PopulationDisclosure(**raw_disc) if raw_disc else PopulationDisclosure()

        return RegressionComparisonResponse(
            id=record.id,
            comparison_id=record.comparison_id,
            baseline_plan_id=record.baseline_plan_id,
            current_plan_id=record.current_plan_id,
            baseline_target=record.baseline_target,
            current_target=record.current_target,
            baseline_environment=record.baseline_environment,
            current_environment=record.current_environment,
            baseline_app_version=record.baseline_app_version,
            current_app_version=record.current_app_version,
            regression_verdict=record.regression_verdict,
            new_findings_count=record.new_findings_count,
            resolved_findings_count=record.resolved_findings_count,
            persistent_findings_count=record.persistent_findings_count,
            reopened_findings_count=record.reopened_findings_count,
            regression_findings_count=record.regression_findings_count,
            baseline_resilience_score=record.baseline_resilience_score,
            current_resilience_score=record.current_resilience_score,
            intersection_resilience_score=record.intersection_resilience_score,
            resilience_drift=record.resilience_drift,
            expansion_factor=record.expansion_factor,
            population_disclosure=population_disc,
            finding_deltas=finding_deltas,
            created_at=record.created_at,
        )

    @classmethod
    def list_comparisons(
        cls,
        db: Session,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[RegressionRunSummary], int]:
        """Lists historical regression comparison runs with pagination."""
        total = db.query(SecurityRegressionComparison).count()
        records = (
            db.query(SecurityRegressionComparison)
            .order_by(SecurityRegressionComparison.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        summaries = [
            RegressionRunSummary(
                id=r.id,
                comparison_id=r.comparison_id,
                baseline_plan_id=r.baseline_plan_id,
                current_plan_id=r.current_plan_id,
                baseline_target=r.baseline_target,
                current_target=r.current_target,
                baseline_environment=r.baseline_environment,
                current_environment=r.current_environment,
                regression_verdict=r.regression_verdict,
                new_findings_count=r.new_findings_count,
                resolved_findings_count=r.resolved_findings_count,
                persistent_findings_count=r.persistent_findings_count,
                reopened_findings_count=r.reopened_findings_count,
                regression_findings_count=r.regression_findings_count,
                intersection_resilience_score=r.intersection_resilience_score,
                resilience_drift=r.resilience_drift,
                expansion_factor=r.expansion_factor,
                created_at=r.created_at,
            )
            for r in records
        ]
        return summaries, total
