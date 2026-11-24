"""Evidence Registry Engine (Phase E4).

Manages cryptographic evidence retrieval, HMAC-SHA256 validation,
and immutable evidence linking for security findings throughout their lifecycle.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.security_agent.crypto import (
    EvidenceTrustLevel,
    compute_evidence_signature,
    verify_evidence_signature,
)
from app.security_agent.models import HttpEvidenceRecord, SecurityTestExecution

logger = logging.getLogger(__name__)


class EvidenceRegistry:
    """Provides cryptographic evidence verification, retrieval, and finding linkage."""

    @classmethod
    def get_evidence_by_id_or_hash(
        cls,
        db: Session,
        evidence_identifier: str,
    ) -> Optional[HttpEvidenceRecord]:
        """Looks up an HttpEvidenceRecord by its primary key id, execution_id, or evidence_sha256."""
        if not evidence_identifier:
            return None

        # 1. Direct PK lookup
        record = db.query(HttpEvidenceRecord).filter(HttpEvidenceRecord.id == evidence_identifier).first()
        if record:
            return record

        # 2. Execution ID lookup
        record = db.query(HttpEvidenceRecord).filter(HttpEvidenceRecord.execution_id == evidence_identifier).first()
        if record:
            return record

        # 3. SHA-256 digest lookup
        record = db.query(HttpEvidenceRecord).filter(HttpEvidenceRecord.evidence_sha256 == evidence_identifier).first()
        return record

    @classmethod
    def verify_evidence_authenticity(
        cls,
        evidence: HttpEvidenceRecord,
        provided_hmac_sig: Optional[str] = None,
    ) -> Tuple[EvidenceTrustLevel, bool, str]:
        """Verifies evidence integrity and authenticity using constant-time cryptographic checks.

        Returns: (EvidenceTrustLevel, is_valid, details_message)
        """
        if not evidence:
            return EvidenceTrustLevel.MISSING, False, "Evidence record is missing or deleted."

        req_body = evidence.request_body or ""
        resp_body = evidence.response_body or ""
        status_code = str(evidence.response_status_code or "")
        method = evidence.http_method or "POST"
        url = evidence.target_url or ""

        # Reconstruct canonical payloads (pipe-delimited from executor/multi_turn, colon-delimited fallback)
        canonical_pipe = f"{url}|{method}|{req_body}|{status_code}|{resp_body}"
        canonical_colon = f"{method}:{url}:{status_code}:{req_body}:{resp_body}"

        digest_to_check = provided_hmac_sig or evidence.evidence_sha256
        if not digest_to_check:
            return EvidenceTrustLevel.MISSING, False, "Missing cryptographic evidence digest."

        # 1. Primary check: pipe-delimited canonical format
        from app.security_agent.crypto import classify_evidence_trust
        trust = classify_evidence_trust(canonical_pipe, digest_to_check)
        if trust == EvidenceTrustLevel.HMAC_VERIFIED:
            return EvidenceTrustLevel.HMAC_VERIFIED, True, "HMAC-SHA256 signature verified with constant-time check."
        elif trust == EvidenceTrustLevel.LEGACY_SHA256_VERIFIED:
            return EvidenceTrustLevel.LEGACY_SHA256_VERIFIED, True, "Integrity verified via legacy unkeyed SHA-256 digest."

        # 2. Secondary check: colon-delimited canonical format
        trust_alt = classify_evidence_trust(canonical_colon, digest_to_check)
        if trust_alt == EvidenceTrustLevel.HMAC_VERIFIED:
            return EvidenceTrustLevel.HMAC_VERIFIED, True, "HMAC-SHA256 signature verified with constant-time check (colon format)."
        elif trust_alt == EvidenceTrustLevel.LEGACY_SHA256_VERIFIED:
            return EvidenceTrustLevel.LEGACY_SHA256_VERIFIED, True, "Integrity verified via legacy unkeyed SHA-256 digest (colon format)."

        return EvidenceTrustLevel.INVALID, False, "Cryptographic evidence digest or HMAC signature verification failed."

    @classmethod
    def package_evidence_bundle(
        cls,
        db: Session,
        evidence_identifiers: List[str],
    ) -> List[Dict[str, Any]]:
        """Bundles and cryptographically validates a collection of evidence identifiers for finding attachments."""
        bundle: List[Dict[str, Any]] = []

        for eid in evidence_identifiers:
            record = cls.get_evidence_by_id_or_hash(db, eid)
            if not record:
                bundle.append({
                    "evidence_id": eid,
                    "trust_level": EvidenceTrustLevel.MISSING.value,
                    "is_verified": False,
                    "error": "Evidence record not found in repository.",
                })
                continue

            trust_level, is_valid, details = cls.verify_evidence_authenticity(record)

            bundle.append({
                "evidence_id": record.id,
                "execution_id": record.execution_id,
                "evidence_sha256": record.evidence_sha256,
                "target_url": record.target_url,
                "http_method": record.http_method,
                "response_status_code": record.response_status_code,
                "response_latency_ms": record.response_latency_ms,
                "trust_level": trust_level.value,
                "is_verified": is_valid,
                "verification_details": details,
                "timestamp_recorded": record.created_at.isoformat() if record.created_at else None,
            })

        return bundle
