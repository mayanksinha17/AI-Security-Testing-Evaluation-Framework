"""Cryptographic Evidence Signing and Verification Module (Phase C.1).

Implements HMAC-SHA256 signature generation and constant-time verification for
unforgeable HTTP wire evidence audit records.
"""

from enum import Enum
import hashlib
import hmac
import os
from typing import Optional

from app.core.config import settings


class EvidenceTrustLevel(str, Enum):
    """Trust and authenticity classification for captured HTTP wire evidence records."""
    HMAC_VERIFIED = "HMAC_VERIFIED"
    LEGACY_SHA256_VERIFIED = "LEGACY_SHA256_VERIFIED"
    INVALID = "INVALID"
    MISSING = "MISSING"


def get_evidence_signing_key() -> bytes:
    """Retrieves the evidence signing secret key from settings or environment.
    
    Fails safely in production environments if a secure key is missing.
    In development/testing, falls back to a deterministic development key.
    """
    key_str = getattr(settings, "evidence_signing_key", None) or os.environ.get("EVIDENCE_SIGNING_KEY")
    if key_str and len(key_str.strip()) > 0:
        return key_str.strip().encode("utf-8")

    # In production, missing signing key is a critical configuration error
    if getattr(settings, "app_env", "development").lower() in ("production", "prod"):
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: EVIDENCE_SIGNING_KEY must be configured in production environments."
        )

    # Safe deterministic fallback for development, testing, and offline auditing
    return b"dev_evidence_hmac_secret_key_ygf_ngo_2026_phase_c1"


def compute_evidence_signature(canonical_payload: str, key: Optional[bytes] = None) -> str:
    """Computes an unforgeable HMAC-SHA256 digest over the canonical evidence string.
    
    Returns formatted digest string with algorithm prefix: 'hmac-sha256:<hex>'
    """
    signing_key = key if key is not None else get_evidence_signing_key()
    digest = hmac.new(signing_key, canonical_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def verify_evidence_signature(canonical_payload: str, stored_digest: Optional[str], key: Optional[bytes] = None) -> bool:
    """Verifies evidence integrity using constant-time comparison.
    
    Backward-compatible:
    - If stored_digest starts with 'hmac-sha256:', verifies using HMAC-SHA256.
    - If stored_digest is a standard 64-char hex string (legacy unkeyed SHA-256), verifies using legacy SHA-256.
    """
    if not stored_digest or len(stored_digest.strip()) == 0:
        return False

    clean_stored = stored_digest.strip()
    payload_bytes = canonical_payload.encode("utf-8")

    if clean_stored.startswith("hmac-sha256:"):
        signing_key = key if key is not None else get_evidence_signing_key()
        expected = compute_evidence_signature(canonical_payload, signing_key)
        return hmac.compare_digest(clean_stored, expected)
    else:
        # Legacy unkeyed SHA-256 verification (backward compatibility)
        legacy_hash = hashlib.sha256(payload_bytes).hexdigest()
        return hmac.compare_digest(clean_stored, legacy_hash)


def classify_evidence_trust(
    canonical_payload: str,
    stored_digest: Optional[str],
    key: Optional[bytes] = None,
) -> EvidenceTrustLevel:
    """Classifies the cryptographic trust level of an evidence record.
    
    Returns:
    - HMAC_VERIFIED: Matches constant-time HMAC-SHA256 signature using the protected key.
    - LEGACY_SHA256_VERIFIED: Matches unkeyed 64-char SHA-256 digest (content integrity only).
    - INVALID: Non-empty digest present but fails constant-time cryptographic verification.
    - MISSING: Missing or empty digest.
    
    Constant-time comparison is strictly enforced to prevent timing attacks.
    Signing keys are never logged, formatted, or exposed through exceptions.
    """
    if not stored_digest or len(stored_digest.strip()) == 0:
        return EvidenceTrustLevel.MISSING

    clean_stored = stored_digest.strip()
    payload_bytes = canonical_payload.encode("utf-8")

    if clean_stored.startswith("hmac-sha256:"):
        signing_key = key if key is not None else get_evidence_signing_key()
        expected = compute_evidence_signature(canonical_payload, signing_key)
        if hmac.compare_digest(clean_stored, expected):
            return EvidenceTrustLevel.HMAC_VERIFIED
        return EvidenceTrustLevel.INVALID
    elif len(clean_stored) == 64:
        legacy_hash = hashlib.sha256(payload_bytes).hexdigest()
        if hmac.compare_digest(clean_stored, legacy_hash):
            return EvidenceTrustLevel.LEGACY_SHA256_VERIFIED
        return EvidenceTrustLevel.INVALID
    else:
        return EvidenceTrustLevel.INVALID

