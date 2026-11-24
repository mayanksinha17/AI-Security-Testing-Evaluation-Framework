"""Re-export of Deep OpenAPI Schema Intelligence Engine (Phase E3)."""

from app.security_agent.schema_intelligence import (
    DeepOpenApiSchemaIntelligence,
    SchemaSecurityViolation,
    MAX_REFERENCE_DEPTH,
    MAX_SCHEMA_SIZE_BYTES,
    MAX_COMPONENT_DEFINITIONS,
    MAX_PAYLOAD_SIZE_BYTES,
    MAX_ANALYSIS_TIME_MS,
    SECURITY_FIELD_KEYWORDS,
)

__all__ = [
    "DeepOpenApiSchemaIntelligence",
    "SchemaSecurityViolation",
    "MAX_REFERENCE_DEPTH",
    "MAX_SCHEMA_SIZE_BYTES",
    "MAX_COMPONENT_DEFINITIONS",
    "MAX_PAYLOAD_SIZE_BYTES",
    "MAX_ANALYSIS_TIME_MS",
    "SECURITY_FIELD_KEYWORDS",
]
