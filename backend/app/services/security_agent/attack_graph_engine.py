"""Re-export of Advanced Attack Graph Planning Engine (Phase E2)."""

from app.security_agent.attack_graph_engine import (
    ENTRY_VECTOR_RISKS,
    IMPACT_SINK_RISKS,
    MAX_ANALYSIS_TIME_MS,
    MAX_CANDIDATE_PATHS,
    MAX_EDGES,
    MAX_HTTP_REQUESTS_PER_CHAIN,
    MAX_LOOP_DEPTH,
    MAX_NODES,
    MAX_PATH_LENGTH,
    AttackGraphEngine,
)

__all__ = [
    "AttackGraphEngine",
    "MAX_NODES",
    "MAX_EDGES",
    "MAX_CANDIDATE_PATHS",
    "MAX_PATH_LENGTH",
    "MAX_LOOP_DEPTH",
    "MAX_HTTP_REQUESTS_PER_CHAIN",
    "MAX_ANALYSIS_TIME_MS",
    "ENTRY_VECTOR_RISKS",
    "IMPACT_SINK_RISKS",
]
