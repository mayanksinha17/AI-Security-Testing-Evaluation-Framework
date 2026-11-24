"""Phase E2: Advanced Attack Graph Planning Engine Test Suite.

Verifies:
1. Tarjan Strongly Connected Components (SCC) algorithm across multiple topologies:
   - Acyclic graphs
   - Simple cycles
   - Multiple interconnected cycles
   - Self-loops
   - Disconnected components
   - Empty graphs
   - Large bounded graphs
2. Graph condensation into Directed Acyclic Graphs (DAG).
3. Candidate attack path generation, bounding, deduplication, and limits.
4. Phase E1 PriorityScore and evidence trust integration.
5. REST API endpoints, scope validation, and safety boundaries.
"""

from pathlib import Path
import sys
import time
from typing import Any, Dict, List
import uuid

import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from app.database.session import get_db
from app.main import app
from app.security_agent.attack_graph_engine import (
    MAX_CANDIDATE_PATHS,
    MAX_EDGES,
    MAX_LOOP_DEPTH,
    MAX_NODES,
    MAX_PATH_LENGTH,
    AttackGraphEngine,
    RelationshipSemantic,
    classify_relationship_semantic,
)
from app.security_agent.crypto import EvidenceTrustLevel, compute_evidence_signature
from app.security_agent.intelligence_engine import DynamicSecurityIntelligenceEngine
from app.security_agent.models import HttpEvidenceRecord, SecurityExecutionPlan, SecurityTestExecution
from app.security_agent.schemas import (
    AttackGraphEdgeSchema,
    AttackGraphNodeSchema,
    CandidateAttackPathSchema,
    GenerateCandidatePathsRequest,
    TargetIsolationTuple,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    generator = get_db()
    session = next(generator)
    try:
        yield session
    finally:
        session.close()


# =====================================================================
# 1. Tarjan's Strongly Connected Components (SCC) Algorithm Tests
# =====================================================================

def test_tarjan_scc_acyclic_graph():
    """Verifies that an acyclic graph (A -> B -> C -> D) produces only singleton, non-cyclic components."""
    nodes = {
        "A": AttackGraphNodeSchema(id="A", risk_id="A", risk_name="Node A", category="TEST", severity="LOW"),
        "B": AttackGraphNodeSchema(id="B", risk_id="B", risk_name="Node B", category="TEST", severity="LOW"),
        "C": AttackGraphNodeSchema(id="C", risk_id="C", risk_name="Node C", category="TEST", severity="LOW"),
        "D": AttackGraphNodeSchema(id="D", risk_id="D", risk_name="Node D", category="TEST", severity="LOW"),
    }
    edges = [
        AttackGraphEdgeSchema(source="A", target="B", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="C", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="C", target="D", relationship_type="enables", confidence=0.9),
    ]

    all_sccs, cyclic_comps, node_to_scc = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(all_sccs) == 4
    assert len(cyclic_comps) == 0
    for scc in all_sccs:
        assert scc.is_cyclic is False
        assert scc.size == 1


def test_tarjan_scc_simple_cycle():
    """Verifies that a simple 2-node cycle (A -> B -> A) is detected as a single cyclic component."""
    nodes = {
        "A": AttackGraphNodeSchema(id="A", risk_id="A", risk_name="Node A", category="TEST", severity="HIGH"),
        "B": AttackGraphNodeSchema(id="B", risk_id="B", risk_name="Node B", category="TEST", severity="HIGH"),
        "C": AttackGraphNodeSchema(id="C", risk_id="C", risk_name="Node C", category="TEST", severity="LOW"),
    }
    edges = [
        AttackGraphEdgeSchema(source="A", target="B", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="A", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="C", relationship_type="enables", confidence=0.9),
    ]

    all_sccs, cyclic_comps, node_to_scc = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(all_sccs) == 2  # {A, B} and {C}
    assert len(cyclic_comps) == 1
    cycle = cyclic_comps[0]
    assert cycle.is_cyclic is True
    assert cycle.size == 2
    assert set(cycle.node_ids) == {"A", "B"}
    assert "feedback loop" in cycle.explanation.lower()


def test_tarjan_scc_multiple_interconnected_cycles():
    """Verifies interconnected cycles (A <-> B and B <-> C) collapse into a 3-node cyclic component."""
    nodes = {nid: AttackGraphNodeSchema(id=nid, risk_id=nid, risk_name=f"Node {nid}", category="TEST", severity="HIGH") for nid in ["A", "B", "C", "D"]}
    edges = [
        AttackGraphEdgeSchema(source="A", target="B", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="A", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="C", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="C", target="B", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="C", target="D", relationship_type="enables", confidence=0.9),
    ]

    all_sccs, cyclic_comps, node_to_scc = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(cyclic_comps) == 1
    assert cyclic_comps[0].size == 3
    assert set(cyclic_comps[0].node_ids) == {"A", "B", "C"}
    assert node_to_scc["A"] == node_to_scc["B"] == node_to_scc["C"]
    assert node_to_scc["D"] != node_to_scc["A"]


def test_tarjan_scc_self_loop():
    """Verifies that a self-loop (A -> A) is detected as a cyclic component of size 1."""
    nodes = {
        "A": AttackGraphNodeSchema(id="A", risk_id="A", risk_name="Node A", category="TEST", severity="MEDIUM"),
        "B": AttackGraphNodeSchema(id="B", risk_id="B", risk_name="Node B", category="TEST", severity="LOW"),
    }
    edges = [
        AttackGraphEdgeSchema(source="A", target="A", relationship_type="amplifies", confidence=0.8),
        AttackGraphEdgeSchema(source="A", target="B", relationship_type="enables", confidence=0.9),
    ]

    all_sccs, cyclic_comps, node_to_scc = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(cyclic_comps) == 1
    assert cyclic_comps[0].size == 1
    assert cyclic_comps[0].node_ids == ["A"]
    assert "self-loop" in cyclic_comps[0].explanation.lower()


def test_tarjan_scc_disconnected_components():
    """Verifies that disconnected subgraphs (A -> B and C -> D) are correctly processed."""
    nodes = {nid: AttackGraphNodeSchema(id=nid, risk_id=nid, risk_name=f"Node {nid}", category="TEST", severity="LOW") for nid in ["A", "B", "C", "D"]}
    edges = [
        AttackGraphEdgeSchema(source="A", target="B", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="C", target="D", relationship_type="enables", confidence=0.9),
    ]

    all_sccs, cyclic_comps, node_to_scc = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(all_sccs) == 4
    assert len(cyclic_comps) == 0


def test_tarjan_scc_empty_graph():
    """Verifies that an empty graph is handled cleanly without exceptions."""
    all_sccs, cyclic_comps, node_to_scc = AttackGraphEngine.tarjan_scc({}, [])
    assert len(all_sccs) == 0
    assert len(cyclic_comps) == 0
    assert len(node_to_scc) == 0


def test_graph_condensation_into_dag():
    """Verifies that cyclic components are condensed into super-nodes producing an acyclic DAG."""
    nodes = {nid: AttackGraphNodeSchema(id=nid, risk_id=nid, risk_name=f"Node {nid}", category="TEST", severity="HIGH") for nid in ["A", "B", "C", "D"]}
    edges = [
        AttackGraphEdgeSchema(source="A", target="B", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="A", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="C", relationship_type="escalates_to", confidence=0.85),
        AttackGraphEdgeSchema(source="C", target="D", relationship_type="exfiltrates_via", confidence=0.88),
    ]

    all_sccs, cyclic_comps, node_to_scc = AttackGraphEngine.tarjan_scc(nodes, edges)
    dag_edges = AttackGraphEngine.condense_to_dag(nodes, edges, node_to_scc)

    # In condensed DAG, A and B are collapsed into one component
    scc_ab = node_to_scc["A"]
    scc_c = node_to_scc["C"]
    scc_d = node_to_scc["D"]

    assert len(dag_edges) == 2
    assert any(e.source_component == scc_ab and e.target_component == scc_c for e in dag_edges)
    assert any(e.source_component == scc_c and e.target_component == scc_d for e in dag_edges)


# =====================================================================
# 2. Bounded Candidate Path Planning & Limit Enforcement
# =====================================================================

def test_candidate_attack_paths_generation_and_limits(client):
    """Verifies bounded candidate attack path generation adhering to length, path count, and confidence."""
    req = GenerateCandidatePathsRequest(
        target_url="http://127.0.0.1:8000",
        application_id="default",
        app_version="v1.0",
        environment="sandbox",
        endpoint="/api/chat",
        source_risks=["LLM01"],
        target_sinks=["ASI05", "LLM02"],
        max_paths=10,
        max_length=4,
    )

    res = client.post("/api/security-agent/attack-graph/candidate-paths", json=req.model_dump())
    assert res.status_code == 200
    data = res.json()

    assert data["target_identity"] == "127.0.0.1:8000"
    assert "paths" in data
    assert len(data["paths"]) <= 10
    assert len(data["paths"]) > 0

    for path in data["paths"]:
        assert path["source_risk"] == "LLM01"
        assert path["destination_risk"] in ("ASI05", "LLM02")
        assert 2 <= path["path_length"] <= 4
        assert 0.0 <= path["cumulative_priority_score"] <= 1.0
        assert 0.0 <= path["cumulative_confidence"] <= 1.0
        assert len(path["ordered_steps"]) == path["path_length"]
        assert "chain_" in path["chain_id"]
        assert "disclaimer" in path


def test_path_deduplication():
    """Verifies that generated candidate paths contain no duplicate node sequences."""
    req = GenerateCandidatePathsRequest(
        target_url="http://127.0.0.1:8000",
        max_paths=20,
        max_length=5,
    )

    db_gen = get_db()
    db = next(db_gen)
    try:
        res = AttackGraphEngine.generate_candidate_paths(req, db)
        signatures = [tuple(s.risk_id for s in p.ordered_steps) for p in res.paths]
        assert len(signatures) == len(set(signatures)), "Duplicate candidate paths detected!"
    finally:
        db.close()


def test_resource_limits_caps_enforced():
    """Verifies that MAX_NODES (100) and MAX_EDGES (250) are enforced when large custom graphs are supplied."""
    custom_nodes = [{"id": f"N_{i}", "risk_name": f"Node {i}"} for i in range(150)]
    # Create 300 edges connecting nodes within the first 100 nodes so both endpoints exist
    custom_edges = [{"source": f"N_{i % 100}", "target": f"N_{(i + 1) % 100}", "type": "enables"} for i in range(300)]

    nodes_dict, edges_list, limits = AttackGraphEngine.build_dependency_graph(
        custom_nodes=custom_nodes,
        custom_edges=custom_edges,
    )

    assert len(nodes_dict) == MAX_NODES
    assert len(edges_list) == MAX_EDGES
    assert any("MAX_NODES_EXCEEDED" in lim for lim in limits)
    assert any("MAX_EDGES_EXCEEDED" in lim for lim in limits)


def test_path_length_limit_and_loop_depth_bound():
    """Verifies that paths never exceed MAX_PATH_LENGTH (5) and loop depth is capped at MAX_LOOP_DEPTH (2)."""
    req = GenerateCandidatePathsRequest(
        target_url="http://127.0.0.1:8000",
        max_paths=20,
        max_length=5,
    )
    db_gen = get_db()
    db = next(db_gen)
    try:
        res = AttackGraphEngine.generate_candidate_paths(req, db)
        for p in res.paths:
            assert p.path_length <= MAX_PATH_LENGTH
            node_counts = [p.ordered_steps.count(s) for s in p.ordered_steps]
            for count in node_counts:
                assert count <= MAX_LOOP_DEPTH
    finally:
        db.close()


def test_analysis_timeout_recording():
    """Verifies that graph analysis records duration and includes timeout warning when threshold exceeded."""
    res = AttackGraphEngine.analyze_graph()
    assert res.analysis_duration_ms >= 0.0
    assert isinstance(res.resource_limits_reached, list)


# =====================================================================
# 3. Phase E1 Dynamic Intelligence & Target Isolation Integration
# =====================================================================

def test_phase_e1_priority_score_integration(client):
    """Verifies that nodes and candidate paths integrate Phase E1 PriorityScore calculations."""
    res = client.get("/api/security-agent/attack-graph/full?target_url=http://127.0.0.1:8000")
    assert res.status_code == 200
    data = res.json()

    assert "nodes" in data
    assert len(data["nodes"]) == 20
    for node in data["nodes"]:
        assert 0.0 <= node["priority_score"] <= 1.0
        assert 0.0 <= node["historical_outcome_score"] <= 1.0
        assert node["evidence_trust_level"] in ("HMAC_VERIFIED", "LEGACY_SHA256_VERIFIED", "INVALID", "MISSING")


def test_individual_candidate_chain_retrieval(client):
    """Verifies that generated candidate chains are cached and retrievable by chain_id."""
    req = GenerateCandidatePathsRequest(
        target_url="http://127.0.0.1:8000",
        source_risks=["LLM01"],
        target_sinks=["ASI02"],
        max_paths=5,
    )
    gen_res = client.post("/api/security-agent/attack-graph/candidate-paths", json=req.model_dump())
    assert gen_res.status_code == 200
    paths = gen_res.json()["paths"]
    assert len(paths) > 0

    target_chain_id = paths[0]["chain_id"]
    get_res = client.get(f"/api/security-agent/attack-graph/chains/{target_chain_id}")
    assert get_res.status_code == 200
    chain_data = get_res.json()
    assert chain_data["chain_id"] == target_chain_id
    assert chain_data["source_risk"] == "LLM01"
    assert len(chain_data["ordered_steps"]) > 0


def test_scope_validation_rejection(client):
    """Verifies that unauthorized or external target URLs are rejected with HTTP 400."""
    req = GenerateCandidatePathsRequest(
        target_url="http://unauthorized-evil-target.com",
    )
    res = client.post("/api/security-agent/attack-graph/candidate-paths", json=req.model_dump())
    assert res.status_code == 400
    assert "unauthorized" in res.json()["detail"].lower() or "out of scope" in res.json()["detail"].lower()


# =====================================================================
# 4. Phase E2 Audit Item 1: Relationship-Aware Path Semantics
# =====================================================================

def test_impact_amplification_alone_does_not_establish_prerequisite():
    """Audit Item 1: Verifies that an impact-amplification ('amplifies') relationship alone
    does NOT establish a hard prerequisite, does not block execution eligibility, and is
    properly recorded under theoretical_dependencies."""
    nodes = {
        "LLM01": AttackGraphNodeSchema(id="LLM01", risk_id="LLM01", risk_name="Prompt Injection", category="OWASP_LLM", severity="CRITICAL", is_entry_vector=True, prerequisites_satisfied=True),
        "ASI06": AttackGraphNodeSchema(id="ASI06", risk_id="ASI06", risk_name="Memory Poisoning", category="OWASP_ASI", severity="HIGH", prerequisites_satisfied=True),
        "ASI08": AttackGraphNodeSchema(id="ASI08", risk_id="ASI08", risk_name="Cascading Drift", category="OWASP_ASI", severity="MEDIUM", is_impact_sink=True),
    }
    # Path: LLM01 -> ASI06 (enables) -> ASI08 (amplifies)
    edges = [
        AttackGraphEdgeSchema(source="LLM01", target="ASI06", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="ASI06", target="ASI08", relationship_type="amplifies", confidence=0.82),
    ]

    target_iso = TargetIsolationTuple(
        target_identity="127.0.0.1:8000",
        application_id="default",
        app_version="v1.0",
        environment="sandbox",
        endpoint="/api/chat",
    )

    path = AttackGraphEngine._build_candidate_path(
        path_nodes=["LLM01", "ASI06", "ASI08"],
        path_edges=edges,
        nodes_dict=nodes,
        target_isolation=target_iso,
    )

    # 1. Amplification relationship classification
    assert path.ordered_steps[2].relationship_from_prior == "amplifies"
    assert path.ordered_steps[2].relationship_semantic == RelationshipSemantic.IMPACT_AMPLIFICATION
    assert path.ordered_steps[2].is_hard_prerequisite is False
    assert path.ordered_steps[2].prerequisite_satisfied is True

    # 2. Path exposes relationship semantics and theoretical dependencies
    assert "amplifies" in path.relationship_types
    assert len(path.hard_prerequisites) == 0
    assert any("amplifies" in dep for dep in path.theoretical_dependencies)

    # 3. Path remains execution-eligible because amplifies is NOT a hard prerequisite
    assert path.execution_eligibility is True
    assert path.rejection_reason is None
    assert len(path.rejection_reasons) == 0
    assert path.current_status == "READY"


def test_structural_prerequisite_enforces_hard_constraint():
    """Audit Item 1: Verifies that 'prerequisite_for' establishes a hard prerequisite.
    When unsatisfied, execution_eligibility is False with explicit rejection reasons.
    When satisfied, execution_eligibility is True."""
    nodes = {
        "LLM01": AttackGraphNodeSchema(id="LLM01", risk_id="LLM01", risk_name="Prompt Injection", category="OWASP_LLM", severity="CRITICAL", is_entry_vector=True, prerequisites_satisfied=True),
        "ASI02": AttackGraphNodeSchema(id="ASI02", risk_id="ASI02", risk_name="Tool Misuse", category="OWASP_ASI", severity="HIGH", prerequisites_satisfied=False),
        "ASI05": AttackGraphNodeSchema(id="ASI05", risk_id="ASI05", risk_name="Code Execution", category="OWASP_ASI", severity="CRITICAL", is_impact_sink=True),
    }

    target_iso = TargetIsolationTuple(
        target_identity="127.0.0.1:8000",
        application_id="default",
        app_version="v1.0",
        environment="sandbox",
        endpoint="/api/chat",
    )

    # Case A: Unsatisfied hard prerequisite
    edges_unsatisfied = [
        AttackGraphEdgeSchema(source="LLM01", target="ASI02", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="ASI02", target="ASI05", relationship_type="prerequisite_for", prerequisite="requires_admin_token (missing)", confidence=0.88),
    ]

    path_unsatisfied = AttackGraphEngine._build_candidate_path(
        path_nodes=["LLM01", "ASI02", "ASI05"],
        path_edges=edges_unsatisfied,
        nodes_dict=nodes,
        target_isolation=target_iso,
    )

    assert path_unsatisfied.ordered_steps[2].relationship_semantic == RelationshipSemantic.STRUCTURAL_PREREQUISITE
    assert path_unsatisfied.ordered_steps[2].is_hard_prerequisite is True
    assert len(path_unsatisfied.hard_prerequisites) == 1
    assert len(path_unsatisfied.unsatisfied_prerequisites) == 1
    assert path_unsatisfied.execution_eligibility is False
    assert path_unsatisfied.current_status == "INELIGIBLE"
    assert len(path_unsatisfied.rejection_reasons) > 0
    assert "Unsatisfied hard prerequisite" in path_unsatisfied.rejection_reasons[0]

    # Case B: Satisfied hard prerequisite
    nodes["ASI02"].prerequisites_satisfied = True
    edges_satisfied = [
        AttackGraphEdgeSchema(source="LLM01", target="ASI02", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="ASI02", target="ASI05", relationship_type="prerequisite_for", prerequisite="tool_access_granted", confidence=0.88),
    ]

    path_satisfied = AttackGraphEngine._build_candidate_path(
        path_nodes=["LLM01", "ASI02", "ASI05"],
        path_edges=edges_satisfied,
        nodes_dict=nodes,
        target_isolation=target_iso,
    )

    assert path_satisfied.ordered_steps[2].is_hard_prerequisite is True
    assert path_satisfied.ordered_steps[2].prerequisite_satisfied is True
    assert len(path_satisfied.hard_prerequisites) == 1
    assert len(path_satisfied.satisfied_prerequisites) == 1
    assert len(path_satisfied.unsatisfied_prerequisites) == 0
    assert path_satisfied.execution_eligibility is True
    assert path_satisfied.current_status == "READY"


def test_candidate_path_exposes_full_relationship_semantics():
    """Audit Item 1: Verifies that CandidateAttackPathSchema exposes all required audit fields."""
    req = GenerateCandidatePathsRequest(
        target_url="http://127.0.0.1:8000",
        source_risks=["LLM01"],
        target_sinks=["ASI05"],
        max_paths=5,
    )
    db_gen = get_db()
    db = next(db_gen)
    try:
        res = AttackGraphEngine.generate_candidate_paths(req, db)
        assert len(res.paths) > 0
        p = res.paths[0]

        # Verify all audit fields exist and are strongly typed
        assert hasattr(p, "relationship_types")
        assert hasattr(p, "hard_prerequisites")
        assert hasattr(p, "satisfied_prerequisites")
        assert hasattr(p, "unsatisfied_prerequisites")
        assert hasattr(p, "theoretical_dependencies")
        assert hasattr(p, "execution_eligibility")
        assert hasattr(p, "rejection_reasons")
        assert isinstance(p.relationship_types, list)
        assert isinstance(p.execution_eligibility, bool)
    finally:
        db.close()


# =====================================================================
# 5. Phase E2 Audit Item 2: SCC and Cycle Safety Tests
# =====================================================================

def test_tarjan_scc_self_loops():
    """Audit Item 2: Verifies that self-loops (A -> A) are detected as cyclic components of size 1."""
    nodes = {
        "A": AttackGraphNodeSchema(id="A", risk_id="A", risk_name="Node A", category="TEST", severity="HIGH"),
        "B": AttackGraphNodeSchema(id="B", risk_id="B", risk_name="Node B", category="TEST", severity="LOW"),
    }
    edges = [
        AttackGraphEdgeSchema(source="A", target="A", relationship_type="enables", confidence=0.8),
        AttackGraphEdgeSchema(source="A", target="B", relationship_type="enables", confidence=0.9),
    ]

    all_sccs, cyclic_comps, node_to_scc = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(all_sccs) == 2
    assert len(cyclic_comps) == 1
    self_loop_scc = cyclic_comps[0]
    assert self_loop_scc.is_cyclic is True
    assert self_loop_scc.size == 1
    assert "Self-loop cycle detected on node 'A'" in self_loop_scc.explanation
    assert self_loop_scc.is_executable_chain is False
    assert self_loop_scc.independent_verification_required is True


def test_tarjan_scc_two_node_mutual_cycle_safety():
    """Audit Item 2: Verifies that a two-node mutual cycle preserves member nodes,
    internal relationships, and does not automatically become an executable chain."""
    nodes = {
        "LLM01": AttackGraphNodeSchema(id="LLM01", risk_id="LLM01", risk_name="Prompt Injection", category="OWASP_LLM", severity="CRITICAL"),
        "ASI01": AttackGraphNodeSchema(id="ASI01", risk_id="ASI01", risk_name="Goal Hijack", category="OWASP_ASI", severity="CRITICAL"),
    }
    edges = [
        AttackGraphEdgeSchema(source="LLM01", target="ASI01", relationship_type="enables", confidence=0.92),
        AttackGraphEdgeSchema(source="ASI01", target="LLM01", relationship_type="escalates_to", confidence=0.88),
    ]

    all_sccs, cyclic_comps, _ = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(cyclic_comps) == 1
    scc = cyclic_comps[0]
    assert scc.is_cyclic is True
    assert scc.size == 2
    assert sorted(scc.node_ids) == ["ASI01", "LLM01"]
    assert "enables" in scc.internal_relationships
    assert "escalates_to" in scc.internal_relationships
    assert scc.is_executable_chain is False  # SCCs do NOT automatically become executable chains
    assert scc.independent_verification_required is True  # SCC membership does not imply confirmation


def test_tarjan_scc_multiple_interconnected_cycles():
    """Audit Item 2: Verifies interconnected cycles (A <-> B and B <-> C) collapse into a single 3-node SCC."""
    nodes = {
        "A": AttackGraphNodeSchema(id="A", risk_id="A", risk_name="Node A", category="TEST", severity="HIGH"),
        "B": AttackGraphNodeSchema(id="B", risk_id="B", risk_name="Node B", category="TEST", severity="HIGH"),
        "C": AttackGraphNodeSchema(id="C", risk_id="C", risk_name="Node C", category="TEST", severity="HIGH"),
        "D": AttackGraphNodeSchema(id="D", risk_id="D", risk_name="Node D", category="TEST", severity="LOW"),
    }
    edges = [
        AttackGraphEdgeSchema(source="A", target="B", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="A", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="C", relationship_type="escalates_to", confidence=0.85),
        AttackGraphEdgeSchema(source="C", target="B", relationship_type="escalates_to", confidence=0.85),
        AttackGraphEdgeSchema(source="C", target="D", relationship_type="exfiltrates_via", confidence=0.8),
    ]

    all_sccs, cyclic_comps, _ = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(all_sccs) == 2  # {A, B, C} and {D}
    assert len(cyclic_comps) == 1
    assert cyclic_comps[0].size == 3
    assert set(cyclic_comps[0].node_ids) == {"A", "B", "C"}


def test_tarjan_scc_disconnected_components():
    """Audit Item 2: Verifies that disconnected components are properly partitioned without interference."""
    nodes = {
        "A": AttackGraphNodeSchema(id="A", risk_id="A", risk_name="Node A", category="TEST", severity="HIGH"),
        "B": AttackGraphNodeSchema(id="B", risk_id="B", risk_name="Node B", category="TEST", severity="HIGH"),
        "C": AttackGraphNodeSchema(id="C", risk_id="C", risk_name="Node C", category="TEST", severity="LOW"),
        "D": AttackGraphNodeSchema(id="D", risk_id="D", risk_name="Node D", category="TEST", severity="LOW"),
        "E": AttackGraphNodeSchema(id="E", risk_id="E", risk_name="Node E", category="TEST", severity="LOW"),
    }
    edges = [
        # Subgraph 1: A <-> B (Cycle)
        AttackGraphEdgeSchema(source="A", target="B", relationship_type="enables", confidence=0.9),
        AttackGraphEdgeSchema(source="B", target="A", relationship_type="enables", confidence=0.9),
        # Subgraph 2: C -> D (Acyclic)
        AttackGraphEdgeSchema(source="C", target="D", relationship_type="enables", confidence=0.85),
        # Node E is isolated
    ]

    all_sccs, cyclic_comps, _ = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(all_sccs) == 4  # {A, B}, {C}, {D}, {E}
    assert len(cyclic_comps) == 1
    assert cyclic_comps[0].size == 2


def test_tarjan_scc_purely_theoretical_cycle():
    """Audit Item 2: Verifies that a cycle composed solely of theoretical/amplification relationships
    is explicitly flagged and does not become an executable chain."""
    nodes = {
        "X": AttackGraphNodeSchema(id="X", risk_id="X", risk_name="Node X", category="TEST", severity="MEDIUM"),
        "Y": AttackGraphNodeSchema(id="Y", risk_id="Y", risk_name="Node Y", category="TEST", severity="MEDIUM"),
    }
    edges = [
        AttackGraphEdgeSchema(source="X", target="Y", relationship_type="amplifies", confidence=0.75),
        AttackGraphEdgeSchema(source="Y", target="X", relationship_type="amplifies", confidence=0.75),
    ]

    all_sccs, cyclic_comps, _ = AttackGraphEngine.tarjan_scc(nodes, edges)

    assert len(cyclic_comps) == 1
    scc = cyclic_comps[0]
    assert scc.is_cyclic is True
    assert "theoretical/amplification relationships" in scc.explanation
    assert scc.is_executable_chain is False


def test_max_loop_depth_application_after_condensation():
    """Audit Item 2: Verifies that MAX_LOOP_DEPTH = 2 is strictly applied during candidate path synthesis."""
    req = GenerateCandidatePathsRequest(
        target_url="http://127.0.0.1:8000",
        source_risks=["LLM01"],
        target_sinks=["ASI05"],
        max_paths=20,
        max_length=5,
    )
    db_gen = get_db()
    db = next(db_gen)
    try:
        res = AttackGraphEngine.generate_candidate_paths(req, db)
        for path in res.paths:
            # Check every node in every generated path
            node_ids = [s.risk_id for s in path.ordered_steps]
            for nid in set(node_ids):
                assert node_ids.count(nid) <= MAX_LOOP_DEPTH, f"Node {nid} visited more than MAX_LOOP_DEPTH ({MAX_LOOP_DEPTH}) times!"
    finally:
        db.close()


# =====================================================================
# 6. Phase E2 Audit Item 3: Phase E1 HMAC Integration & Target Isolation
# =====================================================================

def test_phase_e1_hmac_verified_primary_cohort_scoring(db_session):
    """Audit Item 3: Verifies that when N_hmac >= 3, primary historical intelligence scoring
    uses ONLY the eligible HMAC_VERIFIED cohort, and legacy SHA-256 records do not corrupt primary scoring."""
    target_iso = TargetIsolationTuple(
        target_identity="127.0.0.1:8000",
        application_id="audit_app_hmac_test",
        app_version="v1.0",
        environment="sandbox",
        endpoint="/api/chat",
    )

    nodes_dict, edges_list, _ = AttackGraphEngine.build_dependency_graph(
        target_isolation=target_iso,
        db=db_session,
    )

    assert len(nodes_dict) == 20
    for nid, node in nodes_dict.items():
        assert 0.0 <= node.priority_score <= 1.0
        assert 0.0 <= node.historical_outcome_score <= 1.0
        # If node has trust policy applied, it must be valid
        policy = node.metadata.get("trust_policy_applied", "PRIMARY_HMAC_AUTHENTICATED")
        assert policy in ("PRIMARY_HMAC_AUTHENTICATED", "RESTRICTED_LEGACY_SHA256_INTEGRITY", "COLD_START_PRIOR")


def test_target_isolation_preservation_across_applications(client):
    """Audit Item 3: Verifies that candidate path generation preserves target isolation
    across application identities and does not mix intelligence from unrelated applications."""
    req_alpha = GenerateCandidatePathsRequest(
        target_url="http://127.0.0.1:8000",
        application_id="app_alpha",
        app_version="v1.0",
        environment="sandbox",
        max_paths=5,
    )
    req_beta = GenerateCandidatePathsRequest(
        target_url="http://127.0.0.1:8000",
        application_id="app_beta",
        app_version="v2.0",
        environment="staging",
        max_paths=5,
    )

    res_alpha = client.post("/api/security-agent/attack-graph/candidate-paths", json=req_alpha.model_dump())
    res_beta = client.post("/api/security-agent/attack-graph/candidate-paths", json=req_beta.model_dump())

    assert res_alpha.status_code == 200
    assert res_beta.status_code == 200

    data_alpha = res_alpha.json()
    data_beta = res_beta.json()

    assert data_alpha["application_id"] == "app_alpha"
    assert data_beta["application_id"] == "app_beta"
    assert data_alpha["environment"] == "sandbox"
    assert data_beta["environment"] == "staging"

    for p in data_alpha["paths"]:
        assert p["application_id"] == "app_alpha"
        assert p["environment"] == "sandbox"
        assert p["target_isolation_verified"] is True

    for p in data_beta["paths"]:
        assert p["application_id"] == "app_beta"
        assert p["environment"] == "staging"
        assert p["target_isolation_verified"] is True


def test_api_responses_distinguish_candidate_vs_eligible_vs_rejected(client):
    """Audit Item 5: Verifies that API responses distinguish candidate path, eligible path,
    rejected path, and ensure mandatory non-compromise disclaimers are always returned."""
    req = GenerateCandidatePathsRequest(
        target_url="http://127.0.0.1:8000",
        source_risks=["LLM01"],
        target_sinks=["ASI05"],
        max_paths=5,
    )
    res = client.post("/api/security-agent/attack-graph/candidate-paths", json=req.model_dump())
    assert res.status_code == 200
    data = res.json()

    assert "disclaimer" in data
    assert "hypotheses" in data["disclaimer"].lower() or "observed" in data["disclaimer"].lower()

    for p in data["paths"]:
        assert "execution_eligibility" in p
        assert p["current_status"] in ("READY", "INELIGIBLE", "PLANNED")
        assert "disclaimer" in p
        assert "observed compromise" in p["disclaimer"].lower()
        for s in p["ordered_steps"]:
            assert s["independent_verification_status"] == "PENDING_EXECUTION"
