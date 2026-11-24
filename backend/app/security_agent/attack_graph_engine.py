"""Advanced Attack Graph Planning Engine (Phase E2).

Implements security dependency graph modeling, Tarjan's Strongly Connected
Components (SCC) cycle detection, graph condensation into DAG, and bounded
candidate attack path planning.

Strictly distinguishes theoretical risk dependencies from observed vulnerabilities,
ensuring proposed attack paths are never presented as observed compromises.
"""

from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.security_agent.correlation_engine import ALL_OWASP_RISKS, RISK_RELATIONSHIPS_CATALOG
from app.security_agent.crypto import EvidenceTrustLevel
from app.security_agent.intelligence_engine import (
    COLD_START_BASE_PRIORS,
    DynamicSecurityIntelligenceEngine,
    SEVERITY_WEIGHTS,
)
from app.security_agent.schemas import (
    AttackGraphAnalysisResponse,
    AttackGraphEdgeSchema,
    AttackGraphNodeSchema,
    CandidateAttackPathSchema,
    CandidateAttackPathStepSchema,
    CondensedDagEdgeSchema,
    GenerateCandidatePathsRequest,
    GenerateCandidatePathsResponse,
    StronglyConnectedComponentSchema,
    TargetIsolationTuple,
)
from app.security_agent.scope_validator import ScopeValidator

logger = logging.getLogger(__name__)

# Mandatory Phase E2 Resource Limits
MAX_NODES: int = 100
MAX_EDGES: int = 250
MAX_CANDIDATE_PATHS: int = 20
MAX_PATH_LENGTH: int = 5
MAX_LOOP_DEPTH: int = 2
MAX_HTTP_REQUESTS_PER_CHAIN: int = 15
MAX_ANALYSIS_TIME_MS: float = 5000.0  # 5.0 seconds timeout


class RelationshipSemantic:
    """Semantic classifications for graph edge relationships."""
    STRUCTURAL_PREREQUISITE = "STRUCTURAL_PREREQUISITE"
    CAPABILITY_ENABLING = "CAPABILITY_ENABLING"
    IMPACT_AMPLIFICATION = "IMPACT_AMPLIFICATION"
    EXFILTRATION_VECTOR = "EXFILTRATION_VECTOR"
    THEORETICAL_CORRELATION = "THEORETICAL_CORRELATION"


def classify_relationship_semantic(rel_type: Optional[str]) -> str:
    """Maps a relationship string into its formal semantic classification."""
    r = (rel_type or "").lower().strip()
    if r == "prerequisite_for":
        return RelationshipSemantic.STRUCTURAL_PREREQUISITE
    elif r in ("enables", "escalates_to"):
        return RelationshipSemantic.CAPABILITY_ENABLING
    elif r == "amplifies":
        return RelationshipSemantic.IMPACT_AMPLIFICATION
    elif r == "exfiltrates_via":
        return RelationshipSemantic.EXFILTRATION_VECTOR
    return RelationshipSemantic.THEORETICAL_CORRELATION

# Common Entry Vectors & Impact Sinks across OWASP LLM & Agentic Risks
ENTRY_VECTOR_RISKS: Set[str] = {
    "LLM01",  # Prompt Injection
    "LLM03",  # Supply Chain
    "LLM04",  # Data & Model Poisoning
    "LLM08",  # Vector / Embedding Weaknesses
    "LLM10",  # Unbounded Consumption
    "ASI04",  # Multi-Agent Supply Chain
    "ASI06",  # Memory & Context Poisoning
    "ASI07",  # Insecure Inter-Agent Comm
    "ASI09",  # Human-in-the-Loop Bypass
    "ASI10",  # Inadequate Logging
}

IMPACT_SINK_RISKS: Set[str] = {
    "ASI05",  # Unexpected Code Execution
    "LLM02",  # Sensitive Info Disclosure
    "ASI02",  # Tool Misuse & Sandbox Traversal
    "ASI03",  # Identity & Privilege Abuse
    "LLM06",  # Excessive Agency
    "ASI01",  # Agent Goal Hijack
}


class AttackGraphEngine:
    """Advanced security dependency graph and bounded attack path planning engine."""

    # In-memory store for generated candidate attack chains
    _chains_cache: Dict[str, CandidateAttackPathSchema] = {}

    @classmethod
    def get_candidate_chain(cls, chain_id: str) -> Optional[CandidateAttackPathSchema]:
        """Retrieves a cached candidate attack chain by ID."""
        return cls._chains_cache.get(chain_id)

    @classmethod
    def build_dependency_graph(
        cls,
        target_isolation: Optional[TargetIsolationTuple] = None,
        db: Optional[Session] = None,
        custom_nodes: Optional[List[Dict[str, Any]]] = None,
        custom_edges: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[Dict[str, AttackGraphNodeSchema], List[AttackGraphEdgeSchema], List[str]]:
        """Constructs the security dependency graph with metadata, confidences, and E1 intelligence.

        Enforces MAX_NODES (100) and MAX_EDGES (250) resource bounds.
        """
        limits_reached: List[str] = []

        # 1. Build Nodes
        nodes_dict: Dict[str, AttackGraphNodeSchema] = {}

        if custom_nodes is not None:
            raw_nodes = custom_nodes[:MAX_NODES]
            if len(custom_nodes) > MAX_NODES:
                limits_reached.append(f"MAX_NODES_EXCEEDED: Capped {len(custom_nodes)} nodes to {MAX_NODES}.")
            for n in raw_nodes:
                nid = n["id"]
                nodes_dict[nid] = AttackGraphNodeSchema(
                    id=nid,
                    risk_id=n.get("risk_id", nid),
                    risk_name=n.get("risk_name", n.get("name", nid)),
                    category=n.get("category", "CUSTOM"),
                    severity=n.get("severity", "MEDIUM"),
                    endpoint=n.get("endpoint", "/api/chat"),
                    priority_score=n.get("priority_score", 0.5),
                    historical_outcome_score=n.get("historical_outcome_score", 0.5),
                    evidence_trust_level=n.get("evidence_trust_level", "HMAC_VERIFIED"),
                    is_entry_vector=n.get("is_entry_vector", False),
                    is_impact_sink=n.get("is_impact_sink", False),
                    prerequisites_satisfied=n.get("prerequisites_satisfied", False),
                    description=n.get("description", ""),
                    metadata=n.get("metadata", {}),
                )
        else:
            # Query E1 priorities if db and target_isolation are available
            e1_priorities: Dict[str, Any] = {}
            if db and target_isolation:
                try:
                    prioritized = DynamicSecurityIntelligenceEngine.prioritize_risks(
                        db=db,
                        target_isolation=target_isolation,
                    )
                    for item in prioritized:
                        e1_priorities[item.risk_id] = item
                except Exception as ex:
                    logger.warning("Could not compute E1 dynamic priorities: %s", ex)

            for risk_id, meta in list(ALL_OWASP_RISKS.items())[:MAX_NODES]:
                p_item = e1_priorities.get(risk_id)
                priority_score = p_item.priority_score if p_item else 0.50
                hist_score = p_item.component_scores.historical_outcome if p_item else COLD_START_BASE_PRIORS.get(risk_id, 0.50)
                trust_lvl = p_item.evidence_trust_level if p_item else "HMAC_VERIFIED"
                endpoint = p_item.endpoint if p_item else "/api/chat"

                # Extract E1 Trust Policy details
                trust_policy = getattr(p_item, "trust_policy_applied", "COLD_START_PRIOR" if not p_item else "PRIMARY_HMAC_AUTHENTICATED")
                legacy_contrib = getattr(p_item, "legacy_evidence_contribution", 0.0)

                nodes_dict[risk_id] = AttackGraphNodeSchema(
                    id=risk_id,
                    risk_id=risk_id,
                    risk_name=meta["name"],
                    category=meta["category"],
                    severity=meta["severity"],
                    endpoint=endpoint,
                    priority_score=priority_score,
                    historical_outcome_score=hist_score,
                    evidence_trust_level=trust_lvl,
                    is_entry_vector=(risk_id in ENTRY_VECTOR_RISKS),
                    is_impact_sink=(risk_id in IMPACT_SINK_RISKS),
                    prerequisites_satisfied=True if (risk_id in ENTRY_VECTOR_RISKS) else False,
                    description=meta["desc"],
                    metadata={
                        "catalog_source": "OWASP_2025_CORRELATION",
                        "trust_policy_applied": trust_policy,
                        "legacy_evidence_contribution": legacy_contrib,
                    },
                )

        # 2. Build Directed Edges
        edges: List[AttackGraphEdgeSchema] = []
        raw_edges = custom_edges if custom_edges is not None else RISK_RELATIONSHIPS_CATALOG
        if len(raw_edges) > MAX_EDGES:
            limits_reached.append(f"MAX_EDGES_EXCEEDED: Capped {len(raw_edges)} edges to {MAX_EDGES}.")
            raw_edges = raw_edges[:MAX_EDGES]

        for rel in raw_edges:
            src = rel.get("source") or rel.get("source_risk")
            tgt = rel.get("target") or rel.get("related") or rel.get("related_risk")
            if src and tgt and (src in nodes_dict) and (tgt in nodes_dict):
                edges.append(
                    AttackGraphEdgeSchema(
                        source=src,
                        target=tgt,
                        relationship_type=rel.get("type") or rel.get("relationship_type", "enables"),
                        confidence=float(rel.get("confidence", 0.85)),
                        prerequisite=rel.get("prerequisite"),
                        rationale=rel.get("rationale", ""),
                        is_cyclic=False,
                        evidence_status="THEORETICAL",
                    )
                )

        return nodes_dict, edges, limits_reached

    @classmethod
    def tarjan_scc(
        cls,
        nodes: Dict[str, Any],
        edges: List[AttackGraphEdgeSchema],
    ) -> Tuple[List[StronglyConnectedComponentSchema], List[StronglyConnectedComponentSchema], Dict[str, str]]:
        """Executes Tarjan's Strongly Connected Components algorithm.

        Identifies all strongly connected components, detects cyclic dependencies,
        and provides human-readable cycle explainability.

        Returns:
            - all_sccs: List of all SCC components
            - cyclic_components: List of components that contain cycles
            - node_to_scc_map: Mapping from node_id -> component_id
        """
        adj: Dict[str, List[str]] = {nid: [] for nid in nodes}
        has_self_loop: Set[str] = set()

        for edge in edges:
            if edge.source in adj and edge.target in adj:
                adj[edge.source].append(edge.target)
                if edge.source == edge.target:
                    has_self_loop.add(edge.source)

        index = 0
        indices: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        on_stack: Set[str] = set()
        stack: List[str] = []
        scc_list: List[List[str]] = []

        def strongconnect(v: str):
            nonlocal index
            indices[v] = index
            lowlink[v] = index
            index += 1
            stack.append(v)
            on_stack.add(v)

            for w in adj.get(v, []):
                if w not in indices:
                    # Successor w has not yet been visited; recurse on it
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif w in on_stack:
                    # Successor w is in stack and hence in the current SCC
                    lowlink[v] = min(lowlink[v], indices[w])

            # If v is a root node, pop the stack and generate an SCC
            if lowlink[v] == indices[v]:
                component: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack.remove(w)
                    component.append(w)
                    if w == v:
                        break
                scc_list.append(component)

        for node_id in nodes:
            if node_id not in indices:
                strongconnect(node_id)

        all_sccs: List[StronglyConnectedComponentSchema] = []
        cyclic_components: List[StronglyConnectedComponentSchema] = []
        node_to_scc_map: Dict[str, str] = {}

        for idx, comp in enumerate(scc_list):
            cid = f"SCC_{idx+1:02d}"
            comp_nodes = sorted(comp)
            for nid in comp_nodes:
                node_to_scc_map[nid] = cid

            # A component is cyclic if it has > 1 node, or has 1 node with a self-loop
            is_cyclic = len(comp_nodes) > 1 or (len(comp_nodes) == 1 and comp_nodes[0] in has_self_loop)

            # Collect internal edges and relationships within this component
            comp_nodes_set = set(comp_nodes)
            internal_edges = [e for e in edges if e.source in comp_nodes_set and e.target in comp_nodes_set]
            internal_rels = sorted(list(set(e.relationship_type for e in internal_edges)))

            # Check if component contains only theoretical/amplification relationships
            is_purely_theoretical = False
            if is_cyclic and internal_rels:
                theoretical_types = {"amplifies", "theoretical", "correlation", "hypothesis"}
                is_purely_theoretical = all(r.lower() in theoretical_types for r in internal_rels)

            if is_cyclic:
                if len(comp_nodes) == 1:
                    expl = f"Self-loop cycle detected on node '{comp_nodes[0]}': node depends directly on its own execution outcome."
                else:
                    nodes_str = ", ".join(f"'{n}'" for n in comp_nodes)
                    expl = (
                        f"Mutual cyclic dependency feedback loop detected among [{nodes_str}]: "
                        f"nodes mutually enable or escalate to one another in a circular path. "
                        f"Requires bounded condensation to prevent infinite traversal."
                    )
                if is_purely_theoretical:
                    expl += " Note: Component contains only theoretical/amplification relationships without verified execution chains."
            else:
                expl = f"Acyclic singleton component containing node '{comp_nodes[0]}'."

            scc_schema = StronglyConnectedComponentSchema(
                component_id=cid,
                node_ids=comp_nodes,
                size=len(comp_nodes),
                is_cyclic=is_cyclic,
                explanation=expl,
                internal_relationships=internal_rels,
                is_executable_chain=False,  # SCCs do not automatically become executable chains
                independent_verification_required=True,  # Each node requires independent verification
            )
            all_sccs.append(scc_schema)
            if is_cyclic:
                cyclic_components.append(scc_schema)

        # Mark cyclic edges
        for edge in edges:
            src_scc = node_to_scc_map.get(edge.source)
            tgt_scc = node_to_scc_map.get(edge.target)
            if src_scc and tgt_scc and src_scc == tgt_scc:
                # If they belong to the same multi-node SCC or self-loop
                matching_scc = next((s for s in cyclic_components if s.component_id == src_scc), None)
                if matching_scc:
                    edge.is_cyclic = True

        return all_sccs, cyclic_components, node_to_scc_map

    @classmethod
    def condense_to_dag(
        cls,
        nodes: Dict[str, AttackGraphNodeSchema],
        edges: List[AttackGraphEdgeSchema],
        node_to_scc_map: Dict[str, str],
    ) -> List[CondensedDagEdgeSchema]:
        """Condenses strongly connected components into a Directed Acyclic Graph (DAG).

        Guarantees zero cyclic dependencies across condensed component super-nodes.
        """
        dag_edge_dict: Dict[Tuple[str, str], List[str]] = {}

        for edge in edges:
            src_comp = node_to_scc_map.get(edge.source)
            tgt_comp = node_to_scc_map.get(edge.target)

            if src_comp and tgt_comp and src_comp != tgt_comp:
                pair = (src_comp, tgt_comp)
                if pair not in dag_edge_dict:
                    dag_edge_dict[pair] = []
                dag_edge_dict[pair].append(edge.relationship_type)

        condensed_edges: List[CondensedDagEdgeSchema] = []
        for (src_c, tgt_c), rels in dag_edge_dict.items():
            condensed_edges.append(
                CondensedDagEdgeSchema(
                    source_component=src_c,
                    target_component=tgt_c,
                    edge_count=len(rels),
                    relationships=list(set(rels)),
                )
            )

        condensed_edges.sort(key=lambda x: (x.source_component, x.target_component))
        return condensed_edges

    @classmethod
    def analyze_graph(
        cls,
        target_isolation: Optional[TargetIsolationTuple] = None,
        db: Optional[Session] = None,
        custom_nodes: Optional[List[Dict[str, Any]]] = None,
        custom_edges: Optional[List[Dict[str, Any]]] = None,
    ) -> AttackGraphAnalysisResponse:
        """Executes full graph analysis: dependency mapping, Tarjan SCC, and DAG condensation.

        Enforces MAX_ANALYSIS_TIME_MS (5000 ms) execution timeout.
        """
        start_time = time.perf_counter()
        limits_reached: List[str] = []

        # 1. Build Graph
        nodes_dict, edges_list, build_limits = cls.build_dependency_graph(
            target_isolation=target_isolation,
            db=db,
            custom_nodes=custom_nodes,
            custom_edges=custom_edges,
        )
        limits_reached.extend(build_limits)

        # 2. Tarjan SCC Algorithm
        all_sccs, cyclic_comps, node_to_scc_map = cls.tarjan_scc(nodes_dict, edges_list)

        # 3. Condensation into DAG
        condensed_dag_edges = cls.condense_to_dag(nodes_dict, edges_list, node_to_scc_map)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        if elapsed_ms > MAX_ANALYSIS_TIME_MS:
            limits_reached.append(f"ANALYSIS_TIMEOUT_EXCEEDED: Completed in {elapsed_ms}ms (> {MAX_ANALYSIS_TIME_MS}ms).")

        return AttackGraphAnalysisResponse(
            nodes=list(nodes_dict.values()),
            edges=edges_list,
            sccs=all_sccs,
            cyclic_components=cyclic_comps,
            condensed_dag_edges=condensed_dag_edges,
            total_nodes=len(nodes_dict),
            total_edges=len(edges_list),
            total_sccs=len(all_sccs),
            cyclic_count=len(cyclic_comps),
            analysis_duration_ms=elapsed_ms,
            resource_limits_reached=limits_reached,
        )

    @classmethod
    def generate_candidate_paths(
        cls,
        request: GenerateCandidatePathsRequest,
        db: Session,
    ) -> GenerateCandidatePathsResponse:
        """Generates bounded, explainable candidate attack paths using the condensed DAG.

        Enforces limits:
        - Max candidate paths: 20
        - Max path length: 5
        - Max loop depth: 2
        - Max analysis duration: 5,000 ms
        - Path deduplication
        - E1 PriorityScore integration
        - Independent step evaluation
        """
        start_time = time.perf_counter()
        limits_reached: List[str] = []

        # 1. Target Scope Validation
        scope = ScopeValidator.resolve_and_validate_target(
            raw_url=request.target_url,
            user_confirmed_authorization=request.user_confirmed_authorization,
        )
        if not scope.is_in_scope:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target URL is unauthorized or out of scope: {scope.reason}",
            )

        norm_target_id = DynamicSecurityIntelligenceEngine.normalize_target_identity(scope.normalized_url)
        target_isolation = TargetIsolationTuple(
            target_identity=norm_target_id,
            application_id=request.application_id,
            app_version=request.app_version,
            environment=request.environment,
            endpoint=request.endpoint,
        )

        # 2. Build Graph with E1 Priorities
        nodes_dict, edges_list, build_limits = cls.build_dependency_graph(
            target_isolation=target_isolation,
            db=db,
        )
        limits_reached.extend(build_limits)

        # 3. Detect Cycles & Condense
        all_sccs, cyclic_comps, node_to_scc_map = cls.tarjan_scc(nodes_dict, edges_list)

        # 4. Adjacency Structure
        adj: Dict[str, List[AttackGraphEdgeSchema]] = {nid: [] for nid in nodes_dict}
        for e in edges_list:
            if e.source in adj:
                adj[e.source].append(e)

        # Determine Entry Nodes & Target Sinks
        entry_nodes: List[str] = []
        if request.source_risks:
            entry_nodes = [r.upper().strip() for r in request.source_risks if r.upper().strip() in nodes_dict]
        if not entry_nodes:
            entry_nodes = [nid for nid, n in nodes_dict.items() if n.is_entry_vector]

        sink_nodes: Set[str] = set()
        if request.target_sinks:
            sink_nodes = {r.upper().strip() for r in request.target_sinks if r.upper().strip() in nodes_dict}
        if not sink_nodes:
            sink_nodes = {nid for nid, n in nodes_dict.items() if n.is_impact_sink}

        candidate_paths: List[CandidateAttackPathSchema] = []
        visited_signatures: Set[Tuple[str, ...]] = set()

        max_paths_cap = min(request.max_paths, MAX_CANDIDATE_PATHS)
        max_length_cap = min(request.max_length, MAX_PATH_LENGTH)

        # 5. Bounded DFS Traversal over Graph
        def dfs_search(current: str, path_nodes: List[str], path_edges: List[AttackGraphEdgeSchema]):
            nonlocal limits_reached
            if len(candidate_paths) >= max_paths_cap:
                return

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            if elapsed_ms > MAX_ANALYSIS_TIME_MS:
                if "ANALYSIS_TIMEOUT_EXCEEDED" not in limits_reached:
                    limits_reached.append(f"ANALYSIS_TIMEOUT_EXCEEDED: Analysis time exceeded {MAX_ANALYSIS_TIME_MS}ms.")
                return

            # Check if destination reached and path length >= 2
            if len(path_nodes) >= 2 and current in sink_nodes:
                sig = tuple(path_nodes)
                if sig not in visited_signatures:
                    visited_signatures.add(sig)

                    # Build candidate path schema
                    path_schema = cls._build_candidate_path(
                        path_nodes=path_nodes,
                        path_edges=path_edges,
                        nodes_dict=nodes_dict,
                        target_isolation=target_isolation,
                    )
                    candidate_paths.append(path_schema)
                    cls._chains_cache[path_schema.chain_id] = path_schema

                    if len(candidate_paths) >= max_paths_cap:
                        if f"MAX_CANDIDATE_PATHS_REACHED ({max_paths_cap})" not in limits_reached:
                            limits_reached.append(f"MAX_CANDIDATE_PATHS_REACHED: Generated maximum {max_paths_cap} paths.")
                        return

            # Terminate if max path length reached
            if len(path_nodes) >= max_length_cap:
                return

            for edge in adj.get(current, []):
                nxt = edge.target
                # Loop depth check within path
                visit_count = path_nodes.count(nxt)
                if visit_count >= MAX_LOOP_DEPTH:
                    if f"LOOP_DEPTH_LIMIT_REACHED ({MAX_LOOP_DEPTH})" not in limits_reached:
                        limits_reached.append(f"LOOP_DEPTH_LIMIT_REACHED: Loop depth reached {MAX_LOOP_DEPTH} cycles for node '{nxt}'.")
                    continue  # Loop depth limit reached to prevent infinite cycle spinning

                dfs_search(nxt, path_nodes + [nxt], path_edges + [edge])

        for start_node in entry_nodes:
            if len(candidate_paths) >= max_paths_cap:
                break
            dfs_search(start_node, [start_node], [])

        # Sort paths by cumulative priority score descending, then cumulative confidence
        candidate_paths.sort(
            key=lambda p: (p.cumulative_priority_score, p.cumulative_confidence, -p.path_length),
            reverse=True,
        )

        elapsed_total_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        return GenerateCandidatePathsResponse(
            paths=candidate_paths,
            total_candidate_paths=len(candidate_paths),
            target_identity=norm_target_id,
            application_id=request.application_id,
            environment=request.environment,
            analysis_duration_ms=elapsed_total_ms,
            resource_limits_reached=limits_reached,
            disclaimer="Candidate attack paths represent planning hypotheses and must never be interpreted as observed compromises.",
        )

    @classmethod
    def _build_candidate_path(
        cls,
        path_nodes: List[str],
        path_edges: List[AttackGraphEdgeSchema],
        nodes_dict: Dict[str, AttackGraphNodeSchema],
        target_isolation: TargetIsolationTuple,
    ) -> CandidateAttackPathSchema:
        """Constructs an explainable CandidateAttackPathSchema from traversed nodes and edges."""
        chain_id = f"chain_{uuid.uuid4().hex[:12]}"
        path_id = f"path_{uuid.uuid4().hex[:8]}"
        src_risk = path_nodes[0]
        dst_risk = path_nodes[-1]

        steps: List[CandidateAttackPathStepSchema] = []
        conf_product = 1.0
        priority_sum = 0.0

        rel_types: List[str] = []
        hard_prereqs: List[str] = []
        satisfied_prereqs: List[str] = []
        unsatisfied_prereqs: List[str] = []
        theoretical_deps: List[str] = []
        rejection_reasons: List[str] = []

        for idx, nid in enumerate(path_nodes):
            node = nodes_dict[nid]
            edge_from_prior = path_edges[idx - 1] if idx > 0 else None

            rel_type = edge_from_prior.relationship_type if edge_from_prior else None
            edge_conf = edge_from_prior.confidence if edge_from_prior else 1.0
            prereq = edge_from_prior.prerequisite if edge_from_prior else None

            rel_semantic = classify_relationship_semantic(rel_type) if rel_type else None
            is_hard = False
            prereq_satisfied = False

            if edge_from_prior:
                conf_product *= edge_conf
                rel_types.append(rel_type)

                if rel_semantic == RelationshipSemantic.STRUCTURAL_PREREQUISITE:
                    is_hard = True
                    prereq_label = prereq or f"Prerequisite {path_nodes[idx - 1]} required for {nid}"
                    hard_prereqs.append(prereq_label)

                    # Check prerequisite satisfaction:
                    # An explicit check:
                    # - If prereq explicitly contains "unsatisfied", "unmet", "missing", or "failed", or
                    # - If predecessor node has prerequisites_satisfied=False and is not the entry point
                    if (prereq and any(k in prereq.lower() for k in ("unsatisfied", "unmet", "failed", "blocked", "missing"))) or (not nodes_dict[path_nodes[idx - 1]].prerequisites_satisfied and idx - 1 > 0):
                        unsatisfied_prereqs.append(prereq_label)
                        rejection_reasons.append(
                            f"Unsatisfied hard prerequisite on step {idx + 1} ({nid}): '{prereq_label}'"
                        )
                    else:
                        prereq_satisfied = True
                        satisfied_prereqs.append(prereq_label)

                elif rel_semantic == RelationshipSemantic.IMPACT_AMPLIFICATION:
                    # Impact-amplification relationships NEVER establish a hard prerequisite
                    is_hard = False
                    prereq_satisfied = True
                    theoretical_deps.append(f"{path_nodes[idx - 1]} amplifies {nid} (impact amplification)")

                elif rel_semantic == RelationshipSemantic.CAPABILITY_ENABLING:
                    is_hard = False
                    prereq_satisfied = True
                    if prereq:
                        theoretical_deps.append(f"Capability enablement: {prereq}")

                elif rel_semantic == RelationshipSemantic.EXFILTRATION_VECTOR:
                    is_hard = False
                    prereq_satisfied = True
                    theoretical_deps.append(f"Exfiltration vector: {path_nodes[idx - 1]} -> {nid}")

                else:
                    is_hard = False
                    prereq_satisfied = True
                    theoretical_deps.append(f"Theoretical relationship: {path_nodes[idx - 1]} -> {nid}")
            else:
                # Step 1 (Entry vector)
                prereq_satisfied = True

            priority_sum += node.priority_score

            steps.append(
                CandidateAttackPathStepSchema(
                    step_number=idx + 1,
                    risk_id=nid,
                    risk_name=node.risk_name,
                    category=node.category,
                    severity=node.severity,
                    endpoint=node.endpoint,
                    relationship_from_prior=rel_type,
                    relationship_semantic=rel_semantic,
                    confidence=round(edge_conf, 4),
                    prerequisite=prereq,
                    is_hard_prerequisite=is_hard,
                    prerequisite_satisfied=prereq_satisfied,
                    step_priority_score=node.priority_score,
                    independent_verification_status="PENDING_EXECUTION",
                )
            )

        k = len(path_nodes)
        cum_priority = round(min(1.0, max(0.0, (priority_sum / float(k)) * (conf_product ** 0.5))), 4)
        cum_confidence = round(min(1.0, max(0.0, conf_product)), 4)

        # Eligibility evaluation:
        # A path is eligible for bounded execution testing if:
        # - Target is validated and in scope
        # - Source risk is an entry vector
        # - Path length <= MAX_PATH_LENGTH (5)
        # - Loop depth does not exceed MAX_LOOP_DEPTH (2)
        # - Zero unsatisfied hard prerequisites
        eligibility = True

        if len(path_nodes) > MAX_PATH_LENGTH:
            eligibility = False
            rejection_reasons.append(f"Path length ({len(path_nodes)}) exceeds maximum allowed ({MAX_PATH_LENGTH}).")

        for nid in set(path_nodes):
            if path_nodes.count(nid) > MAX_LOOP_DEPTH:
                eligibility = False
                rejection_reasons.append(f"Loop depth on node '{nid}' ({path_nodes.count(nid)}) exceeds safety bound ({MAX_LOOP_DEPTH}).")

        if unsatisfied_prereqs:
            eligibility = False

        rejection_reason = rejection_reasons[0] if rejection_reasons else None

        rel_types_str = " -> ".join(e.relationship_type for e in path_edges) if path_edges else "direct"
        rationale = (
            f"Candidate attack progression from entry vector {src_risk} ({nodes_dict[src_risk].risk_name}) "
            f"to critical impact sink {dst_risk} ({nodes_dict[dst_risk].risk_name}) "
            f"via relationships [{rel_types_str}]. "
            f"Cumulative priority score: {cum_priority:.4f}, confidence: {cum_confidence:.4f}. "
            f"Hard prerequisites: {len(hard_prereqs)} ({len(satisfied_prereqs)} satisfied, {len(unsatisfied_prereqs)} unsatisfied). "
            f"Each step requires independent empirical verification."
        )

        resource_limits = {
            "max_path_length": MAX_PATH_LENGTH,
            "max_loop_depth": MAX_LOOP_DEPTH,
            "max_http_requests_per_chain": MAX_HTTP_REQUESTS_PER_CHAIN,
            "analysis_timeout_ms": MAX_ANALYSIS_TIME_MS,
        }

        # Determine primary trust level from source node or steps
        src_trust = nodes_dict[src_risk].evidence_trust_level if src_risk in nodes_dict else "HMAC_VERIFIED"
        src_policy = nodes_dict[src_risk].metadata.get("trust_policy_applied", "PRIMARY_HMAC_AUTHENTICATED") if src_risk in nodes_dict else "PRIMARY_HMAC_AUTHENTICATED"

        return CandidateAttackPathSchema(
            path_id=path_id,
            chain_id=chain_id,
            target_identity=target_isolation.target_identity,
            application_id=target_isolation.application_id,
            environment=target_isolation.environment,
            source_risk=src_risk,
            destination_risk=dst_risk,
            path_length=k,
            cumulative_priority_score=cum_priority,
            cumulative_confidence=cum_confidence,
            ordered_steps=steps,
            relationship_types=rel_types,
            hard_prerequisites=hard_prereqs,
            satisfied_prerequisites=satisfied_prereqs,
            unsatisfied_prerequisites=unsatisfied_prereqs,
            theoretical_dependencies=theoretical_deps,
            execution_eligibility=eligibility,
            rejection_reasons=rejection_reasons,
            rejection_reason=rejection_reason,
            selection_rationale=rationale,
            evidence_trust_level=src_trust,
            trust_policy_applied=src_policy,
            target_isolation_verified=True,
            resource_limits=resource_limits,
            current_status="READY" if eligibility else "INELIGIBLE",
            disclaimer="Proposed candidate attack path. Must never be presented as an observed compromise. Each step requires independent verification.",
        )
