"""OWASP Risk Correlation Engine (Phase D).

Maps dependencies, prerequisite relationships, and attack progression pathways
across the full spectrum of 10 OWASP LLM Risks and 10 OWASP Agentic AI Risks.

Strictly preserves the distinction between a theoretical correlation hypothesis
and an independently verified vulnerability finding.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from app.security_agent.schemas import (
    RiskCorrelationGraphSchema,
    RiskRelationshipSchema,
)

# Comprehensive OWASP Catalog (10 LLM Risks + 10 Agentic AI Risks)
ALL_OWASP_RISKS: Dict[str, Dict[str, str]] = {
    # 10 OWASP LLM Risks
    "LLM01": {"name": "Prompt Injection", "category": "OWASP_LLM", "severity": "HIGH", "desc": "Adversarial inputs manipulating model behavior, overriding system instructions or injecting secondary directives."},
    "LLM02": {"name": "Sensitive Information Disclosure", "category": "OWASP_LLM", "severity": "CRITICAL", "desc": "Eliciting confidential data, synthetic canary tokens, credentials, or proprietary intellectual property."},
    "LLM03": {"name": "Supply Chain Vulnerabilities", "category": "OWASP_LLM", "severity": "HIGH", "desc": "Compromised third-party packages, plugins, base models, or upstream dependencies."},
    "LLM04": {"name": "Data and Model Poisoning", "category": "OWASP_LLM", "severity": "CRITICAL", "desc": "Manipulating training data, fine-tuning datasets, or embedding vectors to introduce backdoors."},
    "LLM05": {"name": "Improper Output Handling", "category": "OWASP_LLM", "severity": "MEDIUM", "desc": "Generating unvalidated output containing script injection, malicious HTML, or unsanitized payloads."},
    "LLM06": {"name": "Excessive Agency", "category": "OWASP_LLM", "severity": "HIGH", "desc": "Granting damaging autonomy, unbounded tool permissions, or bypassing required human authorization."},
    "LLM07": {"name": "System Prompt Leakage", "category": "OWASP_LLM", "severity": "MEDIUM", "desc": "Extracting unrevealed system instructions, developer constraints, or hidden prompt chain metadata."},
    "LLM08": {"name": "Vector & Embedding Weaknesses", "category": "OWASP_LLM", "severity": "MEDIUM", "desc": "Poisoning or manipulating semantic embeddings and vector store context to bias retrieval."},
    "LLM09": {"name": "Misinformation & Overreliance", "category": "OWASP_LLM", "severity": "MEDIUM", "desc": "Unchecked hallucinations causing incorrect business decisions or corrupted downstream state."},
    "LLM10": {"name": "Unbounded Consumption", "category": "OWASP_LLM", "severity": "MEDIUM", "desc": "Resource exhaustion via runaway token loops, high-concurrency requests, or unbounded context expansion."},

    # 10 OWASP Agentic AI Risks
    "ASI01": {"name": "Agent Goal Hijack", "category": "OWASP_AGENTIC", "severity": "HIGH", "desc": "Subverting agent reasoning loop to abandon legitimate goals and pursue attacker-controlled objectives."},
    "ASI02": {"name": "Tool Misuse & Sandbox Traversal", "category": "OWASP_AGENTIC", "severity": "CRITICAL", "desc": "Invoking tools with unauthorized parameters, hitting forbidden endpoints, or violating sandbox limits."},
    "ASI03": {"name": "Identity & Privilege Abuse", "category": "OWASP_AGENTIC", "severity": "HIGH", "desc": "Attempting role elevation, bypassing permission managers, or performing administrative operations unauthorized."},
    "ASI04": {"name": "Multi-Agent Supply Chain", "category": "OWASP_AGENTIC", "severity": "HIGH", "desc": "Compromised collaborative subagents or third-party agent service integrations."},
    "ASI05": {"name": "Unexpected Code Execution", "category": "OWASP_AGENTIC", "severity": "CRITICAL", "desc": "Tricking the agent or backend into executing arbitrary operating system commands or arbitrary code."},
    "ASI06": {"name": "Memory & Context Poisoning", "category": "OWASP_AGENTIC", "severity": "HIGH", "desc": "Corrupting long-term memory, session state, or synthetic documents to skew subsequent agent judgments."},
    "ASI07": {"name": "Insecure Inter-Agent Communication", "category": "OWASP_AGENTIC", "severity": "HIGH", "desc": "Unauthenticated or unencrypted communication channels between collaborating agents."},
    "ASI08": {"name": "Cascading Failures & Goal Drift", "category": "OWASP_AGENTIC", "severity": "MEDIUM", "desc": "Uncontrolled error propagation across multi-agent pipelines causing emergent system instability."},
    "ASI09": {"name": "Human-in-the-Loop Bypass", "category": "OWASP_AGENTIC", "severity": "HIGH", "desc": "Evasion of mandatory operator approvals for destructive, external, or high-privilege actions."},
    "ASI10": {"name": "Inadequate Logging & Auditing", "category": "OWASP_AGENTIC", "severity": "LOW", "desc": "Lack of tamper-evident audit logging for agent actions, tool calls, and model decisions."},
}

# Empirical Relationship Graph Definitions
RISK_RELATIONSHIPS_CATALOG: List[Dict[str, Any]] = [
    {
        "source": "LLM01",
        "related": "ASI01",
        "type": "enables",
        "prerequisite": "Direct or indirect prompt injection payload bypasses initial boundary fence",
        "rationale": "Adversarial prompt injection is the primary entry vector enabling an attacker to rewrite the agent reasoning loop and redirect its mission.",
        "confidence": 0.95,
    },
    {
        "source": "ASI01",
        "related": "ASI02",
        "type": "escalates_to",
        "prerequisite": "Agent objective redirected to attacker task",
        "rationale": "Once the core mission is hijacked, the agent invokes available tool utilities (HTTP, filesystem, email) with malicious parameters.",
        "confidence": 0.90,
    },
    {
        "source": "ASI02",
        "related": "LLM02",
        "type": "exfiltrates_via",
        "prerequisite": "Agent accesses filesystem tool or unapproved outbound HTTP client",
        "rationale": "Misused tools allow the agent to read internal sensitive files or exfiltrate synthetic canary credentials to external servers.",
        "confidence": 0.88,
    },
    {
        "source": "ASI02",
        "related": "ASI05",
        "type": "amplifies",
        "prerequisite": "Tool parameters lack strict shell/command injection sanitization",
        "rationale": "If tool arguments allow shell metacharacters or arbitrary script paths, tool misuse escalates to unexpected operating system code execution.",
        "confidence": 0.92,
    },
    {
        "source": "LLM01",
        "related": "LLM07",
        "type": "enables",
        "prerequisite": "Instruction hierarchy fails to protect developer instructions",
        "rationale": "Prompt framing attacks override the delimiter boundary to coerce the model into leaking its hidden system instructions.",
        "confidence": 0.85,
    },
    {
        "source": "ASI06",
        "related": "ASI01",
        "type": "prerequisite_for",
        "prerequisite": "Attacker injects poisoned document into knowledge base or long-term session memory",
        "rationale": "Poisoned context or memory entries persistently alter agent judgment on subsequent turns, triggering goal redirection.",
        "confidence": 0.86,
    },
    {
        "source": "ASI09",
        "related": "LLM06",
        "type": "amplifies",
        "prerequisite": "Approval lifecycle checks fail or are skipped for sensitive tools",
        "rationale": "Bypassing the human approval gate grants the agent excessive unchecked agency to perform irreversible actions autonomously.",
        "confidence": 0.91,
    },
    {
        "source": "ASI07",
        "related": "ASI03",
        "type": "enables",
        "prerequisite": "Subagent messages lack mutual authentication or signature verification",
        "rationale": "Insecure inter-agent channels allow malicious or rogue agents to impersonate high-privilege coordinators and abuse roles.",
        "confidence": 0.84,
    },
    {
        "source": "LLM04",
        "related": "ASI08",
        "type": "amplifies",
        "prerequisite": "Poisoned training dataset or embedding vectors injected into agent pipeline",
        "rationale": "Poisoned semantic models trigger cascading reasoning failures and systematic drift across cooperating agents.",
        "confidence": 0.82,
    },
    {
        "source": "LLM10",
        "related": "ASI08",
        "type": "enables",
        "prerequisite": "Lack of per-turn request or token budget limits",
        "rationale": "Unbounded token consumption causes API rate-limiting and thread pool starvation, bringing down dependent agent pipelines.",
        "confidence": 0.80,
    },
    {
        "source": "ASI03",
        "related": "ASI02",
        "type": "enables",
        "prerequisite": "Role elevation to administrative tier",
        "rationale": "Privilege abuse unlocks administrative tools (e.g. database schema modifications, file deletions) for destructive misuse.",
        "confidence": 0.89,
    },
]


class OWASPRiskCorrelationEngine:
    """Computes risk dependencies, prerequisite conditions, and correlation graphs."""

    @classmethod
    def get_full_graph(cls) -> RiskCorrelationGraphSchema:
        """Returns the full 20-risk dependency graph with nodes and directed edges."""
        nodes = []
        for r_id, meta in ALL_OWASP_RISKS.items():
            nodes.append({
                "id": r_id,
                "label": f"{r_id}: {meta['name']}",
                "category": meta["category"],
                "severity": meta["severity"],
                "description": meta["desc"],
            })

        edges = []
        for rel in RISK_RELATIONSHIPS_CATALOG:
            edges.append(
                RiskRelationshipSchema(
                    source_risk=rel["source"],
                    related_risk=rel["related"],
                    relationship_type=rel["type"],
                    prerequisite=rel.get("prerequisite"),
                    rationale=rel["rationale"],
                    correlation_confidence=rel["confidence"],
                    validation_status="HYPOTHESIS",
                )
            )

        return RiskCorrelationGraphSchema(
            nodes=nodes,
            edges=edges,
            total_risks_mapped=len(nodes),
            total_relationships=len(edges),
        )

    @classmethod
    def correlate_risks(cls, requested_risk_ids: List[str]) -> Dict[str, Any]:
        """Analyzes a set of requested risk IDs, identifies correlated risks, and builds execution pathways."""
        clean_ids = [r.upper().strip() for r in requested_risk_ids if r.upper().strip() in ALL_OWASP_RISKS]
        if not clean_ids:
            clean_ids = ["LLM01", "LLM02", "ASI01", "ASI02"]

        correlated_records: List[RiskRelationshipSchema] = []
        related_risk_set: Set[str] = set(clean_ids)

        for rel in RISK_RELATIONSHIPS_CATALOG:
            if rel["source"] in clean_ids or rel["related"] in clean_ids:
                correlated_records.append(
                    RiskRelationshipSchema(
                        source_risk=rel["source"],
                        related_risk=rel["related"],
                        relationship_type=rel["type"],
                        prerequisite=rel.get("prerequisite"),
                        rationale=rel["rationale"],
                        correlation_confidence=rel["confidence"],
                        validation_status="HYPOTHESIS",
                    )
                )
                related_risk_set.add(rel["source"])
                related_risk_set.add(rel["related"])

        # Construct dependency sequence (topological ordering hypothesis)
        sequence_hypotheses: List[List[str]] = []
        if "LLM01" in related_risk_set and "ASI01" in related_risk_set and "ASI02" in related_risk_set:
            chain = ["LLM01", "ASI01", "ASI02"]
            if "LLM02" in related_risk_set:
                chain.append("LLM02")
            if "ASI05" in related_risk_set:
                chain.append("ASI05")
            sequence_hypotheses.append(chain)

        if "ASI06" in related_risk_set and "ASI01" in related_risk_set:
            sequence_hypotheses.append(["ASI06", "ASI01", "ASI02"])

        if not sequence_hypotheses:
            sequence_hypotheses.append(list(clean_ids))

        return {
            "requested_risks": clean_ids,
            "all_correlated_risks": sorted(list(related_risk_set)),
            "relationships": [r.model_dump() for r in correlated_records],
            "recommended_attack_chains": sequence_hypotheses,
            "disclaimer": "Identified risk relationships represent attack progression hypotheses for testing. They do not constitute verified vulnerabilities until verified by real HTTP test executions.",
        }
