"""OWASP Risk Identifier & Semantic Intent Mapper (Phase A).

Extracts and maps OWASP risk identifiers (LLM01-LLM10, ASI01-ASI06) from
natural language commands, recognizing exact codes, synonym phrases, and
group categories.
"""

from dataclasses import dataclass
import re
from typing import Dict, List, Optional, Set, Tuple

from app.security_agent.schemas import RiskMatchSchema


@dataclass(frozen=True)
class RiskMetadata:
    risk_id: str
    risk_name: str
    category: str  # "OWASP_LLM" or "OWASP_AGENTIC"
    description: str
    severity: str
    synonyms: Tuple[str, ...]


RISK_REGISTRY: Dict[str, RiskMetadata] = {
    "LLM01": RiskMetadata(
        risk_id="LLM01",
        risk_name="Prompt Injection",
        category="OWASP_LLM",
        description="Adversarial inputs manipulating model behavior, overriding system instructions or injecting secondary directives.",
        severity="high",
        synonyms=(
            "prompt injection",
            "instruction override",
            "system override",
            "jailbreak",
            "direct prompt injection",
            "indirect prompt injection",
            "instruction hierarchy",
            "unrestricted override",
            "prompt injection tests",
        ),
    ),
    "LLM02": RiskMetadata(
        risk_id="LLM02",
        risk_name="Sensitive Information Disclosure",
        category="OWASP_LLM",
        description="Eliciting confidential data, synthetic canary tokens, credentials, or proprietary intellectual property.",
        severity="critical",
        synonyms=(
            "sensitive information",
            "sensitive info",
            "information disclosure",
            "credential leak",
            "credential exfiltration",
            "canary token",
            "secret extraction",
            "data leakage",
            "canary flag",
            "secret disclosure",
        ),
    ),
    "LLM03": RiskMetadata(
        risk_id="LLM03",
        risk_name="Excessive Agency",
        category="OWASP_LLM",
        description="Granting damaging autonomy, unbounded tool permissions, or bypassing required human authorization.",
        severity="high",
        synonyms=(
            "excessive agency",
            "unauthorized tool",
            "unbounded tool permissions",
            "unbounded action",
            "missing approval",
            "bypassing human authorization",
            "autonomous agency",
        ),
    ),
    "LLM08": RiskMetadata(
        risk_id="LLM08",
        risk_name="Hidden Context Exposure",
        category="OWASP_LLM",
        description="Extracting unrevealed system instructions, developer constraints, or hidden prompt chain metadata.",
        severity="medium",
        synonyms=(
            "hidden context",
            "hidden context exposure",
            "system prompt extraction",
            "developer instructions",
            "meta-rules leakage",
            "internal instructions",
            "context exposure",
            "prompt extraction",
        ),
    ),
    "LLM10": RiskMetadata(
        risk_id="LLM10",
        risk_name="Improper Output Handling",
        category="OWASP_LLM",
        description="Generating unvalidated output containing script injection, malicious HTML, or unsanitized payloads.",
        severity="medium",
        synonyms=(
            "improper output handling",
            "improper output",
            "xss",
            "cross-site scripting",
            "script injection",
            "svg injection",
            "sql injection in output",
            "output sanitization",
        ),
    ),
    "ASI01": RiskMetadata(
        risk_id="ASI01",
        risk_name="Agent Goal Hijack",
        category="OWASP_AGENTIC",
        description="Subverting agent reasoning loop to abandon legitimate goals and pursue attacker-controlled objectives.",
        severity="high",
        synonyms=(
            "agent goal hijack",
            "goal hijack",
            "goal hijacking",
            "objective hijack",
            "task redirection",
            "objective abandonment",
            "persona inversion",
            "evil agent",
            "goal subversion",
        ),
    ),
    "ASI02": RiskMetadata(
        risk_id="ASI02",
        risk_name="Tool Misuse",
        category="OWASP_AGENTIC",
        description="Invoking tools with unauthorized parameters, hitting forbidden endpoints, or violating sandbox limits.",
        severity="critical",
        synonyms=(
            "tool misuse",
            "unauthorized http",
            "ssrf",
            "path traversal",
            "directory traversal",
            "mass email",
            "forbidden endpoint",
            "sandbox escape",
        ),
    ),
    "ASI03": RiskMetadata(
        risk_id="ASI03",
        risk_name="Identity & Privilege Abuse",
        category="OWASP_AGENTIC",
        description="Attempting role elevation, bypassing permission managers, or performing administrative operations unauthorized.",
        severity="high",
        synonyms=(
            "identity abuse",
            "privilege abuse",
            "privilege escalation",
            "role elevation",
            "rbac bypass",
            "unauthorized role",
            "identity and privilege abuse",
        ),
    ),
    "ASI05": RiskMetadata(
        risk_id="ASI05",
        risk_name="Unexpected Code Execution",
        category="OWASP_AGENTIC",
        description="Tricking the agent or backend into executing arbitrary operating system commands or arbitrary code.",
        severity="critical",
        synonyms=(
            "unexpected code execution",
            "code execution",
            "rce",
            "command injection",
            "arbitrary code",
            "shell execution",
            "arbitrary python",
        ),
    ),
    "ASI06": RiskMetadata(
        risk_id="ASI06",
        risk_name="Memory & Context Poisoning",
        category="OWASP_AGENTIC",
        description="Corrupting long-term memory, session state, or synthetic documents to skew subsequent agent judgments.",
        severity="high",
        synonyms=(
            "memory poisoning",
            "context poisoning",
            "memory and context poisoning",
            "knowledge base corruption",
            "memory corruption",
            "session poisoning",
            "audit subversion",
        ),
    ),
}

# Group keyword patterns
GROUP_PATTERNS: List[Tuple[re.Pattern, List[str]]] = [
    (re.compile(r"\b(?:all\s+)?prompt\s+injection(?:\s+test\s*cases?)?\b", re.IGNORECASE), ["LLM01"]),
    (re.compile(r"\b(?:all\s+)?agentic\s+(?:ai\s+)?risks?\b", re.IGNORECASE), ["ASI01", "ASI02", "ASI03", "ASI05", "ASI06"]),
    (re.compile(r"\b(?:all\s+)?llm\s+risks?\b", re.IGNORECASE), ["LLM01", "LLM02", "LLM03", "LLM08", "LLM10"]),
    (re.compile(r"\b(?:priority|top\s*4|core)\s+risks?\b", re.IGNORECASE), ["LLM01", "LLM02", "ASI01", "ASI02"]),
    (re.compile(r"\b(?:all|full|comprehensive|complete)\s+(?:owasp\s+)?(?:ai\s+)?(?:risks?|security\s+tests?|scan)\b", re.IGNORECASE), list(RISK_REGISTRY.keys())),
]

EXACT_CODE_PATTERN = re.compile(
    r"\b(LLM01|LLM02|LLM03|LLM08|LLM10|ASI01|ASI02|ASI03|ASI05|ASI06)\b",
    re.IGNORECASE,
)

ANY_RISK_CODE_PATTERN = re.compile(
    r"\b(LLM\d+|ASI\d+)\b",
    re.IGNORECASE,
)


class RiskIdentifier:
    """Identifies OWASP risks from natural language commands and returns structured matches."""

    @classmethod
    def extract_invalid_risks(cls, text: str) -> List[str]:
        """Finds any OWASP risk-formatted codes in text that are not in the registered catalog."""
        cleaned = text.strip()
        all_codes = {m.group(1).upper() for m in ANY_RISK_CODE_PATTERN.finditer(cleaned)}
        return sorted(list(all_codes - set(RISK_REGISTRY.keys())))

    @classmethod
    def identify_risks(cls, text: str) -> List[RiskMatchSchema]:
        matched_risks: Dict[str, RiskMatchSchema] = {}
        cleaned = text.strip()
        invalid_codes = cls.extract_invalid_risks(cleaned)

        # 1. Exact OWASP Code Matches (Highest confidence: 1.0)
        for match in EXACT_CODE_PATTERN.finditer(cleaned):
            code = match.group(1).upper()
            if code in RISK_REGISTRY:
                meta = RISK_REGISTRY[code]
                matched_risks[code] = RiskMatchSchema(
                    risk_id=meta.risk_id,
                    risk_name=meta.risk_name,
                    category=meta.category,
                    matched_phrase=match.group(0),
                    confidence=1.0,
                    severity=meta.severity,
                    description=meta.description,
                )

        # 2. Group Expression Matches (High confidence: 0.95)
        for pattern, risk_codes in GROUP_PATTERNS:
            match = pattern.search(cleaned)
            if match:
                for code in risk_codes:
                    if code not in matched_risks and code in RISK_REGISTRY:
                        meta = RISK_REGISTRY[code]
                        matched_risks[code] = RiskMatchSchema(
                            risk_id=meta.risk_id,
                            risk_name=meta.risk_name,
                            category=meta.category,
                            matched_phrase=match.group(0),
                            confidence=0.95,
                            severity=meta.severity,
                            description=meta.description,
                        )

        # 3. Synonym / Keyword Phrase Matches (Confidence: 0.90)
        text_lower = cleaned.lower()
        for code, meta in RISK_REGISTRY.items():
            if code in matched_risks:
                continue
            for syn in meta.synonyms:
                if syn.lower() in text_lower:
                    matched_risks[code] = RiskMatchSchema(
                        risk_id=meta.risk_id,
                        risk_name=meta.risk_name,
                        category=meta.category,
                        matched_phrase=syn,
                        confidence=0.90,
                        severity=meta.severity,
                        description=meta.description,
                    )
                    break

        # If user command asks generally to "test/audit/scan my application" with no specific risks,
        # default to priority baseline risks (LLM01, LLM02, ASI01, ASI02) ONLY if no invalid risks were found
        if not matched_risks and not invalid_codes and any(w in text_lower for w in ["test", "audit", "scan", "evaluate"]):
            for code in ["LLM01", "LLM02", "ASI01", "ASI02"]:
                meta = RISK_REGISTRY[code]
                matched_risks[code] = RiskMatchSchema(
                    risk_id=meta.risk_id,
                    risk_name=meta.risk_name,
                    category=meta.category,
                    matched_phrase="default priority risk set",
                    confidence=0.75,
                    severity=meta.severity,
                    description=meta.description,
                )

        # Return sorted by code
        return sorted(list(matched_risks.values()), key=lambda r: r.risk_id)

    @classmethod
    def get_all_registered_risks(cls) -> List[RiskMatchSchema]:
        return [
            RiskMatchSchema(
                risk_id=meta.risk_id,
                risk_name=meta.risk_name,
                category=meta.category,
                matched_phrase=meta.risk_id,
                confidence=1.0,
                severity=meta.severity,
                description=meta.description,
            )
            for meta in sorted(RISK_REGISTRY.values(), key=lambda r: r.risk_id)
        ]
