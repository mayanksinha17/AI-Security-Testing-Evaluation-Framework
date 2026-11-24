"""Target Application Resolver for Autonomous Security Testing Agent (Phase A).

Resolves, extracts, and normalizes target URLs from natural language commands,
handles local testing defaults, and interfaces with the ScopeValidator.
"""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from app.security_agent.schemas import ScopeStatusEnum, TargetScopeSchema
from app.security_agent.scope_validator import ScopeValidator


# Regex pattern to match explicit HTTP/HTTPS URLs in text
URL_REGEX = re.compile(
    r"\bhttps?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s\"'<>,;)]*)?",
    re.IGNORECASE,
)

# Regex pattern to match raw host:port or ip:port (e.g. localhost:8080, 127.0.0.1:8000)
HOST_PORT_REGEX = re.compile(
    r"\b(?:localhost|127\.0\.0\.1|(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(\d{2,5})(?:/[^\s\"'<>,;)]*)?",
    re.IGNORECASE,
)

# Patterns indicating testing against local application environment
LOCAL_REFERENCE_PATTERNS = [
    re.compile(r"\b(?:my|the|our|this)\s+(?:local\s+)?(?:test\s+)?(?:application|app|service|api|backend|chatbot|agent)\b", re.IGNORECASE),
    re.compile(r"\blocal\s+(?:test\s+)?(?:application|app|service|api|backend|environment)\b", re.IGNORECASE),
    re.compile(r"\blocalhost\b", re.IGNORECASE),
]

# Patterns for target indicator phrases like "against http://..." or "target: http://..."
TARGET_INDICATOR_REGEX = re.compile(
    r"(?:against|target(?:ing)?(?:\s+(?:is|=|:))?|on\s+url|at\s+url|endpoint\s*(?:is|=|:)?)\s+([^\s\"'<>,;)]+)",
    re.IGNORECASE,
)


class TargetResolver:
    """Extracts target application specifications from natural language and validates their scope."""

    DEFAULT_LOCAL_TARGET = "http://127.0.0.1:8000"

    @classmethod
    def extract_target_string(cls, text: str) -> Tuple[Optional[str], str]:
        """Extracts candidate target URL or host from natural language text.

        Returns:
            Tuple[Optional[str], str]: (extracted_target_or_None, extraction_source_description)
        """
        # 1. Check for explicit URL scheme match
        url_match = URL_REGEX.search(text)
        if url_match:
            candidate = url_match.group(0).rstrip(".,;:!?)")
            return candidate, "explicit_url_regex"

        # 2. Check for host:port or ip:port
        host_port_match = HOST_PORT_REGEX.search(text)
        if host_port_match:
            candidate = host_port_match.group(0).rstrip(".,;:!?)")
            if not candidate.startswith("http://") and not candidate.startswith("https://"):
                candidate = f"http://{candidate}"
            return candidate, "host_port_regex"

        # 3. Check for target indicator phrases (e.g. "against http://..." or "target: ...")
        indicator_match = TARGET_INDICATOR_REGEX.search(text)
        if indicator_match:
            candidate = indicator_match.group(1).rstrip(".,;:!?)")
            # Ensure it looks somewhat like a host or URL
            if "." in candidate or ":" in candidate:
                if not candidate.startswith("http://") and not candidate.startswith("https://"):
                    candidate = f"http://{candidate}"
                return candidate, "target_indicator_phrase"

        # 4. Check for local application reference phrases
        for pattern in LOCAL_REFERENCE_PATTERNS:
            if pattern.search(text):
                return cls.DEFAULT_LOCAL_TARGET, "local_application_reference"

        # No specific target extracted
        return None, "none"

    @classmethod
    def resolve_target(
        cls,
        command: str,
        explicit_target: Optional[str] = None,
        user_confirmed_authorization: bool = False,
        default_target: Optional[str] = None,
    ) -> TargetScopeSchema:
        """Resolves the effective target URL and validates it with ScopeValidator.

        Priority:
        1. Explicit target_url override parameter.
        2. Target extracted from command text.
        3. Configured default target (default: http://127.0.0.1:8000).
        """
        fallback_default = default_target or cls.DEFAULT_LOCAL_TARGET

        # 1. Explicit override provided
        if explicit_target and explicit_target.strip():
            target_str = explicit_target.strip()
            return ScopeValidator.resolve_and_validate_target(
                raw_url=target_str,
                user_confirmed_authorization=user_confirmed_authorization,
            )

        # 2. Extract from command
        extracted_str, extraction_method = cls.extract_target_string(command)
        if extracted_str:
            return ScopeValidator.resolve_and_validate_target(
                raw_url=extracted_str,
                user_confirmed_authorization=user_confirmed_authorization,
            )

        # 3. Fallback to default local target
        return ScopeValidator.resolve_and_validate_target(
            raw_url=fallback_default,
            user_confirmed_authorization=user_confirmed_authorization,
        )
