"""Code Execution Guardrail protecting against Unexpected Code Execution (ASI05).

Detects and blocks shell command execution attempts, arbitrary Python code execution,
and shell metacharacters / command substitution inside tool arguments.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, Optional, Tuple, List


# Shell commands, reconnaissance utilities, and terminal execution requests
SHELL_EXECUTION_PATTERNS = [
    (
        re.compile(r"(?:execute|run)\s+(?:shell\s+command|os\s+command|command|terminal|bash|powershell|cmd)\s*:\s*[`'\"]?([^`'\"]+)[`'\"]?", re.IGNORECASE),
        "Operating System Shell Command Execution: Direct shell execution request blocked.",
    ),
    (
        re.compile(r"\b(whoami|ipconfig|ifconfig|netstat|uname|cat\s+/etc/passwd|nc\s+[\w\.\-]+|\bping\s+[\w\.\-]+)\b", re.IGNORECASE),
        "Host Reconnaissance Command: Direct invocation of operating system reconnaissance utility blocked.",
    ),
    (
        re.compile(r"(?:spawn|invoke|open)\s+(?:a\s+)?(?:bash|cmd\.exe|powershell|sh)\s+(?:shell|session|process)", re.IGNORECASE),
        "Shell Process Spawn Attempt: Request to spawn an operating system terminal process.",
    ),
]

# Arbitrary Python runtime execution patterns
PYTHON_EXECUTION_PATTERNS = [
    (
        re.compile(r"(?:run|execute|evaluate)\s+(?:this\s+)?(?:python\s+code|script|python)\s*:\s*[`'\"]?([^`'\"]+)[`'\"]?", re.IGNORECASE),
        "Arbitrary Python Runtime Execution: Dynamic evaluation of untrusted Python code blocked.",
    ),
    (
        re.compile(r"\b(import\s+os|os\.listdir|subprocess\.|sys\.modules|eval\(|exec\(|__import__)\b", re.IGNORECASE),
        "Arbitrary Python Runtime Call: System-level Python modules or dangerous built-in execution blocked.",
    ),
]

# Shell injection characters and command substitution in tool arguments
COMMAND_INJECTION_PATTERNS = [
    (re.compile(r";"), "Semicolon command separator (;)"),
    (re.compile(r"\|"), "Pipe redirection (|)"),
    (re.compile(r"\$\([^\)]*\)"), "Command substitution ($(...))"),
    (re.compile(r"`[^`]*`"), "Backtick command substitution (`...`)"),
    (re.compile(r"&&|\|\|"), "Boolean command chaining (&&, ||)"),
]


@dataclass
class CodeGuardResult:
    is_blocked: bool
    risk_id: str = "ASI05"
    detection_type: str = "none"
    decision: str = "ALLOWED"  # "ALLOWED" or "BLOCKED"
    reason: str = ""
    refusal_response: Optional[str] = None
    error_message: Optional[str] = None


class CodeExecutionGuard:
    """Enforces zero-code execution boundaries and sanitizes tool arguments against shell injection."""

    @classmethod
    def inspect_prompt(cls, prompt: str) -> CodeGuardResult:
        """Inspects user prompt for shell execution or arbitrary Python runtime commands."""
        cleaned = (prompt or "").strip()

        # 1. Shell command execution patterns
        for pattern, desc in SHELL_EXECUTION_PATTERNS:
            if pattern.search(cleaned):
                return CodeGuardResult(
                    is_blocked=True,
                    risk_id="ASI05",
                    detection_type="shell_execution_blocked",
                    decision="BLOCKED",
                    reason=desc,
                    refusal_response=(
                        f"Agent Security Boundary [ASI05 - Code Execution Intercepted]: {desc}\n"
                        "Arbitrary operating system shell commands cannot be executed. "
                        "The agent runs in a sandboxed evaluation environment with no shell or terminal access; "
                        "such requests are strictly prohibited and unauthorized."
                    ),
                    error_message=f"Access Denied [ASI05]: Shell execution prohibited: {desc}",
                )

        # 2. Python code execution patterns
        for pattern, desc in PYTHON_EXECUTION_PATTERNS:
            if pattern.search(cleaned):
                return CodeGuardResult(
                    is_blocked=True,
                    risk_id="ASI05",
                    detection_type="python_execution_blocked",
                    decision="BLOCKED",
                    reason=desc,
                    refusal_response=(
                        f"Agent Security Boundary [ASI05 - Code Execution Intercepted]: {desc}\n"
                        "Arbitrary Python runtime execution is not supported. "
                        "The backend does not expose dynamic code evaluation (eval/exec); "
                        "code execution is strictly prohibited and unauthorized."
                    ),
                    error_message=f"Access Denied [ASI05]: Python runtime execution prohibited: {desc}",
                )

        return CodeGuardResult(
            is_blocked=False,
            risk_id="ASI05",
            detection_type="none",
            decision="ALLOWED",
            reason="Prompt does not request arbitrary code or shell execution.",
        )

    @classmethod
    def validate_tool_arguments(cls, tool_name: str, arguments: Dict[str, Any]) -> CodeGuardResult:
        """Validates that tool arguments do not contain shell injection meta-characters or command substitutions."""
        normalized_name = (tool_name or "").lower().strip()

        for key, val in arguments.items():
            if isinstance(val, str):
                for pattern, desc in COMMAND_INJECTION_PATTERNS:
                    if pattern.search(val):
                        return CodeGuardResult(
                            is_blocked=True,
                            risk_id="ASI05",
                            detection_type="command_injection_detected",
                            decision="BLOCKED",
                            reason=f"Command injection character in argument '{key}' for tool '{normalized_name}': {desc}",
                            refusal_response=(
                                f"Agent Security Boundary [ASI05 - Command Injection Intercepted]: "
                                f"Parameter '{key}' contains forbidden shell meta-character ({desc}). "
                                "Command chaining, substitution, and piping in tool arguments are prohibited."
                            ),
                            error_message=f"Security Policy Violation [ASI05]: Command injection in '{key}' blocked.",
                        )

        return CodeGuardResult(
            is_blocked=False,
            risk_id="ASI05",
            detection_type="none",
            decision="ALLOWED",
            reason="Tool arguments verified clean of command injection patterns.",
        )

