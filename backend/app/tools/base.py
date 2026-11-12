from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ToolResult:
    success: bool
    output: Any
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "metadata": self.metadata,
        }


class BaseTool(ABC):
    """Abstract base class for all controllable agent tools."""

    name: str = ""
    description: str = ""
    parameters_schema: Dict[str, Any] = {}
    required_role: str = "analyst"

    @abstractmethod
    async def execute(self, arguments: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ToolResult:
        """Executes the tool with validated arguments."""
        pass

    def to_claude_tool(self) -> Dict[str, Any]:
        """Formats the tool schema for the Anthropic Messages API."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters_schema,
        }

    def to_gemini_tool(self) -> Dict[str, Any]:
        """Formats the tool schema for the Google Gen AI API function declaration."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters_schema,
        }

