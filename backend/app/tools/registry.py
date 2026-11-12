from typing import Any, Dict, List, Optional

from app.tools.base import BaseTool
from app.tools.email_simulator import EmailSimulatorTool
from app.tools.file_reader import FileReaderTool
from app.tools.http_simulator import HttpSimulatorTool
from app.tools.knowledge_search import KnowledgeSearchTool


class ToolRegistry:
    """Central registry managing all active agent tools and schemas."""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        self.register(FileReaderTool())
        self.register(KnowledgeSearchTool())
        self.register(HttpSimulatorTool())
        self.register(EmailSimulatorTool())

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "parameters_schema": tool.parameters_schema,
                "required_role": tool.required_role,
            }
            for tool in self._tools.values()
        ]

    def get_claude_tools(self) -> List[Dict[str, Any]]:
        return [tool.to_claude_tool() for tool in self._tools.values()]

    def get_gemini_tools(self) -> List[Dict[str, Any]]:
        return [tool.to_gemini_tool() for tool in self._tools.values()]


# Global registry singleton
tool_registry = ToolRegistry()

