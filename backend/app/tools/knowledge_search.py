from typing import Any, Dict, List, Optional

from app.knowledge_base.documents import search_knowledge
from app.tools.base import BaseTool, ToolResult


class KnowledgeSearchTool(BaseTool):
    name = "knowledge_search"
    description = (
        "Searches fictional enterprise knowledge base documents. "
        "Returns matching document snippets, classifications, and titles."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Keyword or topic to search within company knowledge base documents.",
            },
            "include_restricted": {
                "type": "boolean",
                "description": "Whether to include restricted/confidential documents. Requires elevated permission.",
                "default": False,
            },
        },
        "required": ["query"],
    }
    required_role = "user"  # Accessible to all roles, but restricted docs require analyst/admin

    async def execute(self, arguments: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ToolResult:
        query = str(arguments.get("query", "")).strip()
        if not query:
            return ToolResult(
                success=False,
                output=None,
                error="Argument 'query' is required.",
            )

        # Context role check for restricted documents
        role = (context or {}).get("role", "user")
        include_restricted = bool(arguments.get("include_restricted", False))

        if include_restricted and role == "user":
            return ToolResult(
                success=False,
                output=None,
                error="Permission denied: Role 'user' cannot search restricted or confidential documents.",
                metadata={"blocked": True, "reason": "unauthorized_classification"},
            )

        matching_docs = search_knowledge(query=query, include_restricted=include_restricted)

        formatted_results: List[Dict[str, Any]] = []
        for doc in matching_docs:
            formatted_results.append({
                "id": doc.id,
                "title": doc.title,
                "category": doc.category,
                "classification": doc.classification,
                "content": doc.content,
            })

        return ToolResult(
            success=True,
            output={
                "query": query,
                "matches_count": len(formatted_results),
                "results": formatted_results,
            },
            metadata={"matches": len(formatted_results), "query": query},
        )

