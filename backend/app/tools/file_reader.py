from pathlib import Path
from typing import Any, Dict, Optional

from app.security.validation import (
    MAX_FILE_READ_BYTES,
    SecurityValidationError,
    validate_file_path,
)
from app.tools.base import BaseTool, ToolResult


class FileReaderTool(BaseTool):
    name = "file_reader"
    description = (
        "Reads files from the controlled synthetic data directory. "
        "Allows reading company handbook, project statuses, or playbooks. "
        "Path traversal outside the synthetic directory is strictly blocked."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Relative filename within the synthetic directory (e.g. 'company_handbook.txt', 'project_status.json').",
            }
        },
        "required": ["file_path"],
    }
    required_role = "analyst"

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            self.base_dir = (Path(__file__).resolve().parent.parent / "synthetic_data").resolve()
        else:
            self.base_dir = base_dir.resolve()

    async def execute(self, arguments: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ToolResult:
        file_path_str = arguments.get("file_path", "")
        if not file_path_str:
            return ToolResult(
                success=False,
                output=None,
                error="Argument 'file_path' is required.",
            )

        try:
            resolved_path = validate_file_path(self.base_dir, file_path_str)
        except SecurityValidationError as e:
            return ToolResult(
                success=False,
                output=None,
                error=f"Security Policy Violation: {str(e)}",
                metadata={"blocked": True, "reason": "security_validation_failure"},
            )

        if not resolved_path.exists() or not resolved_path.is_file():
            return ToolResult(
                success=False,
                output=None,
                error=f"File not found: '{file_path_str}'.",
            )

        # Check file size limit
        file_size = resolved_path.stat().st_size
        if file_size > MAX_FILE_READ_BYTES:
            return ToolResult(
                success=False,
                output=None,
                error=f"File size {file_size} bytes exceeds maximum limit of {MAX_FILE_READ_BYTES} bytes.",
            )

        try:
            content = resolved_path.read_text(encoding="utf-8")
            return ToolResult(
                success=True,
                output={
                    "file_name": resolved_path.name,
                    "content": content,
                    "size_bytes": file_size,
                },
                metadata={"file_name": resolved_path.name, "bytes_read": file_size},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output=None,
                error=f"Error reading file '{file_path_str}': {str(e)}",
            )

