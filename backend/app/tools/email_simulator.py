from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from app.security.validation import SecurityValidationError, validate_email_address
from app.tools.base import BaseTool, ToolResult


class EmailSimulatorTool(BaseTool):
    name = "email_simulator"
    description = (
        "Simulates sending emails in a controlled sandbox. "
        "Validates recipients, formats mock messages, and simulates delivery. "
        "Sensitive external action requiring human approval."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "recipient": {
                "type": "string",
                "description": "Recipient email address (e.g. 'analyst@apexshield.example.test').",
            },
            "subject": {
                "type": "string",
                "description": "Subject line of the email.",
            },
            "body": {
                "type": "string",
                "description": "Content of the email body.",
            },
        },
        "required": ["recipient", "subject", "body"],
    }
    required_role = "analyst"

    async def execute(self, arguments: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ToolResult:
        recipient = str(arguments.get("recipient", "")).strip()
        subject = str(arguments.get("subject", "")).strip()
        body = str(arguments.get("body", "")).strip()

        if not recipient or not subject or not body:
            return ToolResult(
                success=False,
                output=None,
                error="Arguments 'recipient', 'subject', and 'body' are all required.",
            )

        # Validate recipient format
        try:
            validated_recipient = validate_email_address(recipient)
        except SecurityValidationError as e:
            return ToolResult(
                success=False,
                output=None,
                error=f"Security Policy Violation: {str(e)}",
                metadata={"blocked": True, "reason": "invalid_email_format"},
            )

        delivery_id = f"sim-mail-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        preview = {
            "delivery_id": delivery_id,
            "status": "simulated_sent",
            "recipient": validated_recipient,
            "subject": subject,
            "body_snippet": body[:120] + ("..." if len(body) > 120 else ""),
            "full_length": len(body),
            "simulated_timestamp": now_iso,
            "note": "SIMULATION ONLY: No actual email was transmitted over external networks.",
        }

        return ToolResult(
            success=True,
            output=preview,
            metadata={
                "delivery_id": delivery_id,
                "recipient": validated_recipient,
                "simulated": True,
            },
        )

