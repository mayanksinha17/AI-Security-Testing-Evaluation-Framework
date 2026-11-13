from pathlib import Path
import re
from typing import Set, Sequence


class SecurityValidationError(ValueError):
    """Raised when an argument violates security policies (traversal, disallowed URL, invalid email, etc.)."""
    pass


# Allowed file extensions for FileReader tool
ALLOWED_FILE_EXTENSIONS: Set[str] = {".txt", ".json", ".md", ".csv", ".yaml", ".yml"}

# Maximum allowable file read size (100 KB)
MAX_FILE_READ_BYTES = 100 * 1024

# Allowed simulated HTTP endpoints
ALLOWED_HTTP_ENDPOINTS: Sequence[str] = (
    "https://api.internal.apexshield.local/v1/health",
    "https://api.internal.apexshield.local/v1/telemetry",
    "https://api.internal.apexshield.local/v1/auth/verify",
    "https://staging-internal.aegiscore.local:8443/status",
)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_file_path(base_dir: Path, requested_path: str, allowed_extensions: Set[str] = ALLOWED_FILE_EXTENSIONS) -> Path:
    """Validates that requested_path is within base_dir and has an allowed extension.
    
    Prevents path traversal, absolute paths escaping sandbox, and sensitive file probing.
    """
    if not requested_path or not requested_path.strip():
        raise SecurityValidationError("File path cannot be empty.")

    cleaned_path = requested_path.strip().lstrip("/\\")

    # Reject blatant traversal sequences before path resolution
    if ".." in cleaned_path or cleaned_path.startswith("/") or cleaned_path.startswith("\\"):
        raise SecurityValidationError(f"Path traversal sequence detected in '{requested_path}'. Access denied.")

    # Reject command injection characters in file path
    if any(c in cleaned_path for c in [";", "|", "&", "`", "$"]):
        raise SecurityValidationError(f"Command injection characters detected in path '{requested_path}'. Access denied.")

    base_dir_resolved = base_dir.resolve()
    candidate_resolved = (base_dir_resolved / cleaned_path).resolve()

    # Verify candidate is strictly inside base_dir
    try:
        candidate_resolved.relative_to(base_dir_resolved)
    except ValueError:
        raise SecurityValidationError(f"Access denied: Path '{requested_path}' escapes the synthetic data directory.")

    if candidate_resolved.suffix.lower() not in allowed_extensions:
        raise SecurityValidationError(
            f"Extension '{candidate_resolved.suffix}' is disallowed. Allowed: {sorted(allowed_extensions)}"
        )

    return candidate_resolved


def validate_http_url(url: str, allowed_endpoints: Sequence[str] = ALLOWED_HTTP_ENDPOINTS) -> str:
    """Validates that a simulated HTTP request targets an allowlisted endpoint."""
    if not url or not url.strip():
        raise SecurityValidationError("HTTP URL cannot be empty.")

    cleaned_url = url.strip()

    # Exact or prefix match against allowlisted endpoints
    normalized_allowed = [ep.rstrip("/") for ep in allowed_endpoints]
    cleaned_no_slash = cleaned_url.rstrip("/")

    is_allowed = any(cleaned_no_slash == ep or cleaned_no_slash.startswith(ep + "/") for ep in normalized_allowed)

    if not is_allowed:
        raise SecurityValidationError(
            f"Destination URL '{url}' is not in the controlled endpoint allowlist. "
            f"Allowed endpoints: {list(allowed_endpoints)}"
        )

    return cleaned_url


def validate_email_address(email: str) -> str:
    """Validates an email address format and identifies domain classification."""
    if not email or not email.strip():
        raise SecurityValidationError("Email address cannot be empty.")

    cleaned = email.strip()
    if not EMAIL_REGEX.match(cleaned):
        raise SecurityValidationError(f"Invalid email address format: '{email}'.")

    return cleaned

