from pathlib import Path
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_CONFIG_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _CONFIG_FILE.parents[3]
_BACKEND_DIR = _CONFIG_FILE.parents[2]
_DEFAULT_DB_PATH = _PROJECT_ROOT / "ai_security_poc.db"
_DEFAULT_DB_URL = f"sqlite:///{_DEFAULT_DB_PATH.as_posix()}"


class Settings(BaseSettings):
    app_name: str = "AI Security POC"
    app_env: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    database_url: str = _DEFAULT_DB_URL
    frontend_origin: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174"

    # Phase 2: AI Provider Configuration
    anthropic_api_key: str | None = None
    gemini_api_key: str | None = None
    claude_model: str = "claude-sonnet-5"
    gemini_model: str = "gemini-3.8-flash"
    ai_provider_mode: str = "mock"  # "mock" or "live"
    request_timeout_seconds: float = 30.0
    max_message_length: int = 4000

    # Phase 5: OWASP LLM Security Configuration
    enable_prompt_injection_detection: bool = True
    enable_sensitive_data_redaction: bool = True
    enable_output_sanitization: bool = True
    enable_tool_authorization_guard: bool = True
    enable_security_audit_logging: bool = True
    max_input_length: int = 4000
    max_output_length: int = 8000

    # Phase C.1: Evidence Signing & Integrity Key
    evidence_signing_key: str | None = None

    @field_validator("database_url", mode="before")
    @classmethod
    def resolve_database_url(cls, v: str | None) -> str:
        if not v or v in ("sqlite:///./ai_security_poc.db", "sqlite:///ai_security_poc.db"):
            return _DEFAULT_DB_URL
        if v.startswith("sqlite:///./"):
            rel_path = v[len("sqlite:///./") :]
            abs_path = (_PROJECT_ROOT / rel_path).resolve()
            return f"sqlite:///{abs_path.as_posix()}"
        return v

    @property
    def cors_origins(self) -> list[str]:
        origins = [orig.strip() for orig in self.frontend_origin.split(",") if orig.strip()]
        for dev_origin in (
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
        ):
            if dev_origin not in origins:
                origins.append(dev_origin)
        return origins

    @property
    def CLAUDE_MODEL(self) -> str:
        return self.claude_model

    @property
    def GEMINI_MODEL(self) -> str:
        return self.gemini_model

    @property
    def AI_PROVIDER_MODE(self) -> str:
        return self.ai_provider_mode

    @property
    def ANTHROPIC_API_KEY(self) -> str | None:
        return self.anthropic_api_key

    @property
    def GEMINI_API_KEY(self) -> str | None:
        return self.gemini_api_key

    model_config = SettingsConfigDict(
        env_file=(
            (_PROJECT_ROOT / ".env").as_posix(),
            (_BACKEND_DIR / ".env").as_posix(),
        ),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
