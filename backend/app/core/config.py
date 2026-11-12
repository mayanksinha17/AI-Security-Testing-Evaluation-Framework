from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Security POC"
    app_env: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    database_url: str = "sqlite:///./ai_security_poc.db"
    frontend_origin: str = "http://localhost:5173"

    # Phase 2: AI Provider Configuration
    anthropic_api_key: str | None = None
    gemini_api_key: str | None = None
    claude_model: str = "claude-sonnet-5-5"
    gemini_model: str = "gemini-3.8-flash"
    ai_provider_mode: str = "mock"  # "mock" or "live"
    request_timeout_seconds: float = 30.0
    max_message_length: int = 4000

    @property
    def cors_origins(self) -> list[str]:
        origins = [orig.strip() for orig in self.frontend_origin.split(",") if orig.strip()]
        for dev_origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
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
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
