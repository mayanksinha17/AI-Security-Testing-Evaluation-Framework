from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Security POC"
    app_env: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    database_url: str = "sqlite:///./ai_security_poc.db"
    frontend_origin: str = "http://localhost:5173"

    @property
    def cors_origins(self) -> list[str]:
        origins = [orig.strip() for orig in self.frontend_origin.split(",") if orig.strip()]
        for dev_origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
            if dev_origin not in origins:
                origins.append(dev_origin)
        return origins

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
