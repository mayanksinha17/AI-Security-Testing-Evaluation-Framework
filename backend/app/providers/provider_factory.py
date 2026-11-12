from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.providers.base import BaseLLMProvider, ProviderError
from app.providers.claude_provider import ClaudeProvider
from app.providers.gemini_provider import GeminiProvider
from app.providers.mock_provider import MockLLMProvider

SUPPORTED_PROVIDERS = {"claude", "gemini"}


def get_provider(
    provider_name: str,
    force_mock: bool = False,
    model_id: Optional[str] = None,
) -> BaseLLMProvider:
    """Factory function resolving the requested LLM provider based on mode and credentials."""
    normalized_name = (provider_name or "").lower().strip()

    if normalized_name not in SUPPORTED_PROVIDERS:
        raise ProviderError(
            message=f"Unsupported provider: '{provider_name}'. Supported providers: {sorted(SUPPORTED_PROVIDERS)}",
            provider=normalized_name,
        )

    mode = settings.ai_provider_mode.lower().strip()

    # If mock mode is explicitly requested or configured globally
    if force_mock or mode == "mock":
        return MockLLMProvider(target_provider=normalized_name, model_id=model_id)

    # In live mode, instantiate the real provider
    if normalized_name == "claude":
        claude = ClaudeProvider(model_id=model_id)
        if mode == "auto" and not claude.is_available():
            return MockLLMProvider(target_provider="claude", model_id=model_id)
        return claude

    if normalized_name == "gemini":
        gemini = GeminiProvider(model_id=model_id)
        if mode == "auto" and not gemini.is_available():
            return MockLLMProvider(target_provider="gemini", model_id=model_id)
        return gemini

    # Fallback to mock
    return MockLLMProvider(target_provider=normalized_name, model_id=model_id)


def list_available_providers() -> List[Dict[str, Any]]:
    """Return status and configuration for all supported LLM providers."""
    claude = ClaudeProvider()
    gemini = GeminiProvider()
    mode = settings.ai_provider_mode.lower().strip()

    return [
        {
            "id": "claude",
            "name": "Anthropic Claude",
            "model": settings.claude_model,
            "is_live_available": claude.is_available(),
            "execution_mode": "live" if (mode == "live" and claude.is_available()) else "mock",
            "description": "Anthropic Claude Sonnet 5.5 advanced reasoning model",
        },
        {
            "id": "gemini",
            "name": "Google Gemini",
            "model": settings.gemini_model,
            "is_live_available": gemini.is_available(),
            "execution_mode": "live" if (mode == "live" and gemini.is_available()) else "mock",
            "description": "Google Gemini 3.8 Flash high-speed multimodal model",
        },
    ]

