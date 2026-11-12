from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class TokenUsage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

    def to_dict(self) -> Dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass
class ProviderResponse:
    content: str
    provider: str
    model: str
    response_time_ms: float
    execution_mode: str  # "mock" or "live"
    token_usage: Optional[TokenUsage] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "provider": self.provider,
            "model": self.model,
            "response_time_ms": round(self.response_time_ms, 2),
            "execution_mode": self.execution_mode,
            "token_usage": self.token_usage.to_dict() if self.token_usage else None,
        }


class ProviderError(Exception):
    """Base exception for LLM provider errors."""

    def __init__(self, message: str, provider: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.original_error = original_error


class ProviderUnavailableError(ProviderError):
    """Raised when an API key is missing or the provider service is unreachable."""
    pass


class ProviderTimeoutError(ProviderError):
    """Raised when an LLM provider request times out."""
    pass


class ProviderAuthenticationError(ProviderError):
    """Raised when API credentials are invalid or rejected."""
    pass


class BaseLLMProvider(ABC):
    """Unified interface for LLM providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """The canonical name of the provider (e.g. 'claude', 'gemini')."""
        pass

    @property
    @abstractmethod
    def model_id(self) -> str:
        """The active model identifier."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether the provider has credentials configured for live calls."""
        pass

    @abstractmethod
    async def generate_response(
        self,
        prompt: str,
        history: Optional[List[Dict[str, str]]] = None,
        system_prompt: Optional[str] = None,
    ) -> ProviderResponse:
        """Generate an assistant response from the underlying provider."""
        pass

