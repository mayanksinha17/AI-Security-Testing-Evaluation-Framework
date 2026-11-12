import asyncio
import time
from typing import Dict, List, Optional

from app.core.config import settings
from app.providers.base import (
    BaseLLMProvider,
    ProviderAuthenticationError,
    ProviderError,
    ProviderResponse,
    ProviderTimeoutError,
    ProviderUnavailableError,
    TokenUsage,
)


class ClaudeProvider(BaseLLMProvider):
    """Anthropic Claude LLM Provider using the official Anthropic Python SDK."""

    def __init__(self, model_id: Optional[str] = None):
        self._model_id = model_id or settings.claude_model
        self._api_key = settings.anthropic_api_key
        self._timeout = settings.request_timeout_seconds

    @property
    def provider_name(self) -> str:
        return "claude"

    @property
    def model_id(self) -> str:
        return self._model_id

    def is_available(self) -> bool:
        return bool(self._api_key and self._api_key.strip())

    async def generate_response(
        self,
        prompt: str,
        history: Optional[List[Dict[str, str]]] = None,
        system_prompt: Optional[str] = None,
    ) -> ProviderResponse:
        if not self.is_available():
            raise ProviderUnavailableError(
                message="Anthropic API key is not configured. Set ANTHROPIC_API_KEY or use mock mode.",
                provider=self.provider_name,
            )

        try:
            from anthropic import (
                APIError,
                APITimeoutError,
                AsyncAnthropic,
                AuthenticationError,
            )
        except ImportError as e:
            raise ProviderUnavailableError(
                message="Anthropic Python SDK is not installed.",
                provider=self.provider_name,
                original_error=e,
            )

        client = AsyncAnthropic(api_key=self._api_key, timeout=self._timeout)

        # Build message history conforming to Anthropic's expected format
        formatted_messages = []
        if history:
            for msg in history:
                role = msg.get("role", "user")
                if role in {"user", "assistant"}:
                    formatted_messages.append({"role": role, "content": msg.get("content", "")})

        # Append latest prompt
        formatted_messages.append({"role": "user", "content": prompt})

        start_time = time.perf_counter()

        try:
            kwargs = {
                "model": self._model_id,
                "max_tokens": 1024,
                "messages": formatted_messages,
            }
            if system_prompt:
                kwargs["system"] = system_prompt

            api_response = await client.messages.create(**kwargs)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Extract text blocks
            content_parts = []
            for block in api_response.content:
                if hasattr(block, "text"):
                    content_parts.append(block.text)
            content = "".join(content_parts)

            token_usage = None
            if hasattr(api_response, "usage") and api_response.usage:
                prompt_tokens = getattr(api_response.usage, "input_tokens", 0)
                completion_tokens = getattr(api_response.usage, "output_tokens", 0)
                token_usage = TokenUsage(
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=prompt_tokens + completion_tokens,
                )

            return ProviderResponse(
                content=content,
                provider=self.provider_name,
                model=self._model_id,
                response_time_ms=elapsed_ms,
                execution_mode="live",
                token_usage=token_usage,
            )

        except AuthenticationError as e:
            raise ProviderAuthenticationError(
                message="Anthropic API authentication failed. Verify ANTHROPIC_API_KEY.",
                provider=self.provider_name,
                original_error=e,
            )
        except APITimeoutError as e:
            raise ProviderTimeoutError(
                message=f"Anthropic API request timed out after {self._timeout}s.",
                provider=self.provider_name,
                original_error=e,
            )
        except APIError as e:
            raise ProviderError(
                message=f"Anthropic API returned an error: {e.message if hasattr(e, 'message') else str(e)}",
                provider=self.provider_name,
                original_error=e,
            )
        except Exception as e:
            raise ProviderError(
                message=f"Unexpected error communicating with Anthropic Claude: {str(e)}",
                provider=self.provider_name,
                original_error=e,
            )

