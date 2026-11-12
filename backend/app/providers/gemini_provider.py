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


class GeminiProvider(BaseLLMProvider):
    """Google Gemini LLM Provider using the official Google Gen AI Python SDK."""

    def __init__(self, model_id: Optional[str] = None):
        self._model_id = model_id or settings.gemini_model
        self._api_key = settings.gemini_api_key
        self._timeout = settings.request_timeout_seconds

    @property
    def provider_name(self) -> str:
        return "gemini"

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
                message="Google Gemini API key is not configured. Set GEMINI_API_KEY or use mock mode.",
                provider=self.provider_name,
            )

        try:
            from google import genai
            from google.genai import errors, types
        except ImportError as e:
            raise ProviderUnavailableError(
                message="Google Gen AI SDK is not installed.",
                provider=self.provider_name,
                original_error=e,
            )

        client = genai.Client(api_key=self._api_key)

        # Build content list
        contents = []
        if history:
            for msg in history:
                role = msg.get("role", "user")
                # Gemini expects "user" or "model"
                gemini_role = "model" if role == "assistant" else "user"
                content_text = msg.get("content", "")
                if content_text:
                    contents.append(
                        types.Content(
                            role=gemini_role,
                            parts=[types.Part.from_text(text=content_text)],
                        )
                    )

        # Append latest prompt
        contents.append(
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt)],
            )
        )

        config_args = {}
        if system_prompt:
            config_args["system_instruction"] = system_prompt
        config = types.GenerateContentConfig(**config_args) if config_args else None

        start_time = time.perf_counter()

        try:
            async def _call_api():
                return await client.aio.models.generate_content(
                    model=self._model_id,
                    contents=contents,
                    config=config,
                )

            api_response = await asyncio.wait_for(_call_api(), timeout=self._timeout)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            content = getattr(api_response, "text", "") or ""

            token_usage = None
            if hasattr(api_response, "usage_metadata") and api_response.usage_metadata:
                usage = api_response.usage_metadata
                prompt_tokens = getattr(usage, "prompt_token_count", 0) or 0
                completion_tokens = getattr(usage, "candidates_token_count", 0) or 0
                total_tokens = getattr(usage, "total_token_count", 0) or (prompt_tokens + completion_tokens)
                token_usage = TokenUsage(
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                )

            return ProviderResponse(
                content=content,
                provider=self.provider_name,
                model=self._model_id,
                response_time_ms=elapsed_ms,
                execution_mode="live",
                token_usage=token_usage,
            )

        except asyncio.TimeoutError as e:
            raise ProviderTimeoutError(
                message=f"Gemini API request timed out after {self._timeout}s.",
                provider=self.provider_name,
                original_error=e,
            )
        except errors.APIError as e:
            message_text = str(e)
            if "401" in message_text or "403" in message_text or "API_KEY_INVALID" in message_text:
                raise ProviderAuthenticationError(
                    message="Gemini API authentication failed. Verify GEMINI_API_KEY.",
                    provider=self.provider_name,
                    original_error=e,
                )
            raise ProviderError(
                message=f"Gemini API returned an error: {message_text}",
                provider=self.provider_name,
                original_error=e,
            )
        except Exception as e:
            raise ProviderError(
                message=f"Unexpected error communicating with Google Gemini: {str(e)}",
                provider=self.provider_name,
                original_error=e,
            )

