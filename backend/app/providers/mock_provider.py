import asyncio
import time
from typing import Dict, List, Optional

from app.core.config import settings
from app.providers.base import BaseLLMProvider, ProviderResponse, TokenUsage


class MockLLMProvider(BaseLLMProvider):
    """Deterministic mock provider simulating Claude and Gemini without external API calls."""

    def __init__(self, target_provider: str = "claude", model_id: Optional[str] = None):
        self._provider = target_provider.lower().strip()
        if self._provider not in {"claude", "gemini"}:
            self._provider = "claude"

        if model_id:
            self._model_id = model_id
        else:
            self._model_id = (
                settings.claude_model if self._provider == "claude" else settings.gemini_model
            )

    @property
    def provider_name(self) -> str:
        return self._provider

    @property
    def model_id(self) -> str:
        return self._model_id

    def is_available(self) -> bool:
        # Mock mode is always available regardless of keys
        return True

    async def generate_response(
        self,
        prompt: str,
        history: Optional[List[Dict[str, str]]] = None,
        system_prompt: Optional[str] = None,
    ) -> ProviderResponse:
        start_time = time.perf_counter()

        # Simulate brief async inference latency (approx 50ms - 100ms)
        await asyncio.sleep(0.06)

        cleaned_prompt = prompt.strip()
        lower_prompt = cleaned_prompt.lower()

        # Determine deterministic synthetic response based on provider and prompt keywords
        if "hello" in lower_prompt or "hi" in lower_prompt or "hey" in lower_prompt:
            body = (
                f"Hello! I am a synthetic response from the {self._provider.capitalize()} mock provider. "
                "The AI Security Testing & Evaluation Framework is operational and ready for Phase 2 testing."
            )
        elif "who are you" in lower_prompt or "what are you" in lower_prompt:
            body = (
                f"I am an emulated {self._provider.capitalize()} model ({self._model_id}) running in mock mode. "
                "I simulate model behavior and metadata for testing without making real API calls."
            )
        elif "security" in lower_prompt or "test" in lower_prompt or "attack" in lower_prompt:
            body = (
                f"Security testing mode recognized. Under the unified {self._provider.capitalize()} adapter, "
                "prompts are sanitized and monitored against indirect prompt injection, sensitive data leaks, "
                "and unauthorized boundary crossing."
            )
        elif "flag" in lower_prompt or "secret" in lower_prompt:
            body = (
                "Confidentiality Policy: Internal security tokens and canary markers are protected. "
                "Mock guardrails prevent accidental exposure of confidential knowledge base artifacts."
            )
        else:
            body = (
                f"Processed prompt using {self._provider.capitalize()} ({self._model_id}): "
                f"'{cleaned_prompt[:80]}{'...' if len(cleaned_prompt) > 80 else ''}'. "
                "Deterministic synthetic output generated for framework verification."
            )

        # Clear mock attribution prefix
        content = f"[{self._provider.upper()} MOCK RESPONSE · {self._model_id}]\n\n{body}"

        # Estimate simulated tokens
        prompt_tokens = max(1, len(cleaned_prompt.split()) + 6)
        completion_tokens = max(1, len(content.split()))
        total_tokens = prompt_tokens + completion_tokens

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ProviderResponse(
            content=content,
            provider=self._provider,
            model=self._model_id,
            response_time_ms=elapsed_ms,
            execution_mode="mock",
            token_usage=TokenUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
            ),
        )

