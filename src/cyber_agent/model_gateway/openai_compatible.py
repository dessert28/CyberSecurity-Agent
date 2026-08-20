"""Bounded OpenAI-compatible adapter for explicit non-Kimi profiles."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx

from cyber_agent.contracts.common import ErrorCategory
from cyber_agent.contracts.errors import CyberAgentError
from cyber_agent.contracts.model import (
    ModelCapabilities,
    ModelHealth,
    ModelRequest,
    ModelResponse,
    ModelUsage,
)
from cyber_agent.model_gateway._schema import JsonSchemaViolation

from .kimi import _error, _extract_data, _safe_message_content

logger = logging.getLogger(__name__)


class StructuredOutputMode(str, Enum):
    JSON_SCHEMA = "json_schema"
    JSON_OBJECT = "json_object"


@dataclass(frozen=True, slots=True)
class OpenAICompatibleConfig:
    provider: str
    base_url: str
    model: str
    structured_output_mode: StructuredOutputMode = StructuredOutputMode.JSON_OBJECT
    api_key_env: str = "MODEL_API_KEY"
    timeout_seconds: float = 60.0
    max_retries: int = 2
    initial_backoff_seconds: float = 0.5
    max_context_tokens: int = 262_144

    def __post_init__(self) -> None:
        if self.provider not in {"deepseek", "openai_compatible"}:
            raise ValueError("provider must be deepseek or openai_compatible")
        if not self.base_url.startswith("https://"):
            raise ValueError("base_url must use HTTPS")
        if not self.model.strip():
            raise ValueError("model must not be empty")
        if not self.api_key_env or "=" in self.api_key_env:
            raise ValueError("api_key_env must be an environment variable name")
        if not 0 < self.timeout_seconds <= 600:
            raise ValueError("timeout_seconds must be between 0 and 600")
        if not 0 <= self.max_retries <= 5:
            raise ValueError("max_retries must be between 0 and 5")
        if not 0 <= self.initial_backoff_seconds <= 60:
            raise ValueError("initial_backoff_seconds must be between 0 and 60")


class OpenAICompatibleAdapter:
    """Use strict schema or JSON Object mode with one local repair attempt."""

    def __init__(
        self,
        config: OpenAICompatibleConfig,
        *,
        client: httpx.AsyncClient | None = None,
        environment: Mapping[str, str] | None = None,
        request_guard: Callable[[], None] | None = None,
    ) -> None:
        self._config = config
        self._environment = os.environ if environment is None else environment
        self._client = client or httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        )
        self._request_guard = request_guard

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        api_key = self._api_key()
        if api_key is None:
            raise _error(
                "MODEL_API_KEY_MISSING",
                ErrorCategory.SYSTEM_ERROR,
                "The configured model credential is unavailable.",
            )
        payload = self._payload(request)
        raw, body, latency_ms = await self._post_with_retries(payload, request, api_key)
        try:
            data = _extract_data(body, request.output_schema)
        except (JsonSchemaViolation, ValueError, KeyError, TypeError):
            repair = self._repair_payload(request, body)
            raw, body, repair_latency = await self._post_with_retries(repair, request, api_key)
            latency_ms += repair_latency
            try:
                data = _extract_data(body, request.output_schema)
            except (JsonSchemaViolation, ValueError, KeyError, TypeError) as exc:
                raise _error(
                    "MODEL_SCHEMA_INVALID",
                    ErrorCategory.MODEL_SCHEMA_INVALID,
                    "The model response remained invalid after one schema repair attempt.",
                ) from exc
        usage = body.get("usage") or {}
        logger.debug(
            "Compatible structured model call completed request_id=%s purpose=%s",
            request.request_id,
            request.purpose.value,
        )
        return ModelResponse(
            request_id=request.request_id,
            provider=self._config.provider,
            model=str(body.get("model") or self._config.model),
            data=data,
            usage=ModelUsage(
                input_tokens=int(usage.get("prompt_tokens", 0)),
                output_tokens=int(usage.get("completion_tokens", 0)),
                cached_input_tokens=int(
                    (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
                ),
            ),
            latency_ms=latency_ms,
            finish_reason=str(body["choices"][0].get("finish_reason") or "unknown"),
            provider_request_id=str(body.get("id") or "unknown"),
            raw_response_hash=hashlib.sha256(raw).hexdigest(),
            schema_valid=True,
        )

    async def health_check(self) -> ModelHealth:
        api_key = self._api_key()
        if api_key is None:
            return ModelHealth(
                available=False,
                provider=self._config.provider,
                model=self._config.model,
                message="model credential unavailable",
            )
        try:
            self._enforce_request_guard()
            response = await self._client.get(
                f"{self._config.base_url.rstrip('/')}/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=self._config.timeout_seconds,
            )
            available = response.status_code < 400
        except (CyberAgentError, httpx.HTTPError):
            available = False
        return ModelHealth(
            available=available,
            provider=self._config.provider,
            model=self._config.model,
            message="available" if available else "model endpoint unavailable",
        )

    def get_capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            provider=self._config.provider,
            model=self._config.model,
            structured_output=True,
            vision=False,
            max_context_tokens=self._config.max_context_tokens,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def _api_key(self) -> str | None:
        value = self._environment.get(self._config.api_key_env)
        return value if value else None

    def _payload(self, request: ModelRequest) -> dict[str, Any]:
        system = request.system_instructions
        if self._config.structured_output_mode is StructuredOutputMode.JSON_OBJECT:
            schema_text = json.dumps(
                request.output_schema,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            system = (
                f"{system}\nReturn only one JSON object matching this JSON Schema: {schema_text}"
            )
            response_format: dict[str, Any] = {"type": "json_object"}
        else:
            response_format = {
                "type": "json_schema",
                "json_schema": {
                    "name": f"{request.purpose.value}_response",
                    "strict": True,
                    "schema": request.output_schema,
                },
            }
        payload: dict[str, Any] = {
            "model": self._config.model,
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": json.dumps(
                        request.context,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                },
            ],
            "response_format": response_format,
            "max_tokens": request.max_output_tokens,
        }
        if self._config.provider == "deepseek":
            payload["reasoning_effort"] = (
                "high" if request.reasoning_effort.value in {"high", "max"} else "low"
            )
        return payload

    def _repair_payload(
        self,
        request: ModelRequest,
        invalid_body: Mapping[str, Any],
    ) -> dict[str, Any]:
        payload = self._payload(request)
        payload["messages"].extend(
            [
                {"role": "assistant", "content": _safe_message_content(invalid_body)},
                {
                    "role": "user",
                    "content": (
                        "Repair the preceding answer once. Return only a JSON object "
                        "that satisfies the requested schema; do not add commentary."
                    ),
                },
            ]
        )
        return payload

    async def _post_with_retries(
        self,
        payload: dict[str, Any],
        request: ModelRequest,
        api_key: str,
    ) -> tuple[bytes, dict[str, Any], int]:
        last_error: CyberAgentError | None = None
        for attempt in range(self._config.max_retries + 1):
            started = time.perf_counter()
            try:
                self._enforce_request_guard()
                response = await self._client.post(
                    f"{self._config.base_url.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=min(request.timeout_seconds, self._config.timeout_seconds),
                )
                latency_ms = max(0, int((time.perf_counter() - started) * 1000))
                error_type = _response_error_type(response)
                if response.status_code in {401, 403}:
                    raise _error(
                        "MODEL_AUTH_FAILED",
                        ErrorCategory.INPUT_INVALID,
                        "The model service rejected the configured credential.",
                    )
                if response.status_code == 402 or error_type == "exceeded_current_quota_error":
                    raise _error(
                        "MODEL_QUOTA_EXCEEDED",
                        ErrorCategory.MODEL_TRANSIENT,
                        "The model service quota or balance is unavailable.",
                        retryable=False,
                    )
                if response.status_code == 429:
                    last_error = _error(
                        "MODEL_RATE_LIMITED",
                        ErrorCategory.MODEL_TRANSIENT,
                        "The model service rate-limited the request.",
                        retryable=True,
                    )
                elif response.status_code >= 500:
                    last_error = _error(
                        "MODEL_SERVER_ERROR",
                        ErrorCategory.MODEL_TRANSIENT,
                        "The model service returned a temporary server error.",
                        retryable=True,
                    )
                elif response.status_code >= 400:
                    raise _error(
                        "MODEL_REQUEST_REJECTED",
                        ErrorCategory.INPUT_INVALID,
                        "The model service rejected the request.",
                    )
                else:
                    body = response.json()
                    if not isinstance(body, dict):
                        raise ValueError("model response body must be a JSON object")
                    return response.content, body, latency_ms
            except httpx.TimeoutException:
                last_error = _error(
                    "MODEL_TIMEOUT",
                    ErrorCategory.MODEL_TRANSIENT,
                    "The model request timed out.",
                    retryable=True,
                )
            except httpx.TransportError:
                last_error = _error(
                    "MODEL_NETWORK_ERROR",
                    ErrorCategory.MODEL_TRANSIENT,
                    "The model service could not be reached.",
                    retryable=True,
                )
            except (json.JSONDecodeError, ValueError) as exc:
                raise _error(
                    "MODEL_PROTOCOL_ERROR",
                    ErrorCategory.SYSTEM_ERROR,
                    "The model service returned an invalid protocol response.",
                ) from exc
            if attempt < self._config.max_retries:
                delay = self._config.initial_backoff_seconds * (2**attempt)
                if delay:
                    await asyncio.sleep(delay)
        if last_error is None:
            raise RuntimeError("model retry loop terminated without an error")
        raise last_error

    def _enforce_request_guard(self) -> None:
        if self._request_guard is None:
            return
        try:
            self._request_guard()
        except CyberAgentError:
            raise
        except Exception as exc:
            raise _error(
                "MODEL_ENDPOINT_POLICY_DENIED",
                ErrorCategory.POLICY_DENIED,
                "The model endpoint no longer satisfies the approved endpoint policy.",
            ) from exc


def _response_error_type(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(body, dict):
        return None
    error = body.get("error")
    if not isinstance(error, dict):
        return None
    value = error.get("type")
    return value if isinstance(value, str) else None


__all__ = [
    "OpenAICompatibleAdapter",
    "OpenAICompatibleConfig",
    "StructuredOutputMode",
]
