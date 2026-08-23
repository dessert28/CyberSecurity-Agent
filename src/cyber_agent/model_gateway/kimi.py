"""Kimi K3 adapter using the provider's OpenAI-compatible HTTP surface."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import httpx

from cyber_agent.contracts.common import ErrorCategory, ErrorInfo
from cyber_agent.contracts.errors import CyberAgentError
from cyber_agent.contracts.model import (
    ModelCapabilities,
    ModelHealth,
    ModelPurpose,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ReasoningEffort,
)

from ._schema import JsonSchemaViolation, validate_json_schema
from .io_trace import (
    ModelIoOperation,
    ModelIoStage,
    ModelIoStatus,
    ModelIoTraceStore,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class KimiK3Config:
    """Non-secret adapter configuration; the key is referenced by env-var name."""

    base_url: str
    model: str
    provider: str = "kimi"
    api_key_env: str = "KIMI_API_KEY"
    timeout_seconds: float = 60.0
    max_retries: int = 2
    initial_backoff_seconds: float = 0.5
    reasoning_effort_map: Mapping[str, str] = field(
        default_factory=lambda: {"low": "low", "high": "high", "max": "high"}
    )
    max_context_tokens: int = 262_144
    strict_schema: bool = True

    def __post_init__(self) -> None:
        if self.provider != "kimi":
            raise ValueError("provider must be kimi for KimiK3Config")
        if not self.base_url.startswith(("https://", "http://")):
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if not self.model.strip():
            raise ValueError("model must not be empty")
        if not self.api_key_env or "=" in self.api_key_env:
            raise ValueError("api_key_env must be an environment variable name")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 600:
            raise ValueError("timeout_seconds must be between 0 and 600")
        if self.max_retries < 0 or self.max_retries > 5:
            raise ValueError("max_retries must be between 0 and 5")
        if self.initial_backoff_seconds < 0 or self.initial_backoff_seconds > 60:
            raise ValueError("initial_backoff_seconds must be between 0 and 60")
        if set(self.reasoning_effort_map) != {"low", "high", "max"}:
            raise ValueError("reasoning_effort_map must define low, high, and max")
        if not all(isinstance(value, str) and value for value in self.reasoning_effort_map.values()):
            raise ValueError("reasoning effort mappings must be non-empty strings")
        if not self.strict_schema:
            raise ValueError("KimiK3Adapter requires strict_schema=true")

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "KimiK3Config":
        allowed = {
            "provider",
            "base_url",
            "model",
            "api_key_env",
            "timeout_seconds",
            "timeout",
            "max_retries",
            "initial_backoff_seconds",
            "reasoning_effort_map",
            "max_context_tokens",
            "strict_schema",
        }
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unknown Kimi configuration fields: {', '.join(sorted(unknown))}")
        normalized = dict(values)
        if "timeout" in normalized:
            if "timeout_seconds" in normalized:
                raise ValueError("use only one of timeout or timeout_seconds")
            normalized["timeout_seconds"] = normalized.pop("timeout")
        if "base_url" not in normalized or "model" not in normalized:
            raise ValueError("base_url and model are required")
        return cls(**normalized)


class KimiK3Adapter:
    """Perform bounded, stateless, strict-schema Kimi K3 calls."""

    def __init__(
        self,
        config: KimiK3Config,
        *,
        client: httpx.AsyncClient | None = None,
        environment: Mapping[str, str] | None = None,
        request_guard: Callable[[], None] | None = None,
        trace_store: ModelIoTraceStore | None = None,
    ) -> None:
        self._config = config
        self._environment = os.environ if environment is None else environment
        self._client = client or httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        )
        self._request_guard = request_guard
        self._trace_store = trace_store

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        trace_id = self._trace_begin(
            operation=ModelIoOperation.GENERATE_STRUCTURED,
            purpose=request.purpose.value,
            request_id=request.request_id,
        )
        try:
            api_key = self._api_key()
            if api_key is None:
                raise _error(
                    "MODEL_API_KEY_MISSING",
                    ErrorCategory.SYSTEM_ERROR,
                    f"The configured API key environment variable {self._config.api_key_env} is not set.",
                )

            payload = self._payload(request)
            raw, body, latency_ms, attempt_no = await self._post_with_retries(
                payload,
                request,
                api_key,
                trace_id=trace_id,
                stage=ModelIoStage.INITIAL,
            )
            try:
                data = _extract_data(body, request.output_schema)
            except (JsonSchemaViolation, ValueError, KeyError, TypeError) as first_error:
                self._trace_validation(trace_id, attempt_no, False, str(first_error))
                repair_payload = self._repair_payload(request, body)
                raw, body, repair_latency, attempt_no = await self._post_with_retries(
                    repair_payload,
                    request,
                    api_key,
                    trace_id=trace_id,
                    stage=ModelIoStage.REPAIR,
                )
                latency_ms += repair_latency
                try:
                    data = _extract_data(body, request.output_schema)
                except (JsonSchemaViolation, ValueError, KeyError, TypeError) as exc:
                    self._trace_validation(trace_id, attempt_no, False, str(exc))
                    raise _error(
                        "MODEL_SCHEMA_INVALID",
                        ErrorCategory.MODEL_SCHEMA_INVALID,
                        "The model response remained invalid after one schema repair attempt.",
                    ) from exc
                self._trace_validation(trace_id, attempt_no, True)
            else:
                self._trace_validation(trace_id, attempt_no, True)

            usage_data = body.get("usage") or {}
            prompt_details = usage_data.get("prompt_tokens_details") or {}
            logger.debug(
                "Structured model call completed request_id=%s purpose=%s",
                request.request_id,
                request.purpose.value,
            )
            result = ModelResponse(
                request_id=request.request_id,
                provider=self._config.provider,
                model=str(body.get("model") or self._config.model),
                data=data,
                usage=ModelUsage(
                    input_tokens=int(usage_data.get("prompt_tokens", 0)),
                    output_tokens=int(usage_data.get("completion_tokens", 0)),
                    cached_input_tokens=int(prompt_details.get("cached_tokens", 0)),
                ),
                latency_ms=latency_ms,
                finish_reason=str(body["choices"][0].get("finish_reason") or "unknown"),
                provider_request_id=str(body.get("id") or "unknown"),
                raw_response_hash=hashlib.sha256(raw).hexdigest(),
                schema_valid=True,
            )
        except BaseException as exc:
            self._trace_finish(trace_id, ModelIoStatus.FAILED, _trace_error_code(exc))
            raise
        self._trace_finish(trace_id, ModelIoStatus.SUCCEEDED)
        return result

    async def probe_reply(self) -> bool:
        """Return whether the provider produced a non-empty final reply."""

        request = _connection_probe_request()
        trace_id = self._trace_begin(operation=ModelIoOperation.PROBE_REPLY)
        try:
            api_key = self._api_key()
            if api_key is None:
                raise _error(
                    "MODEL_API_KEY_MISSING",
                    ErrorCategory.SYSTEM_ERROR,
                    f"The configured API key environment variable {self._config.api_key_env} is not set.",
                )
            _, body, _, _ = await self._post_with_retries(
                self._connection_probe_payload(),
                request,
                api_key,
                trace_id=trace_id,
                stage=ModelIoStage.INITIAL,
            )
            result = _has_nonempty_message_content(body)
        except BaseException as exc:
            self._trace_finish(trace_id, ModelIoStatus.FAILED, _trace_error_code(exc))
            raise
        self._trace_finish(
            trace_id,
            ModelIoStatus.SUCCEEDED if result else ModelIoStatus.FAILED,
            None if result else "MODEL_REPLY_EMPTY",
        )
        return result

    async def health_check(self) -> ModelHealth:
        api_key = self._api_key()
        if api_key is None:
            return ModelHealth(
                available=False,
                provider=self._config.provider,
                model=self._config.model,
                message=(
                    f"API key environment variable {self._config.api_key_env} is not set."
                ),
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
        system_instructions = (
            f"{request.system_instructions}\n"
            "Return exactly one raw JSON object matching the requested schema. "
            "Do not use Markdown code fences, explanations, or additional fields."
        )
        return {
            "model": self._config.model,
            "messages": [
                {"role": "system", "content": system_instructions},
                {
                    "role": "user",
                    "content": json.dumps(
                        request.context, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                    ),
                },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": f"{request.purpose.value}_response",
                    "strict": True,
                    "schema": request.output_schema,
                },
            },
            "reasoning_effort": self._config.reasoning_effort_map[
                request.reasoning_effort.value
            ],
            "max_tokens": request.max_output_tokens,
        }

    def _connection_probe_payload(self) -> dict[str, Any]:
        return {
            "model": self._config.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Reply with a short non-empty message. Do not call tools.",
                },
                {"role": "user", "content": "connection probe"},
            ],
            "max_tokens": 16,
        }

    def _repair_payload(
        self, request: ModelRequest, invalid_body: Mapping[str, Any]
    ) -> dict[str, Any]:
        payload = self._payload(request)
        invalid_content = _safe_message_content(invalid_body)
        payload["messages"].extend(
            [
                {"role": "assistant", "content": invalid_content},
                {
                    "role": "user",
                    "content": (
                        "Repair the preceding answer once. Return exactly one raw JSON object "
                        "that satisfies the requested schema. Do not use Markdown code fences, "
                        "explanations, or additional fields."
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
        *,
        trace_id: UUID | None,
        stage: ModelIoStage,
    ) -> tuple[bytes, dict[str, Any], int, int | None]:
        last_error: CyberAgentError | None = None
        for attempt in range(self._config.max_retries + 1):
            started = time.perf_counter()
            attempt_no: int | None = None
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
                error_code = _http_error_code(response.status_code)
                attempt_no = self._trace_attempt(
                    trace_id,
                    stage=stage if attempt == 0 else ModelIoStage.RETRY,
                    retry_index=attempt,
                    request_body=payload,
                    response_body=response.text,
                    http_status=response.status_code,
                    latency_ms=latency_ms,
                    error=error_code,
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
                    return response.content, body, latency_ms, attempt_no
            except httpx.TimeoutException:
                latency_ms = max(0, int((time.perf_counter() - started) * 1000))
                self._trace_attempt(
                    trace_id,
                    stage=stage if attempt == 0 else ModelIoStage.RETRY,
                    retry_index=attempt,
                    request_body=payload,
                    response_body=None,
                    http_status=None,
                    latency_ms=latency_ms,
                    error="MODEL_TIMEOUT",
                )
                last_error = _error(
                    "MODEL_TIMEOUT",
                    ErrorCategory.MODEL_TRANSIENT,
                    "The model request timed out.",
                    retryable=True,
                )
            except httpx.TransportError:
                latency_ms = max(0, int((time.perf_counter() - started) * 1000))
                self._trace_attempt(
                    trace_id,
                    stage=stage if attempt == 0 else ModelIoStage.RETRY,
                    retry_index=attempt,
                    request_body=payload,
                    response_body=None,
                    http_status=None,
                    latency_ms=latency_ms,
                    error="MODEL_NETWORK_ERROR",
                )
                last_error = _error(
                    "MODEL_NETWORK_ERROR",
                    ErrorCategory.MODEL_TRANSIENT,
                    "The model service could not be reached.",
                    retryable=True,
                )
            except (json.JSONDecodeError, ValueError) as exc:
                self._trace_validation(trace_id, attempt_no, False, str(exc))
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

    def _trace_begin(
        self,
        *,
        operation: ModelIoOperation,
        purpose: str | None = None,
        request_id: UUID | None = None,
    ) -> UUID | None:
        if self._trace_store is None:
            return None
        try:
            return self._trace_store.begin(
                provider=self._config.provider,
                model=self._config.model,
                operation=operation,
                purpose=purpose,
                request_id=request_id,
            )
        except Exception:
            return None

    def _trace_attempt(self, trace_id: UUID | None, **values: Any) -> int | None:
        if self._trace_store is None or trace_id is None:
            return None
        try:
            return self._trace_store.append_attempt(trace_id, **values)
        except Exception:
            return None

    def _trace_validation(
        self,
        trace_id: UUID | None,
        attempt_no: int | None,
        schema_valid: bool,
        error: str | None = None,
    ) -> None:
        if self._trace_store is None or trace_id is None or attempt_no is None:
            return
        try:
            self._trace_store.set_validation(
                trace_id, attempt_no, schema_valid=schema_valid, error=error
            )
        except Exception:
            pass

    def _trace_finish(
        self,
        trace_id: UUID | None,
        status: ModelIoStatus,
        error_code: str | None = None,
    ) -> None:
        if self._trace_store is None or trace_id is None:
            return
        try:
            self._trace_store.finish(trace_id, status=status, error_code=error_code)
        except Exception:
            pass

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


def _safe_message_content(body: Mapping[str, Any]) -> str:
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return "{}"
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text = _text_content_parts(content)
        if text:
            return text
    return json.dumps(content, ensure_ascii=False)


def _has_nonempty_message_content(body: Mapping[str, Any]) -> bool:
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return False
    if isinstance(content, str):
        return bool(content.strip())
    return isinstance(content, list) and bool(_text_content_parts(content).strip())


def _text_content_parts(content: list[Any]) -> str:
    text_parts: list[str] = []
    for item in content:
        if isinstance(item, str):
            text_parts.append(item)
        elif isinstance(item, Mapping) and isinstance(item.get("text"), str):
            text_parts.append(item["text"])
    return "".join(text_parts)


def _connection_probe_request() -> ModelRequest:
    return ModelRequest(
        purpose=ModelPurpose.TASK_UNDERSTANDING,
        system_instructions="Reply with a short non-empty message.",
        context={"probe": "connection"},
        output_schema={},
        reasoning_effort=ReasoningEffort.LOW,
        max_output_tokens=16,
        timeout_seconds=30,
    )


def _extract_data(body: Mapping[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    content = _normalize_json_content(_safe_message_content(body))
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError("structured model output must be a JSON object")
    validate_json_schema(parsed, schema)
    return parsed


def _normalize_json_content(content: str) -> str:
    normalized = content.strip()
    if not normalized:
        raise ValueError("structured model output is empty")
    if not normalized.startswith("```"):
        return normalized

    lines = normalized.splitlines()
    if len(lines) < 3 or lines[-1].strip() != "```":
        raise ValueError("structured model output has an invalid Markdown code fence")
    language = lines[0][3:].strip().lower()
    if language not in {"", "json"}:
        raise ValueError("structured model output must use a JSON code fence")
    inner = "\n".join(lines[1:-1]).strip()
    if not inner or "```" in inner:
        raise ValueError("structured model output must contain one JSON code fence")
    return inner


def _http_error_code(status_code: int) -> str | None:
    if status_code == 429:
        return "MODEL_RATE_LIMITED"
    if status_code >= 500:
        return "MODEL_SERVER_ERROR"
    if status_code >= 400:
        return "MODEL_REQUEST_REJECTED"
    return None


def _trace_error_code(exc: BaseException) -> str:
    if isinstance(exc, CyberAgentError):
        return exc.error.code
    return type(exc).__name__.upper()


def _error(
    code: str,
    category: ErrorCategory,
    message: str,
    *,
    retryable: bool = False,
) -> CyberAgentError:
    return CyberAgentError(
        ErrorInfo(
            code=code,
            category=category,
            retryable=retryable,
            safe_message=message,
        )
    )
