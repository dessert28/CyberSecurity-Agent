"""Deterministic model adapter for tests and offline integration."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from copy import deepcopy

from cyber_agent.contracts.common import ErrorCategory, ErrorInfo
from cyber_agent.contracts.errors import CyberAgentError
from cyber_agent.contracts.model import (
    ModelCapabilities,
    ModelHealth,
    ModelPurpose,
    ModelRequest,
    ModelResponse,
    ModelUsage,
)

from ._schema import JsonSchemaViolation, validate_json_schema


class FakeModelAdapter:
    """Return purpose-keyed structured fixtures without network access."""

    def __init__(
        self,
        *,
        responses: Mapping[ModelPurpose | str, dict],
        model: str = "fake-model",
    ) -> None:
        self._responses = {
            ModelPurpose(key) if isinstance(key, str) else key: deepcopy(value)
            for key, value in responses.items()
        }
        self._model = model

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        if request.purpose not in self._responses:
            raise _model_error(
                "FAKE_RESPONSE_MISSING",
                ErrorCategory.SYSTEM_ERROR,
                "No deterministic response is configured for this model purpose.",
            )
        data = deepcopy(self._responses[request.purpose])
        try:
            validate_json_schema(data, request.output_schema)
        except JsonSchemaViolation as exc:
            raise _model_error(
                "MODEL_SCHEMA_INVALID",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "The deterministic model response failed schema validation.",
            ) from exc
        canonical = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return ModelResponse(
            request_id=request.request_id,
            provider="fake",
            model=self._model,
            data=data,
            usage=ModelUsage(input_tokens=0, output_tokens=0),
            latency_ms=0,
            finish_reason="stop",
            provider_request_id=f"fake-{request.purpose.value}",
            raw_response_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            schema_valid=True,
        )

    async def health_check(self) -> ModelHealth:
        return ModelHealth(available=True, provider="fake", model=self._model)

    def get_capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            provider="fake",
            model=self._model,
            structured_output=True,
            vision=False,
            max_context_tokens=1_000_000,
        )


def _model_error(
    code: str, category: ErrorCategory, message: str, *, retryable: bool = False
) -> CyberAgentError:
    return CyberAgentError(
        ErrorInfo(
            code=code,
            category=category,
            retryable=retryable,
            safe_message=message,
        )
    )
