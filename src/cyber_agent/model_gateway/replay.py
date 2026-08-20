"""Replay adapter backed by saved, structured model responses."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

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


class ReplayModelAdapter:
    """Serve recorded structured data by model-call purpose."""

    def __init__(self, entries: Sequence[Mapping[str, Any]]) -> None:
        self._entries: dict[ModelPurpose, dict[str, Any]] = {}
        for raw_entry in entries:
            entry = deepcopy(dict(raw_entry))
            purpose = ModelPurpose(entry.pop("purpose"))
            self._entries.setdefault(purpose, entry)

    @classmethod
    def from_path(cls, path: str | Path) -> "ReplayModelAdapter":
        replay_path = Path(path)
        text = replay_path.read_text(encoding="utf-8")
        if replay_path.suffix.lower() == ".jsonl":
            entries = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            entries = json.loads(text)
        if not isinstance(entries, list):
            raise ValueError("replay files must contain a JSON array or JSONL records")
        return cls(entries)

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        entry = self._entries.get(request.purpose)
        if entry is None:
            raise CyberAgentError(
                ErrorInfo(
                    code="REPLAY_RESPONSE_MISSING",
                    category=ErrorCategory.SYSTEM_ERROR,
                    retryable=False,
                    safe_message="No replay response is available for this model purpose.",
                )
            )
        data = deepcopy(entry.get("data"))
        if not isinstance(data, dict):
            raise ValueError("replay entry data must be a JSON object")
        try:
            validate_json_schema(data, request.output_schema)
        except JsonSchemaViolation as exc:
            raise CyberAgentError(
                ErrorInfo(
                    code="MODEL_SCHEMA_INVALID",
                    category=ErrorCategory.MODEL_SCHEMA_INVALID,
                    retryable=False,
                    safe_message="The replay response failed schema validation.",
                )
            ) from exc
        canonical = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        usage = ModelUsage.model_validate(
            entry.get("usage", {"input_tokens": 0, "output_tokens": 0})
        )
        return ModelResponse(
            request_id=request.request_id,
            provider=entry.get("provider", "replay"),
            model=entry.get("model", "replay-model"),
            data=data,
            usage=usage,
            latency_ms=int(entry.get("latency_ms", 0)),
            finish_reason=entry.get("finish_reason", "stop"),
            provider_request_id=entry.get(
                "provider_request_id", f"replay-{request.purpose.value}"
            ),
            raw_response_hash=entry.get(
                "raw_response_hash",
                hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            ),
            schema_valid=True,
        )

    async def health_check(self) -> ModelHealth:
        return ModelHealth(available=True, provider="replay", model="recorded")

    def get_capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            provider="replay",
            model="recorded",
            structured_output=True,
            vision=False,
            max_context_tokens=1_000_000,
        )
