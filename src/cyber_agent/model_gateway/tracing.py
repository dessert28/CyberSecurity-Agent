"""Run-level tracing decorator for real provider model calls."""

from __future__ import annotations

import hashlib
import json
import threading
from uuid import UUID

from cyber_agent.contracts.model import (
    ModelCallRef,
    ModelCallStatus,
    ModelCapabilities,
    ModelHealth,
    ModelRequest,
    ModelResponse,
)
from cyber_agent.contracts.ports import ModelGateway


class ModelCallCollector:
    """Process-local collector containing only strict, secret-free references."""

    def __init__(self) -> None:
        self._refs: list[ModelCallRef] = []
        self._lock = threading.RLock()

    def begin(self, ref: ModelCallRef) -> None:
        if ref.status is not ModelCallStatus.SUBMITTED:
            raise ValueError("a collected model call must begin as submitted")
        with self._lock:
            if any(item.model_call_id == ref.model_call_id for item in self._refs):
                raise ValueError("model call reference already exists")
            self._refs.append(ref.model_copy(deep=True))

    def finish(self, ref: ModelCallRef) -> None:
        if ref.status not in {ModelCallStatus.SUCCEEDED, ModelCallStatus.FAILED}:
            raise ValueError("a completed model call requires a final status")
        with self._lock:
            for index, existing in enumerate(self._refs):
                if existing.model_call_id != ref.model_call_id:
                    continue
                if existing.status is not ModelCallStatus.SUBMITTED:
                    raise ValueError("model call reference is already final")
                self._refs[index] = ref.model_copy(deep=True)
                return
        raise ValueError("submitted model call reference was not found")

    def snapshot(self) -> tuple[ModelCallRef, ...]:
        with self._lock:
            return tuple(item.model_copy(deep=True) for item in self._refs)


class TracingModelGateway:
    """Delegate one real call unchanged while collecting only hashed metadata."""

    def __init__(
        self,
        *,
        delegate: ModelGateway,
        collector: ModelCallCollector,
        run_id: UUID,
        provider: str,
        model_id: str,
    ) -> None:
        if not isinstance(delegate, ModelGateway):
            raise TypeError("delegate does not implement ModelGateway")
        if not isinstance(collector, ModelCallCollector):
            raise TypeError("collector must be a ModelCallCollector")
        self._delegate = delegate
        self._collector = collector
        self._run_id = run_id
        self._provider = provider
        self._model_id = model_id

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        submitted = ModelCallRef(
            run_id=self._run_id,
            provider=self._provider,
            model_id=self._model_id,
            purpose=request.purpose,
            status=ModelCallStatus.SUBMITTED,
            request_id=request.request_id,
            request_hash=_request_hash(request),
        )
        self._collector.begin(submitted)
        try:
            response = await self._delegate.generate_structured(request)
        except BaseException:
            try:
                self._collector.finish(
                    _transition(submitted, status=ModelCallStatus.FAILED)
                )
            except Exception:
                # Tracing infrastructure must never replace the provider's exception.
                pass
            raise
        self._collector.finish(
            _transition(
                submitted,
                status=ModelCallStatus.SUCCEEDED,
                response_id=response.response_id,
                response_hash=response.raw_response_hash,
            )
        )
        return response

    async def health_check(self) -> ModelHealth:
        return await self._delegate.health_check()

    def get_capabilities(self) -> ModelCapabilities:
        return self._delegate.get_capabilities()

    async def aclose(self) -> None:
        close = getattr(self._delegate, "aclose", None)
        if callable(close):
            await close()


def _request_hash(request: ModelRequest) -> str:
    payload = {
        "hash_contract": "model-request/v1",
        "request": request.model_dump(mode="json"),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _transition(
    submitted: ModelCallRef,
    *,
    status: ModelCallStatus,
    response_id: UUID | None = None,
    response_hash: str | None = None,
) -> ModelCallRef:
    payload = submitted.model_dump(mode="python")
    payload.update(
        status=status,
        response_id=response_id,
        response_hash=response_hash,
    )
    return ModelCallRef.model_validate(payload)


__all__ = ["ModelCallCollector", "TracingModelGateway"]
