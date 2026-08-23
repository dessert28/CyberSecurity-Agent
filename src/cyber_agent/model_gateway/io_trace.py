"""In-memory full-body tracing for beta model I/O diagnostics."""

from __future__ import annotations

import threading
from copy import deepcopy
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field

from cyber_agent.contracts.common import StrictModel, UtcDateTime


class ModelIoOperation(str, Enum):
    GENERATE_STRUCTURED = "generate_structured"
    PROBE_REPLY = "probe_reply"


class ModelIoStage(str, Enum):
    INITIAL = "initial"
    REPAIR = "repair"
    RETRY = "retry"


class ModelIoStatus(str, Enum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ModelIoAttempt(StrictModel):
    attempt_no: int = Field(ge=1)
    stage: ModelIoStage
    retry_index: int = Field(ge=0)
    request_body: dict[str, Any]
    response_body: str | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    latency_ms: int = Field(ge=0)
    schema_valid: bool | None = None
    error: str | None = None


class ModelIoTrace(StrictModel):
    trace_id: UUID = Field(default_factory=uuid4)
    started_at: UtcDateTime
    finished_at: UtcDateTime | None = None
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=255)
    operation: ModelIoOperation
    purpose: str | None = Field(default=None, max_length=128)
    request_id: UUID | None = None
    status: ModelIoStatus = ModelIoStatus.RUNNING
    total_latency_ms: int = Field(default=0, ge=0)
    error_code: str | None = Field(default=None, max_length=128)
    attempts: list[ModelIoAttempt] = Field(default_factory=list)


class ModelIoTraceSummary(StrictModel):
    trace_id: UUID
    started_at: UtcDateTime
    finished_at: UtcDateTime | None = None
    provider: str
    model: str
    operation: ModelIoOperation
    purpose: str | None = None
    status: ModelIoStatus
    total_latency_ms: int
    error_code: str | None = None
    attempt_count: int = Field(ge=0)


class ModelIoTraceStore:
    """Keep a bounded newest-first view of complete logical model calls."""

    def __init__(self, *, capacity: int = 100) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._order: deque[UUID] = deque()
        self._traces: dict[UUID, ModelIoTrace] = {}
        self._lock = threading.RLock()

    def begin(
        self,
        *,
        provider: str,
        model: str,
        operation: ModelIoOperation,
        purpose: str | None = None,
        request_id: UUID | None = None,
    ) -> UUID:
        trace = ModelIoTrace(
            started_at=datetime.now(timezone.utc),
            provider=provider,
            model=model,
            operation=operation,
            purpose=purpose,
            request_id=request_id,
        )
        with self._lock:
            self._order.append(trace.trace_id)
            self._traces[trace.trace_id] = trace
            while len(self._order) > self._capacity:
                self._traces.pop(self._order.popleft(), None)
        return trace.trace_id

    def append_attempt(
        self,
        trace_id: UUID,
        *,
        stage: ModelIoStage,
        retry_index: int,
        request_body: dict[str, Any],
        response_body: str | None,
        http_status: int | None,
        latency_ms: int,
        error: str | None = None,
    ) -> int:
        with self._lock:
            trace = self._require(trace_id)
            attempt_no = len(trace.attempts) + 1
            trace.attempts.append(
                ModelIoAttempt(
                    attempt_no=attempt_no,
                    stage=stage,
                    retry_index=retry_index,
                    request_body=deepcopy(request_body),
                    response_body=response_body,
                    http_status=http_status,
                    latency_ms=latency_ms,
                    error=error,
                )
            )
            return attempt_no

    def set_validation(
        self,
        trace_id: UUID,
        attempt_no: int,
        *,
        schema_valid: bool,
        error: str | None = None,
    ) -> None:
        with self._lock:
            trace = self._require(trace_id)
            if not 1 <= attempt_no <= len(trace.attempts):
                raise KeyError(f"unknown model I/O attempt {attempt_no}")
            attempt = trace.attempts[attempt_no - 1]
            attempt.schema_valid = schema_valid
            attempt.error = error

    def finish(
        self,
        trace_id: UUID,
        *,
        status: ModelIoStatus,
        error_code: str | None = None,
    ) -> None:
        if status is ModelIoStatus.RUNNING:
            raise ValueError("a finished trace requires a final status")
        with self._lock:
            trace = self._require(trace_id)
            trace.status = status
            trace.error_code = error_code
            trace.finished_at = datetime.now(timezone.utc)
            trace.total_latency_ms = sum(item.latency_ms for item in trace.attempts)

    def get(self, trace_id: UUID) -> ModelIoTrace:
        with self._lock:
            return self._require(trace_id).model_copy(deep=True)

    def snapshot(self) -> tuple[ModelIoTraceSummary, ...]:
        with self._lock:
            return tuple(
                ModelIoTraceSummary(
                    trace_id=trace.trace_id,
                    started_at=trace.started_at,
                    finished_at=trace.finished_at,
                    provider=trace.provider,
                    model=trace.model,
                    operation=trace.operation,
                    purpose=trace.purpose,
                    status=trace.status,
                    total_latency_ms=trace.total_latency_ms,
                    error_code=trace.error_code,
                    attempt_count=len(trace.attempts),
                )
                for trace_id in reversed(self._order)
                if (trace := self._traces.get(trace_id)) is not None
            )

    def clear(self) -> int:
        with self._lock:
            count = len(self._traces)
            self._traces.clear()
            self._order.clear()
            return count

    def _require(self, trace_id: UUID) -> ModelIoTrace:
        trace = self._traces.get(trace_id)
        if trace is None:
            raise KeyError(f"unknown model I/O trace {trace_id}")
        return trace


__all__ = [
    "ModelIoAttempt",
    "ModelIoOperation",
    "ModelIoStage",
    "ModelIoStatus",
    "ModelIoTrace",
    "ModelIoTraceStore",
    "ModelIoTraceSummary",
]
