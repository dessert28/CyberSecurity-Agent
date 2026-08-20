"""Deterministic executor test double; it never starts a host process."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID

from cyber_agent.contracts.common import ErrorCategory, ErrorInfo
from cyber_agent.contracts.tool import ExecutionRequest, RawExecutionResult, RunnerType, ToolResultStatus


class FakeRunner:
    def __init__(
        self,
        *,
        stdout: bytes = b"{}",
        stderr: bytes = b"",
        exit_code: int = 0,
        delay_seconds: float = 0,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._exit_code = exit_code
        self._delay_seconds = delay_seconds
        self._cancellations: dict[UUID, asyncio.Event] = {}

    @property
    def active_request_ids(self) -> tuple[UUID, ...]:
        return tuple(self._cancellations)

    async def execute(self, request: ExecutionRequest) -> RawExecutionResult:
        started = datetime.now(timezone.utc)
        if request.runner is not RunnerType.FAKE:
            return self._result(
                request,
                started=started,
                status=ToolResultStatus.EXECUTOR_ERROR,
                exit_code=None,
                error=self._error(
                    "FAKE_RUNNER_TYPE_MISMATCH",
                    ErrorCategory.SYSTEM_ERROR,
                    "FakeRunner accepts only fake execution requests",
                ),
            )

        cancelled = asyncio.Event()
        self._cancellations[request.request_id] = cancelled
        try:
            if self._delay_seconds > 0:
                try:
                    await asyncio.wait_for(cancelled.wait(), timeout=self._delay_seconds)
                except TimeoutError:
                    pass
            if cancelled.is_set():
                return self._result(
                    request,
                    started=started,
                    status=ToolResultStatus.CANCELLED,
                    exit_code=None,
                    error=self._error(
                        "FAKE_EXECUTION_CANCELLED",
                        ErrorCategory.TOOL_FAILED,
                        "Fake execution was cancelled",
                    ),
                )
            status = ToolResultStatus.SUCCEEDED if self._exit_code == 0 else ToolResultStatus.FAILED
            error = None
            if status is ToolResultStatus.FAILED:
                error = self._error(
                    "FAKE_EXIT_NONZERO",
                    ErrorCategory.TOOL_FAILED,
                    "Fake execution returned a non-zero exit status",
                )
            return self._result(
                request,
                started=started,
                status=status,
                exit_code=self._exit_code,
                stdout=self._stdout,
                stderr=self._stderr,
                error=error,
            )
        finally:
            self._cancellations.pop(request.request_id, None)

    async def cancel(self, request_id: UUID) -> None:
        event = self._cancellations.get(request_id)
        if event is not None:
            event.set()

    @staticmethod
    def _result(
        request: ExecutionRequest,
        *,
        started: datetime,
        status: ToolResultStatus,
        exit_code: int | None,
        stdout: bytes = b"",
        stderr: bytes = b"",
        error: ErrorInfo | None = None,
    ) -> RawExecutionResult:
        return RawExecutionResult(
            request_id=request.request_id,
            status=status,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            error=error,
        )

    @staticmethod
    def _error(code: str, category: ErrorCategory, message: str) -> ErrorInfo:
        return ErrorInfo(
            code=code,
            category=category,
            retryable=False,
            safe_message=message,
        )
