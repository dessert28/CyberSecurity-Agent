"""Fail-closed in-process runner for allowlisted source-analysis handlers."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID

from cyber_agent.contracts.common import ErrorCategory, ErrorInfo
from cyber_agent.contracts.tool import (
    ExecutionRequest,
    NetworkMode,
    RawExecutionResult,
    RunnerType,
    ToolResultStatus,
)

ArtifactReader = Callable[[UUID], Awaitable[bytes]]
_STABLE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")


class SourceAnalysisHandler(Protocol):
    async def __call__(self, request: ExecutionRequest, source_zip: bytes) -> bytes: ...


class SourceWorkerGuard(Protocol):
    async def run(self, request: ExecutionRequest, source_zip: bytes) -> bytes: ...

    async def cancel(self, request_id: UUID) -> None: ...

    async def health_check(self) -> bool: ...


class SourceAnalysisExecutionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SourceAnalysisRunner:
    """Execute only registered Python handlers; never spawn or import target code."""

    def __init__(
        self,
        *,
        artifact_reader: ArtifactReader,
        handlers: Mapping[str, SourceAnalysisHandler] | None = None,
        worker_guard: SourceWorkerGuard | None = None,
    ) -> None:
        if not callable(artifact_reader):
            raise TypeError("artifact_reader must be callable")
        if (handlers is None) == (worker_guard is None):
            raise ValueError("configure exactly one source handler mode")
        if handlers is not None and (
            not handlers
            or any(not key or not callable(value) for key, value in handlers.items())
        ):
            raise ValueError("source-analysis handlers must be a non-empty callable mapping")
        self._artifact_reader = artifact_reader
        self._handlers = dict(handlers or {})
        self._worker_guard = worker_guard
        self._active: dict[UUID, asyncio.Task[RawExecutionResult] | None] = {}

    async def execute(self, request: ExecutionRequest) -> RawExecutionResult:
        started = datetime.now(timezone.utc)
        current = asyncio.current_task()
        self._active[request.request_id] = current
        try:
            self._validate_request(request)
            handler = self._handlers.get(request.entrypoint[0])
            if self._worker_guard is None and handler is None:
                raise SourceAnalysisExecutionError(
                    "SOURCE_ANALYSIS_HANDLER_DENIED",
                    "Requested source-analysis handler is not registered.",
                )
            mount = request.mounts[0]
            source_zip = await self._artifact_reader(mount.artifact_id)
            if not isinstance(source_zip, bytes):
                raise SourceAnalysisExecutionError(
                    "SOURCE_ANALYSIS_ARTIFACT_INVALID",
                    "Trusted artifact reader returned an invalid content type.",
                )
            if self._worker_guard is not None:
                stdout = await self._worker_guard.run(request, bytes(source_zip))
            else:
                assert handler is not None
                stdout = await asyncio.wait_for(
                    handler(request, bytes(source_zip)),
                    timeout=request.timeout_seconds,
                )
            if not isinstance(stdout, bytes):
                raise SourceAnalysisExecutionError(
                    "SOURCE_ANALYSIS_OUTPUT_INVALID",
                    "Source-analysis handler returned an invalid output type.",
                )
            if len(stdout) > request.resources.max_output_bytes:
                raise SourceAnalysisExecutionError(
                    "SOURCE_ANALYSIS_OUTPUT_LIMIT",
                    "Source-analysis output exceeded its configured limit.",
                )
            return RawExecutionResult(
                request_id=request.request_id,
                status=ToolResultStatus.SUCCEEDED,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                exit_code=0,
                stdout=stdout,
            )
        except TimeoutError:
            return self._error_result(
                request,
                started,
                ToolResultStatus.TIMED_OUT,
                "SOURCE_ANALYSIS_TIMEOUT",
                ErrorCategory.TOOL_FAILED,
                "Source analysis exceeded its controlled timeout.",
            )
        except asyncio.CancelledError:
            return self._error_result(
                request,
                started,
                ToolResultStatus.CANCELLED,
                "SOURCE_ANALYSIS_CANCELLED",
                ErrorCategory.TOOL_FAILED,
                "Source analysis was cancelled.",
            )
        except SourceAnalysisExecutionError as exc:
            return self._error_result(
                request,
                started,
                ToolResultStatus.FAILED,
                exc.code,
                ErrorCategory.TOOL_FAILED,
                str(exc),
            )
        except Exception as exc:
            code = getattr(exc, "code", None)
            if isinstance(code, str) and _STABLE_CODE.fullmatch(code):
                return self._error_result(
                    request,
                    started,
                    (
                        ToolResultStatus.TIMED_OUT
                        if code == "SOURCE_ANALYSIS_TIMEOUT"
                        else ToolResultStatus.FAILED
                    ),
                    code,
                    ErrorCategory.TOOL_FAILED,
                    str(exc),
                )
            return self._error_result(
                request,
                started,
                ToolResultStatus.EXECUTOR_ERROR,
                "SOURCE_ANALYSIS_INTERNAL_ERROR",
                ErrorCategory.SYSTEM_ERROR,
                "Source analysis failed inside the controlled runner.",
            )
        finally:
            self._active.pop(request.request_id, None)

    async def cancel(self, request_id: UUID) -> None:
        if self._worker_guard is not None:
            await self._worker_guard.cancel(request_id)
            return
        task = self._active.get(request_id)
        if task is not None:
            task.cancel()

    async def health_check(self) -> bool:
        if self._worker_guard is None:
            return False
        try:
            return bool(await self._worker_guard.health_check())
        except Exception:
            return False

    def _validate_request(self, request: ExecutionRequest) -> None:
        if request.runner is not RunnerType.SOURCE_ANALYSIS:
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_RUNNER_MISMATCH",
                "SourceAnalysisRunner accepts only SOURCE_ANALYSIS requests.",
            )
        if request.image is not None:
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_IMAGE_DENIED",
                "Source analysis does not accept an execution image.",
            )
        if request.network_policy.mode is not NetworkMode.NONE:
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_NETWORK_DENIED",
                "Source analysis requires network mode NONE.",
            )
        if request.environment:
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_ENVIRONMENT_DENIED",
                "Source analysis does not accept environment variables.",
            )
        if request.resources.max_processes != 1:
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_PROCESS_LIMIT_INVALID",
                "Source analysis requires a single-process limit.",
            )
        if len(request.entrypoint) != 1:
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_ENTRYPOINT_DENIED",
                "Source analysis requires one registered entrypoint token.",
            )
        if len(request.mounts) != 1:
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_MOUNT_DENIED",
                "Source analysis requires exactly one source archive mount.",
            )
        mount = request.mounts[0]
        if mount.container_path != "/inputs/source.zip" or mount.read_only is not True:
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_MOUNT_DENIED",
                "Source analysis accepts only the fixed read-only source archive.",
            )

    @staticmethod
    def _error_result(
        request: ExecutionRequest,
        started: datetime,
        status: ToolResultStatus,
        code: str,
        category: ErrorCategory,
        message: str,
    ) -> RawExecutionResult:
        return RawExecutionResult(
            request_id=request.request_id,
            status=status,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            error=ErrorInfo(
                code=code,
                category=category,
                retryable=False,
                safe_message=message,
            ),
        )


__all__ = [
    "ArtifactReader",
    "SourceAnalysisExecutionError",
    "SourceAnalysisHandler",
    "SourceAnalysisRunner",
    "SourceWorkerGuard",
]
