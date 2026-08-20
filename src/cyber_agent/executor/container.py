"""Fail-closed container execution orchestration.

This module intentionally contains no Docker/Podman SDK dependency.  A runtime
adapter must be supplied by the deployment owner; when absent, execution is
unavailable and never falls back to the host.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping, Set
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID

from cyber_agent.contracts.common import ErrorCategory, ErrorInfo
from cyber_agent.contracts.tool import ExecutionRequest, RawExecutionResult, RunnerType, ToolResultStatus


_PERMANENTLY_FORBIDDEN_ENVIRONMENT_KEYS = {
    "DOCKER_HOST",
    "CONTAINER_HOST",
    "KUBECONFIG",
    "LD_PRELOAD",
    "PYTHONPATH",
}
_SHELL_ENTRYPOINTS = {"bash", "sh", "powershell", "pwsh", "cmd", "cmd.exe"}
_PINNED_IMAGE_PATTERN = re.compile(r"^.+@sha256:[0-9a-fA-F]{64}$")


class ContainerRuntime(Protocol):
    async def health_check(self) -> tuple[bool, str]: ...

    async def run(
        self, request: ExecutionRequest, isolation: "ContainerIsolation"
    ) -> RawExecutionResult: ...

    async def cancel(self, request_id: UUID) -> None: ...

    async def cleanup(self, request_id: UUID) -> None: ...


class UnavailableContainerRuntime:
    """Explicit unavailable adapter used when Docker/Podman is not configured."""

    def __init__(self, message: str = "container runtime is not configured") -> None:
        self._message = message

    async def health_check(self) -> tuple[bool, str]:
        return False, self._message

    async def run(
        self, request: ExecutionRequest, isolation: "ContainerIsolation"
    ) -> RawExecutionResult:
        raise RuntimeError(self._message)

    async def cancel(self, request_id: UUID) -> None:
        return None

    async def cleanup(self, request_id: UUID) -> None:
        return None


@dataclass(frozen=True, slots=True)
class ExecutorLimits:
    max_cpu_cores: float = 4
    max_memory_megabytes: int = 2048
    max_processes: int = 128
    max_output_bytes: int = 10_000_000
    max_timeout_seconds: int = 180


@dataclass(frozen=True, slots=True)
class ContainerIsolation:
    """Mandatory settings a Docker/Podman adapter must enforce."""

    run_as_non_root: bool = True
    read_only_root_filesystem: bool = True
    drop_all_capabilities: bool = True
    no_new_privileges: bool = True
    privileged: bool = False
    mount_runtime_socket: bool = False
    share_host_pid: bool = False
    share_host_ipc: bool = False
    share_host_network: bool = False
    ephemeral_output_directory: bool = True


class ContainerExecutor:
    def __init__(
        self,
        runtime: ContainerRuntime,
        *,
        allowed_entrypoints: Mapping[str, Set[tuple[str, ...]]],
        allowed_environment_keys: Set[str] = frozenset(),
        limits: ExecutorLimits | None = None,
    ) -> None:
        self._runtime = runtime
        self._allowed_entrypoints = {
            image: frozenset(tuple(entrypoint) for entrypoint in entrypoints)
            for image, entrypoints in allowed_entrypoints.items()
        }
        self._allowed_environment_keys = frozenset(allowed_environment_keys)
        self._limits = limits or ExecutorLimits()
        self._isolation = ContainerIsolation()
        self._tasks: dict[UUID, asyncio.Task[RawExecutionResult]] = {}
        self._cancel_requested: set[UUID] = set()

    async def health_check(self) -> tuple[bool, str]:
        try:
            return await self._runtime.health_check()
        except Exception as exc:
            return False, f"container runtime health check failed: {type(exc).__name__}"

    async def execute(
        self,
        request: ExecutionRequest,
        *,
        timeout_override_seconds: float | None = None,
    ) -> RawExecutionResult:
        started = datetime.now(timezone.utc)
        validation_error = self._validate_request(request)
        if validation_error is not None:
            return self._error_result(
                request,
                started=started,
                status=ToolResultStatus.DENIED,
                error=validation_error,
            )

        available, message = await self.health_check()
        if not available:
            return self._error_result(
                request,
                started=started,
                status=ToolResultStatus.EXECUTOR_ERROR,
                error=self._error(
                    "CONTAINER_RUNTIME_UNAVAILABLE",
                    ErrorCategory.TOOL_UNAVAILABLE,
                    message or "container runtime unavailable",
                    retryable=True,
                ),
            )

        task = asyncio.create_task(self._runtime.run(request, self._isolation))
        self._tasks[request.request_id] = task
        timeout = timeout_override_seconds or request.timeout_seconds
        try:
            result = await asyncio.wait_for(task, timeout=timeout)
            if result.request_id != request.request_id:
                return self._error_result(
                    request,
                    started=started,
                    status=ToolResultStatus.EXECUTOR_ERROR,
                    error=self._error(
                        "RUNTIME_RESULT_MISMATCH",
                        ErrorCategory.SYSTEM_ERROR,
                        "Container runtime returned a mismatched request id",
                    ),
                )
            return self._normalize_result(request, result)
        except TimeoutError:
            await self._safe_cancel(request.request_id)
            return self._error_result(
                request,
                started=started,
                status=ToolResultStatus.TIMED_OUT,
                error=self._error(
                    "EXECUTION_TIMEOUT",
                    ErrorCategory.EXECUTION_TIMEOUT,
                    "Container execution exceeded its deadline",
                    retryable=True,
                ),
            )
        except asyncio.CancelledError:
            if request.request_id not in self._cancel_requested:
                await self._safe_cancel(request.request_id)
            return self._error_result(
                request,
                started=started,
                status=ToolResultStatus.CANCELLED,
                error=self._error(
                    "EXECUTION_CANCELLED",
                    ErrorCategory.TOOL_FAILED,
                    "Container execution was cancelled",
                ),
            )
        except Exception as exc:
            return self._error_result(
                request,
                started=started,
                status=ToolResultStatus.EXECUTOR_ERROR,
                error=self._error(
                    "CONTAINER_RUNTIME_ERROR",
                    ErrorCategory.SYSTEM_ERROR,
                    f"Container runtime failed safely: {type(exc).__name__}",
                ),
            )
        finally:
            self._tasks.pop(request.request_id, None)
            self._cancel_requested.discard(request.request_id)
            await self._safe_cleanup(request.request_id)

    async def cancel(self, request_id: UUID) -> None:
        task = self._tasks.get(request_id)
        if task is None:
            return
        self._cancel_requested.add(request_id)
        await self._safe_cancel(request_id)
        task.cancel()

    def _validate_request(self, request: ExecutionRequest) -> ErrorInfo | None:
        if request.runner is not RunnerType.CONTAINER:
            return self._denied("RUNNER_TYPE_DENIED", "ContainerExecutor accepts only container requests")
        if request.image is None or _PINNED_IMAGE_PATTERN.fullmatch(request.image) is None:
            return self._denied("IMAGE_NOT_PINNED", "Container image must be pinned by digest")
        entrypoints = self._allowed_entrypoints.get(request.image)
        if entrypoints is None:
            return self._denied("IMAGE_NOT_ALLOWED", "Container image is not allowlisted")
        if tuple(request.entrypoint) not in entrypoints:
            return self._denied("ENTRYPOINT_NOT_ALLOWED", "Container entrypoint is not allowlisted")
        executable = request.entrypoint[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if executable in _SHELL_ENTRYPOINTS:
            return self._denied("SHELL_ENTRYPOINT_DENIED", "Shell entrypoints are permanently forbidden")
        if set(request.environment) & _PERMANENTLY_FORBIDDEN_ENVIRONMENT_KEYS:
            return self._denied(
                "ENVIRONMENT_NOT_ALLOWED", "Execution environment contains a permanently forbidden key"
            )
        if set(request.environment) - self._allowed_environment_keys:
            return self._denied("ENVIRONMENT_NOT_ALLOWED", "Execution environment contains a forbidden key")
        for mount in request.mounts:
            if not mount.read_only:
                return self._denied(
                    "WRITABLE_INPUT_MOUNT_DENIED", "Caller-provided mounts must be read-only"
                )
            if not mount.container_path.startswith("/inputs/"):
                return self._denied("MOUNT_PATH_DENIED", "Input mounts must be below /inputs")
        resources = request.resources
        if resources.cpu_cores > self._limits.max_cpu_cores:
            return self._denied("CPU_LIMIT_EXCEEDED", "CPU request exceeds deployment limit")
        if resources.memory_megabytes > self._limits.max_memory_megabytes:
            return self._denied("MEMORY_LIMIT_EXCEEDED", "Memory request exceeds deployment limit")
        if resources.max_processes > self._limits.max_processes:
            return self._denied("PROCESS_LIMIT_EXCEEDED", "Process request exceeds deployment limit")
        if resources.max_output_bytes > self._limits.max_output_bytes:
            return self._denied("OUTPUT_LIMIT_EXCEEDED", "Output request exceeds deployment limit")
        if request.timeout_seconds > self._limits.max_timeout_seconds:
            return self._denied("TIMEOUT_LIMIT_EXCEEDED", "Timeout exceeds deployment limit")
        return None

    def _normalize_result(
        self, request: ExecutionRequest, result: RawExecutionResult
    ) -> RawExecutionResult:
        status = result.status
        error = result.error
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error(
                "TOOL_EXIT_NONZERO",
                ErrorCategory.TOOL_FAILED,
                "Tool returned a non-zero exit status",
            )

        limit = request.resources.max_output_bytes
        stdout = result.stdout[:limit]
        remaining = max(0, limit - len(stdout))
        stderr = result.stderr[:remaining]
        output_artifacts = result.output_artifacts
        if len(result.stdout) + len(result.stderr) > limit:
            status = ToolResultStatus.FAILED
            error = self._error(
                "OUTPUT_LIMIT_EXCEEDED",
                ErrorCategory.TOOL_FAILED,
                "Tool output exceeded the configured byte limit",
            )
        if sum(artifact.size_bytes for artifact in result.output_artifacts) > limit:
            status = ToolResultStatus.FAILED
            output_artifacts = []
            error = self._error(
                "OUTPUT_ARTIFACT_LIMIT_EXCEEDED",
                ErrorCategory.TOOL_FAILED,
                "Tool output artifacts exceeded the configured byte limit",
            )
        return result.model_copy(
            update={
                "status": status,
                "stdout": stdout,
                "stderr": stderr,
                "output_artifacts": output_artifacts,
                "error": error,
            }
        )

    async def _safe_cancel(self, request_id: UUID) -> None:
        try:
            await self._runtime.cancel(request_id)
        except Exception:
            pass

    async def _safe_cleanup(self, request_id: UUID) -> None:
        try:
            await self._runtime.cleanup(request_id)
        except Exception:
            pass

    def _error_result(
        self,
        request: ExecutionRequest,
        *,
        started: datetime,
        status: ToolResultStatus,
        error: ErrorInfo,
    ) -> RawExecutionResult:
        return RawExecutionResult(
            request_id=request.request_id,
            status=status,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            exit_code=None,
            error=error,
        )

    @staticmethod
    def _error(
        code: str,
        category: ErrorCategory,
        message: str,
        *,
        retryable: bool = False,
    ) -> ErrorInfo:
        return ErrorInfo(
            code=code,
            category=category,
            retryable=retryable,
            safe_message=message,
        )

    def _denied(self, code: str, message: str) -> ErrorInfo:
        return self._error(code, ErrorCategory.POLICY_DENIED, message)
