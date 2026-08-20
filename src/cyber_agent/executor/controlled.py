"""ExecutorPort implementation that routes only explicit runner types."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from cyber_agent.contracts.common import ErrorCategory, ErrorInfo
from cyber_agent.contracts.tool import ExecutionRequest, RawExecutionResult, RunnerType, ToolResultStatus

from .container import ContainerExecutor
from .fake import FakeRunner
from .source_analysis import SourceAnalysisRunner


class ControlledExecutor:
    """Dispatch allowlisted runners without any host-process fallback."""

    def __init__(
        self,
        *,
        fake_runner: FakeRunner | None = None,
        container_executor: ContainerExecutor | None = None,
        source_analysis_runner: SourceAnalysisRunner | None = None,
    ) -> None:
        self._fake = fake_runner
        self._container = container_executor
        self._source_analysis = source_analysis_runner
        self._active: dict[UUID, RunnerType] = {}

    async def execute(self, request: ExecutionRequest) -> RawExecutionResult:
        self._active[request.request_id] = request.runner
        try:
            if request.runner is RunnerType.FAKE and self._fake is not None:
                return await self._fake.execute(request)
            if request.runner is RunnerType.CONTAINER and self._container is not None:
                return await self._container.execute(request)
            if (
                request.runner is RunnerType.SOURCE_ANALYSIS
                and self._source_analysis is not None
            ):
                return await self._source_analysis.execute(request)
            return self._unavailable_result(request)
        finally:
            self._active.pop(request.request_id, None)

    async def cancel(self, request_id: UUID) -> None:
        runner = self._active.get(request_id)
        if runner is RunnerType.FAKE and self._fake is not None:
            await self._fake.cancel(request_id)
        elif runner is RunnerType.CONTAINER and self._container is not None:
            await self._container.cancel(request_id)
        elif runner is RunnerType.SOURCE_ANALYSIS and self._source_analysis is not None:
            await self._source_analysis.cancel(request_id)

    @staticmethod
    def _unavailable_result(request: ExecutionRequest) -> RawExecutionResult:
        now = datetime.now(timezone.utc)
        return RawExecutionResult(
            request_id=request.request_id,
            status=ToolResultStatus.EXECUTOR_ERROR,
            started_at=now,
            finished_at=now,
            error=ErrorInfo(
                code="RUNNER_UNAVAILABLE",
                category=ErrorCategory.TOOL_UNAVAILABLE,
                retryable=False,
                safe_message="Requested runner is unavailable; host fallback is forbidden",
            ),
        )
