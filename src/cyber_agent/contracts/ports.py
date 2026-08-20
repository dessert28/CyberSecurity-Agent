"""Runtime-checkable ports between independently owned modules."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable
from uuid import UUID

from .audit import AuditRecord
from .common import ArtifactRef, ErrorInfo
from .evidence import Evidence, VerificationVerdict
from .model import ModelCapabilities, ModelHealth, ModelRequest, ModelResponse
from .plan import DecisionProposal, Plan, PlanProposal, Run, Step
from .task import Task
from .tool import (
    ExecutionRequest,
    RawExecutionResult,
    ToolHealth,
    ToolInvocation,
    ToolResult,
    ToolSpec,
)


@runtime_checkable
class ModelGateway(Protocol):
    async def generate_structured(self, request: ModelRequest) -> ModelResponse: ...

    async def health_check(self) -> ModelHealth: ...

    def get_capabilities(self) -> ModelCapabilities: ...


@runtime_checkable
class PlannerPort(Protocol):
    async def understand_task(self, task: Task) -> Task: ...

    async def propose_plan(self, task: Task, run: Run) -> PlanProposal: ...

    async def propose_next_action(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        step: Step,
        evidence: Sequence[Evidence],
        tool_candidates: Sequence[ToolSpec],
    ) -> DecisionProposal: ...

    async def replan(
        self,
        task: Task,
        run: Run,
        current_plan: Plan,
        evidence: Sequence[Evidence],
        cause: ErrorInfo,
    ) -> PlanProposal: ...


@runtime_checkable
class ToolPlugin(Protocol):
    def get_spec(self) -> ToolSpec: ...

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest: ...

    def parse(self, result: RawExecutionResult) -> ToolResult: ...

    async def health_check(self) -> ToolHealth: ...


@runtime_checkable
class ToolRegistryPort(Protocol):
    def register(self, plugin: ToolPlugin) -> None: ...

    def candidates(self, capability: str) -> Sequence[ToolSpec]: ...


@runtime_checkable
class ExecutorPort(Protocol):
    async def execute(self, request: ExecutionRequest) -> RawExecutionResult: ...

    async def cancel(self, request_id: UUID) -> None: ...


@runtime_checkable
class VerifierPort(Protocol):
    async def verify_step(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        step: Step,
        results: Sequence[ToolResult],
        evidence: Sequence[Evidence],
    ) -> VerificationVerdict: ...

    async def verify_task(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        evidence: Sequence[Evidence],
    ) -> VerificationVerdict: ...


@runtime_checkable
class AuditStorePort(Protocol):
    async def append(self, record: AuditRecord) -> None: ...

    async def list_by_run(self, run_id: UUID) -> Sequence[AuditRecord]: ...


@runtime_checkable
class ArtifactStorePort(Protocol):
    async def put_bytes(
        self,
        content: bytes,
        *,
        media_type: str,
        source_ref: UUID | None = None,
        quarantined: bool = False,
    ) -> ArtifactRef: ...

    async def read_bytes(self, artifact_id: UUID) -> bytes: ...
