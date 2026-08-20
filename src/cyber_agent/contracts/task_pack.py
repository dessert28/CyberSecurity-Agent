"""Contracts for scenario-specific task packs and observation adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from .common import MachineName, StrictModel, UtcDateTime
from .evidence import Evidence
from .plan import CandidateAction, Plan, PlanProposal, Run, Step
from .task import Task
from .tool import PolicyDecision, ToolInvocation, ToolResult, ToolSpec


class TaskPackManifest(StrictModel):
    """Strict metadata that binds a task type to approved runtime components."""

    task_pack_id: MachineName
    version: str = Field(
        pattern=r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$",
        max_length=255,
    )
    task_type: MachineName
    required_tools: tuple[MachineName, ...] = Field(min_length=1)
    verifier: MachineName
    report_template: MachineName
    security_policy: str = Field(
        pattern=r"^[a-z][a-z0-9_.-]{1,127}/\d+\.\d+$",
        max_length=255,
    )

    @field_validator("required_tools")
    @classmethod
    def required_tools_are_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("required_tools must contain unique tool IDs")
        return value


class ScenarioObservation(StrictModel):
    """One normalized tool result and its scenario-derived evidence."""

    result: ToolResult
    evidence: list[Evidence] = Field(min_length=1)

    @model_validator(mode="after")
    def evidence_belongs_to_result_run(self) -> "ScenarioObservation":
        if any(item.run_id != self.result.run_id for item in self.evidence):
            raise ValueError("scenario evidence must belong to the tool result run")
        return self


@runtime_checkable
class ScenarioAdapter(Protocol):
    """Scenario boundary used by the generic orchestrator lifecycle."""

    def validate_task(self, task: Task, manifest: TaskPackManifest) -> None: ...

    def open_run(
        self,
        task: Task,
        run: Run,
        manifest: TaskPackManifest,
    ) -> None: ...

    def validate_plan(
        self,
        task: Task,
        run: Run,
        proposal: PlanProposal,
        manifest: TaskPackManifest,
    ) -> None: ...

    def validate_action(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        step: Step,
        action: CandidateAction,
        tool_spec: ToolSpec,
    ) -> None: ...

    def build_observation(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        step: Step,
        invocation: ToolInvocation,
        policy_decision: PolicyDecision,
        result: ToolResult | None,
        observed_at: UtcDateTime,
    ) -> ScenarioObservation: ...

    def close_run(self, run_id: UUID) -> None: ...


@dataclass(frozen=True, slots=True)
class TaskPack:
    """An immutable pairing of trusted manifest metadata and an adapter."""

    manifest: TaskPackManifest
    adapter: ScenarioAdapter

    def __post_init__(self) -> None:
        if not isinstance(self.adapter, ScenarioAdapter):
            raise TypeError("adapter does not implement ScenarioAdapter")
        object.__setattr__(self, "manifest", self.manifest.model_copy(deep=True))
