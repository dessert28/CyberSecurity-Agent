"""Run, plan, and step contracts."""

from __future__ import annotations

from enum import Enum
from uuid import UUID, uuid4

from pydantic import Field, JsonValue, model_validator

from .common import (
    ArtifactRef,
    Budget,
    EnvironmentProfile,
    ErrorInfo,
    MachineName,
    ModelProfileRef,
    RiskLevel,
    StrictModel,
    SuccessCriterion,
    UtcDateTime,
)


class RunStatus(str, Enum):
    QUEUED = "queued"
    PLANNING = "planning"
    VALIDATING_PLAN = "validating_plan"
    RUNNING = "running"
    WAITING_HUMAN = "waiting_human"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class PlanStatus(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    COMPLETED = "completed"
    FAILED = "failed"


class PlanTrigger(str, Enum):
    INITIAL = "initial"
    EVIDENCE_INSUFFICIENT = "evidence_insufficient"
    ASSUMPTION_REJECTED = "assumption_rejected"
    TOOL_UNAVAILABLE = "tool_unavailable"
    EXECUTION_FAILED = "execution_failed"
    POLICY_DENIED = "policy_denied"
    BUDGET_PRESSURE = "budget_pressure"


class StepStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class StepKind(str, Enum):
    OBSERVE = "observe"
    ANALYZE = "analyze"
    EXECUTE = "execute"
    VERIFY = "verify"
    REPORT = "report"


class ApprovalMode(str, Enum):
    AUTOMATIC = "automatic"
    PREAUTHORIZED = "preauthorized"
    HUMAN_REQUIRED = "human_required"
    PROHIBITED = "prohibited"


class RetryPolicy(StrictModel):
    max_attempts: int = Field(default=2, ge=1, le=20)
    retryable_error_codes: set[str] = Field(default_factory=set)
    initial_backoff_seconds: float = Field(default=1.0, ge=0, le=300)
    maximum_backoff_seconds: float = Field(default=30.0, ge=0, le=600)

    @model_validator(mode="after")
    def maximum_backoff_is_not_smaller(self) -> "RetryPolicy":
        if self.maximum_backoff_seconds < self.initial_backoff_seconds:
            raise ValueError("maximum backoff must not be smaller than initial backoff")
        return self


class Step(StrictModel):
    step_id: UUID = Field(default_factory=uuid4)
    plan_id: UUID
    ordinal: int = Field(ge=1)
    objective: str = Field(min_length=1, max_length=10_000)
    kind: StepKind
    depends_on: list[UUID] = Field(
        default_factory=list,
        description=(
            "IDs of direct prerequisite steps that must complete before this step. "
            "Each dependency must be mirrored by a DependencyEdge whose before is "
            "the prerequisite and whose after is this step."
        ),
    )
    required_capabilities: list[MachineName] = Field(default_factory=list)
    input_refs: list[UUID] = Field(default_factory=list)
    success_criteria: list[SuccessCriterion] = Field(min_length=1)
    risk_level: RiskLevel
    approval_mode: ApprovalMode
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)
    status: StepStatus = StepStatus.PENDING

    @model_validator(mode="after")
    def step_cannot_depend_on_itself(self) -> "Step":
        if self.step_id in self.depends_on:
            raise ValueError("a step cannot depend on itself")
        return self


class DependencyEdge(StrictModel):
    before: UUID = Field(
        description="ID of the direct prerequisite step that must complete first."
    )
    after: UUID = Field(
        description="ID of the dependent step that may run after the prerequisite."
    )

    @model_validator(mode="after")
    def edge_cannot_reference_itself(self) -> "DependencyEdge":
        if self.before == self.after:
            raise ValueError("dependency edges cannot be self-referential")
        return self


class Plan(StrictModel):
    plan_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    version: int = Field(ge=1)
    parent_plan_id: UUID | None = None
    trigger: PlanTrigger
    trigger_ref: UUID | None = None
    strategy_summary: str = Field(min_length=1, max_length=20_000)
    assumptions: list[str] = Field(default_factory=list)
    step_ids: list[UUID] = Field(min_length=1)
    dependency_edges: list[DependencyEdge] = Field(
        default_factory=list,
        description=(
            "Directed prerequisite edges. Every edge uses before=prerequisite and "
            "after=dependent and must exactly mirror Step.depends_on declarations."
        ),
    )
    status: PlanStatus = PlanStatus.DRAFT

    @model_validator(mode="after")
    def graph_references_declared_steps(self) -> "Plan":
        declared = set(self.step_ids)
        if len(declared) != len(self.step_ids):
            raise ValueError("step_ids must be unique")
        successors: dict[UUID, set[UUID]] = {step_id: set() for step_id in declared}
        indegree: dict[UUID, int] = {step_id: 0 for step_id in declared}
        for edge in self.dependency_edges:
            if edge.before not in declared or edge.after not in declared:
                raise ValueError("dependency edges must reference declared steps")
            if edge.after not in successors[edge.before]:
                successors[edge.before].add(edge.after)
                indegree[edge.after] += 1
        ready = [step_id for step_id, degree in indegree.items() if degree == 0]
        visited = 0
        while ready:
            current = ready.pop()
            visited += 1
            for successor in successors[current]:
                indegree[successor] -= 1
                if indegree[successor] == 0:
                    ready.append(successor)
        if visited != len(declared):
            raise ValueError("dependency graph must be acyclic")
        if self.version == 1 and self.parent_plan_id is not None:
            raise ValueError("the initial plan cannot have a parent")
        if self.version > 1 and self.parent_plan_id is None:
            raise ValueError("replanned versions must reference a parent")
        return self


class PlanProposal(StrictModel):
    """A complete planner proposal with every executable step attached."""

    plan: Plan
    steps: list[Step] = Field(min_length=1)

    @model_validator(mode="after")
    def steps_match_declared_plan(self) -> "PlanProposal":
        step_ids = [step.step_id for step in self.steps]
        declared_ids = set(self.plan.step_ids)
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("proposal step IDs must be unique")
        if set(step_ids) != declared_ids:
            raise ValueError("proposal steps must exactly match plan.step_ids")
        for step in self.steps:
            if step.plan_id != self.plan.plan_id:
                raise ValueError("proposal steps must reference the proposed plan")
            if not set(step.depends_on).issubset(declared_ids):
                raise ValueError("step dependencies must reference declared plan steps")
        return self


class Run(StrictModel):
    run_id: UUID = Field(default_factory=uuid4)
    task_id: UUID
    created_at: UtcDateTime
    status: RunStatus = RunStatus.QUEUED
    budget: Budget
    model_profile: ModelProfileRef
    environment_profile: EnvironmentProfile
    active_plan_id: UUID | None = None
    termination_reason: ErrorInfo | None = None
    output_artifacts: list[ArtifactRef] = Field(default_factory=list)


class CandidateAction(StrictModel):
    capability: MachineName
    tool_id: str | None = None
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    rationale: str = Field(min_length=1, max_length=10_000)
    evidence_ids: list[UUID] = Field(default_factory=list)
    estimated_risk: RiskLevel

    @model_validator(mode="after")
    def arguments_require_a_tool(self) -> "CandidateAction":
        if self.tool_id is None and self.arguments:
            raise ValueError("non-tool candidate actions cannot carry tool arguments")
        return self


class DecisionProposal(StrictModel):
    proposal_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    plan_id: UUID
    step_id: UUID
    candidates: list[CandidateAction] = Field(min_length=1)
    selected_index: int = Field(ge=0)
    uncertainty: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def selected_candidate_exists(self) -> "DecisionProposal":
        if self.selected_index >= len(self.candidates):
            raise ValueError("selected_index does not reference a candidate")
        return self
