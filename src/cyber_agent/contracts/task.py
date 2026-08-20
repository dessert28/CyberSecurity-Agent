"""Task and authorization-scope contracts."""

from __future__ import annotations

from enum import Enum
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from .common import (
    ArtifactRef,
    Budget,
    MachineName,
    RiskLevel,
    StrictModel,
    SuccessCriterion,
    UtcDateTime,
)


class TargetKind(str, Enum):
    URL = "url"
    HOST = "host"
    IP = "ip"
    FILE = "file"
    PROCESS = "process"


class TaskStatus(str, Enum):
    RECEIVED = "received"
    NORMALIZED = "normalized"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class ScopeTarget(StrictModel):
    kind: TargetKind
    value: str = Field(min_length=1, max_length=2048)
    protocols: set[str] = Field(default_factory=set)
    ports: set[int] = Field(default_factory=set)

    @field_validator("protocols")
    @classmethod
    def protocols_are_allowlisted(cls, value: set[str]) -> set[str]:
        allowed = {"http", "https", "tcp", "udp", "file", "process"}
        normalized = {item.lower() for item in value}
        if not normalized <= allowed:
            raise ValueError("scope target contains an unsupported protocol")
        return normalized

    @field_validator("ports")
    @classmethod
    def ports_are_valid(cls, value: set[int]) -> set[int]:
        if any(port < 1 or port > 65_535 for port in value):
            raise ValueError("ports must be between 1 and 65535")
        return value

    @model_validator(mode="after")
    def target_kind_matches_protocols(self) -> "ScopeTarget":
        if self.kind is TargetKind.URL and self.protocols - {"http", "https"}:
            raise ValueError("URL targets only support http and https")
        if self.kind is TargetKind.FILE and self.protocols - {"file"}:
            raise ValueError("file targets only support the file protocol")
        return self


class ScopePolicy(StrictModel):
    policy_id: UUID = Field(default_factory=uuid4)
    allowed_targets: list[ScopeTarget] = Field(min_length=1)
    denied_targets: list[ScopeTarget] = Field(default_factory=list)
    network_access: bool = False
    allowed_tool_ids: set[str] = Field(default_factory=set)
    maximum_risk: RiskLevel = RiskLevel.R1


class TaskConstraints(StrictModel):
    budget: Budget = Field(default_factory=Budget)
    human_approval_allowed: bool = True
    required_labels: set[MachineName] = Field(default_factory=set)


class Task(StrictModel):
    task_id: UUID = Field(default_factory=uuid4)
    created_at: UtcDateTime
    request_text: str = Field(min_length=1, max_length=100_000)
    input_artifacts: list[ArtifactRef] = Field(default_factory=list)
    objective: str = Field(min_length=1, max_length=10_000)
    scope: ScopePolicy
    constraints: TaskConstraints
    success_criteria: list[SuccessCriterion] = Field(min_length=1)
    scenario_hints: list[str] = Field(default_factory=list)
    status: TaskStatus = TaskStatus.RECEIVED
