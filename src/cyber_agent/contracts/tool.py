"""Tool registration, invocation, execution, and result contracts."""

from __future__ import annotations

from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, JsonValue, field_validator, model_validator

from .common import (
    ArtifactRef,
    ErrorInfo,
    MachineName,
    RiskLevel,
    Sha256,
    StableCode,
    StrictModel,
    UtcDateTime,
)


class RunnerType(str, Enum):
    FAKE = "fake"
    CONTAINER = "container"
    IN_PROCESS_TEST = "in_process_test"
    SOURCE_ANALYSIS = "source_analysis"


class SideEffect(str, Enum):
    NONE = "none"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_READ = "network_read"
    NETWORK_ACTIVE = "network_active"
    PROCESS_INTERACTION = "process_interaction"
    SIDE_EFFECT_SUPPRESSED = "side_effect_suppressed"


class NetworkMode(str, Enum):
    NONE = "none"
    ALLOWLIST = "allowlist"


class ToolInvocationStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    DENIED = "denied"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class ToolResultStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    DENIED = "denied"
    CANCELLED = "cancelled"
    EXECUTOR_ERROR = "executor_error"
    INTERRUPTED = "interrupted"


class ToolRef(StrictModel):
    tool_id: MachineName
    version: str = Field(pattern=r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


class ToolPermissions(StrictModel):
    network: bool = False
    filesystem_read: bool = False
    filesystem_write: bool = False
    process_interaction: bool = False


class ResourceLimits(StrictModel):
    cpu_cores: float = Field(gt=0, le=64)
    memory_megabytes: int = Field(ge=16, le=262_144)
    max_processes: int = Field(ge=1, le=4096)
    max_output_bytes: int = Field(ge=1, le=1_000_000_000)


class ExecutionProfile(StrictModel):
    runner: RunnerType
    image: str | None = Field(default=None, max_length=1024)
    entrypoint: list[str] = Field(min_length=1)
    default_timeout_seconds: int = Field(ge=1, le=3600)
    max_timeout_seconds: int = Field(ge=1, le=3600)
    default_resources: ResourceLimits

    @model_validator(mode="after")
    def container_profile_is_pinned(self) -> "ExecutionProfile":
        if self.default_timeout_seconds > self.max_timeout_seconds:
            raise ValueError("default timeout cannot exceed maximum timeout")
        if self.runner is RunnerType.CONTAINER:
            if self.image is None or "@sha256:" not in self.image:
                raise ValueError("container images must be pinned by digest")
            digest = self.image.rsplit("@sha256:", 1)[-1]
            if len(digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in digest):
                raise ValueError("container image digest must be a SHA-256 hash")
        return self


class ToolSpec(StrictModel):
    tool_id: MachineName
    name: str = Field(min_length=1, max_length=255)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
    plugin_id: MachineName
    capabilities: list[MachineName] = Field(min_length=1)
    description: str = Field(min_length=1, max_length=5000)
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue]
    side_effects: set[SideEffect]
    risk_level: RiskLevel
    permissions: ToolPermissions
    execution_profile: ExecutionProfile


class PolicyDecision(StrictModel):
    decision_id: UUID = Field(default_factory=uuid4)
    allowed: bool
    policy_version: str = Field(min_length=1, max_length=255)
    reason_codes: list[StableCode] = Field(default_factory=list)
    constrained_arguments: dict[str, JsonValue] = Field(default_factory=dict)


class ToolInvocation(StrictModel):
    invocation_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    plan_id: UUID
    step_id: UUID
    attempt: int = Field(ge=1)
    tool_ref: ToolRef
    validated_arguments: dict[str, JsonValue]
    policy_decision_ref: UUID | None = None
    deadline: UtcDateTime
    status: ToolInvocationStatus

    @model_validator(mode="after")
    def policy_reference_matches_lifecycle(self) -> "ToolInvocation":
        if (
            self.status is ToolInvocationStatus.PROPOSED
            and self.policy_decision_ref is not None
        ):
            raise ValueError("proposed invocations cannot reference a policy decision")
        policy_resolved = {
            ToolInvocationStatus.APPROVED,
            ToolInvocationStatus.DENIED,
            ToolInvocationStatus.RUNNING,
            ToolInvocationStatus.COMPLETED,
        }
        if self.status in policy_resolved and self.policy_decision_ref is None:
            raise ValueError("policy-resolved invocations require a policy decision reference")
        return self


class MountSpec(StrictModel):
    artifact_id: UUID
    container_path: str = Field(min_length=1, max_length=1024)
    read_only: bool = True

    @field_validator("container_path")
    @classmethod
    def path_is_contained_in_container(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if not normalized.startswith("/") or ".." in normalized.split("/"):
            raise ValueError("container paths must be absolute and traversal-free")
        return normalized


class NetworkPolicy(StrictModel):
    mode: NetworkMode = NetworkMode.NONE
    allowed_targets: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def no_targets_when_network_is_disabled(self) -> "NetworkPolicy":
        if self.mode is NetworkMode.NONE and self.allowed_targets:
            raise ValueError("network-disabled requests cannot have allowed targets")
        if self.mode is NetworkMode.ALLOWLIST and not self.allowed_targets:
            raise ValueError("allowlist mode requires at least one target")
        return self


class ExecutionRequest(StrictModel):
    request_id: UUID = Field(default_factory=uuid4)
    invocation_id: UUID
    runner: RunnerType
    image: str | None = Field(default=None, max_length=1024)
    entrypoint: list[str] = Field(min_length=1)
    argv: list[str] = Field(default_factory=list)
    mounts: list[MountSpec] = Field(default_factory=list)
    environment: dict[str, str] = Field(default_factory=dict)
    network_policy: NetworkPolicy = Field(default_factory=NetworkPolicy)
    resources: ResourceLimits
    timeout_seconds: int = Field(ge=1, le=3600)


class RawExecutionResult(StrictModel):
    request_id: UUID
    status: ToolResultStatus
    started_at: UtcDateTime
    finished_at: UtcDateTime
    exit_code: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    output_artifacts: list[ArtifactRef] = Field(default_factory=list)
    error: ErrorInfo | None = None

    @model_validator(mode="after")
    def finish_is_not_before_start(self) -> "RawExecutionResult":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at cannot be before started_at")
        return self


class ToolResult(StrictModel):
    result_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    plan_id: UUID
    step_id: UUID
    attempt: int = Field(ge=1)
    tool_ref: ToolRef
    validated_arguments: dict[str, JsonValue]
    policy_decision_ref: UUID
    status: ToolResultStatus
    started_at: UtcDateTime
    finished_at: UtcDateTime
    exit_code: int | None = None
    normalized_output: dict[str, JsonValue] = Field(default_factory=dict)
    artifact_refs: list[ArtifactRef] = Field(default_factory=list)
    error: ErrorInfo | None = None
    environment_fingerprint: Sha256

    @model_validator(mode="after")
    def finish_is_not_before_start(self) -> "ToolResult":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at cannot be before started_at")
        return self


class ToolHealth(StrictModel):
    tool_ref: ToolRef
    available: bool
    message: str = Field(default="", max_length=2000)
