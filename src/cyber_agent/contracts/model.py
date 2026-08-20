"""Provider-neutral model request and response contracts."""

from __future__ import annotations

from enum import Enum
from uuid import UUID, uuid4

from pydantic import Field, JsonValue, model_validator

from .common import MachineName, Sha256, StrictModel


class ModelPurpose(str, Enum):
    TASK_UNDERSTANDING = "task_understanding"
    INITIAL_PLAN = "initial_plan"
    TOOL_SELECTION = "tool_selection"
    RESULT_ANALYSIS = "result_analysis"
    REPLAN = "replan"
    REPORT_DRAFT = "report_draft"


class ReasoningEffort(str, Enum):
    LOW = "low"
    HIGH = "high"
    MAX = "max"


class ModelCallStatus(str, Enum):
    SUBMITTED = "SUBMITTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ModelRequest(StrictModel):
    request_id: UUID = Field(default_factory=uuid4)
    purpose: ModelPurpose
    system_instructions: str = Field(min_length=1, max_length=100_000)
    context: dict[str, JsonValue]
    output_schema: dict[str, JsonValue]
    reasoning_effort: ReasoningEffort
    max_output_tokens: int = Field(ge=1, le=1_048_576)
    timeout_seconds: int = Field(ge=1, le=600)


class ModelUsage(StrictModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)


class ModelResponse(StrictModel):
    response_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    provider: MachineName
    model: str = Field(min_length=1, max_length=255)
    data: dict[str, JsonValue]
    usage: ModelUsage
    latency_ms: int = Field(ge=0)
    finish_reason: str = Field(min_length=1, max_length=255)
    provider_request_id: str = Field(min_length=1, max_length=1024)
    raw_response_hash: Sha256
    schema_valid: bool


class ModelCapabilities(StrictModel):
    provider: MachineName
    model: str = Field(min_length=1, max_length=255)
    structured_output: bool
    vision: bool
    max_context_tokens: int = Field(ge=1)


class ModelHealth(StrictModel):
    available: bool
    provider: MachineName
    model: str = Field(min_length=1, max_length=255)
    message: str = Field(default="", max_length=2000)


class ModelCallRef(StrictModel):
    model_call_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    response_id: UUID | None = None
    request_hash: Sha256
    response_hash: Sha256 | None = None
    run_id: UUID | None = None
    provider: MachineName | None = None
    model_id: str | None = Field(default=None, min_length=1, max_length=255)
    purpose: ModelPurpose | None = None
    status: ModelCallStatus | None = None
    plan_id: UUID | None = None
    plan_version: int | None = Field(default=None, ge=1)
    action_id: UUID | None = None
    step_id: UUID | None = None
    audit_event_id: UUID | None = None

    @model_validator(mode="after")
    def validate_trace_state(self) -> "ModelCallRef":
        formal_identity = (
            self.run_id,
            self.provider,
            self.model_id,
            self.purpose,
            self.status,
        )
        if any(value is not None for value in formal_identity) and not all(
            value is not None for value in formal_identity
        ):
            raise ValueError("formal model call identity must be complete")
        if self.status in {ModelCallStatus.SUBMITTED, ModelCallStatus.FAILED} and (
            self.response_id is not None or self.response_hash is not None
        ):
            raise ValueError("unfinished or failed model calls cannot reference a response")
        if self.status is ModelCallStatus.SUCCEEDED and (
            self.response_id is None or self.response_hash is None
        ):
            raise ValueError("successful model calls require the real response reference")
        if self.plan_version is not None and self.plan_id is None:
            raise ValueError("plan_version requires plan_id")
        return self


__all__ = [
    "ModelCallRef",
    "ModelCallStatus",
    "ModelCapabilities",
    "ModelHealth",
    "ModelPurpose",
    "ModelRequest",
    "ModelResponse",
    "ModelUsage",
    "ReasoningEffort",
]
