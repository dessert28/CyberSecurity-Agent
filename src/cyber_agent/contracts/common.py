"""Shared primitives for all public contracts."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

SCHEMA_VERSION = "1.0"


def _require_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime values must include a timezone")
    return value.astimezone(timezone.utc)


UtcDateTime = Annotated[datetime, AfterValidator(_require_aware_utc)]
Sha256 = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-fA-F]{64}$", to_lower=True),
]
StableCode = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,127}$"),
]
MachineName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{1,127}$"),
]


class StrictModel(BaseModel):
    """Base for strict, versioned, JSON-safe public objects."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        ser_json_bytes="base64",
        val_json_bytes="base64",
    )

    schema_version: str = Field(default=SCHEMA_VERSION, pattern=r"^\d+\.\d+$")


class RiskLevel(str, Enum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"


class ErrorCategory(str, Enum):
    INPUT_INVALID = "INPUT_INVALID"
    MODEL_TRANSIENT = "MODEL_TRANSIENT"
    MODEL_SCHEMA_INVALID = "MODEL_SCHEMA_INVALID"
    POLICY_DENIED = "POLICY_DENIED"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    EXECUTION_TIMEOUT = "EXECUTION_TIMEOUT"
    TOOL_FAILED = "TOOL_FAILED"
    EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    SYSTEM_ERROR = "SYSTEM_ERROR"


class ActorType(str, Enum):
    SYSTEM = "system"
    MODEL = "model"
    TOOL = "tool"
    HUMAN = "human"


class ArtifactRef(StrictModel):
    artifact_id: UUID = Field(default_factory=uuid4)
    logical_uri: str = Field(min_length=1, max_length=1024)
    media_type: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(ge=0)
    sha256: Sha256
    source_ref: UUID | None = None
    quarantined: bool = False

    @field_validator("logical_uri")
    @classmethod
    def logical_uri_must_not_be_a_host_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if re.match(r"^[A-Za-z]:/", normalized) or normalized.startswith("/"):
            raise ValueError("logical_uri must not contain an absolute host path")
        if ".." in normalized.split("/"):
            raise ValueError("logical_uri must not contain path traversal")
        return value


class SuccessCriterion(StrictModel):
    criterion_id: UUID = Field(default_factory=uuid4)
    kind: MachineName
    description: str = Field(min_length=1, max_length=2000)
    expected: JsonValue | None = None
    evidence_requirements: list[str] = Field(default_factory=list)
    required: bool = True


class Budget(StrictModel):
    max_duration_seconds: int = Field(default=1200, ge=1, le=86_400)
    max_steps: int = Field(default=20, ge=1, le=1_000)
    max_model_calls: int = Field(default=20, ge=0, le=1_000)
    max_tool_calls: int = Field(default=30, ge=0, le=2_000)
    max_replans: int = Field(default=2, ge=0, le=100)
    max_attempts_per_step: int = Field(default=2, ge=1, le=20)
    max_tool_timeout_seconds: int = Field(default=180, ge=1, le=3_600)

    @model_validator(mode="after")
    def tool_timeout_must_fit_run(self) -> "Budget":
        if self.max_tool_timeout_seconds > self.max_duration_seconds:
            raise ValueError("tool timeout cannot exceed the run duration")
        return self


class ErrorInfo(StrictModel):
    code: StableCode
    category: ErrorCategory
    retryable: bool
    safe_message: str = Field(min_length=1, max_length=2000)
    diagnostic_ref: UUID | None = None


class ActorRef(StrictModel):
    actor_type: ActorType
    actor_id: str = Field(min_length=1, max_length=255)


class EntityRef(StrictModel):
    entity_type: MachineName
    entity_id: UUID


class ModelProfileRef(StrictModel):
    provider: MachineName
    model: str = Field(min_length=1, max_length=255)
    configuration_fingerprint: Sha256


class EnvironmentProfile(StrictModel):
    executor_backend: MachineName
    platform: str = Field(min_length=1, max_length=255)
    configuration_fingerprint: Sha256
    image_digests: dict[str, Sha256] = Field(default_factory=dict)
