"""Strict workbench request, response, and startup configuration models."""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from pathlib import PurePosixPath
from typing import Annotated, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator


class WorkbenchModel(BaseModel):
    """Fail-closed base for local workbench data."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ProviderType(str, Enum):
    KIMI = "kimi"
    DEEPSEEK = "deepseek"
    QWEN = "qwen"
    DOMESTIC_COMPATIBLE = "domestic_compatible"
    OPENAI_COMPATIBLE = "openai_compatible"


class WorkbenchMode(str, Enum):
    DEVELOPMENT = "development"
    COMPETITION = "competition"


class RunMode(str, Enum):
    REPLAY_FAKE = "replay_fake"
    MODEL_FAKE = "model_fake"
    MODEL_DOCKER = "model_docker"


class ModelCheckStatus(str, Enum):
    UNCHECKED = "unchecked"
    PASSED = "passed"
    FAILED = "failed"


class ReadinessState(str, Enum):
    """Stable, public reason-code contract for runtime admission."""

    READY = "READY"
    MODEL_NOT_READY = "MODEL_NOT_READY"
    CREDENTIAL_MISSING = "CREDENTIAL_MISSING"
    CAPABILITY_STALE = "CAPABILITY_STALE"
    CAPABILITY_FAILED = "CAPABILITY_FAILED"
    ADAPTER_NOT_READY = "ADAPTER_NOT_READY"
    PLANNER_NOT_READY = "PLANNER_NOT_READY"
    REGISTRY_NOT_READY = "REGISTRY_NOT_READY"
    POLICY_NOT_READY = "POLICY_NOT_READY"
    ARTIFACT_RUNTIME_NOT_READY = "ARTIFACT_RUNTIME_NOT_READY"
    EXECUTOR_NOT_READY = "EXECUTOR_NOT_READY"
    TASKPACK_DISABLED = "TASKPACK_DISABLED"
    RUNTIME_SNAPSHOT_CONFLICT = "RUNTIME_SNAPSHOT_CONFLICT"


class ModelProfileCreateRequest(WorkbenchModel):
    display_name: str
    provider: ProviderType
    base_url: str
    model_id: str

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        normalized = value.strip()
        if not 1 <= len(normalized) <= 64:
            raise ValueError("display_name must contain 1 to 64 characters")
        if any(ord(character) < 32 for character in normalized):
            raise ValueError("display_name contains a control character")
        return normalized

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return normalize_model_base_url(value)

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str) -> str:
        normalized = value.strip()
        if not 1 <= len(normalized) <= 255:
            raise ValueError("model_id must contain 1 to 255 characters")
        if any(ord(character) < 33 or ord(character) == 127 for character in normalized):
            raise ValueError("model_id contains whitespace or a control character")
        return normalized

    @property
    def name_key(self) -> str:
        return self.display_name.casefold()


class ModelProfileUpdateRequest(ModelProfileCreateRequest):
    pass


class ModelCredentialRequest(WorkbenchModel):
    api_key: str = Field(min_length=1, max_length=16_384, repr=False)

    @field_validator("api_key")
    @classmethod
    def normalize_api_key(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(character in normalized for character in ("\r", "\n", "\x00")):
            raise ValueError("api_key is empty or contains a forbidden character")
        return normalized


class ActiveModelProfileRequest(WorkbenchModel):
    profile_id: UUID


class RunCreateRequest(WorkbenchModel):
    scenario: Literal["web_idor"]
    mode: RunMode
    confirmation_token: str | None = Field(default=None, min_length=16, max_length=512)


class ShutdownRequest(WorkbenchModel):
    pass


class ModelProfileView(WorkbenchModel):
    profile_id: UUID
    display_name: str
    provider: ProviderType
    base_url: str
    model_id: str
    credential_present: bool
    check_status: ModelCheckStatus
    security_default: bool
    active: bool

    _display_name = field_validator("display_name")(ModelProfileCreateRequest.validate_display_name.__func__)
    _base_url = field_validator("base_url")(ModelProfileCreateRequest.validate_base_url.__func__)
    _model_id = field_validator("model_id")(ModelProfileCreateRequest.validate_model_id.__func__)


class ModelCheckResult(WorkbenchModel):
    profile_id: UUID
    passed: bool
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,127}$")
    message: str = Field(min_length=1, max_length=2_000)
    checked_at: datetime
    expires_at: datetime
    probe_id: UUID
    active: bool

    @field_validator("checked_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("checked_at must include a timezone")
        return value

    _expires_at = field_validator("expires_at")(require_utc_timestamp.__func__)


class CapabilityProbeRecord(WorkbenchModel):
    """Immutable evidence that a specific model identity passed or failed a probe."""

    probe_id: UUID
    profile_id: UUID
    provider: ProviderType
    model_id: str
    base_url_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_snapshot_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    credential_version: int = Field(ge=0)
    capability_contract_version: str = Field(pattern=r"^[a-z0-9][a-z0-9._/-]{1,63}$")
    status: ModelCheckStatus
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,127}$")
    checked_at: datetime
    expires_at: datetime

    _model_id = field_validator("model_id")(ModelProfileCreateRequest.validate_model_id.__func__)
    _checked_at = field_validator("checked_at")(ModelCheckResult.require_utc_timestamp.__func__)
    _expires_at = field_validator("expires_at")(ModelCheckResult.require_utc_timestamp.__func__)

    @model_validator(mode="after")
    def validate_probe(self) -> "CapabilityProbeRecord":
        if self.status is ModelCheckStatus.UNCHECKED:
            raise ValueError("capability probe status cannot be unchecked")
        if self.expires_at <= self.checked_at:
            raise ValueError("capability probe expiry must follow its check time")
        if self.status is ModelCheckStatus.PASSED and self.endpoint_snapshot_fingerprint is None:
            raise ValueError("passed capability probe requires an endpoint fingerprint")
        return self


class ModelRuntimeReadiness(WorkbenchModel):
    ready: bool
    state: ReadinessState
    reason_codes: tuple[ReadinessState, ...]
    capability_probe_ref: UUID | None = None

    @model_validator(mode="after")
    def validate_state(self) -> "ModelRuntimeReadiness":
        if self.ready != (self.state is ReadinessState.READY):
            raise ValueError("model readiness flag contradicts state")
        if self.ready and self.reason_codes:
            raise ValueError("ready model cannot contain blocking reason codes")
        if not self.ready and self.state not in self.reason_codes:
            raise ValueError("unready model must include its state as a reason code")
        if self.ready and self.capability_probe_ref is None:
            raise ValueError("ready model requires a capability probe reference")
        return self


class ToolReadinessView(WorkbenchModel):
    tool_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    state: Literal["healthy", "unhealthy", "unregistered"]
    healthy: bool
    message: str = Field(default="", max_length=2_000)

    @model_validator(mode="after")
    def validate_state(self) -> "ToolReadinessView":
        if self.healthy != (self.state == "healthy"):
            raise ValueError("tool health flag contradicts state")
        return self


class TaskPackReadiness(WorkbenchModel):
    task_pack_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    state: ReadinessState
    reason_codes: tuple[ReadinessState, ...]
    required_tools: tuple[str, ...] = Field(default_factory=tuple)
    tool_states: tuple[ToolReadinessView, ...] = Field(default_factory=tuple)
    model_capability_ready: bool | None = None
    docker_required: bool | None = None
    detail: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def validate_state(self) -> "TaskPackReadiness":
        if self.state is ReadinessState.READY and self.reason_codes:
            raise ValueError("ready taskpack cannot contain blocking reason codes")
        if self.state is not ReadinessState.READY and self.state not in self.reason_codes:
            raise ValueError("unready taskpack must include its state as a reason code")
        return self


class DebugToolListResponse(WorkbenchModel):
    expected_tool_ids: tuple[str, ...]
    registered_tool_ids: tuple[str, ...]
    missing_tool_ids: tuple[str, ...]
    tool_statuses: tuple[ToolReadinessView, ...]


class ToolHealthDetailView(WorkbenchModel):
    tool_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    healthy: bool
    message: str = Field(default="", max_length=2_000)
    last_health_exception: str | None = Field(default=None, max_length=20_000)


class DebugToolHealthReport(WorkbenchModel):
    tools: tuple[ToolHealthDetailView, ...]


class RuntimeReadinessResponse(WorkbenchModel):
    state: ReadinessState
    runtime_available: bool
    model_ready: bool
    core_ready: bool
    reason_codes: tuple[ReadinessState, ...]
    available_taskpacks: tuple[str, ...]
    unavailable_taskpacks: tuple[TaskPackReadiness, ...]
    taskpacks: tuple[TaskPackReadiness, ...]
    checked_at: datetime

    _checked_at = field_validator("checked_at")(ModelCheckResult.require_utc_timestamp.__func__)

    @model_validator(mode="after")
    def validate_contract(self) -> "RuntimeReadinessResponse":
        ready_ids = tuple(
            item.task_pack_id for item in self.taskpacks if item.state is ReadinessState.READY
        )
        unavailable = tuple(
            item for item in self.taskpacks if item.state is not ReadinessState.READY
        )
        if self.available_taskpacks != ready_ids or self.unavailable_taskpacks != unavailable:
            raise ValueError("taskpack summary contradicts detailed readiness")
        expected = self.model_ready and self.core_ready and bool(ready_ids)
        if self.runtime_available != expected:
            raise ValueError("runtime_available contradicts readiness components")
        if self.runtime_available != (self.state is ReadinessState.READY):
            raise ValueError("runtime availability contradicts state")
        if self.runtime_available and self.reason_codes:
            raise ValueError("available runtime cannot contain blocking reason codes")
        if not self.runtime_available and self.state not in self.reason_codes:
            raise ValueError("unavailable runtime must include its state as a reason code")
        return self


class RuntimeIdentityProjection(WorkbenchModel):
    """Public, non-secret identity for one admitted Runtime Snapshot."""

    snapshot_id: UUID
    provider: ProviderType
    model_id: str
    endpoint_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    taskpack_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    taskpack_version: str = Field(
        pattern=r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$",
        max_length=255,
    )

    _model_id = field_validator("model_id")(ModelProfileCreateRequest.validate_model_id.__func__)


class DockerStatusView(WorkbenchModel):
    available: bool
    message: str = Field(min_length=1, max_length=2_000)


class WorkbenchStatusResponse(WorkbenchModel):
    service: Literal["available"] = "available"
    mode: WorkbenchMode
    current_model: ModelProfileView | None
    docker: DockerStatusView
    storage: Literal["available"] = "available"
    available_run_modes: list[RunMode]


class ErrorObject(WorkbenchModel):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,127}$")
    message: str = Field(min_length=1, max_length=2_000)
    retryable: bool = False
    next_action: str | None = Field(default=None, max_length=2_000)


class ErrorResponse(WorkbenchModel):
    error: ErrorObject


_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")


def _relative_runtime_path(value: str) -> str:
    if "\\" in value or "\x00" in value:
        raise ValueError("runtime paths must use safe repository-relative POSIX notation")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError("runtime path must remain relative to the repository")
    return path.as_posix()


def _environment_name(value: str) -> str:
    if not _ENV_NAME.fullmatch(value):
        raise ValueError("invalid environment variable name")
    return value


class WorkbenchSettingsBase(WorkbenchModel):
    mode: WorkbenchMode
    host: Literal["127.0.0.1"]
    database: str
    runs_directory: str
    max_concurrent_runs: Literal[1]

    _database = field_validator("database")(_relative_runtime_path)
    _runs_directory = field_validator("runs_directory")(_relative_runtime_path)


class DevelopmentWorkbenchSettings(WorkbenchSettingsBase):
    mode: Literal[WorkbenchMode.DEVELOPMENT]
    security_default_provider: Literal[ProviderType.KIMI]


class LockedModelSettings(WorkbenchModel):
    provider: Literal[ProviderType.KIMI]
    model_id: str
    reported: Literal[True]
    gateway_base_url_env: str
    credential_source: Literal["process_environment"] = "process_environment"
    credential_env: str
    gateway_allowlist_env: str

    _model_id = field_validator("model_id")(ModelProfileCreateRequest.validate_model_id.__func__)
    _gateway_base_url_env = field_validator("gateway_base_url_env")(_environment_name)
    _credential_env = field_validator("credential_env")(_environment_name)
    _gateway_allowlist_env = field_validator("gateway_allowlist_env")(_environment_name)


class CompetitionWorkbenchSettings(WorkbenchSettingsBase):
    mode: Literal[WorkbenchMode.COMPETITION]
    locked_model: LockedModelSettings

    @model_validator(mode="after")
    def require_distinct_runtime_paths(self) -> "CompetitionWorkbenchSettings":
        if self.database == self.runs_directory:
            raise ValueError("database and runs_directory must be distinct")
        return self


WorkbenchSettings = Annotated[
    DevelopmentWorkbenchSettings | CompetitionWorkbenchSettings,
    Field(discriminator="mode"),
]
_WORKBENCH_SETTINGS_ADAPTER = TypeAdapter(WorkbenchSettings)


def parse_workbench_settings(values: object) -> WorkbenchSettings:
    """Parse a trusted YAML mapping without accepting mode-specific extras."""

    return _WORKBENCH_SETTINGS_ADAPTER.validate_python(values)


def normalize_model_base_url(value: str) -> str:
    """Normalize the URL shape; address safety is enforced by endpoint policy later."""

    normalized = value.strip()
    if not normalized or len(normalized) > 2_048:
        raise ValueError("base_url must contain 1 to 2048 characters")
    if any(character in normalized for character in ("\\", "\r", "\n", "\t", "\x00")):
        raise ValueError("base_url contains a forbidden character")
    try:
        parsed = urlsplit(normalized)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("base_url is invalid") from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("base_url must use HTTPS")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must contain a host and no credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url cannot contain a query or fragment")
    hostname = parsed.hostname.rstrip(".").lower()
    if not hostname:
        raise ValueError("base_url host is empty")
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        authority = f"{authority}:{port}"
    path = (parsed.path or "").rstrip("/")
    return urlunsplit(("https", authority, path, "", ""))


__all__ = [
    "ActiveModelProfileRequest",
    "CompetitionWorkbenchSettings",
    "DevelopmentWorkbenchSettings",
    "ErrorObject",
    "ErrorResponse",
    "LockedModelSettings",
    "DockerStatusView",
    "ModelCheckResult",
    "ModelCheckStatus",
    "CapabilityProbeRecord",
    "ModelCredentialRequest",
    "ModelProfileCreateRequest",
    "ModelProfileUpdateRequest",
    "ModelProfileView",
    "ProviderType",
    "ReadinessState",
    "ModelRuntimeReadiness",
    "RuntimeReadinessResponse",
    "RuntimeIdentityProjection",
    "TaskPackReadiness",
    "RunCreateRequest",
    "RunMode",
    "ShutdownRequest",
    "WorkbenchMode",
    "WorkbenchStatusResponse",
    "WorkbenchSettings",
    "normalize_model_base_url",
    "parse_workbench_settings",
]
