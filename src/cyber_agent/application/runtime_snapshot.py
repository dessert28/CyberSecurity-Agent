"""Immutable runtime identity and preparation-context contracts."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Literal, Protocol, runtime_checkable
from uuid import UUID, uuid4

from pydantic import ConfigDict, Field

from cyber_agent.contracts.common import MachineName, Sha256, StrictModel, UtcDateTime
from cyber_agent.workbench.schemas import ProviderType, RuntimeIdentityProjection


class RuntimeSnapshot(StrictModel):
    """Frozen, non-secret identity for one admitted real Runtime."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        ser_json_bytes="base64",
        val_json_bytes="base64",
    )

    snapshot_id: UUID
    created_at: UtcDateTime
    runtime_mode: Literal["real"] = "real"
    profile_id: UUID
    provider: ProviderType
    model_id: str = Field(min_length=1, max_length=255)
    endpoint_fingerprint: Sha256
    credential_version: int = Field(ge=0)
    capability_probe_ref: UUID
    taskpack_id: MachineName
    taskpack_version: str = Field(
        pattern=r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$",
        max_length=255,
    )
    executor_profile: str = Field(
        pattern=r"^[a-z][a-z0-9_.-]{1,127}/[a-z0-9][a-z0-9_.-]{0,63}$"
    )
    tool_registry_fingerprint: Sha256
    policy_fingerprint: Sha256
    planner: Literal["PlannerService"] = "PlannerService"
    environment_fingerprint: Sha256

    def public_identity(self) -> RuntimeIdentityProjection:
        return RuntimeIdentityProjection(
            snapshot_id=self.snapshot_id,
            provider=self.provider,
            model_id=self.model_id,
            endpoint_fingerprint=self.endpoint_fingerprint,
            taskpack_id=self.taskpack_id,
            taskpack_version=self.taskpack_version,
        )


class RuntimeSnapshotConflictError(RuntimeError):
    """Raised when trusted runtime identity changes before admission publishes."""


@runtime_checkable
class PreparedRuntimeContextPort(Protocol):
    """A prepared Runtime that has not yet been admitted for execution."""

    snapshot: RuntimeSnapshot

    async def validate_admission(self) -> None: ...

    async def run_task(
        self,
        *,
        task_pack_id: str,
        request_text: str,
        artifact_id: UUID | None,
        scenario_input: Mapping[str, object],
    ) -> object: ...

    async def aclose(self) -> None: ...


class RuntimeSnapshotBuilder:
    """Build snapshots only from explicit, already-sanitized identity fields."""

    def __init__(
        self,
        *,
        snapshot_id_factory: Callable[[], UUID] = uuid4,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._snapshot_id_factory = snapshot_id_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def build(
        self,
        *,
        profile_id: UUID,
        provider: ProviderType,
        model_id: str,
        endpoint_fingerprint: str,
        credential_version: int,
        capability_probe_ref: UUID,
        taskpack_id: str,
        taskpack_version: str,
        executor_profile: str,
        tool_registry_fingerprint: str,
        policy_fingerprint: str,
        environment_fingerprint: str,
    ) -> RuntimeSnapshot:
        return RuntimeSnapshot(
            snapshot_id=self._snapshot_id_factory(),
            created_at=self._clock(),
            profile_id=profile_id,
            provider=provider,
            model_id=model_id,
            endpoint_fingerprint=endpoint_fingerprint,
            credential_version=credential_version,
            capability_probe_ref=capability_probe_ref,
            taskpack_id=taskpack_id,
            taskpack_version=taskpack_version,
            executor_profile=executor_profile,
            tool_registry_fingerprint=tool_registry_fingerprint,
            policy_fingerprint=policy_fingerprint,
            environment_fingerprint=environment_fingerprint,
        )


__all__ = [
    "PreparedRuntimeContextPort",
    "RuntimeSnapshot",
    "RuntimeSnapshotBuilder",
    "RuntimeSnapshotConflictError",
]
