"""Strict contracts for temporary read-only artifact inputs."""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from .common import ArtifactRef, Sha256, StrictModel, UtcDateTime
from .tool import MountSpec

SOURCE_ARCHIVE_CONTAINER_PATH = "/inputs/source.zip"


class ArtifactMaterializationRequest(StrictModel):
    """Bind one stored ZIP and trusted hash to the fixed container input path."""

    run_id: UUID
    artifact: ArtifactRef
    expected_sha256: Sha256
    expected_media_type: Literal["application/zip"] = "application/zip"
    container_path: Literal["/inputs/source.zip"] = SOURCE_ARCHIVE_CONTAINER_PATH
    read_only: Literal[True] = True
    max_size_bytes: int = Field(ge=1, le=1_000_000_000)
    lease_ttl_seconds: int = Field(default=120, ge=1, le=3600)

    @model_validator(mode="after")
    def artifact_metadata_matches_trusted_expectations(
        self,
    ) -> "ArtifactMaterializationRequest":
        if self.artifact.sha256 != self.expected_sha256:
            raise ValueError("artifact hash does not match the trusted expectation")
        if self.artifact.media_type != self.expected_media_type:
            raise ValueError("artifact media type is not allowed")
        if self.artifact.size_bytes > self.max_size_bytes:
            raise ValueError("artifact size exceeds the materialization limit")
        return self


class MaterializedArtifactInput(StrictModel):
    """Opaque lease metadata; deliberately contains no host filesystem path."""

    materialization_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    artifact_id: UUID
    artifact_sha256: Sha256
    media_type: Literal["application/zip"] = "application/zip"
    size_bytes: int = Field(ge=0, le=1_000_000_000)
    container_path: Literal["/inputs/source.zip"] = SOURCE_ARCHIVE_CONTAINER_PATH
    read_only: Literal[True] = True
    created_at: UtcDateTime
    expires_at: UtcDateTime

    @model_validator(mode="after")
    def lease_has_a_positive_lifetime(self) -> "MaterializedArtifactInput":
        if self.expires_at <= self.created_at:
            raise ValueError("materialization lease expires_at must follow created_at")
        return self

    def as_mount_spec(self) -> MountSpec:
        """Return the only public mount metadata exposed to the executor."""

        return MountSpec(
            artifact_id=self.artifact_id,
            container_path=self.container_path,
            read_only=self.read_only,
        )


@runtime_checkable
class ArtifactMaterializerPort(Protocol):
    """Create and clean an opaque read-only input lease for one run."""

    async def materialize(
        self,
        request: ArtifactMaterializationRequest,
    ) -> MaterializedArtifactInput: ...

    async def cleanup(self, materialization_id: UUID) -> None: ...


__all__ = [
    "ArtifactMaterializationRequest",
    "ArtifactMaterializerPort",
    "MaterializedArtifactInput",
    "SOURCE_ARCHIVE_CONTAINER_PATH",
]
