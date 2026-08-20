"""Competition-facing upload lifecycle for source ZIP artifacts."""

from __future__ import annotations

import hashlib
import hmac
import inspect
from enum import Enum
from typing import Awaitable, Callable
from uuid import UUID, uuid4

from pydantic import Field

from cyber_agent.artifacts import ArtifactMaterializationError
from cyber_agent.contracts import (
    ArtifactMaterializationRequest,
    ArtifactMaterializerPort,
    ArtifactRef,
)
from cyber_agent.contracts.common import Sha256, StrictModel
from cyber_agent.contracts.ports import ArtifactStorePort
from cyber_agent.contracts.source_audit_budget import SourceAuditResourceBudget


class ArtifactUploadState(str, Enum):
    UPLOADED = "uploaded"
    VALIDATED = "validated"


class ArtifactUploadError(ValueError):
    """Safe upload failure carrying a stable public error code."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class ArtifactUploadResponse(StrictModel):
    artifact_id: UUID
    sha256: Sha256
    media_type: str = Field(pattern=r"^application/zip$")
    size: int = Field(ge=0)

    @classmethod
    def from_ref(cls, artifact: ArtifactRef) -> "ArtifactUploadResponse":
        return cls(
            artifact_id=artifact.artifact_id,
            sha256=artifact.sha256,
            media_type=artifact.media_type,
            size=artifact.size_bytes,
        )


DeleteArtifact = Callable[[UUID], Awaitable[None] | None]


class ArtifactUploadService:
    """Quarantine, validate, and publish ZIP references for Source Audit."""

    def __init__(
        self,
        *,
        store: ArtifactStorePort,
        materializer: ArtifactMaterializerPort,
        max_upload_bytes: int | None = None,
        resource_budget: SourceAuditResourceBudget | None = None,
    ) -> None:
        if not isinstance(store, ArtifactStorePort):
            raise TypeError("store does not implement ArtifactStorePort")
        if not isinstance(materializer, ArtifactMaterializerPort):
            raise TypeError("materializer does not implement ArtifactMaterializerPort")
        if resource_budget is not None and not isinstance(
            resource_budget, SourceAuditResourceBudget
        ):
            raise TypeError("resource_budget must be a SourceAuditResourceBudget")
        if resource_budget is not None:
            if (
                max_upload_bytes is not None
                and max_upload_bytes != resource_budget.max_upload_bytes
            ):
                raise ValueError("max_upload_bytes conflicts with resource_budget")
            max_upload_bytes = resource_budget.max_upload_bytes
        if max_upload_bytes is None or not 1 <= max_upload_bytes <= 1_000_000_000:
            raise ValueError("max_upload_bytes must be between 1 and 1,000,000,000")
        self._store = store
        self._materializer = materializer
        self._max_upload_bytes = max_upload_bytes
        self._states: dict[UUID, ArtifactUploadState] = {}
        self._validated: dict[UUID, ArtifactRef] = {}

    @property
    def max_upload_bytes(self) -> int:
        return self._max_upload_bytes

    async def upload_zip(self, content: bytes, *, media_type: str) -> ArtifactRef:
        if media_type.strip().lower() != "application/zip":
            raise ArtifactUploadError(
                "ARTIFACT_MEDIA_TYPE_DENIED",
                "Only application/zip source artifacts are accepted.",
                status_code=415,
            )
        if not isinstance(content, bytes):
            raise ArtifactUploadError(
                "ARTIFACT_CONTENT_INVALID",
                "Artifact content must be a binary request body.",
                status_code=422,
            )
        if not content:
            raise ArtifactUploadError(
                "ARTIFACT_CONTENT_EMPTY",
                "The source artifact cannot be empty.",
                status_code=422,
            )
        if len(content) > self._max_upload_bytes:
            raise ArtifactUploadError(
                "ARTIFACT_SIZE_EXCEEDED",
                "The source artifact exceeds the configured upload limit.",
                status_code=413,
            )

        expected_sha256 = hashlib.sha256(content).hexdigest()
        try:
            artifact = await self._store.put_bytes(
                content,
                media_type="application/zip",
                quarantined=True,
            )
        except Exception as exc:
            raise ArtifactUploadError(
                "ARTIFACT_STORE_WRITE_FAILED",
                "The artifact could not be placed in trusted quarantine.",
                status_code=503,
            ) from exc

        self._states[artifact.artifact_id] = ArtifactUploadState.UPLOADED
        if (
            artifact.media_type != "application/zip"
            or artifact.size_bytes != len(content)
            or not hmac.compare_digest(artifact.sha256, expected_sha256)
            or artifact.quarantined is not True
        ):
            await self._discard(artifact.artifact_id)
            raise ArtifactUploadError(
                "ARTIFACT_STORE_REFERENCE_INVALID",
                "The artifact store returned inconsistent quarantine metadata.",
                status_code=503,
            )

        lease = None
        try:
            lease = await self._materializer.materialize(
                ArtifactMaterializationRequest(
                    run_id=uuid4(),
                    artifact=artifact,
                    expected_sha256=expected_sha256,
                    max_size_bytes=self._max_upload_bytes,
                )
            )
            await self._materializer.cleanup(lease.materialization_id)
        except ArtifactMaterializationError as exc:
            await self._discard(artifact.artifact_id)
            raise ArtifactUploadError(
                exc.code,
                str(exc),
                status_code=_materialization_status(exc.code),
            ) from exc
        except Exception as exc:
            if lease is not None:
                try:
                    await self._materializer.cleanup(lease.materialization_id)
                except Exception:
                    pass
            await self._discard(artifact.artifact_id)
            raise ArtifactUploadError(
                "ARTIFACT_VALIDATION_FAILED",
                "The artifact could not be validated safely.",
                status_code=503,
            ) from exc

        validated = artifact.model_copy(update={"quarantined": False}, deep=True)
        self._validated[validated.artifact_id] = validated
        self._states[validated.artifact_id] = ArtifactUploadState.VALIDATED
        return validated.model_copy(deep=True)

    def resolve(self, artifact_id: UUID) -> ArtifactRef:
        try:
            artifact = self._validated[artifact_id]
        except KeyError as exc:
            raise KeyError("artifact is not validated for task use") from exc
        return artifact.model_copy(deep=True)

    def state(self, artifact_id: UUID) -> ArtifactUploadState:
        try:
            return self._states[artifact_id]
        except KeyError as exc:
            raise KeyError("artifact upload is not registered") from exc

    async def _discard(self, artifact_id: UUID) -> None:
        self._states.pop(artifact_id, None)
        self._validated.pop(artifact_id, None)
        delete: DeleteArtifact | None = getattr(self._store, "delete", None)
        if delete is None:
            return
        try:
            result = delete(artifact_id)
            if inspect.isawaitable(result):
                await result
        except Exception:
            return


def _materialization_status(code: str) -> int:
    if code == "ARTIFACT_SIZE_EXCEEDED":
        return 413
    if code == "ARTIFACT_MEDIA_TYPE_DENIED":
        return 415
    if code in {
        "ARTIFACT_STORE_READ_FAILED",
        "ARTIFACT_STORE_RESULT_INVALID",
        "MATERIALIZATION_PATH_DENIED",
        "MATERIALIZATION_WRITE_FAILED",
        "MATERIALIZATION_LEASE_INVALID",
        "MATERIALIZATION_CLEANUP_FAILED",
    }:
        return 503
    return 422


__all__ = [
    "ArtifactUploadError",
    "ArtifactUploadResponse",
    "ArtifactUploadService",
    "ArtifactUploadState",
]
