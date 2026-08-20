"""Stable report discovery contracts for competition presentation clients."""

from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from cyber_agent.contracts.common import (
    MachineName,
    Sha256,
    StableCode,
    StrictModel,
    UtcDateTime,
)
from cyber_agent.contracts.evidence import VerificationOutcome


class ReportStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class ReportFormat(str, Enum):
    PDF = "pdf"
    JSON = "json"
    AUDIT_JSON = "audit_json"


class ReportArtifactProjection(StrictModel):
    """One immutable report artifact exposed for download."""

    format: ReportFormat
    media_type: str = Field(min_length=1, max_length=255)
    file_name: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(ge=0)
    sha256: Sha256
    download_url: str = Field(min_length=1, max_length=2048)

    @field_validator("file_name")
    @classmethod
    def file_name_is_leaf_only(cls, value: str) -> str:
        if value in {".", ".."} or any(character in value for character in ("/", "\\", "\x00")):
            raise ValueError("report file_name must not contain a path")
        return value

    @field_validator("download_url")
    @classmethod
    def download_url_is_local_api_path(cls, value: str) -> str:
        if not value.startswith("/api/v1/runs/") or ".." in value.split("/"):
            raise ValueError("report download_url must be a local run API path")
        return value


class ReportProjection(StrictModel):
    """Report availability and immutable artifact metadata for one run."""

    run_id: UUID
    status: ReportStatus
    title: str = Field(min_length=1, max_length=500)
    template_id: MachineName
    verdict_outcome: VerificationOutcome | None = None
    evidence_count: int = Field(ge=0)
    audit_count: int = Field(ge=0)
    generated_at: UtcDateTime | None = None
    artifacts: tuple[ReportArtifactProjection, ...] = ()
    reason_code: StableCode | None = None

    @model_validator(mode="after")
    def readiness_matches_artifacts(self) -> "ReportProjection":
        if self.status is ReportStatus.READY:
            if self.generated_at is None or not self.artifacts:
                raise ValueError("ready reports require generated artifacts and a timestamp")
            if self.reason_code is not None:
                raise ValueError("ready reports cannot carry a failure reason")
        else:
            if self.artifacts or self.generated_at is not None:
                raise ValueError("non-ready reports cannot expose generated artifacts")
            if self.status in {ReportStatus.UNAVAILABLE, ReportStatus.FAILED} and self.reason_code is None:
                raise ValueError("unavailable and failed reports require a reason code")
        formats = [artifact.format for artifact in self.artifacts]
        if len(formats) != len(set(formats)):
            raise ValueError("report artifact formats must be unique")
        expected_prefix = f"/api/v1/runs/{self.run_id}/report/"
        if any(
            not artifact.download_url.startswith(expected_prefix)
            for artifact in self.artifacts
        ):
            raise ValueError("report artifacts must belong to the projected run")
        return self


@runtime_checkable
class ReportProviderPort(Protocol):
    """Future report generators implement discovery without changing the API."""

    async def describe(self, run_id: UUID) -> ReportProjection: ...


__all__ = [
    "ReportArtifactProjection",
    "ReportFormat",
    "ReportProjection",
    "ReportProviderPort",
    "ReportStatus",
]
