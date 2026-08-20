"""Evidence and independent verification contracts."""

from __future__ import annotations

from enum import Enum
from uuid import UUID, uuid4

from pydantic import Field

from .common import ArtifactRef, EntityRef, StableCode, StrictModel, UtcDateTime


class EvidenceKind(str, Enum):
    TOOL_OBSERVATION = "tool_observation"
    RULE_VERIFICATION = "rule_verification"
    MODEL_INFERENCE = "model_inference"
    HUMAN_CONFIRMATION = "human_confirmation"


class VerificationMethod(str, Enum):
    DIRECT_OBSERVATION = "direct_observation"
    RULE = "rule"
    COMPARISON = "comparison"
    REPLAY = "replay"
    MODEL = "model"
    HUMAN = "human"


class VerificationOutcome(str, Enum):
    VERIFIED = "verified"
    INSUFFICIENT = "insufficient"
    FAILED = "failed"
    BLOCKED = "blocked"


class Evidence(StrictModel):
    evidence_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    source_ref: EntityRef
    kind: EvidenceKind
    artifact_ref: ArtifactRef | None = None
    summary: str = Field(min_length=1, max_length=20_000)
    supports_claims: list[str] = Field(default_factory=list)
    verification_method: VerificationMethod
    confidence: float = Field(ge=0, le=1)
    created_at: UtcDateTime


class VerificationVerdict(StrictModel):
    outcome: VerificationOutcome
    reason_codes: list[StableCode] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    summary: str = Field(min_length=1, max_length=20_000)
