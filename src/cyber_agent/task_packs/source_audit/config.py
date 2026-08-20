"""Trusted, conclusion-free configuration for the Python audit pipeline."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from cyber_agent.contracts.common import MachineName, Sha256, StrictModel

from .manifest import SOURCE_AUDIT_REQUIRED_TOOLS


class SourceAuditScenarioConfig(StrictModel):
    """Bind one source artifact to the fixed three-tool audit scope."""

    artifact_id: UUID
    artifact_sha256: Sha256
    language: Literal["python"] = "python"
    audit_scope: Literal["sql_injection"] = "sql_injection"
    network_access: Literal[False] = False
    allowed_tools: tuple[MachineName, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def only_fixed_source_audit_tools_are_allowed(self) -> "SourceAuditScenarioConfig":
        if self.allowed_tools != SOURCE_AUDIT_REQUIRED_TOOLS:
            raise ValueError("allowed_tools must match the fixed source-audit pipeline")
        return self


__all__ = ["SourceAuditScenarioConfig"]
