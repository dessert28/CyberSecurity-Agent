"""Trusted, conclusion-free configuration for the reverse keycheck pipeline."""

from __future__ import annotations

from uuid import UUID

from pydantic import model_validator

from cyber_agent.contracts.common import MachineName, Sha256, StrictModel

from .manifest import REVERSE_KEYCHECK_REQUIRED_TOOLS


class ReverseKeycheckScenarioConfig(StrictModel):
    """Bind one binary artifact to the fixed two-tool keycheck scope."""

    artifact_id: UUID
    artifact_sha256: Sha256
    network_access: bool = False
    allowed_tools: tuple[MachineName, ...]

    @model_validator(mode="after")
    def only_fixed_reverse_tools_are_allowed(self) -> "ReverseKeycheckScenarioConfig":
        if self.allowed_tools != REVERSE_KEYCHECK_REQUIRED_TOOLS:
            raise ValueError("allowed_tools must match the fixed reverse keycheck pipeline")
        return self


__all__ = ["ReverseKeycheckScenarioConfig"]
