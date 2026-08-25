"""Trusted, conclusion-free configuration for the incident login-chain pipeline."""

from __future__ import annotations

from uuid import UUID

from pydantic import model_validator

from cyber_agent.contracts.common import MachineName, Sha256, StrictModel

from .manifest import INCIDENT_LOGIN_CHAIN_REQUIRED_TOOLS


class IncidentLoginChainScenarioConfig(StrictModel):
    """Bind one log-bundle artifact to the fixed two-tool read-only scope."""

    artifact_id: UUID
    artifact_sha256: Sha256
    network_access: bool = False
    allowed_tools: tuple[MachineName, ...]

    @model_validator(mode="after")
    def only_fixed_incident_tools_are_allowed(self) -> "IncidentLoginChainScenarioConfig":
        if self.allowed_tools != INCIDENT_LOGIN_CHAIN_REQUIRED_TOOLS:
            raise ValueError("allowed_tools must match the fixed incident login-chain pipeline")
        return self


__all__ = ["IncidentLoginChainScenarioConfig"]
