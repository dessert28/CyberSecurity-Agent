"""Trusted, conclusion-free configuration for the Pwn ret2win pipeline."""

from __future__ import annotations

from uuid import UUID

from pydantic import Field, model_validator

from cyber_agent.contracts.common import MachineName, Sha256, StrictModel

from .manifest import PWN_RET2WIN_REQUIRED_TOOLS


class PwnRet2winScenarioConfig(StrictModel):
    """Bind one executable artifact to the fixed two-tool ret2win scope."""

    artifact_id: UUID
    artifact_sha256: Sha256
    network_access: bool = False
    allowed_tools: tuple[MachineName, ...]
    target_host: str | None = Field(default=None, min_length=1, max_length=255)
    target_port: int | None = Field(default=None, ge=1, le=65535)

    @model_validator(mode="after")
    def only_fixed_pwn_tools_are_allowed(self) -> "PwnRet2winScenarioConfig":
        if self.allowed_tools != PWN_RET2WIN_REQUIRED_TOOLS:
            raise ValueError("allowed_tools must match the fixed Pwn ret2win pipeline")
        if (self.target_host is None) != (self.target_port is None):
            raise ValueError("target_host and target_port must be provided together")
        if self.target_host is not None and not self.network_access:
            raise ValueError("a remote pwn target requires network access")
        if self.target_host is not None and self.target_host not in {"127.0.0.1", "localhost"}:
            raise ValueError("only the loopback remote target is supported")
        return self


__all__ = ["PwnRet2winScenarioConfig"]
