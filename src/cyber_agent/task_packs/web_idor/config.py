"""Trusted, conclusion-free configuration for Web-IDOR observations."""

from __future__ import annotations

from enum import Enum

from pydantic import Field, field_validator, model_validator

from cyber_agent.contracts.common import StrictModel
from cyber_agent.contracts.task import ScopePolicy, TargetKind

from .manifest import WEB_IDOR_TOOL_ID


class WebIdorObservationType(str, Enum):
    AUTHORIZED_BASELINE = "authorized_baseline"
    CROSS_TENANT_PROBE = "cross_tenant_probe"


class WebIdorStepBinding(StrictModel):
    """Bind one planned ordinal to trusted actor and object metadata."""

    ordinal: int = Field(ge=1)
    observation_type: WebIdorObservationType
    actor_id: str = Field(min_length=1, max_length=255)
    expected_object_id: str = Field(min_length=1, max_length=255)

    @field_validator("actor_id", "expected_object_id")
    @classmethod
    def trusted_labels_are_safe(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("trusted binding labels must be trimmed printable text")
        return value


class WebIdorScenarioConfig(StrictModel):
    """Trusted scope and the exact baseline/probe bindings; never a verdict."""

    scope: ScopePolicy
    bindings: tuple[WebIdorStepBinding, ...] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def bindings_form_one_ordered_comparison(self) -> "WebIdorScenarioConfig":
        ordinals = [item.ordinal for item in self.bindings]
        if len(set(ordinals)) != 2:
            raise ValueError("bindings must use two unique ordinals")

        by_type = {item.observation_type: item for item in self.bindings}
        required = {
            WebIdorObservationType.AUTHORIZED_BASELINE,
            WebIdorObservationType.CROSS_TENANT_PROBE,
        }
        if set(by_type) != required:
            raise ValueError("bindings must contain one baseline and one probe")

        baseline = by_type[WebIdorObservationType.AUTHORIZED_BASELINE]
        probe = by_type[WebIdorObservationType.CROSS_TENANT_PROBE]
        if baseline.ordinal >= probe.ordinal:
            raise ValueError("bindings must place the baseline before the probe")
        if baseline.actor_id != probe.actor_id:
            raise ValueError("bindings must use the same trusted actor")
        if baseline.expected_object_id == probe.expected_object_id:
            raise ValueError("bindings must use distinct expected objects")
        if not self.scope.network_access:
            raise ValueError("scope must authorize network observations")
        if WEB_IDOR_TOOL_ID not in self.scope.allowed_tool_ids:
            raise ValueError("scope must authorize web.http_request")
        if not any(item.kind is TargetKind.URL for item in self.scope.allowed_targets):
            raise ValueError("scope must contain an authorized URL target")
        return self

    @property
    def baseline(self) -> WebIdorStepBinding:
        return self._binding_for_type(WebIdorObservationType.AUTHORIZED_BASELINE)

    @property
    def probe(self) -> WebIdorStepBinding:
        return self._binding_for_type(WebIdorObservationType.CROSS_TENANT_PROBE)

    def binding_for_ordinal(self, ordinal: int) -> WebIdorStepBinding:
        for binding in self.bindings:
            if binding.ordinal == ordinal:
                return binding
        raise ValueError("step ordinal has no trusted Web-IDOR binding")

    def _binding_for_type(
        self,
        observation_type: WebIdorObservationType,
    ) -> WebIdorStepBinding:
        for binding in self.bindings:
            if binding.observation_type is observation_type:
                return binding
        raise RuntimeError("validated Web-IDOR binding is missing")


__all__ = [
    "WebIdorObservationType",
    "WebIdorScenarioConfig",
    "WebIdorStepBinding",
]
