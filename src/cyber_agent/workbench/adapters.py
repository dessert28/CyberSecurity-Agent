"""Allowlisted model adapter construction from validated profiles."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from cyber_agent.model_gateway import (
    KimiK3Adapter,
    KimiK3Config,
    OpenAICompatibleAdapter,
    OpenAICompatibleConfig,
    StructuredOutputMode,
)
from cyber_agent.workbench.credentials import CredentialBackendError, CredentialStore
from cyber_agent.workbench.endpoint_policy import (
    EndpointPolicyError,
    EndpointSnapshot,
    ModelEndpointPolicy,
    endpoint_snapshot_fingerprint,
)
from cyber_agent.workbench.schemas import ProviderType
from cyber_agent.workbench.store import StoredModelProfile


class AdapterFactoryError(RuntimeError):
    pass


class ModelAdapterFactory:
    """Construct only built-in adapter classes; browser input cannot extend routing."""

    _INTERNAL_KEY_NAME = "CYBER_AGENT_INTERNAL_MODEL_KEY"

    def __init__(
        self,
        *,
        credentials: CredentialStore,
        endpoint_policy: ModelEndpointPolicy,
    ) -> None:
        self._credentials = credentials
        self._endpoint_policy = endpoint_policy
        self._check_snapshots: dict[UUID, EndpointSnapshot] = {}

    def create(self, profile: StoredModelProfile):
        if not isinstance(profile.provider, ProviderType):
            raise AdapterFactoryError("model profile provider is not allowlisted")
        try:
            secret = self._credentials.get(profile.profile_id)
        except CredentialBackendError as exc:
            raise AdapterFactoryError("model credential could not be read") from exc
        if not secret:
            raise AdapterFactoryError("model credential is unavailable")
        try:
            snapshot = self._endpoint_policy.validate_and_snapshot(profile.base_url)
        except EndpointPolicyError as exc:
            raise AdapterFactoryError("model endpoint failed policy validation") from exc
        self._check_snapshots[profile.profile_id] = snapshot

        def request_guard() -> None:
            self._endpoint_policy.revalidate(snapshot)

        environment = {self._INTERNAL_KEY_NAME: secret}
        if profile.provider is ProviderType.KIMI:
            return KimiK3Adapter(
                KimiK3Config(
                    base_url=profile.base_url,
                    model=profile.model_id,
                    api_key_env=self._INTERNAL_KEY_NAME,
                ),
                environment=environment,
                request_guard=request_guard,
            )
        if profile.provider in {
            ProviderType.DEEPSEEK,
            ProviderType.QWEN,
            ProviderType.DOMESTIC_COMPATIBLE,
            ProviderType.OPENAI_COMPATIBLE,
        }:
            return OpenAICompatibleAdapter(
                OpenAICompatibleConfig(
                    provider=(
                        profile.provider.value
                        if profile.provider is ProviderType.DEEPSEEK
                        else ProviderType.OPENAI_COMPATIBLE.value
                    ),
                    base_url=profile.base_url,
                    model=profile.model_id,
                    api_key_env=self._INTERNAL_KEY_NAME,
                    structured_output_mode=StructuredOutputMode.JSON_OBJECT,
                ),
                environment=environment,
                request_guard=request_guard,
            )
        raise AdapterFactoryError("model profile provider is not allowlisted")

    def is_check_current(self, profile: StoredModelProfile) -> bool:
        """Return whether the last check's endpoint snapshot still resolves identically."""

        snapshot = self._check_snapshots.get(profile.profile_id)
        if snapshot is None or snapshot.base_url != profile.base_url:
            return False
        try:
            self._endpoint_policy.revalidate(snapshot)
        except EndpointPolicyError:
            return False
        return True

    def capability_probe_fingerprint(
        self,
        profile: StoredModelProfile,
        *,
        observed_at: datetime,
    ) -> str:
        """Fingerprint the validated endpoint used by the just-completed probe."""

        try:
            snapshot = self._check_snapshots.get(profile.profile_id)
            if snapshot is None or snapshot.base_url != profile.base_url:
                current = self._endpoint_policy.validate_and_snapshot(profile.base_url)
            else:
                current = self._endpoint_policy.revalidate(snapshot)
        except EndpointPolicyError as exc:
            raise AdapterFactoryError("model endpoint snapshot is stale") from exc
        return endpoint_snapshot_fingerprint(current, observed_at=observed_at)


__all__ = ["AdapterFactoryError", "ModelAdapterFactory"]
