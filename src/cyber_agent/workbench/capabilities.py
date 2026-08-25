"""Model capability probes and graded local workbench readiness."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import UUID, uuid4

from cyber_agent.contracts.errors import CyberAgentError
from cyber_agent.contracts.model import ModelPurpose, ModelRequest, ReasoningEffort
from cyber_agent.workbench.adapters import AdapterFactoryError
from cyber_agent.workbench.profiles import ModelProfileStore
from cyber_agent.workbench.schemas import (
    CapabilityProbeRecord,
    DockerStatusView,
    ModelCheckResult,
    ModelCheckStatus,
    ModelRuntimeReadiness,
    ReadinessState,
    RunMode,
    WorkbenchStatusResponse,
)
from cyber_agent.workbench.store import StoredModelProfile


class CapabilityAdapter(Protocol):
    async def generate_structured(self, request: ModelRequest): ...

    async def aclose(self) -> None: ...


class CapabilityAdapterFactory(Protocol):
    def create(self, profile: StoredModelProfile) -> CapabilityAdapter: ...

    def capability_probe_fingerprint(
        self,
        profile: StoredModelProfile,
        *,
        observed_at: datetime,
    ) -> str: ...


_PROBE_SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean", "const": True}},
    "required": ["ok"],
    "additionalProperties": False,
}
_CAPABILITY_CONTRACT_VERSION = "structured-output/v1"
_DEFAULT_PROBE_TTL = timedelta(minutes=30)
_MIN_PROBE_TTL = timedelta(minutes=1)
_MAX_PROBE_TTL = timedelta(days=1)


class ModelCapabilityService:
    """Verify one configured model and expose fail-closed run-mode readiness."""

    def __init__(
        self,
        *,
        profiles: ModelProfileStore,
        adapter_factory: CapabilityAdapterFactory,
        docker_probe: Callable[[], tuple[bool, str]],
        probe_ttl_seconds: int = int(_DEFAULT_PROBE_TTL.total_seconds()),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        probe_ttl = timedelta(seconds=probe_ttl_seconds)
        if not _MIN_PROBE_TTL <= probe_ttl <= _MAX_PROBE_TTL:
            raise ValueError("probe_ttl must be between 60 and 86400 seconds")
        self._profiles = profiles
        self._adapter_factory = adapter_factory
        self._docker_probe = docker_probe
        self._probe_ttl = probe_ttl
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    async def check_model(self, profile_id: UUID) -> ModelCheckResult:
        profile = self._profiles.get(profile_id)
        checked_at = self._utc_now()
        adapter: CapabilityAdapter | None = None
        passed = False
        code = "MODEL_CHECK_FAILED"
        message = "The model capability check failed."
        endpoint_fingerprint: str | None = None

        if not profile.credential_present:
            code = "MODEL_CREDENTIAL_MISSING"
            message = "Save an API credential before checking this model profile."
        else:
            try:
                adapter = self._adapter_factory.create(profile)
                response = await adapter.generate_structured(
                    ModelRequest(
                        purpose=ModelPurpose.TASK_UNDERSTANDING,
                        system_instructions=(
                            "Return only one JSON object that matches the supplied schema. "
                            "Set ok to true. Do not call tools or include additional fields."
                        ),
                        context={"probe": "structured_output"},
                        output_schema=_PROBE_SCHEMA,
                        reasoning_effort=ReasoningEffort.LOW,
                        max_output_tokens=2048,
                        timeout_seconds=30,
                    )
                )
                if response.schema_valid and response.data == {"ok": True}:
                    endpoint_fingerprint = (
                        self._adapter_factory.capability_probe_fingerprint(
                            profile,
                            observed_at=checked_at,
                        )
                    )
                    passed = True
                    code = "MODEL_CHECK_PASSED"
                    message = "The model passed the structured-output capability check."
                else:
                    code = "MODEL_STRUCTURED_OUTPUT_INCOMPATIBLE"
                    message = "The model did not return the required structured probe result."
            except CyberAgentError as exc:
                code = exc.error.code
                message = exc.error.safe_message
            except AdapterFactoryError:
                code = "MODEL_CHECK_SETUP_FAILED"
                message = "The model profile could not be prepared for a capability check."
            except Exception:
                code = "MODEL_CHECK_FAILED"
                message = "The model capability check failed safely."
            finally:
                if adapter is not None:
                    try:
                        await adapter.aclose()
                    except Exception:
                        pass

        probe = CapabilityProbeRecord(
            probe_id=uuid4(),
            profile_id=profile_id,
            provider=profile.provider,
            model_id=profile.model_id,
            base_url_fingerprint=self._base_url_fingerprint(profile.base_url),
            endpoint_snapshot_fingerprint=endpoint_fingerprint if passed else None,
            credential_version=profile.credential_version,
            capability_contract_version=_CAPABILITY_CONTRACT_VERSION,
            status=ModelCheckStatus.PASSED if passed else ModelCheckStatus.FAILED,
            reason_code=code,
            checked_at=checked_at,
            expires_at=checked_at + self._probe_ttl,
        )
        view = self._profiles.record_probe(probe, message=message)
        return ModelCheckResult(
            profile_id=profile_id,
            passed=passed,
            code=code,
            message=message,
            checked_at=checked_at,
            expires_at=probe.expires_at,
            probe_id=probe.probe_id,
            active=view.active,
        )

    def runtime_readiness(self, profile_id: UUID | None = None) -> ModelRuntimeReadiness:
        """Evaluate current model evidence without mutating its historical result."""

        if profile_id is None:
            current = next((view for view in self._profiles.list_views() if view.active), None)
            if current is None:
                return self._not_ready(ReadinessState.MODEL_NOT_READY)
            profile_id = current.profile_id
        profile = self._profiles.get(profile_id)
        if not self._profiles.credential_available(profile_id):
            return self._not_ready(ReadinessState.CREDENTIAL_MISSING)
        probe = self._profiles.current_probe(profile_id)
        if probe is None:
            state = (
                ReadinessState.CAPABILITY_FAILED
                if profile.check_status is ModelCheckStatus.FAILED
                else ReadinessState.CAPABILITY_STALE
                if profile.check_status is ModelCheckStatus.PASSED
                else ReadinessState.MODEL_NOT_READY
            )
            return self._not_ready(state)
        if (
            probe.provider is not profile.provider
            or probe.model_id != profile.model_id
            or probe.base_url_fingerprint != self._base_url_fingerprint(profile.base_url)
            or probe.credential_version != profile.credential_version
            or probe.capability_contract_version != _CAPABILITY_CONTRACT_VERSION
            or self._utc_now() >= probe.expires_at
        ):
            return self._not_ready(ReadinessState.CAPABILITY_STALE, probe.probe_id)
        if probe.status is not ModelCheckStatus.PASSED:
            return self._not_ready(ReadinessState.CAPABILITY_FAILED, probe.probe_id)
        try:
            current_endpoint = self._adapter_factory.capability_probe_fingerprint(
                profile,
                observed_at=probe.checked_at,
            )
        except Exception:
            return self._not_ready(ReadinessState.CAPABILITY_STALE, probe.probe_id)
        if current_endpoint != probe.endpoint_snapshot_fingerprint:
            return self._not_ready(ReadinessState.CAPABILITY_STALE, probe.probe_id)
        return ModelRuntimeReadiness(
            ready=True,
            state=ReadinessState.READY,
            reason_codes=(),
            capability_probe_ref=probe.probe_id,
        )

    def status(self) -> WorkbenchStatusResponse:
        current = next((view for view in self._profiles.list_views() if view.active), None)
        model_ready = bool(
            current is not None
            and current.credential_present
            and current.check_status is ModelCheckStatus.PASSED
            and self._check_snapshot_current(self._profiles.get(current.profile_id))
        )
        try:
            docker_available, docker_message = self._docker_probe()
        except Exception:
            docker_available, docker_message = False, "Docker availability check failed safely."
        docker_message = (docker_message or "Docker availability is unknown.")[:2_000]

        modes = [RunMode.REPLAY_FAKE]
        if model_ready:
            modes.append(RunMode.MODEL_FAKE)
            if docker_available:
                modes.append(RunMode.MODEL_DOCKER)
        return WorkbenchStatusResponse(
            mode=self._profiles.mode,
            current_model=current,
            docker=DockerStatusView(available=docker_available, message=docker_message),
            available_run_modes=modes,
        )

    def activate(self, profile_id: UUID):
        readiness = self.runtime_readiness(profile_id)
        if not readiness.ready:
            from cyber_agent.workbench.profiles import ProfileNotReadyError

            raise ProfileNotReadyError(
                f"model profile is not ready: {readiness.state.value}"
            )
        return self._profiles.activate(profile_id)

    def _check_snapshot_current(self, profile: StoredModelProfile) -> bool:
        checker = getattr(self._adapter_factory, "is_check_current", None)
        if checker is None:
            return True
        try:
            return bool(checker(profile))
        except Exception:
            return False

    def _utc_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("capability probe clock must return a timezone-aware value")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _base_url_fingerprint(base_url: str) -> str:
        return hashlib.sha256(base_url.encode("utf-8")).hexdigest()

    @staticmethod
    def _not_ready(
        state: ReadinessState,
        probe_id: UUID | None = None,
    ) -> ModelRuntimeReadiness:
        return ModelRuntimeReadiness(
            ready=False,
            state=state,
            reason_codes=(state,),
            capability_probe_ref=probe_id,
        )


__all__ = ["ModelCapabilityService"]
