"""Per-run construction of the formal, fail-closed Runtime core."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Protocol
from uuid import UUID

from cyber_agent.application.competition_service import (
    ArtifactResolver,
    CompetitionRunService,
)
from cyber_agent.application.run_management import RunManagementError
from cyber_agent.application.run_orchestrator import RunOrchestrator
from cyber_agent.application.runtime_fingerprints import (
    FingerprintInputError,
    fingerprint_environment,
    fingerprint_executor,
    fingerprint_policy,
    fingerprint_tool_registry,
)
from cyber_agent.application.runtime_snapshot import (
    RuntimeSnapshot,
    RuntimeSnapshotBuilder,
    RuntimeSnapshotConflictError,
)
from cyber_agent.audit_store.memory import InMemoryAuditStore
from cyber_agent.contracts.common import EnvironmentProfile, ModelProfileRef
from cyber_agent.contracts.model import ModelCallRef
from cyber_agent.contracts.ports import ModelGateway, ToolPlugin
from cyber_agent.contracts.source_audit_budget import SourceAuditResourceBudget
from cyber_agent.contracts.tool import ExecutionProfile, ResourceLimits, RunnerType
from cyber_agent.executor.controlled import ControlledExecutor
from cyber_agent.executor.source_analysis import SourceAnalysisRunner, SourceWorkerGuard
from cyber_agent.model_gateway import ModelCallCollector, TracingModelGateway
from cyber_agent.planner.service import PlannerService
from cyber_agent.task_packs import TaskPackCatalog, build_competition_task_pack_catalog
from cyber_agent.task_packs.source_audit import (
    SOURCE_AUDIT_TASK_PACK_ID,
    SOURCE_AUDIT_VERIFIER_ID,
)
from cyber_agent.task_packs.web_idor import WEB_IDOR_VERIFIER_ID
from cyber_agent.tools.hypothesis_validate import HypothesisValidatePlugin
from cyber_agent.tools.policy import PolicyGate
from cyber_agent.tools.project_inventory import ProjectInventoryPlugin
from cyber_agent.tools.python_dataflow import PythonDataflowPlugin
from cyber_agent.tools.registry import HealthState, ToolRegistry
from cyber_agent.verification import SourceAuditVerifier, VerifierRegistry, WebIdorVerifier
from cyber_agent.workbench.profiles import configuration_fingerprint
from cyber_agent.workbench.schemas import (
    CapabilityProbeRecord,
    ModelRuntimeReadiness,
    ReadinessState,
)
from cyber_agent.workbench.store import StoredModelProfile


@dataclass(frozen=True, slots=True)
class TaskPackRuntimeAssembly:
    """Trusted executor-side components supplied by a formal TaskPack provider."""

    plugins: tuple[ToolPlugin, ...]
    executor: ControlledExecutor
    executor_profile: str
    platform: str
    resource_budget: Mapping[str, object]
    execution_profile: ExecutionProfile | None = None
    image_digests: Mapping[str, str] = MappingProxyType({})

    def __post_init__(self) -> None:
        object.__setattr__(self, "plugins", tuple(self.plugins))
        object.__setattr__(
            self,
            "resource_budget",
            MappingProxyType(dict(self.resource_budget)),
        )
        object.__setattr__(
            self,
            "image_digests",
            MappingProxyType(dict(self.image_digests)),
        )


class TaskPackExecutorProvider(Protocol):
    """Supply trusted executor-side components for a TaskPack."""

    def readiness(self, task_pack_id: str) -> ReadinessState: ...

    async def build(self, task_pack_id: str) -> TaskPackRuntimeAssembly: ...


class SourceAuditExecutorProvider:
    """Production provider for the currently supported Source Audit TaskPack."""

    def __init__(
        self,
        *,
        budget: SourceAuditResourceBudget,
        artifact_reader: Callable[[UUID], Awaitable[bytes]],
        worker_guard: SourceWorkerGuard,
        platform: str,
    ) -> None:
        if not isinstance(budget, SourceAuditResourceBudget):
            raise TypeError("budget must be a SourceAuditResourceBudget")
        if not callable(artifact_reader):
            raise TypeError("artifact_reader must be callable")
        if not platform.strip():
            raise ValueError("platform must be a stable non-empty label")
        self._budget = budget
        self._artifact_reader = artifact_reader
        self._worker_guard = worker_guard
        self._platform = platform.strip()
        self._health_verified = False

    async def initialize(self) -> bool:
        """Cache only a verified guard result; any error remains unavailable."""

        try:
            self._health_verified = bool(await self._worker_guard.health_check())
        except Exception:
            self._health_verified = False
        return self._health_verified

    def readiness(self, task_pack_id: str) -> ReadinessState:
        if task_pack_id != SOURCE_AUDIT_TASK_PACK_ID or not self._health_verified:
            return ReadinessState.EXECUTOR_NOT_READY
        return ReadinessState.READY

    async def build(self, task_pack_id: str) -> TaskPackRuntimeAssembly:
        if task_pack_id != SOURCE_AUDIT_TASK_PACK_ID or not self._health_verified:
            raise RuntimeError("Source Audit executor is unavailable")
        try:
            healthy = bool(await self._worker_guard.health_check())
        except Exception:
            healthy = False
        if not healthy:
            self._health_verified = False
            raise RuntimeError("Source Audit executor health could not be verified")

        inventory_resources = self._resources(self._budget.inventory_output_bytes)
        dataflow_resources = self._resources(self._budget.dataflow_output_bytes)
        validation_resources = self._resources(self._budget.validation_output_bytes)
        runtime_available = lambda: self._health_verified
        plugins: tuple[ToolPlugin, ...] = (
            ProjectInventoryPlugin(
                runtime_available=runtime_available,
                resources=inventory_resources,
                timeout_seconds=self._budget.inventory_timeout_seconds,
            ),
            PythonDataflowPlugin(
                runtime_available=runtime_available,
                resources=dataflow_resources,
                timeout_seconds=self._budget.dataflow_timeout_seconds,
                max_members=self._budget.max_members,
            ),
            HypothesisValidatePlugin(
                runtime_available=runtime_available,
                resources=validation_resources,
                timeout_seconds=self._budget.validation_timeout_seconds,
            ),
        )
        runner = SourceAnalysisRunner(
            artifact_reader=self._artifact_reader,
            worker_guard=self._worker_guard,
        )
        return TaskPackRuntimeAssembly(
            plugins=plugins,
            executor=ControlledExecutor(source_analysis_runner=runner),
            executor_profile="controlled/source-analysis-worker-v1",
            platform=self._platform,
            resource_budget=self._budget.fingerprint_input(),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                entrypoint=["source.audit.worker"],
                default_timeout_seconds=max(
                    self._budget.inventory_timeout_seconds,
                    self._budget.dataflow_timeout_seconds,
                    self._budget.validation_timeout_seconds,
                ),
                max_timeout_seconds=max(
                    self._budget.inventory_timeout_seconds,
                    self._budget.dataflow_timeout_seconds,
                    self._budget.validation_timeout_seconds,
                ),
                default_resources=self._resources(
                    max(
                        self._budget.inventory_output_bytes,
                        self._budget.dataflow_output_bytes,
                        self._budget.validation_output_bytes,
                    )
                ),
            ),
        )

    def _resources(self, max_output_bytes: int) -> ResourceLimits:
        return ResourceLimits(
            cpu_cores=self._budget.cpu_cores,
            memory_megabytes=self._budget.memory_megabytes,
            max_processes=self._budget.max_processes,
            max_output_bytes=max_output_bytes,
        )


@dataclass(frozen=True, slots=True)
class _CapturedModelIdentity:
    profile_id: UUID
    provider: object
    model_id: str
    base_url: str
    credential_version: int
    probe_id: UUID
    endpoint_fingerprint: str
    probe_checked_at: datetime
    probe_expires_at: datetime


class PreparedRuntimeContext:
    """Process-local owner of one immutable formal Runtime composition."""

    def __init__(
        self,
        *,
        snapshot: RuntimeSnapshot,
        model_gateway: ModelGateway,
        planner: PlannerService,
        registry: ToolRegistry,
        policy_gate: PolicyGate,
        executor: ControlledExecutor,
        verifier_registry: VerifierRegistry,
        audit_store: InMemoryAuditStore,
        service: CompetitionRunService,
        model_call_collector: ModelCallCollector,
        validate_identity: Callable[[], None],
    ) -> None:
        self.snapshot = snapshot
        self.model_gateway = model_gateway
        self.planner = planner
        self.registry = registry
        self.policy_gate = policy_gate
        self.executor = executor
        self.verifier_registry = verifier_registry
        self.audit_store = audit_store
        self.service = service
        self._model_call_collector = model_call_collector
        self._validate_identity = validate_identity
        self._closed = False

    @property
    def model_call_refs(self) -> tuple[ModelCallRef, ...]:
        return self._model_call_collector.snapshot()

    async def validate_admission(self) -> None:
        if self._closed:
            raise RuntimeSnapshotConflictError("prepared Runtime is already closed")
        self._validate_identity()

    async def run_task(
        self,
        *,
        task_pack_id: str,
        request_text: str,
        artifact_id: UUID | None,
        scenario_input: Mapping[str, object],
    ) -> object:
        if self._closed:
            raise RuntimeError("prepared Runtime is closed")
        return await self.service.run_task(
            task_pack_id=task_pack_id,
            request_text=request_text,
            artifact_id=artifact_id,
            scenario_input=scenario_input,
        )

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        close = getattr(self.model_gateway, "aclose", None)
        if callable(close):
            await close()


class RealRuntimeFactory:
    """Create only real model/planner components; no fallback path exists."""

    _POLICY_CONFIG = MappingProxyType({"allowed_private_networks": ()})

    def __init__(
        self,
        *,
        profiles,
        capabilities,
        adapter_factory,
        executor_provider: TaskPackExecutorProvider | None = None,
        catalog: TaskPackCatalog | None = None,
        artifact_resolver: ArtifactResolver | None = None,
        planner_factory: Callable[[ModelGateway], PlannerService] = PlannerService,
        snapshot_builder: RuntimeSnapshotBuilder | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._profiles = profiles
        self._capabilities = capabilities
        self._adapter_factory = adapter_factory
        self._executor_provider = executor_provider
        self._catalog = catalog or build_competition_task_pack_catalog()
        self._artifact_resolver = artifact_resolver
        self._planner_factory = planner_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._snapshot_builder = snapshot_builder or RuntimeSnapshotBuilder(clock=self._clock)

    @property
    def adapter_factory(self):
        return self._adapter_factory

    def core_readiness(self) -> ReadinessState:
        if self._planner_factory is not PlannerService:
            return ReadinessState.PLANNER_NOT_READY
        if self._adapter_factory is None:
            return ReadinessState.ADAPTER_NOT_READY
        return ReadinessState.READY

    def taskpack_readiness(self, task_pack_id: str) -> ReadinessState:
        try:
            self._catalog.get(task_pack_id)
        except Exception:
            return ReadinessState.TASKPACK_DISABLED
        if self._executor_provider is None:
            return ReadinessState.EXECUTOR_NOT_READY
        try:
            state = self._executor_provider.readiness(task_pack_id)
        except Exception:
            return ReadinessState.EXECUTOR_NOT_READY
        return state if isinstance(state, ReadinessState) else ReadinessState.EXECUTOR_NOT_READY

    async def prepare(
        self,
        *,
        run_id: UUID,
        task_pack_id: str,
        request_text: str,
        artifact_id: UUID | None,
        scenario_input: Mapping[str, object],
    ) -> PreparedRuntimeContext:
        taskpack_state = self.taskpack_readiness(task_pack_id)
        if taskpack_state is not ReadinessState.READY:
            raise _admission_error(taskpack_state)

        profile, probe, captured = self._capture_ready_identity()
        adapter = None
        try:
            try:
                adapter = self._adapter_factory.create(profile)
                if not isinstance(adapter, ModelGateway):
                    raise TypeError("adapter does not implement the model gateway port")
            except Exception as exc:
                raise _admission_error(ReadinessState.ADAPTER_NOT_READY) from exc

            try:
                model_call_collector = ModelCallCollector()
                traced_gateway = TracingModelGateway(
                    delegate=adapter,
                    collector=model_call_collector,
                    run_id=run_id,
                    provider=profile.provider.value,
                    model_id=profile.model_id,
                )
                planner = self._planner_factory(traced_gateway)
                if type(planner) is not PlannerService:
                    raise TypeError("formal Runtime requires PlannerService")
            except Exception as exc:
                raise _admission_error(ReadinessState.PLANNER_NOT_READY) from exc

            assembly = await self._build_executor_assembly(task_pack_id)
            registry, tool_specs = await self._build_registry(assembly.plugins)
            policy_gate = self._build_policy()
            verifier_registry = self._build_verifier_registry()
            audit_store = InMemoryAuditStore()

            executor_fingerprint = self._executor_fingerprint(assembly, tool_specs)
            environment_profile = EnvironmentProfile(
                executor_backend=assembly.executor_profile.split("/", 1)[0],
                platform=assembly.platform,
                configuration_fingerprint=executor_fingerprint,
                image_digests=dict(assembly.image_digests),
            )
            model_profile = ModelProfileRef(
                provider=profile.provider.value,
                model=profile.model_id,
                configuration_fingerprint=configuration_fingerprint(profile),
            )
            orchestrator = RunOrchestrator(
                planner=planner,
                registry=registry,
                policy_gate=policy_gate,
                executor=assembly.executor,
                verifier_registry=verifier_registry,
                audit_store=audit_store,
                model_profile=model_profile,
                environment_profile=environment_profile,
                run_id_factory=lambda: run_id,
                clock=self._clock,
            )
            service = CompetitionRunService(
                catalog=self._catalog,
                orchestrator=orchestrator,
                tool_registry=registry,
                verifier_registry=verifier_registry,
                artifact_resolver=self._artifact_resolver,
                clock=self._clock,
            )
            service.validate_request(
                task_pack_id=task_pack_id,
                request_text=request_text,
                artifact_id=artifact_id,
                scenario_input=scenario_input,
            )

            self._assert_identity_current(captured)
            manifest = self._catalog.get(task_pack_id)
            snapshot = self._snapshot_builder.build(
                profile_id=profile.profile_id,
                provider=profile.provider,
                model_id=profile.model_id,
                endpoint_fingerprint=probe.endpoint_snapshot_fingerprint,
                credential_version=profile.credential_version,
                capability_probe_ref=probe.probe_id,
                taskpack_id=manifest.task_pack_id,
                taskpack_version=manifest.version,
                executor_profile=assembly.executor_profile,
                tool_registry_fingerprint=fingerprint_tool_registry(tool_specs),
                policy_fingerprint=fingerprint_policy(
                    policy_gate.POLICY_VERSION,
                    self._POLICY_CONFIG,
                ),
                environment_fingerprint=fingerprint_environment(environment_profile),
            )
            return PreparedRuntimeContext(
                snapshot=snapshot,
                model_gateway=traced_gateway,
                planner=planner,
                registry=registry,
                policy_gate=policy_gate,
                executor=assembly.executor,
                verifier_registry=verifier_registry,
                audit_store=audit_store,
                service=service,
                model_call_collector=model_call_collector,
                validate_identity=lambda: self._assert_identity_current(captured),
            )
        except Exception:
            if adapter is not None:
                await _close_adapter(adapter)
            raise

    def _capture_ready_identity(
        self,
    ) -> tuple[StoredModelProfile, CapabilityProbeRecord, _CapturedModelIdentity]:
        active = [item for item in self._profiles.list_views() if item.active]
        if len(active) != 1:
            raise _admission_error(ReadinessState.MODEL_NOT_READY)
        profile = self._profiles.get(active[0].profile_id)
        readiness: ModelRuntimeReadiness = self._capabilities.runtime_readiness(
            profile.profile_id
        )
        if not readiness.ready:
            raise _admission_error(readiness.state)
        probe = self._profiles.current_probe(profile.profile_id)
        if (
            probe is None
            or readiness.capability_probe_ref != probe.probe_id
            or probe.endpoint_snapshot_fingerprint is None
            or probe.profile_id != profile.profile_id
            or probe.provider is not profile.provider
            or probe.model_id != profile.model_id
            or probe.credential_version != profile.credential_version
        ):
            raise _admission_error(ReadinessState.CAPABILITY_STALE)
        captured = _CapturedModelIdentity(
            profile_id=profile.profile_id,
            provider=profile.provider,
            model_id=profile.model_id,
            base_url=profile.base_url,
            credential_version=profile.credential_version,
            probe_id=probe.probe_id,
            endpoint_fingerprint=probe.endpoint_snapshot_fingerprint,
            probe_checked_at=probe.checked_at,
            probe_expires_at=probe.expires_at,
        )
        return profile, probe, captured

    def _assert_identity_current(self, expected: _CapturedModelIdentity) -> None:
        try:
            _, _, current = self._capture_ready_identity()
        except Exception as exc:
            raise RuntimeSnapshotConflictError(
                "runtime identity changed during admission"
            ) from exc
        if current != expected:
            raise RuntimeSnapshotConflictError(
                "runtime identity changed during admission"
            )

    async def _build_executor_assembly(
        self,
        task_pack_id: str,
    ) -> TaskPackRuntimeAssembly:
        if self._executor_provider is None:
            raise _admission_error(ReadinessState.EXECUTOR_NOT_READY)
        try:
            assembly = await self._executor_provider.build(task_pack_id)
        except Exception as exc:
            raise _admission_error(ReadinessState.EXECUTOR_NOT_READY) from exc
        if (
            not isinstance(assembly, TaskPackRuntimeAssembly)
            or not isinstance(assembly.executor, ControlledExecutor)
            or not assembly.plugins
            or assembly.executor._fake is not None
        ):
            raise _admission_error(ReadinessState.EXECUTOR_NOT_READY)
        return assembly

    @staticmethod
    async def _build_registry(
        plugins: Sequence[ToolPlugin],
    ) -> tuple[ToolRegistry, tuple]:
        registry = ToolRegistry()
        specs = []
        try:
            for plugin in plugins:
                if not isinstance(plugin, ToolPlugin):
                    raise TypeError("plugin does not implement ToolPlugin")
                status = await registry.register_checked(plugin)
                if status.state is not HealthState.HEALTHY:
                    raise RuntimeError("plugin is not healthy")
                specs.append(plugin.get_spec().model_copy(deep=True))
        except Exception as exc:
            raise _admission_error(ReadinessState.REGISTRY_NOT_READY) from exc
        return registry, tuple(specs)

    @staticmethod
    def _build_policy() -> PolicyGate:
        try:
            return PolicyGate()
        except Exception as exc:
            raise _admission_error(ReadinessState.POLICY_NOT_READY) from exc

    @staticmethod
    def _build_verifier_registry() -> VerifierRegistry:
        try:
            registry = VerifierRegistry()
            registry.register(WEB_IDOR_VERIFIER_ID, WebIdorVerifier())
            registry.register(SOURCE_AUDIT_VERIFIER_ID, SourceAuditVerifier())
            return registry
        except Exception as exc:
            raise _admission_error(ReadinessState.REGISTRY_NOT_READY) from exc

    @staticmethod
    def _executor_fingerprint(assembly: TaskPackRuntimeAssembly, tool_specs: tuple) -> str:
        execution_profile = assembly.execution_profile
        if execution_profile is None:
            execution_profile = tool_specs[0].execution_profile
            if any(spec.execution_profile != execution_profile for spec in tool_specs[1:]):
                raise _admission_error(ReadinessState.EXECUTOR_NOT_READY)
        try:
            return fingerprint_executor(
                assembly.executor_profile,
                execution_profile,
                assembly.resource_budget,
            )
        except FingerprintInputError as exc:
            raise _admission_error(ReadinessState.EXECUTOR_NOT_READY) from exc


async def _close_adapter(adapter: object) -> None:
    close = getattr(adapter, "aclose", None)
    if not callable(close):
        return
    try:
        await close()
    except Exception:
        pass


def _admission_error(state: ReadinessState) -> RunManagementError:
    messages = {
        ReadinessState.MODEL_NOT_READY: "No active model is ready for a formal Runtime.",
        ReadinessState.CREDENTIAL_MISSING: "The active model credential is unavailable.",
        ReadinessState.CAPABILITY_STALE: "The active model capability proof is stale.",
        ReadinessState.CAPABILITY_FAILED: "The active model capability proof failed.",
        ReadinessState.ADAPTER_NOT_READY: "The formal model adapter could not be initialized.",
        ReadinessState.PLANNER_NOT_READY: "PlannerService could not be initialized.",
        ReadinessState.REGISTRY_NOT_READY: "The formal Runtime registry is unavailable.",
        ReadinessState.POLICY_NOT_READY: "The formal Runtime policy is unavailable.",
        ReadinessState.ARTIFACT_RUNTIME_NOT_READY: "The artifact Runtime is unavailable.",
        ReadinessState.EXECUTOR_NOT_READY: "The selected TaskPack executor is unavailable.",
        ReadinessState.TASKPACK_DISABLED: "The selected TaskPack is disabled.",
    }
    return RunManagementError(
        state.value,
        messages.get(state, "The formal Runtime is unavailable."),
        status_code=503,
    )


__all__ = [
    "PreparedRuntimeContext",
    "RealRuntimeFactory",
    "SourceAuditExecutorProvider",
    "TaskPackExecutorProvider",
    "TaskPackRuntimeAssembly",
]
