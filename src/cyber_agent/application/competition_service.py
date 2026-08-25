"""Competition-facing application service over the generic orchestrator."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from cyber_agent.application.run_orchestrator import RunOrchestratorResult
from cyber_agent.contracts.common import ArtifactRef
from cyber_agent.contracts.task import Task
from cyber_agent.contracts.task_pack import TaskPack
from cyber_agent.tools import HealthState, RegistryError, ToolRegistry
from cyber_agent.verification import VerifierRegistry, VerifierRegistryError

if TYPE_CHECKING:
    from cyber_agent.task_packs import TaskPackCatalog

ArtifactResolver = Callable[[UUID], ArtifactRef]


class RunOrchestratorPort(Protocol):
    async def run(self, task: Task, task_pack: TaskPack) -> RunOrchestratorResult: ...


class CompetitionServiceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CompetitionRunService:
    """Create a trusted Task/TaskPack pair and invoke the generic core once."""

    def __init__(
        self,
        *,
        catalog: TaskPackCatalog,
        orchestrator: RunOrchestratorPort,
        tool_registry: ToolRegistry,
        verifier_registry: VerifierRegistry,
        artifact_resolver: ArtifactResolver | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._catalog = catalog
        self._orchestrator = orchestrator
        self._tool_registry = tool_registry
        self._verifier_registry = verifier_registry
        self._artifact_resolver = artifact_resolver
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def catalog(self) -> TaskPackCatalog:
        return self._catalog

    async def run_task(
        self,
        *,
        task_pack_id: str,
        request_text: str,
        artifact_id: UUID | None,
        scenario_input: Mapping[str, object],
    ) -> RunOrchestratorResult:
        task, task_pack = self._prepare_task(
            task_pack_id=task_pack_id,
            request_text=request_text,
            artifact_id=artifact_id,
            scenario_input=scenario_input,
        )
        return await self._orchestrator.run(task, task_pack)

    def validate_request(
        self,
        *,
        task_pack_id: str,
        request_text: str,
        artifact_id: UUID | None,
        scenario_input: Mapping[str, object],
    ) -> None:
        """Fail closed before an API run is accepted for background execution."""

        self._prepare_task(
            task_pack_id=task_pack_id,
            request_text=request_text,
            artifact_id=artifact_id,
            scenario_input=scenario_input,
        )

    def _prepare_task(
        self,
        *,
        task_pack_id: str,
        request_text: str,
        artifact_id: UUID | None,
        scenario_input: Mapping[str, object],
    ) -> tuple[Task, TaskPack]:
        from cyber_agent.task_packs import TaskPackCatalogError

        if not isinstance(request_text, str) or not request_text.strip():
            raise CompetitionServiceError(
                "TASK_REQUEST_INVALID",
                "The task request must contain non-empty natural-language text.",
            )
        if not isinstance(scenario_input, Mapping):
            raise CompetitionServiceError(
                "SCENARIO_INPUT_INVALID",
                "Scenario input must be a structured mapping.",
            )
        try:
            manifest = self._catalog.get(task_pack_id)
        except TaskPackCatalogError as exc:
            raise CompetitionServiceError(exc.code, str(exc)) from exc

        self._require_runtime_components(manifest.verifier, manifest.required_tools)
        artifact = self._resolve_artifact(artifact_id)
        values = dict(scenario_input)
        try:
            task_pack = self._catalog.create_task_pack(
                task_pack_id,
                scenario_input=values,
                artifact=artifact,
            )
            task = self._catalog.create_task(
                task_pack_id,
                request_text=request_text.strip(),
                scenario_input=values,
                artifact=artifact,
                created_at=self._clock(),
            )
        except TaskPackCatalogError as exc:
            raise CompetitionServiceError(exc.code, str(exc)) from exc
        return task, task_pack

    def _require_runtime_components(
        self,
        verifier_id: str,
        required_tools: tuple[str, ...],
    ) -> None:
        try:
            self._verifier_registry.resolve(verifier_id)
        except VerifierRegistryError as exc:
            raise CompetitionServiceError(
                "TASK_PACK_VERIFIER_UNAVAILABLE",
                "The selected task pack verifier is not registered.",
            ) from exc
        for tool_id in required_tools:
            try:
                status = self._tool_registry.status(tool_id)
            except RegistryError as exc:
                raise CompetitionServiceError(
                    "TASK_PACK_TOOL_UNAVAILABLE",
                    "A required task pack tool is not registered.",
                ) from exc
            if status.state is not HealthState.HEALTHY:
                raise CompetitionServiceError(
                    "TASK_PACK_TOOL_UNAVAILABLE",
                    "A required task pack tool did not pass its health check.",
                )

    def _resolve_artifact(self, artifact_id: UUID | None) -> ArtifactRef | None:
        if artifact_id is None:
            return None
        if self._artifact_resolver is None:
            raise CompetitionServiceError(
                "ARTIFACT_RESOLVER_UNAVAILABLE",
                "No registered artifact resolver is available.",
            )
        try:
            artifact = self._artifact_resolver(artifact_id)
        except KeyError as exc:
            raise CompetitionServiceError(
                "ARTIFACT_NOT_FOUND",
                "The requested artifact is not registered.",
            ) from exc
        if not isinstance(artifact, ArtifactRef) or artifact.artifact_id != artifact_id:
            raise CompetitionServiceError(
                "ARTIFACT_REFERENCE_INVALID",
                "The artifact resolver returned a mismatched reference.",
            )
        return artifact.model_copy(deep=True)


__all__ = [
    "ArtifactResolver",
    "CompetitionRunService",
    "CompetitionServiceError",
    "RunOrchestratorPort",
]
