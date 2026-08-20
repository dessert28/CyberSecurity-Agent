"""Explicit allowlist catalog for competition-visible task packs."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import ValidationError

from cyber_agent.contracts.common import (
    ArtifactRef,
    Budget,
    RiskLevel,
    StrictModel,
    SuccessCriterion,
)
from cyber_agent.contracts.task import (
    ScopePolicy,
    ScopeTarget,
    TargetKind,
    Task,
    TaskConstraints,
    TaskStatus,
)
from cyber_agent.contracts.task_pack import TaskPack, TaskPackManifest

from .source_audit import (
    SOURCE_AUDIT_REQUIRED_TOOLS,
    SOURCE_AUDIT_TASK_PACK_ID,
    SOURCE_AUDIT_TASK_TYPE,
    SourceAuditScenarioConfig,
    SourceAuditTaskPack,
    source_audit_manifest,
)
from .web_idor import (
    WEB_IDOR_TASK_PACK_ID,
    WEB_IDOR_TASK_TYPE,
    WebIdorScenarioConfig,
    WebIdorTaskPack,
    web_idor_manifest,
)


class TaskPackCatalogError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SourceAuditScenarioInput(StrictModel):
    """Only user-selectable, conclusion-free Source Audit options."""

    language: Literal["python"] = "python"
    audit_scope: Literal["sql_injection"] = "sql_injection"


class TaskPackCatalog:
    """Construct only the two competition-approved task packs without scanning."""

    _ORDER = (WEB_IDOR_TASK_PACK_ID, SOURCE_AUDIT_TASK_PACK_ID)

    def __init__(self) -> None:
        self._manifests = {
            WEB_IDOR_TASK_PACK_ID: web_idor_manifest(),
            SOURCE_AUDIT_TASK_PACK_ID: source_audit_manifest(),
        }

    def list(self) -> tuple[TaskPackManifest, ...]:
        return tuple(
            self._manifests[item].model_copy(deep=True) for item in self._ORDER
        )

    def get(self, task_pack_id: str) -> TaskPackManifest:
        try:
            return self._manifests[task_pack_id].model_copy(deep=True)
        except KeyError as exc:
            raise TaskPackCatalogError(
                "TASK_PACK_NOT_REGISTERED",
                "The requested task pack is not registered for competition use.",
            ) from exc

    def create_task_pack(
        self,
        task_pack_id: str,
        *,
        scenario_input: dict,
        artifact: ArtifactRef | None,
    ) -> TaskPack:
        self.get(task_pack_id)
        try:
            if task_pack_id == WEB_IDOR_TASK_PACK_ID:
                if artifact is not None:
                    raise TaskPackCatalogError(
                        "SCENARIO_ARTIFACT_NOT_ALLOWED",
                        "Web-IDOR does not accept an uploaded source artifact.",
                    )
                return WebIdorTaskPack(
                    WebIdorScenarioConfig.model_validate(scenario_input)
                )
            source_input = SourceAuditScenarioInput.model_validate(scenario_input)
            source_artifact = self._require_source_artifact(artifact)
            return SourceAuditTaskPack(
                SourceAuditScenarioConfig(
                    artifact_id=source_artifact.artifact_id,
                    artifact_sha256=source_artifact.sha256,
                    language=source_input.language,
                    audit_scope=source_input.audit_scope,
                    network_access=False,
                    allowed_tools=SOURCE_AUDIT_REQUIRED_TOOLS,
                )
            )
        except TaskPackCatalogError:
            raise
        except (ValidationError, ValueError) as exc:
            raise TaskPackCatalogError(
                "SCENARIO_INPUT_INVALID",
                "The scenario input does not satisfy the selected task pack contract.",
            ) from exc

    def create_task(
        self,
        task_pack_id: str,
        *,
        request_text: str,
        scenario_input: dict,
        artifact: ArtifactRef | None,
        created_at: datetime,
    ) -> Task:
        self.get(task_pack_id)
        try:
            if task_pack_id == WEB_IDOR_TASK_PACK_ID:
                if artifact is not None:
                    raise TaskPackCatalogError(
                        "SCENARIO_ARTIFACT_NOT_ALLOWED",
                        "Web-IDOR does not accept an uploaded source artifact.",
                    )
                config = WebIdorScenarioConfig.model_validate(scenario_input)
                return self._web_task(request_text, config, created_at)
            source_input = SourceAuditScenarioInput.model_validate(scenario_input)
            source_artifact = self._require_source_artifact(artifact)
            return self._source_task(
                request_text,
                source_input,
                source_artifact,
                created_at,
            )
        except TaskPackCatalogError:
            raise
        except (ValidationError, ValueError) as exc:
            raise TaskPackCatalogError(
                "SCENARIO_INPUT_INVALID",
                "The scenario input does not satisfy the selected task pack contract.",
            ) from exc

    @staticmethod
    def _require_source_artifact(artifact: ArtifactRef | None) -> ArtifactRef:
        if artifact is None:
            raise TaskPackCatalogError(
                "SCENARIO_ARTIFACT_REQUIRED",
                "Source Audit requires one registered source ZIP artifact.",
            )
        if artifact.media_type != "application/zip":
            raise TaskPackCatalogError(
                "SCENARIO_ARTIFACT_INVALID",
                "Source Audit accepts only an application/zip artifact.",
            )
        return artifact.model_copy(deep=True)

    @staticmethod
    def _web_task(
        request_text: str,
        config: WebIdorScenarioConfig,
        created_at: datetime,
    ) -> Task:
        return Task(
            created_at=created_at,
            request_text=request_text,
            objective=request_text,
            scope=config.scope.model_copy(deep=True),
            constraints=TaskConstraints(
                budget=Budget(
                    max_duration_seconds=180,
                    max_steps=2,
                    max_model_calls=3,
                    max_tool_calls=2,
                    max_replans=0,
                    max_attempts_per_step=1,
                    max_tool_timeout_seconds=60,
                )
            ),
            success_criteria=[
                SuccessCriterion(
                    kind="web.idor-assessment",
                    description=(
                        "Compare an authorized baseline with one cross-tenant probe "
                        "using result-backed evidence."
                    ),
                    evidence_requirements=["authorized_baseline", "cross_tenant_probe"],
                )
            ],
            scenario_hints=[WEB_IDOR_TASK_TYPE],
            status=TaskStatus.READY,
        )

    @staticmethod
    def _source_task(
        request_text: str,
        scenario_input: SourceAuditScenarioInput,
        artifact: ArtifactRef,
        created_at: datetime,
    ) -> Task:
        scope = ScopePolicy(
            allowed_targets=[
                ScopeTarget(
                    kind=TargetKind.FILE,
                    value=artifact.logical_uri,
                    protocols={"file"},
                )
            ],
            network_access=False,
            allowed_tool_ids=set(SOURCE_AUDIT_REQUIRED_TOOLS),
            maximum_risk=RiskLevel.R2,
        )
        return Task(
            created_at=created_at,
            request_text=request_text,
            input_artifacts=[artifact.model_copy(deep=True)],
            objective=(
                f"Audit the registered {scenario_input.language} artifact for "
                f"{scenario_input.audit_scope}."
            ),
            scope=scope,
            constraints=TaskConstraints(
                budget=Budget(
                    max_duration_seconds=180,
                    max_steps=3,
                    max_model_calls=4,
                    max_tool_calls=3,
                    max_replans=0,
                    max_attempts_per_step=1,
                    max_tool_timeout_seconds=60,
                )
            ),
            success_criteria=[
                SuccessCriterion(
                    kind="source.sql-injection-assessment",
                    description=(
                        "Inventory the project, generate a dataflow hypothesis, and "
                        "validate it with a suppressed sink."
                    ),
                    evidence_requirements=[
                        "source.project_inventory",
                        "source.dataflow_hypotheses",
                        "source.hypothesis_validation",
                    ],
                )
            ],
            scenario_hints=[SOURCE_AUDIT_TASK_TYPE],
            status=TaskStatus.READY,
        )


def build_competition_task_pack_catalog() -> TaskPackCatalog:
    """Return the fixed two-entry competition catalog."""

    return TaskPackCatalog()


__all__ = [
    "SourceAuditScenarioInput",
    "TaskPackCatalog",
    "TaskPackCatalogError",
    "build_competition_task_pack_catalog",
]
