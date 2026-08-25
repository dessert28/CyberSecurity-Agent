"""Explicit allowlist catalog for competition-visible task packs."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, ValidationError, model_validator

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

from .pwn_ret2win import (
    PWN_RET2WIN_REQUIRED_TOOLS,
    PWN_RET2WIN_TASK_PACK_ID,
    PWN_RET2WIN_TASK_TYPE,
    PwnRet2winScenarioConfig,
    PwnRet2winTaskPack,
    pwn_ret2win_manifest,
)
from .incident_login_chain import (
    INCIDENT_LOGIN_CHAIN_REQUIRED_TOOLS,
    INCIDENT_LOGIN_CHAIN_TASK_PACK_ID,
    INCIDENT_LOGIN_CHAIN_TASK_TYPE,
    IncidentLoginChainScenarioConfig,
    IncidentLoginChainTaskPack,
    incident_login_chain_manifest,
)
from .reverse_keycheck import (
    REVERSE_KEYCHECK_REQUIRED_TOOLS,
    REVERSE_KEYCHECK_TASK_PACK_ID,
    REVERSE_KEYCHECK_TASK_TYPE,
    ReverseKeycheckScenarioConfig,
    ReverseKeycheckTaskPack,
    reverse_keycheck_manifest,
)
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
    WebIdorObservationType,
    WebIdorScenarioConfig,
    WebIdorStepBinding,
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


class PwnRet2winScenarioInput(StrictModel):
    """Only user-selectable, conclusion-free Pwn Ret2win options."""

    exploit_kind: Literal["ret2win"] = "ret2win"
    target_host: str | None = Field(default=None, min_length=1, max_length=255)
    target_port: int | None = Field(default=None, ge=1, le=65535)

    @model_validator(mode="after")
    def remote_target_is_whole(self) -> "PwnRet2winScenarioInput":
        if (self.target_host is None) != (self.target_port is None):
            raise ValueError("target_host and target_port must be provided together")
        return self


class ReverseKeycheckScenarioInput(StrictModel):
    """Only user-selectable, conclusion-free Reverse Keycheck options."""

    transform_kind: Literal["xor"] = "xor"


class IncidentLoginChainScenarioInput(StrictModel):
    """Only user-selectable, conclusion-free Incident login-chain options."""

    log_format: Literal["jsonl_csv"] = "jsonl_csv"


_DEMO_WEB_TARGET_URL = "http://web-target.test:18080"


def _default_web_idor_config() -> WebIdorScenarioConfig:
    """Trusted demo scope and bindings for the local Web-IDOR target."""
    return WebIdorScenarioConfig(
        scope=ScopePolicy(
            allowed_targets=[
                ScopeTarget(
                    kind=TargetKind.URL,
                    value=_DEMO_WEB_TARGET_URL,
                    protocols={"http"},
                    ports={18080},
                )
            ],
            network_access=True,
            allowed_tool_ids={"web.http_request"},
            maximum_risk=RiskLevel.R2,
        ),
        bindings=(
            WebIdorStepBinding(
                ordinal=1,
                observation_type=WebIdorObservationType.AUTHORIZED_BASELINE,
                actor_id="alice",
                expected_object_id="1001",
            ),
            WebIdorStepBinding(
                ordinal=2,
                observation_type=WebIdorObservationType.CROSS_TENANT_PROBE,
                actor_id="alice",
                expected_object_id="1002",
            ),
        ),
    )


def _web_idor_config(scenario_input: dict) -> WebIdorScenarioConfig:
    """Resolve the Web-IDOR config, defaulting to the local demo target."""
    if "scope" in scenario_input or "bindings" in scenario_input:
        return WebIdorScenarioConfig.model_validate(scenario_input)
    return _default_web_idor_config()


class TaskPackCatalog:
    """Construct only the competition-approved task packs without scanning."""

    _ORDER = (
        WEB_IDOR_TASK_PACK_ID,
        SOURCE_AUDIT_TASK_PACK_ID,
        PWN_RET2WIN_TASK_PACK_ID,
        REVERSE_KEYCHECK_TASK_PACK_ID,
        INCIDENT_LOGIN_CHAIN_TASK_PACK_ID,
    )

    def __init__(self) -> None:
        self._manifests = {
            WEB_IDOR_TASK_PACK_ID: web_idor_manifest(),
            SOURCE_AUDIT_TASK_PACK_ID: source_audit_manifest(),
            PWN_RET2WIN_TASK_PACK_ID: pwn_ret2win_manifest(),
            REVERSE_KEYCHECK_TASK_PACK_ID: reverse_keycheck_manifest(),
            INCIDENT_LOGIN_CHAIN_TASK_PACK_ID: incident_login_chain_manifest(),
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
                return WebIdorTaskPack(_web_idor_config(scenario_input))
            if task_pack_id == SOURCE_AUDIT_TASK_PACK_ID:
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
            if task_pack_id == PWN_RET2WIN_TASK_PACK_ID:
                pwn_input = PwnRet2winScenarioInput.model_validate(scenario_input)
                pwn_artifact = self._require_pwn_artifact(artifact)
                return PwnRet2winTaskPack(
                    PwnRet2winScenarioConfig(
                        artifact_id=pwn_artifact.artifact_id,
                        artifact_sha256=pwn_artifact.sha256,
                        network_access=pwn_input.target_host is not None,
                        allowed_tools=PWN_RET2WIN_REQUIRED_TOOLS,
                        target_host=pwn_input.target_host,
                        target_port=pwn_input.target_port,
                    )
                )
            if task_pack_id == REVERSE_KEYCHECK_TASK_PACK_ID:
                ReverseKeycheckScenarioInput.model_validate(scenario_input)
                reverse_artifact = self._require_reverse_artifact(artifact)
                return ReverseKeycheckTaskPack(
                    ReverseKeycheckScenarioConfig(
                        artifact_id=reverse_artifact.artifact_id,
                        artifact_sha256=reverse_artifact.sha256,
                        network_access=False,
                        allowed_tools=REVERSE_KEYCHECK_REQUIRED_TOOLS,
                    )
                )
            if task_pack_id == INCIDENT_LOGIN_CHAIN_TASK_PACK_ID:
                IncidentLoginChainScenarioInput.model_validate(scenario_input)
                incident_artifact = self._require_incident_artifact(artifact)
                return IncidentLoginChainTaskPack(
                    IncidentLoginChainScenarioConfig(
                        artifact_id=incident_artifact.artifact_id,
                        artifact_sha256=incident_artifact.sha256,
                        network_access=False,
                        allowed_tools=INCIDENT_LOGIN_CHAIN_REQUIRED_TOOLS,
                    )
                )
            raise TaskPackCatalogError(
                "TASK_PACK_NOT_REGISTERED",
                "The requested task pack is not registered for competition use.",
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
                config = _web_idor_config(scenario_input)
                return self._web_task(request_text, config, created_at)
            if task_pack_id == SOURCE_AUDIT_TASK_PACK_ID:
                source_input = SourceAuditScenarioInput.model_validate(scenario_input)
                source_artifact = self._require_source_artifact(artifact)
                return self._source_task(
                    request_text,
                    source_input,
                    source_artifact,
                    created_at,
                )
            if task_pack_id == PWN_RET2WIN_TASK_PACK_ID:
                pwn_input = PwnRet2winScenarioInput.model_validate(scenario_input)
                pwn_artifact = self._require_pwn_artifact(artifact)
                return self._pwn_task(
                    request_text,
                    pwn_artifact,
                    created_at,
                    target_host=pwn_input.target_host,
                    target_port=pwn_input.target_port,
                )
            if task_pack_id == REVERSE_KEYCHECK_TASK_PACK_ID:
                ReverseKeycheckScenarioInput.model_validate(scenario_input)
                reverse_artifact = self._require_reverse_artifact(artifact)
                return self._reverse_task(request_text, reverse_artifact, created_at)
            if task_pack_id == INCIDENT_LOGIN_CHAIN_TASK_PACK_ID:
                IncidentLoginChainScenarioInput.model_validate(scenario_input)
                incident_artifact = self._require_incident_artifact(artifact)
                return self._incident_task(request_text, incident_artifact, created_at)
            raise TaskPackCatalogError(
                "TASK_PACK_NOT_REGISTERED",
                "The requested task pack is not registered for competition use.",
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
    def _require_pwn_artifact(artifact: ArtifactRef | None) -> ArtifactRef:
        if artifact is None:
            raise TaskPackCatalogError(
                "SCENARIO_ARTIFACT_REQUIRED",
                "Pwn Ret2win requires one registered executable artifact.",
            )
        if artifact.media_type != "application/x-executable":
            raise TaskPackCatalogError(
                "SCENARIO_ARTIFACT_INVALID",
                "Pwn Ret2win accepts only an application/x-executable artifact.",
            )
        return artifact.model_copy(deep=True)

    @staticmethod
    def _require_reverse_artifact(artifact: ArtifactRef | None) -> ArtifactRef:
        if artifact is None:
            raise TaskPackCatalogError(
                "SCENARIO_ARTIFACT_REQUIRED",
                "Reverse Keycheck requires one registered binary artifact.",
            )
        if artifact.media_type != "application/octet-stream":
            raise TaskPackCatalogError(
                "SCENARIO_ARTIFACT_INVALID",
                "Reverse Keycheck accepts only an application/octet-stream artifact.",
            )
        return artifact.model_copy(deep=True)

    @staticmethod
    def _require_incident_artifact(artifact: ArtifactRef | None) -> ArtifactRef:
        if artifact is None:
            raise TaskPackCatalogError(
                "SCENARIO_ARTIFACT_REQUIRED",
                "Incident login-chain requires one registered log ZIP artifact.",
            )
        if artifact.media_type != "application/zip":
            raise TaskPackCatalogError(
                "SCENARIO_ARTIFACT_INVALID",
                "Incident login-chain accepts only an application/zip artifact.",
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

    @staticmethod
    def _pwn_task(
        request_text: str,
        artifact: ArtifactRef,
        created_at: datetime,
        *,
        target_host: str | None = None,
        target_port: int | None = None,
    ) -> Task:
        allowed_targets = [
            ScopeTarget(
                kind=TargetKind.FILE,
                value=artifact.logical_uri,
                protocols={"file"},
            )
        ]
        if target_host is not None:
            allowed_targets.append(
                ScopeTarget(
                    kind=TargetKind.HOST,
                    value=target_host,
                    ports={target_port} if target_port is not None else set(),
                )
            )
        scope = ScopePolicy(
            allowed_targets=allowed_targets,
            network_access=target_host is not None,
            allowed_tool_ids=set(PWN_RET2WIN_REQUIRED_TOOLS),
            maximum_risk=RiskLevel.R2,
        )
        return Task(
            created_at=created_at,
            request_text=request_text,
            input_artifacts=[artifact.model_copy(deep=True)],
            objective=(
                "Recover the x86-64 binary properties and trigger its win function "
                "through a structured ret2win overflow."
            ),
            scope=scope,
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
                    kind="pwn.ret2win",
                    description=(
                        "Recover binary properties and trigger win via a structured "
                        "overflow with evidence-backed parameters."
                    ),
                    evidence_requirements=[
                        "pwn.binary_properties",
                        "pwn.process_interaction",
                    ],
                )
            ],
            scenario_hints=[PWN_RET2WIN_TASK_TYPE],
            status=TaskStatus.READY,
        )

    @staticmethod
    def _reverse_task(
        request_text: str,
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
            allowed_tool_ids=set(REVERSE_KEYCHECK_REQUIRED_TOOLS),
            maximum_risk=RiskLevel.R2,
        )
        return Task(
            created_at=created_at,
            request_text=request_text,
            input_artifacts=[artifact.model_copy(deep=True)],
            objective=(
                "Recover the keycheck transform from the binary, derive the valid "
                "key, and verify it through controlled run verification."
            ),
            scope=scope,
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
                    kind="reverse.keycheck",
                    description=(
                        "Recover the transform and verify the derived key with "
                        "evidence-backed parameters."
                    ),
                    evidence_requirements=[
                        "reverse.static_extract",
                        "reverse.run_verify",
                    ],
                )
            ],
            scenario_hints=[REVERSE_KEYCHECK_TASK_TYPE],
            status=TaskStatus.READY,
        )

    @staticmethod
    def _incident_task(
        request_text: str,
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
            allowed_tool_ids=set(INCIDENT_LOGIN_CHAIN_REQUIRED_TOOLS),
            maximum_risk=RiskLevel.R1,
        )
        return Task(
            created_at=created_at,
            request_text=request_text,
            input_artifacts=[artifact.model_copy(deep=True)],
            objective=(
                "Inventory the log bundle, reconstruct the failed-login to success "
                "to sensitive-access chain, and give read-only remediation advice."
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
                    kind="incident.login-chain",
                    description=(
                        "Inventory the logs and reconstruct one evidence-backed "
                        "failed-login to success to sensitive-access chain."
                    ),
                    evidence_requirements=[
                        "incident.log_inventory",
                        "incident.log_search",
                    ],
                )
            ],
            scenario_hints=[INCIDENT_LOGIN_CHAIN_TASK_TYPE],
            status=TaskStatus.READY,
        )


def build_competition_task_pack_catalog() -> TaskPackCatalog:
    """Return the fixed competition catalog."""

    return TaskPackCatalog()


__all__ = [
    "IncidentLoginChainScenarioInput",
    "PwnRet2winScenarioInput",
    "ReverseKeycheckScenarioInput",
    "SourceAuditScenarioInput",
    "TaskPackCatalog",
    "TaskPackCatalogError",
    "build_competition_task_pack_catalog",
]
