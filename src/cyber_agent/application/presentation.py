"""Read-only presentation projections for the competition workbench."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from pydantic import Field

from cyber_agent.application.run_management import ManagedRunRecord
from cyber_agent.audit_store import audit_event_hash
from cyber_agent.contracts.audit import AuditRecord
from cyber_agent.contracts.common import (
    MachineName,
    RiskLevel,
    Sha256,
    StableCode,
    StrictModel,
    UtcDateTime,
)
from cyber_agent.contracts.evidence import (
    Evidence,
    EvidenceKind,
    VerificationMethod,
    VerificationOutcome,
)
from cyber_agent.contracts.plan import (
    PlanStatus,
    RunStatus,
    StepKind,
    StepStatus,
)
from cyber_agent.contracts.task import TargetKind, TaskStatus
from cyber_agent.contracts.tool import ToolInvocationStatus, ToolResultStatus
from cyber_agent.reporting import (
    ReportProjection,
    ReportProviderPort,
    ReportStatus,
)
from cyber_agent.task_packs.source_audit.manifest import (
    SOURCE_AUDIT_REPORT_TEMPLATE,
    SOURCE_AUDIT_TASK_PACK_ID,
)
from cyber_agent.task_packs.web_idor.manifest import (
    WEB_IDOR_REPORT_TEMPLATE,
    WEB_IDOR_TASK_PACK_ID,
)
from cyber_agent.workbench.schemas import (
    ModelCheckStatus,
    WorkbenchMode,
    WorkbenchStatusResponse,
)


class DashboardReadiness(str, Enum):
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class ConnectionStatus(str, Enum):
    VERIFIED = "verified"
    UNCHECKED = "unchecked"
    FAILED = "failed"
    CREDENTIAL_MISSING = "credential_missing"
    NOT_CONFIGURED = "not_configured"


class CapabilityStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    UNCHECKED = "unchecked"


class DisplayStage(str, Enum):
    TASK = "task"
    PLAN = "plan"
    TOOL = "tool"
    POLICY = "policy"
    EXECUTOR = "executor"
    EVIDENCE = "evidence"
    VERIFIER = "verifier"


class DisplayStageStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class ModelCapabilityProjection(StrictModel):
    capability_id: MachineName
    label: str = Field(min_length=1, max_length=255)
    status: CapabilityStatus
    evidence_code: StableCode | None = None


class ModelStatusProjection(StrictModel):
    configured: bool
    provider: MachineName | None = None
    provider_label: str | None = Field(default=None, min_length=1, max_length=255)
    model_name: str | None = Field(default=None, min_length=1, max_length=255)
    credential_configured: bool
    connection_status: ConnectionStatus
    capabilities: tuple[ModelCapabilityProjection, ...]


class DockerStatusProjection(StrictModel):
    available: bool
    message: str = Field(min_length=1, max_length=2000)


class DashboardStatusProjection(StrictModel):
    readiness: DashboardReadiness
    mode: WorkbenchMode | None
    model: ModelStatusProjection
    docker: DockerStatusProjection
    storage_available: bool
    available_run_modes: tuple[MachineName, ...]
    observed_at: UtcDateTime


class ArtifactDisplayProjection(StrictModel):
    artifact_id: UUID
    media_type: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(ge=0)
    sha256: Sha256
    quarantined: bool


class TaskDisplayProjection(StrictModel):
    task_id: UUID
    request_text: str = Field(min_length=1, max_length=100_000)
    objective: str = Field(min_length=1, max_length=10_000)
    status: TaskStatus
    authorized_targets: tuple[str, ...]
    success_criteria: tuple[str, ...]
    input_artifacts: tuple[ArtifactDisplayProjection, ...]


class PlanDisplayProjection(StrictModel):
    plan_id: UUID
    version: int = Field(ge=1)
    status: PlanStatus
    strategy_summary: str = Field(min_length=1, max_length=20_000)
    assumptions: tuple[str, ...]


class StepDisplayProjection(StrictModel):
    step_id: UUID
    ordinal: int = Field(ge=1)
    objective: str = Field(min_length=1, max_length=10_000)
    kind: StepKind
    status: StepStatus
    risk_level: RiskLevel
    required_capabilities: tuple[MachineName, ...]
    depends_on: tuple[UUID, ...]
    selected_tools: tuple[MachineName, ...]


class PolicyDisplayProjection(StrictModel):
    decision_id: UUID
    invocation_id: UUID | None = None
    tool_id: MachineName | None = None
    allowed: bool
    policy_version: str = Field(min_length=1, max_length=255)
    reason_codes: tuple[StableCode, ...]


class ToolExecutionProjection(StrictModel):
    invocation_id: UUID
    step_id: UUID
    tool_id: MachineName
    attempt: int = Field(ge=1)
    invocation_status: ToolInvocationStatus
    result_status: ToolResultStatus | None = None
    started_at: UtcDateTime | None = None
    finished_at: UtcDateTime | None = None
    duration_milliseconds: int | None = Field(default=None, ge=0)
    error_code: StableCode | None = None


class VerdictDisplayProjection(StrictModel):
    outcome: VerificationOutcome
    summary: str = Field(min_length=1, max_length=20_000)
    reason_codes: tuple[StableCode, ...]
    evidence_ids: tuple[UUID, ...]


class AuditSummaryProjection(StrictModel):
    event_count: int = Field(ge=0)
    chain_valid: bool
    head_hash: Sha256 | None = None
    first_event_at: UtcDateTime | None = None
    last_event_at: UtcDateTime | None = None


class RunStageProjection(StrictModel):
    stage: DisplayStage
    status: DisplayStageStatus
    item_count: int = Field(ge=0)


class RunDisplayProjection(StrictModel):
    run_id: UUID
    core_run_id: UUID | None = None
    task_pack_id: MachineName
    scenario_title: str = Field(min_length=1, max_length=255)
    status: RunStatus
    created_at: UtcDateTime
    task: TaskDisplayProjection | None = None
    plan: PlanDisplayProjection | None = None
    stages: tuple[RunStageProjection, ...]
    steps: tuple[StepDisplayProjection, ...]
    policies: tuple[PolicyDisplayProjection, ...]
    executions: tuple[ToolExecutionProjection, ...]
    verdict: VerdictDisplayProjection | None = None
    evidence_count: int = Field(ge=0)
    audit: AuditSummaryProjection
    executor_backend: MachineName | None = None
    executor_platform: str | None = Field(default=None, min_length=1, max_length=255)
    error_code: StableCode | None = None


class EvidenceDisplayProjection(StrictModel):
    evidence_id: UUID
    kind: EvidenceKind
    source_type: MachineName
    source_id: UUID
    summary: str = Field(min_length=1, max_length=20_000)
    supports_claims: tuple[str, ...]
    verification_method: VerificationMethod
    confidence: float = Field(ge=0, le=1)
    created_at: UtcDateTime
    artifact: ArtifactDisplayProjection | None = None


class EvidenceListProjection(StrictModel):
    run_id: UUID
    core_run_id: UUID | None = None
    total: int = Field(ge=0)
    items: tuple[EvidenceDisplayProjection, ...]


class PresentationError(ValueError):
    def __init__(self, code: str, message: str, *, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@runtime_checkable
class RunRecordSourcePort(Protocol):
    async def get_record(self, run_id: UUID) -> ManagedRunRecord: ...


class CompetitionPresentationService:
    """Build immutable, secret-minimized read models from run snapshots."""

    def __init__(
        self,
        *,
        source: RunRecordSourcePort,
        report_provider: ReportProviderPort | None = None,
    ) -> None:
        if not isinstance(source, RunRecordSourcePort):
            raise TypeError("source does not implement RunRecordSourcePort")
        if report_provider is not None and not isinstance(report_provider, ReportProviderPort):
            raise TypeError("report_provider does not implement ReportProviderPort")
        self._source = source
        self._report_provider = report_provider

    async def get_run(self, run_id: UUID) -> RunDisplayProjection:
        return project_run(await self._source.get_record(run_id))

    async def get_evidence(self, run_id: UUID) -> EvidenceListProjection:
        return project_evidence(await self._source.get_record(run_id))

    async def get_report(self, run_id: UUID) -> ReportProjection:
        record = await self._source.get_record(run_id)
        if self._report_provider is not None:
            report = await self._report_provider.describe(run_id)
            if report.run_id != run_id:
                raise PresentationError(
                    "REPORT_RUN_MISMATCH",
                    "The report provider returned a descriptor for another run.",
                )
            return report.model_copy(deep=True)
        return _unconfigured_report(record)


def project_dashboard(
    status: WorkbenchStatusResponse | None,
    *,
    observed_at: datetime | None = None,
) -> DashboardStatusProjection:
    now = observed_at or datetime.now(timezone.utc)
    if status is None:
        return DashboardStatusProjection(
            readiness=DashboardReadiness.UNAVAILABLE,
            mode=None,
            model=ModelStatusProjection(
                configured=False,
                provider=None,
                provider_label=None,
                model_name=None,
                credential_configured=False,
                connection_status=ConnectionStatus.NOT_CONFIGURED,
                capabilities=(
                    ModelCapabilityProjection(
                        capability_id="model.structured-output",
                        label="JSON structured output",
                        status=CapabilityStatus.UNCHECKED,
                    ),
                ),
            ),
            docker=DockerStatusProjection(
                available=False,
                message="Docker availability has not been configured.",
            ),
            storage_available=True,
            available_run_modes=(),
            observed_at=now,
        )

    current = status.current_model
    if current is None:
        connection = ConnectionStatus.NOT_CONFIGURED
        capability_status = CapabilityStatus.UNCHECKED
        evidence_code = None
    elif not current.credential_present:
        connection = ConnectionStatus.CREDENTIAL_MISSING
        capability_status = CapabilityStatus.UNCHECKED
        evidence_code = "MODEL_CREDENTIAL_MISSING"
    elif current.check_status is ModelCheckStatus.PASSED:
        connection = ConnectionStatus.VERIFIED
        capability_status = CapabilityStatus.PASSED
        evidence_code = "MODEL_CHECK_PASSED"
    elif current.check_status is ModelCheckStatus.FAILED:
        connection = ConnectionStatus.FAILED
        capability_status = CapabilityStatus.FAILED
        evidence_code = "MODEL_CHECK_FAILED"
    else:
        connection = ConnectionStatus.UNCHECKED
        capability_status = CapabilityStatus.UNCHECKED
        evidence_code = None

    model_ready = connection is ConnectionStatus.VERIFIED
    readiness = (
        DashboardReadiness.READY
        if model_ready and status.docker.available
        else DashboardReadiness.DEGRADED
    )
    return DashboardStatusProjection(
        readiness=readiness,
        mode=status.mode,
        model=ModelStatusProjection(
            configured=current is not None,
            provider=current.provider.value if current is not None else None,
            provider_label=(
                _provider_label(current.provider.value, current.display_name)
                if current is not None
                else None
            ),
            model_name=current.model_id if current is not None else None,
            credential_configured=bool(current and current.credential_present),
            connection_status=connection,
            capabilities=(
                ModelCapabilityProjection(
                    capability_id="model.structured-output",
                    label="JSON structured output",
                    status=capability_status,
                    evidence_code=evidence_code,
                ),
            ),
        ),
        docker=DockerStatusProjection(
            available=status.docker.available,
            message=status.docker.message,
        ),
        storage_available=status.storage == "available",
        available_run_modes=tuple(mode.value for mode in status.available_run_modes),
        observed_at=now,
    )


def project_run(record: ManagedRunRecord) -> RunDisplayProjection:
    outcome = record.outcome
    if outcome is None:
        return RunDisplayProjection(
            run_id=record.run_id,
            task_pack_id=record.task_pack_id,
            scenario_title=_scenario_title(record.task_pack_id),
            status=record.status,
            created_at=record.created_at,
            stages=_stage_projections(record),
            steps=(),
            policies=(),
            executions=(),
            evidence_count=0,
            audit=AuditSummaryProjection(event_count=0, chain_valid=True),
            error_code=record.error_code,
        )

    core_run_id = outcome.run.run_id
    _require_run_consistency(core_run_id, outcome)
    invocations = tuple(getattr(outcome, "tool_invocations", ()))
    decisions = tuple(getattr(outcome, "policy_decisions", ()))
    results = tuple(getattr(outcome, "results", ()))
    evidence = tuple(getattr(outcome, "evidence", ()))
    audits = tuple(getattr(outcome, "audit_records", ()))
    verdicts = tuple(getattr(outcome, "verdicts", ()))
    invocations_by_step: dict[UUID, list] = {}
    for invocation in invocations:
        invocations_by_step.setdefault(invocation.step_id, []).append(invocation)

    task = outcome.task
    plan = getattr(outcome, "plan", None)
    steps = tuple(getattr(outcome, "steps", ()))
    return RunDisplayProjection(
        run_id=record.run_id,
        core_run_id=core_run_id,
        task_pack_id=record.task_pack_id,
        scenario_title=_scenario_title(record.task_pack_id),
        status=record.status,
        created_at=record.created_at,
        task=TaskDisplayProjection(
            task_id=task.task_id,
            request_text=task.request_text,
            objective=task.objective,
            status=task.status,
            authorized_targets=tuple(
                _safe_target_value(target.kind, target.value)
                for target in task.scope.allowed_targets
            ),
            success_criteria=tuple(item.description for item in task.success_criteria),
            input_artifacts=tuple(_project_artifact(item) for item in task.input_artifacts),
        ),
        plan=(
            PlanDisplayProjection(
                plan_id=plan.plan_id,
                version=plan.version,
                status=plan.status,
                strategy_summary=plan.strategy_summary,
                assumptions=tuple(plan.assumptions),
            )
            if plan is not None
            else None
        ),
        stages=_stage_projections(record),
        steps=tuple(
            StepDisplayProjection(
                step_id=step.step_id,
                ordinal=step.ordinal,
                objective=step.objective,
                kind=step.kind,
                status=step.status,
                risk_level=step.risk_level,
                required_capabilities=tuple(step.required_capabilities),
                depends_on=tuple(step.depends_on),
                selected_tools=tuple(
                    dict.fromkeys(
                        invocation.tool_ref.tool_id
                        for invocation in invocations_by_step.get(step.step_id, ())
                    )
                ),
            )
            for step in sorted(steps, key=lambda item: item.ordinal)
        ),
        policies=_project_policies(decisions, invocations),
        executions=_project_executions(invocations, results),
        verdict=(
            VerdictDisplayProjection(
                outcome=verdicts[-1].outcome,
                summary=verdicts[-1].summary,
                reason_codes=tuple(verdicts[-1].reason_codes),
                evidence_ids=tuple(verdicts[-1].evidence_ids),
            )
            if verdicts
            else None
        ),
        evidence_count=len(evidence),
        audit=_project_audit(audits, core_run_id),
        executor_backend=outcome.run.environment_profile.executor_backend,
        executor_platform=outcome.run.environment_profile.platform,
        error_code=record.error_code,
    )


def project_evidence(record: ManagedRunRecord) -> EvidenceListProjection:
    outcome = record.outcome
    if outcome is None:
        return EvidenceListProjection(run_id=record.run_id, total=0, items=())
    core_run_id = outcome.run.run_id
    evidence: Sequence[Evidence] = tuple(getattr(outcome, "evidence", ()))
    if any(item.run_id != core_run_id for item in evidence):
        raise PresentationError(
            "EVIDENCE_RUN_MISMATCH",
            "Evidence from another run cannot enter this presentation.",
        )
    items = tuple(
        EvidenceDisplayProjection(
            evidence_id=item.evidence_id,
            kind=item.kind,
            source_type=item.source_ref.entity_type,
            source_id=item.source_ref.entity_id,
            summary=item.summary,
            supports_claims=tuple(item.supports_claims),
            verification_method=item.verification_method,
            confidence=item.confidence,
            created_at=item.created_at,
            artifact=(
                _project_artifact(item.artifact_ref)
                if item.artifact_ref is not None
                else None
            ),
        )
        for item in evidence
    )
    return EvidenceListProjection(
        run_id=record.run_id,
        core_run_id=core_run_id,
        total=len(items),
        items=items,
    )


def _project_artifact(artifact) -> ArtifactDisplayProjection:
    return ArtifactDisplayProjection(
        artifact_id=artifact.artifact_id,
        media_type=artifact.media_type,
        size_bytes=artifact.size_bytes,
        sha256=artifact.sha256,
        quarantined=artifact.quarantined,
    )


def _safe_target_value(kind: TargetKind, value: str) -> str:
    if kind is not TargetKind.URL:
        return value
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _project_policies(decisions, invocations) -> tuple[PolicyDisplayProjection, ...]:
    invocation_by_decision = {
        invocation.policy_decision_ref: invocation
        for invocation in invocations
        if invocation.policy_decision_ref is not None
    }
    return tuple(
        PolicyDisplayProjection(
            decision_id=decision.decision_id,
            invocation_id=(
                invocation_by_decision[decision.decision_id].invocation_id
                if decision.decision_id in invocation_by_decision
                else None
            ),
            tool_id=(
                invocation_by_decision[decision.decision_id].tool_ref.tool_id
                if decision.decision_id in invocation_by_decision
                else None
            ),
            allowed=decision.allowed,
            policy_version=decision.policy_version,
            reason_codes=tuple(decision.reason_codes),
        )
        for decision in decisions
    )


def _project_executions(invocations, results) -> tuple[ToolExecutionProjection, ...]:
    result_by_key = {
        (result.step_id, result.attempt, result.tool_ref.tool_id): result
        for result in results
    }
    projected = []
    for invocation in invocations:
        result = result_by_key.get(
            (invocation.step_id, invocation.attempt, invocation.tool_ref.tool_id)
        )
        duration = None
        if result is not None:
            duration = max(
                0,
                int((result.finished_at - result.started_at).total_seconds() * 1000),
            )
        projected.append(
            ToolExecutionProjection(
                invocation_id=invocation.invocation_id,
                step_id=invocation.step_id,
                tool_id=invocation.tool_ref.tool_id,
                attempt=invocation.attempt,
                invocation_status=invocation.status,
                result_status=result.status if result is not None else None,
                started_at=result.started_at if result is not None else None,
                finished_at=result.finished_at if result is not None else None,
                duration_milliseconds=duration,
                error_code=(
                    result.error.code
                    if result is not None and result.error is not None
                    else None
                ),
            )
        )
    return tuple(projected)


def _project_audit(
    records: Sequence[AuditRecord],
    core_run_id: UUID,
) -> AuditSummaryProjection:
    if not records:
        return AuditSummaryProjection(event_count=0, chain_valid=True)
    valid = True
    previous_hash = None
    for expected_sequence, record in enumerate(records, start=1):
        if (
            record.run_id != core_run_id
            or record.sequence != expected_sequence
            or record.previous_hash != previous_hash
            or record.event_hash != audit_event_hash(record)
        ):
            valid = False
        previous_hash = record.event_hash
    return AuditSummaryProjection(
        event_count=len(records),
        chain_valid=valid,
        head_hash=records[-1].event_hash,
        first_event_at=records[0].timestamp,
        last_event_at=records[-1].timestamp,
    )


def _require_run_consistency(core_run_id: UUID, outcome) -> None:
    plan = getattr(outcome, "plan", None)
    if (
        outcome.run.task_id != outcome.task.task_id
        or (plan is not None and plan.run_id != core_run_id)
        or any(
            plan is not None and step.plan_id != plan.plan_id
            for step in getattr(outcome, "steps", ())
        )
    ):
        raise PresentationError(
            "PRESENTATION_RUN_MISMATCH",
            "Cross-run data cannot enter a run presentation.",
        )
    collections = (
        getattr(outcome, "tool_invocations", ()),
        getattr(outcome, "results", ()),
        getattr(outcome, "evidence", ()),
        getattr(outcome, "audit_records", ()),
    )
    if any(
        getattr(item, "run_id", core_run_id) != core_run_id
        for collection in collections
        for item in collection
    ):
        raise PresentationError(
            "PRESENTATION_RUN_MISMATCH",
            "Cross-run data cannot enter a run presentation.",
        )


def _stage_projections(record: ManagedRunRecord) -> tuple[RunStageProjection, ...]:
    outcome = record.outcome
    if outcome is None:
        active = (
            DisplayStage.PLAN
            if record.status in {RunStatus.PLANNING, RunStatus.VALIDATING_PLAN}
            else DisplayStage.TOOL
            if record.status is RunStatus.RUNNING
            else DisplayStage.TASK
        )
        return tuple(
            RunStageProjection(
                stage=stage,
                status=(
                    DisplayStageStatus.ACTIVE
                    if stage is active
                    else DisplayStageStatus.PENDING
                ),
                item_count=0,
            )
            for stage in DisplayStage
        )

    counts = {
        DisplayStage.TASK: 1,
        DisplayStage.PLAN: 1 if getattr(outcome, "plan", None) is not None else 0,
        DisplayStage.TOOL: len(getattr(outcome, "tool_invocations", ())),
        DisplayStage.POLICY: len(getattr(outcome, "policy_decisions", ())),
        DisplayStage.EXECUTOR: len(getattr(outcome, "results", ())),
        DisplayStage.EVIDENCE: len(getattr(outcome, "evidence", ())),
        DisplayStage.VERIFIER: len(getattr(outcome, "verdicts", ())),
    }
    denied = any(
        not decision.allowed for decision in getattr(outcome, "policy_decisions", ())
    )
    executor_failed = any(
        result.status
        in {
            ToolResultStatus.FAILED,
            ToolResultStatus.TIMED_OUT,
            ToolResultStatus.EXECUTOR_ERROR,
            ToolResultStatus.INTERRUPTED,
        }
        for result in getattr(outcome, "results", ())
    )
    projections = []
    for stage in DisplayStage:
        if stage is DisplayStage.POLICY and denied:
            state = DisplayStageStatus.BLOCKED
        elif stage is DisplayStage.EXECUTOR and executor_failed:
            state = DisplayStageStatus.FAILED
        elif counts[stage] > 0:
            state = DisplayStageStatus.COMPLETED
        else:
            state = DisplayStageStatus.PENDING
        projections.append(
            RunStageProjection(stage=stage, status=state, item_count=counts[stage])
        )
    return tuple(projections)


def _unconfigured_report(record: ManagedRunRecord) -> ReportProjection:
    outcome = record.outcome
    verdicts = tuple(getattr(outcome, "verdicts", ())) if outcome is not None else ()
    terminal = record.status in {
        RunStatus.COMPLETED,
        RunStatus.FAILED,
        RunStatus.BLOCKED,
        RunStatus.CANCELLED,
    }
    return ReportProjection(
        run_id=record.run_id,
        status=ReportStatus.UNAVAILABLE if terminal else ReportStatus.PENDING,
        title=f"{_scenario_title(record.task_pack_id)}报告",
        template_id=_report_template(record.task_pack_id),
        verdict_outcome=verdicts[-1].outcome if verdicts else None,
        evidence_count=(len(getattr(outcome, "evidence", ())) if outcome is not None else 0),
        audit_count=(len(getattr(outcome, "audit_records", ())) if outcome is not None else 0),
        reason_code="REPORT_GENERATOR_NOT_CONFIGURED" if terminal else None,
    )


def _scenario_title(task_pack_id: str) -> str:
    return {
        WEB_IDOR_TASK_PACK_ID: "Web安全评估",
        SOURCE_AUDIT_TASK_PACK_ID: "Python源码审计",
    }.get(task_pack_id, "安全任务")


def _provider_label(provider: str, display_name: str) -> str:
    known = {
        "kimi": "Kimi",
        "deepseek": "DeepSeek",
    }
    return known.get(provider, display_name)


def _report_template(task_pack_id: str) -> str:
    return {
        WEB_IDOR_TASK_PACK_ID: WEB_IDOR_REPORT_TEMPLATE,
        SOURCE_AUDIT_TASK_PACK_ID: SOURCE_AUDIT_REPORT_TEMPLATE,
    }.get(task_pack_id, "security.generic-report")


__all__ = [
    "ArtifactDisplayProjection",
    "AuditSummaryProjection",
    "CapabilityStatus",
    "CompetitionPresentationService",
    "ConnectionStatus",
    "DashboardReadiness",
    "DashboardStatusProjection",
    "DisplayStage",
    "DisplayStageStatus",
    "DockerStatusProjection",
    "EvidenceDisplayProjection",
    "EvidenceListProjection",
    "ModelCapabilityProjection",
    "ModelStatusProjection",
    "PlanDisplayProjection",
    "PolicyDisplayProjection",
    "PresentationError",
    "RunDisplayProjection",
    "RunRecordSourcePort",
    "RunStageProjection",
    "StepDisplayProjection",
    "TaskDisplayProjection",
    "ToolExecutionProjection",
    "VerdictDisplayProjection",
    "project_dashboard",
    "project_evidence",
    "project_run",
]
