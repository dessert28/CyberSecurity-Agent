"""Competition run admission, in-memory lifecycle, and read models."""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import Field, JsonValue, ValidationError, field_validator

from cyber_agent.application.competition_service import CompetitionServiceError
from cyber_agent.application.runtime_snapshot import (
    PreparedRuntimeContextPort,
    RuntimeSnapshot,
    RuntimeSnapshotConflictError,
)
from cyber_agent.contracts.audit import AuditRecord
from cyber_agent.contracts.common import RiskLevel, StableCode, StrictModel, UtcDateTime
from cyber_agent.contracts.evidence import VerificationVerdict
from cyber_agent.contracts.model import ModelCallRef, ModelCallStatus
from cyber_agent.contracts.plan import RunStatus, Step, StepStatus
from cyber_agent.contracts.task import ScopePolicy, ScopeTarget, TargetKind, Task
from cyber_agent.task_packs.catalog import SourceAuditScenarioInput
from cyber_agent.task_packs.source_audit import SOURCE_AUDIT_TASK_PACK_ID
from cyber_agent.task_packs.web_idor import (
    WEB_IDOR_TASK_PACK_ID,
    WEB_IDOR_TOOL_ID,
    WebIdorStepBinding,
)
from cyber_agent.workbench.schemas import RuntimeIdentityProjection


class RunCreateRequest(StrictModel):
    """The complete browser-writable run contract; extras are forbidden."""

    task_pack_id: str = Field(min_length=1, max_length=128)
    request_text: str = Field(min_length=1, max_length=100_000)
    artifact_id: UUID | None = None
    scenario_input: dict[str, JsonValue] = Field(default_factory=dict)


class RunAcceptedResponse(StrictModel):
    run_id: UUID
    status: RunStatus
    runtime_identity: RuntimeIdentityProjection | None = None


class RunStepSummary(StrictModel):
    step_id: UUID
    ordinal: int = Field(ge=1)
    objective: str
    status: StepStatus


class RunSummaryResponse(StrictModel):
    run_id: UUID
    core_run_id: UUID | None = None
    task: Task | None = None
    task_pack: str
    status: RunStatus
    current_step: RunStepSummary | None = None
    verdict: VerificationVerdict | None = None
    evidence_count: int = Field(ge=0)
    audit_count: int = Field(ge=0)
    error_code: StableCode | None = None
    runtime_identity: RuntimeIdentityProjection | None = None
    model_call_refs: tuple[ModelCallRef, ...] = ()


class RunAuditResponse(StrictModel):
    run_id: UUID
    after_sequence: int = Field(ge=0)
    events: tuple[AuditRecord, ...]


class WebRunScenarioInput(StrictModel):
    """Browser-selectable Web facts; execution policy is generated server-side."""

    target_url: str = Field(min_length=1, max_length=2048)
    bindings: tuple[WebIdorStepBinding, ...] = Field(min_length=2, max_length=2)

    @field_validator("target_url")
    @classmethod
    def target_url_is_trimmed_printable_text(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("target_url must be trimmed printable text")
        return value


class CompetitionRunServicePort(Protocol):
    def validate_request(
        self,
        *,
        task_pack_id: str,
        request_text: str,
        artifact_id: UUID | None,
        scenario_input: Mapping[str, object],
    ) -> None: ...

    async def run_task(
        self,
        *,
        task_pack_id: str,
        request_text: str,
        artifact_id: UUID | None,
        scenario_input: Mapping[str, object],
    ) -> object: ...


@runtime_checkable
class RuntimePreparationPort(Protocol):
    """Prepare a real Runtime while preserving the admission boundary."""

    async def prepare(
        self,
        *,
        run_id: UUID,
        task_pack_id: str,
        request_text: str,
        artifact_id: UUID | None,
        scenario_input: Mapping[str, object],
    ) -> PreparedRuntimeContextPort: ...


class RunManagementError(ValueError):
    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass(slots=True)
class ManagedRunRecord:
    run_id: UUID
    task_pack_id: str
    request_text: str
    artifact_id: UUID | None
    scenario_input: dict[str, object]
    status: RunStatus
    created_at: datetime
    outcome: object | None = None
    error_code: str | None = None
    runtime_snapshot: RuntimeSnapshot | None = None
    model_call_refs: tuple[ModelCallRef, ...] = ()


@runtime_checkable
class RunStorePort(Protocol):
    async def create(self, record: ManagedRunRecord) -> None: ...

    async def claim(self, run_id: UUID) -> ManagedRunRecord | None: ...

    async def save(self, record: ManagedRunRecord) -> None: ...

    async def get(self, run_id: UUID) -> ManagedRunRecord: ...


class InMemoryRunStore:
    """Process-local RunStore implementation with per-record isolation."""

    def __init__(self) -> None:
        self._records: dict[UUID, ManagedRunRecord] = {}
        self._lock = asyncio.Lock()

    async def create(self, record: ManagedRunRecord) -> None:
        async with self._lock:
            if record.run_id in self._records:
                raise RunManagementError(
                    "RUN_ALREADY_EXISTS",
                    "The generated run identifier already exists.",
                    status_code=409,
                )
            self._records[record.run_id] = copy.deepcopy(record)

    async def save(self, record: ManagedRunRecord) -> None:
        async with self._lock:
            if record.run_id not in self._records:
                raise RunManagementError(
                    "RUN_NOT_FOUND",
                    "The requested run was not found.",
                    status_code=404,
                )
            self._records[record.run_id] = copy.deepcopy(record)

    async def claim(self, run_id: UUID) -> ManagedRunRecord | None:
        """Atomically move one queued run to running exactly once."""

        async with self._lock:
            try:
                record = self._records[run_id]
            except KeyError as exc:
                raise RunManagementError(
                    "RUN_NOT_FOUND",
                    "The requested run was not found.",
                    status_code=404,
                ) from exc
            if record.status is not RunStatus.QUEUED:
                return None
            record.status = RunStatus.RUNNING
            self._records[run_id] = copy.deepcopy(record)
            return copy.deepcopy(record)

    async def get(self, run_id: UUID) -> ManagedRunRecord:
        async with self._lock:
            try:
                record = self._records[run_id]
            except KeyError as exc:
                raise RunManagementError(
                    "RUN_NOT_FOUND",
                    "The requested run was not found.",
                    status_code=404,
                ) from exc
            return copy.deepcopy(record)


class CompetitionRunManager:
    """Admit a safe request, execute it, and expose polling read models."""

    def __init__(
        self,
        *,
        service: CompetitionRunServicePort | None,
        store: RunStorePort,
        runtime_preparer: RuntimePreparationPort | None = None,
        run_id_factory=uuid4,
        clock=None,
    ) -> None:
        if not isinstance(store, RunStorePort):
            raise TypeError("store does not implement RunStorePort")
        if runtime_preparer is not None and not isinstance(
            runtime_preparer,
            RuntimePreparationPort,
        ):
            raise TypeError("runtime_preparer does not implement RuntimePreparationPort")
        if service is None and runtime_preparer is None:
            raise TypeError("service is required when no runtime_preparer is configured")
        self._service = service
        self._store = store
        self._runtime_preparer = runtime_preparer
        self._run_id_factory = run_id_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._prepared_contexts: dict[UUID, PreparedRuntimeContextPort] = {}
        self._prepared_contexts_lock = asyncio.Lock()

    @property
    def runtime_preparer(self) -> RuntimePreparationPort | None:
        return self._runtime_preparer

    async def create_run(self, request: RunCreateRequest) -> RunAcceptedResponse:
        scenario_input = _normalize_scenario_input(
            request.task_pack_id,
            request.scenario_input,
        )
        if self._runtime_preparer is None:
            try:
                assert self._service is not None
                self._service.validate_request(
                    task_pack_id=request.task_pack_id,
                    request_text=request.request_text,
                    artifact_id=request.artifact_id,
                    scenario_input=scenario_input,
                )
            except CompetitionServiceError as exc:
                raise RunManagementError(
                    exc.code,
                    str(exc),
                    status_code=_competition_error_status(exc.code),
                ) from exc

        run_id = self._run_id_factory()
        request_text = request.request_text.strip()
        context: PreparedRuntimeContextPort | None = None
        snapshot: RuntimeSnapshot | None = None
        if self._runtime_preparer is not None:
            try:
                context = await self._runtime_preparer.prepare(
                    run_id=run_id,
                    task_pack_id=request.task_pack_id,
                    request_text=request_text,
                    artifact_id=request.artifact_id,
                    scenario_input=scenario_input,
                )
                if not isinstance(context, PreparedRuntimeContextPort):
                    raise TypeError("prepared context does not implement its lifecycle port")
                snapshot = context.snapshot
                if (
                    not isinstance(snapshot, RuntimeSnapshot)
                    or snapshot.taskpack_id != request.task_pack_id
                ):
                    raise RuntimeSnapshotConflictError(
                        "prepared snapshot does not match the requested taskpack"
                    )
                await context.validate_admission()
                if context.snapshot != snapshot:
                    raise RuntimeSnapshotConflictError(
                        "prepared snapshot changed during admission"
                    )
            except RuntimeSnapshotConflictError as exc:
                await _close_context(context)
                raise RunManagementError(
                    "RUNTIME_SNAPSHOT_CONFLICT",
                    "Runtime identity changed during admission.",
                    status_code=409,
                ) from exc
            except RunManagementError:
                await _close_context(context)
                raise
            except Exception as exc:
                await _close_context(context)
                raise RunManagementError(
                    "RUNTIME_PREPARATION_FAILED",
                    "The formal Runtime could not be prepared safely.",
                    status_code=503,
                ) from exc
        record = ManagedRunRecord(
            run_id=run_id,
            task_pack_id=request.task_pack_id,
            request_text=request_text,
            artifact_id=request.artifact_id,
            scenario_input=scenario_input,
            status=RunStatus.QUEUED,
            created_at=self._clock(),
            runtime_snapshot=snapshot,
        )
        try:
            await self._store.create(record)
        except Exception:
            await _close_context(context)
            raise
        if context is not None:
            async with self._prepared_contexts_lock:
                self._prepared_contexts[run_id] = context
        return RunAcceptedResponse(
            run_id=run_id,
            status=RunStatus.QUEUED,
            runtime_identity=(snapshot.public_identity() if snapshot is not None else None),
        )

    async def execute_run(self, run_id: UUID) -> None:
        try:
            record = await self._store.claim(run_id)
        except Exception:
            await _close_context(await self._take_prepared_context(run_id))
            raise
        if record is None:
            return
        context = await self._take_prepared_context(run_id)
        try:
            if record.runtime_snapshot is not None:
                if context is None:
                    raise RuntimeError("prepared Runtime context is unavailable")
                outcome = await context.run_task(
                    task_pack_id=record.task_pack_id,
                    request_text=record.request_text,
                    artifact_id=record.artifact_id,
                    scenario_input=record.scenario_input,
                )
            else:
                if self._service is None:
                    raise RuntimeError("legacy Runtime service is unavailable")
                outcome = await self._service.run_task(
                    task_pack_id=record.task_pack_id,
                    request_text=record.request_text,
                    artifact_id=record.artifact_id,
                    scenario_input=record.scenario_input,
                )
            _validate_outcome(record, outcome)
        except CompetitionServiceError as exc:
            record.status = RunStatus.FAILED
            record.error_code = exc.code
        except Exception:
            record.status = RunStatus.FAILED
            record.error_code = "RUN_MANAGEMENT_EXECUTION_FAILED"
        else:
            record.outcome = outcome
            record.status = outcome.run.status
        finally:
            try:
                record.model_call_refs = _model_call_refs(context, record.run_id)
            except Exception:
                record.model_call_refs = ()
                record.status = RunStatus.FAILED
                record.error_code = "MODEL_CALL_TRACE_INVALID"
            finally:
                await _close_context(context)
        await self._store.save(record)

    async def get_summary(self, run_id: UUID) -> RunSummaryResponse:
        record = await self._store.get(run_id)
        outcome = record.outcome
        task = outcome.task.model_copy(deep=True) if outcome is not None else None
        audit_records = _audit_records(outcome)
        evidence = tuple(outcome.evidence) if outcome is not None else ()
        verdicts = tuple(outcome.verdicts) if outcome is not None else ()
        return RunSummaryResponse(
            run_id=record.run_id,
            core_run_id=outcome.run.run_id if outcome is not None else None,
            task=task,
            task_pack=record.task_pack_id,
            status=record.status,
            current_step=_current_step(outcome),
            verdict=verdicts[-1].model_copy(deep=True) if verdicts else None,
            evidence_count=len(evidence),
            audit_count=len(audit_records),
            error_code=record.error_code,
            runtime_identity=(
                record.runtime_snapshot.public_identity()
                if record.runtime_snapshot is not None
                else None
            ),
            model_call_refs=tuple(
                item.model_copy(deep=True) for item in record.model_call_refs
            ),
        )

    async def _take_prepared_context(
        self,
        run_id: UUID,
    ) -> PreparedRuntimeContextPort | None:
        async with self._prepared_contexts_lock:
            return self._prepared_contexts.pop(run_id, None)

    async def get_record(self, run_id: UUID) -> ManagedRunRecord:
        """Return an isolated snapshot for trusted read-model projectors."""

        return await self._store.get(run_id)

    async def get_audit(
        self,
        run_id: UUID,
        *,
        after_sequence: int = 0,
    ) -> RunAuditResponse:
        if after_sequence < 0:
            raise RunManagementError(
                "AUDIT_SEQUENCE_INVALID",
                "after_sequence must not be negative.",
                status_code=422,
            )
        record = await self._store.get(run_id)
        events = tuple(
            item.model_copy(deep=True)
            for item in _audit_records(record.outcome)
            if item.sequence > after_sequence
        )
        return RunAuditResponse(
            run_id=run_id,
            after_sequence=after_sequence,
            events=events,
        )


def _normalize_scenario_input(
    task_pack_id: str,
    scenario_input: Mapping[str, JsonValue],
) -> dict[str, object]:
    if task_pack_id == WEB_IDOR_TASK_PACK_ID:
        try:
            selected = WebRunScenarioInput.model_validate(scenario_input)
            scope = _web_scope(selected.target_url)
        except (ValidationError, ValueError) as exc:
            raise RunManagementError(
                "SCENARIO_INPUT_INVALID",
                "The Web scenario input is invalid.",
                status_code=422,
            ) from exc
        return {
            "scope": scope.model_dump(mode="json"),
            "bindings": [item.model_dump(mode="json") for item in selected.bindings],
        }
    if task_pack_id == SOURCE_AUDIT_TASK_PACK_ID:
        try:
            selected = SourceAuditScenarioInput.model_validate(scenario_input)
        except ValidationError as exc:
            raise RunManagementError(
                "SCENARIO_INPUT_INVALID",
                "The Source Audit scenario input is invalid.",
                status_code=422,
            ) from exc
        return selected.model_dump(mode="json")
    return dict(scenario_input)


def _web_scope(target_url: str) -> ScopePolicy:
    try:
        parsed = urlsplit(target_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target_url is invalid") from exc
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("target_url must use http or https")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("target_url credentials and fragments are forbidden")
    effective_port = port or (443 if parsed.scheme == "https" else 80)
    return ScopePolicy(
        allowed_targets=[
            ScopeTarget(
                kind=TargetKind.URL,
                value=target_url,
                protocols={parsed.scheme},
                ports={effective_port},
            )
        ],
        network_access=True,
        allowed_tool_ids={WEB_IDOR_TOOL_ID},
        maximum_risk=RiskLevel.R1,
    )


def _validate_outcome(record: ManagedRunRecord, outcome: object) -> None:
    run = getattr(outcome, "run", None)
    task = getattr(outcome, "task", None)
    task_pack_id = getattr(outcome, "task_pack_id", None)
    if (
        run is None
        or not isinstance(getattr(run, "run_id", None), UUID)
        or not isinstance(getattr(run, "status", None), RunStatus)
        or not isinstance(task, Task)
        or task_pack_id != record.task_pack_id
    ):
        raise ValueError("run outcome is invalid")
    for item in getattr(outcome, "audit_records", ()):
        if not isinstance(item, AuditRecord) or item.run_id != run.run_id:
            raise ValueError("run audit result is invalid")


def _model_call_refs(
    context: PreparedRuntimeContextPort | None,
    run_id: UUID,
) -> tuple[ModelCallRef, ...]:
    if context is None:
        return ()
    value = getattr(context, "model_call_refs", ())
    if callable(value):
        value = value()
    if not isinstance(value, (tuple, list)):
        raise ValueError("prepared Runtime model call refs are invalid")
    refs: list[ModelCallRef] = []
    for item in value:
        if (
            not isinstance(item, ModelCallRef)
            or item.run_id != run_id
            or item.status
            not in {ModelCallStatus.SUCCEEDED, ModelCallStatus.FAILED}
        ):
            raise ValueError("prepared Runtime model call ref is invalid")
        refs.append(item.model_copy(deep=True))
    return tuple(refs)


def _audit_records(outcome: object | None) -> tuple[AuditRecord, ...]:
    if outcome is None:
        return ()
    return tuple(getattr(outcome, "audit_records", ()))


def _current_step(outcome: object | None) -> RunStepSummary | None:
    if outcome is None:
        return None
    steps: Sequence[Step] = tuple(getattr(outcome, "steps", ()))
    if not steps:
        return None
    active = {
        StepStatus.READY,
        StepStatus.RUNNING,
        StepStatus.VERIFYING,
    }
    selected = next((item for item in reversed(steps) if item.status in active), steps[-1])
    return RunStepSummary(
        step_id=selected.step_id,
        ordinal=selected.ordinal,
        objective=selected.objective,
        status=selected.status,
    )


def _competition_error_status(code: str) -> int:
    if code in {"TASK_PACK_NOT_REGISTERED", "ARTIFACT_NOT_FOUND"}:
        return 404
    if code in {
        "TASK_PACK_VERIFIER_UNAVAILABLE",
        "TASK_PACK_TOOL_UNAVAILABLE",
        "ARTIFACT_RESOLVER_UNAVAILABLE",
    }:
        return 503
    return 422


async def _close_context(context: PreparedRuntimeContextPort | None) -> None:
    if context is None:
        return
    try:
        await context.aclose()
    except Exception:
        # Cleanup is best-effort but never changes the stable admission/execution error.
        pass


__all__ = [
    "CompetitionRunManager",
    "InMemoryRunStore",
    "ManagedRunRecord",
    "RunAcceptedResponse",
    "RunAuditResponse",
    "RunCreateRequest",
    "RunManagementError",
    "RuntimePreparationPort",
    "RunStepSummary",
    "RunStorePort",
    "RunSummaryResponse",
]
