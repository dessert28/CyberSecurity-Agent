from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from cyber_agent.application.run_management import (
    CompetitionRunManager,
    InMemoryRunStore,
    ManagedRunRecord,
    RunManagementError,
    _summary_from_record,
)
from cyber_agent.audit_store import build_audit_record
from cyber_agent.contracts.audit import AuditEventType
from cyber_agent.contracts.common import (
    ActorRef,
    ActorType,
    EnvironmentProfile,
    ErrorCategory,
    ErrorInfo,
    ModelProfileRef,
    RiskLevel,
    SuccessCriterion,
)
from cyber_agent.contracts.plan import Run, RunStatus
from cyber_agent.contracts.task import (
    ScopePolicy,
    ScopeTarget,
    Task,
    TaskConstraints,
    TaskStatus,
    TargetKind,
)


@pytest.mark.asyncio
async def test_run_store_lists_records_by_most_recent_update() -> None:
    store = InMemoryRunStore()
    created_at = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
    older = ManagedRunRecord(
        run_id=uuid4(),
        task_pack_id="web.idor",
        request_text="Older task",
        artifact_id=None,
        scenario_input={},
        status=RunStatus.COMPLETED,
        created_at=created_at,
    )
    newer = ManagedRunRecord(
        run_id=uuid4(),
        task_pack_id="web.idor",
        request_text="Newer task",
        artifact_id=None,
        scenario_input={},
        status=RunStatus.QUEUED,
        created_at=created_at + timedelta(minutes=1),
    )
    await store.create(older)
    await store.create(newer)

    records = await store.list_recent(limit=20)

    assert [record.run_id for record in records] == [newer.run_id, older.run_id]


@pytest.mark.asyncio
async def test_sqlite_run_history_survives_a_new_store_instance(tmp_path) -> None:
    from cyber_agent.application.run_history import SQLiteRunHistory
    from cyber_agent.application.run_management import RunSummaryResponse

    run_id = uuid4()
    created_at = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
    record = ManagedRunRecord(
        run_id=run_id,
        task_pack_id="web.idor",
        request_text="Assess the authorized order API.",
        artifact_id=None,
        scenario_input={},
        status=RunStatus.COMPLETED,
        created_at=created_at,
    )
    summary = RunSummaryResponse(
        run_id=run_id,
        task_pack="web.idor",
        status=RunStatus.COMPLETED,
        evidence_count=0,
        audit_count=0,
    )
    database_path = tmp_path / "state.db"

    history = SQLiteRunHistory(database_path=database_path)
    await history.save(record, summary=summary, audit_events=())
    recovered = SQLiteRunHistory(database_path=database_path)

    assert await recovered.get_summary(run_id) == summary
    items = await recovered.list_recent(limit=20)
    assert len(items) == 1
    assert items[0].run_id == run_id
    assert items[0].request_preview == "Assess the authorized order API."


@pytest.mark.asyncio
async def test_sqlite_run_history_recovers_legacy_interruption_error_code(tmp_path) -> None:
    from cyber_agent.application.run_history import SQLiteRunHistory
    from cyber_agent.application.run_management import RunSummaryResponse

    run_id = uuid4()
    created_at = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
    record = ManagedRunRecord(
        run_id=run_id,
        task_pack_id="source.audit.python",
        request_text="Audit the uploaded Python project.",
        artifact_id=None,
        scenario_input={},
        status=RunStatus.FAILED,
        created_at=created_at,
    )
    interruption = build_audit_record(
        run_id=run_id,
        sequence=1,
        timestamp=created_at,
        actor=ActorRef(actor_type=ActorType.SYSTEM, actor_id="test"),
        event_type=AuditEventType.RUN_INTERRUPTED,
        outcome="The model request timed out.",
        reason_codes=["MODEL_TIMEOUT"],
        correlation_id=run_id,
    )
    history = SQLiteRunHistory(database_path=tmp_path / "state.db")
    await history.save(
        record,
        summary=RunSummaryResponse(
            run_id=run_id,
            task_pack=record.task_pack_id,
            status=RunStatus.FAILED,
            evidence_count=0,
            audit_count=1,
        ),
        audit_events=(interruption,),
    )

    recovered = await history.get_summary(run_id)
    recent = await history.list_recent(limit=20)

    assert recovered.error_code == "MODEL_TIMEOUT"
    assert recent[0].error_code == "MODEL_TIMEOUT"


@pytest.mark.asyncio
async def test_run_manager_reads_a_completed_run_from_durable_history(tmp_path) -> None:
    from cyber_agent.application.run_history import SQLiteRunHistory
    from cyber_agent.application.run_management import RunSummaryResponse

    run_id = uuid4()
    created_at = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
    record = ManagedRunRecord(
        run_id=run_id,
        task_pack_id="web.idor",
        request_text="Assess the authorized order API.",
        artifact_id=None,
        scenario_input={},
        status=RunStatus.COMPLETED,
        created_at=created_at,
    )
    expected = RunSummaryResponse(
        run_id=run_id,
        task_pack="web.idor",
        status=RunStatus.COMPLETED,
        evidence_count=0,
        audit_count=0,
    )
    history = SQLiteRunHistory(database_path=tmp_path / "state.db")
    await history.save(record, summary=expected, audit_events=())

    manager = CompetitionRunManager(
        service=object(),
        store=InMemoryRunStore(),
        history=history,
    )

    assert await manager.get_summary(run_id) == expected


@pytest.mark.asyncio
async def test_sqlite_history_marks_active_runs_interrupted_after_restart(tmp_path) -> None:
    from cyber_agent.application.run_history import SQLiteRunHistory
    from cyber_agent.application.run_management import RunSummaryResponse

    run_id = uuid4()
    created_at = datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)
    record = ManagedRunRecord(
        run_id=run_id,
        task_pack_id="web.idor",
        request_text="Assess the authorized order API.",
        artifact_id=None,
        scenario_input={},
        status=RunStatus.RUNNING,
        created_at=created_at,
    )
    history = SQLiteRunHistory(database_path=tmp_path / "state.db")
    await history.save(
        record,
        summary=RunSummaryResponse(
            run_id=run_id,
            task_pack="web.idor",
            status=RunStatus.RUNNING,
            evidence_count=0,
            audit_count=0,
        ),
        audit_events=(),
    )

    await history.interrupt_active_runs()

    recovered = await history.get_summary(run_id)
    assert recovered.status is RunStatus.CANCELLED
    assert recovered.error_code == "RUN_INTERRUPTED_BY_RESTART"


@pytest.mark.asyncio
async def test_run_manager_reports_missing_durable_run_as_not_found(tmp_path) -> None:
    from cyber_agent.application.run_history import SQLiteRunHistory

    manager = CompetitionRunManager(
        service=object(),
        store=InMemoryRunStore(),
        history=SQLiteRunHistory(database_path=tmp_path / "state.db"),
    )

    with pytest.raises(RunManagementError, match="not found") as error:
        await manager.get_summary(uuid4())

    assert error.value.code == "RUN_NOT_FOUND"


def test_summary_exposes_interrupted_outcome_error_code() -> None:
    """A model timeout must be visible in the persisted run summary."""

    run_id = uuid4()
    now = datetime.now(timezone.utc)
    error = ErrorInfo(
        code="MODEL_TIMEOUT",
        category=ErrorCategory.MODEL_TRANSIENT,
        retryable=True,
        safe_message="The model request timed out.",
    )
    task = Task(
        created_at=now,
        request_text="Audit the uploaded Python project.",
        objective="Audit the uploaded Python project.",
        scope=ScopePolicy(
            allowed_targets=[
                ScopeTarget(
                    kind=TargetKind.FILE,
                    value="uploaded-project",
                    protocols={"file"},
                )
            ],
            allowed_tool_ids=set(),
            maximum_risk=RiskLevel.R1,
        ),
        constraints=TaskConstraints(),
        success_criteria=[
            SuccessCriterion(kind="audit", description="Produce an audit result.")
        ],
        status=TaskStatus.FAILED,
    )
    core_run = Run(
        run_id=run_id,
        task_id=task.task_id,
        created_at=now,
        status=RunStatus.FAILED,
        budget=task.constraints.budget,
        model_profile=ModelProfileRef(
            provider="test-provider",
            model="test-model",
            configuration_fingerprint="0" * 64,
        ),
        environment_profile=EnvironmentProfile(
            executor_backend="test-executor",
            platform="test",
            configuration_fingerprint="1" * 64,
        ),
        termination_reason=error,
    )
    outcome = SimpleNamespace(
        task=task,
        run=core_run,
        steps=(),
        evidence=(),
        verdicts=(),
        audit_records=(),
    )
    record = ManagedRunRecord(
        run_id=run_id,
        task_pack_id="source.audit.python",
        request_text=task.request_text,
        artifact_id=None,
        scenario_input={},
        status=RunStatus.FAILED,
        created_at=now,
        outcome=outcome,
    )

    summary = _summary_from_record(record)

    assert summary.error_code == "MODEL_TIMEOUT"
