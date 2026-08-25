from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from cyber_agent.workbench import ReadinessState as ExportedReadinessState
from cyber_agent.application.runtime_readiness import RuntimeReadinessService
from cyber_agent.workbench.schemas import (
    ModelRuntimeReadiness,
    ReadinessState,
    RuntimeReadinessResponse,
    TaskPackReadiness,
    ToolReadinessView,
)


NOW = datetime(2026, 8, 18, 8, 0, tzinfo=timezone.utc)
SOURCE_TASKPACK = "source.audit.python"
WEB_TASKPACK = "web.idor"


def _model_ready() -> ModelRuntimeReadiness:
    return ModelRuntimeReadiness(
        ready=True,
        state=ReadinessState.READY,
        reason_codes=(),
        capability_probe_ref="11111111-1111-4111-8111-111111111111",
    )


def _service(
    *,
    model_probe=_model_ready,
    core_state: ReadinessState = ReadinessState.READY,
    source_state: ReadinessState = ReadinessState.READY,
    web_state: ReadinessState = ReadinessState.EXECUTOR_NOT_READY,
) -> RuntimeReadinessService:
    states = {
        SOURCE_TASKPACK: source_state,
        WEB_TASKPACK: web_state,
    }
    return RuntimeReadinessService(
        model_probe=model_probe,
        core_probe=lambda: core_state,
        taskpack_ids=(WEB_TASKPACK, SOURCE_TASKPACK),
        taskpack_probe=lambda taskpack_id: states[taskpack_id],
        clock=lambda: NOW,
    )


def test_runtime_is_available_when_core_and_at_least_one_taskpack_are_ready() -> None:
    result = _service().status()

    assert result.state is ReadinessState.READY
    assert result.runtime_available is True
    assert result.model_ready is True
    assert result.core_ready is True
    assert result.available_taskpacks == (SOURCE_TASKPACK,)
    assert result.unavailable_taskpacks == (
        TaskPackReadiness(
            task_pack_id=WEB_TASKPACK,
            state=ReadinessState.EXECUTOR_NOT_READY,
            reason_codes=(ReadinessState.EXECUTOR_NOT_READY,),
        ),
    )
    assert result.checked_at == NOW


@pytest.mark.parametrize(
    ("model_state", "expected_state"),
    [
        (ReadinessState.MODEL_NOT_READY, ReadinessState.MODEL_NOT_READY),
        (ReadinessState.CREDENTIAL_MISSING, ReadinessState.CREDENTIAL_MISSING),
        (ReadinessState.CAPABILITY_STALE, ReadinessState.CAPABILITY_STALE),
        (ReadinessState.CAPABILITY_FAILED, ReadinessState.CAPABILITY_FAILED),
    ],
)
def test_model_failure_states_fail_closed(
    model_state: ReadinessState,
    expected_state: ReadinessState,
) -> None:
    def model_probe() -> ModelRuntimeReadiness:
        return ModelRuntimeReadiness(
            ready=False,
            state=model_state,
            reason_codes=(model_state,),
        )

    result = _service(model_probe=model_probe).status()

    assert result.runtime_available is False
    assert result.model_ready is False
    assert result.core_ready is False
    assert result.state is expected_state
    assert result.reason_codes == (expected_state,)


def test_global_ready_does_not_make_web_idor_ready() -> None:
    result = _service().status()
    states = {item.task_pack_id: item.state for item in result.taskpacks}

    assert result.runtime_available is True
    assert states == {
        WEB_TASKPACK: ReadinessState.EXECUTOR_NOT_READY,
        SOURCE_TASKPACK: ReadinessState.READY,
    }


def test_no_ready_taskpack_fails_closed_with_deterministic_catalog_order() -> None:
    result = _service(
        source_state=ReadinessState.TASKPACK_DISABLED,
        web_state=ReadinessState.EXECUTOR_NOT_READY,
    ).status()

    assert result.runtime_available is False
    assert result.core_ready is True
    assert result.state is ReadinessState.EXECUTOR_NOT_READY
    assert result.reason_codes == (
        ReadinessState.EXECUTOR_NOT_READY,
        ReadinessState.TASKPACK_DISABLED,
    )


def test_probe_exceptions_are_replaced_by_stable_safe_states() -> None:
    def model_probe() -> ModelRuntimeReadiness:
        raise RuntimeError("private provider failure with secret-marker")

    result = _service(model_probe=model_probe).status()

    assert result.runtime_available is False
    assert result.state is ReadinessState.MODEL_NOT_READY
    assert "secret-marker" not in result.model_dump_json()


def test_response_model_rejects_contradictory_available_taskpack_lists() -> None:
    with pytest.raises(ValidationError):
        RuntimeReadinessResponse(
            state=ReadinessState.READY,
            runtime_available=True,
            model_ready=True,
            core_ready=True,
            reason_codes=(),
            available_taskpacks=(WEB_TASKPACK,),
            unavailable_taskpacks=(),
            taskpacks=(
                TaskPackReadiness(
                    task_pack_id=WEB_TASKPACK,
                    state=ReadinessState.EXECUTOR_NOT_READY,
                    reason_codes=(ReadinessState.EXECUTOR_NOT_READY,),
                ),
            ),
            checked_at=NOW,
        )


def test_response_model_rejects_unknown_internal_fields() -> None:
    payload = _service().status().model_dump()
    payload["internal_exception"] = "provider stack trace"

    with pytest.raises(ValidationError):
        RuntimeReadinessResponse.model_validate(payload)


def test_workbench_package_exports_the_stable_readiness_contract() -> None:
    assert ExportedReadinessState is ReadinessState


def test_detail_probe_populates_taskpack_report_and_unknown_id_is_disabled() -> None:
    detail = TaskPackReadiness(
        task_pack_id=WEB_TASKPACK,
        state=ReadinessState.EXECUTOR_NOT_READY,
        reason_codes=(ReadinessState.EXECUTOR_NOT_READY,),
        required_tools=("web.http_request",),
        tool_states=(
            ToolReadinessView(
                tool_id="web.http_request",
                state="unhealthy",
                healthy=False,
                message="container runtime unavailable",
            ),
        ),
        model_capability_ready=True,
        detail="依赖工具未就绪：web.http_request",
    )
    service = RuntimeReadinessService(
        model_probe=_model_ready,
        core_probe=lambda: ReadinessState.READY,
        taskpack_ids=(WEB_TASKPACK, SOURCE_TASKPACK),
        taskpack_probe=lambda task_pack_id: (
            ReadinessState.EXECUTOR_NOT_READY
            if task_pack_id == WEB_TASKPACK
            else ReadinessState.READY
        ),
        taskpack_detail_probe=lambda task_pack_id: (
            detail
            if task_pack_id == WEB_TASKPACK
            else TaskPackReadiness(
                task_pack_id=task_pack_id,
                state=ReadinessState.READY,
                reason_codes=(),
            )
        ),
        clock=lambda: NOW,
    )

    result = service.status()
    by_id = {item.task_pack_id: item for item in result.taskpacks}
    assert by_id[WEB_TASKPACK].detail == detail.detail
    assert by_id[WEB_TASKPACK].tool_states == detail.tool_states
    assert by_id[WEB_TASKPACK].model_capability_ready is True
    assert by_id[SOURCE_TASKPACK].state is ReadinessState.READY

    unknown = service.detail("unknown.pack")
    assert unknown.state is ReadinessState.TASKPACK_DISABLED
    assert unknown.reason_codes == (ReadinessState.TASKPACK_DISABLED,)
    assert unknown.detail is not None
