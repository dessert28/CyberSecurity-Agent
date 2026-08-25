"""Stable fail-closed readiness aggregation for formal runtime admission."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone

from cyber_agent.workbench.schemas import (
    ModelRuntimeReadiness,
    ReadinessState,
    RuntimeReadinessResponse,
    TaskPackReadiness,
)

logger = logging.getLogger(__name__)


class RuntimeReadinessService:
    """Combine independent model, core, and TaskPack readiness probes."""

    def __init__(
        self,
        *,
        model_probe: Callable[[], ModelRuntimeReadiness],
        core_probe: Callable[[], ReadinessState],
        taskpack_ids: tuple[str, ...],
        taskpack_probe: Callable[[str], ReadinessState],
        taskpack_detail_probe: Callable[[str], TaskPackReadiness] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not taskpack_ids or len(taskpack_ids) != len(set(taskpack_ids)):
            raise ValueError("taskpack_ids must be a non-empty unique catalog")
        self._model_probe = model_probe
        self._core_probe = core_probe
        self._taskpack_ids = taskpack_ids
        self._taskpack_probe = taskpack_probe
        self._taskpack_detail_probe = taskpack_detail_probe
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def status(self) -> RuntimeReadinessResponse:
        model = self._safe_model_probe()
        core_state = self._safe_core_probe()
        core_ready = model.ready and core_state is ReadinessState.READY
        taskpacks = tuple(self._taskpack_status(taskpack_id) for taskpack_id in self._taskpack_ids)
        available = tuple(
            item.task_pack_id for item in taskpacks if item.state is ReadinessState.READY
        )
        unavailable = tuple(
            item for item in taskpacks if item.state is not ReadinessState.READY
        )
        runtime_available = model.ready and core_ready and bool(available)

        if runtime_available:
            state = ReadinessState.READY
            reasons: tuple[ReadinessState, ...] = ()
        elif not model.ready:
            state = model.state
            reasons = model.reason_codes
        elif not core_ready:
            state = core_state
            reasons = (core_state,)
        else:
            reasons = self._unique_reasons(unavailable)
            state = reasons[0]

        return RuntimeReadinessResponse(
            state=state,
            runtime_available=runtime_available,
            model_ready=model.ready,
            core_ready=core_ready,
            reason_codes=reasons,
            available_taskpacks=available,
            unavailable_taskpacks=unavailable,
            taskpacks=taskpacks,
            checked_at=self._utc_now(),
        )

    def _safe_model_probe(self) -> ModelRuntimeReadiness:
        try:
            return self._model_probe()
        except Exception:
            return ModelRuntimeReadiness(
                ready=False,
                state=ReadinessState.MODEL_NOT_READY,
                reason_codes=(ReadinessState.MODEL_NOT_READY,),
            )

    def _safe_core_probe(self) -> ReadinessState:
        try:
            state = self._core_probe()
            return state if isinstance(state, ReadinessState) else ReadinessState.REGISTRY_NOT_READY
        except Exception:
            return ReadinessState.REGISTRY_NOT_READY

    def _taskpack_status(self, taskpack_id: str) -> TaskPackReadiness:
        if self._taskpack_detail_probe is not None:
            try:
                item = self._taskpack_detail_probe(taskpack_id)
            except Exception as exc:
                logger.warning(
                    "TaskPack readiness detail probe failed taskpack_id=%s error=%s",
                    taskpack_id,
                    type(exc).__name__,
                )
                item = None
            if isinstance(item, TaskPackReadiness) and item.task_pack_id == taskpack_id:
                self._log_unavailable(taskpack_id, item)
                return item
        try:
            state = self._taskpack_probe(taskpack_id)
            if not isinstance(state, ReadinessState):
                state = ReadinessState.EXECUTOR_NOT_READY
        except Exception:
            state = ReadinessState.EXECUTOR_NOT_READY
        item = TaskPackReadiness(
            task_pack_id=taskpack_id,
            state=state,
            reason_codes=() if state is ReadinessState.READY else (state,),
        )
        self._log_unavailable(taskpack_id, item)
        return item

    def detail(self, task_pack_id: str) -> TaskPackReadiness:
        """Return the full availability report for one TaskPack."""

        if task_pack_id in self._taskpack_ids:
            return self._taskpack_status(task_pack_id)
        item = TaskPackReadiness(
            task_pack_id=task_pack_id,
            state=ReadinessState.TASKPACK_DISABLED,
            reason_codes=(ReadinessState.TASKPACK_DISABLED,),
            detail="TaskPack 未注册或已禁用",
        )
        self._log_unavailable(task_pack_id, item)
        return item

    @staticmethod
    def _log_unavailable(taskpack_id: str, item: TaskPackReadiness) -> None:
        if item.state is ReadinessState.READY:
            return
        unhealthy_tools = tuple(tool.tool_id for tool in item.tool_states if not tool.healthy)
        logger.warning(
            "TaskPack executor unavailable taskpack_id=%s state=%s reason_codes=%s "
            "unhealthy_tools=%s model_capability_ready=%s detail=%s",
            taskpack_id,
            item.state.value,
            tuple(reason.value for reason in item.reason_codes),
            unhealthy_tools,
            item.model_capability_ready,
            item.detail,
        )

    @staticmethod
    def _unique_reasons(
        unavailable: tuple[TaskPackReadiness, ...],
    ) -> tuple[ReadinessState, ...]:
        reasons: list[ReadinessState] = []
        for item in unavailable:
            for reason in item.reason_codes:
                if reason not in reasons:
                    reasons.append(reason)
        return tuple(reasons) or (ReadinessState.EXECUTOR_NOT_READY,)

    def _utc_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("readiness clock must return a timezone-aware value")
        return value.astimezone(timezone.utc)


__all__ = ["RuntimeReadinessService"]
