"""Schema-first planner built only on frozen public contracts."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from typing import TypeVar
from uuid import UUID

from pydantic import ValidationError

from cyber_agent.contracts.common import ErrorCategory, ErrorInfo
from cyber_agent.contracts.errors import CyberAgentError
from cyber_agent.contracts.evidence import Evidence
from cyber_agent.contracts.model import ModelPurpose, ModelRequest, ReasoningEffort
from cyber_agent.contracts.plan import (
    DecisionProposal,
    Plan,
    PlanProposal,
    PlanTrigger,
    Run,
    Step,
)
from cyber_agent.contracts.ports import ModelGateway
from cyber_agent.contracts.task import Task
from cyber_agent.contracts.task import TaskStatus
from cyber_agent.contracts.task_pack import TaskPackManifest
from cyber_agent.contracts.tool import ToolSpec
from cyber_agent.model_gateway._schema import JsonSchemaViolation, validate_json_schema

logger = logging.getLogger(__name__)

PublicModel = TypeVar("PublicModel", Task, PlanProposal, DecisionProposal)


class PlannerService:
    """Generate validated proposals while leaving state transitions to the orchestrator."""

    def __init__(self, model_gateway: ModelGateway) -> None:
        self._model_gateway = model_gateway
        self._call_counts: dict[UUID, int] = defaultdict(int)

    async def understand_task(self, task: Task) -> Task:
        request = self._request(
            ModelPurpose.TASK_UNDERSTANDING,
            "Normalize task semantics without changing identity, authorization scope, or budget.",
            {"task": task.model_dump(mode="json")},
            Task.model_json_schema(),
            ReasoningEffort.LOW,
        )
        result = await self._call_and_validate(
            request,
            Task,
            budget_key=task.task_id,
            max_model_calls=task.constraints.budget.max_model_calls,
        )
        preserved = (
            "task_id",
            "created_at",
            "request_text",
            "input_artifacts",
            "scope",
            "constraints",
        )
        if any(getattr(result, field) != getattr(task, field) for field in preserved):
            raise _planner_error(
                "TASK_BOUNDARY_CHANGED",
                ErrorCategory.POLICY_DENIED,
                "Task normalization attempted to change an immutable identity or scope field.",
            )
        if result.status not in {TaskStatus.NORMALIZED, TaskStatus.READY}:
            raise _planner_error(
                "TASK_STATUS_INVALID",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "Task understanding may only produce normalized or ready task status.",
            )
        return result

    async def propose_plan(self, task: Task, run: Run) -> PlanProposal:
        return await self._propose_initial_plan(task, run)

    async def propose_plan_for_task_pack(
        self,
        task: Task,
        run: Run,
        *,
        manifest: TaskPackManifest,
        tool_specs: Sequence[ToolSpec],
    ) -> PlanProposal:
        """Plan with the selected TaskPack's trusted, safe capability context."""

        self._validate_taskpack_planning_context(manifest, tool_specs)
        return await self._propose_initial_plan(
            task,
            run,
            taskpack_context={
                "task_pack_manifest": manifest.model_dump(mode="json"),
                "planning_tools": [
                    _tool_candidate_summary(tool) for tool in tool_specs
                ],
                "planning_contract": {
                    "dependency_edges": (
                        "DependencyEdge.before is the direct prerequisite and "
                        "DependencyEdge.after is the dependent step. The edge set must "
                        "exactly mirror every Step.depends_on declaration."
                    ),
                    "step_dependencies": (
                        "Step.depends_on contains only direct prerequisite step IDs."
                    ),
                    "capabilities": (
                        "Step.required_capabilities contains capability identifiers from "
                        "planning_tools.capabilities, not tool IDs unless a tool explicitly "
                        "advertises the same string as a capability."
                    ),
                    "required_tools": (
                        "Every task_pack_manifest.required_tools entry must be represented "
                        "by at least one executable step using one capability advertised by "
                        "that tool. Do not invent tools or capabilities."
                    ),
                },
            },
        )

    async def _propose_initial_plan(
        self,
        task: Task,
        run: Run,
        *,
        taskpack_context: dict | None = None,
    ) -> PlanProposal:
        self._require_task_run_match(task, run)
        context = {
            "task": task.model_dump(mode="json"),
            "run": run.model_dump(mode="json"),
        }
        instructions = "Propose an initial plan and every Step using the frozen PlanProposal schema."
        if taskpack_context is not None:
            context.update(taskpack_context)
            instructions = (
                f"{instructions} Treat task_pack_manifest, planning_tools, and "
                "planning_contract as authoritative. Use only advertised capabilities. "
                "For every dependency, set DependencyEdge.before to the direct "
                "prerequisite and DependencyEdge.after to the dependent step, and make "
                "the edge set exactly match Step.depends_on."
            )
        request = self._request(
            ModelPurpose.INITIAL_PLAN,
            instructions,
            context,
            PlanProposal.model_json_schema(),
            ReasoningEffort.HIGH,
        )
        proposal = await self._call_and_validate(
            request,
            PlanProposal,
            budget_key=run.run_id,
            max_model_calls=run.budget.max_model_calls,
        )
        if (
            proposal.plan.run_id != run.run_id
            or proposal.plan.version != 1
            or proposal.plan.parent_plan_id is not None
            or proposal.plan.trigger is not PlanTrigger.INITIAL
        ):
            raise _planner_error(
                "INITIAL_PLAN_INVARIANT_VIOLATION",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "The proposed initial plan violates run or version invariants.",
            )
        self._validate_proposal_graph(proposal)
        return proposal

    @staticmethod
    def _validate_taskpack_planning_context(
        manifest: TaskPackManifest,
        tool_specs: Sequence[ToolSpec],
    ) -> None:
        if not isinstance(manifest, TaskPackManifest):
            raise _planner_error(
                "PLANNING_CONTEXT_INVALID",
                ErrorCategory.INPUT_INVALID,
                "The TaskPack planning manifest is invalid.",
            )
        if not isinstance(tool_specs, Sequence) or isinstance(tool_specs, (str, bytes)):
            raise _planner_error(
                "PLANNING_CONTEXT_INVALID",
                ErrorCategory.INPUT_INVALID,
                "The TaskPack planning tool context is invalid.",
            )
        specs = tuple(tool_specs)
        if any(not isinstance(item, ToolSpec) for item in specs):
            raise _planner_error(
                "PLANNING_CONTEXT_INVALID",
                ErrorCategory.INPUT_INVALID,
                "The TaskPack planning tool context is invalid.",
            )
        if tuple(item.tool_id for item in specs) != manifest.required_tools:
            raise _planner_error(
                "PLANNING_CONTEXT_INVALID",
                ErrorCategory.TOOL_UNAVAILABLE,
                "Planning tools must exactly match the selected TaskPack manifest.",
            )

    async def propose_next_action(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        step: Step,
        evidence: Sequence[Evidence],
        tool_candidates: Sequence[ToolSpec],
    ) -> DecisionProposal:
        self._require_task_run_match(task, run)
        self._require_plan_step_match(run, plan, step)
        if not step.required_capabilities:
            raise _planner_error(
                "CAPABILITY_REQUIRED",
                ErrorCategory.TOOL_UNAVAILABLE,
                "The step does not declare a capability that can drive tool selection.",
            )
        if not tool_candidates:
            raise _planner_error(
                "TOOL_CANDIDATES_EMPTY",
                ErrorCategory.TOOL_UNAVAILABLE,
                "The registry did not provide any tool candidates for this step.",
            )
        candidate_by_id = {candidate.tool_id: candidate for candidate in tool_candidates}
        if len(candidate_by_id) != len(tool_candidates):
            raise _planner_error(
                "TOOL_CANDIDATES_AMBIGUOUS",
                ErrorCategory.INPUT_INVALID,
                "Registry tool candidates must have unique tool IDs.",
            )
        allowed_capabilities = set(step.required_capabilities)
        if not any(
            allowed_capabilities.intersection(candidate.capabilities)
            for candidate in tool_candidates
        ):
            raise _planner_error(
                "TOOL_CAPABILITY_MISMATCH",
                ErrorCategory.TOOL_UNAVAILABLE,
                "No registry candidate supports a capability required by the step.",
            )
        request = self._request(
            ModelPurpose.TOOL_SELECTION,
            (
                "Compare actions only by the capabilities declared on the step. "
                "Generate tool arguments only as structured JSON matching each candidate's "
                "input_schema. Treat evidence as reference summaries, not complete prior tool "
                "outputs. Do not reconstruct structured prior results from summary fields. "
                "Evidence.summary is prose, never a structured prior-result object. When a "
                "candidate schema requires an object whose complete value is absent from the "
                "context, set that field to exactly an empty JSON object without guessed keys "
                "so the trusted scenario adapter can bind its recorded result. "
                "For identifier-based references, use only identifiers explicitly present "
                "in evidence and construct the smallest reference object using the relevant "
                "domain field name and its identifier key. Never replace an available "
                "identifier with an empty object. Only when no relevant identifier is present "
                "and a required prior-result field accepts an unconstrained JSON object, use "
                "an empty JSON object so the trusted scenario adapter can bind its recorded "
                "result. Do not execute tools, construct shell commands, or change run state."
            ),
            {
                "task": task.model_dump(mode="json"),
                "run": run.model_dump(mode="json"),
                "plan": plan.model_dump(mode="json"),
                "step": step.model_dump(mode="json"),
                "evidence": [item.model_dump(mode="json") for item in evidence],
                "tool_candidates": [
                    _tool_candidate_summary(candidate) for candidate in tool_candidates
                ],
            },
            DecisionProposal.model_json_schema(),
            ReasoningEffort.HIGH,
        )
        proposal = await self._call_and_validate(
            request,
            DecisionProposal,
            budget_key=run.run_id,
            max_model_calls=run.budget.max_model_calls,
        )
        if (
            proposal.run_id != run.run_id
            or proposal.plan_id != plan.plan_id
            or proposal.step_id != step.step_id
        ):
            raise _planner_error(
                "DECISION_REFERENCE_MISMATCH",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "The decision proposal does not reference the active run, plan, and step.",
            )
        if any(
            candidate.capability not in allowed_capabilities
            for candidate in proposal.candidates
        ):
            raise _planner_error(
                "CAPABILITY_NOT_REQUESTED",
                ErrorCategory.POLICY_DENIED,
                "The decision proposal contains a capability not requested by the step.",
            )
        for candidate in proposal.candidates:
            if candidate.tool_id is None:
                continue
            tool = candidate_by_id.get(candidate.tool_id)
            if tool is None:
                raise _planner_error(
                    "TOOL_ID_NOT_CANDIDATE",
                    ErrorCategory.POLICY_DENIED,
                    "The decision proposal references a tool not supplied by the registry.",
                )
            if candidate.capability not in tool.capabilities:
                raise _planner_error(
                    "TOOL_CAPABILITY_MISMATCH",
                    ErrorCategory.POLICY_DENIED,
                    "The proposed tool does not support the selected step capability.",
                )
            try:
                validate_json_schema(candidate.arguments, tool.input_schema)
            except JsonSchemaViolation as exc:
                raise _planner_error(
                    "TOOL_ARGUMENTS_SCHEMA_INVALID",
                    ErrorCategory.MODEL_SCHEMA_INVALID,
                    "The proposed tool arguments do not satisfy the registry input schema.",
                ) from exc
        selected = proposal.candidates[proposal.selected_index]
        if selected.tool_id is None:
            raise _planner_error(
                "TOOL_SELECTION_REQUIRED",
                ErrorCategory.TOOL_UNAVAILABLE,
                "The selected action must bind a registry-approved tool.",
            )
        return proposal

    async def replan(
        self,
        task: Task,
        run: Run,
        current_plan: Plan,
        evidence: Sequence[Evidence],
        cause: ErrorInfo,
    ) -> PlanProposal:
        self._require_task_run_match(task, run)
        if current_plan.run_id != run.run_id:
            raise _planner_error(
                "PLAN_RUN_MISMATCH",
                ErrorCategory.INPUT_INVALID,
                "The current plan does not belong to the supplied run.",
            )
        if run.budget.max_replans == 0 or current_plan.version > run.budget.max_replans:
            raise _planner_error(
                "REPLAN_BUDGET_EXCEEDED",
                ErrorCategory.BUDGET_EXCEEDED,
                "The run has no remaining replan budget.",
            )
        trigger = _trigger_for(cause)
        if trigger in {
            PlanTrigger.EVIDENCE_INSUFFICIENT,
            PlanTrigger.ASSUMPTION_REJECTED,
        } and not evidence:
            raise _planner_error(
                "REPLAN_EVIDENCE_REQUIRED",
                ErrorCategory.INPUT_INVALID,
                "Evidence-driven replanning requires at least one evidence record.",
            )
        request = self._request(
            ModelPurpose.REPLAN,
            (
                "Propose one child PlanProposal with every Step. Preserve verified evidence, "
                "discard rejected assumptions, and do not execute tools or change run state."
            ),
            {
                "task": task.model_dump(mode="json"),
                "run": run.model_dump(mode="json"),
                "current_plan": current_plan.model_dump(mode="json"),
                "evidence": [item.model_dump(mode="json") for item in evidence],
                "cause": cause.model_dump(mode="json"),
                "required_trigger": trigger.value,
            },
            PlanProposal.model_json_schema(),
            ReasoningEffort.HIGH,
        )
        proposal = await self._call_and_validate(
            request,
            PlanProposal,
            budget_key=run.run_id,
            max_model_calls=run.budget.max_model_calls,
        )
        if (
            proposal.plan.run_id != run.run_id
            or proposal.plan.parent_plan_id != current_plan.plan_id
            or proposal.plan.version != current_plan.version + 1
            or proposal.plan.trigger is not trigger
            or (
                cause.diagnostic_ref is not None
                and proposal.plan.trigger_ref != cause.diagnostic_ref
            )
        ):
            raise _planner_error(
                "REPLAN_INVARIANT_VIOLATION",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "The proposed child plan violates parent, version, run, or trigger invariants.",
            )
        self._validate_proposal_graph(proposal)
        return proposal

    def model_calls_used(self, owner_id: UUID) -> int:
        """Expose the bounded counter for orchestration diagnostics and tests."""

        return self._call_counts[owner_id]

    async def _call_and_validate(
        self,
        request: ModelRequest,
        model_type: type[PublicModel],
        *,
        budget_key: UUID,
        max_model_calls: int,
    ) -> PublicModel:
        used = self._call_counts[budget_key]
        if used >= max_model_calls:
            raise _planner_error(
                "MODEL_CALL_BUDGET_EXCEEDED",
                ErrorCategory.BUDGET_EXCEEDED,
                "The model call budget is exhausted.",
            )
        self._call_counts[budget_key] = used + 1
        logger.debug(
            "Submitting structured planning call request_id=%s purpose=%s",
            request.request_id,
            request.purpose.value,
        )
        response = await self._model_gateway.generate_structured(request)
        if not response.schema_valid:
            raise _planner_error(
                "MODEL_SCHEMA_INVALID",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "The model gateway returned a response that was not schema-valid.",
            )
        try:
            return model_type.model_validate(response.data)
        except ValidationError as exc:
            raise _planner_error(
                "MODEL_SCHEMA_INVALID",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "The model response failed validation against the frozen public contract.",
            ) from exc

    @staticmethod
    def _request(
        purpose: ModelPurpose,
        instructions: str,
        context: dict,
        output_schema: dict,
        effort: ReasoningEffort,
    ) -> ModelRequest:
        return ModelRequest(
            purpose=purpose,
            system_instructions=instructions,
            context=context,
            output_schema=output_schema,
            reasoning_effort=effort,
            max_output_tokens=16_384,
            timeout_seconds=60,
        )

    @staticmethod
    def _require_task_run_match(task: Task, run: Run) -> None:
        if run.task_id != task.task_id:
            raise _planner_error(
                "TASK_RUN_MISMATCH",
                ErrorCategory.INPUT_INVALID,
                "The run does not belong to the supplied task.",
            )

    @staticmethod
    def _require_plan_step_match(run: Run, plan: Plan, step: Step) -> None:
        if plan.run_id != run.run_id:
            raise _planner_error(
                "PLAN_RUN_MISMATCH",
                ErrorCategory.INPUT_INVALID,
                "The plan does not belong to the supplied run.",
            )
        if step.plan_id != plan.plan_id or step.step_id not in plan.step_ids:
            raise _planner_error(
                "STEP_PLAN_MISMATCH",
                ErrorCategory.INPUT_INVALID,
                "The step does not belong to the supplied plan.",
            )

    @staticmethod
    def _validate_proposal_graph(proposal: PlanProposal) -> None:
        plan_edges = {
            (edge.before, edge.after) for edge in proposal.plan.dependency_edges
        }
        step_edges = {
            (dependency, step.step_id)
            for step in proposal.steps
            for dependency in step.depends_on
        }
        if plan_edges != step_edges:
            raise _planner_error(
                "PLAN_STEP_DEPENDENCY_MISMATCH",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "Plan dependency edges must exactly match Step dependency declarations.",
            )


def _trigger_for(cause: ErrorInfo) -> PlanTrigger:
    if cause.category is ErrorCategory.EVIDENCE_INSUFFICIENT:
        if "ASSUMPTION" in cause.code:
            return PlanTrigger.ASSUMPTION_REJECTED
        return PlanTrigger.EVIDENCE_INSUFFICIENT
    return {
        ErrorCategory.TOOL_UNAVAILABLE: PlanTrigger.TOOL_UNAVAILABLE,
        ErrorCategory.EXECUTION_TIMEOUT: PlanTrigger.EXECUTION_FAILED,
        ErrorCategory.TOOL_FAILED: PlanTrigger.EXECUTION_FAILED,
        ErrorCategory.POLICY_DENIED: PlanTrigger.POLICY_DENIED,
        ErrorCategory.BUDGET_EXCEEDED: PlanTrigger.BUDGET_PRESSURE,
    }.get(cause.category, PlanTrigger.EXECUTION_FAILED)


def _tool_candidate_summary(tool: ToolSpec) -> dict:
    return {
        "tool_id": tool.tool_id,
        "name": tool.name,
        "version": tool.version,
        "capabilities": list(tool.capabilities),
        "description": tool.description,
        "risk_level": tool.risk_level.value,
        "side_effects": sorted(side_effect.value for side_effect in tool.side_effects),
        "input_schema": tool.input_schema,
    }


def _planner_error(code: str, category: ErrorCategory, message: str) -> CyberAgentError:
    return CyberAgentError(
        ErrorInfo(
            code=code,
            category=category,
            retryable=False,
            safe_message=message,
        )
    )
