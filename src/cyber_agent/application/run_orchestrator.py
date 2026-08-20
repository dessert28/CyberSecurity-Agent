"""Minimal, scenario-neutral orchestration over the existing trusted ports."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from cyber_agent.audit_store import build_audit_record
from cyber_agent.contracts.audit import AuditEventType, AuditRecord
from cyber_agent.contracts.common import (
    ActorRef,
    ActorType,
    EntityRef,
    EnvironmentProfile,
    ErrorCategory,
    ErrorInfo,
    ModelProfileRef,
)
from cyber_agent.contracts.errors import CyberAgentError
from cyber_agent.contracts.evidence import (
    Evidence,
    EvidenceKind,
    VerificationMethod,
    VerificationOutcome,
    VerificationVerdict,
)
from cyber_agent.contracts.plan import (
    CandidateAction,
    DecisionProposal,
    Plan,
    PlanProposal,
    PlanStatus,
    PlanTrigger,
    Run,
    RunStatus,
    Step,
    StepStatus,
)
from cyber_agent.contracts.ports import (
    AuditStorePort,
    ExecutorPort,
    PlannerPort,
    VerifierPort,
)
from cyber_agent.contracts.task import Task, TaskStatus
from cyber_agent.contracts.task_pack import ScenarioObservation, TaskPack
from cyber_agent.contracts.tool import (
    PolicyDecision,
    ToolInvocation,
    ToolInvocationStatus,
    ToolRef,
    ToolResult,
    ToolSpec,
)
from cyber_agent.tools import BudgetUsage, PolicyGate, ToolRegistry
from cyber_agent.verification import VerifierRegistry

_SYSTEM_ACTOR = ActorRef(actor_type=ActorType.SYSTEM, actor_id="run-orchestrator")
_PLANNER_ACTOR = ActorRef(actor_type=ActorType.MODEL, actor_id="planner")


@dataclass(frozen=True, slots=True)
class RunOrchestratorOutcome:
    task_pack_id: str
    task: Task
    run: Run
    plan: Plan
    steps: tuple[Step, ...]
    tool_invocations: tuple[ToolInvocation, ...]
    policy_decisions: tuple[PolicyDecision, ...]
    results: tuple[ToolResult, ...]
    evidence: tuple[Evidence, ...]
    verdicts: tuple[VerificationVerdict, ...]
    audit_records: tuple[AuditRecord, ...]

    @property
    def task_verdict(self) -> VerificationVerdict:
        return self.verdicts[-1]


@dataclass(frozen=True, slots=True)
class RunInterruptedOutcome:
    """Partial, audited result returned when orchestration cannot continue."""

    task_pack_id: str
    task: Task
    run: Run
    plan: Plan | None
    steps: tuple[Step, ...]
    tool_invocations: tuple[ToolInvocation, ...]
    policy_decisions: tuple[PolicyDecision, ...]
    results: tuple[ToolResult, ...]
    evidence: tuple[Evidence, ...]
    verdicts: tuple[VerificationVerdict, ...]
    audit_records: tuple[AuditRecord, ...]
    error: ErrorInfo


RunOrchestratorResult = RunOrchestratorOutcome | RunInterruptedOutcome


class _AuditTrail:
    def __init__(
        self,
        *,
        store: AuditStorePort,
        run_id: UUID,
        clock: Callable[[], datetime],
    ) -> None:
        self._store = store
        self._run_id = run_id
        self._clock = clock
        self._sequence = 0
        self._previous: AuditRecord | None = None

    async def emit(
        self,
        event_type: AuditEventType,
        outcome: str,
        *,
        actor: ActorRef = _SYSTEM_ACTOR,
        reason_codes: Sequence[str] = (),
        subjects: Sequence[EntityRef] = (),
        inputs: Sequence[EntityRef] = (),
        policy_ref: UUID | None = None,
    ) -> AuditRecord:
        self._sequence += 1
        record = build_audit_record(
            run_id=self._run_id,
            sequence=self._sequence,
            timestamp=self._clock(),
            actor=actor,
            event_type=event_type,
            outcome=outcome[:2000],
            reason_codes=list(reason_codes),
            correlation_id=self._run_id,
            subject_refs=list(subjects),
            input_refs=list(inputs),
            policy_ref=policy_ref,
            causation_id=self._previous.event_id if self._previous is not None else None,
            previous_hash=self._previous.event_hash if self._previous is not None else None,
        )
        await self._store.append(record)
        self._previous = record
        return record


class RunOrchestrator:
    """Advance one ready task through a single-attempt generic execution loop."""

    def __init__(
        self,
        *,
        planner: PlannerPort,
        registry: ToolRegistry,
        policy_gate: PolicyGate,
        executor: ExecutorPort,
        verifier_registry: VerifierRegistry,
        audit_store: AuditStorePort,
        model_profile: ModelProfileRef,
        environment_profile: EnvironmentProfile,
        run_id_factory: Callable[[], UUID] = uuid4,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._planner = planner
        self._registry = registry
        self._policy_gate = policy_gate
        self._executor = executor
        self._verifier_registry = verifier_registry
        self._audit_store = audit_store
        self._model_profile = model_profile.model_copy(deep=True)
        self._environment_profile = environment_profile.model_copy(deep=True)
        self._run_id_factory = run_id_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic

    async def run(self, task: Task, task_pack: TaskPack) -> RunOrchestratorResult:
        if task.status is not TaskStatus.READY:
            raise _orchestrator_error(
                "TASK_NOT_READY",
                ErrorCategory.INPUT_INVALID,
                "The generic orchestrator accepts only ready tasks.",
            )
        manifest = task_pack.manifest
        policy_version = getattr(self._policy_gate, "POLICY_VERSION", None)
        if manifest.security_policy != policy_version:
            raise _orchestrator_error(
                "SECURITY_POLICY_MISMATCH",
                ErrorCategory.POLICY_DENIED,
                "The task pack requires a different security policy version.",
            )
        started_monotonic = self._monotonic()
        run = Run(
            run_id=self._run_id_factory(),
            task_id=task.task_id,
            created_at=self._clock(),
            status=RunStatus.PLANNING,
            budget=task.constraints.budget.model_copy(deep=True),
            model_profile=self._model_profile.model_copy(deep=True),
            environment_profile=self._environment_profile.model_copy(deep=True),
        )
        audit = _AuditTrail(store=self._audit_store, run_id=run.run_id, clock=self._clock)
        await audit.emit(
            AuditEventType.INPUT_RECEIVED,
            "A ready task and explicit task pack were accepted.",
            subjects=[_entity("task", task.task_id)],
        )
        await audit.emit(
            AuditEventType.RUN_CREATED,
            "A generic run was created from the ready task.",
            subjects=[_entity("run", run.run_id), _entity("task", task.task_id)],
        )

        plan: Plan | None = None
        steps: list[Step] = []
        invocations: list[ToolInvocation] = []
        decisions: list[PolicyDecision] = []
        results: list[ToolResult] = []
        evidence: list[Evidence] = []
        step_verdicts: list[VerificationVerdict] = []
        runtime_phase = "verifier_registry"
        opened = False
        verifier: VerifierPort | None = None
        try:
            verifier = self._verifier_registry.resolve(manifest.verifier)
            runtime_phase = "adapter_validate_task"
            task_pack.adapter.validate_task(task, manifest)
            runtime_phase = "adapter_open_run"
            task_pack.adapter.open_run(task, run, manifest)
            opened = True
            runtime_phase = "planner_plan"
            contextual_plan = getattr(
                self._planner,
                "propose_plan_for_task_pack",
                None,
            )
            if callable(contextual_plan):
                planning_tool_specs = tuple(
                    self._registry.plugin(tool_id).get_spec().model_copy(deep=True)
                    for tool_id in manifest.required_tools
                )
                proposal = await contextual_plan(
                    task,
                    run,
                    manifest=manifest.model_copy(deep=True),
                    tool_specs=planning_tool_specs,
                )
            else:
                proposal = await self._planner.propose_plan(task, run)
            await audit.emit(
                AuditEventType.PLAN_PROPOSED,
                "Planner returned a complete PlanProposal.",
                actor=_PLANNER_ACTOR,
                subjects=[_entity("plan", proposal.plan.plan_id)],
                inputs=[_entity("run", run.run_id)],
            )
            runtime_phase = "validate_plan_proposal"
            self._validate_plan_proposal(run, proposal)
            runtime_phase = "adapter_validate_plan"
            task_pack.adapter.validate_plan(task, run, proposal, manifest)

            plan = proposal.plan.model_copy(update={"status": PlanStatus.ACTIVE})
            steps[:] = [item.model_copy(deep=True) for item in proposal.steps]
            run = run.model_copy(
                update={"status": RunStatus.RUNNING, "active_plan_id": plan.plan_id}
            )
            task = task.model_copy(update={"status": TaskStatus.RUNNING})
            await audit.emit(
                AuditEventType.PLAN_ACCEPTED,
                "The plan passed generic and scenario-specific validation.",
                subjects=[_entity("plan", plan.plan_id)],
            )

            completed_step_ids: set[UUID] = set()
            tool_calls = 0

            for index in self._execution_order(steps):
                step = steps[index]
                if not set(step.depends_on).issubset(completed_step_ids):
                    raise _orchestrator_error(
                        "STEP_DEPENDENCY_NOT_SATISFIED",
                        ErrorCategory.SYSTEM_ERROR,
                        "A step became runnable before its dependencies completed.",
                    )
                step = step.model_copy(update={"status": StepStatus.RUNNING})
                steps[index] = step
                await audit.emit(
                    AuditEventType.STEP_STATE_CHANGED,
                    "Step entered running state.",
                    subjects=[_entity("step", step.step_id)],
                )

                runtime_phase = "tool_candidates"
                candidates = self._tool_candidates(step, manifest.required_tools)
                if not candidates:
                    raise _orchestrator_error(
                        "TOOL_CANDIDATES_EMPTY",
                        ErrorCategory.TOOL_UNAVAILABLE,
                        "No healthy task-pack tool satisfies every required capability.",
                    )
                runtime_phase = "planner_action"
                action_proposal = await self._planner.propose_next_action(
                    task,
                    run,
                    plan,
                    step,
                    tuple(evidence),
                    candidates,
                )
                runtime_phase = "validate_action_proposal"
                selected, spec = self._validate_action_proposal(
                    run,
                    plan,
                    step,
                    action_proposal,
                    candidates,
                )
                runtime_phase = "adapter_validate_action"
                task_pack.adapter.validate_action(
                    task,
                    run,
                    plan,
                    step,
                    selected,
                    spec,
                )
                await audit.emit(
                    AuditEventType.TOOL_CANDIDATES_COMPARED,
                    "Planner selected one task-pack and registry approved tool.",
                    actor=_PLANNER_ACTOR,
                    subjects=[_entity("step", step.step_id)],
                )

                elapsed = max(0.0, self._monotonic() - started_monotonic)
                invocation = ToolInvocation(
                    run_id=run.run_id,
                    plan_id=plan.plan_id,
                    step_id=step.step_id,
                    attempt=1,
                    tool_ref=ToolRef(tool_id=spec.tool_id, version=spec.version),
                    validated_arguments=selected.arguments,
                    deadline=self._invocation_deadline(run, elapsed),
                    status=ToolInvocationStatus.PROPOSED,
                )
                runtime_phase = "policy_gate"
                decision = self._policy_gate.evaluate(
                    invocation,
                    spec,
                    task.scope,
                    run.budget,
                    BudgetUsage(
                        elapsed_seconds=elapsed,
                        tool_calls=tool_calls,
                        attempts_for_step=0,
                    ),
                )
                decisions.append(decision)
                bound_invocation = _materialize_policy_decision(invocation, decision)
                await audit.emit(
                    AuditEventType.POLICY_ALLOWED
                    if decision.allowed
                    else AuditEventType.POLICY_DENIED,
                    "Policy allowed the proposed invocation."
                    if decision.allowed
                    else "Policy denied the proposed invocation before execution.",
                    reason_codes=decision.reason_codes,
                    subjects=[
                        _entity("tool_invocation", invocation.invocation_id),
                        _entity("policy_decision", decision.decision_id),
                    ],
                    policy_ref=decision.decision_id,
                )

                parsed_result: ToolResult | None = None
                terminal_invocation = bound_invocation
                invocations.append(bound_invocation)
                if decision.allowed:
                    plugin = self._registry.plugin(spec.tool_id)
                    runtime_phase = "plugin_prepare"
                    request = plugin.prepare(bound_invocation)
                    terminal_invocation = bound_invocation.model_copy(
                        update={"status": ToolInvocationStatus.RUNNING}
                    )
                    await audit.emit(
                        AuditEventType.EXECUTION_STARTED,
                        "Approved structured request entered the executor.",
                        actor=ActorRef(actor_type=ActorType.TOOL, actor_id=spec.tool_id),
                        subjects=[_entity("tool_invocation", invocation.invocation_id)],
                        policy_ref=decision.decision_id,
                    )
                    runtime_phase = "executor"
                    raw_result = await self._executor.execute(request)
                    tool_calls += 1
                    runtime_phase = "plugin_parse"
                    parsed_result = plugin.parse(raw_result)
                    terminal_invocation = terminal_invocation.model_copy(
                        update={"status": ToolInvocationStatus.COMPLETED}
                    )
                    await audit.emit(
                        AuditEventType.EXECUTION_FINISHED,
                        f"Executor returned tool status {parsed_result.status.value}.",
                        actor=ActorRef(actor_type=ActorType.TOOL, actor_id=spec.tool_id),
                        reason_codes=(
                            [parsed_result.error.code]
                            if parsed_result.error is not None
                            else []
                        ),
                        subjects=[_entity("tool_result", parsed_result.result_id)],
                        policy_ref=decision.decision_id,
                    )

                invocations[-1] = terminal_invocation
                if parsed_result is not None:
                    runtime_phase = "result_policy_review"
                    review_result = getattr(self._policy_gate, "review_result", None)
                    result_decisions = (
                        review_result(
                            bound_invocation,
                            parsed_result,
                            task.scope,
                        )
                        if callable(review_result)
                        else ()
                    )
                    denied_result_decision: PolicyDecision | None = None
                    for result_decision in result_decisions:
                        decisions.append(result_decision)
                        await audit.emit(
                            AuditEventType.POLICY_ALLOWED
                            if result_decision.allowed
                            else AuditEventType.POLICY_DENIED,
                            "Policy allowed a structured follow-up target without executing it."
                            if result_decision.allowed
                            else "Policy denied a structured follow-up target without executing it.",
                            reason_codes=result_decision.reason_codes,
                            subjects=[
                                _entity("tool_result", parsed_result.result_id),
                                _entity(
                                    "policy_decision",
                                    result_decision.decision_id,
                                ),
                            ],
                            policy_ref=result_decision.decision_id,
                        )
                        if not result_decision.allowed:
                            denied_result_decision = result_decision
                            break
                    if denied_result_decision is not None:
                        results.append(parsed_result)
                        evidence.append(
                            _policy_review_evidence(
                                run=run,
                                result=parsed_result,
                                decision=denied_result_decision,
                                observed_at=self._clock(),
                            )
                        )
                        code = (
                            denied_result_decision.reason_codes[0]
                            if denied_result_decision.reason_codes
                            else "RESULT_POLICY_DENIED"
                        )
                        raise _orchestrator_error(
                            code,
                            ErrorCategory.POLICY_DENIED,
                            "Policy denied a follow-up target observed in the tool result.",
                        )

                runtime_phase = "adapter_build_observation"
                observation = task_pack.adapter.build_observation(
                    task,
                    run,
                    plan,
                    step,
                    bound_invocation,
                    decision,
                    parsed_result,
                    self._clock(),
                )
                runtime_phase = "validate_observation"
                self._validate_observation(observation, bound_invocation)
                results.append(observation.result)
                evidence.extend(observation.evidence)

                runtime_phase = "verifier_step"
                verdict = await verifier.verify_step(
                    task,
                    run,
                    plan,
                    step,
                    [observation.result],
                    observation.evidence,
                )
                step_verdicts.append(verdict)
                await audit.emit(
                    AuditEventType.VERIFICATION_COMPLETED,
                    verdict.summary,
                    reason_codes=verdict.reason_codes,
                    subjects=[_entity("step", step.step_id)],
                    inputs=[
                        _entity("tool_result", observation.result.result_id),
                        *[
                            _entity("evidence", item.evidence_id)
                            for item in observation.evidence
                        ],
                    ],
                    policy_ref=decision.decision_id,
                )
                step_status = _step_status(verdict.outcome)
                steps[index] = step.model_copy(update={"status": step_status})
                await audit.emit(
                    AuditEventType.STEP_STATE_CHANGED,
                    f"Step entered terminal state {step_status.value}.",
                    reason_codes=verdict.reason_codes,
                    subjects=[_entity("step", step.step_id)],
                )
                if verdict.outcome is VerificationOutcome.VERIFIED:
                    completed_step_ids.add(step.step_id)
                    continue
                break

            runtime_phase = "verifier_task"
            task_verdict = await verifier.verify_task(
                task,
                run,
                plan,
                tuple(evidence),
            )
            await audit.emit(
                AuditEventType.VERIFICATION_COMPLETED,
                task_verdict.summary,
                reason_codes=task_verdict.reason_codes,
                subjects=[_entity("task", task.task_id)],
                inputs=[_entity("evidence", item.evidence_id) for item in evidence],
            )
            run_status, task_status = _terminal_statuses(task_verdict.outcome)
            run = run.model_copy(
                update={
                    "status": run_status,
                    "termination_reason": _termination_reason(task_verdict),
                }
            )
            task = task.model_copy(update={"status": task_status})
            plan = plan.model_copy(
                update={
                    "status": PlanStatus.COMPLETED
                    if len(completed_step_ids) == len(steps)
                    else PlanStatus.FAILED
                }
            )
            await audit.emit(
                AuditEventType.RUN_FINISHED,
                f"Run finished with task outcome {task_verdict.outcome.value}.",
                reason_codes=task_verdict.reason_codes,
                subjects=[_entity("run", run.run_id), _entity("task", task.task_id)],
            )
            audit_records = tuple(await self._audit_store.list_by_run(run.run_id))
            return RunOrchestratorOutcome(
                task_pack_id=manifest.task_pack_id,
                task=task,
                run=run,
                plan=plan,
                steps=tuple(steps),
                tool_invocations=tuple(invocations),
                policy_decisions=tuple(decisions),
                results=tuple(results),
                evidence=tuple(evidence),
                verdicts=(*step_verdicts, task_verdict),
                audit_records=audit_records,
            )
        except Exception as exc:
            if isinstance(exc, CyberAgentError) and runtime_phase in {
                "validate_plan_proposal",
                "tool_candidates",
                "validate_action_proposal",
                "validate_observation",
            }:
                await audit.emit(
                    AuditEventType.RUN_INTERRUPTED,
                    exc.error.safe_message,
                    reason_codes=[exc.error.code],
                    subjects=[_entity("run", run.run_id), _entity("task", task.task_id)],
                )
                raise
            error = _runtime_interruption_error(runtime_phase, exc)
            return await self._interrupted_outcome(
                task_pack_id=manifest.task_pack_id,
                task=task,
                run=run,
                plan=plan,
                steps=steps,
                invocations=invocations,
                decisions=decisions,
                results=results,
                evidence=evidence,
                verdicts=step_verdicts,
                audit=audit,
                error=error,
            )
        finally:
            try:
                if verifier is not None:
                    clear_run = getattr(verifier, "clear_run", None)
                    if callable(clear_run):
                        clear_run(run.run_id)
            finally:
                if opened:
                    task_pack.adapter.close_run(run.run_id)

    async def _interrupted_outcome(
        self,
        *,
        task_pack_id: str,
        task: Task,
        run: Run,
        plan: Plan | None,
        steps: Sequence[Step],
        invocations: Sequence[ToolInvocation],
        decisions: Sequence[PolicyDecision],
        results: Sequence[ToolResult],
        evidence: Sequence[Evidence],
        verdicts: Sequence[VerificationVerdict],
        audit: _AuditTrail,
        error: ErrorInfo,
    ) -> RunInterruptedOutcome:
        failed_run = run.model_copy(
            update={"status": RunStatus.FAILED, "termination_reason": error}
        )
        failed_task = task.model_copy(update={"status": TaskStatus.FAILED})
        failed_plan = (
            plan.model_copy(update={"status": PlanStatus.FAILED})
            if plan is not None
            else None
        )
        failed_steps = tuple(
            item.model_copy(update={"status": StepStatus.FAILED})
            if item.status in {StepStatus.RUNNING, StepStatus.VERIFYING}
            else item.model_copy(deep=True)
            for item in steps
        )
        await audit.emit(
            AuditEventType.RUN_INTERRUPTED,
            error.safe_message,
            reason_codes=[error.code],
            subjects=[
                _entity("run", failed_run.run_id),
                _entity("task", failed_task.task_id),
            ],
            inputs=[_entity("evidence", item.evidence_id) for item in evidence],
        )
        audit_records = tuple(await self._audit_store.list_by_run(failed_run.run_id))
        return RunInterruptedOutcome(
            task_pack_id=task_pack_id,
            task=failed_task,
            run=failed_run,
            plan=failed_plan,
            steps=failed_steps,
            tool_invocations=tuple(invocations),
            policy_decisions=tuple(decisions),
            results=tuple(results),
            evidence=tuple(evidence),
            verdicts=tuple(verdicts),
            audit_records=audit_records,
            error=error,
        )

    def _tool_candidates(
        self,
        step: Step,
        required_tool_ids: Sequence[str],
    ) -> tuple[ToolSpec, ...]:
        if not step.required_capabilities:
            raise _orchestrator_error(
                "CAPABILITY_REQUIRED",
                ErrorCategory.TOOL_UNAVAILABLE,
                "Every executable step must declare at least one capability.",
            )
        required_capabilities = set(step.required_capabilities)
        allowed_tool_ids = set(required_tool_ids)
        return tuple(
            spec
            for spec in self._registry.candidates(step.required_capabilities[0])
            if spec.tool_id in allowed_tool_ids
            and required_capabilities.issubset(set(spec.capabilities))
        )

    @staticmethod
    def _validate_plan_proposal(run: Run, proposal: PlanProposal) -> None:
        if (
            proposal.plan.run_id != run.run_id
            or proposal.plan.version != 1
            or proposal.plan.parent_plan_id is not None
            or proposal.plan.trigger is not PlanTrigger.INITIAL
            or proposal.plan.status is not PlanStatus.DRAFT
        ):
            raise _orchestrator_error(
                "INITIAL_PLAN_INVALID",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "The proposed initial plan violates generic run invariants.",
            )
        if len(proposal.steps) > run.budget.max_steps:
            raise _orchestrator_error(
                "STEP_BUDGET_EXCEEDED",
                ErrorCategory.BUDGET_EXCEEDED,
                "The proposed plan exceeds the task step budget.",
            )
        ordinals = [item.ordinal for item in proposal.steps]
        if len(ordinals) != len(set(ordinals)):
            raise _orchestrator_error(
                "STEP_ORDINAL_DUPLICATE",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "Planned step ordinals must be unique.",
            )
        if any(not item.required_capabilities for item in proposal.steps):
            raise _orchestrator_error(
                "CAPABILITY_REQUIRED",
                ErrorCategory.TOOL_UNAVAILABLE,
                "Every executable step must declare at least one capability.",
            )

    @staticmethod
    def _validate_action_proposal(
        run: Run,
        plan: Plan,
        step: Step,
        proposal: DecisionProposal,
        candidates: Sequence[ToolSpec],
    ) -> tuple[CandidateAction, ToolSpec]:
        if (
            proposal.run_id != run.run_id
            or proposal.plan_id != plan.plan_id
            or proposal.step_id != step.step_id
        ):
            raise _orchestrator_error(
                "DECISION_REFERENCE_MISMATCH",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "The decision proposal does not reference the active step.",
            )
        candidate_by_id = {item.tool_id: item for item in candidates}
        required = set(step.required_capabilities)
        for action in proposal.candidates:
            if action.capability not in required:
                raise _orchestrator_error(
                    "CAPABILITY_NOT_REQUESTED",
                    ErrorCategory.POLICY_DENIED,
                    "A proposed action references an undeclared capability.",
                )
            if action.tool_id is not None and action.tool_id not in candidate_by_id:
                raise _orchestrator_error(
                    "TOOL_ID_NOT_CANDIDATE",
                    ErrorCategory.POLICY_DENIED,
                    "A proposed action references a non-candidate tool.",
                )
        selected = proposal.candidates[proposal.selected_index]
        if selected.tool_id is None:
            raise _orchestrator_error(
                "TOOL_SELECTION_REQUIRED",
                ErrorCategory.TOOL_UNAVAILABLE,
                "The selected action must bind a healthy registry tool.",
            )
        spec = candidate_by_id[selected.tool_id]
        if selected.capability not in spec.capabilities:
            raise _orchestrator_error(
                "TOOL_CAPABILITY_MISMATCH",
                ErrorCategory.POLICY_DENIED,
                "The selected tool does not implement the proposed capability.",
            )
        return selected, spec

    @staticmethod
    def _execution_order(steps: Sequence[Step]) -> list[int]:
        index_by_id = {item.step_id: index for index, item in enumerate(steps)}
        remaining = set(index_by_id)
        completed: set[UUID] = set()
        ordered: list[int] = []
        while remaining:
            ready = sorted(
                (
                    step_id
                    for step_id in remaining
                    if set(steps[index_by_id[step_id]].depends_on).issubset(completed)
                ),
                key=lambda step_id: (
                    steps[index_by_id[step_id]].ordinal,
                    str(step_id),
                ),
            )
            if not ready:
                raise _orchestrator_error(
                    "PLAN_DEPENDENCY_CYCLE",
                    ErrorCategory.MODEL_SCHEMA_INVALID,
                    "The plan does not have a runnable dependency order.",
                )
            for step_id in ready:
                ordered.append(index_by_id[step_id])
                remaining.remove(step_id)
                completed.add(step_id)
        return ordered

    @staticmethod
    def _validate_observation(
        observation: ScenarioObservation,
        invocation: ToolInvocation,
    ) -> None:
        result = observation.result
        if (
            result.run_id != invocation.run_id
            or result.plan_id != invocation.plan_id
            or result.step_id != invocation.step_id
            or result.attempt != invocation.attempt
            or result.tool_ref != invocation.tool_ref
            or result.policy_decision_ref != invocation.policy_decision_ref
        ):
            raise _orchestrator_error(
                "SCENARIO_OBSERVATION_REFERENCE_MISMATCH",
                ErrorCategory.SYSTEM_ERROR,
                "Scenario observation references do not match the invocation.",
            )
        if not any(
            item.source_ref.entity_type == "tool_result"
            and item.source_ref.entity_id == result.result_id
            for item in observation.evidence
        ):
            raise _orchestrator_error(
                "SCENARIO_EVIDENCE_RESULT_MISSING",
                ErrorCategory.EVIDENCE_INSUFFICIENT,
                "Scenario evidence does not reference its tool result.",
            )

    def _invocation_deadline(self, run: Run, elapsed_seconds: float) -> datetime:
        remaining = max(0.001, run.budget.max_duration_seconds - elapsed_seconds)
        timeout = min(float(run.budget.max_tool_timeout_seconds), remaining)
        return self._clock() + timedelta(seconds=timeout)


def _materialize_policy_decision(
    invocation: ToolInvocation,
    decision: PolicyDecision,
) -> ToolInvocation:
    if (
        invocation.status is not ToolInvocationStatus.PROPOSED
        or invocation.policy_decision_ref is not None
    ):
        raise _orchestrator_error(
            "INVOCATION_NOT_PROPOSED",
            ErrorCategory.INPUT_INVALID,
            "Only an unbound proposed invocation can receive a policy decision.",
        )
    return invocation.model_copy(
        update={
            "status": ToolInvocationStatus.APPROVED
            if decision.allowed
            else ToolInvocationStatus.DENIED,
            "policy_decision_ref": decision.decision_id,
            "validated_arguments": decision.constrained_arguments
            if decision.allowed
            else invocation.validated_arguments,
        }
    )


def _step_status(outcome: VerificationOutcome) -> StepStatus:
    return {
        VerificationOutcome.VERIFIED: StepStatus.SUCCEEDED,
        VerificationOutcome.INSUFFICIENT: StepStatus.FAILED,
        VerificationOutcome.FAILED: StepStatus.FAILED,
        VerificationOutcome.BLOCKED: StepStatus.BLOCKED,
    }[outcome]


def _terminal_statuses(outcome: VerificationOutcome) -> tuple[RunStatus, TaskStatus]:
    return {
        VerificationOutcome.VERIFIED: (RunStatus.COMPLETED, TaskStatus.COMPLETED),
        VerificationOutcome.INSUFFICIENT: (RunStatus.FAILED, TaskStatus.FAILED),
        VerificationOutcome.FAILED: (RunStatus.FAILED, TaskStatus.FAILED),
        VerificationOutcome.BLOCKED: (RunStatus.BLOCKED, TaskStatus.BLOCKED),
    }[outcome]


def _termination_reason(verdict: VerificationVerdict) -> ErrorInfo | None:
    if verdict.outcome is VerificationOutcome.VERIFIED:
        return None
    code = verdict.reason_codes[0] if verdict.reason_codes else "TASK_VERIFICATION_FAILED"
    category = (
        ErrorCategory.POLICY_DENIED
        if verdict.outcome is VerificationOutcome.BLOCKED
        else ErrorCategory.EVIDENCE_INSUFFICIENT
    )
    return ErrorInfo(
        code=code,
        category=category,
        retryable=False,
        safe_message=verdict.summary,
    )


def _runtime_interruption_error(phase: str, exc: Exception) -> ErrorInfo:
    if phase == "planner_plan" and isinstance(exc, CyberAgentError):
        return exc.error
    if phase == "result_policy_review" and isinstance(exc, CyberAgentError):
        return exc.error
    mappings = {
        "verifier_registry": (
            getattr(exc, "code", "VERIFIER_RESOLUTION_FAILED"),
            ErrorCategory.TOOL_UNAVAILABLE,
            "The requested verifier could not be resolved.",
        ),
        "plugin_prepare": (
            "PLUGIN_PREPARE_EXCEPTION",
            ErrorCategory.TOOL_FAILED,
            "The selected tool plugin could not prepare an execution request.",
        ),
        "executor": (
            "EXECUTOR_EXCEPTION",
            ErrorCategory.SYSTEM_ERROR,
            "The controlled executor raised an exception.",
        ),
        "plugin_parse": (
            "PLUGIN_PARSE_EXCEPTION",
            ErrorCategory.TOOL_FAILED,
            "The selected tool plugin could not parse the execution result.",
        ),
        "verifier_step": (
            "VERIFIER_EXCEPTION",
            ErrorCategory.SYSTEM_ERROR,
            "The verifier raised an exception during step verification.",
        ),
        "verifier_task": (
            "VERIFIER_EXCEPTION",
            ErrorCategory.SYSTEM_ERROR,
            "The verifier raised an exception during task verification.",
        ),
        "adapter_build_observation": (
            "SCENARIO_ADAPTER_EXCEPTION",
            ErrorCategory.SYSTEM_ERROR,
            "The scenario adapter could not build an observation.",
        ),
    }
    code, category, message = mappings.get(
        phase,
        (
            "ORCHESTRATOR_RUNTIME_EXCEPTION",
            ErrorCategory.SYSTEM_ERROR,
            "The run was interrupted by an internal orchestration exception.",
        ),
    )
    return ErrorInfo(
        code=code,
        category=category,
        retryable=False,
        safe_message=message,
    )


def _entity(entity_type: str, entity_id: UUID) -> EntityRef:
    return EntityRef(entity_type=entity_type, entity_id=entity_id)


def _policy_review_evidence(
    *,
    run: Run,
    result: ToolResult,
    decision: PolicyDecision,
    observed_at: datetime,
) -> Evidence:
    reason = decision.reason_codes[0] if decision.reason_codes else "RESULT_POLICY_DENIED"
    return Evidence(
        run_id=run.run_id,
        source_ref=EntityRef(entity_type="tool_result", entity_id=result.result_id),
        kind=EvidenceKind.RULE_VERIFICATION,
        summary=f"Policy denied a follow-up target observed in a tool result: {reason}.",
        supports_claims=["claim.policy_enforced"],
        verification_method=VerificationMethod.RULE,
        confidence=1.0,
        created_at=observed_at,
    )


def _orchestrator_error(
    code: str,
    category: ErrorCategory,
    message: str,
) -> CyberAgentError:
    return CyberAgentError(
        ErrorInfo(
            code=code,
            category=category,
            retryable=False,
            safe_message=message,
        )
    )
