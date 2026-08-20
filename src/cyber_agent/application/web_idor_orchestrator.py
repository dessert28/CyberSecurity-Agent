"""Minimal, fail-closed orchestration for the deterministic Web-IDOR scenario."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from cyber_agent.audit_store import InMemoryAuditStore, build_audit_record
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
from cyber_agent.contracts.evidence import Evidence, VerificationOutcome, VerificationVerdict
from cyber_agent.contracts.plan import (
    DecisionProposal,
    Plan,
    PlanProposal,
    PlanStatus,
    Run,
    RunStatus,
    Step,
    StepStatus,
)
from cyber_agent.contracts.ports import ExecutorPort, PlannerPort, VerifierPort
from cyber_agent.contracts.task import Task, TaskStatus
from cyber_agent.contracts.tool import (
    PolicyDecision,
    ToolInvocation,
    ToolInvocationStatus,
    ToolRef,
    ToolResult,
    ToolResultStatus,
    ToolSpec,
)
from cyber_agent.tools import BudgetUsage, PolicyGate, ToolRegistry

from .web_observation import (
    WebIdorObservationType,
    adapt_web_idor_observation,
    materialize_policy_decision,
    policy_denial_observation,
)

_SYSTEM_ACTOR = ActorRef(
    actor_type=ActorType.SYSTEM,
    actor_id="web-idor-orchestrator",
)
_MODEL_ACTOR = ActorRef(actor_type=ActorType.MODEL, actor_id="planner")


@dataclass(frozen=True, slots=True)
class WebIdorStepBinding:
    """Trusted scenario metadata; it is never derived from model rationale."""

    ordinal: int
    observation_type: WebIdorObservationType
    actor_id: str
    expected_object_id: str

    def __post_init__(self) -> None:
        if self.ordinal < 1:
            raise ValueError("step binding ordinal must be positive")
        if not _safe_label(self.actor_id):
            raise ValueError("step binding actor_id is invalid")
        if not _safe_label(self.expected_object_id):
            raise ValueError("step binding expected_object_id is invalid")


@dataclass(frozen=True, slots=True)
class WebIdorScenarioConfig:
    bindings: tuple[WebIdorStepBinding, ...]

    def __post_init__(self) -> None:
        if not self.bindings:
            raise ValueError("Web-IDOR scenario bindings cannot be empty")
        ordinals = [item.ordinal for item in self.bindings]
        if len(ordinals) != len(set(ordinals)):
            raise ValueError("Web-IDOR scenario binding ordinals must be unique")
        observation_types = [item.observation_type for item in self.bindings]
        required = {
            WebIdorObservationType.AUTHORIZED_BASELINE,
            WebIdorObservationType.CROSS_TENANT_PROBE,
        }
        if set(observation_types) != required or len(observation_types) != 2:
            raise ValueError("Web-IDOR requires exactly one baseline and one probe binding")


@dataclass(frozen=True, slots=True)
class WebIdorRunOutcome:
    task: Task
    run: Run
    plan: Plan
    steps: tuple[Step, ...]
    invocations: tuple[ToolInvocation, ...]
    policy_decisions: tuple[PolicyDecision, ...]
    results: tuple[ToolResult, ...]
    evidence: tuple[Evidence, ...]
    step_verdicts: tuple[VerificationVerdict, ...]
    task_verdict: VerificationVerdict
    audit_records: tuple[AuditRecord, ...]


class _AuditTrail:
    def __init__(
        self,
        *,
        store: InMemoryAuditStore,
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


class WebIdorOrchestrator:
    """Coordinate existing ports without executing a host process directly."""

    def __init__(
        self,
        *,
        planner: PlannerPort,
        registry: ToolRegistry,
        policy_gate: PolicyGate,
        executor: ExecutorPort,
        verifier: VerifierPort,
        audit_store: InMemoryAuditStore,
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
        self._verifier = verifier
        self._audit_store = audit_store
        self._model_profile = model_profile.model_copy(deep=True)
        self._environment_profile = environment_profile.model_copy(deep=True)
        self._run_id_factory = run_id_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic

    async def run(
        self,
        task: Task,
        scenario: WebIdorScenarioConfig,
    ) -> WebIdorRunOutcome:
        if task.status is not TaskStatus.READY:
            raise _orchestrator_error(
                "TASK_NOT_READY",
                ErrorCategory.INPUT_INVALID,
                "The orchestrator accepts only normalized, ready tasks.",
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
            AuditEventType.RUN_CREATED,
            "Run created from a ready task.",
            subjects=[_entity("run", run.run_id), _entity("task", task.task_id)],
        )

        proposal = await self._planner.propose_plan(task, run)
        await audit.emit(
            AuditEventType.PLAN_PROPOSED,
            "Planner returned a complete PlanProposal.",
            actor=_MODEL_ACTOR,
            subjects=[_entity("plan", proposal.plan.plan_id)],
            inputs=[_entity("run", run.run_id)],
        )
        self._validate_plan_proposal(run, proposal, scenario)
        plan = proposal.plan.model_copy(update={"status": PlanStatus.ACTIVE})
        steps = [item.model_copy(deep=True) for item in proposal.steps]
        run = run.model_copy(
            update={"status": RunStatus.RUNNING, "active_plan_id": plan.plan_id}
        )
        task = task.model_copy(update={"status": TaskStatus.RUNNING})
        await audit.emit(
            AuditEventType.PLAN_ACCEPTED,
            "Plan and trusted scenario bindings passed orchestration validation.",
            subjects=[_entity("plan", plan.plan_id)],
        )

        binding_by_ordinal = {item.ordinal: item for item in scenario.bindings}
        completed_step_ids: set[UUID] = set()
        invocations: list[ToolInvocation] = []
        decisions: list[PolicyDecision] = []
        results: list[ToolResult] = []
        evidence: list[Evidence] = []
        step_verdicts: list[VerificationVerdict] = []
        tool_calls = 0

        for index in self._execution_order(steps):
            step = steps[index]
            if not set(step.depends_on).issubset(completed_step_ids):
                raise _orchestrator_error(
                    "STEP_DEPENDENCY_NOT_SATISFIED",
                    ErrorCategory.SYSTEM_ERROR,
                    "A step became runnable before all dependencies completed.",
                )
            binding = binding_by_ordinal[step.ordinal]
            step = step.model_copy(update={"status": StepStatus.RUNNING})
            steps[index] = step
            await audit.emit(
                AuditEventType.STEP_STATE_CHANGED,
                "Step entered running state.",
                subjects=[_entity("step", step.step_id)],
            )

            capability = step.required_capabilities[0]
            candidates = tuple(self._registry.candidates(capability))
            if not candidates:
                raise _orchestrator_error(
                    "TOOL_CANDIDATES_EMPTY",
                    ErrorCategory.TOOL_UNAVAILABLE,
                    "No healthy registry candidate supports the required capability.",
                )
            action_proposal = await self._planner.propose_next_action(
                task,
                run,
                plan,
                step,
                tuple(evidence),
                candidates,
            )
            selected, spec = self._validate_action_proposal(
                run,
                plan,
                step,
                action_proposal,
                candidates,
                binding,
            )
            await audit.emit(
                AuditEventType.TOOL_CANDIDATES_COMPARED,
                "Planner selected one registry-approved tool and structured argument set.",
                actor=_MODEL_ACTOR,
                subjects=[_entity("step", step.step_id)],
            )

            elapsed_seconds = max(0.0, self._monotonic() - started_monotonic)
            invocation = ToolInvocation(
                run_id=run.run_id,
                plan_id=plan.plan_id,
                step_id=step.step_id,
                attempt=1,
                tool_ref=ToolRef(tool_id=spec.tool_id, version=spec.version),
                validated_arguments=selected.arguments,
                deadline=self._invocation_deadline(run, elapsed_seconds),
                status=ToolInvocationStatus.PROPOSED,
            )
            decision = self._policy_gate.evaluate(
                invocation,
                spec,
                task.scope,
                run.budget,
                BudgetUsage(
                    elapsed_seconds=elapsed_seconds,
                    tool_calls=tool_calls,
                    attempts_for_step=0,
                ),
            )
            decisions.append(decision)
            bound_invocation = materialize_policy_decision(invocation, decision)
            policy_event = (
                AuditEventType.POLICY_ALLOWED
                if decision.allowed
                else AuditEventType.POLICY_DENIED
            )
            await audit.emit(
                policy_event,
                "Policy gate allowed the proposed invocation."
                if decision.allowed
                else "Policy gate denied the proposed invocation before execution.",
                reason_codes=decision.reason_codes,
                subjects=[
                    _entity("tool_invocation", invocation.invocation_id),
                    _entity("policy_decision", decision.decision_id),
                ],
                policy_ref=decision.decision_id,
            )

            if decision.allowed:
                plugin = self._registry.plugin(spec.tool_id)
                request = plugin.prepare(bound_invocation)
                running_invocation = bound_invocation.model_copy(
                    update={"status": ToolInvocationStatus.RUNNING}
                )
                await audit.emit(
                    AuditEventType.EXECUTION_STARTED,
                    "Approved structured request entered the controlled executor.",
                    actor=ActorRef(actor_type=ActorType.TOOL, actor_id=spec.tool_id),
                    subjects=[_entity("tool_invocation", invocation.invocation_id)],
                    policy_ref=decision.decision_id,
                )
                raw_result = await self._executor.execute(request)
                tool_calls += 1
                parsed_result = plugin.parse(raw_result)
                await audit.emit(
                    AuditEventType.EXECUTION_FINISHED,
                    f"Controlled execution finished with status {parsed_result.status.value}.",
                    actor=ActorRef(actor_type=ActorType.TOOL, actor_id=spec.tool_id),
                    reason_codes=(
                        [parsed_result.error.code]
                        if parsed_result.error is not None
                        else []
                    ),
                    subjects=[_entity("tool_result", parsed_result.result_id)],
                    policy_ref=decision.decision_id,
                )
                if parsed_result.status is not ToolResultStatus.SUCCEEDED:
                    raise _orchestrator_error(
                        parsed_result.error.code
                        if parsed_result.error is not None
                        else "TOOL_EXECUTION_FAILED",
                        parsed_result.error.category
                        if parsed_result.error is not None
                        else ErrorCategory.TOOL_FAILED,
                        "The controlled Web tool did not produce a successful result.",
                    )
                current_url = bound_invocation.validated_arguments.get("url")
                redirects = parsed_result.normalized_output.get("redirects")
                if isinstance(current_url, str) and isinstance(redirects, list):
                    for location in redirects:
                        if not isinstance(location, str):
                            break
                        redirect_decision = self._policy_gate.check_redirect(
                            current_url=current_url,
                            location=location,
                            scope=task.scope,
                        )
                        await audit.emit(
                            AuditEventType.POLICY_ALLOWED
                            if redirect_decision.allowed
                            else AuditEventType.POLICY_DENIED,
                            "Policy gate rechecked an observed redirect without following it.",
                            reason_codes=redirect_decision.reason_codes,
                            subjects=[_entity("tool_result", parsed_result.result_id)],
                            policy_ref=redirect_decision.decision_id,
                        )
                        if not redirect_decision.allowed:
                            code = (
                                redirect_decision.reason_codes[0]
                                if redirect_decision.reason_codes
                                else "REDIRECT_POLICY_DENIED"
                            )
                            raise _orchestrator_error(
                                code,
                                ErrorCategory.POLICY_DENIED,
                                "The observed redirect was outside the approved scope.",
                            )
                        redirected = redirect_decision.constrained_arguments.get("url")
                        if not isinstance(redirected, str):
                            raise _orchestrator_error(
                                "REDIRECT_POLICY_OUTPUT_INVALID",
                                ErrorCategory.SYSTEM_ERROR,
                                "Redirect policy output was malformed.",
                            )
                        current_url = redirected
                adapted = adapt_web_idor_observation(
                    task=task,
                    run=run,
                    plan=plan,
                    step=step,
                    invocation=bound_invocation,
                    decision=decision,
                    result=parsed_result,
                    observation_type=binding.observation_type,
                    actor_id=binding.actor_id,
                )
                terminal_invocation = running_invocation.model_copy(
                    update={"status": ToolInvocationStatus.COMPLETED}
                )
            else:
                adapted = policy_denial_observation(
                    task=task,
                    run=run,
                    plan=plan,
                    step=step,
                    invocation=bound_invocation,
                    decision=decision,
                    occurred_at=self._clock(),
                )
                terminal_invocation = bound_invocation

            invocations.append(terminal_invocation)
            results.append(adapted.result)
            evidence.append(adapted.evidence)
            verdict = await self._verifier.verify_step(
                task,
                run,
                plan,
                step,
                [adapted.result],
                [adapted.evidence],
            )
            step_verdicts.append(verdict)
            await audit.emit(
                AuditEventType.VERIFICATION_COMPLETED,
                verdict.summary,
                reason_codes=verdict.reason_codes,
                subjects=[_entity("step", step.step_id)],
                inputs=[
                    _entity("tool_result", adapted.result.result_id),
                    _entity("evidence", adapted.evidence.evidence_id),
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

        task_verdict = await self._verifier.verify_task(
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
        termination = _termination_reason(task_verdict)
        run = run.model_copy(
            update={"status": run_status, "termination_reason": termination}
        )
        task = task.model_copy(update={"status": task_status})
        plan_status = (
            PlanStatus.COMPLETED
            if len(completed_step_ids) == len(steps)
            else PlanStatus.FAILED
        )
        plan = plan.model_copy(update={"status": plan_status})
        await audit.emit(
            AuditEventType.RUN_FINISHED,
            f"Run finished with task verification outcome {task_verdict.outcome.value}.",
            reason_codes=task_verdict.reason_codes,
            subjects=[_entity("run", run.run_id), _entity("task", task.task_id)],
        )
        audit_records = tuple(await self._audit_store.list_by_run(run.run_id))

        clear_run = getattr(self._verifier, "clear_run", None)
        if callable(clear_run):
            clear_run(run.run_id)

        return WebIdorRunOutcome(
            task=task,
            run=run,
            plan=plan,
            steps=tuple(steps),
            invocations=tuple(invocations),
            policy_decisions=tuple(decisions),
            results=tuple(results),
            evidence=tuple(evidence),
            step_verdicts=tuple(step_verdicts),
            task_verdict=task_verdict,
            audit_records=audit_records,
        )

    @staticmethod
    def _validate_plan_proposal(
        run: Run,
        proposal: PlanProposal,
        scenario: WebIdorScenarioConfig,
    ) -> None:
        if proposal.plan.run_id != run.run_id:
            raise _orchestrator_error(
                "PLAN_RUN_MISMATCH",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "The proposed plan does not belong to the active run.",
            )
        if len(proposal.steps) > run.budget.max_steps:
            raise _orchestrator_error(
                "STEP_BUDGET_EXCEEDED",
                ErrorCategory.BUDGET_EXCEEDED,
                "The proposed plan exceeds the task step budget.",
            )
        step_ordinals = [item.ordinal for item in proposal.steps]
        binding_ordinals = [item.ordinal for item in scenario.bindings]
        if len(step_ordinals) != len(set(step_ordinals)) or set(step_ordinals) != set(
            binding_ordinals
        ):
            raise _orchestrator_error(
                "SCENARIO_STEP_BINDING_MISMATCH",
                ErrorCategory.MODEL_SCHEMA_INVALID,
                "Every planned step must have one trusted scenario binding.",
            )
        if any(item.required_capabilities != ["web.http_request"] for item in proposal.steps):
            raise _orchestrator_error(
                "WEB_IDOR_CAPABILITY_INVALID",
                ErrorCategory.POLICY_DENIED,
                "The minimal Web-IDOR loop accepts only one HTTP request capability per step.",
            )

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
    def _validate_action_proposal(
        run: Run,
        plan: Plan,
        step: Step,
        proposal: DecisionProposal,
        candidates: Sequence[ToolSpec],
        binding: WebIdorStepBinding,
    ):
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
                    "A model-proposed action references an undeclared capability.",
                )
            if action.tool_id is not None and action.tool_id not in candidate_by_id:
                raise _orchestrator_error(
                    "TOOL_ID_NOT_CANDIDATE",
                    ErrorCategory.POLICY_DENIED,
                    "A model-proposed action references a non-candidate tool.",
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
        _validate_bound_request(selected.arguments, binding)
        return selected, spec

    def _invocation_deadline(self, run: Run, elapsed_seconds: float) -> datetime:
        remaining_run_seconds = run.budget.max_duration_seconds - elapsed_seconds
        if remaining_run_seconds < 1:
            # Force PolicyGate to reject the proposal as expired instead of
            # letting the plugin receive a sub-second execution window.
            return self._clock()
        timeout = min(
            run.budget.max_tool_timeout_seconds,
            remaining_run_seconds,
        )
        return self._clock() + timedelta(seconds=timeout)


def _validate_bound_request(arguments: dict, binding: WebIdorStepBinding) -> None:
    if arguments.get("method") != "GET":
        raise _orchestrator_error(
            "WEB_IDOR_METHOD_INVALID",
            ErrorCategory.POLICY_DENIED,
            "Web-IDOR observation bindings require a GET request.",
        )
    raw_url = arguments.get("url")
    if not isinstance(raw_url, str):
        raise _orchestrator_error(
            "WEB_IDOR_URL_INVALID",
            ErrorCategory.MODEL_SCHEMA_INVALID,
            "The selected action does not contain a structured URL.",
        )
    try:
        parsed = urlsplit(raw_url)
    except ValueError as exc:
        raise _orchestrator_error(
            "WEB_IDOR_URL_INVALID",
            ErrorCategory.MODEL_SCHEMA_INVALID,
            "The selected action URL is malformed.",
        ) from exc
    object_id = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    if object_id != binding.expected_object_id:
        raise _orchestrator_error(
            "SCENARIO_OBJECT_BINDING_MISMATCH",
            ErrorCategory.POLICY_DENIED,
            "The model-selected object does not match trusted scenario configuration.",
        )


def _step_status(outcome: VerificationOutcome) -> StepStatus:
    return {
        VerificationOutcome.VERIFIED: StepStatus.SUCCEEDED,
        VerificationOutcome.INSUFFICIENT: StepStatus.BLOCKED,
        VerificationOutcome.BLOCKED: StepStatus.BLOCKED,
        VerificationOutcome.FAILED: StepStatus.FAILED,
    }[outcome]


def _terminal_statuses(outcome: VerificationOutcome) -> tuple[RunStatus, TaskStatus]:
    if outcome is VerificationOutcome.VERIFIED:
        return RunStatus.COMPLETED, TaskStatus.COMPLETED
    if outcome in {VerificationOutcome.INSUFFICIENT, VerificationOutcome.BLOCKED}:
        return RunStatus.BLOCKED, TaskStatus.BLOCKED
    return RunStatus.FAILED, TaskStatus.FAILED


def _termination_reason(verdict: VerificationVerdict) -> ErrorInfo | None:
    if verdict.outcome is VerificationOutcome.VERIFIED:
        return None
    code = verdict.reason_codes[0] if verdict.reason_codes else "VERIFICATION_FAILED"
    category = (
        ErrorCategory.POLICY_DENIED
        if code == "SAFETY_VIOLATION_OUT_OF_SCOPE"
        else ErrorCategory.EVIDENCE_INSUFFICIENT
    )
    return ErrorInfo(
        code=code,
        category=category,
        retryable=False,
        safe_message=verdict.summary,
    )


def _entity(entity_type: str, entity_id: UUID) -> EntityRef:
    return EntityRef(entity_type=entity_type, entity_id=entity_id)


def _safe_label(value: str) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 255
        and value == value.strip()
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
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
