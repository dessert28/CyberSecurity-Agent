"""Validation-only Web-IDOR ScenarioAdapter skeleton."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID

from cyber_agent.contracts.common import UtcDateTime
from cyber_agent.contracts.plan import CandidateAction, Plan, PlanProposal, Run, Step
from cyber_agent.contracts.task import ScopePolicy, Task, TaskStatus
from cyber_agent.contracts.task_pack import ScenarioObservation, TaskPackManifest
from cyber_agent.contracts.tool import (
    PolicyDecision,
    ToolInvocation,
    ToolResult,
    ToolSpec,
)
from cyber_agent.application.web_observation import (
    WebIdorObservationType as LegacyWebIdorObservationType,
    adapt_web_idor_observation,
    policy_denial_observation,
)

from .config import WebIdorScenarioConfig, WebIdorStepBinding
from .manifest import (
    WEB_IDOR_REPORT_TEMPLATE,
    WEB_IDOR_SECURITY_POLICY,
    WEB_IDOR_TASK_PACK_ID,
    WEB_IDOR_TASK_PACK_VERSION,
    WEB_IDOR_TASK_TYPE,
    WEB_IDOR_TOOL_ID,
    WEB_IDOR_VERIFIER_ID,
)


@dataclass(frozen=True, slots=True)
class _OpenRun:
    task_id: UUID
    binding_ordinals: frozenset[int]


class WebIdorScenarioAdapter:
    """Validate trusted Web-IDOR bindings without executing or judging them."""

    def __init__(self, config: WebIdorScenarioConfig) -> None:
        self._config = WebIdorScenarioConfig.model_validate(
            config.model_dump(mode="python")
        )
        self._validated_task_ids: set[UUID] = set()
        self._open_runs: dict[UUID, _OpenRun] = {}
        self._lifecycle: list[str] = []

    @property
    def config(self) -> WebIdorScenarioConfig:
        return self._config.model_copy(deep=True)

    @property
    def lifecycle(self) -> tuple[str, ...]:
        return tuple(self._lifecycle)

    @property
    def open_run_ids(self) -> tuple[UUID, ...]:
        return tuple(sorted(self._open_runs, key=str))

    def validate_task(self, task: Task, manifest: TaskPackManifest) -> None:
        self._validate_manifest(manifest)
        if task.status is not TaskStatus.READY:
            raise ValueError("Web-IDOR adapter accepts only ready tasks")
        if WEB_IDOR_TASK_TYPE not in task.scenario_hints:
            raise ValueError("task does not declare the Web-IDOR task type")
        if not self._scopes_match(task.scope, self._config.scope):
            raise ValueError("task scope does not match trusted Web-IDOR scope")
        if WEB_IDOR_TOOL_ID not in task.scope.allowed_tool_ids:
            raise ValueError("task scope does not authorize web.http_request")
        if task.constraints.budget.max_steps < 2:
            raise ValueError("task budget cannot hold both Web-IDOR bindings")
        if task.constraints.budget.max_tool_calls < 2:
            raise ValueError("task budget cannot execute both Web-IDOR observations")
        self._validated_task_ids.add(task.task_id)
        self._lifecycle.append("validate_task")

    def open_run(
        self,
        task: Task,
        run: Run,
        manifest: TaskPackManifest,
    ) -> None:
        self._validate_manifest(manifest)
        if task.task_id not in self._validated_task_ids:
            raise ValueError("task must be validated before opening a run")
        if run.task_id != task.task_id:
            raise ValueError("run does not belong to the validated task")
        if run.run_id in self._open_runs:
            raise ValueError("Web-IDOR adapter run is already open")
        self._open_runs[run.run_id] = _OpenRun(
            task_id=task.task_id,
            binding_ordinals=frozenset(item.ordinal for item in self._config.bindings),
        )
        self._lifecycle.append("open_run")

    def validate_plan(
        self,
        task: Task,
        run: Run,
        proposal: PlanProposal,
        manifest: TaskPackManifest,
    ) -> None:
        state = self._require_context(task, run)
        self._validate_manifest(manifest)
        if proposal.plan.run_id != run.run_id:
            raise ValueError("plan does not belong to the open Web-IDOR run")
        if set(proposal.plan.step_ids) != {item.step_id for item in proposal.steps}:
            raise ValueError("plan step references do not match its proposal")
        ordinals = [item.ordinal for item in proposal.steps]
        if len(ordinals) != len(set(ordinals)) or set(ordinals) != set(
            state.binding_ordinals
        ):
            raise ValueError("plan steps do not match trusted Web-IDOR bindings")
        if any(item.required_capabilities != [WEB_IDOR_TOOL_ID] for item in proposal.steps):
            raise ValueError("Web-IDOR steps must require only web.http_request")

        step_by_ordinal = {item.ordinal: item for item in proposal.steps}
        baseline_step = step_by_ordinal[self._config.baseline.ordinal]
        probe_step = step_by_ordinal[self._config.probe.ordinal]
        if baseline_step.step_id not in probe_step.depends_on:
            raise ValueError("cross-tenant probe must depend on the trusted baseline")
        self._lifecycle.append("validate_plan")

    def validate_action(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        step: Step,
        action: CandidateAction,
        tool_spec: ToolSpec,
    ) -> None:
        self._require_context(task, run)
        if plan.run_id != run.run_id or step.plan_id != plan.plan_id:
            raise ValueError("action context references a different plan")
        if step.step_id not in plan.step_ids:
            raise ValueError("action step is not present in the active plan")
        binding = self._config.binding_for_ordinal(step.ordinal)
        if action.tool_id != WEB_IDOR_TOOL_ID or tool_spec.tool_id != WEB_IDOR_TOOL_ID:
            raise ValueError("Web-IDOR action must use web.http_request")
        if action.capability != WEB_IDOR_TOOL_ID:
            raise ValueError("Web-IDOR action capability must be web.http_request")
        if action.capability not in step.required_capabilities:
            raise ValueError("action capability is not required by the bound step")
        if action.capability not in tool_spec.capabilities:
            raise ValueError("selected tool does not provide web.http_request")
        self._validate_bound_request(action.arguments, binding)
        self._lifecycle.append("validate_action")

    def build_observation(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        step: Step,
        invocation: ToolInvocation,
        policy_decision: PolicyDecision,
        result: ToolResult | None,
        observed_at: UtcDateTime,
    ) -> ScenarioObservation:
        self._require_context(task, run)
        if plan.run_id != run.run_id or step.plan_id != plan.plan_id:
            raise ValueError("observation context references a different plan")
        if step.step_id not in plan.step_ids:
            raise ValueError("observation step is not present in the active plan")
        binding = self._config.binding_for_ordinal(step.ordinal)
        if (
            invocation.run_id != run.run_id
            or invocation.plan_id != plan.plan_id
            or invocation.step_id != step.step_id
        ):
            raise ValueError("invocation does not match the bound Web-IDOR step")
        if invocation.policy_decision_ref != policy_decision.decision_id:
            raise ValueError("invocation does not reference the supplied policy decision")
        self._validate_bound_request(invocation.validated_arguments, binding)
        if policy_decision.allowed and result is None:
            raise ValueError("an allowed Web-IDOR invocation requires a tool result")
        if not policy_decision.allowed and result is not None:
            raise ValueError("a denied Web-IDOR invocation cannot have an executed result")
        if result is not None and (
            result.run_id != invocation.run_id
            or result.plan_id != invocation.plan_id
            or result.step_id != invocation.step_id
            or result.tool_ref != invocation.tool_ref
            or result.policy_decision_ref != invocation.policy_decision_ref
        ):
            raise ValueError("tool result does not match its Web-IDOR invocation")

        if policy_decision.allowed:
            if result is None:
                raise ValueError("an allowed Web-IDOR invocation requires a tool result")
            adapted = adapt_web_idor_observation(
                task=task,
                run=run,
                plan=plan,
                step=step,
                invocation=invocation,
                decision=policy_decision,
                result=result,
                observation_type=LegacyWebIdorObservationType(
                    binding.observation_type.value
                ),
                actor_id=binding.actor_id,
            )
        else:
            adapted = policy_denial_observation(
                task=task,
                run=run,
                plan=plan,
                step=step,
                invocation=invocation,
                decision=policy_decision,
                occurred_at=observed_at,
            )
        self._lifecycle.append("build_observation")
        return ScenarioObservation(
            result=adapted.result,
            evidence=[adapted.evidence],
        )

    def close_run(self, run_id: UUID) -> None:
        state = self._open_runs.pop(run_id, None)
        if state is None:
            raise ValueError("Web-IDOR adapter run is not open")
        if not any(item.task_id == state.task_id for item in self._open_runs.values()):
            self._validated_task_ids.discard(state.task_id)
        self._lifecycle.append("close_run")

    def _require_context(self, task: Task, run: Run) -> _OpenRun:
        state = self._open_runs.get(run.run_id)
        if state is None:
            raise ValueError("Web-IDOR adapter run is not open")
        if state.task_id != task.task_id or run.task_id != task.task_id:
            raise ValueError("task and run do not match the open Web-IDOR context")
        return state

    @staticmethod
    def _validate_bound_request(
        arguments: dict,
        binding: WebIdorStepBinding,
    ) -> None:
        if arguments.get("method") != "GET":
            raise ValueError("Web-IDOR bindings require a GET request")
        if arguments.get("max_redirects") != 0:
            raise ValueError("Web-IDOR max_redirects must be explicitly set to zero")
        raw_url = arguments.get("url")
        if not isinstance(raw_url, str):
            raise ValueError("Web-IDOR action requires a structured URL")
        try:
            parsed = urlsplit(raw_url)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Web-IDOR action URL is malformed") from exc
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or port == 0
        ):
            raise ValueError("Web-IDOR action URL is malformed")
        object_id = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        if object_id != binding.expected_object_id:
            raise ValueError("Web-IDOR object binding does not match the trusted config")

    @staticmethod
    def _validate_manifest(manifest: TaskPackManifest) -> None:
        if manifest.task_pack_id != WEB_IDOR_TASK_PACK_ID:
            raise ValueError("unexpected Web-IDOR task pack id")
        if manifest.version != WEB_IDOR_TASK_PACK_VERSION:
            raise ValueError("unexpected Web-IDOR task pack version")
        if manifest.task_type != WEB_IDOR_TASK_TYPE:
            raise ValueError("unexpected Web-IDOR task type")
        if manifest.required_tools != (WEB_IDOR_TOOL_ID,):
            raise ValueError("Web-IDOR required_tools must contain only web.http_request")
        if manifest.verifier != WEB_IDOR_VERIFIER_ID:
            raise ValueError("unexpected Web-IDOR verifier")
        if manifest.report_template != WEB_IDOR_REPORT_TEMPLATE:
            raise ValueError("unexpected Web-IDOR report template")
        if manifest.security_policy != WEB_IDOR_SECURITY_POLICY:
            raise ValueError("unexpected Web-IDOR security policy")

    @staticmethod
    def _scopes_match(left: ScopePolicy, right: ScopePolicy) -> bool:
        return left.model_dump(mode="python", exclude={"policy_id"}) == right.model_dump(
            mode="python",
            exclude={"policy_id"},
        )


__all__ = ["WebIdorScenarioAdapter"]
