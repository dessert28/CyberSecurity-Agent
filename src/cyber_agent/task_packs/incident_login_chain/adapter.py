"""ScenarioAdapter for the fixed read-only incident login-chain pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from cyber_agent.contracts.common import EntityRef, ErrorCategory, ErrorInfo, UtcDateTime
from cyber_agent.contracts.evidence import Evidence, EvidenceKind, VerificationMethod
from cyber_agent.contracts.plan import CandidateAction, Plan, PlanProposal, Run, Step
from cyber_agent.contracts.task import TargetKind, Task, TaskStatus
from cyber_agent.contracts.task_pack import ScenarioObservation, TaskPackManifest
from cyber_agent.contracts.tool import (
    PolicyDecision,
    RunnerType,
    SideEffect,
    ToolInvocation,
    ToolResult,
    ToolResultStatus,
    ToolSpec,
)
from cyber_agent.tools.incident_log import (
    IncidentLogInventoryPlugin,
    IncidentLogSearchPlugin,
    LogInventoryResult,
    LogSearchResult,
)

from .config import IncidentLoginChainScenarioConfig
from .manifest import (
    INCIDENT_LOGIN_CHAIN_INVENTORY_CAPABILITY,
    INCIDENT_LOGIN_CHAIN_INVENTORY_TOOL_ID,
    INCIDENT_LOGIN_CHAIN_REPORT_TEMPLATE,
    INCIDENT_LOGIN_CHAIN_REQUIRED_TOOLS,
    INCIDENT_LOGIN_CHAIN_SEARCH_CAPABILITY,
    INCIDENT_LOGIN_CHAIN_SEARCH_TOOL_ID,
    INCIDENT_LOGIN_CHAIN_SECURITY_POLICY,
    INCIDENT_LOGIN_CHAIN_TASK_PACK_ID,
    INCIDENT_LOGIN_CHAIN_TASK_PACK_VERSION,
    INCIDENT_LOGIN_CHAIN_TASK_TYPE,
    INCIDENT_LOGIN_CHAIN_VERIFIER_ID,
)


@dataclass(slots=True)
class _OpenRun:
    task_id: UUID
    artifact_id: UUID
    step_tools: dict[UUID, str] = field(default_factory=dict)
    inventory: LogInventoryResult | None = None


class IncidentLoginChainScenarioAdapter:
    """Bind a trusted log bundle through inventory and evidence-backed search."""

    def __init__(self, config: IncidentLoginChainScenarioConfig) -> None:
        self._config = IncidentLoginChainScenarioConfig.model_validate(
            config.model_dump(mode="python")
        )
        self._validated_tasks: dict[UUID, str] = {}
        self._open_runs: dict[UUID, _OpenRun] = {}
        self._lifecycle: list[str] = []

    @property
    def config(self) -> IncidentLoginChainScenarioConfig:
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
            raise ValueError("incident adapter accepts only ready tasks")
        if INCIDENT_LOGIN_CHAIN_TASK_TYPE not in task.scenario_hints:
            raise ValueError("task does not declare the incident login-chain task type")
        if task.scope.network_access or self._config.network_access:
            raise ValueError("incident login-chain pipeline forbids network access")
        if task.scope.allowed_tool_ids != set(self._config.allowed_tools):
            raise ValueError("task policy must allow exactly the incident login-chain tools")
        if any(target.kind is not TargetKind.FILE for target in task.scope.allowed_targets):
            raise ValueError("incident login-chain policy accepts only file targets")
        if any(target.protocols - {"file"} for target in task.scope.allowed_targets):
            raise ValueError("incident login-chain file targets may use only the file protocol")

        artifacts = [
            item for item in task.input_artifacts if item.artifact_id == self._config.artifact_id
        ]
        if len(artifacts) != 1:
            raise ValueError("task must reference the configured log bundle exactly once")
        artifact = artifacts[0]
        if artifact.sha256 != self._config.artifact_sha256:
            raise ValueError("log bundle hash does not match trusted config")
        if artifact.media_type != "application/zip":
            raise ValueError("log bundle must use application/zip")
        if not any(
            target.kind is TargetKind.FILE and target.value == artifact.logical_uri
            for target in task.scope.allowed_targets
        ):
            raise ValueError("log bundle is not present in the task file scope")
        if task.constraints.budget.max_steps < 3:
            raise ValueError("task budget cannot hold the three incident login-chain steps")
        if task.constraints.budget.max_tool_calls < 3:
            raise ValueError("task budget cannot execute the three incident login-chain tools")

        self._validated_tasks[task.task_id] = artifact.logical_uri
        self._lifecycle.append("validate_task")

    def open_run(self, task: Task, run: Run, manifest: TaskPackManifest) -> None:
        self._validate_manifest(manifest)
        if task.task_id not in self._validated_tasks:
            raise ValueError("task must be validated before opening a run")
        if run.task_id != task.task_id:
            raise ValueError("run does not belong to the validated task")
        if run.run_id in self._open_runs:
            raise ValueError("incident adapter run is already open")
        self._open_runs[run.run_id] = _OpenRun(
            task_id=task.task_id,
            artifact_id=self._config.artifact_id,
        )
        self._lifecycle.append("open_run")

    def validate_plan(self, task: Task, run: Run, proposal: PlanProposal, manifest: TaskPackManifest) -> None:
        state = self._require_context(task, run)
        self._validate_manifest(manifest)
        if proposal.plan.run_id != run.run_id:
            raise ValueError("plan does not belong to the open incident run")
        if proposal.plan.step_ids != [item.step_id for item in proposal.steps]:
            raise ValueError("plan step references do not match its proposal")
        if len(proposal.steps) != 3:
            raise ValueError("incident plan requires exactly three ordered steps")
        inventory, failed_search, account_search = proposal.steps
        if [item.ordinal for item in proposal.steps] != [1, 2, 3]:
            raise ValueError("incident steps must use ordinals 1, 2, and 3")
        if inventory.depends_on:
            raise ValueError("incident.log_inventory must be the root step")
        if failed_search.depends_on != [inventory.step_id]:
            raise ValueError("failed-login search must depend on inventory")
        if account_search.depends_on != [failed_search.step_id]:
            raise ValueError("account search must depend on the failed-login search")
        expected_capabilities = [
            [INCIDENT_LOGIN_CHAIN_INVENTORY_CAPABILITY],
            [INCIDENT_LOGIN_CHAIN_SEARCH_CAPABILITY],
            [INCIDENT_LOGIN_CHAIN_SEARCH_CAPABILITY],
        ]
        if [item.required_capabilities for item in proposal.steps] != expected_capabilities:
            raise ValueError("incident plan capabilities must match the fixed pipeline")
        expected_edges = {
            (inventory.step_id, failed_search.step_id),
            (failed_search.step_id, account_search.step_id),
        }
        actual_edges = {(item.before, item.after) for item in proposal.plan.dependency_edges}
        if actual_edges != expected_edges:
            raise ValueError("incident dependency edges must match the fixed pipeline")
        state.step_tools = {
            inventory.step_id: INCIDENT_LOGIN_CHAIN_INVENTORY_TOOL_ID,
            failed_search.step_id: INCIDENT_LOGIN_CHAIN_SEARCH_TOOL_ID,
            account_search.step_id: INCIDENT_LOGIN_CHAIN_SEARCH_TOOL_ID,
        }
        self._lifecycle.append("validate_plan")

    def validate_action(self, task: Task, run: Run, plan: Plan, step: Step, action: CandidateAction, tool_spec: ToolSpec) -> None:
        state = self._require_context(task, run)
        self._validate_step_context(run, plan, step)
        expected_tool = state.step_tools.get(step.step_id)
        if expected_tool is None:
            raise ValueError("incident step was not approved by validate_plan")
        if action.tool_id != expected_tool or tool_spec.tool_id != expected_tool:
            raise ValueError("incident action does not match the fixed step tool")
        if action.capability not in step.required_capabilities:
            raise ValueError("selected capability is not required by the bound step")
        if action.capability not in tool_spec.capabilities:
            raise ValueError("selected tool does not provide the required capability")
        if tool_spec.permissions.network or tool_spec.side_effects & {SideEffect.NETWORK_READ, SideEffect.NETWORK_ACTIVE}:
            raise ValueError("incident tools must not use network access")
        if tool_spec.permissions.filesystem_write or SideEffect.FILE_WRITE in tool_spec.side_effects:
            raise ValueError("incident tools must not write files")
        if tool_spec.execution_profile.runner is not RunnerType.SOURCE_ANALYSIS:
            raise ValueError("incident tools must use the SOURCE_ANALYSIS runner")

        if expected_tool == INCIDENT_LOGIN_CHAIN_INVENTORY_TOOL_ID:
            self._validate_artifact_arguments(action.arguments, expected_keys={"artifact_id", "artifact_sha256"})
        else:
            self._validate_search_arguments(action.arguments)
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
        state = self._require_context(task, run)
        self._validate_step_context(run, plan, step)
        if invocation.run_id != run.run_id or invocation.plan_id != plan.plan_id or invocation.step_id != step.step_id:
            raise ValueError("invocation does not match the active incident step")
        expected_tool = state.step_tools.get(step.step_id)
        if invocation.tool_ref.tool_id != expected_tool:
            raise ValueError("incident invocation references an unexpected tool")
        if invocation.policy_decision_ref != policy_decision.decision_id:
            raise ValueError("invocation does not reference the supplied policy decision")
        if policy_decision.policy_version != INCIDENT_LOGIN_CHAIN_SECURITY_POLICY:
            raise ValueError("incident policy decision uses an unexpected version")
        self._validate_invocation_arguments(invocation.validated_arguments, expected_tool)

        if policy_decision.allowed:
            if result is None:
                raise ValueError("an allowed incident invocation requires a tool result")
            normalized_result = self._validate_result(result, invocation, state)
            evidence = self._evidence_for_result(normalized_result, observed_at)
        else:
            if result is not None:
                raise ValueError("a denied incident invocation cannot have an executed result")
            normalized_result = self._policy_denial_result(invocation, policy_decision, observed_at)
            evidence = Evidence(
                run_id=run.run_id,
                source_ref=EntityRef(entity_type="tool_result", entity_id=normalized_result.result_id),
                kind=EvidenceKind.RULE_VERIFICATION,
                summary=f"Policy prevented {expected_tool} before execution; no external side effect occurred.",
                supports_claims=["incident.policy_enforced"],
                verification_method=VerificationMethod.RULE,
                confidence=1.0,
                created_at=observed_at,
            )

        self._lifecycle.append("build_observation")
        return ScenarioObservation(result=normalized_result, evidence=[evidence])

    def close_run(self, run_id: UUID) -> None:
        state = self._open_runs.pop(run_id, None)
        if state is None:
            raise ValueError("incident adapter run is not open")
        if not any(item.task_id == state.task_id for item in self._open_runs.values()):
            self._validated_tasks.pop(state.task_id, None)
        self._lifecycle.append("close_run")

    def _require_context(self, task: Task, run: Run) -> _OpenRun:
        state = self._open_runs.get(run.run_id)
        if state is None:
            raise ValueError("incident adapter run is not open")
        if state.task_id != task.task_id or run.task_id != task.task_id:
            raise ValueError("task and run do not match the open incident context")
        if state.artifact_id != self._config.artifact_id:
            raise ValueError("open run artifact binding is invalid")
        return state

    @staticmethod
    def _validate_step_context(run: Run, plan: Plan, step: Step) -> None:
        if plan.run_id != run.run_id or step.plan_id != plan.plan_id:
            raise ValueError("action context references a different plan")
        if step.step_id not in plan.step_ids:
            raise ValueError("action step is not present in the active plan")

    def _validate_artifact_arguments(self, arguments: dict, *, expected_keys: set[str]) -> None:
        if set(arguments) != expected_keys:
            raise ValueError("incident arguments contain unexpected fields")
        if arguments.get("artifact_id") != str(self._config.artifact_id):
            raise ValueError("incident artifact binding does not match trusted config")
        if arguments.get("artifact_sha256") != self._config.artifact_sha256:
            raise ValueError("incident artifact hash does not match trusted config")

    def _validate_search_arguments(self, arguments: dict) -> None:
        self._validate_artifact_arguments(
            arguments,
            expected_keys={"artifact_id", "artifact_sha256", "query"},
        )
        query = arguments.get("query")
        if not isinstance(query, dict) or not query:
            raise ValueError("incident search requires a structured query")
        for key in query:
            if key not in {"user", "src_ip", "event"}:
                raise ValueError(f"incident search query key is not allowed: {key}")

    def _validate_invocation_arguments(self, arguments: dict, tool_id: str | None) -> None:
        if tool_id == INCIDENT_LOGIN_CHAIN_INVENTORY_TOOL_ID:
            self._validate_artifact_arguments(arguments, expected_keys={"artifact_id", "artifact_sha256"})
            return
        if tool_id == INCIDENT_LOGIN_CHAIN_SEARCH_TOOL_ID:
            self._validate_search_arguments(arguments)
            return
        raise ValueError("incident invocation references an unsupported tool")

    def _validate_result(self, result: ToolResult, invocation: ToolInvocation, state: _OpenRun) -> ToolResult:
        if (
            result.run_id != invocation.run_id
            or result.plan_id != invocation.plan_id
            or result.step_id != invocation.step_id
            or result.tool_ref != invocation.tool_ref
            or result.policy_decision_ref != invocation.policy_decision_ref
            or result.validated_arguments != invocation.validated_arguments
        ):
            raise ValueError("tool result does not match its incident invocation")
        tool_id = result.tool_ref.tool_id
        if tool_id == INCIDENT_LOGIN_CHAIN_INVENTORY_TOOL_ID:
            inventory = LogInventoryResult.model_validate(result.normalized_output)
            self._validate_output_artifact(inventory.artifact_id, inventory.artifact_sha256)
            state.inventory = inventory
        elif tool_id == INCIDENT_LOGIN_CHAIN_SEARCH_TOOL_ID:
            search = LogSearchResult.model_validate(result.normalized_output)
            self._validate_output_artifact(search.artifact_id, search.artifact_sha256)
        else:
            raise ValueError("incident result references an unsupported tool")
        return result

    def _validate_output_artifact(self, artifact_id: UUID, artifact_sha256: str) -> None:
        if artifact_id != self._config.artifact_id:
            raise ValueError("incident output artifact id does not match trusted config")
        if artifact_sha256 != self._config.artifact_sha256:
            raise ValueError("incident output artifact hash does not match trusted config")

    @staticmethod
    def _evidence_for_result(result: ToolResult, observed_at: UtcDateTime) -> Evidence:
        if result.tool_ref.tool_id == INCIDENT_LOGIN_CHAIN_INVENTORY_TOOL_ID:
            inventory = LogInventoryResult.model_validate(result.normalized_output)
            accounts = ", ".join(sorted(inventory.accounts)) or "none"
            ips = ", ".join(sorted(inventory.source_ips)) or "none"
            summary = (
                f"Log inventory observed {inventory.total_events} events; accounts={accounts}; "
                f"source_ips={ips}."
            )
            claim = "incident.log_inventory"
        elif result.tool_ref.tool_id == INCIDENT_LOGIN_CHAIN_SEARCH_TOOL_ID:
            search = LogSearchResult.model_validate(result.normalized_output)
            query = ", ".join(f"{k}={v}" for k, v in sorted(search.query.items())) or "all"
            claim = "incident.log_search"
            summary = f"Log search ({query}) returned {len(search.matches)} events."
            if search.query.get("event") == "login_failed":
                # Aggregate failed-login counts per account, most-failed first, so
                # the planner can focus its follow-up search without an answer key.
                failed_by_account: dict[str, int] = {}
                for item in search.matches:
                    failed_by_account[item.user] = failed_by_account.get(item.user, 0) + 1
                ranked = ", ".join(
                    f"{account}:{count}"
                    for account, count in sorted(
                        failed_by_account.items(), key=lambda pair: (-pair[1], pair[0])
                    )
                )
                summary = (
                    f"Log search ({query}) returned {len(search.matches)} events; "
                    f"failed_accounts={ranked}."
                )
            elif "user" in search.query:
                failed = [item for item in search.matches if item.event == "login_failed"]
                summary = (
                    f"Account-scoped log search returned {len(search.matches)} events; "
                    f"failed_logins={len(failed)}."
                )
        else:
            raise ValueError("cannot create evidence for an unsupported incident tool")
        return Evidence(
            run_id=result.run_id,
            source_ref=EntityRef(entity_type="tool_result", entity_id=result.result_id),
            kind=EvidenceKind.TOOL_OBSERVATION,
            summary=summary,
            supports_claims=[claim],
            verification_method=VerificationMethod.DIRECT_OBSERVATION,
            confidence=1.0 if result.status is ToolResultStatus.SUCCEEDED else 0.0,
            created_at=observed_at,
        )

    @staticmethod
    def _policy_denial_result(invocation: ToolInvocation, decision: PolicyDecision, observed_at: UtcDateTime) -> ToolResult:
        code = decision.reason_codes[0] if decision.reason_codes else "INCIDENT_POLICY_DENIED"
        return ToolResult(
            run_id=invocation.run_id,
            plan_id=invocation.plan_id,
            step_id=invocation.step_id,
            attempt=invocation.attempt,
            tool_ref=invocation.tool_ref,
            validated_arguments=invocation.validated_arguments,
            policy_decision_ref=decision.decision_id,
            status=ToolResultStatus.DENIED,
            started_at=observed_at,
            finished_at=observed_at,
            normalized_output={"observation_type": "policy_denial", "reason_codes": list(decision.reason_codes)},
            error=ErrorInfo(
                code=code,
                category=ErrorCategory.POLICY_DENIED,
                retryable=False,
                safe_message="Incident action was denied before execution.",
            ),
            environment_fingerprint="0" * 64,
        )

    @staticmethod
    def _validate_manifest(manifest: TaskPackManifest) -> None:
        if manifest.task_pack_id != INCIDENT_LOGIN_CHAIN_TASK_PACK_ID:
            raise ValueError("unexpected incident task pack id")
        if manifest.version != INCIDENT_LOGIN_CHAIN_TASK_PACK_VERSION:
            raise ValueError("unexpected incident task pack version")
        if manifest.task_type != INCIDENT_LOGIN_CHAIN_TASK_TYPE:
            raise ValueError("unexpected incident task type")
        if manifest.required_tools != INCIDENT_LOGIN_CHAIN_REQUIRED_TOOLS:
            raise ValueError("incident required_tools must match the fixed pipeline")
        if manifest.verifier != INCIDENT_LOGIN_CHAIN_VERIFIER_ID:
            raise ValueError("unexpected incident verifier")
        if manifest.report_template != INCIDENT_LOGIN_CHAIN_REPORT_TEMPLATE:
            raise ValueError("unexpected incident report template")
        if manifest.security_policy != INCIDENT_LOGIN_CHAIN_SECURITY_POLICY:
            raise ValueError("unexpected incident security policy")


__all__ = ["IncidentLoginChainScenarioAdapter"]
