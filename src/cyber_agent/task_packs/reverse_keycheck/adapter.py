"""ScenarioAdapter for the fixed two-stage reverse keycheck pipeline."""

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
from cyber_agent.tools.reverse_static import StaticExtractResult
from cyber_agent.tools.reverse_run import RunVerifyResult

from .config import ReverseKeycheckScenarioConfig
from .manifest import (
    REVERSE_KEYCHECK_REPORT_TEMPLATE,
    REVERSE_KEYCHECK_REQUIRED_TOOLS,
    REVERSE_KEYCHECK_RUN_CAPABILITY,
    REVERSE_KEYCHECK_RUN_TOOL_ID,
    REVERSE_KEYCHECK_SECURITY_POLICY,
    REVERSE_KEYCHECK_STATIC_CAPABILITY,
    REVERSE_KEYCHECK_STATIC_TOOL_ID,
    REVERSE_KEYCHECK_TASK_PACK_ID,
    REVERSE_KEYCHECK_TASK_PACK_VERSION,
    REVERSE_KEYCHECK_TASK_TYPE,
    REVERSE_KEYCHECK_VERIFIER_ID,
)


@dataclass(slots=True)
class _OpenRun:
    task_id: UUID
    artifact_id: UUID
    step_tools: dict[UUID, str] = field(default_factory=dict)
    extracted: StaticExtractResult | None = None


class ReverseKeycheckScenarioAdapter:
    """Bind a trusted binary through static extraction and run verification."""

    def __init__(self, config: ReverseKeycheckScenarioConfig) -> None:
        self._config = ReverseKeycheckScenarioConfig.model_validate(
            config.model_dump(mode="python")
        )
        self._validated_tasks: dict[UUID, str] = {}
        self._open_runs: dict[UUID, _OpenRun] = {}
        self._lifecycle: list[str] = []

    @property
    def config(self) -> ReverseKeycheckScenarioConfig:
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
            raise ValueError("reverse adapter accepts only ready tasks")
        if REVERSE_KEYCHECK_TASK_TYPE not in task.scenario_hints:
            raise ValueError("task does not declare the reverse keycheck task type")
        if task.scope.network_access or self._config.network_access:
            raise ValueError("reverse keycheck pipeline forbids network access")
        if task.scope.allowed_tool_ids != set(self._config.allowed_tools):
            raise ValueError("task policy must allow exactly the reverse keycheck tools")
        if any(target.kind is not TargetKind.FILE for target in task.scope.allowed_targets):
            raise ValueError("reverse keycheck policy accepts only file targets")
        if any(target.protocols - {"file"} for target in task.scope.allowed_targets):
            raise ValueError("reverse keycheck file targets may use only the file protocol")

        artifacts = [
            item
            for item in task.input_artifacts
            if item.artifact_id == self._config.artifact_id
        ]
        if len(artifacts) != 1:
            raise ValueError("task must reference the configured binary exactly once")
        artifact = artifacts[0]
        if artifact.sha256 != self._config.artifact_sha256:
            raise ValueError("binary artifact hash does not match trusted config")
        if artifact.media_type != "application/octet-stream":
            raise ValueError("binary artifact must use application/octet-stream")
        if not any(
            target.kind is TargetKind.FILE and target.value == artifact.logical_uri
            for target in task.scope.allowed_targets
        ):
            raise ValueError("binary artifact is not present in the task file scope")
        if task.constraints.budget.max_steps < 2:
            raise ValueError("task budget cannot hold the two reverse steps")
        if task.constraints.budget.max_tool_calls < 2:
            raise ValueError("task budget cannot execute the two reverse tools")

        self._validated_tasks[task.task_id] = artifact.logical_uri
        self._lifecycle.append("validate_task")

    def open_run(self, task: Task, run: Run, manifest: TaskPackManifest) -> None:
        self._validate_manifest(manifest)
        if task.task_id not in self._validated_tasks:
            raise ValueError("task must be validated before opening a run")
        if run.task_id != task.task_id:
            raise ValueError("run does not belong to the validated task")
        if run.run_id in self._open_runs:
            raise ValueError("reverse adapter run is already open")
        self._open_runs[run.run_id] = _OpenRun(
            task_id=task.task_id,
            artifact_id=self._config.artifact_id,
        )
        self._lifecycle.append("open_run")

    def validate_plan(
        self,
        task: Task,
        run: Run,
        proposal: PlanProposal,
        manifest: TaskPackManifest,
    ) -> None:
        self._require_context(task, run)
        self._validate_manifest(manifest)
        if proposal.plan.run_id != run.run_id:
            raise ValueError("plan does not belong to the open reverse run")
        if proposal.plan.step_ids != [item.step_id for item in proposal.steps]:
            raise ValueError("plan step references do not match its proposal")
        if len(proposal.steps) != 2:
            raise ValueError("reverse plan requires exactly two ordered steps")
        extract, run_verify = proposal.steps
        if [item.ordinal for item in proposal.steps] != [1, 2]:
            raise ValueError("reverse steps must use ordinals 1 and 2")
        if extract.depends_on:
            raise ValueError("reverse.static_extract must be the root step")
        if run_verify.depends_on != [extract.step_id]:
            raise ValueError("reverse.run_verify must depend on static_extract")
        expected_capabilities = [
            [REVERSE_KEYCHECK_STATIC_CAPABILITY],
            [REVERSE_KEYCHECK_RUN_CAPABILITY],
        ]
        if [item.required_capabilities for item in proposal.steps] != expected_capabilities:
            raise ValueError("reverse plan capabilities must match the fixed pipeline")
        expected_edges = {(extract.step_id, run_verify.step_id)}
        actual_edges = {
            (item.before, item.after) for item in proposal.plan.dependency_edges
        }
        if actual_edges != expected_edges:
            raise ValueError("reverse dependency edges must match the fixed pipeline")
        state = self._require_context(task, run)
        state.step_tools = {
            extract.step_id: REVERSE_KEYCHECK_STATIC_TOOL_ID,
            run_verify.step_id: REVERSE_KEYCHECK_RUN_TOOL_ID,
        }
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
        state = self._require_context(task, run)
        self._validate_step_context(run, plan, step)
        expected_tool = state.step_tools.get(step.step_id)
        if expected_tool is None:
            raise ValueError("reverse step was not approved by validate_plan")
        expected_capability = self._capability_for_tool(expected_tool)
        if action.tool_id != expected_tool or tool_spec.tool_id != expected_tool:
            raise ValueError("reverse action does not match the fixed step tool")
        if action.capability != expected_capability:
            raise ValueError("reverse action does not match the fixed step capability")
        if action.capability not in step.required_capabilities:
            raise ValueError("selected capability is not required by the bound step")
        if action.capability not in tool_spec.capabilities:
            raise ValueError("selected tool does not provide the required capability")
        if tool_spec.permissions.network or tool_spec.side_effects & {
            SideEffect.NETWORK_READ,
            SideEffect.NETWORK_ACTIVE,
        }:
            raise ValueError("reverse tools must not use network access")
        if tool_spec.execution_profile.runner is not RunnerType.SOURCE_ANALYSIS:
            raise ValueError("reverse tools must use the SOURCE_ANALYSIS runner")

        if expected_tool == REVERSE_KEYCHECK_STATIC_TOOL_ID:
            self._validate_artifact_arguments(
                action.arguments,
                expected_keys={"artifact_id", "artifact_sha256"},
            )
        else:
            self._bind_run_arguments(action, state)
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
        if (
            invocation.run_id != run.run_id
            or invocation.plan_id != plan.plan_id
            or invocation.step_id != step.step_id
        ):
            raise ValueError("invocation does not match the active reverse step")
        expected_tool = state.step_tools.get(step.step_id)
        if invocation.tool_ref.tool_id != expected_tool:
            raise ValueError("reverse invocation references an unexpected tool")
        if invocation.policy_decision_ref != policy_decision.decision_id:
            raise ValueError("invocation does not reference the supplied policy decision")
        if policy_decision.policy_version != REVERSE_KEYCHECK_SECURITY_POLICY:
            raise ValueError("reverse policy decision uses an unexpected version")
        self._validate_invocation_arguments(invocation.validated_arguments, expected_tool, state)

        if policy_decision.allowed:
            if result is None:
                raise ValueError("an allowed reverse invocation requires a tool result")
            normalized_result = self._validate_result(result, invocation, state)
            evidence = self._evidence_for_result(normalized_result, observed_at)
        else:
            if result is not None:
                raise ValueError("a denied reverse invocation cannot have an executed result")
            normalized_result = self._policy_denial_result(
                invocation, policy_decision, observed_at
            )
            evidence = Evidence(
                run_id=run.run_id,
                source_ref=EntityRef(
                    entity_type="tool_result",
                    entity_id=normalized_result.result_id,
                ),
                kind=EvidenceKind.RULE_VERIFICATION,
                summary=(
                    f"Policy prevented {expected_tool} before execution; no external "
                    "side effect occurred."
                ),
                supports_claims=["reverse.policy_enforced"],
                verification_method=VerificationMethod.RULE,
                confidence=1.0,
                created_at=observed_at,
            )

        self._lifecycle.append("build_observation")
        return ScenarioObservation(result=normalized_result, evidence=[evidence])

    def close_run(self, run_id: UUID) -> None:
        state = self._open_runs.pop(run_id, None)
        if state is None:
            raise ValueError("reverse adapter run is not open")
        if not any(item.task_id == state.task_id for item in self._open_runs.values()):
            self._validated_tasks.pop(state.task_id, None)
        self._lifecycle.append("close_run")

    def _require_context(self, task: Task, run: Run) -> _OpenRun:
        state = self._open_runs.get(run.run_id)
        if state is None:
            raise ValueError("reverse adapter run is not open")
        if state.task_id != task.task_id or run.task_id != task.task_id:
            raise ValueError("task and run do not match the open reverse context")
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
            raise ValueError("reverse arguments contain unexpected fields")
        if arguments.get("artifact_id") != str(self._config.artifact_id):
            raise ValueError("reverse artifact binding does not match trusted config")
        if arguments.get("artifact_sha256") != self._config.artifact_sha256:
            raise ValueError("reverse artifact hash does not match trusted config")

    @staticmethod
    def _capability_for_tool(tool_id: str) -> str:
        capabilities = {
            REVERSE_KEYCHECK_STATIC_TOOL_ID: REVERSE_KEYCHECK_STATIC_CAPABILITY,
            REVERSE_KEYCHECK_RUN_TOOL_ID: REVERSE_KEYCHECK_RUN_CAPABILITY,
        }
        try:
            return capabilities[tool_id]
        except KeyError as exc:
            raise ValueError("unsupported reverse tool") from exc

    def _bind_run_arguments(self, action: CandidateAction, state: _OpenRun) -> None:
        if state.extracted is None:
            raise ValueError("reverse.run_verify cannot run before static_extract")
        self._validate_artifact_arguments(
            action.arguments,
            expected_keys={"artifact_id", "artifact_sha256", "candidate"},
        )
        expected_key = bytes(
            byte ^ state.extracted.transform_constant
            for byte in state.extracted.target_bytes
        ).decode("utf-8", errors="replace")
        if action.arguments.get("candidate") != expected_key:
            raise ValueError("run candidate must match the key derived from static extraction")
        action.arguments = {
            "artifact_id": str(self._config.artifact_id),
            "artifact_sha256": self._config.artifact_sha256,
            "candidate": expected_key,
        }

    def _validate_invocation_arguments(
        self,
        arguments: dict,
        tool_id: str | None,
        state: _OpenRun,
    ) -> None:
        if tool_id == REVERSE_KEYCHECK_STATIC_TOOL_ID:
            self._validate_artifact_arguments(
                arguments,
                expected_keys={"artifact_id", "artifact_sha256"},
            )
            return
        if tool_id == REVERSE_KEYCHECK_RUN_TOOL_ID:
            self._validate_artifact_arguments(
                arguments,
                expected_keys={"artifact_id", "artifact_sha256", "candidate"},
            )
            if state.extracted is None:
                raise ValueError("run_verify invocation has no prior extraction")
            expected_key = bytes(
                byte ^ state.extracted.transform_constant
                for byte in state.extracted.target_bytes
            ).decode("utf-8", errors="replace")
            if arguments.get("candidate") != expected_key:
                raise ValueError("run candidate is not bound to the prior extraction")
            return
        raise ValueError("reverse invocation references an unsupported tool")

    def _validate_result(
        self,
        result: ToolResult,
        invocation: ToolInvocation,
        state: _OpenRun,
    ) -> ToolResult:
        if (
            result.run_id != invocation.run_id
            or result.plan_id != invocation.plan_id
            or result.step_id != invocation.step_id
            or result.tool_ref != invocation.tool_ref
            or result.policy_decision_ref != invocation.policy_decision_ref
            or result.validated_arguments != invocation.validated_arguments
        ):
            raise ValueError("tool result does not match its reverse invocation")
        tool_id = result.tool_ref.tool_id
        if tool_id == REVERSE_KEYCHECK_STATIC_TOOL_ID:
            extracted = StaticExtractResult.model_validate(result.normalized_output)
            self._validate_output_artifact(extracted.artifact_id, extracted.artifact_sha256)
            state.extracted = extracted
        elif tool_id == REVERSE_KEYCHECK_RUN_TOOL_ID:
            run = RunVerifyResult.model_validate(result.normalized_output)
            self._validate_output_artifact(run.artifact_id, run.artifact_sha256)
        else:
            raise ValueError("reverse result references an unsupported tool")
        return result

    def _validate_output_artifact(self, artifact_id: UUID, artifact_sha256: str) -> None:
        if artifact_id != self._config.artifact_id:
            raise ValueError("reverse output artifact id does not match trusted config")
        if artifact_sha256 != self._config.artifact_sha256:
            raise ValueError("reverse output artifact hash does not match trusted config")

    @staticmethod
    def _evidence_for_result(result: ToolResult, observed_at: UtcDateTime) -> Evidence:
        if result.tool_ref.tool_id == REVERSE_KEYCHECK_STATIC_TOOL_ID:
            claim = "reverse.static_extract"
            extracted = StaticExtractResult.model_validate(result.normalized_output)
            summary = (
                f"Static extraction recovered {extracted.file_format} with transform "
                f"constant={extracted.transform_constant} and "
                f"target_hex={bytes(extracted.target_bytes).hex()}."
            )
        elif result.tool_ref.tool_id == REVERSE_KEYCHECK_RUN_TOOL_ID:
            claim = "reverse.run_verify"
            summary = "A candidate key was replayed through the keycheck checker."
        else:
            raise ValueError("cannot create evidence for an unsupported reverse tool")
        return Evidence(
            run_id=result.run_id,
            source_ref=EntityRef(
                entity_type="tool_result",
                entity_id=result.result_id,
            ),
            kind=EvidenceKind.TOOL_OBSERVATION,
            summary=summary,
            supports_claims=[claim],
            verification_method=VerificationMethod.DIRECT_OBSERVATION,
            confidence=1.0 if result.status is ToolResultStatus.SUCCEEDED else 0.0,
            created_at=observed_at,
        )

    @staticmethod
    def _policy_denial_result(
        invocation: ToolInvocation,
        decision: PolicyDecision,
        observed_at: UtcDateTime,
    ) -> ToolResult:
        code = (
            decision.reason_codes[0]
            if decision.reason_codes
            else "REVERSE_POLICY_DENIED"
        )
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
            normalized_output={
                "observation_type": "policy_denial",
                "reason_codes": list(decision.reason_codes),
            },
            error=ErrorInfo(
                code=code,
                category=ErrorCategory.POLICY_DENIED,
                retryable=False,
                safe_message="Reverse action was denied before execution.",
            ),
            environment_fingerprint="0" * 64,
        )

    @staticmethod
    def _validate_manifest(manifest: TaskPackManifest) -> None:
        if manifest.task_pack_id != REVERSE_KEYCHECK_TASK_PACK_ID:
            raise ValueError("unexpected reverse task pack id")
        if manifest.version != REVERSE_KEYCHECK_TASK_PACK_VERSION:
            raise ValueError("unexpected reverse task pack version")
        if manifest.task_type != REVERSE_KEYCHECK_TASK_TYPE:
            raise ValueError("unexpected reverse task type")
        if manifest.required_tools != REVERSE_KEYCHECK_REQUIRED_TOOLS:
            raise ValueError("reverse required_tools must match the fixed pipeline")
        if manifest.verifier != REVERSE_KEYCHECK_VERIFIER_ID:
            raise ValueError("unexpected reverse verifier")
        if manifest.report_template != REVERSE_KEYCHECK_REPORT_TEMPLATE:
            raise ValueError("unexpected reverse report template")
        if manifest.security_policy != REVERSE_KEYCHECK_SECURITY_POLICY:
            raise ValueError("unexpected reverse security policy")


__all__ = ["ReverseKeycheckScenarioAdapter"]
