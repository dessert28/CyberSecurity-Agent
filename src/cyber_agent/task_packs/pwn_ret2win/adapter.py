"""ScenarioAdapter for the fixed two-stage Pwn ret2win pipeline."""

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
from cyber_agent.tools.pwn_binary import BinaryPropertiesResult
from cyber_agent.tools.pwn_interaction import ProcessInteractionResult

from .config import PwnRet2winScenarioConfig
from .manifest import (
    PWN_RET2WIN_BINARY_CAPABILITY,
    PWN_RET2WIN_BINARY_TOOL_ID,
    PWN_RET2WIN_INTERACTION_CAPABILITY,
    PWN_RET2WIN_INTERACTION_TOOL_ID,
    PWN_RET2WIN_REPORT_TEMPLATE,
    PWN_RET2WIN_REQUIRED_TOOLS,
    PWN_RET2WIN_SECURITY_POLICY,
    PWN_RET2WIN_TASK_PACK_ID,
    PWN_RET2WIN_TASK_PACK_VERSION,
    PWN_RET2WIN_TASK_TYPE,
    PWN_RET2WIN_VERIFIER_ID,
)

_FORBIDDEN_CONCLUSION_KEYS = {"answer_key", "flag", "verdict", "vulnerable", "is_vulnerable"}


@dataclass(slots=True)
class _OpenRun:
    task_id: UUID
    artifact_id: UUID
    step_tools: dict[UUID, str] = field(default_factory=dict)
    properties: BinaryPropertiesResult | None = None


class PwnRet2winScenarioAdapter:
    """Bind a trusted executable through binary properties and interaction."""

    def __init__(self, config: PwnRet2winScenarioConfig) -> None:
        self._config = PwnRet2winScenarioConfig.model_validate(
            config.model_dump(mode="python")
        )
        self._validated_tasks: dict[UUID, str] = {}
        self._open_runs: dict[UUID, _OpenRun] = {}
        self._lifecycle: list[str] = []

    @property
    def config(self) -> PwnRet2winScenarioConfig:
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
            raise ValueError("Pwn adapter accepts only ready tasks")
        if PWN_RET2WIN_TASK_TYPE not in task.scenario_hints:
            raise ValueError("task does not declare the Pwn ret2win task type")
        remote = self._config.target_host is not None
        if bool(task.scope.network_access) != remote or bool(self._config.network_access) != remote:
            raise ValueError("Pwn ret2win network access must match its remote target")
        if task.scope.allowed_tool_ids != set(self._config.allowed_tools):
            raise ValueError("task policy must allow exactly the Pwn ret2win tools")
        file_targets = [t for t in task.scope.allowed_targets if t.kind is TargetKind.FILE]
        if not file_targets or any(t.protocols - {"file"} for t in file_targets):
            raise ValueError("Pwn ret2win file targets may use only the file protocol")
        non_file = [t for t in task.scope.allowed_targets if t.kind is not TargetKind.FILE]
        if remote:
            if len(non_file) != 1 or non_file[0].kind is not TargetKind.HOST:
                raise ValueError("Pwn remote mode requires exactly one loopback host target")
            if non_file[0].value != self._config.target_host:
                raise ValueError("Pwn host target does not match trusted config")
            if non_file[0].ports != {self._config.target_port}:
                raise ValueError("Pwn host port does not match trusted config")
        elif non_file:
            raise ValueError("Pwn ret2win policy accepts only file targets")

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
        if artifact.media_type != "application/x-executable":
            raise ValueError("binary artifact must use application/x-executable")
        if not any(
            target.kind is TargetKind.FILE and target.value == artifact.logical_uri
            for target in task.scope.allowed_targets
        ):
            raise ValueError("binary artifact is not present in the task file scope")
        if task.constraints.budget.max_steps < 2:
            raise ValueError("task budget cannot hold the two Pwn steps")
        if task.constraints.budget.max_tool_calls < 2:
            raise ValueError("task budget cannot execute the two Pwn tools")

        self._validated_tasks[task.task_id] = artifact.logical_uri
        self._lifecycle.append("validate_task")

    def open_run(self, task: Task, run: Run, manifest: TaskPackManifest) -> None:
        self._validate_manifest(manifest)
        if task.task_id not in self._validated_tasks:
            raise ValueError("task must be validated before opening a run")
        if run.task_id != task.task_id:
            raise ValueError("run does not belong to the validated task")
        if run.run_id in self._open_runs:
            raise ValueError("Pwn adapter run is already open")
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
            raise ValueError("plan does not belong to the open Pwn run")
        if proposal.plan.step_ids != [item.step_id for item in proposal.steps]:
            raise ValueError("plan step references do not match its proposal")
        if len(proposal.steps) != 2:
            raise ValueError("Pwn plan requires exactly two ordered steps")
        properties, interaction = proposal.steps
        if [item.ordinal for item in proposal.steps] != [1, 2]:
            raise ValueError("Pwn steps must use ordinals 1 and 2")
        if properties.depends_on:
            raise ValueError("pwn.binary_properties must be the root step")
        if interaction.depends_on != [properties.step_id]:
            raise ValueError("pwn.process_interaction must depend on binary_properties")
        expected_capabilities = [
            [PWN_RET2WIN_BINARY_CAPABILITY],
            [PWN_RET2WIN_INTERACTION_CAPABILITY],
        ]
        if [item.required_capabilities for item in proposal.steps] != expected_capabilities:
            raise ValueError("Pwn plan capabilities must match the fixed pipeline")
        expected_edges = {(properties.step_id, interaction.step_id)}
        actual_edges = {
            (item.before, item.after) for item in proposal.plan.dependency_edges
        }
        if actual_edges != expected_edges:
            raise ValueError("Pwn dependency edges must match the fixed pipeline")
        state = self._require_context(task, run)
        state.step_tools = {
            properties.step_id: PWN_RET2WIN_BINARY_TOOL_ID,
            interaction.step_id: PWN_RET2WIN_INTERACTION_TOOL_ID,
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
            raise ValueError("Pwn step was not approved by validate_plan")
        expected_capability = self._capability_for_tool(expected_tool)
        if action.tool_id != expected_tool or tool_spec.tool_id != expected_tool:
            raise ValueError("Pwn action does not match the fixed step tool")
        if action.capability != expected_capability:
            raise ValueError("Pwn action does not match the fixed step capability")
        if action.capability not in step.required_capabilities:
            raise ValueError("selected capability is not required by the bound step")
        if action.capability not in tool_spec.capabilities:
            raise ValueError("selected tool does not provide the required capability")
        if tool_spec.permissions.network or tool_spec.side_effects & {
            SideEffect.NETWORK_READ,
            SideEffect.NETWORK_ACTIVE,
        }:
            raise ValueError("Pwn tools must not use network access")
        if tool_spec.execution_profile.runner is not RunnerType.SOURCE_ANALYSIS:
            raise ValueError("Pwn tools must use the SOURCE_ANALYSIS runner")

        if expected_tool == PWN_RET2WIN_BINARY_TOOL_ID:
            self._validate_artifact_arguments(
                action.arguments,
                expected_keys={"artifact_id", "artifact_sha256"},
            )
        else:
            self._bind_interaction_arguments(action, state)
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
            raise ValueError("invocation does not match the active Pwn step")
        expected_tool = state.step_tools.get(step.step_id)
        if invocation.tool_ref.tool_id != expected_tool:
            raise ValueError("Pwn invocation references an unexpected tool")
        if invocation.policy_decision_ref != policy_decision.decision_id:
            raise ValueError("invocation does not reference the supplied policy decision")
        if policy_decision.policy_version != PWN_RET2WIN_SECURITY_POLICY:
            raise ValueError("Pwn policy decision uses an unexpected version")
        self._validate_invocation_arguments(invocation.validated_arguments, expected_tool, state)

        if policy_decision.allowed:
            if result is None:
                raise ValueError("an allowed Pwn invocation requires a tool result")
            normalized_result = self._validate_result(result, invocation, state)
            evidence = self._evidence_for_result(normalized_result, observed_at)
        else:
            if result is not None:
                raise ValueError("a denied Pwn invocation cannot have an executed result")
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
                supports_claims=["pwn.policy_enforced"],
                verification_method=VerificationMethod.RULE,
                confidence=1.0,
                created_at=observed_at,
            )

        self._lifecycle.append("build_observation")
        return ScenarioObservation(result=normalized_result, evidence=[evidence])

    def close_run(self, run_id: UUID) -> None:
        state = self._open_runs.pop(run_id, None)
        if state is None:
            raise ValueError("Pwn adapter run is not open")
        if not any(item.task_id == state.task_id for item in self._open_runs.values()):
            self._validated_tasks.pop(state.task_id, None)
        self._lifecycle.append("close_run")

    def _require_context(self, task: Task, run: Run) -> _OpenRun:
        state = self._open_runs.get(run.run_id)
        if state is None:
            raise ValueError("Pwn adapter run is not open")
        if state.task_id != task.task_id or run.task_id != task.task_id:
            raise ValueError("task and run do not match the open Pwn context")
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
            raise ValueError("Pwn arguments contain unexpected fields")
        if arguments.get("artifact_id") != str(self._config.artifact_id):
            raise ValueError("Pwn artifact binding does not match trusted config")
        if arguments.get("artifact_sha256") != self._config.artifact_sha256:
            raise ValueError("Pwn artifact hash does not match trusted config")

    @staticmethod
    def _capability_for_tool(tool_id: str) -> str:
        capabilities = {
            PWN_RET2WIN_BINARY_TOOL_ID: PWN_RET2WIN_BINARY_CAPABILITY,
            PWN_RET2WIN_INTERACTION_TOOL_ID: PWN_RET2WIN_INTERACTION_CAPABILITY,
        }
        try:
            return capabilities[tool_id]
        except KeyError as exc:
            raise ValueError("unsupported Pwn tool") from exc

    def _bind_interaction_arguments(self, action: CandidateAction, state: _OpenRun) -> None:
        if state.properties is None:
            raise ValueError("pwn.process_interaction cannot run before binary_properties")
        remote = self._config.target_host is not None
        expected_keys = {
            "artifact_id",
            "artifact_sha256",
            "padding_length",
            "target_address",
        }
        if remote:
            expected_keys |= {"host", "port"}
        self._validate_artifact_arguments(action.arguments, expected_keys=expected_keys)
        if action.arguments.get("padding_length") != state.properties.return_offset:
            raise ValueError("exploit padding must match the analyzed return offset")
        if action.arguments.get("target_address") != state.properties.win_symbol.address:
            raise ValueError("exploit target must match the analyzed win address")
        bound: dict[str, object] = {
            "artifact_id": str(self._config.artifact_id),
            "artifact_sha256": self._config.artifact_sha256,
            "padding_length": state.properties.return_offset,
            "target_address": state.properties.win_symbol.address,
        }
        if remote:
            if action.arguments.get("host") != self._config.target_host:
                raise ValueError("exploit host must match the trusted remote target")
            if action.arguments.get("port") != self._config.target_port:
                raise ValueError("exploit port must match the trusted remote target")
            bound["host"] = self._config.target_host
            bound["port"] = self._config.target_port
        action.arguments = bound

    def _validate_invocation_arguments(
        self,
        arguments: dict,
        tool_id: str | None,
        state: _OpenRun,
    ) -> None:
        if tool_id == PWN_RET2WIN_BINARY_TOOL_ID:
            self._validate_artifact_arguments(
                arguments,
                expected_keys={"artifact_id", "artifact_sha256"},
            )
            return
        if tool_id == PWN_RET2WIN_INTERACTION_TOOL_ID:
            remote = self._config.target_host is not None
            expected_keys = {
                "artifact_id",
                "artifact_sha256",
                "padding_length",
                "target_address",
            }
            if remote:
                expected_keys |= {"host", "port"}
            self._validate_artifact_arguments(arguments, expected_keys=expected_keys)
            if state.properties is None:
                raise ValueError("process_interaction invocation has no prior analysis")
            if arguments.get("padding_length") != state.properties.return_offset:
                raise ValueError("interaction padding is not bound to the prior analysis")
            if arguments.get("target_address") != state.properties.win_symbol.address:
                raise ValueError("interaction target is not bound to the prior analysis")
            if remote:
                if arguments.get("host") != self._config.target_host:
                    raise ValueError("interaction host is not bound to the trusted target")
                if arguments.get("port") != self._config.target_port:
                    raise ValueError("interaction port is not bound to the trusted target")
            return
        raise ValueError("Pwn invocation references an unsupported tool")

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
            raise ValueError("tool result does not match its Pwn invocation")
        tool_id = result.tool_ref.tool_id
        if tool_id == PWN_RET2WIN_BINARY_TOOL_ID:
            properties = BinaryPropertiesResult.model_validate(result.normalized_output)
            self._validate_output_artifact(properties.artifact_id, properties.artifact_sha256)
            state.properties = properties
        elif tool_id == PWN_RET2WIN_INTERACTION_TOOL_ID:
            interaction = ProcessInteractionResult.model_validate(result.normalized_output)
            self._validate_output_artifact(interaction.artifact_id, interaction.artifact_sha256)
            if state.properties is None:
                raise ValueError("interaction result arrived before binary properties")
        else:
            raise ValueError("Pwn result references an unsupported tool")
        return result

    def _validate_output_artifact(self, artifact_id: UUID, artifact_sha256: str) -> None:
        if artifact_id != self._config.artifact_id:
            raise ValueError("Pwn output artifact id does not match trusted config")
        if artifact_sha256 != self._config.artifact_sha256:
            raise ValueError("Pwn output artifact hash does not match trusted config")

    @staticmethod
    def _evidence_for_result(result: ToolResult, observed_at: UtcDateTime) -> Evidence:
        if result.tool_ref.tool_id == PWN_RET2WIN_BINARY_TOOL_ID:
            claim = "pwn.binary_properties"
            properties = BinaryPropertiesResult.model_validate(result.normalized_output)
            summary = (
                f"Binary properties recovered {properties.architecture} with "
                f"return_offset={properties.return_offset} and "
                f"win_address={properties.win_symbol.address:#x}."
            )
        elif result.tool_ref.tool_id == PWN_RET2WIN_INTERACTION_TOOL_ID:
            claim = "pwn.process_interaction"
            summary = "A structured payload was replayed through the ret2win runner."
        else:
            raise ValueError("cannot create evidence for an unsupported Pwn tool")
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
            else "PWN_POLICY_DENIED"
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
                safe_message="Pwn action was denied before execution.",
            ),
            environment_fingerprint="0" * 64,
        )

    @staticmethod
    def _validate_manifest(manifest: TaskPackManifest) -> None:
        if manifest.task_pack_id != PWN_RET2WIN_TASK_PACK_ID:
            raise ValueError("unexpected Pwn task pack id")
        if manifest.version != PWN_RET2WIN_TASK_PACK_VERSION:
            raise ValueError("unexpected Pwn task pack version")
        if manifest.task_type != PWN_RET2WIN_TASK_TYPE:
            raise ValueError("unexpected Pwn task type")
        if manifest.required_tools != PWN_RET2WIN_REQUIRED_TOOLS:
            raise ValueError("Pwn required_tools must match the fixed pipeline")
        if manifest.verifier != PWN_RET2WIN_VERIFIER_ID:
            raise ValueError("unexpected Pwn verifier")
        if manifest.report_template != PWN_RET2WIN_REPORT_TEMPLATE:
            raise ValueError("unexpected Pwn report template")
        if manifest.security_policy != PWN_RET2WIN_SECURITY_POLICY:
            raise ValueError("unexpected Pwn security policy")


__all__ = ["PwnRet2winScenarioAdapter"]
