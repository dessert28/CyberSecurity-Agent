"""ScenarioAdapter for the fixed three-stage Python source-audit pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from uuid import UUID

from cyber_agent.contracts.common import (
    EntityRef,
    ErrorCategory,
    ErrorInfo,
    UtcDateTime,
)
from cyber_agent.contracts.evidence import (
    Evidence,
    EvidenceKind,
    VerificationMethod,
)
from cyber_agent.contracts.plan import CandidateAction, Plan, PlanProposal, Run, Step
from cyber_agent.contracts.task import TargetKind, Task, TaskStatus
from cyber_agent.contracts.task_pack import ScenarioObservation, TaskPackManifest
from cyber_agent.contracts.tool import (
    PolicyDecision,
    SideEffect,
    ToolInvocation,
    ToolInvocationStatus,
    ToolResult,
    ToolResultStatus,
    RunnerType,
    ToolSpec,
)
from cyber_agent.tools.hypothesis_validate import HypothesisValidationResult
from cyber_agent.tools.project_inventory import ProjectInventoryResult
from cyber_agent.tools.python_dataflow import (
    DataflowAnalysisResult,
    DataflowHypothesis,
    PythonDataflowAnalyzer,
)

from .config import SourceAuditScenarioConfig
from .manifest import (
    SOURCE_AUDIT_DATAFLOW_CAPABILITY,
    SOURCE_AUDIT_DATAFLOW_TOOL_ID,
    SOURCE_AUDIT_INVENTORY_CAPABILITY,
    SOURCE_AUDIT_INVENTORY_TOOL_ID,
    SOURCE_AUDIT_REPORT_TEMPLATE,
    SOURCE_AUDIT_REQUIRED_TOOLS,
    SOURCE_AUDIT_SECURITY_POLICY,
    SOURCE_AUDIT_TASK_PACK_ID,
    SOURCE_AUDIT_TASK_PACK_VERSION,
    SOURCE_AUDIT_TASK_TYPE,
    SOURCE_AUDIT_VALIDATION_CAPABILITY,
    SOURCE_AUDIT_VALIDATION_TOOL_ID,
    SOURCE_AUDIT_VERIFIER_ID,
)

_SHELL_ENTRYPOINTS = {"bash", "sh", "powershell", "pwsh", "cmd", "cmd.exe"}
_FORBIDDEN_CONCLUSION_KEYS = {
    "answer_key",
    "finding",
    "is_vulnerable",
    "verdict",
    "vulnerability",
    "vulnerable",
}


@dataclass(frozen=True, slots=True)
class _ValidatedTask:
    artifact_logical_uri: str


@dataclass(slots=True)
class _OpenRun:
    task_id: UUID
    artifact_id: UUID
    step_tools: dict[UUID, str] = field(default_factory=dict)
    completed_results: dict[str, ToolResult] = field(default_factory=dict)
    inventory: ProjectInventoryResult | None = None
    hypotheses: dict[str, DataflowHypothesis] = field(default_factory=dict)


class SourceAuditScenarioAdapter:
    """Bind a trusted ZIP through inventory, dataflow, and controlled validation."""

    def __init__(self, config: SourceAuditScenarioConfig) -> None:
        self._config = SourceAuditScenarioConfig.model_validate(
            config.model_dump(mode="python")
        )
        self._validated_tasks: dict[UUID, _ValidatedTask] = {}
        self._open_runs: dict[UUID, _OpenRun] = {}
        self._lifecycle: list[str] = []

    @property
    def config(self) -> SourceAuditScenarioConfig:
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
            raise ValueError("source-audit adapter accepts only ready tasks")
        if SOURCE_AUDIT_TASK_TYPE not in task.scenario_hints:
            raise ValueError("task does not declare the source-audit task type")
        if task.scope.network_access or self._config.network_access:
            raise ValueError("source-audit pipeline forbids network access")
        if task.scope.allowed_tool_ids != set(self._config.allowed_tools):
            raise ValueError("task policy must allow exactly the source-audit tools")
        if any(target.kind is not TargetKind.FILE for target in task.scope.allowed_targets):
            raise ValueError("source-audit policy accepts only file targets")
        if any(target.protocols - {"file"} for target in task.scope.allowed_targets):
            raise ValueError("source-audit file targets may use only the file protocol")

        artifacts = [
            item
            for item in task.input_artifacts
            if item.artifact_id == self._config.artifact_id
        ]
        if len(artifacts) != 1:
            raise ValueError("task must reference the configured source artifact exactly once")
        artifact = artifacts[0]
        if artifact.sha256 != self._config.artifact_sha256:
            raise ValueError("source artifact hash does not match trusted config")
        if artifact.media_type != "application/zip":
            raise ValueError("source artifact must use application/zip")
        if not any(
            target.kind is TargetKind.FILE and target.value == artifact.logical_uri
            for target in task.scope.allowed_targets
        ):
            raise ValueError("source artifact is not present in the task file scope")
        if task.constraints.budget.max_steps < 3:
            raise ValueError("task budget cannot hold the three source-audit steps")
        if task.constraints.budget.max_tool_calls < 3:
            raise ValueError("task budget cannot execute the three source-audit tools")

        self._validated_tasks[task.task_id] = _ValidatedTask(
            artifact_logical_uri=artifact.logical_uri
        )
        self._lifecycle.append("validate_task")

    def open_run(
        self,
        task: Task,
        run: Run,
        manifest: TaskPackManifest,
    ) -> None:
        self._validate_manifest(manifest)
        if task.task_id not in self._validated_tasks:
            raise ValueError("task must be validated before opening a run")
        if run.task_id != task.task_id:
            raise ValueError("run does not belong to the validated task")
        if run.run_id in self._open_runs:
            raise ValueError("source-audit adapter run is already open")
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
            raise ValueError("plan does not belong to the open source-audit run")
        if proposal.plan.step_ids != [item.step_id for item in proposal.steps]:
            raise ValueError("plan step references do not match its proposal")
        if len(proposal.steps) != 3:
            raise ValueError("source-audit plan requires exactly three ordered steps")
        inventory, dataflow, validation = proposal.steps
        if [item.ordinal for item in proposal.steps] != [1, 2, 3]:
            raise ValueError("source-audit steps must use ordinals 1, 2, and 3")
        if inventory.depends_on:
            raise ValueError("project_inventory must be the root step")
        if dataflow.depends_on != [inventory.step_id]:
            raise ValueError("python_dataflow must depend directly on project_inventory")
        if validation.depends_on != [dataflow.step_id]:
            raise ValueError("hypothesis_validate must depend directly on python_dataflow")
        expected_capabilities = [
            [SOURCE_AUDIT_INVENTORY_CAPABILITY],
            [SOURCE_AUDIT_DATAFLOW_CAPABILITY],
            [SOURCE_AUDIT_VALIDATION_CAPABILITY],
        ]
        if [item.required_capabilities for item in proposal.steps] != expected_capabilities:
            raise ValueError("source-audit plan capabilities must match the fixed pipeline")
        expected_edges = {
            (inventory.step_id, dataflow.step_id),
            (dataflow.step_id, validation.step_id),
        }
        actual_edges = {
            (item.before, item.after) for item in proposal.plan.dependency_edges
        }
        if actual_edges != expected_edges:
            raise ValueError("source-audit dependency edges must match the fixed pipeline")
        state = self._require_context(task, run)
        state.step_tools = {
            inventory.step_id: SOURCE_AUDIT_INVENTORY_TOOL_ID,
            dataflow.step_id: SOURCE_AUDIT_DATAFLOW_TOOL_ID,
            validation.step_id: SOURCE_AUDIT_VALIDATION_TOOL_ID,
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
            raise ValueError("source-audit step was not approved by validate_plan")
        expected_capability = self._capability_for_tool(expected_tool)
        if action.tool_id != expected_tool or tool_spec.tool_id != expected_tool:
            raise ValueError("source-audit action does not match the fixed step tool")
        if action.capability != expected_capability:
            raise ValueError("source-audit action does not match the fixed step capability")
        if action.capability not in step.required_capabilities:
            raise ValueError("selected capability is not required by the bound step")
        if action.capability not in tool_spec.capabilities:
            raise ValueError("selected tool does not provide the required capability")
        for dependency_id in step.depends_on:
            dependency_tool = state.step_tools.get(dependency_id)
            if dependency_tool not in state.completed_results:
                raise ValueError("source-audit step dependency has not produced evidence")
        if tool_spec.permissions.network or tool_spec.side_effects & {
            SideEffect.NETWORK_READ,
            SideEffect.NETWORK_ACTIVE,
        }:
            raise ValueError("source-audit tools must not use network access")
        if tool_spec.permissions.process_interaction or SideEffect.PROCESS_INTERACTION in tool_spec.side_effects:
            raise ValueError("source-audit tools must not interact with processes")
        if tool_spec.permissions.filesystem_write or SideEffect.FILE_WRITE in tool_spec.side_effects:
            raise ValueError("source-audit tools must not write files")
        if tool_spec.execution_profile.runner is not RunnerType.SOURCE_ANALYSIS:
            raise ValueError("source-audit tools must use the SOURCE_ANALYSIS runner")
        executable = PurePosixPath(
            tool_spec.execution_profile.entrypoint[0].replace("\\", "/")
        ).name.lower()
        if executable in _SHELL_ENTRYPOINTS:
            raise ValueError("source-audit tools must not use a shell entrypoint")
        if tool_spec.execution_profile.entrypoint != [expected_tool]:
            raise ValueError("source-audit tool entrypoint does not match its fixed tool id")

        if expected_tool == SOURCE_AUDIT_INVENTORY_TOOL_ID:
            self._validate_artifact_arguments(
                action.arguments,
                expected_keys={"artifact_id", "artifact_sha256"},
            )
        elif expected_tool == SOURCE_AUDIT_DATAFLOW_TOOL_ID:
            self._bind_dataflow_arguments(action, state)
        else:
            self._bind_validation_arguments(action, state)
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
            raise ValueError("invocation does not match the active source-audit step")
        expected_tool = state.step_tools.get(step.step_id)
        if invocation.tool_ref.tool_id != expected_tool:
            raise ValueError("source-audit invocation references an unexpected tool")
        if invocation.policy_decision_ref != policy_decision.decision_id:
            raise ValueError("invocation does not reference the supplied policy decision")
        if policy_decision.policy_version != SOURCE_AUDIT_SECURITY_POLICY:
            raise ValueError("source-audit policy decision uses an unexpected version")
        self._validate_invocation_arguments(invocation.validated_arguments, expected_tool, state)

        if policy_decision.allowed:
            if result is None:
                raise ValueError("an allowed source-audit invocation requires a tool result")
            normalized_result = self._validate_result(result, invocation, state)
            evidence = self._evidence_for_result(normalized_result, observed_at)
            state.completed_results[expected_tool] = normalized_result
        else:
            if result is not None:
                raise ValueError("a denied source-audit invocation cannot have an executed result")
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
                supports_claims=["source.audit_policy_enforced"],
                verification_method=VerificationMethod.RULE,
                confidence=1.0,
                created_at=observed_at,
            )

        self._lifecycle.append("build_observation")
        return ScenarioObservation(result=normalized_result, evidence=[evidence])

    def close_run(self, run_id: UUID) -> None:
        state = self._open_runs.pop(run_id, None)
        if state is None:
            raise ValueError("source-audit adapter run is not open")
        if not any(item.task_id == state.task_id for item in self._open_runs.values()):
            self._validated_tasks.pop(state.task_id, None)
        self._lifecycle.append("close_run")

    def _require_context(self, task: Task, run: Run) -> _OpenRun:
        state = self._open_runs.get(run.run_id)
        if state is None:
            raise ValueError("source-audit adapter run is not open")
        if state.task_id != task.task_id or run.task_id != task.task_id:
            raise ValueError("task and run do not match the open source-audit context")
        if state.artifact_id != self._config.artifact_id:
            raise ValueError("open run artifact binding is invalid")
        return state

    @staticmethod
    def _validate_step_context(run: Run, plan: Plan, step: Step) -> None:
        if plan.run_id != run.run_id or step.plan_id != plan.plan_id:
            raise ValueError("action context references a different plan")
        if step.step_id not in plan.step_ids:
            raise ValueError("action step is not present in the active plan")

    def _validate_artifact_arguments(
        self,
        arguments: dict,
        *,
        expected_keys: set[str],
    ) -> None:
        if set(arguments) != expected_keys:
            raise ValueError("source-audit arguments contain unexpected fields")
        if arguments.get("artifact_id") != str(self._config.artifact_id):
            raise ValueError("source-audit artifact binding does not match trusted config")
        if arguments.get("artifact_sha256") != self._config.artifact_sha256:
            raise ValueError("source-audit artifact hash does not match trusted config")

    @staticmethod
    def _capability_for_tool(tool_id: str) -> str:
        capabilities = {
            SOURCE_AUDIT_INVENTORY_TOOL_ID: SOURCE_AUDIT_INVENTORY_CAPABILITY,
            SOURCE_AUDIT_DATAFLOW_TOOL_ID: SOURCE_AUDIT_DATAFLOW_CAPABILITY,
            SOURCE_AUDIT_VALIDATION_TOOL_ID: SOURCE_AUDIT_VALIDATION_CAPABILITY,
        }
        try:
            return capabilities[tool_id]
        except KeyError as exc:
            raise ValueError("unsupported source-audit tool") from exc

    def _bind_dataflow_arguments(
        self,
        action: CandidateAction,
        state: _OpenRun,
    ) -> None:
        self._validate_artifact_arguments(
            action.arguments,
            expected_keys={"artifact_id", "artifact_sha256", "project_inventory"},
        )
        if state.inventory is None:
            raise ValueError("python_dataflow cannot run before project_inventory")
        supplied = action.arguments.get("project_inventory")
        trusted = state.inventory.model_dump(mode="json")
        if not isinstance(supplied, dict) or (supplied and supplied != trusted):
            raise ValueError("python_dataflow project_inventory must reference the prior result")
        action.arguments = {
            "artifact_id": str(self._config.artifact_id),
            "artifact_sha256": self._config.artifact_sha256,
            "project_inventory": trusted,
        }

    def _bind_validation_arguments(
        self,
        action: CandidateAction,
        state: _OpenRun,
    ) -> None:
        self._validate_artifact_arguments(
            action.arguments,
            expected_keys={"artifact_id", "artifact_sha256", "hypothesis"},
        )
        supplied = action.arguments.get("hypothesis")
        if not isinstance(supplied, dict):
            raise ValueError("hypothesis_validate requires a structured hypothesis reference")
        hypothesis_id = supplied.get("hypothesis_id")
        if not isinstance(hypothesis_id, str) or hypothesis_id not in state.hypotheses:
            raise ValueError("hypothesis_id was not produced by the prior dataflow step")
        trusted = state.hypotheses[hypothesis_id]
        trusted_json = trusted.model_dump(mode="json")
        if set(supplied) != {"hypothesis_id"}:
            try:
                candidate = DataflowHypothesis.model_validate(supplied)
            except ValueError as exc:
                raise ValueError("hypothesis reference is structurally invalid") from exc
            if candidate != trusted:
                raise ValueError("hypothesis content differs from the prior dataflow result")
        action.arguments = {
            "artifact_id": str(self._config.artifact_id),
            "artifact_sha256": self._config.artifact_sha256,
            "hypothesis": trusted_json,
        }

    def _validate_invocation_arguments(
        self,
        arguments: dict,
        tool_id: str | None,
        state: _OpenRun,
    ) -> None:
        if tool_id == SOURCE_AUDIT_INVENTORY_TOOL_ID:
            self._validate_artifact_arguments(
                arguments,
                expected_keys={"artifact_id", "artifact_sha256"},
            )
            return
        if tool_id == SOURCE_AUDIT_DATAFLOW_TOOL_ID:
            self._validate_artifact_arguments(
                arguments,
                expected_keys={"artifact_id", "artifact_sha256", "project_inventory"},
            )
            if state.inventory is None or arguments.get("project_inventory") != state.inventory.model_dump(mode="json"):
                raise ValueError("python_dataflow invocation is not bound to the prior inventory")
            return
        if tool_id == SOURCE_AUDIT_VALIDATION_TOOL_ID:
            self._validate_artifact_arguments(
                arguments,
                expected_keys={"artifact_id", "artifact_sha256", "hypothesis"},
            )
            try:
                hypothesis = DataflowHypothesis.model_validate(arguments.get("hypothesis"))
            except ValueError as exc:
                raise ValueError("validation invocation hypothesis is invalid") from exc
            if state.hypotheses.get(hypothesis.hypothesis_id) != hypothesis:
                raise ValueError("validation invocation is not bound to a known hypothesis")
            return
        raise ValueError("source-audit invocation references an unsupported tool")

    def _validate_output_artifact(self, artifact_id: UUID, artifact_sha256: str) -> None:
        if artifact_id != self._config.artifact_id:
            raise ValueError("source-audit output artifact id does not match trusted config")
        if artifact_sha256 != self._config.artifact_sha256:
            raise ValueError("source-audit output artifact hash does not match trusted config")

    @classmethod
    def _evidence_for_result(
        cls,
        result: ToolResult,
        observed_at: UtcDateTime,
    ) -> Evidence:
        if result.tool_ref.tool_id == SOURCE_AUDIT_INVENTORY_TOOL_ID:
            return cls._inventory_evidence(result, observed_at)
        if result.tool_ref.tool_id == SOURCE_AUDIT_DATAFLOW_TOOL_ID:
            return cls._dataflow_evidence(result, observed_at)
        if result.tool_ref.tool_id == SOURCE_AUDIT_VALIDATION_TOOL_ID:
            return cls._hypothesis_validation_evidence(result, observed_at)
        raise ValueError("cannot create evidence for an unsupported source-audit tool")

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
            raise ValueError("tool result does not match its source-audit invocation")
        if self._contains_conclusion_key(result.normalized_output):
            raise ValueError("source-audit tool output must not contain a vulnerability conclusion")
        tool_id = result.tool_ref.tool_id
        if tool_id == SOURCE_AUDIT_INVENTORY_TOOL_ID:
            inventory = ProjectInventoryResult.model_validate(result.normalized_output)
            if inventory.file_count != len(inventory.files):
                raise ValueError("project inventory file count is inconsistent")
            self._validate_output_artifact(inventory.artifact_id, inventory.artifact_sha256)
            state.inventory = inventory
        elif tool_id == SOURCE_AUDIT_DATAFLOW_TOOL_ID:
            if state.inventory is None:
                raise ValueError("python_dataflow requires a completed project inventory")
            analysis = DataflowAnalysisResult.model_validate(result.normalized_output)
            self._validate_output_artifact(analysis.artifact_id, analysis.artifact_sha256)
            expected_inventory_hash = PythonDataflowAnalyzer.inventory_sha256(
                state.inventory
            )
            if analysis.project_inventory_sha256 != expected_inventory_hash:
                raise ValueError("python_dataflow references a different project inventory")
            hypotheses = {item.hypothesis_id: item for item in analysis.hypotheses}
            if len(hypotheses) != len(analysis.hypotheses):
                raise ValueError("python_dataflow returned duplicate hypothesis ids")
            state.hypotheses = hypotheses
        elif tool_id == SOURCE_AUDIT_VALIDATION_TOOL_ID:
            validation = HypothesisValidationResult.model_validate(
                result.normalized_output
            )
            self._validate_output_artifact(
                validation.artifact_id,
                validation.artifact_sha256,
            )
            if validation.hypothesis_id not in state.hypotheses:
                raise ValueError("validation references an unknown dataflow hypothesis")
        else:
            raise ValueError("source-audit result references an unsupported tool")
        return result

    @staticmethod
    def _contains_conclusion_key(value: object) -> bool:
        if isinstance(value, dict):
            return any(
                str(key).lower() in _FORBIDDEN_CONCLUSION_KEYS
                or SourceAuditScenarioAdapter._contains_conclusion_key(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(
                SourceAuditScenarioAdapter._contains_conclusion_key(item)
                for item in value
            )
        return False

    @staticmethod
    def _inventory_evidence(result: ToolResult, observed_at: UtcDateTime) -> Evidence:
        output = result.normalized_output
        frameworks = output.get("frameworks")
        entrypoints = output.get("entrypoints")
        dependency_files = output.get("dependency_files")
        framework_count = len(frameworks) if isinstance(frameworks, list) else 0
        entrypoint_count = len(entrypoints) if isinstance(entrypoints, list) else 0
        dependency_count = (
            len(dependency_files) if isinstance(dependency_files, list) else 0
        )
        return Evidence(
            run_id=result.run_id,
            source_ref=EntityRef(
                entity_type="tool_result",
                entity_id=result.result_id,
            ),
            kind=EvidenceKind.TOOL_OBSERVATION,
            summary=(
                f"Project inventory observed {output['file_count']} Python files or records; "
                f"{framework_count} framework marker(s), {entrypoint_count} entrypoint(s), "
                f"and {dependency_count} dependency manifest(s)."
            ),
            supports_claims=["source.project_inventory"],
            verification_method=VerificationMethod.DIRECT_OBSERVATION,
            confidence=1.0 if result.status is ToolResultStatus.SUCCEEDED else 0.0,
            created_at=observed_at,
        )

    @staticmethod
    def _dataflow_evidence(result: ToolResult, observed_at: UtcDateTime) -> Evidence:
        """Convert a fact-only dataflow result into scenario-owned evidence."""

        if result.tool_ref.tool_id != "source.python_dataflow":
            raise ValueError("dataflow evidence requires source.python_dataflow")
        if result.status is not ToolResultStatus.SUCCEEDED:
            raise ValueError("dataflow evidence requires a successful tool observation")
        output = result.normalized_output
        if SourceAuditScenarioAdapter._contains_conclusion_key(output):
            raise ValueError("dataflow output must not contain a vulnerability conclusion")
        if (
            output.get("observation_type") != "python_dataflow"
            or output.get("language") != "python"
            or output.get("analysis_scope") != "sql_injection"
            or not isinstance(output.get("hypotheses"), list)
            or not isinstance(output.get("sanitizers"), list)
        ):
            raise ValueError("dataflow output is structurally invalid")
        for hypothesis in output["hypotheses"]:
            if (
                not isinstance(hypothesis, dict)
                or not isinstance(hypothesis.get("hypothesis_id"), str)
                or hypothesis.get("validation_suggestion") != "hypothesis_validate"
            ):
                raise ValueError("dataflow hypothesis is structurally invalid")
        hypothesis_ids = [item["hypothesis_id"] for item in output["hypotheses"]]
        hypothesis_text = ", ".join(hypothesis_ids) if hypothesis_ids else "none"
        return Evidence(
            run_id=result.run_id,
            source_ref=EntityRef(
                entity_type="tool_result",
                entity_id=result.result_id,
            ),
            kind=EvidenceKind.TOOL_OBSERVATION,
            summary=(
                f"Static AST analysis generated {len(output['hypotheses'])} validation "
                f"hypothesis candidate(s) and observed {len(output['sanitizers'])} "
                f"query-handling control(s). Hypothesis ids: {hypothesis_text}. "
                "No final vulnerability conclusion was made."
            ),
            supports_claims=["source.dataflow_hypotheses"],
            verification_method=VerificationMethod.DIRECT_OBSERVATION,
            confidence=1.0,
            created_at=observed_at,
        )

    @staticmethod
    def _hypothesis_validation_evidence(
        result: ToolResult,
        observed_at: UtcDateTime,
    ) -> Evidence:
        if result.tool_ref.tool_id != "source.hypothesis_validate":
            raise ValueError("validation evidence requires source.hypothesis_validate")
        if result.status is not ToolResultStatus.SUCCEEDED:
            raise ValueError("validation evidence requires a successful tool observation")
        output = result.normalized_output
        if SourceAuditScenarioAdapter._contains_conclusion_key(output):
            raise ValueError("validation output must not contain a vulnerability conclusion")
        if (
            output.get("observation_type") != "hypothesis_validation"
            or output.get("validation_mode") != "symbolic_intercepted_sink"
            or output.get("side_effect_suppressed") is not True
            or not isinstance(output.get("baseline_observation"), dict)
            or not isinstance(output.get("probe_observation"), dict)
            or not isinstance(output.get("intercepted_sink"), dict)
        ):
            raise ValueError("hypothesis validation output is structurally invalid")
        sink = output["intercepted_sink"]
        if sink.get("side_effect_suppressed") is not True:
            raise ValueError("hypothesis validation did not suppress its sink")
        return Evidence(
            run_id=result.run_id,
            source_ref=EntityRef(
                entity_type="tool_result",
                entity_id=result.result_id,
            ),
            kind=EvidenceKind.TOOL_OBSERVATION,
            summary=(
                "Controlled symbolic replay captured baseline and probe values at an "
                "intercepted database sink with external side effects suppressed."
            ),
            supports_claims=["source.hypothesis_validation"],
            verification_method=VerificationMethod.DIRECT_OBSERVATION,
            confidence=1.0,
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
            else "SOURCE_AUDIT_POLICY_DENIED"
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
                safe_message="Source-audit action was denied before execution.",
            ),
            environment_fingerprint="0" * 64,
        )

    @staticmethod
    def _validate_manifest(manifest: TaskPackManifest) -> None:
        if manifest.task_pack_id != SOURCE_AUDIT_TASK_PACK_ID:
            raise ValueError("unexpected source-audit task pack id")
        if manifest.version != SOURCE_AUDIT_TASK_PACK_VERSION:
            raise ValueError("unexpected source-audit task pack version")
        if manifest.task_type != SOURCE_AUDIT_TASK_TYPE:
            raise ValueError("unexpected source-audit task type")
        if manifest.required_tools != SOURCE_AUDIT_REQUIRED_TOOLS:
            raise ValueError("source-audit required_tools must match the fixed pipeline")
        if manifest.verifier != SOURCE_AUDIT_VERIFIER_ID:
            raise ValueError("unexpected source-audit verifier")
        if manifest.report_template != SOURCE_AUDIT_REPORT_TEMPLATE:
            raise ValueError("unexpected source-audit report template")
        if manifest.security_policy != SOURCE_AUDIT_SECURITY_POLICY:
            raise ValueError("unexpected source-audit security policy")


__all__ = ["SourceAuditScenarioAdapter"]
