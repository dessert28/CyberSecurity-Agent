"""Controlled symbolic validation for one Python SQL dataflow hypothesis."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import tokenize
import zipfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from cyber_agent.contracts import MaterializedArtifactInput
from cyber_agent.contracts.common import (
    ErrorCategory,
    ErrorInfo,
    RiskLevel,
    Sha256,
    StrictModel,
)
from cyber_agent.contracts.tool import (
    ExecutionProfile,
    ExecutionRequest,
    MountSpec,
    NetworkPolicy,
    RawExecutionResult,
    ResourceLimits,
    RunnerType,
    SideEffect,
    ToolHealth,
    ToolInvocation,
    ToolInvocationStatus,
    ToolPermissions,
    ToolRef,
    ToolResult,
    ToolResultStatus,
    ToolSpec,
)
from cyber_agent.executor.source_analysis import SourceAnalysisExecutionError

from .project_inventory import ProjectInventoryAnalyzer
from .python_dataflow import DataflowHypothesis
from .validation import ArgumentValidationError, validate_arguments

HYPOTHESIS_VALIDATE_TOOL_ID = "source.hypothesis_validate"
HYPOTHESIS_VALIDATE_CAPABILITY = "source.hypothesis_validate"
_SOURCE_INPUT_PATH = "/inputs/source.zip"
_BASELINE_VALUE = "7"
_PROBE_VALUE = "7' OR '1'='1"
_MAX_SOURCE_BYTES = 1_000_000
_MAX_AST_NODES = 200_000
_DEFAULT_RESOURCES = ResourceLimits(
    cpu_cores=1,
    memory_megabytes=256,
    max_processes=1,
    max_output_bytes=2_000_000,
)
_UNKNOWN = object()


class ValidationObservation(StrictModel):
    input_label: Literal["baseline", "probe"]
    synthetic_input: str = Field(min_length=1, max_length=255)
    sink_reached: Literal[True] = True
    query_text: str = Field(max_length=20_000)
    parameters: list[str] = Field(default_factory=list)
    query_sha256: Sha256


class InterceptedSink(StrictModel):
    call: str = Field(min_length=1, max_length=255)
    file: str = Field(min_length=1, max_length=2_048)
    line: int = Field(ge=1)
    baseline_query: str = Field(max_length=20_000)
    probe_query: str = Field(max_length=20_000)
    baseline_parameters: list[str] = Field(default_factory=list)
    probe_parameters: list[str] = Field(default_factory=list)
    query_text_changed: bool
    parameter_values_changed: bool
    side_effect_suppressed: Literal[True] = True


class HypothesisValidationResult(StrictModel):
    observation_type: Literal["hypothesis_validation"] = "hypothesis_validation"
    hypothesis_id: str = Field(pattern=r"^hyp-[0-9a-f]{24}$")
    artifact_id: UUID
    artifact_sha256: Sha256
    validation_mode: Literal["symbolic_intercepted_sink"] = (
        "symbolic_intercepted_sink"
    )
    baseline_observation: ValidationObservation
    probe_observation: ValidationObservation
    intercepted_sink: InterceptedSink
    side_effect_suppressed: Literal[True] = True


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return type(node).__name__


def _source_kind(node: ast.AST) -> str | None:
    candidates = {
        "request.args",
        "request.form",
        "request.json",
        "request.values",
        "request.query_params",
    }
    if isinstance(node, ast.Attribute):
        name = _call_name(node)
        return name if name in candidates else None
    if isinstance(node, ast.Subscript):
        name = _call_name(node.value)
        return name if name in candidates else None
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name == "request.get_json":
            return "request.json"
        for candidate in candidates:
            if name == f"{candidate}.get" or name.startswith(f"{candidate}."):
                return candidate
    return None


def _validation_scope(
    tree: ast.AST,
    hypothesis: DataflowHypothesis,
) -> ast.AST:
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    def innermost(line: int) -> ast.AST | None:
        containing = [
            node
            for node in functions
            if node.lineno <= line <= (node.end_lineno or node.lineno)
        ]
        if not containing:
            return None
        return min(
            containing,
            key=lambda node: (node.end_lineno or node.lineno) - node.lineno,
        )

    source_scope = innermost(hypothesis.source.line)
    sink_scope = innermost(hypothesis.sink.line)
    if source_scope is not sink_scope:
        raise SourceAnalysisExecutionError(
            "SOURCE_HYPOTHESIS_PATH_UNSUPPORTED",
            "Controlled validation requires source and sink in one lexical scope.",
        )
    return source_scope or tree


class _SymbolicReplay:
    """Evaluate a deliberately small expression subset without compile or exec."""

    def __init__(
        self,
        *,
        tree: ast.AST,
        hypothesis: DataflowHypothesis,
        synthetic_input: str,
    ) -> None:
        self._tree = tree
        self._hypothesis = hypothesis
        self._synthetic_input = synthetic_input
        self._environment: dict[str, Any] = {}

    def capture(self) -> tuple[str, list[str]]:
        source_found = any(
            getattr(node, "lineno", None) == self._hypothesis.source.line
            and _source_kind(node) == self._hypothesis.source.kind
            for node in ast.walk(self._tree)
        )
        if not source_found:
            raise SourceAnalysisExecutionError(
                "SOURCE_HYPOTHESIS_NOT_FOUND",
                "Hypothesis source location was not found in the source copy.",
            )
        sinks = [
            node
            for node in ast.walk(self._tree)
            if isinstance(node, ast.Call)
            and node.lineno == self._hypothesis.sink.line
            and _call_name(node.func) == self._hypothesis.sink.call
        ]
        if len(sinks) != 1 or not sinks[0].args:
            raise SourceAnalysisExecutionError(
                "SOURCE_HYPOTHESIS_NOT_FOUND",
                "Hypothesis sink location was not found uniquely in the source copy.",
            )
        sink = sinks[0]
        for node in sorted(
            (
                item
                for item in ast.walk(self._tree)
                if isinstance(item, (ast.Assign, ast.AnnAssign))
                and getattr(item, "lineno", 0) < sink.lineno
            ),
            key=lambda item: item.lineno,
        ):
            value_node = node.value
            if value_node is None:
                continue
            value = self._evaluate(value_node)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                self._bind(target, value)

        query = self._evaluate(sink.args[0])
        if query is _UNKNOWN:
            raise SourceAnalysisExecutionError(
                "SOURCE_HYPOTHESIS_PATH_UNSUPPORTED",
                "Hypothesis query path uses an unsupported expression.",
            )
        raw_parameters = [self._evaluate(item) for item in sink.args[1:]]
        if any(value is _UNKNOWN for value in raw_parameters):
            raise SourceAnalysisExecutionError(
                "SOURCE_HYPOTHESIS_PATH_UNSUPPORTED",
                "Hypothesis parameter path uses an unsupported expression.",
            )
        parameters: list[Any] = []
        for value in raw_parameters:
            if isinstance(value, (tuple, list)):
                parameters.extend(value)
            else:
                parameters.append(value)
        return str(query), [str(value) for value in parameters]

    def _bind(self, target: ast.AST, value: Any) -> None:
        if isinstance(target, ast.Name):
            self._environment[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(
            value, (tuple, list)
        ):
            for item, bound in zip(target.elts, value, strict=False):
                self._bind(item, bound)

    def _evaluate(self, node: ast.AST) -> Any:
        if (
            getattr(node, "lineno", None) == self._hypothesis.source.line
            and _source_kind(node) == self._hypothesis.source.kind
        ):
            return self._synthetic_input
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self._environment.get(node.id, _UNKNOWN)
        if isinstance(node, ast.Tuple):
            values = [self._evaluate(item) for item in node.elts]
            return _UNKNOWN if _UNKNOWN in values else tuple(values)
        if isinstance(node, ast.List):
            values = [self._evaluate(item) for item in node.elts]
            return _UNKNOWN if _UNKNOWN in values else values
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for item in node.values:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    parts.append(item.value)
                elif isinstance(item, ast.FormattedValue):
                    value = self._evaluate(item.value)
                    if value is _UNKNOWN:
                        return _UNKNOWN
                    parts.append(str(value))
                else:
                    return _UNKNOWN
            return "".join(parts)
        if isinstance(node, ast.BinOp):
            left = self._evaluate(node.left)
            right = self._evaluate(node.right)
            if left is _UNKNOWN or right is _UNKNOWN:
                return _UNKNOWN
            if isinstance(node.op, ast.Add):
                try:
                    return left + right
                except TypeError:
                    return _UNKNOWN
            if isinstance(node.op, ast.Mod) and isinstance(left, str):
                try:
                    return left % right
                except (TypeError, ValueError):
                    return _UNKNOWN
            return _UNKNOWN
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in {"str", "repr"} and len(node.args) == 1:
                value = self._evaluate(node.args[0])
                if value is _UNKNOWN:
                    return _UNKNOWN
                return str(value) if name == "str" else repr(value)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                template = self._evaluate(node.func.value)
                values = [self._evaluate(item) for item in node.args]
                if template is _UNKNOWN or _UNKNOWN in values:
                    return _UNKNOWN
                try:
                    return str(template).format(*values)
                except (IndexError, KeyError, ValueError):
                    return _UNKNOWN
        return _UNKNOWN


class HypothesisValidationHandler:
    """Allowlisted SOURCE_ANALYSIS handler using symbolic sink interception."""

    def __init__(
        self,
        *,
        max_members: int = 2_000,
        max_uncompressed_bytes: int = 50_000_000,
        max_member_bytes: int = 5_000_000,
        max_source_bytes: int = _MAX_SOURCE_BYTES,
        max_ast_nodes: int = _MAX_AST_NODES,
    ) -> None:
        if min(
            max_members,
            max_uncompressed_bytes,
            max_member_bytes,
            max_source_bytes,
            max_ast_nodes,
        ) < 1:
            raise ValueError("hypothesis validation limits must be positive")
        self._max_members = max_members
        self._max_uncompressed_bytes = max_uncompressed_bytes
        self._max_member_bytes = max_member_bytes
        self._max_source_bytes = max_source_bytes
        self._max_ast_nodes = max_ast_nodes

    async def __call__(self, request: ExecutionRequest, source_zip: bytes) -> bytes:
        artifact_sha256, hypothesis = self._parse_request(request)
        if hashlib.sha256(source_zip).hexdigest() != artifact_sha256:
            raise SourceAnalysisExecutionError(
                "SOURCE_VALIDATION_ARTIFACT_HASH_MISMATCH",
                "Source copy does not match the invocation hash binding.",
            )
        now = datetime.now(timezone.utc)
        lease = MaterializedArtifactInput(
            run_id=request.invocation_id,
            artifact_id=request.mounts[0].artifact_id,
            artifact_sha256=artifact_sha256,
            media_type="application/zip",
            size_bytes=len(source_zip),
            created_at=now,
            expires_at=now + timedelta(seconds=request.timeout_seconds + 1),
        )
        inventory = ProjectInventoryAnalyzer(
            archive_reader=lambda: source_zip,
            max_members=self._max_members,
            max_uncompressed_bytes=self._max_uncompressed_bytes,
            max_member_bytes=self._max_member_bytes,
            max_text_bytes=self._max_source_bytes,
        ).analyze(lease)
        if hypothesis.source.file != hypothesis.sink.file:
            raise SourceAnalysisExecutionError(
                "SOURCE_HYPOTHESIS_PATH_UNSUPPORTED",
                "Controlled validation currently requires source and sink in one file.",
            )
        record = next(
            (item for item in inventory.files if item.path == hypothesis.sink.file),
            None,
        )
        if record is None or not record.path.lower().endswith(".py"):
            raise SourceAnalysisExecutionError(
                "SOURCE_HYPOTHESIS_NOT_FOUND",
                "Hypothesis source file was not found in the source copy.",
            )
        if record.size_bytes > self._max_source_bytes:
            raise SourceAnalysisExecutionError(
                "SOURCE_VALIDATION_FILE_SIZE_LIMIT",
                "Hypothesis source exceeds the validation size limit.",
            )
        try:
            with zipfile.ZipFile(io.BytesIO(source_zip), mode="r") as archive:
                data = archive.read(record.path)
            if hashlib.sha256(data).hexdigest() != record.sha256:
                raise SourceAnalysisExecutionError(
                    "SOURCE_VALIDATION_FILE_HASH_MISMATCH",
                    "Hypothesis source file does not match its inventory hash.",
                )
            encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
            source = data.decode(encoding)
            tree = ast.parse(source, filename=record.path, mode="exec")
        except SourceAnalysisExecutionError:
            raise
        except (zipfile.BadZipFile, KeyError, LookupError, SyntaxError, UnicodeDecodeError) as exc:
            raise SourceAnalysisExecutionError(
                "SOURCE_VALIDATION_PARSE_FAILED",
                "Hypothesis source could not be parsed safely.",
            ) from exc
        if sum(1 for _ in ast.walk(tree)) > self._max_ast_nodes:
            raise SourceAnalysisExecutionError(
                "SOURCE_AST_NODE_LIMIT",
                "Hypothesis source exceeds the validation AST node limit.",
            )

        validation_scope = _validation_scope(tree, hypothesis)
        baseline_query, baseline_parameters = _SymbolicReplay(
            tree=validation_scope,
            hypothesis=hypothesis,
            synthetic_input=_BASELINE_VALUE,
        ).capture()
        probe_query, probe_parameters = _SymbolicReplay(
            tree=validation_scope,
            hypothesis=hypothesis,
            synthetic_input=_PROBE_VALUE,
        ).capture()
        baseline = self._observation(
            "baseline", _BASELINE_VALUE, baseline_query, baseline_parameters
        )
        probe = self._observation(
            "probe", _PROBE_VALUE, probe_query, probe_parameters
        )
        result = HypothesisValidationResult(
            hypothesis_id=hypothesis.hypothesis_id,
            artifact_id=lease.artifact_id,
            artifact_sha256=artifact_sha256,
            baseline_observation=baseline,
            probe_observation=probe,
            intercepted_sink=InterceptedSink(
                call=hypothesis.sink.call,
                file=hypothesis.sink.file,
                line=hypothesis.sink.line,
                baseline_query=baseline_query,
                probe_query=probe_query,
                baseline_parameters=baseline_parameters,
                probe_parameters=probe_parameters,
                query_text_changed=baseline_query != probe_query,
                parameter_values_changed=baseline_parameters != probe_parameters,
            ),
        )
        return result.model_dump_json().encode("utf-8")

    @staticmethod
    def _parse_request(
        request: ExecutionRequest,
    ) -> tuple[str, DataflowHypothesis]:
        if len(request.argv) != 4 or request.argv[0] != "--artifact-sha256" or request.argv[2] != "--hypothesis-json":
            raise SourceAnalysisExecutionError(
                "SOURCE_VALIDATION_ARGUMENTS_INVALID",
                "Controlled validation received invalid structured arguments.",
            )
        artifact_sha256 = request.argv[1]
        if len(artifact_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in artifact_sha256.lower()
        ):
            raise SourceAnalysisExecutionError(
                "SOURCE_VALIDATION_ARGUMENTS_INVALID",
                "Controlled validation received an invalid artifact hash.",
            )
        try:
            hypothesis = DataflowHypothesis.model_validate_json(request.argv[3])
        except ValueError as exc:
            raise SourceAnalysisExecutionError(
                "SOURCE_VALIDATION_ARGUMENTS_INVALID",
                "Controlled validation received an invalid hypothesis.",
            ) from exc
        return artifact_sha256.lower(), hypothesis

    @staticmethod
    def _observation(
        label: Literal["baseline", "probe"],
        value: str,
        query: str,
        parameters: list[str],
    ) -> ValidationObservation:
        return ValidationObservation(
            input_label=label,
            synthetic_input=value,
            query_text=query,
            parameters=parameters,
            query_sha256=hashlib.sha256(query.encode()).hexdigest(),
        )


class HypothesisValidatePlugin:
    input_schema = {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "pattern": r"^[0-9a-fA-F-]{36}$"},
            "artifact_sha256": {"type": "string", "pattern": r"^[0-9a-fA-F]{64}$"},
            "hypothesis": {"type": "object"},
        },
        "required": ["artifact_id", "artifact_sha256", "hypothesis"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "schema_version": {"type": "string"},
            "observation_type": {"type": "string", "const": "hypothesis_validation"},
            "hypothesis_id": {"type": "string"},
            "artifact_id": {"type": "string"},
            "artifact_sha256": {"type": "string"},
            "validation_mode": {"type": "string", "const": "symbolic_intercepted_sink"},
            "baseline_observation": {"type": "object"},
            "probe_observation": {"type": "object"},
            "intercepted_sink": {"type": "object"},
            "side_effect_suppressed": {"type": "boolean", "const": True},
        },
        "required": [
            "schema_version",
            "observation_type",
            "hypothesis_id",
            "artifact_id",
            "artifact_sha256",
            "validation_mode",
            "baseline_observation",
            "probe_observation",
            "intercepted_sink",
            "side_effect_suppressed",
        ],
        "additionalProperties": False,
    }

    def __init__(
        self,
        *,
        runtime_available: Callable[[], bool] | None = None,
        resources: ResourceLimits | None = None,
        timeout_seconds: int = 10,
    ) -> None:
        if not 1 <= timeout_seconds <= 10:
            raise ValueError("source validation timeout must be between 1 and 10 seconds")
        self._runtime_available = runtime_available or (lambda: False)
        self._resources = (resources or _DEFAULT_RESOURCES).model_copy(deep=True)
        self._timeout_seconds = timeout_seconds
        self._pending: dict[UUID, ToolInvocation] = {}
        self._spec = ToolSpec(
            tool_id=HYPOTHESIS_VALIDATE_TOOL_ID,
            name="Controlled source hypothesis validation",
            version="1.0.0",
            plugin_id="builtin.source-audit",
            capabilities=[HYPOTHESIS_VALIDATE_CAPABILITY],
            description=(
                "Symbolically replay one bounded Python SQL path with an intercepted "
                "sink and no external side effects."
            ),
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects={SideEffect.FILE_READ, SideEffect.SIDE_EFFECT_SUPPRESSED},
            risk_level=RiskLevel.R2,
            permissions=ToolPermissions(filesystem_read=True),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                image=None,
                entrypoint=[HYPOTHESIS_VALIDATE_TOOL_ID],
                default_timeout_seconds=self._timeout_seconds,
                max_timeout_seconds=self._timeout_seconds,
                default_resources=self._resources,
            ),
        )
        fingerprint = json.dumps(
            self._spec.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self._environment_fingerprint = hashlib.sha256(fingerprint).hexdigest()

    def get_spec(self) -> ToolSpec:
        return self._spec.model_copy(deep=True)

    async def health_check(self) -> ToolHealth:
        try:
            available = bool(self._runtime_available())
        except Exception:
            available = False
        return ToolHealth(
            tool_ref=ToolRef(tool_id=HYPOTHESIS_VALIDATE_TOOL_ID, version="1.0.0"),
            available=available,
            message=(
                "controlled source-analysis runtime available"
                if available
                else "controlled source-analysis runtime unavailable"
            ),
        )

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        expected = ToolRef(tool_id=HYPOTHESIS_VALIDATE_TOOL_ID, version="1.0.0")
        if invocation.tool_ref != expected:
            raise ValueError("invocation tool reference does not match validation tool")
        if invocation.status is not ToolInvocationStatus.APPROVED:
            raise ValueError("only approved hypothesis validations can be prepared")
        if invocation.deadline <= datetime.now(timezone.utc):
            raise ValueError("hypothesis validation deadline has expired")
        arguments = validate_arguments(invocation.validated_arguments, self.input_schema)
        try:
            artifact_id = UUID(arguments["artifact_id"])
            hypothesis = DataflowHypothesis.model_validate(arguments["hypothesis"])
        except ValueError as exc:
            raise ArgumentValidationError("hypothesis validation input is invalid") from exc
        remaining = int((invocation.deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining < 1:
            raise ValueError("hypothesis validation deadline leaves less than one second")
        request = ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.SOURCE_ANALYSIS,
            image=None,
            entrypoint=[HYPOTHESIS_VALIDATE_TOOL_ID],
            argv=[
                "--artifact-sha256",
                arguments["artifact_sha256"].lower(),
                "--hypothesis-json",
                hypothesis.model_dump_json(),
            ],
            mounts=[
                MountSpec(
                    artifact_id=artifact_id,
                    container_path=_SOURCE_INPUT_PATH,
                    read_only=True,
                )
            ],
            environment={},
            network_policy=NetworkPolicy(),
            resources=self._resources.model_copy(deep=True),
            timeout_seconds=min(self._timeout_seconds, remaining),
        )
        self._pending[request.request_id] = invocation
        return request

    def parse(self, result: RawExecutionResult) -> ToolResult:
        invocation = self._pending.pop(result.request_id, None)
        if invocation is None:
            raise ValueError("raw result does not match a prepared validation request")
        status = result.status
        error = result.error
        normalized: dict[str, Any] = {}
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error(
                "SOURCE_VALIDATION_EXIT_NONZERO",
                "Controlled hypothesis validation exited non-zero.",
            )
        if status is ToolResultStatus.SUCCEEDED:
            try:
                decoded = json.loads(result.stdout.decode("utf-8"))
                observation = HypothesisValidationResult.model_validate(decoded)
                hypothesis = DataflowHypothesis.model_validate(
                    invocation.validated_arguments["hypothesis"]
                )
                if observation.hypothesis_id != hypothesis.hypothesis_id:
                    raise ValueError("validation hypothesis id mismatch")
                if str(observation.artifact_id) != invocation.validated_arguments["artifact_id"]:
                    raise ValueError("validation artifact id mismatch")
                if observation.artifact_sha256 != invocation.validated_arguments["artifact_sha256"]:
                    raise ValueError("validation artifact hash mismatch")
                normalized = observation.model_dump(mode="json")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                status = ToolResultStatus.FAILED
                error = self._error(
                    "SOURCE_VALIDATION_OUTPUT_INVALID",
                    "Controlled hypothesis validation returned invalid output.",
                )
                normalized = {}
        elif error is None:
            error = self._error(
                "SOURCE_VALIDATION_EXECUTION_FAILED",
                "Controlled hypothesis validation did not succeed.",
            )
        return ToolResult(
            run_id=invocation.run_id,
            plan_id=invocation.plan_id,
            step_id=invocation.step_id,
            attempt=invocation.attempt,
            tool_ref=invocation.tool_ref,
            validated_arguments=invocation.validated_arguments,
            policy_decision_ref=invocation.policy_decision_ref,
            status=status,
            started_at=result.started_at,
            finished_at=result.finished_at,
            exit_code=result.exit_code,
            normalized_output=normalized,
            artifact_refs=result.output_artifacts,
            error=error,
            environment_fingerprint=self._environment_fingerprint,
        )

    @staticmethod
    def _error(code: str, message: str) -> ErrorInfo:
        return ErrorInfo(
            code=code,
            category=ErrorCategory.TOOL_FAILED,
            retryable=False,
            safe_message=message,
        )


__all__ = [
    "HYPOTHESIS_VALIDATE_CAPABILITY",
    "HYPOTHESIS_VALIDATE_TOOL_ID",
    "HypothesisValidatePlugin",
    "HypothesisValidationHandler",
    "HypothesisValidationResult",
    "InterceptedSink",
    "ValidationObservation",
]
