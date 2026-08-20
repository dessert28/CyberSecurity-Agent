"""Offline Python AST dataflow hypotheses for SQL query construction."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import tokenize
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
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

from .project_inventory import ProjectInventoryAnalyzer, ProjectInventoryResult
from .validation import ArgumentValidationError, validate_arguments

PYTHON_DATAFLOW_TOOL_ID = "source.python_dataflow"
PYTHON_DATAFLOW_CAPABILITY = "source.dataflow"
_SOURCE_INPUT_PATH = "/inputs/source.zip"
_OTHER_SOURCE_SUFFIXES = {
    ".asm",
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".lua",
    ".mjs",
    ".pl",
    ".php",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
    ".vue",
}
_MAX_PYTHON_FILE_BYTES = 1_000_000
_MAX_AST_NODES = 200_000
_DEFAULT_RESOURCES = ResourceLimits(
    cpu_cores=1,
    memory_megabytes=256,
    max_processes=1,
    max_output_bytes=5_000_000,
)


class PythonDataflowError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class DataflowSource(StrictModel):
    kind: str = Field(min_length=1, max_length=128)
    expression: str = Field(min_length=1, max_length=2_000)
    file: str = Field(min_length=1, max_length=2_048)
    line: int = Field(ge=1)


class DataflowSink(StrictModel):
    call: str = Field(min_length=1, max_length=255)
    expression: str = Field(min_length=1, max_length=2_000)
    file: str = Field(min_length=1, max_length=2_048)
    line: int = Field(ge=1)


class DataflowPoint(StrictModel):
    role: Literal["source", "propagation", "sink"]
    file: str = Field(min_length=1, max_length=2_048)
    line: int = Field(ge=1)
    expression: str = Field(min_length=1, max_length=2_000)


class SanitizerObservation(StrictModel):
    kind: Literal["parameterized_query", "type_coercion"]
    file: str = Field(min_length=1, max_length=2_048)
    line: int = Field(ge=1)
    sink_call: str = Field(min_length=1, max_length=255)
    details: str = Field(min_length=1, max_length=2_000)


class DataflowHypothesis(StrictModel):
    hypothesis_id: str = Field(pattern=r"^hyp-[0-9a-f]{24}$")
    hypothesis_type: Literal["sql_injection_candidate"] = "sql_injection_candidate"
    statement: str = Field(min_length=1, max_length=2_000)
    source: DataflowSource
    sink: DataflowSink
    dataflow: list[DataflowPoint] = Field(min_length=2)
    sanitizers: list[SanitizerObservation] = Field(default_factory=list)
    validation_suggestion: Literal["hypothesis_validate"] = "hypothesis_validate"


class ParseObservation(StrictModel):
    file: str = Field(min_length=1, max_length=2_048)
    line: int = Field(ge=0)
    code: Literal["encoding_unsupported", "syntax_unparseable"]


class DataflowAnalysisResult(StrictModel):
    observation_type: Literal["python_dataflow"] = "python_dataflow"
    artifact_id: UUID
    artifact_sha256: Sha256
    project_inventory_sha256: Sha256
    language: Literal["python"] = "python"
    analysis_scope: Literal["sql_injection"] = "sql_injection"
    analyzed_files: list[str] = Field(default_factory=list)
    hypotheses: list[DataflowHypothesis] = Field(default_factory=list)
    sanitizers: list[SanitizerObservation] = Field(default_factory=list)
    parse_observations: list[ParseObservation] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _Trace:
    source: DataflowSource
    points: tuple[DataflowPoint, ...]
    sanitizers: tuple[SanitizerObservation, ...] = ()


def _display(node: ast.AST, *, limit: int = 2_000) -> str:
    try:
        value = ast.unparse(node)
    except Exception:
        value = type(node).__name__
    value = " ".join(value.split())
    return (value or type(node).__name__)[:limit]


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return _display(node, limit=255)


def _source_kind(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        name = _call_name(node)
        if name in {
            "request.args",
            "request.form",
            "request.json",
            "request.values",
            "request.query_params",
        }:
            return name
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        for candidate in (
            "request.args",
            "request.form",
            "request.json",
            "request.values",
            "request.query_params",
        ):
            if name == f"{candidate}.get" or name.startswith(f"{candidate}."):
                return candidate
        if name in {"request.get_json", "request.json"}:
            return "request.json"
    if isinstance(node, ast.Subscript):
        name = _call_name(node.value)
        if name in {
            "request.args",
            "request.form",
            "request.json",
            "request.values",
            "request.query_params",
        }:
            return name
    return None


class _ScopeDataflow(ast.NodeVisitor):
    """Conservative, function-local taint propagation over an already parsed AST."""

    def __init__(self, *, file: str, artifact_sha256: str) -> None:
        self._file = file
        self._artifact_sha256 = artifact_sha256
        self._environment: dict[str, _Trace] = {}
        self.hypotheses: list[DataflowHypothesis] = []
        self.sanitizers: list[SanitizerObservation] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        child = _ScopeDataflow(
            file=self._file,
            artifact_sha256=self._artifact_sha256,
        )
        for statement in node.body:
            child.visit(statement)
        self.hypotheses.extend(child.hypotheses)
        self.sanitizers.extend(child.sanitizers)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for statement in node.body:
            self.visit(statement)

    def visit_Assign(self, node: ast.Assign) -> None:
        trace = self._trace(node.value)
        if trace is not None:
            for target in node.targets:
                self._bind(target, trace, node.lineno)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is None:
            return
        trace = self._trace(node.value)
        if trace is not None:
            self._bind(node.target, trace, node.lineno)
        self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        traces = [self._trace(node.target), self._trace(node.value)]
        trace = next((item for item in traces if item is not None), None)
        if trace is not None:
            self._bind(node.target, trace, node.lineno)
        self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        call = _call_name(node.func)
        if call.endswith((".execute", ".executemany")):
            self._observe_sink(node, call)
        self.generic_visit(node)

    def _bind(self, target: ast.AST, trace: _Trace, line: int) -> None:
        names: list[str] = []
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            names.extend(
                item.id for item in target.elts if isinstance(item, ast.Name)
            )
        for name in names:
            point = DataflowPoint(
                role="propagation",
                file=self._file,
                line=line,
                expression=f"assignment:{name}",
            )
            self._environment[name] = _Trace(
                source=trace.source,
                points=(*trace.points, point),
                sanitizers=trace.sanitizers,
            )

    def _trace(self, node: ast.AST) -> _Trace | None:
        direct = _source_kind(node)
        if direct is not None:
            source = DataflowSource(
                kind=direct,
                expression=_display(node),
                file=self._file,
                line=getattr(node, "lineno", 1),
            )
            return _Trace(
                source=source,
                points=(
                    DataflowPoint(
                        role="source",
                        file=self._file,
                        line=source.line,
                        expression=source.expression,
                    ),
                ),
            )
        if isinstance(node, ast.Name):
            return self._environment.get(node.id)

        nested = None
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Load, ast.Store, ast.Del)):
                continue
            nested = self._trace(child)
            if nested is not None:
                break
        if nested is None:
            return None
        if isinstance(node, ast.Call) and _call_name(node.func) in {
            "int",
            "float",
            "uuid.UUID",
        }:
            sanitizer = SanitizerObservation(
                kind="type_coercion",
                file=self._file,
                line=getattr(node, "lineno", nested.source.line),
                sink_call=_call_name(node.func),
                details="A type-coercion call was observed on the tracked value.",
            )
            return _Trace(
                source=nested.source,
                points=nested.points,
                sanitizers=(*nested.sanitizers, sanitizer),
            )
        return nested

    def _observe_sink(self, node: ast.Call, call: str) -> None:
        if not node.args:
            return
        query_trace = self._trace(node.args[0])
        parameter_trace = self._trace(node.args[1]) if len(node.args) > 1 else None
        if query_trace is None:
            if parameter_trace is not None:
                sanitizer = SanitizerObservation(
                    kind="parameterized_query",
                    file=self._file,
                    line=node.lineno,
                    sink_call=call,
                    details=(
                        "A separate SQL parameter argument carries the tracked input; "
                        "the query argument itself is not dataflow-tainted."
                    ),
                )
                self.sanitizers.append(sanitizer)
                sink = DataflowSink(
                    call=call,
                    expression=_display(node.args[0]),
                    file=self._file,
                    line=node.lineno,
                )
                sink_point = DataflowPoint(
                    role="sink",
                    file=self._file,
                    line=node.lineno,
                    expression=f"{call}({_display(node.args[0])})",
                )
                identity = "|".join(
                    (
                        self._artifact_sha256,
                        self._file,
                        str(node.lineno),
                        parameter_trace.source.expression,
                        sink.expression,
                    )
                )
                self.hypotheses.append(
                    DataflowHypothesis(
                        hypothesis_id=(
                            "hyp-" + hashlib.sha256(identity.encode()).hexdigest()[:24]
                        ),
                        statement=(
                            "A user-input source candidate reaches a separate SQL parameter "
                            "argument; controlled validation must determine whether effective "
                            "parameterization keeps query text invariant."
                        ),
                        source=parameter_trace.source,
                        sink=sink,
                        dataflow=[*parameter_trace.points, sink_point],
                        sanitizers=[*parameter_trace.sanitizers, sanitizer],
                    )
                )
            return

        sink = DataflowSink(
            call=call,
            expression=_display(node.args[0]),
            file=self._file,
            line=node.lineno,
        )
        sink_point = DataflowPoint(
            role="sink",
            file=self._file,
            line=node.lineno,
            expression=f"{call}({_display(node.args[0])})",
        )
        identity = "|".join(
            (
                self._artifact_sha256,
                self._file,
                str(node.lineno),
                query_trace.source.expression,
                sink.expression,
            )
        )
        hypothesis_id = "hyp-" + hashlib.sha256(identity.encode()).hexdigest()[:24]
        self.hypotheses.append(
            DataflowHypothesis(
                hypothesis_id=hypothesis_id,
                statement=(
                    "A user-input source candidate reaches a dynamically constructed "
                    "SQL query argument; separate hypothesis validation is required."
                ),
                source=query_trace.source,
                sink=sink,
                dataflow=[*query_trace.points, sink_point],
                sanitizers=list(query_trace.sanitizers),
            )
        )


class PythonDataflowAnalyzer:
    """Validate inventory provenance, parse Python, and emit hypotheses only."""

    def __init__(
        self,
        *,
        archive_reader: Callable[[], bytes] | None = None,
        max_members: int = 2_000,
        max_uncompressed_bytes: int = 50_000_000,
        max_member_bytes: int = 5_000_000,
        max_python_file_bytes: int = _MAX_PYTHON_FILE_BYTES,
        max_ast_nodes_per_file: int = _MAX_AST_NODES,
    ) -> None:
        if min(
            max_members,
            max_uncompressed_bytes,
            max_member_bytes,
            max_python_file_bytes,
            max_ast_nodes_per_file,
        ) < 1:
            raise ValueError("dataflow limits must be positive")
        self._archive_reader = archive_reader or self._read_fixed_archive
        self._max_members = max_members
        self._max_uncompressed_bytes = max_uncompressed_bytes
        self._max_member_bytes = max_member_bytes
        self._max_python_file_bytes = max_python_file_bytes
        self._max_ast_nodes_per_file = max_ast_nodes_per_file

    def analyze(
        self,
        materialized_input: MaterializedArtifactInput,
        project_inventory: ProjectInventoryResult,
    ) -> DataflowAnalysisResult:
        try:
            content = self._archive_reader()
        except Exception as exc:
            raise PythonDataflowError(
                "SOURCE_DATAFLOW_READ_FAILED",
                "Materialized source archive could not be read.",
            ) from exc
        if not isinstance(content, bytes):
            raise PythonDataflowError(
                "SOURCE_DATAFLOW_READ_INVALID",
                "Materialized source reader returned an invalid content type.",
            )

        fresh_inventory = ProjectInventoryAnalyzer(
            archive_reader=lambda: content,
            max_members=self._max_members,
            max_uncompressed_bytes=self._max_uncompressed_bytes,
            max_member_bytes=self._max_member_bytes,
            max_text_bytes=self._max_python_file_bytes,
        ).analyze(materialized_input)
        supplied = ProjectInventoryResult.model_validate(project_inventory)
        if supplied.model_dump(mode="json") != fresh_inventory.model_dump(mode="json"):
            raise PythonDataflowError(
                "SOURCE_DATAFLOW_INVENTORY_MISMATCH",
                "Project inventory does not match the materialized source archive.",
            )
        if supplied.language != "python":
            raise PythonDataflowError(
                "SOURCE_DATAFLOW_LANGUAGE_DENIED",
                "Python dataflow accepts only Python project inventories.",
            )
        other_sources = sorted(
            record.path
            for record in supplied.files
            if PurePosixPath(record.path).suffix.lower() in _OTHER_SOURCE_SUFFIXES
        )
        if other_sources:
            raise PythonDataflowError(
                "SOURCE_DATAFLOW_MULTILANGUAGE_DENIED",
                "Python dataflow does not accept additional source languages.",
            )

        inventory_sha256 = self.inventory_sha256(supplied)
        records = {
            record.path: record
            for record in supplied.files
            if PurePosixPath(record.path).suffix.lower() == ".py"
        }
        hypotheses: list[DataflowHypothesis] = []
        sanitizers: list[SanitizerObservation] = []
        observations: list[ParseObservation] = []
        analyzed_files: list[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(content), mode="r") as archive:
                for path, record in sorted(records.items()):
                    if record.size_bytes > self._max_python_file_bytes:
                        raise PythonDataflowError(
                            "SOURCE_FILE_SIZE_LIMIT",
                            "A Python source file exceeds the static-analysis size limit.",
                        )
                    data = archive.read(path)
                    if hashlib.sha256(data).hexdigest() != record.sha256:
                        raise PythonDataflowError(
                            "SOURCE_DATAFLOW_FILE_HASH_MISMATCH",
                            "Python source hash does not match project inventory.",
                        )
                    try:
                        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
                        source = data.decode(encoding)
                    except (LookupError, SyntaxError, UnicodeDecodeError):
                        observations.append(
                            ParseObservation(
                                file=path,
                                line=0,
                                code="encoding_unsupported",
                            )
                        )
                        continue
                    try:
                        tree = ast.parse(source, filename=path, mode="exec")
                    except (SyntaxError, ValueError) as exc:
                        observations.append(
                            ParseObservation(
                                file=path,
                                line=max(0, getattr(exc, "lineno", 0) or 0),
                                code="syntax_unparseable",
                            )
                        )
                        continue
                    ast_nodes_used = sum(1 for _ in ast.walk(tree))
                    if ast_nodes_used > self._max_ast_nodes_per_file:
                        raise PythonDataflowError(
                            "SOURCE_AST_NODE_LIMIT",
                            "Python source exceeds the static-analysis AST node limit.",
                        )
                    analyzed_files.append(path)
                    visitor = _ScopeDataflow(
                        file=path,
                        artifact_sha256=materialized_input.artifact_sha256,
                    )
                    visitor.visit(tree)
                    hypotheses.extend(visitor.hypotheses)
                    sanitizers.extend(visitor.sanitizers)
        except PythonDataflowError:
            raise
        except (zipfile.BadZipFile, KeyError, RuntimeError, EOFError, RecursionError) as exc:
            raise PythonDataflowError(
                "SOURCE_DATAFLOW_ARCHIVE_INVALID",
                "Materialized source could not be read consistently.",
            ) from exc

        hypotheses.sort(key=lambda item: (item.sink.file, item.sink.line, item.hypothesis_id))
        sanitizers.sort(key=lambda item: (item.file, item.line, item.kind))
        observations.sort(key=lambda item: (item.file, item.line, item.code))
        return DataflowAnalysisResult(
            artifact_id=materialized_input.artifact_id,
            artifact_sha256=materialized_input.artifact_sha256,
            project_inventory_sha256=inventory_sha256,
            analyzed_files=sorted(analyzed_files),
            hypotheses=hypotheses,
            sanitizers=sanitizers,
            parse_observations=observations,
        )

    @staticmethod
    def inventory_sha256(project_inventory: ProjectInventoryResult) -> str:
        payload = json.dumps(
            project_inventory.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _read_fixed_archive() -> bytes:
        return Path(_SOURCE_INPUT_PATH).read_bytes()


class PythonDataflowPlugin:
    """ToolPlugin boundary for the read-only SOURCE_ANALYSIS runner."""

    input_schema = {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "pattern": r"^[0-9a-fA-F-]{36}$"},
            "artifact_sha256": {"type": "string", "pattern": r"^[0-9a-fA-F]{64}$"},
            # The repository's dependency-free argument validator intentionally
            # supports only a small JSON Schema subset. Pydantic performs the
            # full strict ProjectInventoryResult validation in prepare().
            "project_inventory": {"type": "object"},
        },
        "required": ["artifact_id", "artifact_sha256", "project_inventory"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "schema_version": {"type": "string"},
            "observation_type": {"type": "string", "const": "python_dataflow"},
            "artifact_id": {"type": "string"},
            "artifact_sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
            "project_inventory_sha256": {
                "type": "string",
                "pattern": r"^[0-9a-f]{64}$",
            },
            "language": {"type": "string", "const": "python"},
            "analysis_scope": {"type": "string", "const": "sql_injection"},
            "analyzed_files": {"type": "array", "items": {"type": "string"}},
            "hypotheses": {"type": "array", "items": {"type": "object"}},
            "sanitizers": {"type": "array", "items": {"type": "object"}},
            "parse_observations": {"type": "array", "items": {"type": "object"}},
        },
        "required": [
            "schema_version",
            "observation_type",
            "artifact_id",
            "artifact_sha256",
            "project_inventory_sha256",
            "language",
            "analysis_scope",
            "analyzed_files",
            "hypotheses",
            "sanitizers",
            "parse_observations",
        ],
        "additionalProperties": False,
    }

    def __init__(
        self,
        *,
        runtime_available: Callable[[], bool] | None = None,
        resources: ResourceLimits | None = None,
        timeout_seconds: int = 30,
        max_members: int = 2_000,
    ) -> None:
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("source dataflow timeout must be between 1 and 30 seconds")
        if not 1 <= max_members <= 2_000:
            raise ValueError("source dataflow member limit must be between 1 and 2,000")
        self._runtime_available = runtime_available or (lambda: False)
        self._resources = (resources or _DEFAULT_RESOURCES).model_copy(deep=True)
        self._timeout_seconds = timeout_seconds
        self._max_members = max_members
        self._pending: dict[UUID, ToolInvocation] = {}
        self._spec = ToolSpec(
            tool_id=PYTHON_DATAFLOW_TOOL_ID,
            name="Python SQL dataflow hypothesis analysis",
            version="1.0.0",
            plugin_id="builtin.source-audit",
            capabilities=[PYTHON_DATAFLOW_CAPABILITY],
            description=(
                "Offline Python AST analysis that emits SQL dataflow hypotheses "
                "without confirming a vulnerability."
            ),
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects={SideEffect.FILE_READ},
            risk_level=RiskLevel.R0,
            permissions=ToolPermissions(filesystem_read=True),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                image=None,
                entrypoint=[PYTHON_DATAFLOW_TOOL_ID],
                default_timeout_seconds=self._timeout_seconds,
                max_timeout_seconds=self._timeout_seconds,
                default_resources=self._resources,
            ),
        )
        fingerprint_source = json.dumps(
            self._spec.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self._environment_fingerprint = hashlib.sha256(fingerprint_source).hexdigest()

    def get_spec(self) -> ToolSpec:
        return self._spec.model_copy(deep=True)

    async def health_check(self) -> ToolHealth:
        try:
            available = bool(self._runtime_available())
        except Exception:
            available = False
        return ToolHealth(
            tool_ref=ToolRef(tool_id=PYTHON_DATAFLOW_TOOL_ID, version="1.0.0"),
            available=available,
            message=(
                "source-analysis runtime available"
                if available
                else "source-analysis runtime unavailable"
            ),
        )

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        expected = ToolRef(tool_id=PYTHON_DATAFLOW_TOOL_ID, version="1.0.0")
        if invocation.tool_ref != expected:
            raise ValueError("invocation tool reference does not match Python dataflow")
        if invocation.status is not ToolInvocationStatus.APPROVED:
            raise ValueError("only approved Python dataflow invocations can be prepared")
        if invocation.deadline <= datetime.now(timezone.utc):
            raise ValueError("Python dataflow invocation deadline has expired")
        arguments = validate_arguments(invocation.validated_arguments, self.input_schema)
        try:
            artifact_id = UUID(arguments["artifact_id"])
            inventory = ProjectInventoryResult.model_validate(
                arguments["project_inventory"]
            )
        except ValueError as exc:
            raise ArgumentValidationError(
                "Python dataflow artifact or inventory input is invalid"
            ) from exc
        if inventory.artifact_id != artifact_id:
            raise ArgumentValidationError("project inventory artifact id mismatch")
        if inventory.artifact_sha256 != arguments["artifact_sha256"]:
            raise ArgumentValidationError("project inventory artifact hash mismatch")
        if (
            inventory.file_count != len(inventory.files)
            or inventory.file_count > self._max_members
        ):
            raise ArgumentValidationError("project inventory file count is inconsistent")
        remaining = int((invocation.deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining < 1:
            raise ValueError("Python dataflow deadline leaves less than one second")
        inventory_sha256 = PythonDataflowAnalyzer.inventory_sha256(inventory)
        request = ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.SOURCE_ANALYSIS,
            image=None,
            entrypoint=[PYTHON_DATAFLOW_TOOL_ID],
            argv=["--inventory-sha256", inventory_sha256],
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
            raise ValueError("raw result does not match a prepared Python dataflow request")
        status = result.status
        error = result.error
        normalized: dict[str, Any] = {}
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error(
                "SOURCE_DATAFLOW_EXIT_NONZERO",
                "Python dataflow exited with a non-zero status.",
            )
        if status is ToolResultStatus.SUCCEEDED:
            try:
                decoded = json.loads(result.stdout.decode("utf-8"))
                analysis = DataflowAnalysisResult.model_validate(decoded)
                inventory = ProjectInventoryResult.model_validate(
                    invocation.validated_arguments["project_inventory"]
                )
                if str(analysis.artifact_id) != invocation.validated_arguments["artifact_id"]:
                    raise ValueError("Python dataflow artifact id mismatch")
                if analysis.artifact_sha256 != invocation.validated_arguments["artifact_sha256"]:
                    raise ValueError("Python dataflow artifact hash mismatch")
                if analysis.project_inventory_sha256 != PythonDataflowAnalyzer.inventory_sha256(
                    inventory
                ):
                    raise ValueError("Python dataflow inventory fingerprint mismatch")
                normalized = analysis.model_dump(mode="json")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                status = ToolResultStatus.FAILED
                error = self._error(
                    "SOURCE_DATAFLOW_OUTPUT_INVALID",
                    "Python dataflow returned invalid structured output.",
                )
                normalized = {}
        elif error is None:
            error = self._error(
                "SOURCE_DATAFLOW_EXECUTION_FAILED",
                "Python dataflow execution did not succeed.",
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
    def analyze(
        materialized_input: MaterializedArtifactInput,
        project_inventory: ProjectInventoryResult,
        *,
        archive_reader: Callable[[], bytes] | None = None,
    ) -> DataflowAnalysisResult:
        return PythonDataflowAnalyzer(archive_reader=archive_reader).analyze(
            materialized_input,
            project_inventory,
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
    "DataflowAnalysisResult",
    "DataflowHypothesis",
    "DataflowPoint",
    "DataflowSink",
    "DataflowSource",
    "PYTHON_DATAFLOW_CAPABILITY",
    "PYTHON_DATAFLOW_TOOL_ID",
    "ParseObservation",
    "PythonDataflowAnalyzer",
    "PythonDataflowError",
    "PythonDataflowPlugin",
    "SanitizerObservation",
]
