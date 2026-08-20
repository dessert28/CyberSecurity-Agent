"""Offline, fact-only inventory for one materialized Python source archive."""

from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import tomllib
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
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

from .validation import ArgumentValidationError, validate_arguments

PROJECT_INVENTORY_TOOL_ID = "source.project_inventory"
PROJECT_INVENTORY_CAPABILITY = "source.inventory"
_SOURCE_INPUT_PATH = "/inputs/source.zip"
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_FLASK_ROUTE = re.compile(
    r"^\s*@(?:[A-Za-z_]\w*\.)+route\(\s*['\"]([^'\"]+)['\"]"
    r"(?:[^)]*?methods\s*=\s*\[([^\]]*)\])?",
)
_FASTAPI_ROUTE = re.compile(
    r"^\s*@(?:[A-Za-z_]\w*\.)+(get|post|put|patch|delete|options|head)"
    r"\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_DJANGO_ROUTE = re.compile(r"\b(?:path|re_path)\(\s*['\"]([^'\"]+)['\"]")
_QUOTED_VALUE = re.compile(r"['\"]([^'\"]+)['\"]")
_SUPPORTED_TEXT_TYPES = {
    ".cfg": "config",
    ".html": "template",
    ".ini": "config",
    ".j2": "template",
    ".jinja": "template",
    ".json": "json",
    ".md": "markdown",
    ".py": "python",
    ".toml": "toml",
    ".txt": "text",
    ".yaml": "yaml",
    ".yml": "yaml",
}
_COMMON_ENTRYPOINTS = {
    "app.py",
    "asgi.py",
    "main.py",
    "manage.py",
    "run.py",
    "server.py",
    "wsgi.py",
}
_DEFAULT_RESOURCES = ResourceLimits(
    cpu_cores=1,
    memory_megabytes=256,
    max_processes=1,
    max_output_bytes=5_000_000,
)


class ProjectInventoryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ProjectFileRecord(StrictModel):
    path: str = Field(min_length=1, max_length=2048)
    size_bytes: int = Field(ge=0)
    sha256: Sha256
    file_type: str = Field(min_length=1, max_length=64)
    supported: bool


class PythonVersionHint(StrictModel):
    source: str = Field(min_length=1, max_length=2048)
    value: str = Field(min_length=1, max_length=255)


class RouteCandidate(StrictModel):
    framework: str = Field(min_length=1, max_length=64)
    file: str = Field(min_length=1, max_length=2048)
    line: int = Field(ge=1)
    path: str = Field(min_length=1, max_length=2048)
    methods: list[str] = Field(default_factory=list)


class DependencyManifest(StrictModel):
    path: str = Field(min_length=1, max_length=2048)
    format: str = Field(min_length=1, max_length=64)
    dependencies: list[str] = Field(default_factory=list)


class ProjectInventoryResult(StrictModel):
    observation_type: str = Field(default="project_inventory", pattern="^project_inventory$")
    artifact_id: UUID
    artifact_sha256: Sha256
    language: str = Field(min_length=1, max_length=64)
    files: list[ProjectFileRecord]
    file_count: int = Field(ge=0)
    zip_size_bytes: int = Field(ge=0)
    python_version_hints: list[PythonVersionHint] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    routes: list[RouteCandidate] = Field(default_factory=list)
    dependencies: list[DependencyManifest] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list)
    unsupported_file_types: list[str] = Field(default_factory=list)


class ProjectInventoryAnalyzer:
    """Read a fixed ZIP input and emit only deterministic project metadata."""

    def __init__(
        self,
        *,
        archive_reader: Callable[[], bytes] | None = None,
        max_members: int = 2_000,
        max_uncompressed_bytes: int = 50_000_000,
        max_member_bytes: int = 5_000_000,
        max_text_bytes: int = 1_000_000,
    ) -> None:
        if min(
            max_members,
            max_uncompressed_bytes,
            max_member_bytes,
            max_text_bytes,
        ) < 1:
            raise ValueError("inventory limits must be positive")
        if max_member_bytes > max_uncompressed_bytes:
            raise ValueError("member limit cannot exceed the total expanded-size limit")
        self._archive_reader = archive_reader or self._read_fixed_archive
        self._max_members = max_members
        self._max_uncompressed_bytes = max_uncompressed_bytes
        self._max_member_bytes = max_member_bytes
        self._max_text_bytes = max_text_bytes

    def analyze(self, materialized_input: MaterializedArtifactInput) -> ProjectInventoryResult:
        self._validate_input(materialized_input)
        try:
            content = self._archive_reader()
        except Exception as exc:
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_READ_FAILED",
                "Materialized source archive could not be read.",
            ) from exc
        if not isinstance(content, bytes):
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_READ_INVALID",
                "Materialized source reader returned an invalid content type.",
            )
        if len(content) != materialized_input.size_bytes:
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_SIZE_MISMATCH",
                "Materialized source size does not match its lease.",
            )
        digest = hashlib.sha256(content).hexdigest()
        if digest != materialized_input.artifact_sha256:
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_HASH_MISMATCH",
                "Materialized source hash does not match its lease.",
            )

        file_records: list[ProjectFileRecord] = []
        text_by_path: dict[str, str] = {}
        unsupported_types: set[str] = set()
        try:
            archive = zipfile.ZipFile(io.BytesIO(content), mode="r")
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_INVALID",
                "Materialized source is not a readable ZIP archive.",
            ) from exc
        try:
            members = archive.infolist()
            if len(members) > self._max_members:
                raise ProjectInventoryError(
                    "ARTIFACT_ZIP_TOO_MANY_MEMBERS",
                    "Source archive contains too many members.",
                )
            total_size = 0
            observed_size = 0
            seen_paths: set[str] = set()
            for member in members:
                path = self._safe_member_path(member)
                key = path.casefold()
                if key in seen_paths:
                    raise ProjectInventoryError(
                        "SOURCE_ARCHIVE_DUPLICATE_PATH",
                        "Source archive contains duplicate paths.",
                    )
                seen_paths.add(key)
                if member.is_dir():
                    continue
                if member.file_size > self._max_member_bytes:
                    raise ProjectInventoryError(
                        "ARTIFACT_ZIP_MEMBER_TOO_LARGE",
                        "A source archive member exceeds the configured size limit.",
                    )
                total_size += member.file_size
                if total_size > self._max_uncompressed_bytes:
                    raise ProjectInventoryError(
                        "ARTIFACT_ZIP_TOO_LARGE",
                        "Source archive exceeds the expanded-size limit.",
                    )
                chunks: list[bytes] = []
                member_size = 0
                with archive.open(member, mode="r") as source:
                    while chunk := source.read(64 * 1024):
                        member_size += len(chunk)
                        observed_size += len(chunk)
                        if member_size > self._max_member_bytes:
                            raise ProjectInventoryError(
                                "ARTIFACT_ZIP_MEMBER_TOO_LARGE",
                                "A source archive member exceeds the configured size limit.",
                            )
                        if observed_size > self._max_uncompressed_bytes:
                            raise ProjectInventoryError(
                                "ARTIFACT_ZIP_TOO_LARGE",
                                "Source archive exceeds the expanded-size limit.",
                            )
                        chunks.append(chunk)
                data = b"".join(chunks)
                if len(data) != member.file_size:
                    raise ProjectInventoryError(
                        "SOURCE_ARCHIVE_INVALID",
                        "Source archive member size is inconsistent.",
                    )
                file_type, supported = self._classify_file(path)
                file_records.append(
                    ProjectFileRecord(
                        path=path,
                        size_bytes=len(data),
                        sha256=hashlib.sha256(data).hexdigest(),
                        file_type=file_type,
                        supported=supported,
                    )
                )
                if not supported:
                    unsupported_types.add(self._extension_label(path))
                elif len(data) <= self._max_text_bytes:
                    try:
                        text_by_path[path] = data.decode("utf-8-sig")
                    except UnicodeDecodeError:
                        unsupported_types.add(self._extension_label(path))
        except ProjectInventoryError:
            raise
        except (zipfile.BadZipFile, RuntimeError, EOFError, NotImplementedError) as exc:
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_INVALID",
                "Source archive content could not be validated.",
            ) from exc
        finally:
            archive.close()

        file_records.sort(key=lambda item: item.path)
        dependencies, python_hints = self._dependency_metadata(text_by_path)
        frameworks = self._detect_frameworks(text_by_path, dependencies)
        entrypoints = self._entrypoints(text_by_path)
        routes = self._routes(text_by_path)
        dependency_files = sorted(item.path for item in dependencies)
        language = "python" if any(item.file_type == "python" for item in file_records) else "unknown"
        return ProjectInventoryResult(
            artifact_id=materialized_input.artifact_id,
            artifact_sha256=materialized_input.artifact_sha256,
            language=language,
            files=file_records,
            file_count=len(file_records),
            zip_size_bytes=len(content),
            python_version_hints=python_hints,
            frameworks=frameworks,
            entrypoints=entrypoints,
            routes=routes,
            dependencies=dependencies,
            dependency_files=dependency_files,
            unsupported_file_types=sorted(unsupported_types),
        )

    @staticmethod
    def _validate_input(materialized_input: MaterializedArtifactInput) -> None:
        if materialized_input.container_path != _SOURCE_INPUT_PATH:
            raise ProjectInventoryError(
                "SOURCE_INPUT_PATH_DENIED",
                "Project inventory accepts only the fixed source archive path.",
            )
        if materialized_input.read_only is not True:
            raise ProjectInventoryError(
                "SOURCE_INPUT_WRITABLE_DENIED",
                "Project inventory requires a read-only source archive.",
            )
        if materialized_input.media_type != "application/zip":
            raise ProjectInventoryError(
                "SOURCE_INPUT_MEDIA_DENIED",
                "Project inventory accepts only ZIP source archives.",
            )

    @staticmethod
    def _safe_member_path(member: zipfile.ZipInfo) -> str:
        name = member.filename
        if not name or "\x00" in name:
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_PATH_DENIED",
                "Source archive contains an invalid member path.",
            )
        normalized = name.replace("\\", "/")
        path = PurePosixPath(normalized)
        if (
            normalized.startswith("/")
            or _DRIVE_PREFIX.match(normalized)
            or path.is_absolute()
            or ".." in path.parts
        ):
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_PATH_DENIED",
                "Source archive member escapes the logical root.",
            )
        member_type = stat.S_IFMT(member.external_attr >> 16)
        if member_type == stat.S_IFLNK:
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_LINK_DENIED",
                "Source archive links are not supported.",
            )
        if member_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise ProjectInventoryError(
                "SOURCE_ARCHIVE_SPECIAL_FILE_DENIED",
                "Source archive special files are not supported.",
            )
        return path.as_posix().rstrip("/")

    @staticmethod
    def _classify_file(path: str) -> tuple[str, bool]:
        name = PurePosixPath(path).name.lower()
        if name == "dockerfile":
            return "dockerfile", True
        suffix = PurePosixPath(path).suffix.lower()
        file_type = _SUPPORTED_TEXT_TYPES.get(suffix)
        if file_type is None:
            return suffix.lstrip(".") or "unknown", False
        return file_type, True

    @staticmethod
    def _extension_label(path: str) -> str:
        suffix = PurePosixPath(path).suffix.lower()
        return suffix or "<none>"

    @staticmethod
    def _dependency_metadata(
        text_by_path: dict[str, str],
    ) -> tuple[list[DependencyManifest], list[PythonVersionHint]]:
        manifests: list[DependencyManifest] = []
        hints: list[PythonVersionHint] = []
        for path, text in sorted(text_by_path.items()):
            name = PurePosixPath(path).name.lower()
            if name.startswith("requirements") and name.endswith(".txt"):
                dependencies = []
                for raw_line in text.splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith(("#", "-")):
                        continue
                    line = line.split(" #", 1)[0].strip()
                    if line:
                        dependencies.append(line)
                manifests.append(
                    DependencyManifest(
                        path=path,
                        format="requirements",
                        dependencies=dependencies,
                    )
                )
            elif name == "pyproject.toml":
                try:
                    document = tomllib.loads(text)
                except tomllib.TOMLDecodeError:
                    continue
                project = document.get("project")
                if isinstance(project, dict):
                    raw_dependencies = project.get("dependencies", [])
                    dependencies = [
                        item for item in raw_dependencies if isinstance(item, str)
                    ] if isinstance(raw_dependencies, list) else []
                    manifests.append(
                        DependencyManifest(
                            path=path,
                            format="pyproject",
                            dependencies=dependencies,
                        )
                    )
                    requires_python = project.get("requires-python")
                    if isinstance(requires_python, str) and requires_python.strip():
                        hints.append(
                            PythonVersionHint(
                                source=path,
                                value=requires_python.strip(),
                            )
                        )
            elif name == ".python-version":
                value = text.strip()
                if value:
                    hints.append(PythonVersionHint(source=path, value=value[:255]))
            elif name == "runtime.txt":
                match = re.search(r"python[-= ]([0-9][^\s]*)", text, re.IGNORECASE)
                if match:
                    hints.append(PythonVersionHint(source=path, value=match.group(1)))
            elif name == "dockerfile":
                match = re.search(r"^\s*FROM\s+python:([^\s]+)", text, re.MULTILINE | re.IGNORECASE)
                if match:
                    hints.append(PythonVersionHint(source=path, value=match.group(1)))
        return manifests, hints

    @staticmethod
    def _detect_frameworks(
        text_by_path: dict[str, str],
        manifests: list[DependencyManifest],
    ) -> list[str]:
        observed: set[str] = set()
        dependency_names = {
            re.split(r"[<>=!~;@\s\[]", dependency, maxsplit=1)[0].lower()
            for manifest in manifests
            for dependency in manifest.dependencies
        }
        if "flask" in dependency_names:
            observed.add("flask")
        if "fastapi" in dependency_names:
            observed.add("fastapi")
        if "django" in dependency_names:
            observed.add("django")
        for path, text in text_by_path.items():
            if not path.lower().endswith(".py"):
                continue
            lowered = text.lower()
            if "from flask import" in lowered or "import flask" in lowered or "flask(" in lowered:
                observed.add("flask")
            if "from fastapi import" in lowered or "import fastapi" in lowered or "fastapi(" in lowered:
                observed.add("fastapi")
            if "from django" in lowered or "import django" in lowered:
                observed.add("django")
        return sorted(observed)

    @staticmethod
    def _entrypoints(text_by_path: dict[str, str]) -> list[str]:
        candidates: set[str] = set()
        for path, text in text_by_path.items():
            if not path.lower().endswith(".py"):
                continue
            if PurePosixPath(path).name.lower() in _COMMON_ENTRYPOINTS:
                candidates.add(path)
            if re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", text):
                candidates.add(path)
        return sorted(candidates)

    @staticmethod
    def _routes(text_by_path: dict[str, str]) -> list[RouteCandidate]:
        routes: list[RouteCandidate] = []
        for path, text in sorted(text_by_path.items()):
            if not path.lower().endswith(".py"):
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                fastapi = _FASTAPI_ROUTE.search(line)
                if fastapi:
                    routes.append(
                        RouteCandidate(
                            framework="fastapi",
                            file=path,
                            line=line_number,
                            path=fastapi.group(2),
                            methods=[fastapi.group(1).upper()],
                        )
                    )
                    continue
                flask = _FLASK_ROUTE.search(line)
                if flask:
                    raw_methods = flask.group(2)
                    methods = (
                        [item.upper() for item in _QUOTED_VALUE.findall(raw_methods)]
                        if raw_methods
                        else ["GET"]
                    )
                    routes.append(
                        RouteCandidate(
                            framework="flask",
                            file=path,
                            line=line_number,
                            path=flask.group(1),
                            methods=methods,
                        )
                    )
                    continue
                django = _DJANGO_ROUTE.search(line)
                if django:
                    route_path = django.group(1)
                    routes.append(
                        RouteCandidate(
                            framework="django",
                            file=path,
                            line=line_number,
                            path="/" + route_path.lstrip("/"),
                            methods=[],
                        )
                    )
        return routes

    @staticmethod
    def _read_fixed_archive() -> bytes:
        return Path(_SOURCE_INPUT_PATH).read_bytes()


class ProjectInventoryPlugin:
    """ToolPlugin boundary for the dedicated offline source-analysis runner."""

    input_schema = {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "pattern": r"^[0-9a-fA-F-]{36}$"},
            "artifact_sha256": {"type": "string", "pattern": r"^[0-9a-fA-F]{64}$"},
        },
        "required": ["artifact_id", "artifact_sha256"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "observation_type": {"type": "string", "const": "project_inventory"},
            "artifact_id": {"type": "string"},
            "artifact_sha256": {"type": "string"},
            "language": {"type": "string"},
            "files": {"type": "array", "items": {"type": "object"}},
            "file_count": {"type": "integer", "minimum": 0},
            "zip_size_bytes": {"type": "integer", "minimum": 0},
            "python_version_hints": {"type": "array", "items": {"type": "object"}},
            "frameworks": {"type": "array", "items": {"type": "string"}},
            "entrypoints": {"type": "array", "items": {"type": "string"}},
            "routes": {"type": "array", "items": {"type": "object"}},
            "dependencies": {"type": "array", "items": {"type": "object"}},
            "dependency_files": {"type": "array", "items": {"type": "string"}},
            "unsupported_file_types": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "observation_type",
            "artifact_id",
            "artifact_sha256",
            "language",
            "files",
            "file_count",
            "zip_size_bytes",
            "python_version_hints",
            "frameworks",
            "entrypoints",
            "routes",
            "dependencies",
            "dependency_files",
            "unsupported_file_types",
        ],
        "additionalProperties": False,
    }

    def __init__(
        self,
        *,
        runtime_available: Callable[[], bool] | None = None,
        resources: ResourceLimits | None = None,
        timeout_seconds: int = 30,
    ) -> None:
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("source inventory timeout must be between 1 and 30 seconds")
        self._runtime_available = runtime_available or (lambda: False)
        self._resources = (resources or _DEFAULT_RESOURCES).model_copy(deep=True)
        self._timeout_seconds = timeout_seconds
        self._pending: dict[UUID, ToolInvocation] = {}
        self._spec = ToolSpec(
            tool_id=PROJECT_INVENTORY_TOOL_ID,
            name="Source project inventory",
            version="1.0.0",
            plugin_id="builtin.source-audit",
            capabilities=[PROJECT_INVENTORY_CAPABILITY],
            description="Offline fact-only inventory of one materialized source ZIP.",
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects={SideEffect.FILE_READ},
            risk_level=RiskLevel.R0,
            permissions=ToolPermissions(filesystem_read=True),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                image=None,
                entrypoint=[PROJECT_INVENTORY_TOOL_ID],
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
            tool_ref=ToolRef(tool_id=PROJECT_INVENTORY_TOOL_ID, version="1.0.0"),
            available=available,
            message=(
                "source-analysis runtime available"
                if available
                else "source-analysis runtime unavailable"
            ),
        )

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        expected = ToolRef(tool_id=PROJECT_INVENTORY_TOOL_ID, version="1.0.0")
        if invocation.tool_ref != expected:
            raise ValueError("invocation tool reference does not match project inventory")
        if invocation.status is not ToolInvocationStatus.APPROVED:
            raise ValueError("only approved inventory invocations can be prepared")
        if invocation.deadline <= datetime.now(timezone.utc):
            raise ValueError("inventory invocation deadline has expired")
        arguments = validate_arguments(invocation.validated_arguments, self.input_schema)
        try:
            artifact_id = UUID(arguments["artifact_id"])
        except ValueError as exc:
            raise ArgumentValidationError("artifact_id must be a UUID") from exc
        remaining = int((invocation.deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining < 1:
            raise ValueError("inventory invocation deadline leaves less than one second")
        request = ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.SOURCE_ANALYSIS,
            image=None,
            entrypoint=[PROJECT_INVENTORY_TOOL_ID],
            argv=[],
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
            raise ValueError("raw result does not match a prepared inventory request")
        status = result.status
        error = result.error
        normalized: dict[str, Any] = {}
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error(
                "SOURCE_INVENTORY_EXIT_NONZERO",
                "Project inventory exited with a non-zero status.",
            )
        if status is ToolResultStatus.SUCCEEDED:
            try:
                decoded = json.loads(result.stdout.decode("utf-8"))
                inventory = ProjectInventoryResult.model_validate(decoded)
                if str(inventory.artifact_id) != invocation.validated_arguments["artifact_id"]:
                    raise ValueError("inventory artifact id mismatch")
                if inventory.artifact_sha256 != invocation.validated_arguments["artifact_sha256"]:
                    raise ValueError("inventory artifact hash mismatch")
                normalized = inventory.model_dump(mode="json")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                status = ToolResultStatus.FAILED
                error = self._error(
                    "SOURCE_INVENTORY_OUTPUT_INVALID",
                    "Project inventory returned invalid structured output.",
                )
                normalized = {}
        elif error is None:
            error = self._error(
                "SOURCE_INVENTORY_EXECUTION_FAILED",
                "Project inventory execution did not succeed.",
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
        *,
        archive_reader: Callable[[], bytes] | None = None,
    ) -> ProjectInventoryResult:
        return ProjectInventoryAnalyzer(archive_reader=archive_reader).analyze(
            materialized_input
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
    "DependencyManifest",
    "PROJECT_INVENTORY_CAPABILITY",
    "PROJECT_INVENTORY_TOOL_ID",
    "ProjectFileRecord",
    "ProjectInventoryAnalyzer",
    "ProjectInventoryError",
    "ProjectInventoryPlugin",
    "ProjectInventoryResult",
    "PythonVersionHint",
    "RouteCandidate",
]
