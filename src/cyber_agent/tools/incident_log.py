"""Offline, fact-only log bundle analysis for the incident login-chain scenario.

Two capabilities:

- ``incident.log_inventory`` parses the uploaded log bundle and reports the
  event schema, per-account and per-source-IP counts, and file list.
- ``incident.log_search`` queries events by account / source IP / event type and
  returns a chronological, evidence-backed event sequence.

Both run in-process (SOURCE_ANALYSIS) and never modify the source or take any
remediation action — the scenario is explicitly read-only per design §11.4.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from uuid import UUID

from pydantic import Field

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

from .health import ToolHealthMixin
from .validation import ArgumentValidationError, validate_arguments

INCIDENT_LOG_INVENTORY_TOOL_ID = "incident.log_inventory"
INCIDENT_LOG_INVENTORY_CAPABILITY = "incident.log_inventory"
INCIDENT_LOG_SEARCH_TOOL_ID = "incident.log_search"
INCIDENT_LOG_SEARCH_CAPABILITY = "incident.log_search"

_SOURCE_INPUT_PATH = "/inputs/source.zip"

_DEFAULT_RESOURCES = ResourceLimits(
    cpu_cores=1,
    memory_megabytes=256,
    max_processes=1,
    max_output_bytes=2_000_000,
)

_LOG_EVENT_TYPES = ("login_failed", "login_ok", "api_access")
_LOG_FIELDS = {"ts", "src_ip", "user", "event", "reason", "method", "path", "status"}


class IncidentLogError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class LogEventRecord(StrictModel):
    ts: str = Field(min_length=1, max_length=64)
    src_ip: str = Field(min_length=1, max_length=64)
    user: str = Field(min_length=1, max_length=255)
    event: str = Field(min_length=1, max_length=64)
    fields: dict[str, str | int] = Field(default_factory=dict)


class LogInventoryResult(StrictModel):
    observation_type: str = Field(default="log_inventory", pattern="^log_inventory$")
    artifact_id: UUID
    artifact_sha256: Sha256
    files: list[str]
    total_events: int = Field(ge=0)
    event_types: dict[str, int] = Field(default_factory=dict)
    accounts: dict[str, int] = Field(default_factory=dict)
    source_ips: dict[str, int] = Field(default_factory=dict)


class LogSearchResult(StrictModel):
    observation_type: str = Field(default="log_search", pattern="^log_search$")
    artifact_id: UUID
    artifact_sha256: Sha256
    query: dict[str, str] = Field(default_factory=dict)
    matches: list[LogEventRecord]


def _parse_jsonl(content: bytes) -> list[dict]:
    events: list[dict] = []
    for raw_line in content.decode("utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise IncidentLogError("LOG_JSONL_INVALID", "JSONL log line is not an object.")
        events.append(item)
    return events


def _parse_csv(content: bytes) -> list[dict]:
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
    events: list[dict] = []
    for row in reader:
        events.append({"ts": row["ts"], "src_ip": row["src_ip"], "user": row["user"], "event": "api_access", "path": row["path"], "status": int(row["status"])})
    return events


def _load_events(content: bytes) -> list[dict]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(content), mode="r")
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise IncidentLogError("LOG_BUNDLE_INVALID", "Log bundle is not a readable ZIP archive.") from exc
    events: list[dict] = []
    try:
        for name in archive.namelist():
            member = archive.read(name)
            lower = name.lower()
            if lower.endswith(".jsonl"):
                events.extend(_parse_jsonl(member))
            elif lower.endswith(".csv"):
                events.extend(_parse_csv(member))
    finally:
        archive.close()
    if not events:
        raise IncidentLogError("LOG_BUNDLE_EMPTY", "Log bundle contains no JSONL or CSV events.")
    return events


def _normalize_event(item: dict) -> LogEventRecord:
    fields = {key: value for key, value in item.items() if key in _LOG_FIELDS and key not in {"ts", "src_ip", "user", "event"}}
    return LogEventRecord(
        ts=str(item.get("ts", "")),
        src_ip=str(item.get("src_ip", "")),
        user=str(item.get("user", "")),
        event=str(item.get("event", "")),
        fields=fields,
    )


class IncidentLogAnalyzer:
    """Read a log ZIP and emit only deterministic, evidence-backed metadata."""

    def analyze_inventory(
        self,
        content: bytes,
        *,
        artifact_id: UUID,
        artifact_sha256: str,
    ) -> LogInventoryResult:
        events = _load_events(content)
        event_types: dict[str, int] = {}
        accounts: dict[str, int] = {}
        source_ips: dict[str, int] = {}
        for item in events:
            event = str(item.get("event", ""))
            user = str(item.get("user", ""))
            ip = str(item.get("src_ip", ""))
            event_types[event] = event_types.get(event, 0) + 1
            accounts[user] = accounts.get(user, 0) + 1
            source_ips[ip] = source_ips.get(ip, 0) + 1
        with zipfile.ZipFile(io.BytesIO(content), mode="r") as archive:
            files = archive.namelist()
        return LogInventoryResult(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            files=files,
            total_events=len(events),
            event_types=event_types,
            accounts=accounts,
            source_ips=source_ips,
        )

    def analyze_search(
        self,
        content: bytes,
        *,
        artifact_id: UUID,
        artifact_sha256: str,
        query: dict[str, str],
    ) -> LogSearchResult:
        events = _load_events(content)
        matches = []
        for item in events:
            if "user" in query and str(item.get("user", "")) != query["user"]:
                continue
            if "src_ip" in query and str(item.get("src_ip", "")) != query["src_ip"]:
                continue
            if "event" in query and str(item.get("event", "")) != query["event"]:
                continue
            matches.append(_normalize_event(item))
        matches.sort(key=lambda item: item.ts)
        return LogSearchResult(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            query=query,
            matches=matches,
        )


class _IncidentPlugin(ToolHealthMixin):
    tool_id: str
    capability: str
    entrypoint: str

    def __init__(self, *, runtime_available: Callable[[], bool] | None = None) -> None:
        self._runtime_available = runtime_available or (lambda: False)
        self._pending: dict[UUID, ToolInvocation] = {}
        self._spec = self._build_spec()
        fingerprint = json.dumps(
            self._spec.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        self._environment_fingerprint = hashlib.sha256(fingerprint).hexdigest()

    def _build_spec(self) -> ToolSpec:
        raise NotImplementedError

    def get_spec(self) -> ToolSpec:
        return self._spec.model_copy(deep=True)

    async def health_check(self) -> ToolHealth:
        return self.probe_health(
            probe=self._runtime_available,
            success_message="source-analysis runtime available",
            failure_message="source-analysis runtime unavailable",
            tool_ref=ToolRef(tool_id=self.tool_id, version="1.0.0"),
        )

    def _prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        raise NotImplementedError

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        expected = ToolRef(tool_id=self.tool_id, version="1.0.0")
        if invocation.tool_ref != expected:
            raise ValueError("invocation tool reference does not match incident tool")
        if invocation.status is not ToolInvocationStatus.APPROVED:
            raise ValueError("only approved incident invocations can be prepared")
        if invocation.deadline <= datetime.now(timezone.utc):
            raise ValueError("incident invocation deadline has expired")
        arguments = validate_arguments(invocation.validated_arguments, self.input_schema)
        request = self._prepare(invocation, arguments)
        self._pending[request.request_id] = invocation
        return request

    def parse(self, result: RawExecutionResult) -> ToolResult:
        invocation = self._pending.pop(result.request_id, None)
        if invocation is None:
            raise ValueError("raw result does not match a prepared incident request")
        status = result.status
        error = result.error
        normalized: dict = {}
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error("INCIDENT_LOG_EXIT_NONZERO", "Log analysis exited non-zero.")
        if status is ToolResultStatus.SUCCEEDED:
            try:
                decoded = json.loads(result.stdout.decode("utf-8"))
                model = self._result_model().model_validate(decoded)
                normalized = model.model_dump(mode="json")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                status = ToolResultStatus.FAILED
                error = self._error("INCIDENT_LOG_OUTPUT_INVALID", "Log analysis returned invalid output.")
                normalized = {}
        elif error is None:
            error = self._error("INCIDENT_LOG_EXECUTION_FAILED", "Log analysis did not succeed.")
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

    def _result_model(self):
        raise NotImplementedError

    @staticmethod
    def _error(code: str, message: str) -> ErrorInfo:
        return ErrorInfo(
            code=code,
            category=ErrorCategory.TOOL_FAILED,
            retryable=False,
            safe_message=message,
        )


class IncidentLogInventoryPlugin(_IncidentPlugin):
    tool_id = INCIDENT_LOG_INVENTORY_TOOL_ID
    capability = INCIDENT_LOG_INVENTORY_CAPABILITY
    entrypoint = INCIDENT_LOG_INVENTORY_TOOL_ID

    def _result_model(self):
        return LogInventoryResult

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
            "observation_type": {"type": "string", "const": "log_inventory"},
            "artifact_id": {"type": "string"},
            "artifact_sha256": {"type": "string"},
            "files": {"type": "array", "items": {"type": "string"}},
            "total_events": {"type": "integer", "minimum": 0},
            "event_types": {"type": "object"},
            "accounts": {"type": "object"},
            "source_ips": {"type": "object"},
        },
        "required": ["observation_type", "artifact_id", "artifact_sha256", "files", "total_events", "event_types", "accounts", "source_ips"],
        "additionalProperties": False,
    }

    def _build_spec(self) -> ToolSpec:
        return ToolSpec(
            tool_id=self.tool_id,
            name="Incident log inventory",
            version="1.0.0",
            plugin_id="builtin.incident",
            capabilities=[self.capability],
            description="Offline inventory of one log bundle: files, event counts, accounts, and source IPs.",
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects={SideEffect.FILE_READ},
            risk_level=RiskLevel.R0,
            permissions=ToolPermissions(filesystem_read=True),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                image=None,
                entrypoint=[self.entrypoint],
                default_timeout_seconds=30,
                max_timeout_seconds=60,
                default_resources=_DEFAULT_RESOURCES,
            ),
        )

    def _prepare(self, invocation: ToolInvocation, arguments: dict) -> ExecutionRequest:
        try:
            artifact_id = UUID(arguments["artifact_id"])
        except ValueError as exc:
            raise ArgumentValidationError("artifact_id must be a UUID") from exc
        remaining = int((invocation.deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining < 1:
            raise ValueError("inventory deadline leaves less than one second")
        return ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.SOURCE_ANALYSIS,
            image=None,
            entrypoint=[self.entrypoint],
            argv=[],
            mounts=[MountSpec(artifact_id=artifact_id, container_path=_SOURCE_INPUT_PATH, read_only=True)],
            environment={},
            network_policy=NetworkPolicy(),
            resources=_DEFAULT_RESOURCES.model_copy(deep=True),
            timeout_seconds=min(30, remaining),
        )


class IncidentLogSearchPlugin(_IncidentPlugin):
    tool_id = INCIDENT_LOG_SEARCH_TOOL_ID
    capability = INCIDENT_LOG_SEARCH_CAPABILITY
    entrypoint = INCIDENT_LOG_SEARCH_TOOL_ID

    def _result_model(self):
        return LogSearchResult

    input_schema = {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "pattern": r"^[0-9a-fA-F-]{36}$"},
            "artifact_sha256": {"type": "string", "pattern": r"^[0-9a-fA-F]{64}$"},
            "query": {"type": "object"},
        },
        "required": ["artifact_id", "artifact_sha256", "query"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "observation_type": {"type": "string", "const": "log_search"},
            "artifact_id": {"type": "string"},
            "artifact_sha256": {"type": "string"},
            "query": {"type": "object"},
            "matches": {"type": "array", "items": {"type": "object"}},
        },
        "required": ["observation_type", "artifact_id", "artifact_sha256", "query", "matches"],
        "additionalProperties": False,
    }

    def _build_spec(self) -> ToolSpec:
        return ToolSpec(
            tool_id=self.tool_id,
            name="Incident log search",
            version="1.0.0",
            plugin_id="builtin.incident",
            capabilities=[self.capability],
            description="Query one log bundle by account, source IP, or event type.",
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects={SideEffect.FILE_READ},
            risk_level=RiskLevel.R1,
            permissions=ToolPermissions(filesystem_read=True),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                image=None,
                entrypoint=[self.entrypoint],
                default_timeout_seconds=30,
                max_timeout_seconds=60,
                default_resources=_DEFAULT_RESOURCES,
            ),
        )

    def _prepare(self, invocation: ToolInvocation, arguments: dict) -> ExecutionRequest:
        try:
            artifact_id = UUID(arguments["artifact_id"])
        except ValueError as exc:
            raise ArgumentValidationError("artifact_id must be a UUID") from exc
        query = arguments.get("query") or {}
        if not isinstance(query, dict) or not query:
            raise ArgumentValidationError("log_search requires a non-empty query")
        for key in query:
            if key not in {"user", "src_ip", "event"}:
                raise ArgumentValidationError(f"log_search query key is not allowed: {key}")
        remaining = int((invocation.deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining < 1:
            raise ValueError("search deadline leaves less than one second")
        return ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.SOURCE_ANALYSIS,
            image=None,
            entrypoint=[self.entrypoint],
            argv=[json.dumps(query, sort_keys=True)],
            mounts=[MountSpec(artifact_id=artifact_id, container_path=_SOURCE_INPUT_PATH, read_only=True)],
            environment={},
            network_policy=NetworkPolicy(),
            resources=_DEFAULT_RESOURCES.model_copy(deep=True),
            timeout_seconds=min(30, remaining),
        )


__all__ = [
    "INCIDENT_LOG_INVENTORY_CAPABILITY",
    "INCIDENT_LOG_INVENTORY_TOOL_ID",
    "INCIDENT_LOG_SEARCH_CAPABILITY",
    "INCIDENT_LOG_SEARCH_TOOL_ID",
    "IncidentLogAnalyzer",
    "IncidentLogError",
    "IncidentLogInventoryPlugin",
    "IncidentLogSearchPlugin",
    "LogEventRecord",
    "LogInventoryResult",
    "LogSearchResult",
]
