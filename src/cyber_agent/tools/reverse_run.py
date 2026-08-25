"""Deterministic run-verify tool for the reverse keycheck scenario.

``prepare`` passes a candidate key to the registered handler, which replays the
trusted key checker (Strace/Ltrace flavor) instead of spawning a real process.
"""

from __future__ import annotations

import hashlib
import json
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

REVERSE_RUN_VERIFY_TOOL_ID = "reverse.run_verify"
REVERSE_RUN_VERIFY_CAPABILITY = "reverse.run_verify"

_BINARY_INPUT_PATH = "/inputs/source.zip"

_DEFAULT_RESOURCES = ResourceLimits(
    cpu_cores=1,
    memory_megabytes=256,
    max_processes=1,
    max_output_bytes=1_000_000,
)


class RunVerifyResult(StrictModel):
    observation_type: str = Field(default="run_verify", pattern="^run_verify$")
    artifact_id: UUID
    artifact_sha256: Sha256
    candidate: str = Field(min_length=1, max_length=255)
    accepted: bool
    observed_output: str = Field(min_length=1, max_length=20_000)


class ReverseRunPlugin(ToolHealthMixin):
    """ToolPlugin boundary for the fixed keycheck run verification."""

    input_schema = {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "pattern": r"^[0-9a-fA-F-]{36}$"},
            "artifact_sha256": {"type": "string", "pattern": r"^[0-9a-fA-F]{64}$"},
            "candidate": {"type": "string", "minLength": 1, "maxLength": 255},
        },
        "required": ["artifact_id", "artifact_sha256", "candidate"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "observation_type": {"type": "string", "const": "run_verify"},
            "artifact_id": {"type": "string"},
            "artifact_sha256": {"type": "string"},
            "candidate": {"type": "string"},
            "accepted": {"type": "boolean"},
            "observed_output": {"type": "string"},
        },
        "required": [
            "observation_type",
            "artifact_id",
            "artifact_sha256",
            "candidate",
            "accepted",
            "observed_output",
        ],
        "additionalProperties": False,
    }

    def __init__(self, *, runtime_available: Callable[[], bool] | None = None) -> None:
        self._runtime_available = runtime_available or (lambda: False)
        self._pending: dict[UUID, ToolInvocation] = {}
        self._spec = ToolSpec(
            tool_id=REVERSE_RUN_VERIFY_TOOL_ID,
            name="Reverse run verification",
            version="1.0.0",
            plugin_id="builtin.reverse",
            capabilities=[REVERSE_RUN_VERIFY_CAPABILITY],
            description="Deterministic keycheck run verification for one candidate key.",
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects={SideEffect.PROCESS_INTERACTION},
            risk_level=RiskLevel.R2,
            permissions=ToolPermissions(process_interaction=True, filesystem_read=True),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                image=None,
                entrypoint=[REVERSE_RUN_VERIFY_TOOL_ID],
                default_timeout_seconds=30,
                max_timeout_seconds=60,
                default_resources=_DEFAULT_RESOURCES,
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
        return self.probe_health(
            probe=self._runtime_available,
            success_message="source-analysis runtime available",
            failure_message="source-analysis runtime unavailable",
            tool_ref=ToolRef(
                tool_id=REVERSE_RUN_VERIFY_TOOL_ID,
                version="1.0.0",
            ),
        )

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        expected = ToolRef(tool_id=REVERSE_RUN_VERIFY_TOOL_ID, version="1.0.0")
        if invocation.tool_ref != expected:
            raise ValueError("invocation tool reference does not match reverse.run_verify")
        if invocation.status is not ToolInvocationStatus.APPROVED:
            raise ValueError("only approved run-verify invocations can be prepared")
        if invocation.deadline <= datetime.now(timezone.utc):
            raise ValueError("run-verify invocation deadline has expired")
        arguments = validate_arguments(invocation.validated_arguments, self.input_schema)
        try:
            artifact_id = UUID(arguments["artifact_id"])
        except ValueError as exc:
            raise ArgumentValidationError("artifact_id must be a UUID") from exc
        candidate = str(arguments["candidate"])
        remaining = int((invocation.deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining < 1:
            raise ValueError("run-verify invocation deadline leaves less than one second")
        request = ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.SOURCE_ANALYSIS,
            image=None,
            entrypoint=[REVERSE_RUN_VERIFY_TOOL_ID],
            argv=[candidate],
            mounts=[
                MountSpec(
                    artifact_id=artifact_id,
                    container_path=_BINARY_INPUT_PATH,
                    read_only=True,
                )
            ],
            environment={},
            network_policy=NetworkPolicy(),
            resources=_DEFAULT_RESOURCES.model_copy(deep=True),
            timeout_seconds=min(30, remaining),
        )
        self._pending[request.request_id] = invocation
        return request

    def parse(self, result: RawExecutionResult) -> ToolResult:
        invocation = self._pending.pop(result.request_id, None)
        if invocation is None:
            raise ValueError("raw result does not match a prepared run-verify request")
        status = result.status
        error = result.error
        normalized: dict = {}
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error(
                "REVERSE_RUN_EXIT_NONZERO",
                "Run verification exited with a non-zero status.",
            )
        if status is ToolResultStatus.SUCCEEDED:
            try:
                decoded = json.loads(result.stdout.decode("utf-8"))
                run = RunVerifyResult.model_validate(decoded)
                if str(run.artifact_id) != invocation.validated_arguments["artifact_id"]:
                    raise ValueError("run-verify artifact id mismatch")
                if run.artifact_sha256 != invocation.validated_arguments["artifact_sha256"]:
                    raise ValueError("run-verify artifact hash mismatch")
                if run.candidate != invocation.validated_arguments["candidate"]:
                    raise ValueError("run-verify candidate mismatch")
                normalized = run.model_dump(mode="json")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                status = ToolResultStatus.FAILED
                error = self._error(
                    "REVERSE_RUN_OUTPUT_INVALID",
                    "Run verification returned invalid structured output.",
                )
                normalized = {}
        elif error is None:
            error = self._error(
                "REVERSE_RUN_EXECUTION_FAILED",
                "Run verification did not succeed.",
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
    "REVERSE_RUN_VERIFY_CAPABILITY",
    "REVERSE_RUN_VERIFY_TOOL_ID",
    "ReverseRunPlugin",
    "RunVerifyResult",
]
