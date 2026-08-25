"""Deterministic process-interaction tool for the Pwn ret2win scenario.

``prepare`` turns structured exploit parameters (padding length + target
address) into a fixed-format payload; the registered handler replays that
payload through the trusted ret2win runner instead of spawning a real process.
"""

from __future__ import annotations

import hashlib
import json
import struct
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

PWN_PROCESS_INTERACTION_TOOL_ID = "pwn.process_interaction"
PWN_PROCESS_INTERACTION_CAPABILITY = "pwn.process_interaction"

# SourceAnalysisRunner pins its single mount to this fixed path.
_BINARY_INPUT_PATH = "/inputs/source.zip"

_DEFAULT_RESOURCES = ResourceLimits(
    cpu_cores=1,
    memory_megabytes=256,
    max_processes=1,
    max_output_bytes=1_000_000,
)


class ProcessInteractionResult(StrictModel):
    observation_type: str = Field(default="process_interaction", pattern="^process_interaction$")
    artifact_id: UUID
    artifact_sha256: Sha256
    padding_length: int = Field(ge=0)
    target_address: int = Field(ge=0)
    win_triggered: bool
    observed_output: str = Field(min_length=1, max_length=20_000)
    exit_code: int


class ProcessInteractionPlugin(ToolHealthMixin):
    """ToolPlugin boundary for the fixed ret2win process interaction."""

    input_schema = {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "pattern": r"^[0-9a-fA-F-]{36}$"},
            "artifact_sha256": {"type": "string", "pattern": r"^[0-9a-fA-F]{64}$"},
            "padding_length": {"type": "integer", "minimum": 0, "maximum": 4096},
            "target_address": {"type": "integer", "minimum": 0, "maximum": 0xFFFFFFFFFFFFFFFF},
            "host": {"type": "string", "minLength": 1, "maxLength": 255},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        },
        "required": ["artifact_id", "artifact_sha256", "padding_length", "target_address"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "observation_type": {"type": "string", "const": "process_interaction"},
            "artifact_id": {"type": "string"},
            "artifact_sha256": {"type": "string"},
            "padding_length": {"type": "integer", "minimum": 0},
            "target_address": {"type": "integer", "minimum": 0},
            "win_triggered": {"type": "boolean"},
            "observed_output": {"type": "string"},
            "exit_code": {"type": "integer"},
        },
        "required": [
            "observation_type",
            "artifact_id",
            "artifact_sha256",
            "padding_length",
            "target_address",
            "win_triggered",
            "observed_output",
            "exit_code",
        ],
        "additionalProperties": False,
    }

    def __init__(self, *, runtime_available: Callable[[], bool] | None = None) -> None:
        self._runtime_available = runtime_available or (lambda: False)
        self._pending: dict[UUID, ToolInvocation] = {}
        self._spec = ToolSpec(
            tool_id=PWN_PROCESS_INTERACTION_TOOL_ID,
            name="Pwn process interaction",
            version="1.0.0",
            plugin_id="builtin.pwn",
            capabilities=[PWN_PROCESS_INTERACTION_CAPABILITY],
            description="Deterministic ret2win process interaction from structured exploit parameters.",
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects={SideEffect.PROCESS_INTERACTION},
            risk_level=RiskLevel.R2,
            permissions=ToolPermissions(process_interaction=True, filesystem_read=True),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                image=None,
                entrypoint=[PWN_PROCESS_INTERACTION_TOOL_ID],
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
                tool_id=PWN_PROCESS_INTERACTION_TOOL_ID,
                version="1.0.0",
            ),
        )

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        expected = ToolRef(tool_id=PWN_PROCESS_INTERACTION_TOOL_ID, version="1.0.0")
        if invocation.tool_ref != expected:
            raise ValueError("invocation tool reference does not match pwn.process_interaction")
        if invocation.status is not ToolInvocationStatus.APPROVED:
            raise ValueError("only approved process-interaction invocations can be prepared")
        if invocation.deadline <= datetime.now(timezone.utc):
            raise ValueError("process-interaction invocation deadline has expired")
        arguments = validate_arguments(invocation.validated_arguments, self.input_schema)
        try:
            artifact_id = UUID(arguments["artifact_id"])
        except ValueError as exc:
            raise ArgumentValidationError("artifact_id must be a UUID") from exc
        padding_length = int(arguments["padding_length"])
        target_address = int(arguments["target_address"])
        if ("host" in arguments) != ("port" in arguments):
            raise ArgumentValidationError("host and port must be provided together")
        argv = [str(padding_length), str(target_address)]
        if "host" in arguments:
            argv = [
                "--remote",
                str(arguments["host"]),
                str(arguments["port"]),
                str(padding_length),
                str(target_address),
            ]
        remaining = int((invocation.deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining < 1:
            raise ValueError("process-interaction invocation deadline leaves less than one second")
        request = ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.SOURCE_ANALYSIS,
            image=None,
            entrypoint=[PWN_PROCESS_INTERACTION_TOOL_ID],
            argv=argv,
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
            raise ValueError("raw result does not match a prepared process-interaction request")
        status = result.status
        error = result.error
        normalized: dict = {}
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error(
                "PWN_INTERACTION_EXIT_NONZERO",
                "Process interaction exited with a non-zero status.",
            )
        if status is ToolResultStatus.SUCCEEDED:
            try:
                decoded = json.loads(result.stdout.decode("utf-8"))
                interaction = ProcessInteractionResult.model_validate(decoded)
                if str(interaction.artifact_id) != invocation.validated_arguments["artifact_id"]:
                    raise ValueError("process-interaction artifact id mismatch")
                if interaction.artifact_sha256 != invocation.validated_arguments["artifact_sha256"]:
                    raise ValueError("process-interaction artifact hash mismatch")
                if interaction.padding_length != invocation.validated_arguments["padding_length"]:
                    raise ValueError("process-interaction padding length mismatch")
                if interaction.target_address != invocation.validated_arguments["target_address"]:
                    raise ValueError("process-interaction target address mismatch")
                normalized = interaction.model_dump(mode="json")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                status = ToolResultStatus.FAILED
                error = self._error(
                    "PWN_INTERACTION_OUTPUT_INVALID",
                    "Process interaction returned invalid structured output.",
                )
                normalized = {}
        elif error is None:
            error = self._error(
                "PWN_INTERACTION_EXECUTION_FAILED",
                "Process interaction did not succeed.",
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
    def build_payload(padding_length: int, target_address: int) -> bytes:
        if padding_length < 0 or target_address < 0:
            raise ValueError("payload parameters must be non-negative")
        if target_address > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("target address exceeds 64-bit range")
        return b"A" * padding_length + struct.pack("<Q", target_address)

    @staticmethod
    def _error(code: str, message: str) -> ErrorInfo:
        return ErrorInfo(
            code=code,
            category=ErrorCategory.TOOL_FAILED,
            retryable=False,
            safe_message=message,
        )


__all__ = [
    "PWN_PROCESS_INTERACTION_CAPABILITY",
    "PWN_PROCESS_INTERACTION_TOOL_ID",
    "ProcessInteractionPlugin",
    "ProcessInteractionResult",
]
