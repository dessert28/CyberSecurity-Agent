"""Built-in Web plugins that only prepare and parse controlled executions."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from cyber_agent.contracts.common import ErrorCategory, ErrorInfo, RiskLevel
from cyber_agent.contracts.tool import (
    ExecutionProfile,
    ExecutionRequest,
    MountSpec,
    NetworkMode,
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


WEB_TOOLS_IMAGE = "registry.local/cyber-agent/web-tools@sha256:" + "8c4f5bbf4bc9323386112038e41b6fd89c9589178068a57d4e55f88d09fba221"
DEFAULT_RESOURCES = ResourceLimits(
    cpu_cores=1,
    memory_megabytes=256,
    max_processes=16,
    max_output_bytes=1_000_000,
)


class _WebPlugin:
    tool_id: str
    entrypoint_module: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    network: bool = True
    risk_level: RiskLevel = RiskLevel.R1

    def __init__(
        self,
        *,
        runtime_available: Callable[[], bool] | None = None,
        image: str = WEB_TOOLS_IMAGE,
    ) -> None:
        self._runtime_available = runtime_available or (lambda: False)
        self._image = image
        self._pending: dict[UUID, ToolInvocation] = {}
        self._spec = self._build_spec()
        fingerprint_source = json.dumps(
            self._spec.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        self._environment_fingerprint = hashlib.sha256(fingerprint_source).hexdigest()

    def _build_spec(self) -> ToolSpec:
        permissions = ToolPermissions(network=self.network, filesystem_read=not self.network)
        side_effects = {SideEffect.NETWORK_READ} if self.network else {SideEffect.FILE_READ}
        return ToolSpec(
            tool_id=self.tool_id,
            name=self.tool_id,
            version="1.0.0",
            plugin_id="builtin.web",
            capabilities=[self.tool_id],
            description=f"Controlled built-in capability {self.tool_id}.",
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects=side_effects,
            risk_level=self.risk_level,
            permissions=permissions,
            execution_profile=ExecutionProfile(
                runner=RunnerType.CONTAINER,
                image=self._image,
                entrypoint=["python", "-m", self.entrypoint_module],
                default_timeout_seconds=30,
                max_timeout_seconds=60,
                default_resources=DEFAULT_RESOURCES,
            ),
        )

    def get_spec(self) -> ToolSpec:
        return self._spec.model_copy(deep=True)

    async def health_check(self) -> ToolHealth:
        try:
            available = bool(self._runtime_available())
        except Exception:
            available = False
        return ToolHealth(
            tool_ref=ToolRef(tool_id=self.tool_id, version="1.0.0"),
            available=available,
            message="container runtime available" if available else "container runtime unavailable",
        )

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        self._validate_invocation(invocation)
        arguments = validate_arguments(invocation.validated_arguments, self.input_schema)
        request = self._prepare(invocation, arguments)
        self._pending[request.request_id] = invocation
        return request

    def _validate_invocation(self, invocation: ToolInvocation) -> None:
        expected = ToolRef(tool_id=self.tool_id, version="1.0.0")
        if invocation.tool_ref != expected:
            raise ValueError("invocation tool reference does not match plugin")
        if invocation.status is not ToolInvocationStatus.APPROVED:
            raise ValueError("only approved invocations can be prepared")
        if invocation.deadline <= datetime.now(timezone.utc):
            raise ValueError("invocation deadline has expired")

    def _prepare(self, invocation: ToolInvocation, arguments: dict[str, Any]) -> ExecutionRequest:
        raise NotImplementedError

    def _request(
        self,
        invocation: ToolInvocation,
        *,
        argv: list[str],
        network_policy: NetworkPolicy,
        mounts: list[MountSpec] | None = None,
        requested_timeout: int | None = None,
    ) -> ExecutionRequest:
        profile = self._spec.execution_profile
        remaining_seconds = (
            invocation.deadline - datetime.now(timezone.utc)
        ).total_seconds()
        if remaining_seconds < 1:
            raise ValueError("invocation deadline leaves less than one second")
        remaining = int(remaining_seconds)
        timeout = min(
            requested_timeout or profile.default_timeout_seconds,
            profile.max_timeout_seconds,
            remaining,
        )
        return ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.CONTAINER,
            image=profile.image,
            entrypoint=list(profile.entrypoint),
            argv=argv,
            mounts=mounts or [],
            environment={},
            network_policy=network_policy,
            resources=profile.default_resources.model_copy(deep=True),
            timeout_seconds=timeout,
        )

    def parse(self, result: RawExecutionResult) -> ToolResult:
        invocation = self._pending.pop(result.request_id, None)
        if invocation is None:
            raise ValueError("raw execution result does not match a prepared request")

        status = result.status
        error = result.error
        normalized: dict[str, Any] = {}
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error("WEB_TOOL_EXIT_NONZERO", "Web tool exited with a non-zero status")
        if status is ToolResultStatus.SUCCEEDED:
            try:
                decoded = json.loads(result.stdout.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise ValueError("tool output must be a JSON object")
                normalized = validate_arguments(decoded, self.output_schema)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ArgumentValidationError):
                status = ToolResultStatus.FAILED
                error = self._error("TOOL_OUTPUT_INVALID", "Web tool returned invalid structured output")
                normalized = {}
        elif error is None:
            error = self._error("WEB_TOOL_EXECUTION_FAILED", "Web tool execution did not succeed")

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

    @staticmethod
    def _network_policy(url: str) -> NetworkPolicy:
        if any(character in url for character in ("\\", "\r", "\n", "\t", "\x00")):
            raise ArgumentValidationError("URL contains a forbidden character")
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ArgumentValidationError("URL must use http or https and include a host")
        if parsed.username is not None or parsed.password is not None:
            raise ArgumentValidationError("URL credentials are not allowed")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        hostname = parsed.hostname
        authority = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
        return NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_targets=[authority])


class HttpRequestPlugin(_WebPlugin):
    tool_id = "web.http_request"
    entrypoint_module = "cyber_tools.http_request"
    input_schema = {
        "type": "object",
        "properties": {
            "method": {"type": "string", "enum": ["GET", "HEAD"]},
            "url": {"type": "string", "minLength": 1, "maxLength": 2048},
            "headers": {
                "type": "object",
                "additionalProperties": {"type": "string", "maxLength": 8192},
            },
            "max_redirects": {"type": "integer", "minimum": 0, "maximum": 5},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 60},
        },
        "required": ["method", "url"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "status_code": {"type": "integer", "minimum": 100, "maximum": 599},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"},
            "redirects": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
        },
        "required": ["status_code", "headers", "body", "redirects"],
        "additionalProperties": False,
    }

    def _prepare(self, invocation: ToolInvocation, arguments: dict[str, Any]) -> ExecutionRequest:
        argv = ["--method", arguments["method"], "--url", arguments["url"]]
        for name, value in sorted(arguments.get("headers", {}).items()):
            if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                raise ArgumentValidationError("HTTP headers may not contain line breaks")
            argv.extend(["--header-name", name, "--header-value", value])
        argv.extend(["--max-redirects", str(arguments.get("max_redirects", 0))])
        return self._request(
            invocation,
            argv=argv,
            network_policy=self._network_policy(arguments["url"]),
            requested_timeout=arguments.get("timeout_seconds"),
        )


class EndpointDiscoveryPlugin(_WebPlugin):
    tool_id = "web.endpoint_discovery"
    entrypoint_module = "cyber_tools.endpoint_discovery"
    input_schema = {
        "type": "object",
        "properties": {
            "base_url": {"type": "string", "minLength": 1, "maxLength": 2048},
            "paths": {
                "type": "array",
                "items": {"type": "string", "minLength": 1, "maxLength": 512},
                "maxItems": 100,
            },
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 60},
        },
        "required": ["base_url"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "endpoints": {"type": "array", "items": {"type": "string"}},
            "observations": {"type": "array", "items": {"type": "object"}},
        },
        "required": ["endpoints", "observations"],
        "additionalProperties": False,
    }

    def _prepare(self, invocation: ToolInvocation, arguments: dict[str, Any]) -> ExecutionRequest:
        argv = ["--base-url", arguments["base_url"]]
        for path in arguments.get("paths", []):
            if not path.startswith("/") or "://" in path or "\\" in path:
                raise ArgumentValidationError("discovery paths must be origin-relative")
            argv.extend(["--path", path])
        return self._request(
            invocation,
            argv=argv,
            network_policy=self._network_policy(arguments["base_url"]),
            requested_timeout=arguments.get("timeout_seconds"),
        )


class OpenApiAnalyzePlugin(_WebPlugin):
    tool_id = "web.openapi_analyze"
    entrypoint_module = "cyber_tools.openapi_analyze"
    network = False
    risk_level = RiskLevel.R0
    input_schema = {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "minLength": 36, "maxLength": 36},
        },
        "required": ["artifact_id"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "operations": {"type": "array", "items": {"type": "object"}},
            "security_schemes": {"type": "object"},
        },
        "required": ["title", "operations", "security_schemes"],
        "additionalProperties": False,
    }

    def _prepare(self, invocation: ToolInvocation, arguments: dict[str, Any]) -> ExecutionRequest:
        try:
            artifact_id = UUID(arguments["artifact_id"])
        except ValueError as exc:
            raise ArgumentValidationError("artifact_id must be a UUID") from exc
        return self._request(
            invocation,
            argv=["--input", "/inputs/openapi.json"],
            network_policy=NetworkPolicy(),
            mounts=[
                MountSpec(
                    artifact_id=artifact_id,
                    container_path="/inputs/openapi.json",
                    read_only=True,
                )
            ],
        )


def built_in_web_plugins(
    *,
    runtime_available: Callable[[], bool] | None = None,
    image: str = WEB_TOOLS_IMAGE,
) -> tuple[_WebPlugin, ...]:
    return (
        HttpRequestPlugin(runtime_available=runtime_available, image=image),
        EndpointDiscoveryPlugin(runtime_available=runtime_available, image=image),
        OpenApiAnalyzePlugin(runtime_available=runtime_available, image=image),
    )
