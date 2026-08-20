"""Fail-closed Docker CLI implementation of the container runtime port."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4

from cyber_agent.contracts.common import ErrorCategory, ErrorInfo
from cyber_agent.contracts.tool import (
    ExecutionRequest,
    NetworkMode,
    RawExecutionResult,
    RunnerType,
    ToolResultStatus,
)

from .container import ContainerIsolation


_EXPECTED_CONTEXT = "desktop-linux"
_EXPECTED_TARGET = "web-target:8080"
_EXPECTED_SUBNET = "172.30.0.0/24"
_EXPECTED_TARGET_IP = "172.30.0.10"
_EXPECTED_USER = "65532:65532"
_EXPECTED_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=16m"
_IMAGE_PATTERN = re.compile(r"^[^\s@]+@sha256:[0-9a-fA-F]{64}$")
_CONTAINER_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_OUTPUT_LIMIT = 1_048_576
_SAFE_DOCKER_ERROR = b"docker command failed safely"

_PROJECT_LABEL = "com.cyber-agent.project"
_RUN_LABEL = "com.cyber-agent.run-id"
_REQUEST_LABEL = "com.cyber-agent.request-id"


def _is_pinned_image(image: str) -> bool:
    if image.startswith("-") or _IMAGE_PATTERN.fullmatch(image) is None:
        return False
    repository = image.rsplit("@sha256:", 1)[0]
    final_component = repository.rsplit("/", 1)[-1]
    return ":" not in final_component


class DockerCliConfigurationError(ValueError):
    """Configuration failure with a stable, non-sensitive code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class DockerOutputLimitExceeded(RuntimeError):
    """Raised by a command transport as soon as combined output exceeds its cap."""

    def __init__(self, stdout: bytes = b"", stderr: bytes = b"") -> None:
        super().__init__("Docker command output exceeded its hard limit")
        self.stdout = stdout
        self.stderr = stderr


@dataclass(frozen=True, slots=True)
class DockerCommandResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


class DockerCommandTransport(Protocol):
    async def execute(
        self,
        executable: Path,
        argv: tuple[str, ...],
        *,
        output_limit: int,
        timeout_seconds: float | None,
    ) -> DockerCommandResult: ...


class AsyncSubprocessDockerTransport:
    """Bounded subprocess transport; it never invokes a command shell."""

    async def execute(
        self,
        executable: Path,
        argv: tuple[str, ...],
        *,
        output_limit: int,
        timeout_seconds: float | None,
    ) -> DockerCommandResult:
        process = await asyncio.create_subprocess_exec(
            str(executable),
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout = bytearray()
        stderr = bytearray()
        total = 0

        async def read_stream(
            stream: asyncio.StreamReader | None, sink: bytearray
        ) -> None:
            nonlocal total
            if stream is None:
                return
            while True:
                chunk = await stream.read(65_536)
                if not chunk:
                    return
                remaining = max(0, output_limit - total)
                sink.extend(chunk[:remaining])
                total += len(chunk)
                if total > output_limit:
                    raise DockerOutputLimitExceeded(bytes(stdout), bytes(stderr))

        async def collect() -> int:
            readers = [
                asyncio.create_task(read_stream(process.stdout, stdout)),
                asyncio.create_task(read_stream(process.stderr, stderr)),
            ]
            try:
                await asyncio.gather(*readers)
                return await process.wait()
            finally:
                for reader in readers:
                    if not reader.done():
                        reader.cancel()

        try:
            if timeout_seconds is None:
                returncode = await collect()
            else:
                returncode = await asyncio.wait_for(collect(), timeout=timeout_seconds)
        except BaseException:
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
        return DockerCommandResult(returncode, bytes(stdout), bytes(stderr))


@dataclass(frozen=True, slots=True)
class DockerNetworkConfig:
    network_id: str
    target_container_id: str
    subnet: str = _EXPECTED_SUBNET
    target_ip: str = _EXPECTED_TARGET_IP

    def __post_init__(self) -> None:
        if _CONTAINER_ID_PATTERN.fullmatch(self.network_id) is None:
            raise DockerCliConfigurationError(
                "DOCKER_NETWORK_ID_INVALID", "network ID must be an exact hexadecimal ID"
            )
        if _CONTAINER_ID_PATTERN.fullmatch(self.target_container_id) is None:
            raise DockerCliConfigurationError(
                "DOCKER_TARGET_ID_INVALID", "target container ID must be an exact hexadecimal ID"
            )
        if self.subnet != _EXPECTED_SUBNET or self.target_ip != _EXPECTED_TARGET_IP:
            raise DockerCliConfigurationError(
                "DOCKER_NETWORK_CONFIG_DENIED", "network boundary does not match the approved gate"
            )


@dataclass(frozen=True, slots=True)
class DockerCliConfig:
    docker_path: Path
    run_id: UUID
    network: DockerNetworkConfig | None = None
    context: str = _EXPECTED_CONTEXT
    project: str = "cyber-agent"
    user: str = _EXPECTED_USER
    tmpfs: str = _EXPECTED_TMPFS


class DockerCliRuntime:
    """Docker CLI adapter with a fixed command and network vocabulary."""

    def __init__(
        self,
        config: DockerCliConfig,
        *,
        transport: DockerCommandTransport | None = None,
        path_validator: Callable[[Path], bool] | None = None,
    ) -> None:
        docker_path = Path(config.docker_path)
        validator = path_validator or (lambda candidate: candidate.is_file())
        if not docker_path.is_absolute() or not validator(docker_path):
            raise DockerCliConfigurationError(
                "DOCKER_PATH_INVALID", "Docker CLI path must be an existing verified absolute file"
            )
        if config.context != _EXPECTED_CONTEXT:
            raise DockerCliConfigurationError(
                "DOCKER_CONTEXT_DENIED", "only the desktop-linux Docker context is allowed"
            )
        if not config.project or any(ord(char) < 32 for char in config.project):
            raise DockerCliConfigurationError(
                "DOCKER_PROJECT_LABEL_INVALID", "project label is invalid"
            )
        if config.user != _EXPECTED_USER:
            raise DockerCliConfigurationError(
                "DOCKER_USER_CONFIG_DENIED",
                "container user must match the approved non-root UID and GID",
            )
        if config.tmpfs != _EXPECTED_TMPFS:
            raise DockerCliConfigurationError(
                "DOCKER_TMPFS_CONFIG_DENIED",
                "container tmpfs must match the approved restricted value",
            )
        self._config = config
        self._docker_path = docker_path
        self._transport = transport or AsyncSubprocessDockerTransport()
        self._containers: dict[UUID, str] = {}

    async def health_check(self) -> tuple[bool, str]:
        try:
            context = await self._execute(("context", "show"))
            if context.returncode != 0 or context.stdout.decode("utf-8", "strict").strip() != _EXPECTED_CONTEXT:
                return False, "Docker context is not desktop-linux"
            info = await self._execute(
                ("--context", _EXPECTED_CONTEXT, "info", "--format", "{{json .}}")
            )
            if info.returncode != 0:
                return False, "Docker Server is unavailable"
            payload = self._load_object(info.stdout)
            if not payload.get("ServerVersion"):
                return False, "Docker Server did not report a version"
            if payload.get("OSType") != "linux":
                return False, "Docker Server OSType is not linux"
        except (OSError, UnicodeError, ValueError, TimeoutError, DockerOutputLimitExceeded):
            return False, "Docker Server health check failed safely"
        return True, "docker server is available"

    async def run(
        self, request: ExecutionRequest, isolation: ContainerIsolation
    ) -> RawExecutionResult:
        started = datetime.now(timezone.utc)
        denied = self._validate_request(request, isolation)
        if denied is not None:
            return self._result(
                request,
                started,
                ToolResultStatus.DENIED,
                error=self._error(denied[0], ErrorCategory.POLICY_DENIED, denied[1]),
            )

        container_id: str | None = None
        try:
            network_mode = "none"
            if request.network_policy.mode is NetworkMode.ALLOWLIST:
                network_error = await self._validate_allowlisted_network(None)
                if network_error is not None:
                    code, category, message = network_error
                    return self._result(
                        request,
                        started,
                        ToolResultStatus.DENIED
                        if category is ErrorCategory.POLICY_DENIED
                        else ToolResultStatus.EXECUTOR_ERROR,
                        error=self._error(code, category, message),
                    )
                if self._config.network is None:
                    return self._docker_failure(
                        request,
                        started,
                        "DOCKER_NETWORK_CONFIG_MISSING",
                    )
                network_mode = self._config.network.network_id
            create = await self._execute(
                self._create_argv(request, network_mode=network_mode),
                output_limit=_CONTROL_OUTPUT_LIMIT,
                timeout_seconds=request.timeout_seconds,
            )
            if create.returncode != 0:
                return self._docker_failure(request, started, "DOCKER_CREATE_FAILED")
            container_id = create.stdout.decode("ascii", "strict").strip()
            if _CONTAINER_ID_PATTERN.fullmatch(container_id) is None:
                return self._docker_failure(request, started, "DOCKER_CONTAINER_ID_INVALID")
            self._containers[request.request_id] = container_id

            container_error = await self._validate_created_container(
                request,
                container_id,
                network_mode=network_mode,
            )
            if container_error is not None:
                return self._docker_failure(request, started, container_error)

            command = await self._execute(
                ("--context", _EXPECTED_CONTEXT, "start", "--attach", container_id),
                output_limit=request.resources.max_output_bytes,
                timeout_seconds=request.timeout_seconds,
            )
            if request.network_policy.mode is NetworkMode.ALLOWLIST:
                network_error = await self._validate_allowlisted_network(container_id)
                if network_error is not None:
                    code, category, message = network_error
                    return self._result(
                        request,
                        started,
                        ToolResultStatus.DENIED
                        if category is ErrorCategory.POLICY_DENIED
                        else ToolResultStatus.EXECUTOR_ERROR,
                        error=self._error(code, category, message),
                    )
            if command.returncode != 0:
                return self._result(
                    request,
                    started,
                    ToolResultStatus.FAILED,
                    exit_code=command.returncode,
                    stderr=_SAFE_DOCKER_ERROR,
                    error=self._error(
                        "DOCKER_COMMAND_FAILED",
                        ErrorCategory.TOOL_FAILED,
                        "Docker command failed safely",
                    ),
                )
            return self._result(
                request,
                started,
                ToolResultStatus.SUCCEEDED,
                exit_code=0,
                stdout=command.stdout,
            )
        except DockerOutputLimitExceeded as exc:
            if container_id is not None:
                await self._terminate(container_id)
            return self._result(
                request,
                started,
                ToolResultStatus.FAILED,
                stdout=exc.stdout,
                error=self._error(
                    "DOCKER_OUTPUT_LIMIT_EXCEEDED",
                    ErrorCategory.TOOL_FAILED,
                    "Container output exceeded its hard byte limit",
                ),
            )
        except TimeoutError:
            if container_id is not None:
                await self._terminate(container_id)
            return self._result(
                request,
                started,
                ToolResultStatus.TIMED_OUT,
                error=self._error(
                    "DOCKER_EXECUTION_TIMEOUT",
                    ErrorCategory.EXECUTION_TIMEOUT,
                    "Container execution exceeded its deadline",
                    retryable=True,
                ),
            )
        except asyncio.CancelledError:
            if container_id is not None:
                await self._terminate(container_id)
            raise
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            return self._docker_failure(request, started, "DOCKER_RUNTIME_FAILED")

    async def cancel(self, request_id: UUID) -> None:
        container_id = self._containers.get(request_id)
        if container_id is not None:
            await self._terminate(container_id)

    async def cleanup(self, request_id: UUID) -> None:
        container_id = self._containers.get(request_id)
        if container_id is None:
            return
        try:
            inspected = await self._execute(
                (
                    "--context",
                    _EXPECTED_CONTEXT,
                    "inspect",
                    "--format",
                    "{{json .Config.Labels}}",
                    container_id,
                )
            )
            if inspected.returncode != 0:
                return
            labels = self._load_object(inspected.stdout)
            expected = {
                _PROJECT_LABEL: self._config.project,
                _RUN_LABEL: str(self._config.run_id),
                _REQUEST_LABEL: str(request_id),
            }
            if any(labels.get(key) != value for key, value in expected.items()):
                return
            removed = await self._execute(
                ("--context", _EXPECTED_CONTEXT, "rm", "--force", container_id)
            )
            if removed.returncode == 0:
                self._containers.pop(request_id, None)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError, DockerOutputLimitExceeded):
            return

    def _validate_request(
        self, request: ExecutionRequest, isolation: ContainerIsolation
    ) -> tuple[str, str] | None:
        required_isolation = ContainerIsolation()
        if isolation != required_isolation:
            return "DOCKER_ISOLATION_DENIED", "Mandatory isolation settings cannot be weakened"
        if request.runner is not RunnerType.CONTAINER:
            return "DOCKER_RUNNER_DENIED", "Docker runtime accepts only container requests"
        if request.request_id in self._containers:
            return "DOCKER_REQUEST_ALREADY_ACTIVE", "Request already has a controlled container"
        if request.image is None or not _is_pinned_image(request.image):
            return "DOCKER_IMAGE_NOT_PINNED", "Image must be a repository pinned by SHA-256 digest"
        if request.mounts:
            return "DOCKER_MOUNTS_DENIED", "Mounts are not supported by this runtime boundary"
        if request.environment:
            return "DOCKER_ENVIRONMENT_DENIED", "Environment variables are not supported by this runtime boundary"
        if not request.entrypoint or not request.entrypoint[0] or any(
            "\x00" in value for value in (*request.entrypoint, *request.argv)
        ):
            return "DOCKER_ENTRYPOINT_DENIED", "Entrypoint and argv must be structured non-NUL strings"
        policy = request.network_policy
        if policy.mode is NetworkMode.ALLOWLIST and policy.allowed_targets != [_EXPECTED_TARGET]:
            return "DOCKER_NETWORK_TARGET_DENIED", "Only web-target:8080 is approved"
        if policy.mode not in {NetworkMode.NONE, NetworkMode.ALLOWLIST}:
            return "DOCKER_NETWORK_MODE_DENIED", "Network mode is not approved"
        if policy.mode is NetworkMode.ALLOWLIST and self._config.network is None:
            return "DOCKER_NETWORK_CONFIG_MISSING", "Approved network configuration is missing"
        return None

    def _create_argv(
        self,
        request: ExecutionRequest,
        *,
        network_mode: str,
    ) -> tuple[str, ...]:
        container_name = f"cyber-agent-tool-{uuid4().hex}"
        resources = request.resources
        labels = (
            f"{_PROJECT_LABEL}={self._config.project}",
            f"{_RUN_LABEL}={self._config.run_id}",
            f"{_REQUEST_LABEL}={request.request_id}",
        )
        argv = [
            "--context",
            _EXPECTED_CONTEXT,
            "create",
            "--name",
            container_name,
            "--network",
            network_mode,
            "--pull",
            "never",
            "--user",
            self._config.user,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(resources.max_processes),
            "--cpus",
            str(resources.cpu_cores),
            "--memory",
            f"{resources.memory_megabytes}m",
            "--tmpfs",
            self._config.tmpfs,
        ]
        for label in labels:
            argv.extend(("--label", label))
        argv.extend(("--entrypoint", request.entrypoint[0], request.image or ""))
        argv.extend(request.entrypoint[1:])
        argv.extend(request.argv)
        return tuple(argv)

    async def _validate_created_container(
        self,
        request: ExecutionRequest,
        container_id: str,
        *,
        network_mode: str,
    ) -> str | None:
        inspected = await self._execute(
            (
                "--context",
                _EXPECTED_CONTEXT,
                "inspect",
                "--format",
                "{{json .}}",
                container_id,
            )
        )
        if inspected.returncode != 0:
            return "DOCKER_CONTAINER_INSPECT_FAILED"
        payload = self._load_object(inspected.stdout)
        config = payload.get("Config")
        host = payload.get("HostConfig")
        labels = config.get("Labels") if isinstance(config, dict) else None
        expected_labels = {
            _PROJECT_LABEL: self._config.project,
            _RUN_LABEL: str(self._config.run_id),
            _REQUEST_LABEL: str(request.request_id),
        }
        if (
            payload.get("Id") != container_id
            or not isinstance(config, dict)
            or not isinstance(host, dict)
            or config.get("Image") != request.image
            or config.get("User") != self._config.user
            or config.get("Entrypoint") != [request.entrypoint[0]]
            or config.get("Cmd") != [*request.entrypoint[1:], *request.argv]
            or not isinstance(labels, dict)
            or any(labels.get(key) != value for key, value in expected_labels.items())
        ):
            return "DOCKER_CONTAINER_ISOLATION_INVALID"
        resources = request.resources
        if (
            host.get("NetworkMode") != network_mode
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("CapDrop") != ["ALL"]
            or host.get("PidsLimit") != resources.max_processes
            or host.get("NanoCpus") != round(resources.cpu_cores * 1_000_000_000)
            or host.get("Memory") != resources.memory_megabytes * 1024 * 1024
            or host.get("Binds") not in (None, [])
            or host.get("PortBindings") not in (None, {})
        ):
            return "DOCKER_CONTAINER_ISOLATION_INVALID"
        if host.get("SecurityOpt") not in (
            ["no-new-privileges"],
            ["no-new-privileges:true"],
        ):
            return "DOCKER_CONTAINER_ISOLATION_INVALID"
        tmpfs = host.get("Tmpfs")
        tmpfs_value = tmpfs.get("/tmp") if isinstance(tmpfs, dict) else None
        expected_tmpfs = self._config.tmpfs.split(":", 1)[1]
        if not isinstance(tmpfs_value, str) or set(tmpfs_value.split(",")) != set(
            expected_tmpfs.split(",")
        ):
            return "DOCKER_CONTAINER_ISOLATION_INVALID"
        mounts = payload.get("Mounts")
        if isinstance(mounts, list) and mounts:
            return "DOCKER_CONTAINER_ISOLATION_INVALID"
        return None

    async def _validate_allowlisted_network(
        self, container_id: str | None
    ) -> tuple[str, ErrorCategory, str] | None:
        network = self._config.network
        if network is None:
            return (
                "DOCKER_NETWORK_INSPECT_INVALID",
                ErrorCategory.POLICY_DENIED,
                "Approved network configuration is missing",
            )
        inspected = await self._execute(
            (
                "--context",
                _EXPECTED_CONTEXT,
                "network",
                "inspect",
                network.network_id,
            )
        )
        if inspected.returncode != 0:
            return (
                "DOCKER_NETWORK_INSPECT_FAILED",
                ErrorCategory.SYSTEM_ERROR,
                "Approved network inspection failed safely",
            )
        try:
            decoded = json.loads(inspected.stdout.decode("utf-8", "strict"))
        except (UnicodeError, json.JSONDecodeError):
            return (
                "DOCKER_NETWORK_INSPECT_FAILED",
                ErrorCategory.SYSTEM_ERROR,
                "Approved network inspection was malformed",
            )
        if not isinstance(decoded, list) or len(decoded) != 1 or not isinstance(decoded[0], dict):
            return (
                "DOCKER_NETWORK_INSPECT_FAILED",
                ErrorCategory.SYSTEM_ERROR,
                "Approved network inspection shape was invalid",
            )
        payload = decoded[0]
        labels = payload.get("Labels")
        ipam = payload.get("IPAM")
        containers = payload.get("Containers")
        if payload.get("Id") != network.network_id:
            return self._network_mismatch("Approved network ID did not match")
        if payload.get("Driver") != "bridge" or payload.get("Internal") is not True:
            return self._network_mismatch("Approved network isolation did not match")
        if not isinstance(labels, dict) or labels.get(_PROJECT_LABEL) != self._config.project:
            return self._network_mismatch("Approved network project label did not match")
        if labels.get(_RUN_LABEL) != str(self._config.run_id):
            return self._network_mismatch("Approved network run label did not match")
        ipam_configs = ipam.get("Config") if isinstance(ipam, dict) else None
        if (
            not isinstance(ipam_configs, list)
            or len(ipam_configs) != 1
            or not isinstance(ipam_configs[0], dict)
            or ipam_configs[0].get("Subnet") != network.subnet
        ):
            return self._network_mismatch("Approved network subnet did not match")
        expected_ids = {network.target_container_id}
        allowed_id_sets = {frozenset(expected_ids)}
        if container_id is not None:
            allowed_id_sets.add(frozenset({*expected_ids, container_id}))
        if (
            not isinstance(containers, dict)
            or frozenset(containers) not in allowed_id_sets
        ):
            return self._network_mismatch("Approved network target set was invalid")
        target = containers.get(network.target_container_id)
        if not isinstance(target, dict) or target.get("Name") != "web-target":
            return self._network_mismatch("Approved target container did not match")
        address = target.get("IPv4Address")
        if not isinstance(address, str) or address.split("/", 1)[0] != network.target_ip:
            return self._network_mismatch("Approved target IP did not match")
        if container_id is not None and container_id in containers:
            tool = containers.get(container_id)
            tool_name = tool.get("Name") if isinstance(tool, dict) else None
            tool_address = tool.get("IPv4Address") if isinstance(tool, dict) else None
            if (
                not isinstance(tool_name, str)
                or not tool_name.startswith("cyber-agent-tool-")
                or not isinstance(tool_address, str)
            ):
                return self._network_mismatch("Approved tool endpoint did not match")
            try:
                address_value = ipaddress.ip_address(tool_address.split("/", 1)[0])
                subnet = ipaddress.ip_network(network.subnet)
            except ValueError:
                return self._network_mismatch("Approved tool address was malformed")
            if address_value not in subnet or str(address_value) == network.target_ip:
                return self._network_mismatch("Approved tool address did not match")
        return None

    @staticmethod
    def _network_mismatch(message: str) -> tuple[str, ErrorCategory, str]:
        return "DOCKER_NETWORK_INSPECT_INVALID", ErrorCategory.POLICY_DENIED, message

    async def _terminate(self, container_id: str) -> None:
        if _CONTAINER_ID_PATTERN.fullmatch(container_id) is None:
            return
        try:
            await self._execute(
                ("--context", _EXPECTED_CONTEXT, "kill", container_id),
                timeout_seconds=10,
            )
        except (OSError, TimeoutError, DockerOutputLimitExceeded):
            return

    async def _execute(
        self,
        argv: tuple[str, ...],
        *,
        output_limit: int = _CONTROL_OUTPUT_LIMIT,
        timeout_seconds: float | None = 30,
    ) -> DockerCommandResult:
        return await self._transport.execute(
            self._docker_path,
            argv,
            output_limit=output_limit,
            timeout_seconds=timeout_seconds,
        )

    @staticmethod
    def _load_object(raw: bytes) -> dict[str, Any]:
        value = json.loads(raw.decode("utf-8", "strict"))
        if not isinstance(value, dict):
            raise ValueError("expected JSON object")
        return value
    def _docker_failure(
        self, request: ExecutionRequest, started: datetime, code: str
    ) -> RawExecutionResult:
        return self._result(
            request,
            started,
            ToolResultStatus.EXECUTOR_ERROR,
            stderr=_SAFE_DOCKER_ERROR,
            error=self._error(
                code,
                ErrorCategory.SYSTEM_ERROR,
                "Docker runtime failed safely",
            ),
        )

    @staticmethod
    def _error(
        code: str,
        category: ErrorCategory,
        message: str,
        *,
        retryable: bool = False,
    ) -> ErrorInfo:
        return ErrorInfo(
            code=code,
            category=category,
            retryable=retryable,
            safe_message=message,
        )

    @staticmethod
    def _result(
        request: ExecutionRequest,
        started: datetime,
        status: ToolResultStatus,
        *,
        exit_code: int | None = None,
        stdout: bytes = b"",
        stderr: bytes = b"",
        error: ErrorInfo | None = None,
    ) -> RawExecutionResult:
        return RawExecutionResult(
            request_id=request.request_id,
            status=status,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            error=error,
        )
