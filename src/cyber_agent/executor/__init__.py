"""Controlled execution boundary."""

from .container import (
    ContainerExecutor,
    ContainerIsolation,
    ContainerRuntime,
    ExecutorLimits,
    UnavailableContainerRuntime,
)
from .controlled import ControlledExecutor
from .docker_cli import (
    AsyncSubprocessDockerTransport,
    DockerCliConfig,
    DockerCliConfigurationError,
    DockerCliRuntime,
    DockerCommandResult,
    DockerCommandTransport,
    DockerNetworkConfig,
    DockerOutputLimitExceeded,
)
from .fake import FakeRunner
from .source_analysis import (
    SourceAnalysisExecutionError,
    SourceAnalysisHandler,
    SourceAnalysisRunner,
)


def __getattr__(name: str):
    """Load the worker boundary lazily to avoid analyzer import cycles."""

    if name in {"SourceWorkerProtocolError", "SourceWorkerRequest"}:
        from .source_worker import SourceWorkerProtocolError, SourceWorkerRequest

        return {
            "SourceWorkerProtocolError": SourceWorkerProtocolError,
            "SourceWorkerRequest": SourceWorkerRequest,
        }[name]
    if name in {
        "SourceWorkerGuardError",
        "UnavailableSourceWorkerGuard",
        "WindowsSourceWorkerGuard",
    }:
        from .source_worker_guard import (
            SourceWorkerGuardError,
            UnavailableSourceWorkerGuard,
            WindowsSourceWorkerGuard,
        )

        return {
            "SourceWorkerGuardError": SourceWorkerGuardError,
            "UnavailableSourceWorkerGuard": UnavailableSourceWorkerGuard,
            "WindowsSourceWorkerGuard": WindowsSourceWorkerGuard,
        }[name]
    raise AttributeError(name)

__all__ = [
    "ContainerExecutor",
    "ContainerIsolation",
    "ContainerRuntime",
    "ControlledExecutor",
    "AsyncSubprocessDockerTransport",
    "DockerCliConfig",
    "DockerCliConfigurationError",
    "DockerCliRuntime",
    "DockerCommandResult",
    "DockerCommandTransport",
    "DockerNetworkConfig",
    "DockerOutputLimitExceeded",
    "ExecutorLimits",
    "FakeRunner",
    "SourceAnalysisExecutionError",
    "SourceAnalysisHandler",
    "SourceAnalysisRunner",
    "SourceWorkerGuardError",
    "SourceWorkerProtocolError",
    "SourceWorkerRequest",
    "UnavailableSourceWorkerGuard",
    "WindowsSourceWorkerGuard",
    "UnavailableContainerRuntime",
]
