"""Model adapter implementation boundary."""

from .fake import FakeModelAdapter
from .io_trace import (
    ModelIoAttempt,
    ModelIoOperation,
    ModelIoStage,
    ModelIoStatus,
    ModelIoTrace,
    ModelIoTraceStore,
    ModelIoTraceSummary,
)
from .kimi import KimiK3Adapter, KimiK3Config
from .openai_compatible import (
    OpenAICompatibleAdapter,
    OpenAICompatibleConfig,
    StructuredOutputMode,
)
from .replay import ReplayModelAdapter
from .tracing import ModelCallCollector, TracingModelGateway

__all__ = [
    "FakeModelAdapter",
    "KimiK3Adapter",
    "KimiK3Config",
    "ModelIoAttempt",
    "ModelIoOperation",
    "ModelIoStage",
    "ModelIoStatus",
    "ModelIoTrace",
    "ModelIoTraceStore",
    "ModelIoTraceSummary",
    "ModelCallCollector",
    "OpenAICompatibleAdapter",
    "OpenAICompatibleConfig",
    "ReplayModelAdapter",
    "StructuredOutputMode",
    "TracingModelGateway",
]
