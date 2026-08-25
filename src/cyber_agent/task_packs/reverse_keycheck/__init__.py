"""Reverse keycheck task pack plugin."""

from __future__ import annotations

from cyber_agent.contracts.task_pack import TaskPack

from .adapter import ReverseKeycheckScenarioAdapter
from .config import ReverseKeycheckScenarioConfig
from .manifest import (
    REVERSE_KEYCHECK_CAPABILITIES,
    REVERSE_KEYCHECK_REPORT_TEMPLATE,
    REVERSE_KEYCHECK_REQUIRED_TOOLS,
    REVERSE_KEYCHECK_RUN_CAPABILITY,
    REVERSE_KEYCHECK_RUN_TOOL_ID,
    REVERSE_KEYCHECK_SECURITY_POLICY,
    REVERSE_KEYCHECK_STATIC_CAPABILITY,
    REVERSE_KEYCHECK_STATIC_TOOL_ID,
    REVERSE_KEYCHECK_TASK_PACK_ID,
    REVERSE_KEYCHECK_TASK_PACK_VERSION,
    REVERSE_KEYCHECK_TASK_TYPE,
    REVERSE_KEYCHECK_VERIFIER_ID,
    reverse_keycheck_manifest,
)


class ReverseKeycheckTaskPack(TaskPack):
    """Immutable two-stage reverse keycheck task pack."""

    def __init__(self, config: ReverseKeycheckScenarioConfig) -> None:
        super().__init__(
            manifest=reverse_keycheck_manifest(),
            adapter=ReverseKeycheckScenarioAdapter(config),
        )


__all__ = [
    "REVERSE_KEYCHECK_CAPABILITIES",
    "REVERSE_KEYCHECK_REPORT_TEMPLATE",
    "REVERSE_KEYCHECK_REQUIRED_TOOLS",
    "REVERSE_KEYCHECK_RUN_CAPABILITY",
    "REVERSE_KEYCHECK_RUN_TOOL_ID",
    "REVERSE_KEYCHECK_SECURITY_POLICY",
    "REVERSE_KEYCHECK_STATIC_CAPABILITY",
    "REVERSE_KEYCHECK_STATIC_TOOL_ID",
    "REVERSE_KEYCHECK_TASK_PACK_ID",
    "REVERSE_KEYCHECK_TASK_PACK_VERSION",
    "REVERSE_KEYCHECK_TASK_TYPE",
    "REVERSE_KEYCHECK_VERIFIER_ID",
    "ReverseKeycheckScenarioAdapter",
    "ReverseKeycheckScenarioConfig",
    "ReverseKeycheckTaskPack",
    "reverse_keycheck_manifest",
]
