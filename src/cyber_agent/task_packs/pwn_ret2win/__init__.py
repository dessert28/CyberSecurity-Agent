"""Pwn ret2win task pack plugin."""

from __future__ import annotations

from cyber_agent.contracts.task_pack import TaskPack

from .adapter import PwnRet2winScenarioAdapter
from .config import PwnRet2winScenarioConfig
from .manifest import (
    PWN_RET2WIN_BINARY_CAPABILITY,
    PWN_RET2WIN_BINARY_TOOL_ID,
    PWN_RET2WIN_CAPABILITIES,
    PWN_RET2WIN_INTERACTION_CAPABILITY,
    PWN_RET2WIN_INTERACTION_TOOL_ID,
    PWN_RET2WIN_REPORT_TEMPLATE,
    PWN_RET2WIN_REQUIRED_TOOLS,
    PWN_RET2WIN_SECURITY_POLICY,
    PWN_RET2WIN_TASK_PACK_ID,
    PWN_RET2WIN_TASK_PACK_VERSION,
    PWN_RET2WIN_TASK_TYPE,
    PWN_RET2WIN_VERIFIER_ID,
    pwn_ret2win_manifest,
)


class PwnRet2winTaskPack(TaskPack):
    """Immutable two-stage Pwn ret2win task pack."""

    def __init__(self, config: PwnRet2winScenarioConfig) -> None:
        super().__init__(
            manifest=pwn_ret2win_manifest(),
            adapter=PwnRet2winScenarioAdapter(config),
        )


__all__ = [
    "PWN_RET2WIN_BINARY_CAPABILITY",
    "PWN_RET2WIN_BINARY_TOOL_ID",
    "PWN_RET2WIN_CAPABILITIES",
    "PWN_RET2WIN_INTERACTION_CAPABILITY",
    "PWN_RET2WIN_INTERACTION_TOOL_ID",
    "PWN_RET2WIN_REPORT_TEMPLATE",
    "PWN_RET2WIN_REQUIRED_TOOLS",
    "PWN_RET2WIN_SECURITY_POLICY",
    "PWN_RET2WIN_TASK_PACK_ID",
    "PWN_RET2WIN_TASK_PACK_VERSION",
    "PWN_RET2WIN_TASK_TYPE",
    "PWN_RET2WIN_VERIFIER_ID",
    "PwnRet2winScenarioAdapter",
    "PwnRet2winScenarioConfig",
    "PwnRet2winTaskPack",
    "pwn_ret2win_manifest",
]
