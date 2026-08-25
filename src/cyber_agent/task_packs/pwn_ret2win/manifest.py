"""Fixed metadata for the Pwn ret2win task pack."""

from __future__ import annotations

from cyber_agent.contracts.task_pack import TaskPackManifest

PWN_RET2WIN_TASK_PACK_ID = "pwn.ret2win"
PWN_RET2WIN_TASK_PACK_VERSION = "1.0.0"
PWN_RET2WIN_TASK_TYPE = "pwn.ret2win"
PWN_RET2WIN_BINARY_TOOL_ID = "pwn.binary_properties"
PWN_RET2WIN_INTERACTION_TOOL_ID = "pwn.process_interaction"
PWN_RET2WIN_REQUIRED_TOOLS = (
    PWN_RET2WIN_BINARY_TOOL_ID,
    PWN_RET2WIN_INTERACTION_TOOL_ID,
)
PWN_RET2WIN_BINARY_CAPABILITY = "pwn.binary_properties"
PWN_RET2WIN_INTERACTION_CAPABILITY = "pwn.process_interaction"
PWN_RET2WIN_CAPABILITIES = (
    PWN_RET2WIN_BINARY_CAPABILITY,
    PWN_RET2WIN_INTERACTION_CAPABILITY,
)
PWN_RET2WIN_VERIFIER_ID = "pwn.ret2win"
PWN_RET2WIN_REPORT_TEMPLATE = "pwn.exploitation"
PWN_RET2WIN_SECURITY_POLICY = "scope-policy/1.0"

_MANIFEST = TaskPackManifest(
    task_pack_id=PWN_RET2WIN_TASK_PACK_ID,
    version=PWN_RET2WIN_TASK_PACK_VERSION,
    task_type=PWN_RET2WIN_TASK_TYPE,
    required_tools=PWN_RET2WIN_REQUIRED_TOOLS,
    verifier=PWN_RET2WIN_VERIFIER_ID,
    report_template=PWN_RET2WIN_REPORT_TEMPLATE,
    security_policy=PWN_RET2WIN_SECURITY_POLICY,
)


def pwn_ret2win_manifest() -> TaskPackManifest:
    """Return an isolated copy of the fixed least-privilege manifest."""

    return _MANIFEST.model_copy(deep=True)


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
    "pwn_ret2win_manifest",
]
