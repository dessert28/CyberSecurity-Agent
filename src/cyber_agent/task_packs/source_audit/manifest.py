"""Fixed metadata for the three-stage Python source-audit task pack."""

from __future__ import annotations

from cyber_agent.contracts.task_pack import TaskPackManifest

SOURCE_AUDIT_TASK_PACK_ID = "source.audit.python"
SOURCE_AUDIT_TASK_PACK_VERSION = "1.0.0"
SOURCE_AUDIT_TASK_TYPE = "source.code-audit"
SOURCE_AUDIT_INVENTORY_TOOL_ID = "source.project_inventory"
SOURCE_AUDIT_DATAFLOW_TOOL_ID = "source.python_dataflow"
SOURCE_AUDIT_VALIDATION_TOOL_ID = "source.hypothesis_validate"
SOURCE_AUDIT_REQUIRED_TOOLS = (
    SOURCE_AUDIT_INVENTORY_TOOL_ID,
    SOURCE_AUDIT_DATAFLOW_TOOL_ID,
    SOURCE_AUDIT_VALIDATION_TOOL_ID,
)
SOURCE_AUDIT_INVENTORY_CAPABILITY = "source.inventory"
SOURCE_AUDIT_DATAFLOW_CAPABILITY = "source.dataflow"
SOURCE_AUDIT_VALIDATION_CAPABILITY = "source.hypothesis_validate"
SOURCE_AUDIT_CAPABILITIES = (
    SOURCE_AUDIT_INVENTORY_CAPABILITY,
    SOURCE_AUDIT_DATAFLOW_CAPABILITY,
    SOURCE_AUDIT_VALIDATION_CAPABILITY,
)
# Compatibility aliases retained for existing public imports.
SOURCE_AUDIT_TOOL_ID = SOURCE_AUDIT_INVENTORY_TOOL_ID
SOURCE_AUDIT_CAPABILITY = SOURCE_AUDIT_INVENTORY_CAPABILITY
SOURCE_AUDIT_VERIFIER_ID = "source.hypothesis"
SOURCE_AUDIT_REPORT_TEMPLATE = "source.security-audit"
SOURCE_AUDIT_SECURITY_POLICY = "scope-policy/1.0"

_MANIFEST = TaskPackManifest(
    task_pack_id=SOURCE_AUDIT_TASK_PACK_ID,
    version=SOURCE_AUDIT_TASK_PACK_VERSION,
    task_type=SOURCE_AUDIT_TASK_TYPE,
    required_tools=SOURCE_AUDIT_REQUIRED_TOOLS,
    verifier=SOURCE_AUDIT_VERIFIER_ID,
    report_template=SOURCE_AUDIT_REPORT_TEMPLATE,
    security_policy=SOURCE_AUDIT_SECURITY_POLICY,
)


def source_audit_manifest() -> TaskPackManifest:
    """Return an isolated copy of the fixed least-privilege manifest."""

    return _MANIFEST.model_copy(deep=True)


__all__ = [
    "SOURCE_AUDIT_REPORT_TEMPLATE",
    "SOURCE_AUDIT_CAPABILITY",
    "SOURCE_AUDIT_CAPABILITIES",
    "SOURCE_AUDIT_DATAFLOW_CAPABILITY",
    "SOURCE_AUDIT_DATAFLOW_TOOL_ID",
    "SOURCE_AUDIT_INVENTORY_CAPABILITY",
    "SOURCE_AUDIT_INVENTORY_TOOL_ID",
    "SOURCE_AUDIT_REQUIRED_TOOLS",
    "SOURCE_AUDIT_SECURITY_POLICY",
    "SOURCE_AUDIT_TASK_PACK_ID",
    "SOURCE_AUDIT_TASK_PACK_VERSION",
    "SOURCE_AUDIT_TASK_TYPE",
    "SOURCE_AUDIT_TOOL_ID",
    "SOURCE_AUDIT_VALIDATION_CAPABILITY",
    "SOURCE_AUDIT_VALIDATION_TOOL_ID",
    "SOURCE_AUDIT_VERIFIER_ID",
    "source_audit_manifest",
]
