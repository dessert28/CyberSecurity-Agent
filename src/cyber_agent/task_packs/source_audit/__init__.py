"""Python source-audit task pack plugin."""

from __future__ import annotations

from cyber_agent.contracts.task_pack import TaskPack

from .adapter import SourceAuditScenarioAdapter
from .config import SourceAuditScenarioConfig
from .manifest import (
    SOURCE_AUDIT_CAPABILITY,
    SOURCE_AUDIT_CAPABILITIES,
    SOURCE_AUDIT_DATAFLOW_CAPABILITY,
    SOURCE_AUDIT_DATAFLOW_TOOL_ID,
    SOURCE_AUDIT_INVENTORY_CAPABILITY,
    SOURCE_AUDIT_INVENTORY_TOOL_ID,
    SOURCE_AUDIT_REPORT_TEMPLATE,
    SOURCE_AUDIT_REQUIRED_TOOLS,
    SOURCE_AUDIT_SECURITY_POLICY,
    SOURCE_AUDIT_TASK_PACK_ID,
    SOURCE_AUDIT_TASK_PACK_VERSION,
    SOURCE_AUDIT_TASK_TYPE,
    SOURCE_AUDIT_TOOL_ID,
    SOURCE_AUDIT_VALIDATION_CAPABILITY,
    SOURCE_AUDIT_VALIDATION_TOOL_ID,
    SOURCE_AUDIT_VERIFIER_ID,
    source_audit_manifest,
)


class SourceAuditTaskPack(TaskPack):
    """Immutable three-stage Python source-audit task pack."""

    def __init__(self, config: SourceAuditScenarioConfig) -> None:
        super().__init__(
            manifest=source_audit_manifest(),
            adapter=SourceAuditScenarioAdapter(config),
        )


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
    "SourceAuditScenarioAdapter",
    "SourceAuditScenarioConfig",
    "SourceAuditTaskPack",
    "source_audit_manifest",
]
