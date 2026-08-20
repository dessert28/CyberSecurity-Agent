"""Production-only adapters for the fixed Source Audit analyzer registry."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

from cyber_agent.contracts.artifact_materialization import MaterializedArtifactInput
from cyber_agent.contracts.source_audit_budget import SourceAuditResourceBudget
from cyber_agent.contracts.tool import ExecutionRequest
from cyber_agent.executor.source_analysis import SourceAnalysisExecutionError

from .hypothesis_validate import HYPOTHESIS_VALIDATE_TOOL_ID, HypothesisValidationHandler
from .project_inventory import (
    PROJECT_INVENTORY_TOOL_ID,
    ProjectInventoryAnalyzer,
)
from .python_dataflow import (
    PYTHON_DATAFLOW_TOOL_ID,
    PythonDataflowAnalyzer,
)

SOURCE_HANDLER_IDS = frozenset(
    {
        PROJECT_INVENTORY_TOOL_ID,
        PYTHON_DATAFLOW_TOOL_ID,
        HYPOTHESIS_VALIDATE_TOOL_ID,
    }
)


def execute_source_handler(
    handler_id: str,
    request: ExecutionRequest,
    source_zip: bytes,
    budget: SourceAuditResourceBudget,
) -> bytes:
    """Run one allowlisted deterministic analyzer without importing target code."""

    if handler_id not in SOURCE_HANDLER_IDS or request.entrypoint != [handler_id]:
        raise SourceAnalysisExecutionError(
            "SOURCE_ANALYSIS_HANDLER_DENIED",
            "Requested source-analysis handler is not registered.",
        )
    lease = _lease(request, source_zip)
    inventory_analyzer = ProjectInventoryAnalyzer(
        archive_reader=lambda: source_zip,
        max_members=budget.max_members,
        max_uncompressed_bytes=budget.max_uncompressed_bytes,
        max_member_bytes=budget.max_member_bytes,
        max_text_bytes=budget.max_python_file_bytes,
    )
    if handler_id == PROJECT_INVENTORY_TOOL_ID:
        if request.argv:
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_ARGUMENTS_DENIED",
                "Project inventory does not accept worker arguments.",
            )
        return inventory_analyzer.analyze(lease).model_dump_json().encode("utf-8")

    if handler_id == PYTHON_DATAFLOW_TOOL_ID:
        if len(request.argv) != 2 or request.argv[0] != "--inventory-sha256":
            raise SourceAnalysisExecutionError(
                "SOURCE_ANALYSIS_ARGUMENTS_DENIED",
                "Python dataflow received invalid worker arguments.",
            )
        inventory = inventory_analyzer.analyze(lease)
        if PythonDataflowAnalyzer.inventory_sha256(inventory) != request.argv[1]:
            raise SourceAnalysisExecutionError(
                "SOURCE_DATAFLOW_INVENTORY_MISMATCH",
                "Project inventory fingerprint does not match the source archive.",
            )
        result = PythonDataflowAnalyzer(
            archive_reader=lambda: source_zip,
            max_members=budget.max_members,
            max_uncompressed_bytes=budget.max_uncompressed_bytes,
            max_member_bytes=budget.max_member_bytes,
            max_python_file_bytes=budget.max_python_file_bytes,
            max_ast_nodes_per_file=budget.max_ast_nodes_per_file,
        ).analyze(lease, inventory)
        return result.model_dump_json().encode("utf-8")

    handler = HypothesisValidationHandler(
        max_members=budget.max_members,
        max_uncompressed_bytes=budget.max_uncompressed_bytes,
        max_member_bytes=budget.max_member_bytes,
        max_source_bytes=budget.max_python_file_bytes,
        max_ast_nodes=budget.max_ast_nodes_per_file,
    )
    return asyncio.run(handler(request, source_zip))


def _lease(request: ExecutionRequest, source_zip: bytes) -> MaterializedArtifactInput:
    now = datetime.now(timezone.utc)
    return MaterializedArtifactInput(
        run_id=request.invocation_id,
        artifact_id=request.mounts[0].artifact_id,
        artifact_sha256=hashlib.sha256(source_zip).hexdigest(),
        media_type="application/zip",
        size_bytes=len(source_zip),
        created_at=now,
        expires_at=now + timedelta(seconds=request.timeout_seconds + 1),
    )


__all__ = ["SOURCE_HANDLER_IDS", "execute_source_handler"]
