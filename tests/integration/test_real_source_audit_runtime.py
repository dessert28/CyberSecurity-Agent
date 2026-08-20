from __future__ import annotations

import io
import zipfile
from uuid import uuid4

import pytest

from cyber_agent.application.runtime_factory import SourceAuditExecutorProvider
from cyber_agent.application.source_audit_budget import SourceAuditResourceBudget
from cyber_agent.artifacts import InMemoryArtifactStore
from cyber_agent.contracts.tool import (
    ExecutionRequest,
    MountSpec,
    NetworkPolicy,
    ResourceLimits,
    RunnerType,
    ToolResultStatus,
)
from cyber_agent.executor import ControlledExecutor, SourceAnalysisRunner
from cyber_agent.task_packs.source_audit import SOURCE_AUDIT_TASK_PACK_ID
from cyber_agent.task_packs.web_idor import WEB_IDOR_TASK_PACK_ID
from cyber_agent.tools import (
    HYPOTHESIS_VALIDATE_TOOL_ID,
    PROJECT_INVENTORY_TOOL_ID,
    PYTHON_DATAFLOW_TOOL_ID,
)
from cyber_agent.workbench.schemas import ReadinessState


def _zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "app.py",
            b"raise RuntimeError('target code must not execute')\n"
            b"from flask import request\n",
        )
    return output.getvalue()


class RecordingGuard:
    def __init__(self, *, healthy: bool = True) -> None:
        self.healthy = healthy
        self.run_calls = 0

    async def health_check(self) -> bool:
        return self.healthy

    async def run(self, request: ExecutionRequest, source_zip: bytes) -> bytes:
        self.run_calls += 1
        assert request.entrypoint == [PROJECT_INVENTORY_TOOL_ID]
        assert source_zip.startswith(b"PK")
        return b'{"observation_type":"project_inventory"}'

    async def cancel(self, _request_id) -> None:
        return None


@pytest.mark.asyncio
async def test_provider_exposes_only_guarded_source_runtime_with_budgeted_tools() -> None:
    budget = SourceAuditResourceBudget()
    store = InMemoryArtifactStore()
    guard = RecordingGuard()
    provider = SourceAuditExecutorProvider(
        budget=budget,
        artifact_reader=store.read_bytes,
        worker_guard=guard,
        platform="test/windows",
    )

    assert provider.readiness(SOURCE_AUDIT_TASK_PACK_ID) is ReadinessState.EXECUTOR_NOT_READY
    assert await provider.initialize() is True
    assert provider.readiness(SOURCE_AUDIT_TASK_PACK_ID) is ReadinessState.READY
    assert provider.readiness(WEB_IDOR_TASK_PACK_ID) is ReadinessState.EXECUTOR_NOT_READY

    assembly = await provider.build(SOURCE_AUDIT_TASK_PACK_ID)

    assert type(assembly.executor) is ControlledExecutor
    assert type(assembly.executor._source_analysis) is SourceAnalysisRunner
    assert assembly.executor._fake is None
    assert {plugin.get_spec().tool_id for plugin in assembly.plugins} == {
        PROJECT_INVENTORY_TOOL_ID,
        PYTHON_DATAFLOW_TOOL_ID,
        HYPOTHESIS_VALIDATE_TOOL_ID,
    }
    by_id = {plugin.get_spec().tool_id: plugin.get_spec() for plugin in assembly.plugins}
    assert by_id[PROJECT_INVENTORY_TOOL_ID].execution_profile.default_timeout_seconds == 30
    assert by_id[PYTHON_DATAFLOW_TOOL_ID].execution_profile.default_timeout_seconds == 30
    assert by_id[HYPOTHESIS_VALIDATE_TOOL_ID].execution_profile.default_timeout_seconds == 10
    assert by_id[HYPOTHESIS_VALIDATE_TOOL_ID].execution_profile.default_resources.max_output_bytes == 2_000_000
    assert assembly.resource_budget == budget.fingerprint_input()

    content = _zip_bytes()
    artifact = await store.put_bytes(content, media_type="application/zip")
    request = ExecutionRequest(
        invocation_id=uuid4(),
        runner=RunnerType.SOURCE_ANALYSIS,
        entrypoint=[PROJECT_INVENTORY_TOOL_ID],
        mounts=[MountSpec(artifact_id=artifact.artifact_id, container_path="/inputs/source.zip")],
        network_policy=NetworkPolicy(),
        resources=ResourceLimits(
            cpu_cores=budget.cpu_cores,
            memory_megabytes=budget.memory_megabytes,
            max_processes=budget.max_processes,
            max_output_bytes=budget.inventory_output_bytes,
        ),
        timeout_seconds=budget.inventory_timeout_seconds,
    )

    result = await assembly.executor.execute(request)

    assert result.status is ToolResultStatus.SUCCEEDED
    assert guard.run_calls == 1


@pytest.mark.asyncio
async def test_provider_health_failure_is_fail_closed_and_never_builds_source() -> None:
    store = InMemoryArtifactStore()
    provider = SourceAuditExecutorProvider(
        budget=SourceAuditResourceBudget(),
        artifact_reader=store.read_bytes,
        worker_guard=RecordingGuard(healthy=False),
        platform="test/windows",
    )

    assert await provider.initialize() is False
    assert provider.readiness(SOURCE_AUDIT_TASK_PACK_ID) is ReadinessState.EXECUTOR_NOT_READY

    with pytest.raises(RuntimeError):
        await provider.build(SOURCE_AUDIT_TASK_PACK_ID)
