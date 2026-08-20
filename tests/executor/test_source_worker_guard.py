from __future__ import annotations

import io
import sys
import zipfile
from uuid import uuid4

import pytest

from cyber_agent.application.source_audit_budget import SourceAuditResourceBudget
from cyber_agent.contracts.tool import (
    ExecutionRequest,
    MountSpec,
    NetworkPolicy,
    ResourceLimits,
    RunnerType,
    ToolResultStatus,
)
from cyber_agent.executor.source_analysis import SourceAnalysisRunner
from cyber_agent.executor.source_worker_guard import WindowsSourceWorkerGuard
from cyber_agent.tools import PROJECT_INVENTORY_TOOL_ID


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object guard")


def _zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("app.py", b"from flask import request\n")
    return output.getvalue()


def _request(*, timeout_seconds: int = 30) -> ExecutionRequest:
    return ExecutionRequest(
        invocation_id=uuid4(),
        runner=RunnerType.SOURCE_ANALYSIS,
        entrypoint=[PROJECT_INVENTORY_TOOL_ID],
        mounts=[MountSpec(artifact_id=uuid4(), container_path="/inputs/source.zip")],
        network_policy=NetworkPolicy(),
        resources=ResourceLimits(
            cpu_cores=1,
            memory_megabytes=256,
            max_processes=1,
            max_output_bytes=5_000_000,
        ),
        timeout_seconds=timeout_seconds,
    )


@pytest.mark.asyncio
async def test_job_object_guard_health_and_real_worker_execution() -> None:
    content = _zip_bytes()
    guard = WindowsSourceWorkerGuard(budget=SourceAuditResourceBudget())
    assert await guard.health_check() is True

    async def read_artifact(_):
        return content

    runner = SourceAnalysisRunner(artifact_reader=read_artifact, worker_guard=guard)
    result = await runner.execute(_request())

    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.exit_code == 0
    assert guard.active_process_count == 0


@pytest.mark.asyncio
async def test_timeout_kills_exact_worker_and_cleans_handles(monkeypatch) -> None:
    content = _zip_bytes()
    guard = WindowsSourceWorkerGuard(budget=SourceAuditResourceBudget())

    async def never_returns(*_args, **_kwargs):
        await __import__("asyncio").Future()

    monkeypatch.setattr(guard, "_exchange", never_returns)

    async def read_artifact(_):
        return content

    runner = SourceAnalysisRunner(artifact_reader=read_artifact, worker_guard=guard)
    result = await runner.execute(_request(timeout_seconds=1))

    assert result.status is ToolResultStatus.TIMED_OUT
    assert result.error.code == "SOURCE_ANALYSIS_TIMEOUT"
    assert guard.active_process_count == 0
