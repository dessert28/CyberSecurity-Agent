from __future__ import annotations

import asyncio
from pathlib import Path

from cyber_agent.application.run_management import CompetitionRunManager
from cyber_agent.application.runtime_factory import RealRuntimeFactory
from cyber_agent.executor import ControlledExecutor, SourceAnalysisRunner
from cyber_agent.model_gateway import ModelIoTraceStore
from cyber_agent.workbench.adapters import ModelAdapterFactory
from cyber_agent.workbench.credentials import MemoryCredentialStore
from cyber_agent.task_packs.source_audit import SOURCE_AUDIT_TASK_PACK_ID
from cyber_agent.task_packs.web_idor import WEB_IDOR_TASK_PACK_ID
from cyber_agent.workbench.schemas import ReadinessState

import cyber_agent.server as local_server


def test_server_exposes_source_runtime_to_workbench_with_taskpack_readiness(
    tmp_path: Path,
) -> None:
    bundle = local_server.build_local_server(
        port=49854,
        runtime_root=tmp_path,
        credential_store=MemoryCredentialStore(),
        launch_token="public-server-token-0000000000000000000000",
    )

    factory = bundle.app.state.real_runtime_factory
    manager = bundle.app.state.formal_run_manager
    readiness = bundle.app.state.runtime_readiness.status()

    assert type(factory) is RealRuntimeFactory
    assert type(factory.adapter_factory) is ModelAdapterFactory
    assert type(bundle.app.state.model_io_traces) is ModelIoTraceStore
    assert factory.adapter_factory.trace_store is bundle.app.state.model_io_traces
    assert type(manager) is CompetitionRunManager
    assert manager.runtime_preparer is factory
    assert bundle.app.state.run_manager is manager
    assert readiness.runtime_available is False
    by_id = {item.task_pack_id: item.state for item in readiness.taskpacks}
    assert readiness.available_taskpacks == (SOURCE_AUDIT_TASK_PACK_ID,)
    assert by_id[SOURCE_AUDIT_TASK_PACK_ID] is ReadinessState.READY
    assert by_id[WEB_IDOR_TASK_PACK_ID] is ReadinessState.EXECUTOR_NOT_READY
    assert bundle.app.state.artifact_uploads is bundle.app.state.source_artifact_upload

    assembly = asyncio.run(factory._build_executor_assembly(SOURCE_AUDIT_TASK_PACK_ID))
    assert type(assembly.executor) is ControlledExecutor
    assert type(assembly.executor._source_analysis) is SourceAnalysisRunner
    assert assembly.executor._fake is None


def test_production_runtime_modules_do_not_reference_demo_fake_or_replay() -> None:
    root = Path(local_server.__file__).resolve().parent
    source = "\n".join(
        (root / relative).read_text(encoding="utf-8")
        for relative in (
            "server.py",
            "application/runtime_factory.py",
            "application/bootstrap.py",
        )
    )

    for forbidden in (
        "DemoPlanner",
        "FakeRunner(",
        "FakeModelAdapter",
        "ReplayModelAdapter",
        "ASGITransport",
    ):
        assert forbidden not in source
