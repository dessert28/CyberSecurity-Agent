from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from cyber_agent.application.run_management import CompetitionRunManager
from cyber_agent.application.run_history import SQLiteRunHistory
from cyber_agent.application.runtime_factory import RealRuntimeFactory
from cyber_agent.executor import ControlledExecutor, SourceAnalysisRunner
from cyber_agent.tools import expected_competition_tool_ids
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
    assert type(manager) is CompetitionRunManager
    assert manager.runtime_preparer is factory
    assert bundle.app.state.run_manager is manager
    assert type(bundle.app.state.run_history) is SQLiteRunHistory
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


def test_taskpack_readiness_detail_reports_tools_model_and_reason(
    tmp_path: Path,
) -> None:
    bundle = local_server.build_local_server(
        port=49854,
        runtime_root=tmp_path,
        credential_store=MemoryCredentialStore(),
        launch_token="public-server-token-0000000000000000000000",
    )

    factory = bundle.app.state.real_runtime_factory
    web = factory.taskpack_readiness_detail(WEB_IDOR_TASK_PACK_ID)

    assert web.state is ReadinessState.EXECUTOR_NOT_READY
    assert web.required_tools == ("web.http_request",)
    assert web.tool_states
    assert web.tool_states[0].tool_id == "web.http_request"
    assert web.tool_states[0].healthy is False
    assert web.model_capability_ready is False
    assert "执行器" in web.detail
    assert "依赖工具未就绪" in web.detail
    assert "当前模型能力校验未完成" in web.detail
    assert web.docker_required is True

    source = factory.taskpack_readiness_detail(SOURCE_AUDIT_TASK_PACK_ID)
    assert source.state is ReadinessState.READY
    assert source.required_tools
    assert source.model_capability_ready is False
    assert source.docker_required is False


def test_server_registers_full_tool_catalog_and_debug_endpoint(
    tmp_path: Path,
) -> None:
    bundle = local_server.build_local_server(
        port=49854,
        runtime_root=tmp_path,
        credential_store=MemoryCredentialStore(),
        launch_token="public-server-token-0000000000000000000000",
    )

    expected = bundle.app.state.expected_tool_ids
    registry = bundle.app.state.tool_registry
    assert set(expected) == set(expected_competition_tool_ids())
    assert {item.tool_ref.tool_id for item in registry.all_statuses()} == set(expected)

    with TestClient(bundle.app, base_url=bundle.origin) as browser:
        exchange = browser.get(
            "/session/exchange?token=public-server-token-0000000000000000000000",
            follow_redirects=False,
        )
        assert exchange.status_code == 303
        response = browser.get("/debug/tools/list_all")

    assert response.status_code == 200
    assert response.json()["missing_tool_ids"] == []
    assert len(response.json()["registered_tool_ids"]) == len(expected)
