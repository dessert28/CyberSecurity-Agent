from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from cyber_agent.api.workbench import create_workbench_app
from cyber_agent.application.runtime_readiness import RuntimeReadinessService
from cyber_agent.tools import (
    ToolRegistry,
    build_competition_tool_registry,
    expected_competition_tool_ids,
)
from cyber_agent.workbench.schemas import (
    ModelRuntimeReadiness,
    ReadinessState,
    TaskPackReadiness,
    ToolReadinessView,
)


ORIGIN = "http://127.0.0.1:49862"
LAUNCH_TOKEN = "public-readiness-token-000000000000000000000"
NOW = datetime(2026, 8, 18, 8, 0, tzinfo=timezone.utc)


def _exchange(browser: TestClient) -> None:
    response = browser.get(
        f"/session/exchange?token={LAUNCH_TOKEN}",
        follow_redirects=False,
    )
    assert response.status_code == 303
    page = browser.get("/")
    assert re.search(r'<meta name="csrf-token" content="[^"]+">', page.text)


def _readiness() -> RuntimeReadinessService:
    states = {
        "web.idor": ReadinessState.EXECUTOR_NOT_READY,
        "source.audit.python": ReadinessState.READY,
    }
    return RuntimeReadinessService(
        model_probe=lambda: ModelRuntimeReadiness(
            ready=True,
            state=ReadinessState.READY,
            reason_codes=(),
            capability_probe_ref="11111111-1111-4111-8111-111111111111",
        ),
        core_probe=lambda: ReadinessState.READY,
        taskpack_ids=("web.idor", "source.audit.python"),
        taskpack_probe=lambda taskpack_id: states[taskpack_id],
        clock=lambda: NOW,
    )


def test_runtime_readiness_route_is_session_protected_and_strict() -> None:
    app = create_workbench_app(
        launch_token=LAUNCH_TOKEN,
        origin=ORIGIN,
        runtime_readiness=_readiness(),
    )
    with TestClient(app, base_url=ORIGIN) as browser:
        assert browser.get("/api/v1/runtime-readiness").status_code == 401
        _exchange(browser)
        response = browser.get("/api/v1/runtime-readiness")

    assert response.status_code == 200
    assert response.json() == {
        "state": "READY",
        "runtime_available": True,
        "model_ready": True,
        "core_ready": True,
        "reason_codes": [],
        "available_taskpacks": ["source.audit.python"],
        "unavailable_taskpacks": [
            {
                "task_pack_id": "web.idor",
                "state": "EXECUTOR_NOT_READY",
                "reason_codes": ["EXECUTOR_NOT_READY"],
            }
        ],
        "taskpacks": [
            {
                "task_pack_id": "web.idor",
                "state": "EXECUTOR_NOT_READY",
                "reason_codes": ["EXECUTOR_NOT_READY"],
            },
            {
                "task_pack_id": "source.audit.python",
                "state": "READY",
                "reason_codes": [],
            },
        ],
        "checked_at": "2026-08-18T08:00:00Z",
    }
    assert "message" not in response.json()


def test_default_runtime_readiness_fails_closed_without_runtime_components() -> None:
    app = create_workbench_app(launch_token=LAUNCH_TOKEN, origin=ORIGIN)
    with TestClient(app, base_url=ORIGIN) as browser:
        _exchange(browser)
        response = browser.get("/api/v1/runtime-readiness")

    assert response.status_code == 200
    assert response.json()["runtime_available"] is False
    assert response.json()["model_ready"] is False
    assert response.json()["core_ready"] is False
    assert response.json()["state"] == "MODEL_NOT_READY"
    assert response.json()["available_taskpacks"] == []
    assert response.json()["unavailable_taskpacks"] == [
        {
            "task_pack_id": "web.idor",
            "state": "EXECUTOR_NOT_READY",
            "reason_codes": ["EXECUTOR_NOT_READY"],
        },
        {
            "task_pack_id": "source.audit.python",
            "state": "EXECUTOR_NOT_READY",
            "reason_codes": ["EXECUTOR_NOT_READY"],
        },
    ]


def test_default_readiness_uses_capability_service_without_unlocking_core() -> None:
    class CapabilityStub:
        def runtime_readiness(self) -> ModelRuntimeReadiness:
            return ModelRuntimeReadiness(
                ready=True,
                state=ReadinessState.READY,
                reason_codes=(),
                capability_probe_ref="11111111-1111-4111-8111-111111111111",
            )

    app = create_workbench_app(
        launch_token=LAUNCH_TOKEN,
        origin=ORIGIN,
        capabilities=CapabilityStub(),  # type: ignore[arg-type]
    )
    with TestClient(app, base_url=ORIGIN) as browser:
        _exchange(browser)
        response = browser.get("/api/v1/runtime-readiness")

    assert response.status_code == 200
    assert response.json()["model_ready"] is True
    assert response.json()["core_ready"] is False
    assert response.json()["runtime_available"] is False
    assert response.json()["state"] == "REGISTRY_NOT_READY"


def test_taskpack_readiness_detail_endpoint_returns_full_report() -> None:
    detail = TaskPackReadiness(
        task_pack_id="web.idor",
        state=ReadinessState.EXECUTOR_NOT_READY,
        reason_codes=(ReadinessState.EXECUTOR_NOT_READY,),
        required_tools=("web.http_request",),
        tool_states=(
            ToolReadinessView(
                tool_id="web.http_request",
                state="unhealthy",
                healthy=False,
                message="container runtime unavailable",
            ),
        ),
        model_capability_ready=False,
        detail="执行器未就绪；依赖工具未就绪：web.http_request；当前模型能力校验未完成",
    )
    readiness = RuntimeReadinessService(
        model_probe=lambda: ModelRuntimeReadiness(
            ready=True,
            state=ReadinessState.READY,
            reason_codes=(),
            capability_probe_ref="11111111-1111-4111-8111-111111111111",
        ),
        core_probe=lambda: ReadinessState.READY,
        taskpack_ids=("web.idor", "source.audit.python"),
        taskpack_probe=lambda task_pack_id: (
            detail.state
            if task_pack_id == "web.idor"
            else ReadinessState.READY
        ),
        taskpack_detail_probe=lambda task_pack_id: (
            detail
            if task_pack_id == "web.idor"
            else TaskPackReadiness(
                task_pack_id=task_pack_id,
                state=ReadinessState.READY,
                reason_codes=(),
            )
        ),
        clock=lambda: NOW,
    )
    app = create_workbench_app(
        launch_token=LAUNCH_TOKEN,
        origin=ORIGIN,
        runtime_readiness=readiness,
    )
    with TestClient(app, base_url=ORIGIN) as browser:
        _exchange(browser)
        response = browser.get("/api/v1/runtime-readiness/web.idor")

    assert response.status_code == 200
    assert response.json() == {
        "task_pack_id": "web.idor",
        "state": "EXECUTOR_NOT_READY",
        "reason_codes": ["EXECUTOR_NOT_READY"],
        "required_tools": ["web.http_request"],
        "tool_states": [
            {
                "tool_id": "web.http_request",
                "state": "unhealthy",
                "healthy": False,
                "message": "container runtime unavailable",
            }
        ],
        "model_capability_ready": False,
        "detail": "执行器未就绪；依赖工具未就绪：web.http_request；当前模型能力校验未完成",
    }


def test_debug_tools_list_reports_missing_tool_ids() -> None:
    app = create_workbench_app(launch_token=LAUNCH_TOKEN, origin=ORIGIN)
    app.state.tool_registry = ToolRegistry()
    app.state.expected_tool_ids = (
        "web.http_request",
        "source.project_inventory",
    )
    with TestClient(app, base_url=ORIGIN) as browser:
        _exchange(browser)
        response = browser.get("/debug/tools/list_all")

    assert response.status_code == 200
    assert response.json()["expected_tool_ids"] == [
        "web.http_request",
        "source.project_inventory",
    ]
    assert response.json()["registered_tool_ids"] == []
    assert response.json()["missing_tool_ids"] == [
        "web.http_request",
        "source.project_inventory",
    ]
    assert response.json()["tool_statuses"] == []


def test_debug_tools_list_full_registry_has_no_missing_tools() -> None:
    registry = asyncio.run(
        build_competition_tool_registry(runtime_available=lambda: False)
    )[0]
    app = create_workbench_app(launch_token=LAUNCH_TOKEN, origin=ORIGIN)
    app.state.tool_registry = registry
    app.state.expected_tool_ids = expected_competition_tool_ids()
    with TestClient(app, base_url=ORIGIN) as browser:
        _exchange(browser)
        response = browser.get("/debug/tools/list_all")

    assert response.status_code == 200
    assert response.json()["missing_tool_ids"] == []
    assert set(response.json()["registered_tool_ids"]) == set(
        expected_competition_tool_ids()
    )
    assert len(response.json()["tool_statuses"]) == len(
        expected_competition_tool_ids()
    )


def test_debug_tools_health_report_returns_exception_details() -> None:
    def broken_probe():
        raise RuntimeError("private probe exploded")

    registry = asyncio.run(
        build_competition_tool_registry(
            runtime_available=broken_probe,
            docker_probe=broken_probe,
        )
    )[0]
    app = create_workbench_app(launch_token=LAUNCH_TOKEN, origin=ORIGIN)
    app.state.tool_registry = registry
    with TestClient(app, base_url=ORIGIN) as browser:
        _exchange(browser)
        response = browser.get("/debug/tools/health_report")

    assert response.status_code == 200
    tools = response.json()["tools"]
    assert len(tools) == len(expected_competition_tool_ids())
    web = next(item for item in tools if item["tool_id"] == "web.http_request")
    assert web["healthy"] is False
    assert web["last_health_exception"]
    assert "Traceback" in web["last_health_exception"]
    assert "private probe exploded" in web["last_health_exception"]


def test_debug_tools_health_report_without_registry_is_empty() -> None:
    app = create_workbench_app(launch_token=LAUNCH_TOKEN, origin=ORIGIN)
    with TestClient(app, base_url=ORIGIN) as browser:
        _exchange(browser)
        response = browser.get("/debug/tools/health_report")

    assert response.status_code == 200
    assert response.json() == {"tools": []}
