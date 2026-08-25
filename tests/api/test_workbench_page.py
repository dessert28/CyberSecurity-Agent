from __future__ import annotations

import re
from datetime import datetime, timezone
from uuid import UUID

from fastapi.testclient import TestClient

from cyber_agent.api.workbench import create_workbench_app
from cyber_agent.application.run_management import (
    RunAcceptedResponse,
    RunCreateRequest,
)
from cyber_agent.application.run_history import RunHistoryItem
from cyber_agent.application.runtime_readiness import RuntimeReadinessService
from cyber_agent.contracts.plan import RunStatus
from cyber_agent.workbench.schemas import (
    ModelRuntimeReadiness,
    ReadinessState,
    TaskPackReadiness,
    ToolReadinessView,
)


ORIGIN = "http://127.0.0.1:49831"
LAUNCH_TOKEN = "public-workbench-token-00000000000000000000"
RUN_ID = UUID("55555555-5555-4555-8555-555555555555")


class RecordingRunManager:
    def __init__(self) -> None:
        self.requests: list[RunCreateRequest] = []
        self.executed: list[UUID] = []

    async def create_run(self, request: RunCreateRequest) -> RunAcceptedResponse:
        self.requests.append(request)
        return RunAcceptedResponse(run_id=RUN_ID, status=RunStatus.QUEUED)

    async def execute_run(self, run_id: UUID) -> None:
        self.executed.append(run_id)

    async def list_recent(self, *, limit: int):
        return (
            RunHistoryItem(
                run_id=RUN_ID,
                task_pack="web.idor",
                status=RunStatus.COMPLETED,
                request_preview="Assess the authorized order API.",
                request_text="Assess the authorized order API.",
                created_at=datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc),
                updated_at=datetime(2026, 8, 25, 10, 1, tzinfo=timezone.utc),
            ),
        )[:limit]


def _browser(*, run_manager=None) -> TestClient:
    runtime_readiness = RuntimeReadinessService(
        model_probe=lambda: ModelRuntimeReadiness(
            ready=True,
            state=ReadinessState.READY,
            reason_codes=(),
            capability_probe_ref="11111111-1111-4111-8111-111111111111",
        ),
        core_probe=lambda: ReadinessState.READY,
        taskpack_ids=("web.idor", "source.audit.python"),
        taskpack_probe=lambda _: ReadinessState.READY,
    )
    app = create_workbench_app(
        launch_token=LAUNCH_TOKEN,
        origin=ORIGIN,
        run_manager=run_manager,
        runtime_readiness=runtime_readiness,
    )
    return TestClient(app, base_url=ORIGIN)


def _exchange(browser: TestClient) -> str:
    exchange = browser.get(
        f"/session/exchange?token={LAUNCH_TOKEN}",
        follow_redirects=False,
    )
    assert exchange.status_code == 303
    page = browser.get("/")
    match = re.search(r'<meta name="csrf-token" content="([^"]+)">', page.text)
    assert match is not None
    return match.group(1)


def test_workbench_home_exposes_both_competition_scenarios() -> None:
    browser = _browser()
    with browser:
        _exchange(browser)
        response = browser.get("/")
        bundle = browser.get("/static/react/assets/index.js")

    assert response.status_code == 200
    assert "网络安全智能体工作台" in response.text
    assert 'href="/static/react/assets/workbench.css"' in response.text
    assert 'src="/static/react/assets/index.js"' in response.text
    assert '<div id="root">' in response.text
    assert bundle.status_code == 200
    assert "web.idor" in bundle.text
    assert "source.audit.python" in bundle.text
    assert "最近任务" in bundle.text
    assert "重新开始" in bundle.text
    assert '"/api/v1/runs?limit=20"' in bundle.text


def test_workbench_static_assets_load_under_the_local_session_boundary() -> None:
    browser = _browser()
    with browser:
        _exchange(browser)
        stylesheet = browser.get("/static/workbench.css")
        script = browser.get("/static/workbench.js")

    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]
    assert script.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in script.headers["content-security-policy"]
    assert "innerHTML" not in script.text
    assert "document.write" not in script.text
    assert "eval(" not in script.text
    assert "localStorage" not in script.text
    assert "sessionStorage" not in script.text


def test_workbench_marks_missing_runtime_sources_instead_of_showing_mock_data() -> None:
    browser = _browser()
    with browser:
        _exchange(browser)
        page = browser.get("/")
        sources = browser.get("/api/v1/runtime-data-sources")

    assert page.status_code == 200
    assert '<div id="root">' in page.text
    assert sources.status_code == 200
    assert sources.json()["runs"] == "unavailable"


def test_workbench_lists_recent_runs_inside_the_local_session() -> None:
    browser = _browser(run_manager=RecordingRunManager())
    with browser:
        _exchange(browser)
        response = browser.get("/api/v1/runs?limit=20")

    assert response.status_code == 200
    assert response.json()["items"] == [
        {
            "run_id": str(RUN_ID),
            "task_pack": "web.idor",
            "status": "completed",
            "request_preview": "Assess the authorized order API.",
            "request_text": "Assess the authorized order API.",
            "created_at": "2026-08-25T10:00:00Z",
            "updated_at": "2026-08-25T10:01:00Z",
            "error_code": None,
            "schema_version": "1.0",
        }
    ]


def test_workbench_run_submission_reports_specific_executor_reason() -> None:
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
        model_capability_ready=True,
        detail="依赖工具未就绪：web.http_request",
    )
    runtime_readiness = RuntimeReadinessService(
        model_probe=lambda: ModelRuntimeReadiness(
            ready=True,
            state=ReadinessState.READY,
            reason_codes=(),
            capability_probe_ref="11111111-1111-4111-8111-111111111111",
        ),
        core_probe=lambda: ReadinessState.READY,
        taskpack_ids=("web.idor", "source.audit.python"),
        taskpack_probe=lambda task_pack_id: (
            ReadinessState.EXECUTOR_NOT_READY
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
    )
    app = create_workbench_app(
        launch_token=LAUNCH_TOKEN,
        origin=ORIGIN,
        run_manager=RecordingRunManager(),
        runtime_readiness=runtime_readiness,
    )
    with TestClient(app, base_url=ORIGIN) as browser:
        csrf = _exchange(browser)
        response = browser.post(
            "/api/v1/runs",
            headers={
                "Origin": ORIGIN,
                "X-CSRF-Token": csrf,
                "Content-Type": "application/json",
            },
            json={
                "task_pack_id": "web.idor",
                "request_text": "Assess the authorized order API for cross-tenant access.",
                "artifact_id": None,
                "scenario_input": {},
            },
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "EXECUTOR_NOT_READY"
    assert "依赖工具未就绪" in response.json()["error"]["message"]


def test_workbench_run_request_uses_only_the_public_application_contract() -> None:
    manager = RecordingRunManager()
    browser = _browser(run_manager=manager)
    payload = {
        "task_pack_id": "web.idor",
        "request_text": "Assess the authorized order API for cross-tenant access.",
        "artifact_id": None,
        "scenario_input": {
            "target_url": "http://127.0.0.1:8080/api/orders",
            "bindings": [
                {
                    "ordinal": 1,
                    "observation_type": "authorized_baseline",
                    "actor_id": "alice",
                    "expected_object_id": "1001",
                },
                {
                    "ordinal": 2,
                    "observation_type": "cross_tenant_probe",
                    "actor_id": "alice",
                    "expected_object_id": "2002",
                },
            ],
        },
    }
    with browser:
        csrf = _exchange(browser)
        script = browser.get("/static/workbench.js")
        response = browser.post(
            "/api/v1/runs",
            headers={
                "Origin": ORIGIN,
                "X-CSRF-Token": csrf,
                "Content-Type": "application/json",
            },
            json=payload,
        )

    assert response.status_code == 202
    assert response.json()["run_id"] == str(RUN_ID)
    assert response.json()["status"] == "queued"
    assert len(manager.requests) == 1
    assert manager.requests[0].model_dump(
        mode="json",
        exclude={"schema_version"},
    ) == payload
    assert manager.executed == [RUN_ID]
    assert 'requestJson("/api/v1/artifacts"' in script.text
    assert 'requestJson("/api/v1/runs"' in script.text
    assert "task_pack_id: taskPackId" in script.text
    assert "request_text: requestText.value.trim()" in script.text
    assert "artifact_id: artifactId" in script.text
    assert "scenario_input: scenarioInput" in script.text
    assert "executor:" not in script.text
    assert "verifier:" not in script.text
    assert "docker:" not in script.text
