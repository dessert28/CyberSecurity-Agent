from __future__ import annotations

import re
from uuid import UUID

from fastapi.testclient import TestClient

from cyber_agent.api.workbench import create_workbench_app
from cyber_agent.application.run_management import (
    RunAcceptedResponse,
    RunCreateRequest,
)
from cyber_agent.application.runtime_readiness import RuntimeReadinessService
from cyber_agent.contracts.plan import RunStatus
from cyber_agent.workbench.schemas import ModelRuntimeReadiness, ReadinessState


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

    assert response.status_code == 200
    assert "网络安全智能体工作台" in response.text
    assert 'value="web.idor"' in response.text
    assert 'value="source.audit.python"' in response.text
    assert 'href="/static/workbench.css"' in response.text
    assert 'src="/static/workbench.js"' in response.text
    assert "<script>" not in response.text


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
    assert "任务运行数据源尚未启用" in page.text
    assert sources.status_code == 200
    assert sources.json()["runs"] == "unavailable"


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
