from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from cyber_agent.api.workbench import create_workbench_app
from cyber_agent.application.runtime_readiness import RuntimeReadinessService
from cyber_agent.workbench.schemas import ModelRuntimeReadiness, ReadinessState


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
