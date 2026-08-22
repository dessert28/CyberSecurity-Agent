from __future__ import annotations

import re
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

from cyber_agent.api.workbench import create_workbench_app
from cyber_agent.application.admin_console import AdminConsoleService
from cyber_agent.workbench.capabilities import ModelCapabilityService
from cyber_agent.contracts.model import ModelResponse, ModelUsage
from cyber_agent.workbench.credentials import MemoryCredentialStore
from cyber_agent.workbench.profiles import ModelProfileStore
from cyber_agent.workbench.schemas import (
    ModelCheckStatus,
    ModelProfileCreateRequest,
    ProviderType,
    ReadinessState,
    WorkbenchMode,
)
from cyber_agent.workbench.store import WorkbenchStore


ORIGIN = "http://127.0.0.1:49888"
TOKEN = "admin-connection-probe-token-000000000000000000"


class ReplyOnlyAdapter:
    async def probe_reply(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None


class StructuredReplyAdapter(ReplyOnlyAdapter):
    async def generate_structured(self, request) -> ModelResponse:
        return ModelResponse(
            response_id=UUID("11111111-1111-4111-8111-111111111111"),
            request_id=request.request_id,
            provider="openai_compatible",
            model="deepseek-v4-pro-0813",
            data={"ok": True},
            usage=ModelUsage(input_tokens=1, output_tokens=1),
            latency_ms=1,
            finish_reason="stop",
            provider_request_id="reply-1",
            raw_response_hash="0" * 64,
            schema_valid=True,
        )


class ReplyOnlyAdapterFactory:
    def create(self, _profile):
        return ReplyOnlyAdapter()

    def capability_probe_fingerprint(self, _profile, *, observed_at):
        raise AssertionError(f"basic connection testing must not request a capability fingerprint: {observed_at}")


class StructuredReplyAdapterFactory(ReplyOnlyAdapterFactory):
    def create(self, _profile):
        return StructuredReplyAdapter()

    def capability_probe_fingerprint(self, _profile, *, observed_at):
        assert observed_at.tzinfo is not None
        return "a" * 64


def _headers(csrf: str) -> dict[str, str]:
    return {
        "Origin": ORIGIN,
        "X-CSRF-Token": csrf,
        "Content-Type": "application/json",
    }


def _exchange(browser: TestClient) -> str:
    response = browser.get(
        f"/session/exchange?token={TOKEN}&destination=admin",
        follow_redirects=False,
    )
    assert response.status_code == 303
    page = browser.get("/admin")
    match = re.search(r'<meta name="csrf-token" content="([^"]+)">', page.text)
    assert match is not None
    return match.group(1)


def test_basic_connection_probe_does_not_activate_or_unlock_the_model(
    tmp_path: Path,
) -> None:
    credentials = MemoryCredentialStore()
    profiles = ModelProfileStore(
        database=WorkbenchStore(
            database_path=tmp_path / "state.db",
            runtime_root=tmp_path,
        ),
        mode=WorkbenchMode.DEVELOPMENT,
        credentials=credentials,
    )
    profile = profiles.create(
        ModelProfileCreateRequest(
            display_name="DashScope DeepSeek",
            provider=ProviderType.DOMESTIC_COMPATIBLE,
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            model_id="deepseek-v4-pro-0813",
        )
    )
    profiles.put_credential(profile.profile_id, "connection-test-key")
    capabilities = ModelCapabilityService(
        profiles=profiles,
        adapter_factory=ReplyOnlyAdapterFactory(),
        docker_probe=lambda: (False, "not needed"),
    )
    app = create_workbench_app(
        launch_token=TOKEN,
        origin=ORIGIN,
        profiles=profiles,
        capabilities=capabilities,
        admin_console=AdminConsoleService(profiles=profiles, capabilities=capabilities),
    )

    with TestClient(app, base_url=ORIGIN) as browser:
        csrf = _exchange(browser)
        response = browser.post(
            "/api/v1/admin/connection-test",
            headers=_headers(csrf),
            json={},
        )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "success": True,
        "code": "MODEL_CONNECTION_PASSED",
        "message": "The model returned a non-empty connection probe reply.",
        "api_accessible": True,
        "structured_output_detected": False,
        "latency_ms": response.json()["latency_ms"],
        "model": "deepseek-v4-pro-0813",
        "model_name": "deepseek-v4-pro-0813",
        "active": False,
    }
    view = profiles.list_views()[0]
    assert view.check_status is ModelCheckStatus.UNCHECKED
    assert view.active is False
    assert capabilities.runtime_readiness().state is ReadinessState.MODEL_NOT_READY


def test_strict_capability_probe_activates_only_a_schema_compliant_model(
    tmp_path: Path,
) -> None:
    credentials = MemoryCredentialStore()
    profiles = ModelProfileStore(
        database=WorkbenchStore(
            database_path=tmp_path / "state.db",
            runtime_root=tmp_path,
        ),
        mode=WorkbenchMode.DEVELOPMENT,
        credentials=credentials,
    )
    profile = profiles.create(
        ModelProfileCreateRequest(
            display_name="Structured model",
            provider=ProviderType.DOMESTIC_COMPATIBLE,
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            model_id="deepseek-v4-pro-0813",
        )
    )
    profiles.put_credential(profile.profile_id, "connection-test-key")
    capabilities = ModelCapabilityService(
        profiles=profiles,
        adapter_factory=StructuredReplyAdapterFactory(),
        docker_probe=lambda: (False, "not needed"),
    )
    app = create_workbench_app(
        launch_token=TOKEN,
        origin=ORIGIN,
        profiles=profiles,
        capabilities=capabilities,
        admin_console=AdminConsoleService(profiles=profiles, capabilities=capabilities),
    )

    with TestClient(app, base_url=ORIGIN) as browser:
        csrf = _exchange(browser)
        response = browser.post(
            "/api/v1/admin/capability-test",
            headers=_headers(csrf),
            json={},
        )

    assert response.status_code == 200
    assert response.json()["code"] == "MODEL_CHECK_PASSED"
    assert response.json()["structured_output_detected"] is True
    assert response.json()["active"] is True
    assert profiles.list_views()[0].check_status is ModelCheckStatus.PASSED
    assert profiles.list_views()[0].active is True


def test_admin_assets_offer_separate_connection_and_capability_actions() -> None:
    app = create_workbench_app(launch_token=TOKEN, origin=ORIGIN)

    with TestClient(app, base_url=ORIGIN) as browser:
        _exchange(browser)
        page = browser.get("/admin")
        script = browser.get("/static/admin.js")

    assert 'id="test-button"' in page.text
    assert 'id="capability-test-button"' in page.text
    assert '"/api/v1/admin/connection-test"' in script.text
    assert '"/api/v1/admin/capability-test"' in script.text
    assert "连接成功；该模型尚未通过结构化能力验证，不能用于正式任务。" in script.text
