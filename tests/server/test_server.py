from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

import cyber_agent.server as local_server
from cyber_agent.workbench.credentials import MemoryCredentialStore


PORT = 49853
TOKEN_ONE = "server-launch-token-one-00000000000000000000"
TOKEN_TWO = "server-launch-token-two-00000000000000000000"


def _exchange(browser: TestClient, token: str) -> str:
    response = browser.get(
        f"/session/exchange?token={token}&destination=admin",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    page = browser.get("/admin")
    match = re.search(r'<meta name="csrf-token" content="([^"]+)">', page.text)
    assert match is not None
    return match.group(1)


def _headers(csrf: str) -> dict[str, str]:
    return {
        "Origin": f"http://127.0.0.1:{PORT}",
        "X-CSRF-Token": csrf,
        "Content-Type": "application/json",
    }


def test_real_server_assembly_registers_admin_page_assets_and_routes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(local_server, "probe_docker", lambda: (True, "Docker test runtime"))
    bundle = local_server.build_local_server(
        port=PORT,
        runtime_root=tmp_path,
        credential_store=MemoryCredentialStore(),
        launch_token=TOKEN_ONE,
    )

    with TestClient(bundle.app, base_url=bundle.origin) as browser:
        _exchange(browser, TOKEN_ONE)
        page = browser.get("/admin")
        providers = browser.get("/api/v1/admin/providers")
        script = browser.get("/static/admin.js")
        stylesheet = browser.get("/static/admin.css")

    assert page.status_code == 200
    assert providers.status_code == 200
    assert script.status_code == 200
    assert stylesheet.status_code == 200
    assert bundle.page_url == f"http://127.0.0.1:{PORT}/admin"


def test_model_metadata_and_server_side_credential_survive_reassembly(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(local_server, "probe_docker", lambda: (True, "Docker test runtime"))
    credentials = MemoryCredentialStore()
    first = local_server.build_local_server(
        port=PORT,
        runtime_root=tmp_path,
        credential_store=credentials,
        launch_token=TOKEN_ONE,
    )
    secret = "persistent-server-side-secret"
    with TestClient(first.app, base_url=first.origin) as browser:
        csrf = _exchange(browser, TOKEN_ONE)
        saved = browser.post(
            "/api/v1/admin/configuration",
            headers=_headers(csrf),
            json={
                "provider": "qwen",
                "model_name": "qwen-plus",
                "api_base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                "api_key": secret,
            },
        )
        assert saved.status_code == 200

    second = local_server.build_local_server(
        port=PORT,
        runtime_root=tmp_path,
        credential_store=credentials,
        launch_token=TOKEN_TWO,
    )
    with TestClient(second.app, base_url=second.origin) as browser:
        _exchange(browser, TOKEN_TWO)
        restored = browser.get("/api/v1/admin/configuration")

    assert restored.status_code == 200
    assert restored.json()["provider"] == "qwen"
    assert restored.json()["model_name"] == "qwen-plus"
    assert restored.json()["credential_configured"] is True
    assert secret not in restored.text
    assert secret.encode() not in (tmp_path / "state.db").read_bytes()


def test_server_reports_injected_workbench_sources_without_mock_data(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(local_server, "probe_docker", lambda: (False, "Docker unavailable"))
    bundle = local_server.build_local_server(
        port=PORT,
        runtime_root=tmp_path,
        credential_store=MemoryCredentialStore(),
        launch_token=TOKEN_ONE,
    )
    with TestClient(bundle.app, base_url=bundle.origin) as browser:
        _exchange(browser, TOKEN_ONE)
        sources = browser.get("/api/v1/runtime-data-sources")

    assert sources.status_code == 200
    assert sources.json() == {
        "admin": "live",
        "model_configuration": "live",
        "artifact_upload": "live",
        "runs": "unavailable",
        "projection": "live",
        "evidence": "live",
        "audit": "live",
        "report": "unavailable",
    }
