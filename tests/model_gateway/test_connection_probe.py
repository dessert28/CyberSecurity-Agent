from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

import httpx
import pytest

from cyber_agent.contracts.errors import CyberAgentError
from cyber_agent.model_gateway.kimi import KimiK3Adapter, KimiK3Config
from cyber_agent.model_gateway.openai_compatible import (
    OpenAICompatibleAdapter,
    OpenAICompatibleConfig,
)


AdapterFactory = Callable[[httpx.AsyncClient], object]


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _openai_adapter(client: httpx.AsyncClient) -> OpenAICompatibleAdapter:
    return OpenAICompatibleAdapter(
        OpenAICompatibleConfig(
            provider="openai_compatible",
            base_url="https://model.example.test/v1",
            model="test-model",
            api_key_env="TEST_MODEL_KEY",
            max_retries=0,
        ),
        client=client,
        environment={"TEST_MODEL_KEY": "test-key"},
    )


def _kimi_adapter(client: httpx.AsyncClient) -> KimiK3Adapter:
    return KimiK3Adapter(
        KimiK3Config(
            base_url="https://model.example.test/v1",
            model="test-model",
            api_key_env="TEST_MODEL_KEY",
            max_retries=0,
        ),
        client=client,
        environment={"TEST_MODEL_KEY": "test-key"},
    )


@pytest.mark.parametrize("adapter_factory", [_openai_adapter, _kimi_adapter])
def test_connection_probe_accepts_a_non_json_nonempty_reply(
    adapter_factory: AdapterFactory,
) -> None:
    received_payloads: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received_payloads.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "reply-1",
                "model": "test-model",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": "服务已连接。"},
                    }
                ],
            },
        )

    client = _client(handler)
    adapter = adapter_factory(client)
    try:
        assert asyncio.run(adapter.probe_reply()) is True  # type: ignore[attr-defined]
    finally:
        asyncio.run(client.aclose())

    assert len(received_payloads) == 1
    assert "response_format" not in received_payloads[0]


@pytest.mark.parametrize("adapter_factory", [_openai_adapter, _kimi_adapter])
def test_connection_probe_accepts_text_content_parts(
    adapter_factory: AdapterFactory,
) -> None:
    client = _client(
        lambda _: httpx.Response(
            200,
            json={
                "id": "reply-1",
                "model": "test-model",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": [{"type": "text", "text": "connected"}]},
                    }
                ],
            },
        )
    )
    adapter = adapter_factory(client)
    try:
        assert asyncio.run(adapter.probe_reply()) is True  # type: ignore[attr-defined]
    finally:
        asyncio.run(client.aclose())


@pytest.mark.parametrize("adapter_factory", [_openai_adapter, _kimi_adapter])
@pytest.mark.parametrize("content", ["", "   ", None])
def test_connection_probe_rejects_blank_or_missing_final_content(
    adapter_factory: AdapterFactory,
    content: str | None,
) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "reply-1",
                "model": "test-model",
                "choices": [{"finish_reason": "stop", "message": {"content": content}}],
            },
        )

    client = _client(handler)
    adapter = adapter_factory(client)
    try:
        assert asyncio.run(adapter.probe_reply()) is False  # type: ignore[attr-defined]
    finally:
        asyncio.run(client.aclose())


@pytest.mark.parametrize("adapter_factory", [_openai_adapter, _kimi_adapter])
@pytest.mark.parametrize(
    "failure",
    [
        lambda request: httpx.Response(401, request=request, json={"error": {}}),
        lambda request: (_ for _ in ()).throw(httpx.ConnectError("offline", request=request)),
        lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=request)),
    ],
)
def test_connection_probe_propagates_provider_failures(
    adapter_factory: AdapterFactory,
    failure: Callable[[httpx.Request], httpx.Response],
) -> None:
    client = _client(failure)
    adapter = adapter_factory(client)
    try:
        with pytest.raises(CyberAgentError):
            asyncio.run(adapter.probe_reply())  # type: ignore[attr-defined]
    finally:
        asyncio.run(client.aclose())
