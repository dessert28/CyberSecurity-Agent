from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

import httpx
import pytest

from cyber_agent.contracts.errors import CyberAgentError
from cyber_agent.contracts.model import ModelPurpose, ModelRequest, ReasoningEffort
from cyber_agent.model_gateway.io_trace import ModelIoStage, ModelIoStatus, ModelIoTraceStore
from cyber_agent.model_gateway.kimi import KimiK3Adapter, KimiK3Config
from cyber_agent.model_gateway.openai_compatible import (
    OpenAICompatibleAdapter,
    OpenAICompatibleConfig,
)


def _request() -> ModelRequest:
    return ModelRequest(
        purpose=ModelPurpose.TASK_UNDERSTANDING,
        system_instructions="只返回符合结构的 JSON。",
        context={"probe": "完整输入"},
        output_schema={
            "type": "object",
            "properties": {"ok": {"type": "boolean", "const": True}},
            "required": ["ok"],
            "additionalProperties": False,
        },
        reasoning_effort=ReasoningEffort.LOW,
        max_output_tokens=64,
        timeout_seconds=30,
    )


def _reply(content: str, *, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json={
            "id": "reply-1",
            "model": "trace-model",
            "choices": [{"finish_reason": "stop", "message": {"content": content}}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        },
    )


def _reply_with_content(content: object, *, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json={
            "id": "reply-1",
            "model": "trace-model",
            "choices": [{"finish_reason": "stop", "message": {"content": content}}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        },
    )


def _factories(store: ModelIoTraceStore, handler: Callable[[httpx.Request], httpx.Response]):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return (
        OpenAICompatibleAdapter(
            OpenAICompatibleConfig(
                provider="openai_compatible",
                base_url="https://model.example.test/v1",
                model="trace-model",
                api_key_env="TEST_KEY",
                max_retries=0,
            ),
            client=client,
            environment={"TEST_KEY": "secret"},
            trace_store=store,
        ),
        KimiK3Adapter(
            KimiK3Config(
                base_url="https://model.example.test/v1",
                model="trace-model",
                api_key_env="TEST_KEY",
                max_retries=0,
            ),
            client=client,
            environment={"TEST_KEY": "secret"},
            trace_store=store,
        ),
        client,
    )


@pytest.mark.parametrize("adapter_index", [0, 1])
def test_adapter_groups_invalid_initial_and_successful_repair(adapter_index: int) -> None:
    store = ModelIoTraceStore()
    replies = iter((_reply('{"ok":false}'), _reply('{"ok":true}')))
    adapters = _factories(store, lambda _: next(replies))
    adapter, client = adapters[adapter_index], adapters[2]
    try:
        response = asyncio.run(adapter.generate_structured(_request()))
    finally:
        asyncio.run(client.aclose())

    assert response.data == {"ok": True}
    trace = store.get(store.snapshot()[0].trace_id)
    assert trace.status is ModelIoStatus.SUCCEEDED
    assert [attempt.stage for attempt in trace.attempts] == [
        ModelIoStage.INITIAL,
        ModelIoStage.REPAIR,
    ]
    assert [attempt.schema_valid for attempt in trace.attempts] == [False, True]
    assert trace.attempts[0].request_body["messages"][1]["content"] == '{"probe":"完整输入"}'
    assert json.loads(trace.attempts[0].response_body)["choices"][0]["message"]["content"] == '{"ok":false}'
    assert trace.attempts[1].request_body["messages"][-1]["content"].startswith("Repair")


@pytest.mark.parametrize("adapter_index", [0, 1])
def test_adapter_marks_trace_failed_when_repair_is_still_invalid(adapter_index: int) -> None:
    store = ModelIoTraceStore()
    adapters = _factories(store, lambda _: _reply('{"ok":false}'))
    adapter, client = adapters[adapter_index], adapters[2]
    try:
        with pytest.raises(CyberAgentError) as captured:
            asyncio.run(adapter.generate_structured(_request()))
    finally:
        asyncio.run(client.aclose())

    assert captured.value.error.code == "MODEL_SCHEMA_INVALID"
    trace = store.get(store.snapshot()[0].trace_id)
    assert trace.status is ModelIoStatus.FAILED
    assert trace.error_code == "MODEL_SCHEMA_INVALID"
    assert len(trace.attempts) == 2
    assert all(attempt.schema_valid is False for attempt in trace.attempts)


@pytest.mark.parametrize("adapter_index", [0, 1])
def test_adapter_accepts_single_json_code_fence_without_changing_raw_trace(
    adapter_index: int,
) -> None:
    store = ModelIoTraceStore()
    adapters = _factories(store, lambda _: _reply("```json\n{\"ok\":true}\n```"))
    adapter, client = adapters[adapter_index], adapters[2]
    try:
        response = asyncio.run(adapter.generate_structured(_request()))
    finally:
        asyncio.run(client.aclose())

    assert response.data == {"ok": True}
    trace = store.get(store.snapshot()[0].trace_id)
    assert json.loads(trace.attempts[0].response_body)["choices"][0]["message"]["content"] == (
        "```json\n{\"ok\":true}\n```"
    )
    assert trace.attempts[0].schema_valid is True
    assert len(trace.attempts) == 1


@pytest.mark.parametrize("adapter_index", [0, 1])
def test_adapter_accepts_text_content_parts(adapter_index: int) -> None:
    store = ModelIoTraceStore()
    content = [{"type": "text", "text": '{"ok":true}'}]
    adapters = _factories(store, lambda _: _reply_with_content(content))
    adapter, client = adapters[adapter_index], adapters[2]
    try:
        response = asyncio.run(adapter.generate_structured(_request()))
    finally:
        asyncio.run(client.aclose())

    assert response.data == {"ok": True}
    trace = store.get(store.snapshot()[0].trace_id)
    assert trace.attempts[0].schema_valid is True
    assert len(trace.attempts) == 1


def test_openai_adapter_records_http_retry_and_connection_probe() -> None:
    store = ModelIoTraceStore()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, json={"error": {"message": "slow down"}})
        return _reply("connected")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = OpenAICompatibleAdapter(
        OpenAICompatibleConfig(
            provider="openai_compatible",
            base_url="https://model.example.test/v1",
            model="trace-model",
            api_key_env="TEST_KEY",
            max_retries=1,
            initial_backoff_seconds=0,
        ),
        client=client,
        environment={"TEST_KEY": "secret"},
        trace_store=store,
    )
    try:
        assert asyncio.run(adapter.probe_reply()) is True
    finally:
        asyncio.run(client.aclose())

    trace = store.get(store.snapshot()[0].trace_id)
    assert trace.status is ModelIoStatus.SUCCEEDED
    assert [attempt.stage for attempt in trace.attempts] == [
        ModelIoStage.INITIAL,
        ModelIoStage.RETRY,
    ]
    assert [attempt.http_status for attempt in trace.attempts] == [429, 200]
    assert json.loads(trace.attempts[0].response_body)["error"]["message"] == "slow down"


@pytest.mark.parametrize(
    ("base_url", "expected_field"),
    [
        ("https://dashscope.aliyuncs.com/compatible-mode/v1", "extra_body"),
        ("https://api.deepseek.com/v1", "thinking"),
    ],
)
def test_openai_probe_disables_reasoning_for_short_final_reply(
    base_url: str,
    expected_field: str,
) -> None:
    received_payloads: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received_payloads.append(json.loads(request.content))
        return _reply("connected")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = OpenAICompatibleAdapter(
        OpenAICompatibleConfig(
            provider="openai_compatible",
            base_url=base_url,
            model="deepseek-v4-pro-0813",
            api_key_env="TEST_KEY",
            max_retries=0,
        ),
        client=client,
        environment={"TEST_KEY": "secret"},
    )
    try:
        assert asyncio.run(adapter.probe_reply()) is True
    finally:
        asyncio.run(client.aclose())

    assert len(received_payloads) == 1
    if expected_field == "extra_body":
        assert received_payloads[0]["enable_thinking"] is False
    else:
        assert received_payloads[0]["extra_body"] == {"thinking": {"type": "disabled"}}


def test_openai_adapter_records_non_json_protocol_response() -> None:
    store = ModelIoTraceStore()
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"provider returned plain text")
        )
    )
    adapter = OpenAICompatibleAdapter(
        OpenAICompatibleConfig(
            provider="openai_compatible",
            base_url="https://model.example.test/v1",
            model="trace-model",
            api_key_env="TEST_KEY",
            max_retries=0,
        ),
        client=client,
        environment={"TEST_KEY": "secret"},
        trace_store=store,
    )
    try:
        with pytest.raises(CyberAgentError) as captured:
            asyncio.run(adapter.probe_reply())
    finally:
        asyncio.run(client.aclose())

    assert captured.value.error.code == "MODEL_PROTOCOL_ERROR"
    trace = store.get(store.snapshot()[0].trace_id)
    assert trace.status is ModelIoStatus.FAILED
    assert trace.attempts[0].response_body == "provider returned plain text"
    assert trace.attempts[0].schema_valid is False


@pytest.mark.parametrize("adapter_index", [0, 1])
def test_adapter_records_transport_timeout_without_a_response(adapter_index: int) -> None:
    store = ModelIoTraceStore()

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("provider timeout", request=request)

    adapters = _factories(store, timeout)
    adapter, client = adapters[adapter_index], adapters[2]
    try:
        with pytest.raises(CyberAgentError) as captured:
            asyncio.run(adapter.probe_reply())
    finally:
        asyncio.run(client.aclose())

    assert captured.value.error.code == "MODEL_TIMEOUT"
    trace = store.get(store.snapshot()[0].trace_id)
    assert trace.status is ModelIoStatus.FAILED
    assert trace.error_code == "MODEL_TIMEOUT"
    assert trace.attempts[0].response_body is None
    assert trace.attempts[0].error == "MODEL_TIMEOUT"


@pytest.mark.parametrize("adapter_index", [0, 1])
def test_connection_probe_marks_empty_reply_as_failed(adapter_index: int) -> None:
    store = ModelIoTraceStore()
    adapters = _factories(store, lambda _: _reply("   "))
    adapter, client = adapters[adapter_index], adapters[2]
    try:
        assert asyncio.run(adapter.probe_reply()) is False
    finally:
        asyncio.run(client.aclose())

    trace = store.get(store.snapshot()[0].trace_id)
    assert trace.status is ModelIoStatus.FAILED
    assert trace.error_code == "MODEL_REPLY_EMPTY"
