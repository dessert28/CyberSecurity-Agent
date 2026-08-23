from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from cyber_agent.model_gateway.io_trace import (
    ModelIoOperation,
    ModelIoStage,
    ModelIoStatus,
    ModelIoTraceStore,
)


def test_trace_store_groups_attempts_and_returns_deep_copies() -> None:
    store = ModelIoTraceStore(capacity=2)
    request_body = {"messages": [{"role": "user", "content": "原始输入"}]}
    trace_id = store.begin(
        provider="deepseek",
        model="deepseek-v4-pro-0813",
        operation=ModelIoOperation.GENERATE_STRUCTURED,
        purpose="task_understanding",
    )

    attempt_no = store.append_attempt(
        trace_id,
        stage=ModelIoStage.INITIAL,
        retry_index=0,
        request_body=request_body,
        response_body='{"choices":[]}',
        http_status=200,
        latency_ms=23,
    )
    request_body["messages"][0]["content"] = "changed after append"
    store.set_validation(trace_id, attempt_no, schema_valid=False, error="missing ok")
    store.finish(trace_id, status=ModelIoStatus.FAILED, error_code="MODEL_SCHEMA_INVALID")

    detail = store.get(trace_id)
    assert detail.status is ModelIoStatus.FAILED
    assert detail.error_code == "MODEL_SCHEMA_INVALID"
    assert detail.attempts[0].request_body["messages"][0]["content"] == "原始输入"
    assert detail.attempts[0].schema_valid is False
    assert detail.attempts[0].error == "missing ok"
    assert store.snapshot()[0].attempt_count == 1

    detail.attempts[0].request_body["messages"][0]["content"] = "mutated snapshot"
    assert store.get(trace_id).attempts[0].request_body["messages"][0]["content"] == "原始输入"


def test_trace_store_evicts_oldest_logical_call_and_clears() -> None:
    store = ModelIoTraceStore(capacity=2)
    first = store.begin(provider="kimi", model="m1", operation=ModelIoOperation.PROBE_REPLY)
    second = store.begin(provider="kimi", model="m2", operation=ModelIoOperation.PROBE_REPLY)
    third = store.begin(provider="kimi", model="m3", operation=ModelIoOperation.PROBE_REPLY)

    assert [item.trace_id for item in store.snapshot()] == [third, second]
    with pytest.raises(KeyError):
        store.get(first)

    assert store.clear() == 2
    assert store.snapshot() == ()


def test_trace_store_accepts_concurrent_writers() -> None:
    store = ModelIoTraceStore(capacity=100)

    def record(index: int) -> None:
        trace_id = store.begin(
            provider="deepseek",
            model=f"model-{index}",
            operation=ModelIoOperation.PROBE_REPLY,
        )
        store.append_attempt(
            trace_id,
            stage=ModelIoStage.INITIAL,
            retry_index=0,
            request_body={"index": index},
            response_body=str(index),
            http_status=200,
            latency_ms=index,
        )
        store.finish(trace_id, status=ModelIoStatus.SUCCEEDED)

    with ThreadPoolExecutor(max_workers=8) as executor:
        tuple(executor.map(record, range(40)))

    traces = store.snapshot()
    assert len(traces) == 40
    assert {item.model for item in traces} == {f"model-{index}" for index in range(40)}
    assert all(item.status is ModelIoStatus.SUCCEEDED for item in traces)
