from __future__ import annotations

import importlib

import pytest

from cyber_agent.tools.catalog import (
    build_competition_tool_registry,
    competition_tool_catalog,
    expected_competition_tool_ids,
)


def test_expected_catalog_contains_competition_required_tools() -> None:
    expected = expected_competition_tool_ids()

    assert "web.http_request" in expected
    assert "source.project_inventory" in expected
    assert "source.python_dataflow" in expected
    assert "source.hypothesis_validate" in expected
    assert "pwn.binary_properties" in expected
    assert "pwn.process_interaction" in expected
    assert "reverse.static_extract" in expected
    assert "reverse.run_verify" in expected
    assert "incident.log_inventory" in expected
    assert "incident.log_search" in expected
    assert len(expected) == len(set(expected))


@pytest.mark.asyncio
async def test_build_registers_every_expected_tool() -> None:
    registry, failed = await build_competition_tool_registry(
        runtime_available=lambda: False,
    )

    assert failed == ()
    assert len(registry.all_statuses()) == len(expected_competition_tool_ids())
    registered = {item.tool_ref.tool_id for item in registry.all_statuses()}
    assert registered == set(expected_competition_tool_ids())


@pytest.mark.asyncio
async def test_web_tools_reflect_docker_probe_without_polluting_source_tools() -> None:
    registry, failed = await build_competition_tool_registry(
        runtime_available=lambda: True,
        docker_probe=lambda: (False, "Docker CLI was not found."),
    )

    assert failed == ()
    web = registry.status("web.http_request")
    assert web.state.value == "unhealthy"
    assert "Docker CLI was not found" in web.message

    source = registry.status("source.project_inventory")
    assert source.state.value == "healthy"
    assert "source-analysis runtime available" in source.message


@pytest.mark.asyncio
async def test_health_check_exception_is_captured_for_diagnostics() -> None:
    def broken_probe():
        raise RuntimeError("private probe exploded")

    registry, _ = await build_competition_tool_registry(
        runtime_available=broken_probe,
        docker_probe=broken_probe,
    )

    status = registry.status("web.http_request")
    assert status.state.value == "unhealthy"
    assert status.last_health_exception
    assert "Traceback" in status.last_health_exception
    assert "private probe exploded" in status.last_health_exception


@pytest.mark.asyncio
async def test_import_failure_is_logged_and_reported_not_silently_skipped(
    monkeypatch,
    caplog,
) -> None:
    original = importlib.import_module

    def failing_import(name, *args, **kwargs):
        if name == "cyber_agent.tools.web":
            raise ImportError("simulated web module import failure")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(
        "cyber_agent.tools.catalog.importlib.import_module",
        failing_import,
    )
    with caplog.at_level("ERROR", logger="cyber_agent.tools.catalog"):
        registry, failed = await build_competition_tool_registry(
            runtime_available=lambda: False,
        )

    assert "web.http_request" in failed
    assert "web.endpoint_discovery" in failed
    assert "web.openapi_analyze" in failed
    assert "source.project_inventory" not in failed
    assert registry.all_statuses()
    messages = "\n".join(record.message for record in caplog.records)
    assert "tool registration failed" in messages
    assert "cyber_agent.tools.web" in messages
    assert "web.http_request" in messages
    assert any(record.exc_info for record in caplog.records)


def test_catalog_entries_reference_existing_plugin_classes() -> None:
    for entry in competition_tool_catalog():
        module = importlib.import_module(entry.module_path)
        assert hasattr(module, entry.plugin_class)
