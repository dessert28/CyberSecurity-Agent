"""Explicit competition tool catalog with diagnostics for registration failures."""

from __future__ import annotations

import importlib
import logging
from collections.abc import Callable
from dataclasses import dataclass

from cyber_agent.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ToolCatalogEntry:
    tool_id: str
    module_path: str
    plugin_class: str
    uses_docker: bool = False


def competition_tool_catalog() -> tuple[ToolCatalogEntry, ...]:
    """All built-in tools the local runtime expects to register."""

    return (
        ToolCatalogEntry(
            "web.http_request",
            "cyber_agent.tools.web",
            "HttpRequestPlugin",
            uses_docker=True,
        ),
        ToolCatalogEntry(
            "web.endpoint_discovery",
            "cyber_agent.tools.web",
            "EndpointDiscoveryPlugin",
            uses_docker=True,
        ),
        ToolCatalogEntry(
            "web.openapi_analyze",
            "cyber_agent.tools.web",
            "OpenApiAnalyzePlugin",
            uses_docker=True,
        ),
        ToolCatalogEntry(
            "source.project_inventory",
            "cyber_agent.tools.project_inventory",
            "ProjectInventoryPlugin",
        ),
        ToolCatalogEntry(
            "source.python_dataflow",
            "cyber_agent.tools.python_dataflow",
            "PythonDataflowPlugin",
        ),
        ToolCatalogEntry(
            "source.hypothesis_validate",
            "cyber_agent.tools.hypothesis_validate",
            "HypothesisValidatePlugin",
        ),
        ToolCatalogEntry(
            "pwn.binary_properties",
            "cyber_agent.tools.pwn_binary",
            "BinaryPropertiesPlugin",
        ),
        ToolCatalogEntry(
            "pwn.process_interaction",
            "cyber_agent.tools.pwn_interaction",
            "ProcessInteractionPlugin",
        ),
        ToolCatalogEntry(
            "reverse.static_extract",
            "cyber_agent.tools.reverse_static",
            "ReverseStaticPlugin",
        ),
        ToolCatalogEntry(
            "reverse.run_verify",
            "cyber_agent.tools.reverse_run",
            "ReverseRunPlugin",
        ),
        ToolCatalogEntry(
            "incident.log_inventory",
            "cyber_agent.tools.incident_log",
            "IncidentLogInventoryPlugin",
        ),
        ToolCatalogEntry(
            "incident.log_search",
            "cyber_agent.tools.incident_log",
            "IncidentLogSearchPlugin",
        ),
    )


def expected_competition_tool_ids() -> tuple[str, ...]:
    return tuple(entry.tool_id for entry in competition_tool_catalog())


async def build_competition_tool_registry(
    *,
    runtime_available: Callable[[], bool] | None = None,
    docker_probe: Callable[[], tuple[bool, str]] | None = None,
) -> tuple[ToolRegistry, tuple[str, ...]]:
    """Register every expected built-in tool; failures are logged with full stacks."""

    registry = ToolRegistry()
    probe = runtime_available or (lambda: False)
    failed: list[str] = []
    for entry in competition_tool_catalog():
        try:
            module = importlib.import_module(entry.module_path)
            plugin_class = getattr(module, entry.plugin_class)
            if entry.uses_docker:
                plugin = plugin_class(
                    runtime_available=probe,
                    docker_probe=docker_probe,
                )
            else:
                plugin = plugin_class(runtime_available=probe)
            await registry.register_checked(plugin)
        except Exception:
            logger.error(
                "tool registration failed module_path=%s tool_id=%s plugin_class=%s",
                entry.module_path,
                entry.tool_id,
                entry.plugin_class,
                exc_info=True,
            )
            failed.append(entry.tool_id)
    if failed:
        logger.warning(
            "tool registration incomplete missing_tool_ids=%s",
            tuple(failed),
        )
    return registry, tuple(failed)


__all__ = [
    "ToolCatalogEntry",
    "build_competition_tool_registry",
    "competition_tool_catalog",
    "expected_competition_tool_ids",
]
