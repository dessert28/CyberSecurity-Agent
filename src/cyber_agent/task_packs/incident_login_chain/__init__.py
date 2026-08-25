"""Incident login-chain task pack plugin."""

from __future__ import annotations

from cyber_agent.contracts.task_pack import TaskPack

from .adapter import IncidentLoginChainScenarioAdapter
from .config import IncidentLoginChainScenarioConfig
from .manifest import (
    INCIDENT_LOGIN_CHAIN_CAPABILITIES,
    INCIDENT_LOGIN_CHAIN_INVENTORY_CAPABILITY,
    INCIDENT_LOGIN_CHAIN_INVENTORY_TOOL_ID,
    INCIDENT_LOGIN_CHAIN_REPORT_TEMPLATE,
    INCIDENT_LOGIN_CHAIN_REQUIRED_TOOLS,
    INCIDENT_LOGIN_CHAIN_SEARCH_CAPABILITY,
    INCIDENT_LOGIN_CHAIN_SEARCH_TOOL_ID,
    INCIDENT_LOGIN_CHAIN_SECURITY_POLICY,
    INCIDENT_LOGIN_CHAIN_TASK_PACK_ID,
    INCIDENT_LOGIN_CHAIN_TASK_PACK_VERSION,
    INCIDENT_LOGIN_CHAIN_TASK_TYPE,
    INCIDENT_LOGIN_CHAIN_VERIFIER_ID,
    incident_login_chain_manifest,
)


class IncidentLoginChainTaskPack(TaskPack):
    """Immutable three-stage read-only incident login-chain task pack."""

    def __init__(self, config: IncidentLoginChainScenarioConfig) -> None:
        super().__init__(
            manifest=incident_login_chain_manifest(),
            adapter=IncidentLoginChainScenarioAdapter(config),
        )


__all__ = [
    "INCIDENT_LOGIN_CHAIN_CAPABILITIES",
    "INCIDENT_LOGIN_CHAIN_INVENTORY_CAPABILITY",
    "INCIDENT_LOGIN_CHAIN_INVENTORY_TOOL_ID",
    "INCIDENT_LOGIN_CHAIN_REPORT_TEMPLATE",
    "INCIDENT_LOGIN_CHAIN_REQUIRED_TOOLS",
    "INCIDENT_LOGIN_CHAIN_SEARCH_CAPABILITY",
    "INCIDENT_LOGIN_CHAIN_SEARCH_TOOL_ID",
    "INCIDENT_LOGIN_CHAIN_SECURITY_POLICY",
    "INCIDENT_LOGIN_CHAIN_TASK_PACK_ID",
    "INCIDENT_LOGIN_CHAIN_TASK_PACK_VERSION",
    "INCIDENT_LOGIN_CHAIN_TASK_TYPE",
    "INCIDENT_LOGIN_CHAIN_VERIFIER_ID",
    "IncidentLoginChainScenarioAdapter",
    "IncidentLoginChainScenarioConfig",
    "IncidentLoginChainTaskPack",
    "incident_login_chain_manifest",
]
