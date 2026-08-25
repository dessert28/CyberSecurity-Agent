from __future__ import annotations

from cyber_agent.application.admin_console import (
    AdminConsoleService,
    AdminHealthState,
)
from cyber_agent.task_packs import build_competition_task_pack_catalog
from cyber_agent.task_packs.web_idor import WEB_IDOR_VERIFIER_ID
from cyber_agent.tools import ToolRegistry
from cyber_agent.verification import (
    SOURCE_AUDIT_VERIFIER_ID,
    SourceAuditVerifier,
    VerifierRegistry,
    WebIdorVerifier,
)


def _service(*, tool_registry, verifier_registry):
    return AdminConsoleService(
        profiles=None,
        capabilities=None,
        task_packs=build_competition_task_pack_catalog(),
        verifier_registry=verifier_registry,
        tool_registry=tool_registry,
    )


def test_tool_health_lists_missing_required_tools() -> None:
    service = _service(tool_registry=ToolRegistry(), verifier_registry=None)

    check = service._tool_health()

    assert check.state is AdminHealthState.DEGRADED
    assert "not registered" in check.message
    assert "web.http_request" in check.message
    assert "source.project_inventory" in check.message


def test_verifier_health_lists_missing_verifier_names() -> None:
    registry = VerifierRegistry()
    registry.register(WEB_IDOR_VERIFIER_ID, WebIdorVerifier())
    registry.register(SOURCE_AUDIT_VERIFIER_ID, SourceAuditVerifier())
    service = _service(tool_registry=ToolRegistry(), verifier_registry=registry)

    check = service._verifier_health()

    assert check.state is AdminHealthState.UNAVAILABLE
    assert "pwn.ret2win" in check.message
    assert "reverse.keycheck" in check.message
    assert "incident.login_chain" in check.message
