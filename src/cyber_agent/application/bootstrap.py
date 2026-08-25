"""Explicit application composition for the two competition task packs."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from cyber_agent.application.competition_service import (
    ArtifactResolver,
    CompetitionRunService,
)
from cyber_agent.application.run_orchestrator import RunOrchestrator
from cyber_agent.contracts.common import EnvironmentProfile, ModelProfileRef
from cyber_agent.contracts.ports import (
    AuditStorePort,
    ExecutorPort,
    PlannerPort,
    ToolPlugin,
)
from cyber_agent.task_packs.source_audit.manifest import SOURCE_AUDIT_VERIFIER_ID
from cyber_agent.task_packs.web_idor.manifest import WEB_IDOR_VERIFIER_ID
from cyber_agent.tools import (
    HttpRequestPlugin,
    HypothesisValidatePlugin,
    PolicyGate,
    ProjectInventoryPlugin,
    PythonDataflowPlugin,
    ToolRegistry,
)
from cyber_agent.verification import SourceAuditVerifier, VerifierRegistry, WebIdorVerifier


async def bootstrap_competition_service(
    *,
    planner: PlannerPort,
    executor: ExecutorPort,
    audit_store: AuditStorePort,
    model_profile: ModelProfileRef,
    environment_profile: EnvironmentProfile,
    artifact_resolver: ArtifactResolver | None = None,
    runtime_available: Callable[[], bool] | None = None,
    plugins: Sequence[ToolPlugin] | None = None,
    policy_gate: PolicyGate | None = None,
) -> CompetitionRunService:
    """Register the explicit competition components and return the run service."""
    from cyber_agent.task_packs import build_competition_task_pack_catalog

    availability = runtime_available or (lambda: False)
    selected_plugins = tuple(plugins) if plugins is not None else (
        HttpRequestPlugin(runtime_available=availability),
        ProjectInventoryPlugin(runtime_available=availability),
        PythonDataflowPlugin(runtime_available=availability),
        HypothesisValidatePlugin(runtime_available=availability),
    )
    tool_registry = ToolRegistry()
    for plugin in selected_plugins:
        await tool_registry.register_checked(plugin)

    verifier_registry = VerifierRegistry()
    verifier_registry.register(WEB_IDOR_VERIFIER_ID, WebIdorVerifier())
    verifier_registry.register(SOURCE_AUDIT_VERIFIER_ID, SourceAuditVerifier())

    orchestrator = RunOrchestrator(
        planner=planner,
        registry=tool_registry,
        policy_gate=policy_gate or PolicyGate(),
        executor=executor,
        verifier_registry=verifier_registry,
        audit_store=audit_store,
        model_profile=model_profile,
        environment_profile=environment_profile,
    )
    return CompetitionRunService(
        catalog=build_competition_task_pack_catalog(),
        orchestrator=orchestrator,
        tool_registry=tool_registry,
        verifier_registry=verifier_registry,
        artifact_resolver=artifact_resolver,
    )


__all__ = ["bootstrap_competition_service"]
