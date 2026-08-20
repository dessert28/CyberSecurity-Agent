from cyber_agent.contracts import (
    ArtifactRef,
    AuditRecord,
    Evidence,
    ModelRequest,
    Plan,
    PlanProposal,
    Run,
    Step,
    Task,
    ToolInvocation,
    ToolResult,
    ToolSpec,
)


def test_required_public_contracts_are_exported() -> None:
    assert all(
        contract is not None
        for contract in (
            ArtifactRef,
            AuditRecord,
            Evidence,
            ModelRequest,
            Plan,
            PlanProposal,
            Run,
            Step,
            Task,
            ToolInvocation,
            ToolResult,
            ToolSpec,
        )
    )
