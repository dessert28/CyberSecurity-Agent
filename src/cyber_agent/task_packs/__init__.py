"""Trusted scenario plugins for the generic orchestration core."""

from .catalog import (
    IncidentLoginChainScenarioInput,
    PwnRet2winScenarioInput,
    ReverseKeycheckScenarioInput,
    SourceAuditScenarioInput,
    TaskPackCatalog,
    TaskPackCatalogError,
    build_competition_task_pack_catalog,
)

__all__ = [
    "IncidentLoginChainScenarioInput",
    "PwnRet2winScenarioInput",
    "ReverseKeycheckScenarioInput",
    "SourceAuditScenarioInput",
    "TaskPackCatalog",
    "TaskPackCatalogError",
    "build_competition_task_pack_catalog",
]
