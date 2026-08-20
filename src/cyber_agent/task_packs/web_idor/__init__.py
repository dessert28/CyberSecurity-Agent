"""Public construction surface for the Web-IDOR task pack plugin."""

from __future__ import annotations

from cyber_agent.contracts.task_pack import TaskPack

from .adapter import WebIdorScenarioAdapter
from .config import (
    WebIdorObservationType,
    WebIdorScenarioConfig,
    WebIdorStepBinding,
)
from .manifest import (
    WEB_IDOR_REPORT_TEMPLATE,
    WEB_IDOR_SECURITY_POLICY,
    WEB_IDOR_TASK_PACK_ID,
    WEB_IDOR_TASK_PACK_VERSION,
    WEB_IDOR_TASK_TYPE,
    WEB_IDOR_TOOL_ID,
    WEB_IDOR_VERIFIER_ID,
    web_idor_manifest,
)


class WebIdorTaskPack(TaskPack):
    """A fixed-manifest TaskPack with a validation-only adapter."""

    __slots__ = ()

    def __init__(self, config: WebIdorScenarioConfig) -> None:
        super().__init__(
            manifest=web_idor_manifest(),
            adapter=WebIdorScenarioAdapter(config),
        )


__all__ = [
    "WEB_IDOR_REPORT_TEMPLATE",
    "WEB_IDOR_SECURITY_POLICY",
    "WEB_IDOR_TASK_PACK_ID",
    "WEB_IDOR_TASK_PACK_VERSION",
    "WEB_IDOR_TASK_TYPE",
    "WEB_IDOR_TOOL_ID",
    "WEB_IDOR_VERIFIER_ID",
    "WebIdorObservationType",
    "WebIdorScenarioAdapter",
    "WebIdorScenarioConfig",
    "WebIdorStepBinding",
    "WebIdorTaskPack",
    "web_idor_manifest",
]
