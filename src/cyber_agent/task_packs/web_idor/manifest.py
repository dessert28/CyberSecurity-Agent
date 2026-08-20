"""Fixed metadata for the minimal Web-IDOR task pack."""

from __future__ import annotations

from cyber_agent.contracts.task_pack import TaskPackManifest

WEB_IDOR_TASK_PACK_ID = "web.idor"
WEB_IDOR_TASK_PACK_VERSION = "1.0.0"
WEB_IDOR_TASK_TYPE = "web.idor-assessment"
WEB_IDOR_TOOL_ID = "web.http_request"
WEB_IDOR_VERIFIER_ID = "web.idor"
WEB_IDOR_REPORT_TEMPLATE = "web.security-assessment"
WEB_IDOR_SECURITY_POLICY = "scope-policy/1.0"

_MANIFEST = TaskPackManifest(
    task_pack_id=WEB_IDOR_TASK_PACK_ID,
    version=WEB_IDOR_TASK_PACK_VERSION,
    task_type=WEB_IDOR_TASK_TYPE,
    required_tools=(WEB_IDOR_TOOL_ID,),
    verifier=WEB_IDOR_VERIFIER_ID,
    report_template=WEB_IDOR_REPORT_TEMPLATE,
    security_policy=WEB_IDOR_SECURITY_POLICY,
)


def web_idor_manifest() -> TaskPackManifest:
    """Return an isolated copy of the fixed, least-privilege manifest."""

    return _MANIFEST.model_copy(deep=True)


__all__ = [
    "WEB_IDOR_REPORT_TEMPLATE",
    "WEB_IDOR_SECURITY_POLICY",
    "WEB_IDOR_TASK_PACK_ID",
    "WEB_IDOR_TASK_PACK_VERSION",
    "WEB_IDOR_TASK_TYPE",
    "WEB_IDOR_TOOL_ID",
    "WEB_IDOR_VERIFIER_ID",
    "web_idor_manifest",
]
