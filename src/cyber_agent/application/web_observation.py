"""Trusted application-layer adaptation between Web tools and IDOR verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from cyber_agent.contracts.common import EntityRef, ErrorCategory, ErrorInfo
from cyber_agent.contracts.errors import ContractValidationError
from cyber_agent.contracts.evidence import Evidence, EvidenceKind, VerificationMethod
from cyber_agent.contracts.plan import Plan, Run, Step
from cyber_agent.contracts.task import Task
from cyber_agent.contracts.tool import (
    PolicyDecision,
    ToolInvocation,
    ToolInvocationStatus,
    ToolResult,
    ToolResultStatus,
)
from cyber_agent.verification.web_idor import canonical_json_sha256

_HTTP_OUTPUT_FIELDS = {"status_code", "headers", "body", "redirects"}
_SCOPE_DENIAL_CODES = {
    "HOSTNAME_DENIED",
    "NETWORK_ACCESS_DENIED",
    "RESOLVED_ADDRESS_DENIED",
    "TARGET_EXPLICITLY_DENIED",
    "TARGET_NOT_AUTHORIZED",
    "TARGET_OUT_OF_SCOPE",
}


class WebIdorObservationType(str, Enum):
    AUTHORIZED_BASELINE = "authorized_baseline"
    CROSS_TENANT_PROBE = "cross_tenant_probe"


@dataclass(frozen=True, slots=True)
class AdaptedToolObservation:
    result: ToolResult
    evidence: Evidence


def materialize_policy_decision(
    invocation: ToolInvocation,
    decision: PolicyDecision,
) -> ToolInvocation:
    """Bind a policy decision to the same invocation without mutating the proposal."""

    if (
        invocation.status is not ToolInvocationStatus.PROPOSED
        or invocation.policy_decision_ref is not None
    ):
        raise _adapter_error(
            "INVOCATION_NOT_PROPOSED",
            ErrorCategory.INPUT_INVALID,
            "Only an unbound proposed invocation can receive a policy decision.",
        )
    status = (
        ToolInvocationStatus.APPROVED
        if decision.allowed
        else ToolInvocationStatus.DENIED
    )
    arguments = (
        decision.constrained_arguments
        if decision.allowed
        else invocation.validated_arguments
    )
    data = invocation.model_dump(mode="python")
    data.update(
        status=status,
        policy_decision_ref=decision.decision_id,
        validated_arguments=arguments,
    )
    return ToolInvocation.model_validate(data)


def adapt_web_idor_observation(
    *,
    task: Task,
    run: Run,
    plan: Plan,
    step: Step,
    invocation: ToolInvocation,
    decision: PolicyDecision,
    result: ToolResult,
    observation_type: WebIdorObservationType,
    actor_id: str,
    max_body_bytes: int = 1_000_000,
) -> AdaptedToolObservation:
    """Convert B's generic HTTP result into C's integrity-checked observation."""

    _validate_context(task, run, plan, step, invocation)
    _validate_allowed_binding(invocation, decision, result)
    if result.tool_ref.tool_id != "web.http_request":
        raise _adapter_error(
            "HTTP_TOOL_REQUIRED",
            ErrorCategory.INPUT_INVALID,
            "The Web-IDOR adapter only accepts web.http_request results.",
        )
    if result.status is not ToolResultStatus.SUCCEEDED or result.error is not None:
        raise _adapter_error(
            "HTTP_RESULT_NOT_SUCCESSFUL",
            ErrorCategory.TOOL_FAILED,
            "Only a successful HTTP tool result can become an observation.",
        )
    if result.finished_at > invocation.deadline:
        raise _adapter_error(
            "HTTP_RESULT_AFTER_DEADLINE",
            ErrorCategory.EXECUTION_TIMEOUT,
            "A result completed after the approved invocation deadline.",
        )
    if result.exit_code not in {None, 0}:
        raise _adapter_error(
            "HTTP_RESULT_EXIT_NONZERO",
            ErrorCategory.TOOL_FAILED,
            "A non-zero tool exit cannot become a successful observation.",
        )

    arguments = invocation.validated_arguments
    method = arguments.get("method")
    url = arguments.get("url")
    if method != "GET" or not isinstance(url, str):
        raise _adapter_error(
            "HTTP_REQUEST_METADATA_INVALID",
            ErrorCategory.INPUT_INVALID,
            "Web-IDOR observations require a structured GET request URL.",
        )
    if not _valid_actor_id(actor_id):
        raise _adapter_error(
            "ACTOR_ID_INVALID",
            ErrorCategory.INPUT_INVALID,
            "The trusted scenario actor ID is invalid.",
        )

    output = result.normalized_output
    if set(output) != _HTTP_OUTPUT_FIELDS:
        raise _adapter_error(
            "HTTP_OUTPUT_SCHEMA_INVALID",
            ErrorCategory.TOOL_FAILED,
            "The HTTP tool output does not match the expected normalized shape.",
        )
    status_code = output.get("status_code")
    headers = output.get("headers")
    body = output.get("body")
    redirects = output.get("redirects")
    if (
        isinstance(status_code, bool)
        or not isinstance(status_code, int)
        or not 100 <= status_code <= 599
        or not _string_mapping(headers)
        or not _string_list(redirects, maximum=5)
        or not isinstance(body, str)
    ):
        raise _adapter_error(
            "HTTP_OUTPUT_SCHEMA_INVALID",
            ErrorCategory.TOOL_FAILED,
            "The HTTP tool output contains invalid field types or limits.",
        )
    if max_body_bytes < 1 or len(body.encode("utf-8")) > max_body_bytes:
        raise _adapter_error(
            "HTTP_BODY_LIMIT_EXCEEDED",
            ErrorCategory.TOOL_FAILED,
            "The HTTP response body exceeds the adapter limit.",
        )
    try:
        payload = json.loads(
            body,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise _adapter_error(
            "HTTP_BODY_JSON_INVALID",
            ErrorCategory.TOOL_FAILED,
            "The HTTP response body is not strict JSON.",
        ) from exc
    if not isinstance(payload, dict):
        raise _adapter_error(
            "HTTP_BODY_OBJECT_REQUIRED",
            ErrorCategory.TOOL_FAILED,
            "The Web-IDOR response body must be a JSON object.",
        )

    normalized_output = {
        "observation_type": observation_type.value,
        # This value is derived only from the bound PolicyDecision above.
        "scope_authorized": True,
        "request": {"method": method, "url": url, "actor_id": actor_id},
        "response": {
            "status_code": status_code,
            "json": payload,
            "body_sha256": canonical_json_sha256(payload),
        },
    }
    result_data = result.model_dump(mode="python")
    result_data["normalized_output"] = normalized_output
    adapted_result = ToolResult.model_validate(result_data)
    evidence = Evidence(
        run_id=run.run_id,
        source_ref=EntityRef(
            entity_type="tool_result",
            entity_id=adapted_result.result_id,
        ),
        kind=EvidenceKind.TOOL_OBSERVATION,
        summary="Policy-bound HTTP observation normalized for deterministic IDOR verification.",
        supports_claims=["claim.web_idor_evaluation"],
        verification_method=VerificationMethod.DIRECT_OBSERVATION,
        confidence=1.0,
        created_at=adapted_result.finished_at,
    )
    return AdaptedToolObservation(result=adapted_result, evidence=evidence)


def policy_denial_observation(
    *,
    task: Task,
    run: Run,
    plan: Plan,
    step: Step,
    invocation: ToolInvocation,
    decision: PolicyDecision,
    occurred_at: datetime,
) -> AdaptedToolObservation:
    """Create an auditable denied ToolResult without invoking an executor."""

    _validate_context(task, run, plan, step, invocation)
    if decision.allowed or invocation.status is not ToolInvocationStatus.DENIED:
        raise _adapter_error(
            "POLICY_DENIAL_REQUIRED",
            ErrorCategory.INPUT_INVALID,
            "A denied observation requires a denied invocation and policy decision.",
        )
    if invocation.policy_decision_ref != decision.decision_id:
        raise _adapter_error(
            "POLICY_DECISION_MISMATCH",
            ErrorCategory.POLICY_DENIED,
            "The denied invocation is not bound to the supplied policy decision.",
        )
    reason_code = decision.reason_codes[0] if decision.reason_codes else "POLICY_DENIED"
    category = _denial_category(reason_code)
    fingerprint = hashlib.sha256(
        (
            decision.policy_version
            + "\0"
            + "\0".join(decision.reason_codes)
        ).encode("utf-8")
    ).hexdigest()
    denied_result = ToolResult(
        run_id=run.run_id,
        plan_id=plan.plan_id,
        step_id=step.step_id,
        attempt=invocation.attempt,
        tool_ref=invocation.tool_ref,
        validated_arguments=invocation.validated_arguments,
        policy_decision_ref=decision.decision_id,
        status=ToolResultStatus.DENIED,
        started_at=occurred_at,
        finished_at=occurred_at,
        error=ErrorInfo(
            code=reason_code,
            category=category,
            retryable=False,
            safe_message="The policy gate denied this tool invocation.",
            diagnostic_ref=decision.decision_id,
        ),
        environment_fingerprint=fingerprint,
    )
    evidence = Evidence(
        run_id=run.run_id,
        source_ref=EntityRef(entity_type="tool_result", entity_id=denied_result.result_id),
        kind=EvidenceKind.RULE_VERIFICATION,
        summary="Policy denial recorded without executing the requested tool.",
        supports_claims=["claim.policy_enforced"],
        verification_method=VerificationMethod.RULE,
        confidence=1.0,
        created_at=occurred_at,
    )
    return AdaptedToolObservation(result=denied_result, evidence=evidence)


def _validate_context(
    task: Task,
    run: Run,
    plan: Plan,
    step: Step,
    invocation: ToolInvocation,
) -> None:
    if (
        run.task_id != task.task_id
        or plan.run_id != run.run_id
        or step.plan_id != plan.plan_id
        or step.step_id not in plan.step_ids
        or invocation.run_id != run.run_id
        or invocation.plan_id != plan.plan_id
        or invocation.step_id != step.step_id
    ):
        raise _adapter_error(
            "APPLICATION_REFERENCE_MISMATCH",
            ErrorCategory.INPUT_INVALID,
            "Task, run, plan, step, and invocation references must agree.",
        )


def _validate_allowed_binding(
    invocation: ToolInvocation,
    decision: PolicyDecision,
    result: ToolResult,
) -> None:
    if not decision.allowed or invocation.status is not ToolInvocationStatus.APPROVED:
        raise _adapter_error(
            "POLICY_APPROVAL_REQUIRED",
            ErrorCategory.POLICY_DENIED,
            "A successful observation requires an allowed policy decision.",
        )
    if (
        invocation.policy_decision_ref != decision.decision_id
        or result.policy_decision_ref != decision.decision_id
    ):
        raise _adapter_error(
            "POLICY_DECISION_MISMATCH",
            ErrorCategory.POLICY_DENIED,
            "Invocation and result must reference the supplied policy decision.",
        )
    if invocation.validated_arguments != decision.constrained_arguments:
        raise _adapter_error(
            "POLICY_ARGUMENT_MISMATCH",
            ErrorCategory.POLICY_DENIED,
            "Execution arguments must equal the policy-constrained arguments.",
        )
    if (
        result.run_id != invocation.run_id
        or result.plan_id != invocation.plan_id
        or result.step_id != invocation.step_id
        or result.attempt != invocation.attempt
        or result.tool_ref != invocation.tool_ref
        or result.validated_arguments != invocation.validated_arguments
    ):
        raise _adapter_error(
            "TOOL_RESULT_REFERENCE_MISMATCH",
            ErrorCategory.INPUT_INVALID,
            "The tool result is not bound to the approved invocation.",
        )


def _string_mapping(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str) and isinstance(item, str)
        for key, item in value.items()
    )


def _string_list(value: Any, *, maximum: int) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= maximum
        and all(isinstance(item, str) for item in value)
    )


def _valid_actor_id(value: str) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 255
        and value == value.strip()
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant is forbidden: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key is forbidden: {key}")
        result[key] = value
    return result


def _denial_category(code: str) -> ErrorCategory:
    if code in _SCOPE_DENIAL_CODES:
        return ErrorCategory.POLICY_DENIED
    if "BUDGET" in code or code == "RUN_DEADLINE_EXCEEDED":
        return ErrorCategory.BUDGET_EXCEEDED
    if code == "INVOCATION_DEADLINE_EXCEEDED":
        return ErrorCategory.EXECUTION_TIMEOUT
    return ErrorCategory.POLICY_DENIED


def _adapter_error(
    code: str,
    category: ErrorCategory,
    message: str,
) -> ContractValidationError:
    return ContractValidationError(
        ErrorInfo(
            code=code,
            category=category,
            retryable=False,
            safe_message=message,
        )
    )
