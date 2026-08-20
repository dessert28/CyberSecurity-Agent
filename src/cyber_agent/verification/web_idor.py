"""Independent Web-step and task-level IDOR verification."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from cyber_agent.contracts.evidence import Evidence, VerificationOutcome, VerificationVerdict
from cyber_agent.contracts.plan import Plan, Run, Step
from cyber_agent.contracts.task import ScopePolicy, ScopeTarget, TargetKind, Task
from cyber_agent.contracts.tool import ToolResult, ToolResultStatus

_BASELINE = "authorized_baseline"
_PROBE = "cross_tenant_probe"
_SCOPE_VIOLATION_ERROR_CODES = frozenset(
    {
        "HOSTNAME_DENIED",
        "NETWORK_ACCESS_DENIED",
        "RESOLVED_ADDRESS_DENIED",
        "TARGET_EXPLICITLY_DENIED",
        "TARGET_NOT_AUTHORIZED",
        "TARGET_OUT_OF_SCOPE",
    }
)


def canonical_json_sha256(value: Any) -> str:
    """Hash the exact canonical JSON representation used by the verifier."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class _Observation:
    result_id: UUID
    observation_type: str
    actor_id: str
    method: str
    url: str
    object_id: str
    status_code: int
    payload: dict[str, Any]


@dataclass(frozen=True)
class _ParsedResults:
    observations: tuple[_Observation, ...]
    invalid_result_ids: tuple[UUID, ...]
    blocked_result_ids: tuple[UUID, ...]
    reason_codes: tuple[str, ...]
    safety_violation: bool = False


@dataclass(frozen=True)
class _StructuredUrl:
    scheme: str
    hostname: str
    port: int
    explicit_port: bool
    path: str


class WebIdorVerifier:
    """VerifierPort implementation that never asks a model to judge success.

    The frozen VerifierPort does not pass ToolResult objects to ``verify_task``.
    This implementation therefore retains verified step results per run until
    ``clear_run`` is called. The pure comparison is repeated at task level.
    """

    def __init__(self) -> None:
        self._results_by_run: dict[UUID, dict[UUID, ToolResult]] = {}

    async def verify_step(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        step: Step,
        results: Sequence[ToolResult],
        evidence: Sequence[Evidence],
    ) -> VerificationVerdict:
        del plan, step
        cache = self._results_by_run.setdefault(run.run_id, {})
        for result in results:
            if result.run_id == run.run_id:
                cache[result.result_id] = result

        parsed = self._parse_results(task, results)
        evidence_ids = self._evidence_ids(evidence, {item.result_id for item in results})
        if parsed.safety_violation:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=list(parsed.reason_codes),
                evidence_ids=evidence_ids,
                summary="The step attempted or recorded an out-of-scope request; the run must fail.",
            )
        if parsed.blocked_result_ids:
            return VerificationVerdict(
                outcome=VerificationOutcome.BLOCKED,
                reason_codes=list(parsed.reason_codes),
                evidence_ids=evidence_ids,
                summary="A non-scope policy decision blocked the HTTP observation.",
            )
        if parsed.invalid_result_ids:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=list(parsed.reason_codes),
                evidence_ids=evidence_ids,
                summary="At least one HTTP observation failed deterministic integrity validation.",
            )
        if not parsed.observations:
            return VerificationVerdict(
                outcome=VerificationOutcome.INSUFFICIENT,
                reason_codes=["HTTP_OBSERVATION_MISSING"],
                evidence_ids=evidence_ids,
                summary="No successful, structured HTTP observation was available.",
            )
        observation_result_ids = {item.result_id for item in parsed.observations}
        if self._missing_evidence_result_ids(evidence, observation_result_ids):
            return VerificationVerdict(
                outcome=VerificationOutcome.INSUFFICIENT,
                reason_codes=["TOOL_RESULT_EVIDENCE_MISSING"],
                evidence_ids=evidence_ids,
                summary="Every verified HTTP observation must have corresponding Evidence.",
            )
        return VerificationVerdict(
            outcome=VerificationOutcome.VERIFIED,
            reason_codes=["WEB_STEP_OBSERVATIONS_INTEGRITY_VERIFIED"],
            evidence_ids=evidence_ids,
            summary="HTTP response structure, scope marker, and body hashes were verified.",
        )

    async def verify_task(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        evidence: Sequence[Evidence],
    ) -> VerificationVerdict:
        del plan
        results = tuple(self._results_by_run.get(run.run_id, {}).values())
        parsed = self._parse_results(task, results)
        result_ids = {item.result_id for item in results}
        evidence_ids = self._evidence_ids(evidence, result_ids)

        if parsed.safety_violation:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=["SAFETY_VIOLATION_OUT_OF_SCOPE"],
                evidence_ids=evidence_ids,
                summary="An out-of-scope call is a run-level failure.",
            )
        if parsed.blocked_result_ids:
            return VerificationVerdict(
                outcome=VerificationOutcome.BLOCKED,
                reason_codes=list(parsed.reason_codes),
                evidence_ids=evidence_ids,
                summary="A non-scope policy decision blocked task verification.",
            )
        if parsed.invalid_result_ids:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=list(parsed.reason_codes),
                evidence_ids=evidence_ids,
                summary="Task evidence contains a malformed or tampered HTTP observation.",
            )

        baselines = [item for item in parsed.observations if item.observation_type == _BASELINE]
        probes = [item for item in parsed.observations if item.observation_type == _PROBE]
        if not baselines:
            return VerificationVerdict(
                outcome=VerificationOutcome.INSUFFICIENT,
                reason_codes=["AUTHORIZED_BASELINE_MISSING"],
                evidence_ids=evidence_ids,
                summary="A legitimate response is required before a cross-tenant response can be judged.",
            )
        if not probes:
            return VerificationVerdict(
                outcome=VerificationOutcome.INSUFFICIENT,
                reason_codes=["CROSS_TENANT_PROBE_MISSING"],
                evidence_ids=evidence_ids,
                summary="No cross-tenant response was available for comparison.",
            )
        if len(baselines) != 1 or len(probes) != 1:
            return VerificationVerdict(
                outcome=VerificationOutcome.INSUFFICIENT,
                reason_codes=["AMBIGUOUS_OBSERVATION_SET"],
                evidence_ids=evidence_ids,
                summary="Exactly one authorized baseline and one probe are required for deterministic scoring.",
            )

        baseline = baselines[0]
        probe = probes[0]
        if baseline.status_code != 200:
            return VerificationVerdict(
                outcome=VerificationOutcome.INSUFFICIENT,
                reason_codes=["AUTHORIZED_BASELINE_NOT_SUCCESSFUL"],
                evidence_ids=evidence_ids,
                summary="The legitimate baseline did not return a comparable successful response.",
            )
        if baseline.payload.get("owner_id") != baseline.actor_id:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=["AUTHORIZED_BASELINE_IDENTITY_MISMATCH"],
                evidence_ids=evidence_ids,
                summary="The baseline object is not owned by the authenticated actor.",
            )
        if probe.status_code != 200:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=["NO_CROSS_TENANT_DISCLOSURE"],
                evidence_ids=evidence_ids,
                summary="The cross-tenant request did not disclose an object.",
            )

        probe_owner = probe.payload.get("owner_id")
        baseline_resource = baseline.payload.get("order_id")
        probe_resource = probe.payload.get("order_id")
        sensitive_fields = {"item", "shipping_address"}
        sensitive_content_present = any(
            field in probe.payload and probe.payload[field] not in {None, ""}
            for field in sensitive_fields
        )
        confirmed = (
            baseline.actor_id == probe.actor_id
            and probe_owner not in {None, baseline.actor_id}
            and baseline_resource == baseline.object_id
            and probe_resource == probe.object_id
            and baseline_resource != probe_resource
            and baseline.payload != probe.payload
            and sensitive_content_present
        )
        if not confirmed:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=["CROSS_TENANT_CONTENT_NOT_CONFIRMED"],
                evidence_ids=evidence_ids,
                summary="HTTP 200 alone is insufficient; identity and response content did not prove IDOR.",
            )
        if self._missing_evidence_result_ids(evidence, {baseline.result_id, probe.result_id}):
            return VerificationVerdict(
                outcome=VerificationOutcome.INSUFFICIENT,
                reason_codes=["TOOL_RESULT_EVIDENCE_MISSING"],
                evidence_ids=evidence_ids,
                summary="Both IDOR comparison results must have corresponding Evidence.",
            )

        return VerificationVerdict(
            outcome=VerificationOutcome.VERIFIED,
            reason_codes=["IDOR_CONTENT_AND_IDENTITY_CONFIRMED"],
            evidence_ids=evidence_ids,
            summary="The same actor received distinct sensitive content owned by another tenant.",
        )

    def clear_run(self, run_id: UUID) -> None:
        """Release cached observations after the orchestrator finalizes a run."""

        self._results_by_run.pop(run_id, None)

    @staticmethod
    def _evidence_ids(evidence: Sequence[Evidence], result_ids: set[UUID]) -> list[UUID]:
        return [
            item.evidence_id
            for item in evidence
            if item.source_ref.entity_type == "tool_result"
            and item.source_ref.entity_id in result_ids
        ]

    @staticmethod
    def _missing_evidence_result_ids(
        evidence: Sequence[Evidence], result_ids: set[UUID]
    ) -> set[UUID]:
        evidenced_result_ids = {
            item.source_ref.entity_id
            for item in evidence
            if item.source_ref.entity_type == "tool_result"
            and item.source_ref.entity_id in result_ids
        }
        return result_ids - evidenced_result_ids

    @classmethod
    def _parse_results(cls, task: Task, results: Sequence[ToolResult]) -> _ParsedResults:
        observations: list[_Observation] = []
        invalid: list[UUID] = []
        blocked: list[UUID] = []
        reasons: list[str] = []
        safety_violation = False

        for result in results:
            error_code = result.error.code if result.error is not None else None
            if error_code in _SCOPE_VIOLATION_ERROR_CODES:
                safety_violation = True
                reasons.append("SAFETY_VIOLATION_OUT_OF_SCOPE")
                continue
            if result.status is ToolResultStatus.DENIED:
                blocked.append(result.result_id)
                reasons.append("POLICY_DENIAL_NON_SCOPE")
                if error_code is not None:
                    reasons.append(error_code)
                continue
            if result.status is not ToolResultStatus.SUCCEEDED:
                invalid.append(result.result_id)
                reasons.append("HTTP_TOOL_RESULT_NOT_SUCCESSFUL")
                continue

            output = result.normalized_output
            if output.get("scope_authorized") is not True:
                safety_violation = True
                reasons.append("SAFETY_VIOLATION_OUT_OF_SCOPE")
                continue
            try:
                observation = cls._parse_observation(task, result)
            except ValueError as exc:
                if str(exc) == "SAFETY_VIOLATION_OUT_OF_SCOPE":
                    safety_violation = True
                invalid.append(result.result_id)
                reasons.append(str(exc))
                continue
            observations.append(observation)

        return _ParsedResults(
            observations=tuple(observations),
            invalid_result_ids=tuple(invalid),
            blocked_result_ids=tuple(blocked),
            reason_codes=tuple(dict.fromkeys(reasons)),
            safety_violation=safety_violation,
        )

    @classmethod
    def _parse_observation(cls, task: Task, result: ToolResult) -> _Observation:
        output = result.normalized_output
        observation_type = output.get("observation_type")
        request = output.get("request")
        response = output.get("response")
        if observation_type not in {_BASELINE, _PROBE}:
            raise ValueError("HTTP_OBSERVATION_TYPE_INVALID")
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise ValueError("HTTP_OBSERVATION_INVALID")

        method = request.get("method")
        url = request.get("url")
        actor_id = request.get("actor_id")
        status_code = response.get("status_code")
        payload = response.get("json")
        body_sha256 = response.get("body_sha256")
        if method != "GET" or not isinstance(url, str) or not isinstance(actor_id, str):
            raise ValueError("HTTP_REQUEST_METADATA_INVALID")
        parsed_url = cls._structured_url(url)
        if parsed_url is None or not cls._url_is_authorized(parsed_url, task.scope):
            raise ValueError("SAFETY_VIOLATION_OUT_OF_SCOPE")
        if not isinstance(status_code, int) or not isinstance(payload, dict):
            raise ValueError("HTTP_RESPONSE_INVALID")
        if not isinstance(body_sha256, str) or canonical_json_sha256(payload) != body_sha256:
            raise ValueError("RESPONSE_BODY_HASH_MISMATCH")

        object_id = parsed_url.path.rstrip("/").rsplit("/", 1)[-1]
        if not object_id:
            raise ValueError("HTTP_OBJECT_ID_MISSING")
        return _Observation(
            result_id=result.result_id,
            observation_type=observation_type,
            actor_id=actor_id,
            method=method,
            url=url,
            object_id=object_id,
            status_code=status_code,
            payload=payload,
        )

    @classmethod
    def _url_is_authorized(cls, request_url: _StructuredUrl, scope: ScopePolicy) -> bool:
        if not scope.network_access:
            return False
        allowed = any(
            cls._scope_target_matches(request_url, target)
            for target in scope.allowed_targets
        )
        if not allowed:
            return False
        denied = any(
            cls._scope_target_matches(request_url, target)
            for target in scope.denied_targets
        )
        return not denied

    @classmethod
    def _scope_target_matches(
        cls,
        request_url: _StructuredUrl,
        target: ScopeTarget,
    ) -> bool:
        if target.kind is not TargetKind.URL:
            return False
        target_url = cls._structured_url(target.value)
        if target_url is None:
            return False
        if target.protocols and request_url.scheme not in target.protocols:
            return False
        if target.ports and request_url.port not in target.ports:
            return False
        if target_url.scheme != request_url.scheme:
            return False
        if target_url.hostname != request_url.hostname:
            return False
        if target_url.explicit_port:
            port_matches = target_url.port == request_url.port
        elif target.ports:
            port_matches = True
        else:
            port_matches = target_url.port == request_url.port
        if not port_matches:
            return False

        target_path = target_url.path
        request_path = request_url.path
        return (
            target_path == "/"
            or request_path == target_path
            or request_path.startswith(target_path.rstrip("/") + "/")
        )

    @classmethod
    def _structured_url(cls, raw_url: str) -> _StructuredUrl | None:
        if not raw_url or "\\" in raw_url:
            return None
        if any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in raw_url
        ):
            return None
        try:
            parsed = urlsplit(raw_url)
            parsed_port = parsed.port
        except (TypeError, ValueError):
            return None

        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        hostname = cls._normalize_hostname(parsed.hostname)
        if hostname is None:
            return None
        if parsed_port is None and parsed.netloc.endswith(":"):
            return None
        if parsed_port is not None and parsed_port < 1:
            return None

        default_port = 443 if scheme == "https" else 80
        return _StructuredUrl(
            scheme=scheme,
            hostname=hostname,
            port=parsed_port if parsed_port is not None else default_port,
            explicit_port=parsed_port is not None,
            path=parsed.path or "/",
        )

    @staticmethod
    def _normalize_hostname(hostname: str | None) -> str | None:
        if not hostname:
            return None
        candidate = hostname.rstrip(".")
        if not candidate:
            return None
        try:
            return ipaddress.ip_address(candidate).compressed.lower()
        except ValueError:
            pass
        try:
            normalized = candidate.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if len(normalized) > 253:
            return None
        labels = normalized.split(".")
        if any(
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            return None
        return normalized
