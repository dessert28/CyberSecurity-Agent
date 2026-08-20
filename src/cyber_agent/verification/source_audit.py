"""Deterministic verifier for Python SQL dataflow and controlled validation."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from cyber_agent.contracts.evidence import (
    Evidence,
    EvidenceKind,
    VerificationMethod,
    VerificationOutcome,
    VerificationVerdict,
)
from cyber_agent.contracts.plan import Plan, Run, Step
from cyber_agent.contracts.task import Task
from cyber_agent.contracts.tool import ToolResult, ToolResultStatus
from cyber_agent.tools.hypothesis_validate import (
    HYPOTHESIS_VALIDATE_TOOL_ID,
    HypothesisValidationResult,
)
from cyber_agent.tools.project_inventory import (
    PROJECT_INVENTORY_TOOL_ID,
    ProjectInventoryResult,
)
from cyber_agent.tools.python_dataflow import (
    PYTHON_DATAFLOW_TOOL_ID,
    DataflowAnalysisResult,
    DataflowHypothesis,
    SanitizerObservation,
)

SOURCE_AUDIT_VERIFIER_ID = "source.hypothesis"
_SUPPORTED_TOOL_IDS = {
    PROJECT_INVENTORY_TOOL_ID,
    PYTHON_DATAFLOW_TOOL_ID,
    HYPOTHESIS_VALIDATE_TOOL_ID,
}
_EXPECTED_CLAIMS = {
    PROJECT_INVENTORY_TOOL_ID: "source.project_inventory",
    PYTHON_DATAFLOW_TOOL_ID: "source.dataflow_hypotheses",
    HYPOTHESIS_VALIDATE_TOOL_ID: "source.hypothesis_validation",
}
_EXTERNAL_SOURCE_KINDS = {
    "request.args",
    "request.form",
    "request.json",
    "request.query_params",
    "request.values",
}


@dataclass(frozen=True, slots=True)
class _ParsedSourceResults:
    dataflow: tuple[DataflowAnalysisResult, ...]
    validations: tuple[HypothesisValidationResult, ...]


class SourceAuditVerifier:
    """Require a complete, same-run, artifact-bound hypothesis evidence chain."""

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
        cache = self._results_by_run.setdefault(run.run_id, {})
        for result in results:
            if result.run_id == run.run_id:
                cache[result.result_id] = result

        evidence_ids = self._evidence_ids(evidence, run.run_id)
        failure = self._integrity_failure(
            task,
            run,
            plan,
            results,
            evidence,
            allowed_step_id=step.step_id,
        )
        if failure is not None:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=[failure],
                evidence_ids=evidence_ids,
                summary="Source-audit step evidence failed deterministic integrity checks.",
            )
        if not results or any(
            result.status is not ToolResultStatus.SUCCEEDED for result in results
        ):
            return VerificationVerdict(
                outcome=VerificationOutcome.INSUFFICIENT,
                reason_codes=["INSUFFICIENT_EVIDENCE"],
                evidence_ids=evidence_ids,
                summary="The source-audit step did not provide a successful structured result.",
            )
        return VerificationVerdict(
            outcome=VerificationOutcome.VERIFIED,
            reason_codes=["SOURCE_STEP_EVIDENCE_ACCEPTED"],
            evidence_ids=evidence_ids,
            summary="The source-audit step result and Evidence reference are internally consistent.",
        )

    async def verify_task(
        self,
        task: Task,
        run: Run,
        plan: Plan,
        evidence: Sequence[Evidence],
    ) -> VerificationVerdict:
        results = tuple(self._results_by_run.get(run.run_id, {}).values())
        evidence_ids = self._evidence_ids(evidence, run.run_id)
        failure = self._integrity_failure(
            task,
            run,
            plan,
            results,
            evidence,
            allowed_step_id=None,
        )
        if failure is not None:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=[failure],
                evidence_ids=evidence_ids,
                summary="Source-audit task evidence failed deterministic integrity checks.",
            )
        if not results or any(
            result.status is not ToolResultStatus.SUCCEEDED for result in results
        ):
            return self._insufficient(evidence_ids)

        try:
            parsed = self._parse_source_results(results)
        except ValueError:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=["EVIDENCE_REFERENCE_INVALID"],
                evidence_ids=evidence_ids,
                summary="A source-audit result did not match its strict structured contract.",
            )

        all_hypotheses = [
            hypothesis
            for analysis in parsed.dataflow
            for hypothesis in analysis.hypotheses
        ]
        hypothesis_ids = [item.hypothesis_id for item in all_hypotheses]
        validation_ids = [item.hypothesis_id for item in parsed.validations]
        known_hypothesis_ids = set(hypothesis_ids)
        if (
            len(hypothesis_ids) != len(known_hypothesis_ids)
            or len(validation_ids) != len(set(validation_ids))
            or any(item not in known_hypothesis_ids for item in validation_ids)
        ):
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=["EVIDENCE_REFERENCE_INVALID"],
                evidence_ids=evidence_ids,
                summary="Hypothesis and controlled-validation references are ambiguous or unmatched.",
            )
        hypotheses = [
            hypothesis
            for hypothesis in all_hypotheses
            if self._hypothesis_has_external_path(hypothesis)
        ]
        if not hypotheses:
            return self._insufficient(evidence_ids)

        validations_by_id: dict[str, list[HypothesisValidationResult]] = {}
        for validation in parsed.validations:
            validations_by_id.setdefault(validation.hypothesis_id, []).append(validation)

        parameterization_observed = False
        matching_validation_observed = False
        for hypothesis in hypotheses:
            matching = validations_by_id.get(hypothesis.hypothesis_id, [])
            if not matching:
                continue
            matching_validation_observed = True
            for validation in matching:
                if not self._validation_matches_hypothesis(validation, hypothesis):
                    return VerificationVerdict(
                        outcome=VerificationOutcome.FAILED,
                        reason_codes=["EVIDENCE_REFERENCE_INVALID"],
                        evidence_ids=evidence_ids,
                        summary="Controlled validation does not match the referenced hypothesis sink.",
                    )
                if self._effective_parameterization(validation, hypothesis, parsed.dataflow):
                    parameterization_observed = True
                    continue
                if self._source_influence_captured(validation):
                    return VerificationVerdict(
                        outcome=VerificationOutcome.VERIFIED,
                        reason_codes=["SOURCE_SQL_INJECTION_CONFIRMED"],
                        evidence_ids=evidence_ids,
                        summary=(
                            "External input, a source-to-sink path, and controlled sink "
                            "capture consistently confirm the selected SQL injection hypothesis."
                        ),
                    )

        if parameterization_observed:
            return VerificationVerdict(
                outcome=VerificationOutcome.FAILED,
                reason_codes=["EFFECTIVE_PARAMETERIZATION_OBSERVED"],
                evidence_ids=evidence_ids,
                summary=(
                    "The selected hypothesis was not confirmed because controlled capture "
                    "kept query text invariant while parameter values changed."
                ),
            )
        if not matching_validation_observed:
            return VerificationVerdict(
                outcome=VerificationOutcome.INSUFFICIENT,
                reason_codes=["SOURCE_DATAFLOW_FOUND_BUT_NOT_VALIDATED"],
                evidence_ids=evidence_ids,
                summary="A source-to-sink hypothesis exists but has no matching controlled validation.",
            )
        return VerificationVerdict(
            outcome=VerificationOutcome.INSUFFICIENT,
            reason_codes=["SOURCE_DATAFLOW_FOUND_BUT_NOT_VALIDATED"],
            evidence_ids=evidence_ids,
            summary="Controlled observations did not reproduce source influence at the selected sink.",
        )

    def clear_run(self, run_id: UUID) -> None:
        self._results_by_run.pop(run_id, None)

    @classmethod
    def _integrity_failure(
        cls,
        task: Task,
        run: Run,
        plan: Plan,
        results: Sequence[ToolResult],
        evidence: Sequence[Evidence],
        *,
        allowed_step_id: UUID | None,
    ) -> str | None:
        result_ids = {result.result_id for result in results}
        if any(
            result.run_id != run.run_id
            or result.plan_id != plan.plan_id
            or result.step_id not in plan.step_ids
            or (allowed_step_id is not None and result.step_id != allowed_step_id)
            or result.tool_ref.tool_id not in _SUPPORTED_TOOL_IDS
            for result in results
        ):
            return "EVIDENCE_REFERENCE_INVALID"
        if any(item.run_id != run.run_id for item in evidence):
            return "EVIDENCE_REFERENCE_INVALID"
        if any(
            item.source_ref.entity_type != "tool_result"
            or item.source_ref.entity_id not in result_ids
            for item in evidence
        ):
            return "EVIDENCE_REFERENCE_INVALID"

        evidence_by_result: dict[UUID, list[Evidence]] = {}
        for item in evidence:
            evidence_by_result.setdefault(item.source_ref.entity_id, []).append(item)
        for result in results:
            expected_claim = _EXPECTED_CLAIMS[result.tool_ref.tool_id]
            linked = evidence_by_result.get(result.result_id, [])
            if not linked or not any(
                item.kind is EvidenceKind.TOOL_OBSERVATION
                and item.verification_method is VerificationMethod.DIRECT_OBSERVATION
                and expected_claim in item.supports_claims
                for item in linked
            ):
                return "EVIDENCE_REFERENCE_INVALID"

        artifact = cls._source_artifact(task)
        if artifact is None:
            return "ARTIFACT_MISMATCH"
        for item in evidence:
            if item.artifact_ref is not None and (
                item.artifact_ref.artifact_id != artifact.artifact_id
                or item.artifact_ref.sha256 != artifact.sha256
            ):
                return "ARTIFACT_MISMATCH"
        for result in results:
            arguments = result.validated_arguments
            if arguments.get("artifact_id") != str(artifact.artifact_id):
                return "ARTIFACT_MISMATCH"
            if arguments.get("artifact_sha256") != artifact.sha256:
                return "ARTIFACT_MISMATCH"
            output = result.normalized_output
            if output.get("artifact_id") != str(artifact.artifact_id):
                return "ARTIFACT_MISMATCH"
            if output.get("artifact_sha256") != artifact.sha256:
                return "ARTIFACT_MISMATCH"
        return None

    @staticmethod
    def _source_artifact(task: Task):
        candidates = [
            item
            for item in task.input_artifacts
            if item.media_type == "application/zip"
        ]
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _parse_source_results(
        results: Sequence[ToolResult],
    ) -> _ParsedSourceResults:
        dataflow: list[DataflowAnalysisResult] = []
        validations: list[HypothesisValidationResult] = []
        for result in results:
            if result.tool_ref.tool_id == PROJECT_INVENTORY_TOOL_ID:
                ProjectInventoryResult.model_validate(result.normalized_output)
            elif result.tool_ref.tool_id == PYTHON_DATAFLOW_TOOL_ID:
                dataflow.append(
                    DataflowAnalysisResult.model_validate(result.normalized_output)
                )
            elif result.tool_ref.tool_id == HYPOTHESIS_VALIDATE_TOOL_ID:
                validations.append(
                    HypothesisValidationResult.model_validate(
                        result.normalized_output
                    )
                )
            else:
                raise ValueError("unsupported source-audit result")
        return _ParsedSourceResults(
            dataflow=tuple(dataflow),
            validations=tuple(validations),
        )

    @staticmethod
    def _hypothesis_has_external_path(hypothesis: DataflowHypothesis) -> bool:
        if hypothesis.source.kind not in _EXTERNAL_SOURCE_KINDS:
            return False
        if len(hypothesis.dataflow) < 2:
            return False
        first = hypothesis.dataflow[0]
        last = hypothesis.dataflow[-1]
        return (
            first.role == "source"
            and first.file == hypothesis.source.file
            and first.line == hypothesis.source.line
            and last.role == "sink"
            and last.file == hypothesis.sink.file
            and last.line == hypothesis.sink.line
            and all(
                item.file in {hypothesis.source.file, hypothesis.sink.file}
                for item in hypothesis.dataflow
            )
        )

    @staticmethod
    def _validation_matches_hypothesis(
        validation: HypothesisValidationResult,
        hypothesis: DataflowHypothesis,
    ) -> bool:
        sink = validation.intercepted_sink
        baseline = validation.baseline_observation
        probe = validation.probe_observation
        return (
            validation.side_effect_suppressed is True
            and sink.side_effect_suppressed is True
            and sink.call == hypothesis.sink.call
            and sink.file == hypothesis.sink.file
            and sink.line == hypothesis.sink.line
            and sink.baseline_query == baseline.query_text
            and sink.probe_query == probe.query_text
            and sink.baseline_parameters == baseline.parameters
            and sink.probe_parameters == probe.parameters
            and baseline.query_sha256
            == hashlib.sha256(baseline.query_text.encode()).hexdigest()
            and probe.query_sha256
            == hashlib.sha256(probe.query_text.encode()).hexdigest()
            and sink.query_text_changed
            == (baseline.query_text != probe.query_text)
            and sink.parameter_values_changed
            == (baseline.parameters != probe.parameters)
        )

    @staticmethod
    def _effective_parameterization(
        validation: HypothesisValidationResult,
        hypothesis: DataflowHypothesis,
        analyses: Sequence[DataflowAnalysisResult],
    ) -> bool:
        sink = validation.intercepted_sink
        baseline = validation.baseline_observation
        probe = validation.probe_observation
        runtime_control = (
            sink.query_text_changed is False
            and sink.parameter_values_changed is True
            and baseline.synthetic_input in baseline.parameters
            and probe.synthetic_input in probe.parameters
        )
        if not runtime_control:
            return False
        observed_control = any(
            SourceAuditVerifier._sanitizer_matches(item, hypothesis)
            for analysis in analyses
            for item in analysis.sanitizers
        )
        return observed_control or runtime_control

    @staticmethod
    def _sanitizer_matches(
        sanitizer: SanitizerObservation,
        hypothesis: DataflowHypothesis,
    ) -> bool:
        return (
            sanitizer.kind == "parameterized_query"
            and sanitizer.file == hypothesis.sink.file
            and sanitizer.line == hypothesis.sink.line
            and sanitizer.sink_call == hypothesis.sink.call
        )

    @staticmethod
    def _source_influence_captured(
        validation: HypothesisValidationResult,
    ) -> bool:
        baseline = validation.baseline_observation
        probe = validation.probe_observation
        sink = validation.intercepted_sink
        return (
            baseline.synthetic_input != probe.synthetic_input
            and sink.query_text_changed is True
            and baseline.synthetic_input in baseline.query_text
            and probe.synthetic_input in probe.query_text
            and sink.side_effect_suppressed is True
        )

    @staticmethod
    def _evidence_ids(evidence: Sequence[Evidence], run_id: UUID) -> list[UUID]:
        return [item.evidence_id for item in evidence if item.run_id == run_id]

    @staticmethod
    def _insufficient(evidence_ids: list[UUID]) -> VerificationVerdict:
        return VerificationVerdict(
            outcome=VerificationOutcome.INSUFFICIENT,
            reason_codes=["INSUFFICIENT_EVIDENCE"],
            evidence_ids=evidence_ids,
            summary="The evidence chain does not establish an external source-to-sink hypothesis.",
        )


__all__ = ["SOURCE_AUDIT_VERIFIER_ID", "SourceAuditVerifier"]
