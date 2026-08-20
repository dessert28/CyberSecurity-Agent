"""Append-only audit event contracts."""

from __future__ import annotations

from enum import Enum
from uuid import UUID, uuid4

from pydantic import Field

from .common import ActorRef, EntityRef, Sha256, StableCode, StrictModel, UtcDateTime


class AuditEventType(str, Enum):
    INPUT_RECEIVED = "input_received"
    TASK_NORMALIZED = "task_normalized"
    RUN_CREATED = "run_created"
    PLAN_PROPOSED = "plan_proposed"
    PLAN_ACCEPTED = "plan_accepted"
    PLAN_REJECTED = "plan_rejected"
    STEP_STATE_CHANGED = "step_state_changed"
    TOOL_CANDIDATES_COMPARED = "tool_candidates_compared"
    POLICY_ALLOWED = "policy_allowed"
    POLICY_DENIED = "policy_denied"
    EXECUTION_STARTED = "execution_started"
    EXECUTION_FINISHED = "execution_finished"
    VERIFICATION_COMPLETED = "verification_completed"
    RETRY_SCHEDULED = "retry_scheduled"
    REPLAN_TRIGGERED = "replan_triggered"
    HUMAN_DECISION = "human_decision"
    RUN_FINISHED = "run_finished"
    RUN_INTERRUPTED = "run_interrupted"


class AuditRecord(StrictModel):
    event_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    sequence: int = Field(ge=1)
    timestamp: UtcDateTime
    actor: ActorRef
    event_type: AuditEventType
    subject_refs: list[EntityRef] = Field(default_factory=list)
    input_refs: list[EntityRef] = Field(default_factory=list)
    outcome: str = Field(min_length=1, max_length=2000)
    reason_codes: list[StableCode] = Field(default_factory=list)
    policy_ref: UUID | None = None
    model_call_ref: UUID | None = None
    correlation_id: UUID
    causation_id: UUID | None = None
    previous_hash: Sha256 | None = None
    event_hash: Sha256
