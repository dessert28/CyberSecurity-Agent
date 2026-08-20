"""Deterministic append-only in-memory audit storage for integration runs."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from cyber_agent.contracts.audit import AuditEventType, AuditRecord
from cyber_agent.contracts.common import ActorRef, EntityRef


class AuditStoreError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def audit_event_hash(record: AuditRecord) -> str:
    payload = record.model_dump(mode="json", exclude={"event_hash"})
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_audit_record(
    *,
    run_id: UUID,
    sequence: int,
    timestamp: datetime,
    actor: ActorRef,
    event_type: AuditEventType,
    outcome: str,
    reason_codes: list[str],
    correlation_id: UUID,
    subject_refs: list[EntityRef] | None = None,
    input_refs: list[EntityRef] | None = None,
    policy_ref: UUID | None = None,
    model_call_ref: UUID | None = None,
    causation_id: UUID | None = None,
    previous_hash: str | None = None,
) -> AuditRecord:
    provisional = AuditRecord(
        run_id=run_id,
        sequence=sequence,
        timestamp=timestamp,
        actor=actor,
        event_type=event_type,
        subject_refs=subject_refs or [],
        input_refs=input_refs or [],
        outcome=outcome,
        reason_codes=reason_codes,
        policy_ref=policy_ref,
        model_call_ref=model_call_ref,
        correlation_id=correlation_id,
        causation_id=causation_id,
        previous_hash=previous_hash,
        event_hash="0" * 64,
    )
    return provisional.model_copy(update={"event_hash": audit_event_hash(provisional)})


class InMemoryAuditStore:
    """AuditStorePort implementation that verifies every append operation."""

    def __init__(self) -> None:
        self._records: dict[UUID, list[AuditRecord]] = {}
        self._lock = asyncio.Lock()

    async def append(self, record: AuditRecord) -> None:
        async with self._lock:
            records = self._records.setdefault(record.run_id, [])
            expected_sequence = len(records) + 1
            if record.sequence != expected_sequence:
                raise AuditStoreError(
                    "AUDIT_SEQUENCE_INVALID",
                    f"expected sequence {expected_sequence}, got {record.sequence}",
                )
            expected_previous = records[-1].event_hash if records else None
            if record.previous_hash != expected_previous:
                raise AuditStoreError(
                    "AUDIT_PREVIOUS_HASH_INVALID",
                    "audit record does not reference the current chain head",
                )
            if record.event_hash != audit_event_hash(record):
                raise AuditStoreError(
                    "AUDIT_EVENT_HASH_INVALID",
                    "audit record hash does not match its canonical payload",
                )
            if any(existing.event_id == record.event_id for existing in records):
                raise AuditStoreError(
                    "AUDIT_EVENT_DUPLICATE",
                    "audit event ID already exists in this run",
                )
            records.append(record.model_copy(deep=True))

    async def list_by_run(self, run_id: UUID) -> Sequence[AuditRecord]:
        async with self._lock:
            return tuple(
                record.model_copy(deep=True)
                for record in self._records.get(run_id, [])
            )
