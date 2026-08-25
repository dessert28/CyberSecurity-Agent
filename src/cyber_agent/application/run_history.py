"""Durable, local-only projections for formal workbench runs."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from pydantic import Field

from cyber_agent.application.run_management import (
    ManagedRunRecord,
    RunAuditResponse,
    RunSummaryResponse,
)
from cyber_agent.contracts.audit import AuditEventType, AuditRecord
from cyber_agent.contracts.common import StrictModel, UtcDateTime
from cyber_agent.contracts.plan import RunStatus


class RunHistoryItem(StrictModel):
    run_id: UUID
    task_pack: str
    status: RunStatus
    request_preview: str = Field(max_length=280)
    request_text: str = Field(max_length=100_000)
    created_at: UtcDateTime
    updated_at: UtcDateTime
    error_code: str | None = None


class RunHistoryListResponse(StrictModel):
    items: tuple[RunHistoryItem, ...]


class RunHistoryError(ValueError):
    pass


class SQLiteRunHistory:
    """Persist safe run projections without retaining uploaded artifacts."""

    def __init__(
        self,
        *,
        database_path: str | Path,
        retention: timedelta = timedelta(days=30),
    ) -> None:
        if retention <= timedelta(0):
            raise ValueError("retention must be positive")
        self._database_path = Path(database_path).resolve()
        self._retention = retention
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self._initialize()

    async def save(
        self,
        record: ManagedRunRecord,
        *,
        summary: RunSummaryResponse,
        audit_events: tuple[AuditRecord, ...],
    ) -> None:
        updated_at = datetime.now(timezone.utc)
        summary_json = summary.model_dump_json()
        async with self._lock:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO formal_run_history (
                        run_id, task_pack_id, request_text, status, created_at,
                        updated_at, error_code, summary_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(run_id) DO UPDATE SET
                        status=excluded.status,
                        updated_at=excluded.updated_at,
                        error_code=excluded.error_code,
                        summary_json=excluded.summary_json
                    """,
                    (
                        str(record.run_id),
                        record.task_pack_id,
                        record.request_text,
                        record.status.value,
                        _format_datetime(record.created_at),
                        _format_datetime(updated_at),
                        summary.error_code or record.error_code,
                        summary_json,
                    ),
                )
                connection.execute("DELETE FROM formal_run_audit WHERE run_id = ?", (str(record.run_id),))
                connection.executemany(
                    """
                    INSERT INTO formal_run_audit (run_id, sequence, event_json)
                    VALUES (?, ?, ?)
                    """,
                    [
                        (str(record.run_id), event.sequence, event.model_dump_json())
                        for event in audit_events
                    ],
                )
                self._purge_before(connection, updated_at - self._retention)

    async def get_summary(self, run_id: UUID) -> RunSummaryResponse:
        async with self._lock:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT summary_json FROM formal_run_history WHERE run_id = ?",
                    (str(run_id),),
                ).fetchone()
                if row is not None:
                    summary = RunSummaryResponse.model_validate_json(row["summary_json"])
                    error_code = self._recover_interruption_error_code(
                        connection,
                        run_id,
                        summary,
                    )
                    if error_code is not None and summary.error_code is None:
                        summary.error_code = error_code
                        connection.execute(
                            """
                            UPDATE formal_run_history
                            SET error_code = ?, summary_json = ?
                            WHERE run_id = ?
                            """,
                            (error_code, summary.model_dump_json(), str(run_id)),
                        )
        if row is None:
            raise RunHistoryError("run history was not found")
        return summary

    async def get_audit(self, run_id: UUID, *, after_sequence: int) -> RunAuditResponse:
        async with self._lock:
            with self._connection() as connection:
                exists = connection.execute(
                    "SELECT 1 FROM formal_run_history WHERE run_id = ?", (str(run_id),)
                ).fetchone()
                rows = connection.execute(
                    """
                    SELECT event_json FROM formal_run_audit
                    WHERE run_id = ? AND sequence > ?
                    ORDER BY sequence ASC
                    """,
                    (str(run_id), after_sequence),
                ).fetchall()
        if exists is None:
            raise RunHistoryError("run history was not found")
        return RunAuditResponse(
            run_id=run_id,
            after_sequence=after_sequence,
            events=tuple(AuditRecord.model_validate_json(row["event_json"]) for row in rows),
        )

    async def list_recent(self, *, limit: int) -> tuple[RunHistoryItem, ...]:
        if limit < 1:
            raise ValueError("limit must be positive")
        async with self._lock:
            with self._connection() as connection:
                self._purge_before(connection, datetime.now(timezone.utc) - self._retention)
                rows = connection.execute(
                    """
                    SELECT run_id, task_pack_id, request_text, status, created_at, updated_at,
                           error_code, summary_json
                    FROM formal_run_history
                    ORDER BY updated_at DESC, run_id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                items: list[RunHistoryItem] = []
                for row in rows:
                    run_id = UUID(row["run_id"])
                    summary = RunSummaryResponse.model_validate_json(row["summary_json"])
                    error_code = row["error_code"] or summary.error_code
                    if error_code is None:
                        error_code = self._recover_interruption_error_code(
                            connection,
                            run_id,
                            summary,
                        )
                    if error_code is not None and row["error_code"] is None:
                        summary.error_code = error_code
                        connection.execute(
                            """
                            UPDATE formal_run_history
                            SET error_code = ?, summary_json = ?
                            WHERE run_id = ?
                            """,
                            (error_code, summary.model_dump_json(), str(run_id)),
                        )
                    items.append(
                        RunHistoryItem(
                            run_id=run_id,
                            task_pack=row["task_pack_id"],
                            status=RunStatus(row["status"]),
                            request_preview=row["request_text"][:280],
                            request_text=row["request_text"],
                            created_at=_parse_datetime(row["created_at"]),
                            updated_at=_parse_datetime(row["updated_at"]),
                            error_code=error_code,
                        )
                    )
        return tuple(items)

    async def interrupt_active_runs(self) -> None:
        active = tuple(status.value for status in RunStatus if status not in _TERMINAL_STATUSES)
        async with self._lock:
            with self._connection() as connection:
                rows = connection.execute(
                    f"SELECT summary_json FROM formal_run_history WHERE status IN ({','.join('?' for _ in active)})",
                    active,
                ).fetchall()
                now = _format_datetime(datetime.now(timezone.utc))
                for row in rows:
                    summary = RunSummaryResponse.model_validate_json(row["summary_json"])
                    summary.status = RunStatus.CANCELLED
                    summary.error_code = "RUN_INTERRUPTED_BY_RESTART"
                    connection.execute(
                        """
                        UPDATE formal_run_history
                        SET status = ?, updated_at = ?, error_code = ?, summary_json = ?
                        WHERE run_id = ?
                        """,
                        (
                            RunStatus.CANCELLED.value,
                            now,
                            "RUN_INTERRUPTED_BY_RESTART",
                            summary.model_dump_json(),
                            str(summary.run_id),
                        ),
                    )

    async def purge_expired(self, *, older_than: datetime) -> int:
        async with self._lock:
            with self._connection() as connection:
                cursor = connection.execute(
                    "DELETE FROM formal_run_history WHERE updated_at < ?",
                    (_format_datetime(older_than),),
                )
                return cursor.rowcount

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS formal_run_history (
                    run_id TEXT PRIMARY KEY,
                    task_pack_id TEXT NOT NULL,
                    request_text TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    error_code TEXT,
                    summary_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS formal_run_audit (
                    run_id TEXT NOT NULL REFERENCES formal_run_history(run_id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    event_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS formal_run_history_updated_at
                    ON formal_run_history(updated_at DESC);
                """
            )

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _recover_interruption_error_code(
        connection: sqlite3.Connection,
        run_id: UUID,
        summary: RunSummaryResponse,
    ) -> str | None:
        if summary.error_code is not None:
            return summary.error_code
        rows = connection.execute(
            """
            SELECT event_json FROM formal_run_audit
            WHERE run_id = ?
            ORDER BY sequence DESC
            """,
            (str(run_id),),
        ).fetchall()
        for row in rows:
            event = AuditRecord.model_validate_json(row["event_json"])
            if event.event_type is AuditEventType.RUN_INTERRUPTED and event.reason_codes:
                return event.reason_codes[0]
        return None

    @staticmethod
    def _purge_before(connection: sqlite3.Connection, older_than: datetime) -> None:
        connection.execute(
            "DELETE FROM formal_run_history WHERE updated_at < ?",
            (_format_datetime(older_than),),
        )


_TERMINAL_STATUSES = {
    RunStatus.COMPLETED,
    RunStatus.FAILED,
    RunStatus.BLOCKED,
    RunStatus.CANCELLED,
}


def _format_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(timezone.utc)


__all__ = [
    "RunHistoryError",
    "RunHistoryItem",
    "RunHistoryListResponse",
    "SQLiteRunHistory",
]
