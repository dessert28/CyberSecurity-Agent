"""SQLite-backed audit store for persistent decision trails.

Implements three-table design borrowed from CTF-BTFly:
- tasks: task metadata and status
- decisions: Planner proposals with sequence ordering
- tool_calls: Executor actions linked to decisions

Provides full timeline reconstruction for decision explainability.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class TaskRecord:
    """Persistent task metadata."""

    id: str
    title: str
    category: str
    status: str
    workspace_path: str
    created_at: str
    updated_at: str
    last_error: str = ""


@dataclass
class DecisionRecord:
    """Planner proposal with approval status."""

    id: str
    task_id: str
    sequence: int
    planner_output: str  # JSON-serialized proposal
    risk_level: str
    approved: bool
    created_at: str


@dataclass
class ToolCallRecord:
    """Executor action linked to a decision."""

    id: str
    task_id: str
    decision_id: str
    tool_name: str
    arguments: str  # JSON
    result: str
    status: str
    created_at: str


@dataclass
class ModelUsageRecord:
    """Token usage for cost tracking."""

    id: str
    task_id: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    created_at: str


class SQLiteAuditStore:
    """Persistent audit log with foreign key enforcement."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(db_path), check_same_thread=False, isolation_level="IMMEDIATE"
        )
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def _migrate(self) -> None:
        """Create schema with foreign keys and indexes."""
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL,
            workspace_path TEXT NOT NULL,
            last_error TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS decisions (
            id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL,
            planner_output TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            approved INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(task_id, sequence)
        );
        CREATE INDEX IF NOT EXISTS idx_decisions_task_seq
        ON decisions(task_id, sequence);

        CREATE TABLE IF NOT EXISTS tool_calls (
            id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            decision_id TEXT NOT NULL REFERENCES decisions(id) ON DELETE CASCADE,
            tool_name TEXT NOT NULL,
            arguments TEXT NOT NULL,
            result TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tool_calls_task
        ON tool_calls(task_id, created_at);

        CREATE TABLE IF NOT EXISTS model_usage (
            id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            model TEXT NOT NULL,
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_model_usage_task
        ON model_usage(task_id, created_at);
        """)
        self._conn.commit()

    def create_task(self, task: TaskRecord) -> None:
        """Insert new task record."""
        self._conn.execute(
            """INSERT INTO tasks
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task.id,
                task.title,
                task.category,
                task.status,
                task.workspace_path,
                task.last_error,
                task.created_at,
                task.updated_at,
            ),
        )
        self._conn.commit()

    def update_task_status(
        self, task_id: str, status: str, last_error: str = ""
    ) -> None:
        """Update task status and error message."""
        now = datetime.utcnow().isoformat()
        self._conn.execute(
            """UPDATE tasks
               SET status = ?, last_error = ?, updated_at = ?
               WHERE id = ?""",
            (status, last_error, now, task_id),
        )
        self._conn.commit()

    def append_decision(self, decision: DecisionRecord) -> None:
        """Append decision to task timeline."""
        self._conn.execute(
            """INSERT INTO decisions
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                decision.id,
                decision.task_id,
                decision.sequence,
                decision.planner_output,
                decision.risk_level,
                int(decision.approved),
                decision.created_at,
            ),
        )
        self._conn.commit()

    def append_tool_call(self, call: ToolCallRecord) -> None:
        """Append tool execution record."""
        self._conn.execute(
            """INSERT INTO tool_calls
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                call.id,
                call.task_id,
                call.decision_id,
                call.tool_name,
                call.arguments,
                call.result,
                call.status,
                call.created_at,
            ),
        )
        self._conn.commit()

    def append_model_usage(self, usage: ModelUsageRecord) -> None:
        """Record token usage for cost tracking."""
        self._conn.execute(
            """INSERT INTO model_usage
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                usage.id,
                usage.task_id,
                usage.model,
                usage.input_tokens,
                usage.output_tokens,
                usage.total_tokens,
                usage.created_at,
            ),
        )
        self._conn.commit()

    def get_task_timeline(self, task_id: str) -> list[dict[str, Any]]:
        """Return chronological decision + tool_call timeline."""
        cursor = self._conn.execute(
            """
            SELECT 'decision' as type, sequence, id, planner_output,
                   risk_level, approved, created_at
            FROM decisions WHERE task_id = ?
            UNION ALL
            SELECT 'tool_call' as type, 0 as sequence, id, tool_name,
                   arguments, result, created_at
            FROM tool_calls WHERE task_id = ?
            ORDER BY created_at
            """,
            (task_id, task_id),
        )
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_task(self, task_id: str) -> TaskRecord | None:
        """Retrieve task record by ID."""
        cursor = self._conn.execute(
            "SELECT * FROM tasks WHERE id = ?", (task_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return TaskRecord(
            id=row[0],
            title=row[1],
            category=row[2],
            status=row[3],
            workspace_path=row[4],
            last_error=row[5],
            created_at=row[6],
            updated_at=row[7],
        )

    def list_tasks(self) -> list[TaskRecord]:
        """Return all tasks ordered by creation time."""
        cursor = self._conn.execute(
            "SELECT * FROM tasks ORDER BY created_at DESC"
        )
        return [
            TaskRecord(
                id=row[0],
                title=row[1],
                category=row[2],
                status=row[3],
                workspace_path=row[4],
                last_error=row[5],
                created_at=row[6],
                updated_at=row[7],
            )
            for row in cursor.fetchall()
        ]

    def get_task_token_usage(self, task_id: str) -> dict[str, int]:
        """Aggregate token usage for a task."""
        cursor = self._conn.execute(
            """SELECT SUM(input_tokens), SUM(output_tokens), SUM(total_tokens)
               FROM model_usage WHERE task_id = ?""",
            (task_id,),
        )
        row = cursor.fetchone()
        return {
            "input_tokens": row[0] or 0,
            "output_tokens": row[1] or 0,
            "total_tokens": row[2] or 0,
        }

    def close(self) -> None:
        """Close database connection."""
        self._conn.close()
