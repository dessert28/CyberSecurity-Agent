"""SQLite persistence for non-secret workbench state."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterator
from uuid import UUID

from cyber_agent.workbench.schemas import (
    CapabilityProbeRecord,
    ModelCheckStatus,
    ProviderType,
    RunMode,
)

_SCHEMA_VERSION = 2


class RunConflictError(RuntimeError):
    """Raised when a second active run is requested."""


class StoredRunStatus(str, Enum):
    PREFLIGHT = "preflight"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"
    INTERRUPTED = "interrupted"


_ACTIVE_RUN_STATUSES = {
    StoredRunStatus.PREFLIGHT,
    StoredRunStatus.AWAITING_CONFIRMATION,
    StoredRunStatus.RUNNING,
}


@dataclass(frozen=True, slots=True)
class StoredModelProfile:
    profile_id: UUID
    display_name: str
    name_key: str
    provider: ProviderType
    base_url: str
    model_id: str
    credential_present: bool
    credential_version: int
    check_status: ModelCheckStatus
    check_fingerprint: str | None
    check_message: str | None
    checked_at: datetime | None
    security_default: bool
    created_at: datetime
    updated_at: datetime
    current_probe_id: UUID | None = None

    def __post_init__(self) -> None:
        if self.credential_version < 0:
            raise ValueError("credential_version cannot be negative")
        _require_utc(self.created_at)
        _require_utc(self.updated_at)
        if self.checked_at is not None:
            _require_utc(self.checked_at)


@dataclass(frozen=True, slots=True)
class StoredRun:
    run_id: UUID
    mode: RunMode
    status: StoredRunStatus
    profile_id: UUID | None
    created_at: datetime
    updated_at: datetime
    last_step: str | None
    error_code: str | None
    result_relative_path: str | None


class WorkbenchStore:
    """Own the single-writer SQLite boundary and repository-relative references."""

    def __init__(self, *, database_path: str | Path, runtime_root: str | Path) -> None:
        self._runtime_root = Path(runtime_root).resolve()
        self._database_path = Path(database_path).resolve()
        if not self._database_path.is_relative_to(self._runtime_root):
            raise ValueError("database_path must stay within runtime_root")
        self._runtime_root.mkdir(parents=True, exist_ok=True)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize_schema()
        self._recover_active_runs()

    @property
    def schema_version(self) -> int:
        with self._lock, self._connection() as connection:
            return int(connection.execute("PRAGMA user_version").fetchone()[0])

    @property
    def database_path(self) -> Path:
        return self._database_path

    def upsert_profile(self, profile: StoredModelProfile) -> None:
        values = (
            str(profile.profile_id),
            profile.display_name,
            profile.name_key,
            profile.provider.value,
            profile.base_url,
            profile.model_id,
            int(profile.credential_present),
            profile.credential_version,
            profile.check_status.value,
            profile.check_fingerprint,
            profile.check_message,
            _format_datetime(profile.checked_at),
            int(profile.security_default),
            _format_datetime(profile.created_at),
            _format_datetime(profile.updated_at),
            str(profile.current_probe_id) if profile.current_probe_id is not None else None,
        )
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO model_profiles (
                    profile_id, display_name, name_key, provider, base_url, model_id,
                    credential_present, credential_version, check_status,
                    check_fingerprint, check_message, checked_at, security_default,
                    created_at, updated_at, current_probe_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(profile_id) DO UPDATE SET
                    display_name=excluded.display_name,
                    name_key=excluded.name_key,
                    provider=excluded.provider,
                    base_url=excluded.base_url,
                    model_id=excluded.model_id,
                    credential_present=excluded.credential_present,
                    credential_version=excluded.credential_version,
                    check_status=excluded.check_status,
                    check_fingerprint=excluded.check_fingerprint,
                    check_message=excluded.check_message,
                    checked_at=excluded.checked_at,
                    security_default=excluded.security_default,
                    updated_at=excluded.updated_at,
                    current_probe_id=excluded.current_probe_id
                """,
                values,
            )

    def record_capability_probe(self, probe: CapabilityProbeRecord) -> None:
        """Persist immutable probe evidence and point the profile at that evidence."""

        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute(
                "SELECT 1 FROM model_profiles WHERE profile_id = ?",
                (str(probe.profile_id),),
            ).fetchone()
            if exists is None:
                raise KeyError(f"unknown model profile {probe.profile_id}")
            connection.execute(
                """
                INSERT INTO capability_probes (
                    probe_id, profile_id, provider, model_id, base_url_fingerprint,
                    endpoint_snapshot_fingerprint, credential_version,
                    capability_contract_version, status, reason_code, checked_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(probe.probe_id),
                    str(probe.profile_id),
                    probe.provider.value,
                    probe.model_id,
                    probe.base_url_fingerprint,
                    probe.endpoint_snapshot_fingerprint,
                    probe.credential_version,
                    probe.capability_contract_version,
                    probe.status.value,
                    probe.reason_code,
                    _format_datetime(probe.checked_at),
                    _format_datetime(probe.expires_at),
                ),
            )
            connection.execute(
                "UPDATE model_profiles SET current_probe_id = ? WHERE profile_id = ?",
                (str(probe.probe_id), str(probe.profile_id)),
            )

    def get_current_capability_probe(self, profile_id: UUID) -> CapabilityProbeRecord | None:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                """
                SELECT probe.*
                FROM model_profiles AS profile
                LEFT JOIN capability_probes AS probe
                    ON probe.probe_id = profile.current_probe_id
                WHERE profile.profile_id = ?
                """,
                (str(profile_id),),
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown model profile {profile_id}")
        if row["probe_id"] is None:
            return None
        return _probe_from_row(row)

    def list_profiles(self) -> list[StoredModelProfile]:
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM model_profiles ORDER BY created_at, profile_id"
            ).fetchall()
        return [_profile_from_row(row) for row in rows]

    def get_profile(self, profile_id: UUID) -> StoredModelProfile:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM model_profiles WHERE profile_id = ?",
                (str(profile_id),),
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown model profile {profile_id}")
        return _profile_from_row(row)

    def delete_profile(self, profile_id: UUID) -> None:
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM model_profiles WHERE profile_id = ?",
                (str(profile_id),),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown model profile {profile_id}")

    def has_active_run(self) -> bool:
        with self._lock, self._connection() as connection:
            placeholders = ", ".join("?" for _ in _ACTIVE_RUN_STATUSES)
            row = connection.execute(
                f"SELECT 1 FROM runs WHERE status IN ({placeholders}) LIMIT 1",
                tuple(status.value for status in _ACTIVE_RUN_STATUSES),
            ).fetchone()
        return row is not None

    def set_current_profile(self, profile_id: UUID | None) -> None:
        with self._lock, self._connection() as connection:
            if profile_id is not None:
                exists = connection.execute(
                    "SELECT 1 FROM model_profiles WHERE profile_id = ?",
                    (str(profile_id),),
                ).fetchone()
                if exists is None:
                    raise KeyError(f"unknown model profile {profile_id}")
            connection.execute(
                "UPDATE workbench_state SET current_profile_id = ? WHERE singleton = 1",
                (str(profile_id) if profile_id is not None else None,),
            )

    def get_current_profile_id(self) -> UUID | None:
        with self._lock, self._connection() as connection:
            value = connection.execute(
                "SELECT current_profile_id FROM workbench_state WHERE singleton = 1"
            ).fetchone()[0]
        return UUID(value) if value is not None else None

    def create_run(
        self,
        *,
        run_id: UUID,
        mode: RunMode,
        profile_id: UUID | None,
    ) -> StoredRun:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            placeholders = ", ".join("?" for _ in _ACTIVE_RUN_STATUSES)
            active = connection.execute(
                f"SELECT run_id FROM runs WHERE status IN ({placeholders}) LIMIT 1",
                tuple(status.value for status in _ACTIVE_RUN_STATUSES),
            ).fetchone()
            if active is not None:
                raise RunConflictError("another workbench run is active")
            connection.execute(
                """
                INSERT INTO runs (
                    run_id, mode, status, profile_id, created_at, updated_at,
                    last_step, error_code, result_relative_path
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                """,
                (
                    str(run_id),
                    mode.value,
                    StoredRunStatus.PREFLIGHT.value,
                    str(profile_id) if profile_id is not None else None,
                    _format_datetime(now),
                    _format_datetime(now),
                ),
            )
        return self.get_run(run_id)

    def update_run_status(
        self,
        run_id: UUID,
        status: StoredRunStatus,
        *,
        last_step: str | None = None,
        error_code: str | None = None,
    ) -> None:
        if last_step is not None and len(last_step) > 1_000:
            raise ValueError("last_step is too long")
        if error_code is not None and len(error_code) > 128:
            raise ValueError("error_code is too long")
        with self._lock, self._connection() as connection:
            if status in _ACTIVE_RUN_STATUSES:
                connection.execute("BEGIN IMMEDIATE")
                placeholders = ", ".join("?" for _ in _ACTIVE_RUN_STATUSES)
                other_active = connection.execute(
                    f"""
                    SELECT run_id FROM runs
                    WHERE run_id != ? AND status IN ({placeholders})
                    LIMIT 1
                    """,
                    (
                        str(run_id),
                        *(item.value for item in _ACTIVE_RUN_STATUSES),
                    ),
                ).fetchone()
                if other_active is not None:
                    raise RunConflictError("another workbench run is active")
            cursor = connection.execute(
                """
                UPDATE runs
                SET status = ?, updated_at = ?,
                    last_step = COALESCE(?, last_step), error_code = ?
                WHERE run_id = ?
                """,
                (
                    status.value,
                    _format_datetime(datetime.now(timezone.utc)),
                    last_step,
                    error_code,
                    str(run_id),
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown run {run_id}")

    def set_run_result(self, run_id: UUID, relative_path: str) -> None:
        normalized = _validate_result_reference(run_id, relative_path)
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "UPDATE runs SET result_relative_path = ?, updated_at = ? WHERE run_id = ?",
                (
                    normalized,
                    _format_datetime(datetime.now(timezone.utc)),
                    str(run_id),
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown run {run_id}")

    def get_run(self, run_id: UUID) -> StoredRun:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (str(run_id),)
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown run {run_id}")
        return _run_from_row(row)

    def checkpoint(self) -> None:
        with self._lock, self._connection() as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()

    def _initialize_schema(self) -> None:
        with self._lock, self._connection() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > _SCHEMA_VERSION:
                raise RuntimeError("workbench database schema is newer than this application")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS model_profiles (
                    profile_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    name_key TEXT NOT NULL UNIQUE,
                    provider TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    credential_present INTEGER NOT NULL CHECK (credential_present IN (0, 1)),
                    credential_version INTEGER NOT NULL CHECK (credential_version >= 0),
                    check_status TEXT NOT NULL,
                    check_fingerprint TEXT,
                    check_message TEXT,
                    checked_at TEXT,
                    security_default INTEGER NOT NULL CHECK (security_default IN (0, 1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS workbench_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    current_profile_id TEXT REFERENCES model_profiles(profile_id) ON DELETE SET NULL
                );

                INSERT OR IGNORE INTO workbench_state (singleton, current_profile_id)
                VALUES (1, NULL);

                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    profile_id TEXT REFERENCES model_profiles(profile_id) ON DELETE RESTRICT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_step TEXT,
                    error_code TEXT,
                    result_relative_path TEXT
                );
                """
            )
            if version < 2:
                connection.execute("ALTER TABLE model_profiles ADD COLUMN current_probe_id TEXT")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS capability_probes (
                    probe_id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL REFERENCES model_profiles(profile_id) ON DELETE CASCADE,
                    provider TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    base_url_fingerprint TEXT NOT NULL,
                    endpoint_snapshot_fingerprint TEXT,
                    credential_version INTEGER NOT NULL CHECK (credential_version >= 0),
                    capability_contract_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS capability_probes_profile_checked
                    ON capability_probes(profile_id, checked_at);
                """
            )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def _recover_active_runs(self) -> None:
        now = _format_datetime(datetime.now(timezone.utc))
        with self._lock, self._connection() as connection:
            placeholders = ", ".join("?" for _ in _ACTIVE_RUN_STATUSES)
            connection.execute(
                f"""
                UPDATE runs
                SET status = ?, error_code = ?, updated_at = ?
                WHERE status IN ({placeholders})
                """,
                (
                    StoredRunStatus.INTERRUPTED.value,
                    "WORKBENCH_RESTARTED",
                    now,
                    *(status.value for status in _ACTIVE_RUN_STATUSES),
                ),
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            with connection:
                yield connection
        finally:
            connection.close()


def _profile_from_row(row: sqlite3.Row) -> StoredModelProfile:
    return StoredModelProfile(
        profile_id=UUID(row["profile_id"]),
        display_name=row["display_name"],
        name_key=row["name_key"],
        provider=ProviderType(row["provider"]),
        base_url=row["base_url"],
        model_id=row["model_id"],
        credential_present=bool(row["credential_present"]),
        credential_version=int(row["credential_version"]),
        check_status=ModelCheckStatus(row["check_status"]),
        check_fingerprint=row["check_fingerprint"],
        check_message=row["check_message"],
        checked_at=_parse_datetime(row["checked_at"]),
        security_default=bool(row["security_default"]),
        created_at=_parse_datetime(row["created_at"]),
        updated_at=_parse_datetime(row["updated_at"]),
        current_probe_id=(
            UUID(row["current_probe_id"]) if row["current_probe_id"] is not None else None
        ),
    )


def _probe_from_row(row: sqlite3.Row) -> CapabilityProbeRecord:
    return CapabilityProbeRecord(
        probe_id=UUID(row["probe_id"]),
        profile_id=UUID(row["profile_id"]),
        provider=ProviderType(row["provider"]),
        model_id=row["model_id"],
        base_url_fingerprint=row["base_url_fingerprint"],
        endpoint_snapshot_fingerprint=row["endpoint_snapshot_fingerprint"],
        credential_version=int(row["credential_version"]),
        capability_contract_version=row["capability_contract_version"],
        status=ModelCheckStatus(row["status"]),
        reason_code=row["reason_code"],
        checked_at=_parse_datetime(row["checked_at"]),
        expires_at=_parse_datetime(row["expires_at"]),
    )


def _run_from_row(row: sqlite3.Row) -> StoredRun:
    return StoredRun(
        run_id=UUID(row["run_id"]),
        mode=RunMode(row["mode"]),
        status=StoredRunStatus(row["status"]),
        profile_id=UUID(row["profile_id"]) if row["profile_id"] is not None else None,
        created_at=_parse_datetime(row["created_at"]),
        updated_at=_parse_datetime(row["updated_at"]),
        last_step=row["last_step"],
        error_code=row["error_code"],
        result_relative_path=row["result_relative_path"],
    )


def _format_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _require_utc(value).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must include a timezone")
    return value.astimezone(timezone.utc)


def _validate_result_reference(run_id: UUID, value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("result path must use repository-relative POSIX notation")
    if PureWindowsPath(value).is_absolute():
        raise ValueError("result path cannot be absolute")
    path = PurePosixPath(value)
    expected = PurePosixPath("runs", str(run_id), "result.json")
    if path.is_absolute() or ".." in path.parts or path != expected:
        raise ValueError("result path must match the run-scoped result location")
    return path.as_posix()


__all__ = [
    "RunConflictError",
    "StoredModelProfile",
    "StoredRun",
    "StoredRunStatus",
    "WorkbenchStore",
]
