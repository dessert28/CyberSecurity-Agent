"""Safe lifecycle for materializing one source ZIP as a read-only input."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import os
import re
import shutil
import stat
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

from cyber_agent.contracts import (
    SOURCE_ARCHIVE_CONTAINER_PATH,
    ArtifactMaterializationRequest,
    ArtifactMaterializerPort,
    MaterializedArtifactInput,
)
from cyber_agent.contracts.ports import ArtifactStorePort

_ZIP_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_READ_CHUNK_BYTES = 64 * 1024


class ArtifactMaterializationError(RuntimeError):
    """Safe failure with a stable code and no host-path disclosure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class _MaterializationState:
    directory: Path
    archive_path: Path


class ArtifactMaterializer(ArtifactMaterializerPort):
    """Verify stored ZIP bytes and expose only an opaque read-only lease."""

    def __init__(
        self,
        store: ArtifactStorePort,
        *,
        staging_root: Path,
        max_uncompressed_bytes: int,
        max_members: int,
        max_member_bytes: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, ArtifactStorePort):
            raise TypeError("store does not implement ArtifactStorePort")
        if max_uncompressed_bytes < 1:
            raise ValueError("max_uncompressed_bytes must be positive")
        if max_members < 1:
            raise ValueError("max_members must be positive")
        effective_member_limit = (
            max_uncompressed_bytes if max_member_bytes is None else max_member_bytes
        )
        if effective_member_limit < 1 or effective_member_limit > max_uncompressed_bytes:
            raise ValueError(
                "max_member_bytes must be positive and no larger than max_uncompressed_bytes"
            )

        root = Path(staging_root)
        if not root.is_absolute():
            raise ValueError("staging_root must be an absolute trusted path")
        if root.exists() and root.is_symlink():
            raise ValueError("staging_root must not be a symbolic link")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not root.is_dir():
            raise ValueError("staging_root must be a directory")
        try:
            root.chmod(0o700)
        except OSError as exc:
            raise ValueError("staging_root permissions could not be restricted") from exc

        self._store = store
        self._staging_root = root.resolve(strict=True)
        self._max_uncompressed_bytes = max_uncompressed_bytes
        self._max_members = max_members
        self._max_member_bytes = effective_member_limit
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._leases: dict[UUID, _MaterializationState] = {}
        self._lock = asyncio.Lock()

    async def materialize(
        self,
        request: ArtifactMaterializationRequest,
    ) -> MaterializedArtifactInput:
        self._validate_request(request)
        try:
            stored = await self._store.read_bytes(request.artifact.artifact_id)
        except Exception as exc:
            raise ArtifactMaterializationError(
                "ARTIFACT_STORE_READ_FAILED",
                "Artifact content could not be read from the trusted store.",
            ) from exc
        if not isinstance(stored, bytes):
            raise ArtifactMaterializationError(
                "ARTIFACT_STORE_RESULT_INVALID",
                "Artifact store returned an invalid content type.",
            )

        self._validate_content(request, stored)
        self._validate_zip(stored)

        materialization_id = uuid4()
        directory: Path | None = None
        try:
            directory = Path(
                tempfile.mkdtemp(
                    prefix=f"artifact-{materialization_id}-",
                    dir=self._staging_root,
                )
            )
            if directory.parent.resolve(strict=True) != self._staging_root:
                raise ArtifactMaterializationError(
                    "MATERIALIZATION_PATH_DENIED",
                    "Materialization directory escaped the trusted staging root.",
                )
            directory.chmod(0o700)
            archive_path = directory / "source.zip"
            self._write_read_only(archive_path, stored)
        except ArtifactMaterializationError:
            if directory is not None:
                self._remove_directory_safely(directory)
            raise
        except Exception as exc:
            if directory is not None:
                self._remove_directory_safely(directory)
            raise ArtifactMaterializationError(
                "MATERIALIZATION_WRITE_FAILED",
                "Verified artifact could not be written to isolated staging.",
            ) from exc

        try:
            created_at = self._clock()
            lease = MaterializedArtifactInput(
                materialization_id=materialization_id,
                run_id=request.run_id,
                artifact_id=request.artifact.artifact_id,
                artifact_sha256=request.expected_sha256,
                media_type=request.expected_media_type,
                size_bytes=len(stored),
                container_path=SOURCE_ARCHIVE_CONTAINER_PATH,
                read_only=True,
                created_at=created_at,
                expires_at=created_at
                + timedelta(seconds=request.lease_ttl_seconds),
            )
        except Exception as exc:
            self._remove_directory_safely(directory)
            raise ArtifactMaterializationError(
                "MATERIALIZATION_LEASE_INVALID",
                "Materialization lease metadata could not be created safely.",
            ) from exc
        async with self._lock:
            self._leases[materialization_id] = _MaterializationState(
                directory=directory,
                archive_path=archive_path,
            )
        return lease

    async def cleanup(self, materialization_id: UUID) -> None:
        async with self._lock:
            state = self._leases.get(materialization_id)
            if state is None:
                return
            try:
                self._remove_directory_safely(state.directory)
            except Exception as exc:
                raise ArtifactMaterializationError(
                    "MATERIALIZATION_CLEANUP_FAILED",
                    "Materialized artifact could not be cleaned safely.",
                ) from exc
            self._leases.pop(materialization_id, None)

    @staticmethod
    def _validate_request(request: ArtifactMaterializationRequest) -> None:
        if request.artifact.sha256 != request.expected_sha256:
            raise ArtifactMaterializationError(
                "ARTIFACT_HASH_BINDING_INVALID",
                "Artifact metadata does not match the trusted hash binding.",
            )
        if (
            request.artifact.media_type != "application/zip"
            or request.expected_media_type != "application/zip"
        ):
            raise ArtifactMaterializationError(
                "ARTIFACT_MEDIA_TYPE_DENIED",
                "Only application/zip source artifacts may be materialized.",
            )
        if request.container_path != SOURCE_ARCHIVE_CONTAINER_PATH:
            raise ArtifactMaterializationError(
                "MATERIALIZATION_PATH_DENIED",
                "Source artifacts may use only the fixed container input path.",
            )
        if request.read_only is not True:
            raise ArtifactMaterializationError(
                "WRITABLE_ARTIFACT_INPUT_DENIED",
                "Materialized artifact inputs must be read-only.",
            )
        if request.artifact.size_bytes > request.max_size_bytes:
            raise ArtifactMaterializationError(
                "ARTIFACT_SIZE_EXCEEDED",
                "Artifact metadata exceeds the configured size limit.",
            )

    @staticmethod
    def _validate_content(
        request: ArtifactMaterializationRequest,
        content: bytes,
    ) -> None:
        if len(content) > request.max_size_bytes:
            raise ArtifactMaterializationError(
                "ARTIFACT_SIZE_EXCEEDED",
                "Artifact content exceeds the configured size limit.",
            )
        if len(content) != request.artifact.size_bytes:
            raise ArtifactMaterializationError(
                "ARTIFACT_SIZE_MISMATCH",
                "Artifact content size does not match trusted metadata.",
            )
        actual_sha256 = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(actual_sha256, request.expected_sha256):
            raise ArtifactMaterializationError(
                "ARTIFACT_HASH_MISMATCH",
                "Artifact content does not match the trusted SHA-256 digest.",
            )

    def _validate_zip(self, content: bytes) -> None:
        if not content.startswith(_ZIP_PREFIXES):
            raise ArtifactMaterializationError(
                "ARTIFACT_NOT_ZIP",
                "Artifact content is not a supported ZIP archive.",
            )
        try:
            archive = zipfile.ZipFile(io.BytesIO(content), mode="r")
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise ArtifactMaterializationError(
                "ARTIFACT_ZIP_CORRUPT",
                "ZIP archive structure is invalid or corrupted.",
            ) from exc

        try:
            members = archive.infolist()
            if len(members) > self._max_members:
                raise ArtifactMaterializationError(
                    "ARTIFACT_ZIP_TOO_MANY_MEMBERS",
                    "ZIP archive contains too many members.",
                )

            declared_size = 0
            normalized_names: set[str] = set()
            for member in members:
                normalized_name = self._validate_member_name(member.filename)
                duplicate_key = normalized_name.casefold()
                if duplicate_key in normalized_names:
                    raise ArtifactMaterializationError(
                        "ARTIFACT_ZIP_DUPLICATE_MEMBER",
                        "ZIP archive contains duplicate member names.",
                    )
                normalized_names.add(duplicate_key)
                if member.flag_bits & 0x1:
                    raise ArtifactMaterializationError(
                        "ARTIFACT_ZIP_ENCRYPTED",
                        "Encrypted ZIP members cannot be validated safely.",
                    )
                member_mode = member.external_attr >> 16
                member_type = stat.S_IFMT(member_mode)
                if member_type == stat.S_IFLNK:
                    raise ArtifactMaterializationError(
                        "ARTIFACT_ZIP_SYMLINK",
                        "ZIP symbolic-link members are forbidden.",
                    )
                if member_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise ArtifactMaterializationError(
                        "ARTIFACT_ZIP_SPECIAL_FILE",
                        "ZIP special-file members are forbidden.",
                    )
                declared_size += member.file_size
                if declared_size > self._max_uncompressed_bytes:
                    raise ArtifactMaterializationError(
                        "ARTIFACT_ZIP_TOO_LARGE",
                        "ZIP uncompressed size exceeds the configured limit.",
                    )
                if member.file_size > self._max_member_bytes:
                    raise ArtifactMaterializationError(
                        "ARTIFACT_ZIP_MEMBER_TOO_LARGE",
                        "A ZIP member exceeds the configured size limit.",
                    )

            observed_size = 0
            for member in members:
                if member.is_dir():
                    continue
                member_size = 0
                with archive.open(member, mode="r") as source:
                    while chunk := source.read(_READ_CHUNK_BYTES):
                        member_size += len(chunk)
                        observed_size += len(chunk)
                        if observed_size > self._max_uncompressed_bytes:
                            raise ArtifactMaterializationError(
                                "ARTIFACT_ZIP_TOO_LARGE",
                                "ZIP expanded content exceeds the configured limit.",
                            )
                        if member_size > self._max_member_bytes:
                            raise ArtifactMaterializationError(
                                "ARTIFACT_ZIP_MEMBER_TOO_LARGE",
                                "A ZIP member exceeds the configured size limit.",
                            )
                if member_size != member.file_size:
                    raise ArtifactMaterializationError(
                        "ARTIFACT_ZIP_CORRUPT",
                        "ZIP member size does not match its directory record.",
                    )
        except ArtifactMaterializationError:
            raise
        except (
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            RuntimeError,
            EOFError,
            NotImplementedError,
        ) as exc:
            raise ArtifactMaterializationError(
                "ARTIFACT_ZIP_CORRUPT",
                "ZIP members could not be validated completely.",
            ) from exc
        finally:
            archive.close()

    @staticmethod
    def _validate_member_name(name: str) -> str:
        if not name or "\x00" in name:
            raise ArtifactMaterializationError(
                "ARTIFACT_ZIP_SLIP",
                "ZIP member path is invalid.",
            )
        normalized = name.replace("\\", "/")
        path = PurePosixPath(normalized)
        if (
            normalized.startswith("/")
            or _DRIVE_PREFIX.match(normalized)
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ArtifactMaterializationError(
                "ARTIFACT_ZIP_SLIP",
                "ZIP member path escapes the logical archive root.",
            )
        return path.as_posix().rstrip("/")

    @staticmethod
    def _write_read_only(path: Path, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        path.chmod(stat.S_IRUSR)

    def _remove_directory_safely(self, directory: Path) -> None:
        if directory.parent.resolve(strict=True) != self._staging_root:
            raise ArtifactMaterializationError(
                "MATERIALIZATION_PATH_DENIED",
                "Cleanup target escaped the trusted staging root.",
            )
        if not directory.exists() and not directory.is_symlink():
            return
        if directory.is_symlink():
            directory.unlink()
            return
        archive_path = directory / "source.zip"
        if archive_path.exists() and not archive_path.is_symlink():
            archive_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        shutil.rmtree(directory)


__all__ = ["ArtifactMaterializationError", "ArtifactMaterializer"]
