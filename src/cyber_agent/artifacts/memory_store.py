"""Process-local artifact storage with opaque identifiers only."""

from __future__ import annotations

import hashlib
from uuid import UUID, uuid4

from cyber_agent.contracts.common import ArtifactRef


class InMemoryArtifactStore:
    """Keep uploaded bytes private and expose only logical artifact references."""

    def __init__(self) -> None:
        self._content: dict[UUID, bytes] = {}

    async def put_bytes(
        self,
        content: bytes,
        *,
        media_type: str,
        source_ref: UUID | None = None,
        quarantined: bool = False,
    ) -> ArtifactRef:
        if not isinstance(content, bytes):
            raise TypeError("artifact content must be bytes")
        artifact_id = uuid4()
        stored = bytes(content)
        self._content[artifact_id] = stored
        return ArtifactRef(
            artifact_id=artifact_id,
            logical_uri=f"artifacts/{artifact_id}/source.zip",
            media_type=media_type,
            size_bytes=len(stored),
            sha256=hashlib.sha256(stored).hexdigest(),
            source_ref=source_ref,
            quarantined=quarantined,
        )

    async def read_bytes(self, artifact_id: UUID) -> bytes:
        try:
            return self._content[artifact_id]
        except KeyError as exc:
            raise KeyError("artifact is not present in the trusted store") from exc

    async def delete(self, artifact_id: UUID) -> None:
        """Discard quarantined content; deletion is intentionally idempotent."""

        self._content.pop(artifact_id, None)


__all__ = ["InMemoryArtifactStore"]
