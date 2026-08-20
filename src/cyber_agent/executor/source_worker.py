"""Fixed framed worker protocol for deterministic Source Audit analyzers."""

from __future__ import annotations

import re
import struct
import sys
from typing import Literal

from pydantic import model_validator

from cyber_agent.contracts.common import StableCode, StrictModel
from cyber_agent.contracts.source_audit_budget import SourceAuditResourceBudget
from cyber_agent.contracts.tool import ExecutionRequest, NetworkMode, RunnerType
from cyber_agent.tools.source_handlers import SOURCE_HANDLER_IDS, execute_source_handler

_MAX_METADATA_BYTES = 1_000_000
_MAX_ARCHIVE_BYTES = 10_000_000
_MAX_RESPONSE_METADATA_BYTES = 64_000
_STABLE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")


class SourceWorkerProtocolError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SourceWorkerRequest(StrictModel):
    handler_id: Literal[
        "source.project_inventory",
        "source.python_dataflow",
        "source.hypothesis_validate",
    ]
    request: ExecutionRequest
    budget: SourceAuditResourceBudget

    @model_validator(mode="after")
    def validate_worker_boundary(self) -> "SourceWorkerRequest":
        request = self.request
        if (
            request.runner is not RunnerType.SOURCE_ANALYSIS
            or request.entrypoint != [self.handler_id]
            or request.image is not None
            or request.environment
            or request.network_policy.mode is not NetworkMode.NONE
            or len(request.mounts) != 1
            or request.mounts[0].container_path != "/inputs/source.zip"
            or request.mounts[0].read_only is not True
            or request.resources.cpu_cores > self.budget.cpu_cores
            or request.resources.memory_megabytes > self.budget.memory_megabytes
            or request.resources.max_processes != self.budget.max_processes
            or request.resources.max_output_bytes > self.budget.output_limit_for(
                self.handler_id
            )
            or request.timeout_seconds > self.budget.timeout_for(self.handler_id)
        ):
            raise ValueError("worker request exceeds the formal Source Audit boundary")
        return self


class SourceWorkerResponse(StrictModel):
    ok: bool
    error_code: StableCode | None = None
    safe_message: str | None = None

    @model_validator(mode="after")
    def validate_response(self) -> "SourceWorkerResponse":
        if self.ok and (self.error_code is not None or self.safe_message is not None):
            raise ValueError("successful worker response cannot contain an error")
        if not self.ok and (not self.error_code or not self.safe_message):
            raise ValueError("failed worker response requires a safe error")
        return self


def execute_worker_request(request: SourceWorkerRequest, source_zip: bytes) -> bytes:
    if not isinstance(source_zip, bytes):
        raise SourceWorkerProtocolError(
            "SOURCE_ANALYSIS_ARTIFACT_INVALID",
            "Worker source archive must be bytes.",
        )
    if len(source_zip) > request.budget.max_upload_bytes:
        raise SourceWorkerProtocolError(
            "ARTIFACT_SIZE_EXCEEDED",
            "Source archive exceeds the configured compressed-size limit.",
        )
    return execute_source_handler(
        request.handler_id,
        request.request,
        source_zip,
        request.budget,
    )


def encode_worker_request(request: SourceWorkerRequest, source_zip: bytes) -> bytes:
    metadata = request.model_dump_json().encode("utf-8")
    if len(metadata) > _MAX_METADATA_BYTES:
        raise SourceWorkerProtocolError(
            "SOURCE_WORKER_METADATA_LIMIT",
            "Worker request metadata exceeds the protocol limit.",
        )
    if len(source_zip) > _MAX_ARCHIVE_BYTES:
        raise SourceWorkerProtocolError(
            "ARTIFACT_SIZE_EXCEEDED",
            "Source archive exceeds the worker protocol limit.",
        )
    return (
        struct.pack(">I", len(metadata))
        + metadata
        + struct.pack(">Q", len(source_zip))
        + source_zip
    )


def decode_worker_response(metadata: bytes, output: bytes) -> bytes:
    try:
        response = SourceWorkerResponse.model_validate_json(metadata)
    except Exception as exc:
        raise SourceWorkerProtocolError(
            "SOURCE_WORKER_RESPONSE_INVALID",
            "Source worker returned invalid response metadata.",
        ) from exc
    if not response.ok:
        raise SourceWorkerProtocolError(response.error_code, response.safe_message)
    return output


def main() -> int:
    try:
        metadata_size = struct.unpack(">I", _read_exact(sys.stdin.buffer, 4))[0]
        if not 1 <= metadata_size <= _MAX_METADATA_BYTES:
            raise SourceWorkerProtocolError(
                "SOURCE_WORKER_METADATA_LIMIT",
                "Worker request metadata exceeds the protocol limit.",
            )
        metadata = _read_exact(sys.stdin.buffer, metadata_size)
        archive_size = struct.unpack(">Q", _read_exact(sys.stdin.buffer, 8))[0]
        if archive_size > _MAX_ARCHIVE_BYTES:
            raise SourceWorkerProtocolError(
                "ARTIFACT_SIZE_EXCEEDED",
                "Source archive exceeds the worker protocol limit.",
            )
        source_zip = _read_exact(sys.stdin.buffer, archive_size)
        request = SourceWorkerRequest.model_validate_json(metadata)
        output = execute_worker_request(request, source_zip)
        response = SourceWorkerResponse(ok=True).model_dump_json().encode("utf-8")
        _write_response(response, output)
        return 0
    except MemoryError:
        _write_error(
            "SOURCE_ANALYSIS_MEMORY_LIMIT",
            "Source analysis exceeded its memory limit.",
        )
    except Exception as exc:
        code = getattr(exc, "code", "SOURCE_ANALYSIS_WORKER_FAILED")
        trusted_error = isinstance(code, str) and _STABLE_CODE.fullmatch(code)
        if not trusted_error:
            code = "SOURCE_ANALYSIS_WORKER_FAILED"
        safe_message = (
            str(exc) if trusted_error else "Source analysis failed safely."
        )
        _write_error(code, safe_message)
    return 2


def _read_exact(stream, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(size - len(chunks))
        if not chunk:
            raise SourceWorkerProtocolError(
                "SOURCE_WORKER_FRAME_TRUNCATED",
                "Source worker request frame is truncated.",
            )
        chunks.extend(chunk)
    return bytes(chunks)


def _write_response(metadata: bytes, output: bytes) -> None:
    if len(metadata) > _MAX_RESPONSE_METADATA_BYTES:
        metadata = SourceWorkerResponse(
            ok=False,
            error_code="SOURCE_WORKER_RESPONSE_INVALID",
            safe_message="Source worker response metadata exceeded its limit.",
        ).model_dump_json().encode("utf-8")
        output = b""
    stream = sys.stdout.buffer
    stream.write(struct.pack(">I", len(metadata)))
    stream.write(metadata)
    stream.write(struct.pack(">Q", len(output)))
    stream.write(output)
    stream.flush()


def _write_error(code: str, message: str) -> None:
    response = SourceWorkerResponse(
        ok=False,
        error_code=code,
        safe_message=message[:2_000],
    ).model_dump_json().encode("utf-8")
    _write_response(response, b"")


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "SourceWorkerProtocolError",
    "SourceWorkerRequest",
    "SourceWorkerResponse",
    "decode_worker_response",
    "encode_worker_request",
    "execute_worker_request",
    "main",
]
