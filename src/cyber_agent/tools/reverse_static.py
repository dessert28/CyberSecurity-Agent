"""Offline static extraction for the reverse keycheck scenario.

This is the string/constant recovery capability (Apktool/readelf/angr flavor):
it recovers the file format, the transform constant, and the embedded target
bytes from a fixed keycheck binary without executing it.
"""

from __future__ import annotations

import hashlib
import json
import struct
from collections.abc import Callable
from datetime import datetime, timezone
from uuid import UUID

from pydantic import Field

from cyber_agent.contracts.common import (
    ErrorCategory,
    ErrorInfo,
    RiskLevel,
    Sha256,
    StrictModel,
)
from cyber_agent.contracts.tool import (
    ExecutionProfile,
    ExecutionRequest,
    MountSpec,
    NetworkPolicy,
    RawExecutionResult,
    ResourceLimits,
    RunnerType,
    SideEffect,
    ToolHealth,
    ToolInvocation,
    ToolInvocationStatus,
    ToolPermissions,
    ToolRef,
    ToolResult,
    ToolResultStatus,
    ToolSpec,
)

from .health import ToolHealthMixin
from .validation import ArgumentValidationError, validate_arguments

REVERSE_STATIC_EXTRACT_TOOL_ID = "reverse.static_extract"
REVERSE_STATIC_EXTRACT_CAPABILITY = "reverse.static_extract"

_BINARY_INPUT_PATH = "/inputs/source.zip"

_ELF_MAGIC = b"\x7fELF"
_EM_X86_64 = 0x3E
_SHT_SYMTAB = 2
_SHT_PROGBITS = 1
_SHF_ALLOC = 0x2
_SYMBOL_SIZE = 24

_XOR_CONSTANT_SYMBOL = "KEYCHECK_XOR_CONSTANT"
_TARGET_SYMBOL = "KEYCHECK_TARGET"

_DEFAULT_RESOURCES = ResourceLimits(
    cpu_cores=1,
    memory_megabytes=256,
    max_processes=1,
    max_output_bytes=1_000_000,
)


class ReverseStaticError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class StaticExtractResult(StrictModel):
    observation_type: str = Field(default="static_extract", pattern="^static_extract$")
    artifact_id: UUID
    artifact_sha256: Sha256
    file_format: str = Field(min_length=1, max_length=64)
    transform_kind: str = Field(min_length=1, max_length=32)
    transform_constant: int = Field(ge=0, le=255)
    target_bytes: list[int] = Field(default_factory=list)


class ReverseStaticAnalyzer:
    """Recover the xor constant and target bytes from a real keycheck ELF.

    The compiled keycheck keeps ``KEYCHECK_XOR_CONSTANT`` and ``KEYCHECK_TARGET``
    in ``.rodata`` as initialized globals. This analyzer parses the ELF section
    table, locates those symbols in ``.symtab``, and reads their values from the
    mapped file offsets — never executing the binary.
    """

    def analyze(
        self,
        content: bytes,
        *,
        artifact_id: UUID,
        artifact_sha256: str,
    ) -> StaticExtractResult:
        if not isinstance(content, bytes):
            raise ReverseStaticError("BINARY_CONTENT_INVALID", "Binary content must be bytes.")
        digest = hashlib.sha256(content).hexdigest()
        if digest != artifact_sha256:
            raise ReverseStaticError("BINARY_HASH_MISMATCH", "Binary content hash does not match its artifact lease.")

        sections = self._parse_elf(content)
        transform_constant = self._read_symbol_bytes(
            content, sections, _XOR_CONSTANT_SYMBOL, 1
        )[0]
        target_bytes = list(self._read_symbol_bytes(content, sections, _TARGET_SYMBOL, None))
        return StaticExtractResult(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            file_format="elf64-x86-64",
            transform_kind="xor",
            transform_constant=transform_constant,
            target_bytes=target_bytes,
        )

    @staticmethod
    def _parse_elf(content: bytes) -> list[tuple[int, int, int, int, int]]:
        """Return (type, flags, addr, offset, size, link) for each section."""
        if len(content) < 64 or content[:4] != _ELF_MAGIC:
            raise ReverseStaticError("BINARY_NOT_KEYCHECK", "Binary content is not an ELF keycheck program.")
        ident_class = content[4]
        ident_data = content[5]
        if ident_class != 2 or ident_data != 1:
            raise ReverseStaticError("KEYCHECK_LAYOUT_INVALID", "Keycheck must be a 64-bit little-endian ELF.")
        e_machine = struct.unpack_from("<H", content, 18)[0]
        if e_machine != _EM_X86_64:
            raise ReverseStaticError("KEYCHECK_LAYOUT_INVALID", "Keycheck must be an x86-64 ELF.")
        e_shoff = struct.unpack_from("<Q", content, 40)[0]
        e_shentsize, e_shnum = struct.unpack_from("<HH", content, 58)
        sections: list[tuple[int, int, int, int, int]] = []
        for index in range(e_shnum):
            offset = e_shoff + index * e_shentsize
            if offset + 64 > len(content):
                break
            sh_type = struct.unpack_from("<I", content, offset + 4)[0]
            sh_flags = struct.unpack_from("<Q", content, offset + 8)[0]
            sh_addr = struct.unpack_from("<Q", content, offset + 16)[0]
            sh_offset = struct.unpack_from("<Q", content, offset + 24)[0]
            sh_size = struct.unpack_from("<Q", content, offset + 32)[0]
            sh_link = struct.unpack_from("<I", content, offset + 40)[0]
            sections.append((sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link))
        return sections

    @classmethod
    def _symbol_address(
        cls,
        content: bytes,
        sections: list[tuple[int, int, int, int, int]],
        symbol_name: str,
    ) -> tuple[int, int]:
        """Return (address, size) of a symbol, or raise on absence."""
        # Find the .strtab file offset for a symtab section via its sh_link.
        for sh_type, _flags, _addr, sh_offset, sh_size, sh_link in sections:
            if sh_type != _SHT_SYMTAB:
                continue
            strtab_offset = cls._section_offset_by_index(sections, sh_link)
            if strtab_offset <= 0:
                continue
            count = sh_size // _SYMBOL_SIZE
            for index in range(count):
                entry = sh_offset + index * _SYMBOL_SIZE
                if entry + _SYMBOL_SIZE > len(content):
                    break
                st_name = struct.unpack_from("<I", content, entry)[0]
                st_value = struct.unpack_from("<Q", content, entry + 8)[0]
                st_size = struct.unpack_from("<Q", content, entry + 16)[0]
                name = cls._read_name(content, strtab_offset + st_name)
                if name == symbol_name:
                    return st_value, st_size
        raise ReverseStaticError(
            "KEYCHECK_SYMBOL_MISSING",
            f"Keycheck ELF does not expose the required {symbol_name} symbol.",
        )

    @staticmethod
    def _section_offset_by_index(
        sections: list[tuple[int, int, int, int, int]],
        index: int,
    ) -> int:
        if index < 0 or index >= len(sections):
            return 0
        return sections[index][3]

    @classmethod
    def _read_symbol_bytes(
        cls,
        content: bytes,
        sections: list[tuple[int, int, int, int, int]],
        symbol_name: str,
        expected_size: int | None,
    ) -> bytes:
        address, size = cls._symbol_address(content, sections, symbol_name)
        length = size if expected_size is None else expected_size
        for sh_type, sh_flags, sh_addr, sh_offset, sh_size, _link in sections:
            if sh_type != _SHT_PROGBITS or not (sh_flags & _SHF_ALLOC):
                continue
            if not (sh_addr <= address < sh_addr + sh_size):
                continue
            start = sh_offset + (address - sh_addr)
            if start + length > len(content):
                raise ReverseStaticError("KEYCHECK_LAYOUT_INVALID", "Keycheck symbol data is truncated.")
            return content[start : start + length]
        raise ReverseStaticError(
            "KEYCHECK_SYMBOL_MISSING",
            f"Keycheck ELF does not map the {symbol_name} symbol to file data.",
        )

    @staticmethod
    def _read_name(content: bytes, offset: int) -> str:
        if offset <= 0 or offset >= len(content):
            return ""
        return content[offset:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")



class ReverseStaticPlugin(ToolHealthMixin):
    """ToolPlugin boundary for the offline static-extraction runner."""

    input_schema = {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "pattern": r"^[0-9a-fA-F-]{36}$"},
            "artifact_sha256": {"type": "string", "pattern": r"^[0-9a-fA-F]{64}$"},
        },
        "required": ["artifact_id", "artifact_sha256"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "observation_type": {"type": "string", "const": "static_extract"},
            "artifact_id": {"type": "string"},
            "artifact_sha256": {"type": "string"},
            "file_format": {"type": "string"},
            "transform_kind": {"type": "string"},
            "transform_constant": {"type": "integer", "minimum": 0, "maximum": 255},
            "target_bytes": {"type": "array", "items": {"type": "integer"}},
        },
        "required": [
            "observation_type",
            "artifact_id",
            "artifact_sha256",
            "file_format",
            "transform_kind",
            "transform_constant",
            "target_bytes",
        ],
        "additionalProperties": False,
    }

    def __init__(self, *, runtime_available: Callable[[], bool] | None = None) -> None:
        self._runtime_available = runtime_available or (lambda: False)
        self._pending: dict[UUID, ToolInvocation] = {}
        self._spec = ToolSpec(
            tool_id=REVERSE_STATIC_EXTRACT_TOOL_ID,
            name="Reverse static extraction",
            version="1.0.0",
            plugin_id="builtin.reverse",
            capabilities=[REVERSE_STATIC_EXTRACT_CAPABILITY],
            description="Offline fact-only extraction of keycheck format, transform, and target bytes.",
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects={SideEffect.FILE_READ},
            risk_level=RiskLevel.R0,
            permissions=ToolPermissions(filesystem_read=True),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                image=None,
                entrypoint=[REVERSE_STATIC_EXTRACT_TOOL_ID],
                default_timeout_seconds=30,
                max_timeout_seconds=60,
                default_resources=_DEFAULT_RESOURCES,
            ),
        )
        fingerprint_source = json.dumps(
            self._spec.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self._environment_fingerprint = hashlib.sha256(fingerprint_source).hexdigest()

    def get_spec(self) -> ToolSpec:
        return self._spec.model_copy(deep=True)

    async def health_check(self) -> ToolHealth:
        return self.probe_health(
            probe=self._runtime_available,
            success_message="source-analysis runtime available",
            failure_message="source-analysis runtime unavailable",
            tool_ref=ToolRef(
                tool_id=REVERSE_STATIC_EXTRACT_TOOL_ID,
                version="1.0.0",
            ),
        )

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        expected = ToolRef(tool_id=REVERSE_STATIC_EXTRACT_TOOL_ID, version="1.0.0")
        if invocation.tool_ref != expected:
            raise ValueError("invocation tool reference does not match reverse.static_extract")
        if invocation.status is not ToolInvocationStatus.APPROVED:
            raise ValueError("only approved static-extract invocations can be prepared")
        if invocation.deadline <= datetime.now(timezone.utc):
            raise ValueError("static-extract invocation deadline has expired")
        arguments = validate_arguments(invocation.validated_arguments, self.input_schema)
        try:
            artifact_id = UUID(arguments["artifact_id"])
        except ValueError as exc:
            raise ArgumentValidationError("artifact_id must be a UUID") from exc
        remaining = int((invocation.deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining < 1:
            raise ValueError("static-extract invocation deadline leaves less than one second")
        request = ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.SOURCE_ANALYSIS,
            image=None,
            entrypoint=[REVERSE_STATIC_EXTRACT_TOOL_ID],
            argv=[],
            mounts=[
                MountSpec(
                    artifact_id=artifact_id,
                    container_path=_BINARY_INPUT_PATH,
                    read_only=True,
                )
            ],
            environment={},
            network_policy=NetworkPolicy(),
            resources=_DEFAULT_RESOURCES.model_copy(deep=True),
            timeout_seconds=min(30, remaining),
        )
        self._pending[request.request_id] = invocation
        return request

    def parse(self, result: RawExecutionResult) -> ToolResult:
        invocation = self._pending.pop(result.request_id, None)
        if invocation is None:
            raise ValueError("raw result does not match a prepared static-extract request")
        status = result.status
        error = result.error
        normalized: dict = {}
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error(
                "REVERSE_STATIC_EXIT_NONZERO",
                "Static extraction exited with a non-zero status.",
            )
        if status is ToolResultStatus.SUCCEEDED:
            try:
                decoded = json.loads(result.stdout.decode("utf-8"))
                extracted = StaticExtractResult.model_validate(decoded)
                if str(extracted.artifact_id) != invocation.validated_arguments["artifact_id"]:
                    raise ValueError("static-extract artifact id mismatch")
                if extracted.artifact_sha256 != invocation.validated_arguments["artifact_sha256"]:
                    raise ValueError("static-extract artifact hash mismatch")
                normalized = extracted.model_dump(mode="json")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                status = ToolResultStatus.FAILED
                error = self._error(
                    "REVERSE_STATIC_OUTPUT_INVALID",
                    "Static extraction returned invalid structured output.",
                )
                normalized = {}
        elif error is None:
            error = self._error(
                "REVERSE_STATIC_EXECUTION_FAILED",
                "Static extraction did not succeed.",
            )
        return ToolResult(
            run_id=invocation.run_id,
            plan_id=invocation.plan_id,
            step_id=invocation.step_id,
            attempt=invocation.attempt,
            tool_ref=invocation.tool_ref,
            validated_arguments=invocation.validated_arguments,
            policy_decision_ref=invocation.policy_decision_ref,
            status=status,
            started_at=result.started_at,
            finished_at=result.finished_at,
            exit_code=result.exit_code,
            normalized_output=normalized,
            artifact_refs=result.output_artifacts,
            error=error,
            environment_fingerprint=self._environment_fingerprint,
        )

    @staticmethod
    def analyze(content: bytes, *, artifact_id: UUID, artifact_sha256: str) -> StaticExtractResult:
        return ReverseStaticAnalyzer().analyze(
            content,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
        )

    @staticmethod
    def _error(code: str, message: str) -> ErrorInfo:
        return ErrorInfo(
            code=code,
            category=ErrorCategory.TOOL_FAILED,
            retryable=False,
            safe_message=message,
        )


__all__ = [
    "REVERSE_STATIC_EXTRACT_CAPABILITY",
    "REVERSE_STATIC_EXTRACT_TOOL_ID",
    "ReverseStaticAnalyzer",
    "ReverseStaticPlugin",
    "ReverseStaticError",
    "StaticExtractResult",
]
