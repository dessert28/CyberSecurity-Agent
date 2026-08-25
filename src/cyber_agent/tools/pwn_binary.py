"""Offline, fact-only ELF64 analysis for the Pwn binary-properties tool.

This is the Checksec/readelf-style static capability: it recovers the machine
architecture, NX/PIE/stack-canary posture, and the ``win``/``vuln``/``buffer``
symbols directly from ELF bytes without ever executing the binary.
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

PWN_BINARY_PROPERTIES_TOOL_ID = "pwn.binary_properties"
PWN_BINARY_PROPERTIES_CAPABILITY = "pwn.binary_properties"

# SourceAnalysisRunner pins its single mount to this fixed path; reuse it so a
# new Pwn tool needs no executor or contract change.
_BINARY_INPUT_PATH = "/inputs/source.zip"

_ELF_MAGIC = b"\x7fELF"
_EM_X86_64 = 0x3E
_ET_EXEC = 2
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PF_X = 0x1
_SHT_SYMTAB = 2
_SHT_STRTAB = 3

_DEFAULT_RESOURCES = ResourceLimits(
    cpu_cores=1,
    memory_megabytes=256,
    max_processes=1,
    max_output_bytes=1_000_000,
)


class PwnBinaryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ProtectionFlags(StrictModel):
    nx: bool
    canary: bool
    pie: bool
    relro: str = Field(min_length=1, max_length=32)


class SymbolRecord(StrictModel):
    present: bool
    address: int = Field(ge=0)
    size: int = Field(ge=0)


class BinaryPropertiesResult(StrictModel):
    observation_type: str = Field(default="binary_properties", pattern="^binary_properties$")
    artifact_id: UUID
    artifact_sha256: Sha256
    architecture: str = Field(min_length=1, max_length=64)
    is_64bit: bool
    endian: str = Field(min_length=1, max_length=16)
    protections: ProtectionFlags
    win_symbol: SymbolRecord
    vuln_symbol: SymbolRecord
    buffer_size: int = Field(ge=0)
    return_offset: int = Field(ge=0)


class BinaryPropertiesAnalyzer:
    """Parse ELF64 headers and symbols; never execute the binary."""

    def analyze(
        self,
        content: bytes,
        *,
        artifact_id: UUID,
        artifact_sha256: str,
    ) -> BinaryPropertiesResult:
        if not isinstance(content, bytes):
            raise PwnBinaryError("BINARY_CONTENT_INVALID", "Binary content must be bytes.")
        digest = hashlib.sha256(content).hexdigest()
        if digest != artifact_sha256:
            raise PwnBinaryError(
                "BINARY_HASH_MISMATCH",
                "Binary content hash does not match its artifact lease.",
            )
        if len(content) < 64 or content[:4] != _ELF_MAGIC:
            raise PwnBinaryError(
                "BINARY_NOT_ELF",
                "Binary content is not a valid ELF file.",
            )

        ident_class = content[4]
        ident_data = content[5]
        is_64bit = ident_class == 2
        endian = "little" if ident_data == 1 else "big"
        if not is_64bit or endian != "little":
            raise PwnBinaryError(
                "BINARY_UNSUPPORTED_LAYOUT",
                "Only 64-bit little-endian ELF binaries are supported.",
            )

        e_type, e_machine = struct.unpack_from("<HH", content, 16)
        e_phoff = struct.unpack_from("<Q", content, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", content, 54)
        e_shoff = struct.unpack_from("<Q", content, 40)[0]
        e_shentsize, e_shnum = struct.unpack_from("<HH", content, 58)

        architecture = "x86-64" if e_machine == _EM_X86_64 else f"machine-{e_machine}"
        if e_machine != _EM_X86_64:
            raise PwnBinaryError(
                "BINARY_UNSUPPORTED_MACHINE",
                "Only x86-64 binaries are supported by this scenario.",
            )

        nx = True
        relro = "none"
        for index in range(e_phnum):
            offset = e_phoff + index * e_phentsize
            if offset + 56 > len(content):
                break
            p_type, p_flags = struct.unpack_from("<II", content, offset)
            if p_type == _PT_GNU_STACK:
                nx = not bool(p_flags & _PF_X)
            elif p_type == _PT_GNU_RELRO:
                relro = "partial"

        symbols: dict[str, SymbolRecord] = {}
        sections: list[tuple[int, int, int, int, int]] = []
        for index in range(e_shnum):
            sh_offset = e_shoff + index * e_shentsize
            if sh_offset + 64 > len(content):
                break
            sh_name, sh_type = struct.unpack_from("<II", content, sh_offset)
            sh_flags = struct.unpack_from("<Q", content, sh_offset + 8)[0]
            sh_addr = struct.unpack_from("<Q", content, sh_offset + 16)[0]
            sh_data_offset = struct.unpack_from("<Q", content, sh_offset + 24)[0]
            sh_size = struct.unpack_from("<Q", content, sh_offset + 32)[0]
            sh_link = struct.unpack_from("<I", content, sh_offset + 40)[0]
            sections.append((sh_type, sh_flags, sh_addr, sh_data_offset, sh_size))
            if sh_type != _SHT_SYMTAB:
                continue
            strtab_offset = self._strtab_offset(
                content,
                e_shoff,
                e_shentsize,
                e_shnum,
                sh_link,
            )
            symbols = self._parse_symbols(
                content,
                sh_data_offset,
                sh_size,
                strtab_offset,
            )

        win = symbols.get("win", SymbolRecord(present=False, address=0, size=0))
        vuln = symbols.get("vuln", SymbolRecord(present=False, address=0, size=0))
        buffer_size = self._recover_buffer_size(content, sections, vuln.address)
        canary = "stack_chk_fail" in symbols
        return BinaryPropertiesResult(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            architecture=architecture,
            is_64bit=is_64bit,
            endian=endian,
            protections=ProtectionFlags(
                nx=nx,
                canary=canary,
                pie=e_type != _ET_EXEC,
                relro=relro,
            ),
            win_symbol=win,
            vuln_symbol=vuln,
            buffer_size=buffer_size,
            return_offset=buffer_size + 8 if buffer_size else 0,
        )

    @staticmethod
    def _strtab_offset(
        content: bytes,
        shoff: int,
        shentsize: int,
        shnum: int,
        link: int,
    ) -> int:
        offset = shoff + link * shentsize
        if offset + 64 > len(content):
            return 0
        return struct.unpack_from("<Q", content, offset + 24)[0]

    @staticmethod
    def _parse_symbols(
        content: bytes,
        symtab_offset: int,
        symtab_size: int,
        strtab_offset: int,
    ) -> dict[str, SymbolRecord]:
        symbols: dict[str, SymbolRecord] = {}
        if symtab_offset <= 0 or strtab_offset <= 0:
            return symbols
        count = symtab_size // 24
        for index in range(count):
            entry = symtab_offset + index * 24
            if entry + 24 > len(content):
                break
            st_name, _st_info, _st_other, _st_shndx = struct.unpack_from(
                "<IBBH",
                content,
                entry,
            )
            st_value = struct.unpack_from("<Q", content, entry + 8)[0]
            st_size = struct.unpack_from("<Q", content, entry + 16)[0]
            name = BinaryPropertiesAnalyzer._read_name(content, strtab_offset + st_name)
            if name:
                symbols[name] = SymbolRecord(present=True, address=st_value, size=st_size)
        return symbols

    @staticmethod
    def _read_name(content: bytes, offset: int) -> str:
        if offset <= 0 or offset >= len(content):
            return ""
        end = content.find(b"\x00", offset)
        if end == -1:
            end = len(content)
        return content[offset:end].decode("utf-8", errors="replace")

    @staticmethod
    def _recover_buffer_size(
        content: bytes,
        sections: list[tuple[int, int, int, int, int]],
        vuln_address: int,
    ) -> int:
        """Recover the vuln() stack buffer size from its prologue.

        A real compiled ret2win has no ``buffer`` symbol: the buffer is a stack
        local. With ``-fno-stack-protector -O0``, gcc emits ``sub rsp, imm`` in
        the prologue; scanning vuln's bytes for that opcode yields the buffer
        size without executing anything.
        """
        if vuln_address == 0:
            return 0
        _SHT_PROGBITS = 1
        _SHF_EXECINSTR = 0x4
        for sh_type, sh_flags, sh_addr, sh_offset, sh_size in sections:
            if sh_type != _SHT_PROGBITS or not (sh_flags & _SHF_EXECINSTR):
                continue
            if not (sh_addr <= vuln_address < sh_addr + sh_size):
                continue
            start = sh_offset + (vuln_address - sh_addr)
            window = content[start : start + 32]
            return BinaryPropertiesAnalyzer._scan_sub_rsp(window)
        return 0

    @staticmethod
    def _scan_sub_rsp(window: bytes) -> int:
        """Return the immediate of ``sub rsp, imm8`` or 0 when absent."""
        # sub rsp, imm8  -> 48 83 EC <imm8>
        # sub rsp, imm32 -> 48 81 EC <imm32:le>
        for index in range(len(window) - 3):
            if window[index] == 0x48 and window[index + 1] == 0x83 and window[index + 2] == 0xEC:
                return window[index + 3]
        for index in range(len(window) - 6):
            if window[index] == 0x48 and window[index + 1] == 0x81 and window[index + 2] == 0xEC:
                return struct.unpack_from("<I", window, index + 3)[0]
        return 0


class BinaryPropertiesPlugin(ToolHealthMixin):
    """ToolPlugin boundary for the dedicated offline ELF-analysis runner."""

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
            "observation_type": {"type": "string", "const": "binary_properties"},
            "artifact_id": {"type": "string"},
            "artifact_sha256": {"type": "string"},
            "architecture": {"type": "string"},
            "is_64bit": {"type": "boolean"},
            "endian": {"type": "string"},
            "protections": {"type": "object"},
            "win_symbol": {"type": "object"},
            "vuln_symbol": {"type": "object"},
            "buffer_size": {"type": "integer", "minimum": 0},
            "return_offset": {"type": "integer", "minimum": 0},
        },
        "required": [
            "observation_type",
            "artifact_id",
            "artifact_sha256",
            "architecture",
            "is_64bit",
            "endian",
            "protections",
            "win_symbol",
            "vuln_symbol",
            "buffer_size",
            "return_offset",
        ],
        "additionalProperties": False,
    }

    def __init__(self, *, runtime_available: Callable[[], bool] | None = None) -> None:
        self._runtime_available = runtime_available or (lambda: False)
        self._pending: dict[UUID, ToolInvocation] = {}
        self._spec = ToolSpec(
            tool_id=PWN_BINARY_PROPERTIES_TOOL_ID,
            name="Pwn binary properties",
            version="1.0.0",
            plugin_id="builtin.pwn",
            capabilities=[PWN_BINARY_PROPERTIES_CAPABILITY],
            description="Offline fact-only ELF64 architecture, protection, and symbol analysis.",
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            side_effects={SideEffect.FILE_READ},
            risk_level=RiskLevel.R0,
            permissions=ToolPermissions(filesystem_read=True),
            execution_profile=ExecutionProfile(
                runner=RunnerType.SOURCE_ANALYSIS,
                image=None,
                entrypoint=[PWN_BINARY_PROPERTIES_TOOL_ID],
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
                tool_id=PWN_BINARY_PROPERTIES_TOOL_ID,
                version="1.0.0",
            ),
        )

    def prepare(self, invocation: ToolInvocation) -> ExecutionRequest:
        expected = ToolRef(tool_id=PWN_BINARY_PROPERTIES_TOOL_ID, version="1.0.0")
        if invocation.tool_ref != expected:
            raise ValueError("invocation tool reference does not match pwn.binary_properties")
        if invocation.status is not ToolInvocationStatus.APPROVED:
            raise ValueError("only approved binary-properties invocations can be prepared")
        if invocation.deadline <= datetime.now(timezone.utc):
            raise ValueError("binary-properties invocation deadline has expired")
        arguments = validate_arguments(invocation.validated_arguments, self.input_schema)
        try:
            artifact_id = UUID(arguments["artifact_id"])
        except ValueError as exc:
            raise ArgumentValidationError("artifact_id must be a UUID") from exc
        remaining = int((invocation.deadline - datetime.now(timezone.utc)).total_seconds())
        if remaining < 1:
            raise ValueError("binary-properties invocation deadline leaves less than one second")
        request = ExecutionRequest(
            invocation_id=invocation.invocation_id,
            runner=RunnerType.SOURCE_ANALYSIS,
            image=None,
            entrypoint=[PWN_BINARY_PROPERTIES_TOOL_ID],
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
            raise ValueError("raw result does not match a prepared binary-properties request")
        status = result.status
        error = result.error
        normalized: dict = {}
        if status is ToolResultStatus.SUCCEEDED and result.exit_code not in (None, 0):
            status = ToolResultStatus.FAILED
            error = self._error(
                "PWN_BINARY_EXIT_NONZERO",
                "Binary properties analysis exited with a non-zero status.",
            )
        if status is ToolResultStatus.SUCCEEDED:
            try:
                decoded = json.loads(result.stdout.decode("utf-8"))
                properties = BinaryPropertiesResult.model_validate(decoded)
                if str(properties.artifact_id) != invocation.validated_arguments["artifact_id"]:
                    raise ValueError("binary-properties artifact id mismatch")
                if properties.artifact_sha256 != invocation.validated_arguments["artifact_sha256"]:
                    raise ValueError("binary-properties artifact hash mismatch")
                normalized = properties.model_dump(mode="json")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                status = ToolResultStatus.FAILED
                error = self._error(
                    "PWN_BINARY_OUTPUT_INVALID",
                    "Binary properties returned invalid structured output.",
                )
                normalized = {}
        elif error is None:
            error = self._error(
                "PWN_BINARY_EXECUTION_FAILED",
                "Binary properties analysis did not succeed.",
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
    def analyze(
        content: bytes,
        *,
        artifact_id: UUID,
        artifact_sha256: str,
    ) -> BinaryPropertiesResult:
        return BinaryPropertiesAnalyzer().analyze(
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
    "PWN_BINARY_PROPERTIES_CAPABILITY",
    "PWN_BINARY_PROPERTIES_TOOL_ID",
    "BinaryPropertiesAnalyzer",
    "BinaryPropertiesPlugin",
    "BinaryPropertiesResult",
    "ProtectionFlags",
    "SymbolRecord",
]
