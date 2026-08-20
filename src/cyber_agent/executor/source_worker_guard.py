"""Windows Job Object supervision for the fixed Source Audit worker."""

from __future__ import annotations

import asyncio
import ctypes
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from cyber_agent.contracts.source_audit_budget import SourceAuditResourceBudget
from cyber_agent.contracts.tool import ExecutionRequest

from .source_worker import (
    SourceWorkerProtocolError,
    SourceWorkerRequest,
    decode_worker_response,
    encode_worker_request,
)

_CREATE_NO_WINDOW = 0x08000000
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_CPU_RATE_CONTROL_INFORMATION = 15
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1
_JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4
_MAX_RESPONSE_METADATA_BYTES = 64_000


class SourceWorkerGuardError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class UnavailableSourceWorkerGuard:
    """Portable fail-closed guard used when Job Object isolation is unavailable."""

    async def health_check(self) -> bool:
        return False

    async def run(self, request: ExecutionRequest, source_zip: bytes) -> bytes:
        raise SourceWorkerGuardError(
            "SOURCE_WORKER_GUARD_UNAVAILABLE",
            "The Source worker resource guard is unavailable.",
        )

    async def cancel(self, request_id: UUID) -> None:
        return None


@dataclass(slots=True)
class _ActiveWorker:
    process: asyncio.subprocess.Process
    job: "_WindowsJobObject"


class WindowsSourceWorkerGuard:
    """Run exactly one trusted worker under verified Windows OS limits."""

    def __init__(
        self,
        *,
        budget: SourceAuditResourceBudget,
        python_executable: Path | None = None,
    ) -> None:
        if sys.platform != "win32":
            raise SourceWorkerGuardError(
                "SOURCE_WORKER_GUARD_UNAVAILABLE",
                "Windows Job Object resource guard is unavailable.",
            )
        # A Windows virtual-environment launcher creates a second process before
        # starting Python. Launch the base interpreter directly so the Job Object
        # can enforce an actual one-process ceiling.
        executable = Path(python_executable or sys._base_executable)
        if not executable.is_absolute() or not executable.is_file():
            raise SourceWorkerGuardError(
                "SOURCE_WORKER_EXECUTABLE_INVALID",
                "The fixed Source worker executable is unavailable.",
            )
        self._budget = budget
        self._python_executable = executable.resolve(strict=True)
        source_root = Path(__file__).resolve(strict=True).parents[2]
        site_packages = Path(sys.prefix).resolve(strict=True) / "Lib" / "site-packages"
        if not source_root.is_dir() or not site_packages.is_dir():
            raise SourceWorkerGuardError(
                "SOURCE_WORKER_RUNTIME_INVALID",
                "The fixed Source worker runtime is unavailable.",
            )
        module_paths = repr([str(site_packages), str(source_root)])
        self._worker_bootstrap = (
            "import sys;"
            f"sys.path[:0]={module_paths};"
            "from cyber_agent.executor import source_worker;"
            "raise SystemExit(source_worker.main())"
        )
        self._active: dict[UUID, _ActiveWorker] = {}
        self._lock = asyncio.Lock()

    @property
    def active_process_count(self) -> int:
        return len(self._active)

    async def health_check(self) -> bool:
        process = None
        job = None
        try:
            process = await self._spawn()
            job = _WindowsJobObject(self._budget)
            job.assign(process.pid)
            await asyncio.sleep(0.1)
            return process.returncode is None
        except Exception:
            return False
        finally:
            if job is not None:
                job.close()
            elif process is not None and process.returncode is None:
                process.kill()
            if process is not None:
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except Exception:
                    pass

    async def run(self, request: ExecutionRequest, source_zip: bytes) -> bytes:
        worker_request = SourceWorkerRequest(
            handler_id=request.entrypoint[0],
            request=request,
            budget=self._budget,
        )
        payload = encode_worker_request(worker_request, source_zip)
        process = await self._spawn()
        job: _WindowsJobObject | None = None
        registered = False
        try:
            job = _WindowsJobObject(self._budget)
            job.assign(process.pid)
            async with self._lock:
                if request.request_id in self._active:
                    raise SourceWorkerGuardError(
                        "SOURCE_WORKER_DUPLICATE_REQUEST",
                        "A Source worker request is already active.",
                    )
                self._active[request.request_id] = _ActiveWorker(process, job)
                registered = True
            try:
                metadata, output = await asyncio.wait_for(
                    self._exchange(
                        process,
                        payload,
                        request.resources.max_output_bytes,
                    ),
                    timeout=request.timeout_seconds,
                )
            except TimeoutError as exc:
                job.close()
                await _wait_for_exit(process)
                raise SourceWorkerGuardError(
                    "SOURCE_ANALYSIS_TIMEOUT",
                    "Source analysis exceeded its controlled timeout.",
                ) from exc
            return decode_worker_response(metadata, output)
        except SourceWorkerProtocolError as exc:
            raise SourceWorkerGuardError(exc.code, str(exc)) from exc
        finally:
            if registered:
                async with self._lock:
                    self._active.pop(request.request_id, None)
            if job is not None:
                job.close()
            elif process.returncode is None:
                process.kill()
            await _wait_for_exit(process)

    async def cancel(self, request_id: UUID) -> None:
        async with self._lock:
            active = self._active.get(request_id)
        if active is None:
            return
        active.job.close()
        await _wait_for_exit(active.process)

    async def _spawn(self) -> asyncio.subprocess.Process:
        # CPython's Windows asyncio bootstrap requires the trusted OS root variables.
        # No user, model, credential, PATH, proxy, or target-provided value is inherited.
        worker_environment = {
            key: os.environ[key]
            for key in ("SYSTEMROOT", "WINDIR")
            if key in os.environ
        }
        try:
            return await asyncio.create_subprocess_exec(
                str(self._python_executable),
                "-I",
                "-c",
                self._worker_bootstrap,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=worker_environment,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception as exc:
            raise SourceWorkerGuardError(
                "SOURCE_WORKER_START_FAILED",
                "The fixed Source worker could not be started.",
            ) from exc

    async def _exchange(
        self,
        process: asyncio.subprocess.Process,
        payload: bytes,
        max_output_bytes: int,
    ) -> tuple[bytes, bytes]:
        if process.stdin is None or process.stdout is None:
            raise SourceWorkerGuardError(
                "SOURCE_WORKER_PIPE_INVALID",
                "Source worker pipes are unavailable.",
            )
        try:
            process.stdin.write(payload)
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()

            metadata_size = struct.unpack(
                ">I", await process.stdout.readexactly(4)
            )[0]
            if not 1 <= metadata_size <= _MAX_RESPONSE_METADATA_BYTES:
                raise SourceWorkerGuardError(
                    "SOURCE_WORKER_RESPONSE_LIMIT",
                    "Source worker response metadata exceeds its limit.",
                )
            metadata = await process.stdout.readexactly(metadata_size)
            output_size = struct.unpack(
                ">Q", await process.stdout.readexactly(8)
            )[0]
            if output_size > max_output_bytes:
                raise SourceWorkerGuardError(
                    "SOURCE_ANALYSIS_OUTPUT_LIMIT",
                    "Source-analysis output exceeded its configured limit.",
                )
            output = await process.stdout.readexactly(output_size)
            await process.wait()
            if await process.stdout.read(1):
                raise SourceWorkerGuardError(
                    "SOURCE_WORKER_RESPONSE_INVALID",
                    "Source worker returned trailing protocol data.",
                )
            return metadata, output
        except asyncio.IncompleteReadError as exc:
            raise SourceWorkerGuardError(
                "SOURCE_WORKER_RESPONSE_TRUNCATED",
                "Source worker returned a truncated response.",
            ) from exc


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", ctypes.c_ulong),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_ulong),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_ulong),
        ("SchedulingClass", ctypes.c_ulong),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _CpuRateControlInformation(ctypes.Structure):
    _fields_ = [("ControlFlags", ctypes.c_ulong), ("CpuRate", ctypes.c_ulong)]


class _WindowsJobObject:
    def __init__(self, budget: SourceAuditResourceBudget) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32 = kernel32
        self._configure_signatures()
        self._handle = kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            memory_bytes = budget.memory_megabytes * 1024 * 1024
            limits = _ExtendedLimitInformation()
            limits.BasicLimitInformation.LimitFlags = (
                _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | _JOB_OBJECT_LIMIT_JOB_MEMORY
                | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            limits.BasicLimitInformation.ActiveProcessLimit = budget.max_processes
            limits.ProcessMemoryLimit = memory_bytes
            limits.JobMemoryLimit = memory_bytes
            self._set_information(
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                limits,
            )

            cpu = _CpuRateControlInformation()
            cpu.ControlFlags = (
                _JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                | _JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
            )
            cpu.CpuRate = max(
                1,
                min(10_000, int(10_000 * budget.cpu_cores / (os.cpu_count() or 1))),
            )
            self._set_information(_JOB_OBJECT_CPU_RATE_CONTROL_INFORMATION, cpu)
        except Exception:
            self.close()
            raise

    def assign(self, pid: int) -> None:
        process = self._kernel32.OpenProcess(
            _PROCESS_TERMINATE
            | _PROCESS_SET_QUOTA
            | _PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            pid,
        )
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self._kernel32.AssignProcessToJobObject(self._handle, process):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self._kernel32.CloseHandle(process)

    def close(self) -> None:
        handle = getattr(self, "_handle", None)
        if handle:
            self._kernel32.CloseHandle(handle)
            self._handle = None

    def _set_information(self, information_class: int, value: ctypes.Structure) -> None:
        if not self._kernel32.SetInformationJobObject(
            self._handle,
            information_class,
            ctypes.byref(value),
            ctypes.sizeof(value),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def _configure_signatures(self) -> None:
        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self._kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        self._kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]
        self._kernel32.SetInformationJobObject.restype = ctypes.c_int
        self._kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        self._kernel32.OpenProcess.restype = ctypes.c_void_p
        self._kernel32.AssignProcessToJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        self._kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self._kernel32.CloseHandle.restype = ctypes.c_int


async def _wait_for_exit(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except TimeoutError:
        process.kill()
        await process.wait()


__all__ = [
    "SourceWorkerGuardError",
    "UnavailableSourceWorkerGuard",
    "WindowsSourceWorkerGuard",
]
