"""Single-command local launcher for the Workbench and Admin Console."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlencode

import uvicorn

from cyber_agent.api.workbench import create_workbench_app
from cyber_agent.application.admin_console import AdminConsoleService
from cyber_agent.application.artifact_upload import ArtifactUploadService
from cyber_agent.application.run_management import CompetitionRunManager, InMemoryRunStore
from cyber_agent.application.run_history import SQLiteRunHistory
from cyber_agent.application.runtime_factory import (
    RealRuntimeFactory,
    SourceAuditExecutorProvider,
)
from cyber_agent.application.runtime_readiness import RuntimeReadinessService
from cyber_agent.application.source_audit_budget import SourceAuditResourceBudget
from cyber_agent.artifacts import ArtifactMaterializer, InMemoryArtifactStore
from cyber_agent.audit_store import SQLiteAuditStore
from cyber_agent.executor import UnavailableSourceWorkerGuard, WindowsSourceWorkerGuard
from cyber_agent.task_packs import build_competition_task_pack_catalog
from cyber_agent.task_packs.source_audit import (
    SOURCE_AUDIT_TASK_PACK_ID,
    SOURCE_AUDIT_VERIFIER_ID,
)
from cyber_agent.task_packs.web_idor import WEB_IDOR_VERIFIER_ID
from cyber_agent.tools import (
    ToolRegistry,
    build_competition_tool_registry,
    expected_competition_tool_ids,
)
from cyber_agent.verification import SourceAuditVerifier, VerifierRegistry, WebIdorVerifier
from cyber_agent.workbench import LocalWorkspaceManager
from cyber_agent.workbench.adapters import ModelAdapterFactory
from cyber_agent.workbench.capabilities import ModelCapabilityService
from cyber_agent.workbench.credentials import CredentialStore, WindowsCredentialStore
from cyber_agent.workbench.endpoint_policy import (
    ModelEndpointPolicy,
    SecureDohFallbackResolver,
    load_model_presets,
)
from cyber_agent.workbench.profiles import ModelProfileStore
from cyber_agent.workbench.schemas import ReadinessState, WorkbenchMode
from cyber_agent.workbench.store import WorkbenchStore

logger = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class ServerStartupError(RuntimeError):
    """Safe startup failure suitable for a deployment console."""


@dataclass(slots=True)
class LocalServerBundle:
    app: object
    host: str
    port: int
    destination: Literal["admin", "workbench"]
    launch_token: str = field(repr=False)

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def page_url(self) -> str:
        return f"{self.origin}/{'admin' if self.destination == 'admin' else ''}".rstrip("/")

    @property
    def exchange_url(self) -> str:
        query = urlencode(
            {"token": self.launch_token, "destination": self.destination}
        )
        return f"{self.origin}/session/exchange?{query}"


def build_local_server(
    *,
    port: int = DEFAULT_PORT,
    destination: Literal["admin", "workbench"] = "admin",
    runtime_root: Path | None = None,
    credential_store: CredentialStore | None = None,
    launch_token: str | None = None,
) -> LocalServerBundle:
    """Assemble the real local application with persistent deployment state."""

    if not 1 <= port <= 65_535:
        raise ServerStartupError("Port must be between 1 and 65535.")
    if destination not in {"admin", "workbench"}:
        raise ServerStartupError("Destination must be admin or workbench.")

    data_root = (runtime_root or (_REPOSITORY_ROOT / "var" / "workbench")).resolve()
    try:
        data_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ServerStartupError("Workbench data directory could not be created.") from exc

    credentials = credential_store
    if credentials is None:
        try:
            credentials = WindowsCredentialStore()
        except Exception as exc:
            raise ServerStartupError(
                "Windows Credential Manager is unavailable; model keys will not be stored."
            ) from exc

    database = WorkbenchStore(
        database_path=data_root / "state.db",
        runtime_root=data_root,
    )
    run_history = SQLiteRunHistory(database_path=data_root / "state.db")
    asyncio.run(run_history.interrupt_active_runs())
    asyncio.run(
        run_history.purge_expired(
            older_than=datetime.now(timezone.utc) - timedelta(days=30),
        )
    )
    profiles = ModelProfileStore(
        database=database,
        mode=WorkbenchMode.DEVELOPMENT,
        credentials=credentials,
    )
    endpoint_policy = ModelEndpointPolicy(resolver=SecureDohFallbackResolver())
    adapter_factory = ModelAdapterFactory(
        credentials=credentials,
        endpoint_policy=endpoint_policy,
    )
    capabilities = ModelCapabilityService(
        profiles=profiles,
        adapter_factory=adapter_factory,
        docker_probe=probe_docker,
    )

    catalog = build_competition_task_pack_catalog()
    source_budget = SourceAuditResourceBudget()
    artifact_store = InMemoryArtifactStore()
    artifact_materializer = ArtifactMaterializer(
        artifact_store,
        staging_root=(data_root / "source-artifacts").resolve(),
        max_uncompressed_bytes=source_budget.max_uncompressed_bytes,
        max_members=source_budget.max_members,
        max_member_bytes=source_budget.max_member_bytes,
    )
    artifact_upload = ArtifactUploadService(
        store=artifact_store,
        materializer=artifact_materializer,
        resource_budget=source_budget,
    )

    # Initialize workspace manager for task isolation
    workspace_manager = LocalWorkspaceManager(root=data_root / "workspaces")

    # Initialize SQLite audit store for persistent decision trails
    audit_store = SQLiteAuditStore(db_path=data_root / "audit.db")

    try:
        source_worker_guard = WindowsSourceWorkerGuard(budget=source_budget)
    except Exception:
        source_worker_guard = UnavailableSourceWorkerGuard()
    source_executor_provider = SourceAuditExecutorProvider(
        budget=source_budget,
        artifact_reader=artifact_store.read_bytes,
        worker_guard=source_worker_guard,
        platform=("windows/job-object" if sys.platform == "win32" else "unsupported"),
    )
    asyncio.run(source_executor_provider.initialize())
    def source_runtime_available() -> bool:
        try:
            return (
                source_executor_provider.readiness(SOURCE_AUDIT_TASK_PACK_ID)
                is ReadinessState.READY
            )
        except Exception:
            return False

    tools, tool_registration_failures = asyncio.run(
        _build_tool_registry(
            runtime_available=source_runtime_available,
            docker_probe=probe_docker,
        )
    )
    if tool_registration_failures:
        logger.warning(
            "tool registration incomplete missing_tool_ids=%s",
            tool_registration_failures,
        )
    runtime_factory = RealRuntimeFactory(
        profiles=profiles,
        capabilities=capabilities,
        adapter_factory=adapter_factory,
        executor_provider=source_executor_provider,
        catalog=catalog,
        artifact_resolver=artifact_upload.resolve,
        tool_registry=tools,
        docker_probe=probe_docker,
    )
    formal_run_manager = CompetitionRunManager(
        service=None,
        store=InMemoryRunStore(),
        runtime_preparer=runtime_factory,
        history=run_history,
        artifact_cleanup=artifact_store.delete,
    )
    runtime_readiness = RuntimeReadinessService(
        model_probe=capabilities.runtime_readiness,
        core_probe=runtime_factory.core_readiness,
        taskpack_ids=tuple(item.task_pack_id for item in catalog.list()),
        taskpack_probe=runtime_factory.taskpack_readiness,
        taskpack_detail_probe=runtime_factory.taskpack_readiness_detail,
    )
    verifiers = _build_verifier_registry()
    admin_console = AdminConsoleService(
        profiles=profiles,
        capabilities=capabilities,
        task_packs=catalog,
        verifier_registry=verifiers,
        tool_registry=tools,
    )
    token = launch_token or secrets.token_urlsafe(48)
    app = create_workbench_app(
        launch_token=token,
        origin=f"http://{DEFAULT_HOST}:{port}",
        profiles=profiles,
        capabilities=capabilities,
        preset_catalog=load_model_presets(_REPOSITORY_ROOT / "config" / "model-presets.yaml"),
        artifact_uploads=artifact_upload,
        run_manager=formal_run_manager,
        admin_console=admin_console,
        runtime_readiness=runtime_readiness,
    )
    app.state.real_runtime_factory = runtime_factory
    app.state.formal_run_manager = formal_run_manager
    app.state.run_history = run_history
    app.state.source_audit_budget = source_budget
    app.state.source_artifact_store = artifact_store
    app.state.source_artifact_upload = artifact_upload
    app.state.source_worker_guard = source_worker_guard
    app.state.workspace_manager = workspace_manager
    app.state.audit_store = audit_store
    app.state.tool_registry = tools
    app.state.expected_tool_ids = expected_competition_tool_ids()
    return LocalServerBundle(
        app=app,
        host=DEFAULT_HOST,
        port=port,
        destination=destination,
        launch_token=token,
    )


async def _build_tool_registry(
    *,
    runtime_available: Callable[[], bool],
    docker_probe: Callable[[], tuple[bool, str]],
) -> tuple[ToolRegistry, tuple[str, ...]]:
    return await build_competition_tool_registry(
        runtime_available=runtime_available,
        docker_probe=docker_probe,
    )


def _build_verifier_registry() -> VerifierRegistry:
    registry = VerifierRegistry()
    for verifier_id, verifier in (
        (WEB_IDOR_VERIFIER_ID, WebIdorVerifier()),
        (SOURCE_AUDIT_VERIFIER_ID, SourceAuditVerifier()),
    ):
        try:
            registry.register(verifier_id, verifier)
            logger.info("verifier registered verifier_id=%s", verifier_id)
        except Exception as exc:
            logger.error(
                "verifier registration failed verifier_id=%s error=%s",
                verifier_id,
                type(exc).__name__,
                exc_info=True,
            )
    return registry


def probe_docker() -> tuple[bool, str]:
    """Check the local Docker engine without changing Docker state."""

    executable = _docker_executable()
    if executable is None:
        return False, "Docker CLI was not found."
    startup = None
    if sys.platform == "win32":
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        completed = subprocess.run(
            [executable, "version", "--format", "{{.Server.Version}}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
            shell=False,
            startupinfo=startup,
        )
    except (OSError, subprocess.SubprocessError):
        return False, "Docker availability check failed safely."
    version = completed.stdout.strip()
    if completed.returncode != 0 or not version:
        return False, "Docker engine is unavailable."
    return True, f"Docker engine {version} is available."


def _docker_executable() -> str | None:
    configured = os.environ.get("CYBER_AGENT_DOCKER_PATH", "").strip()
    candidates = [
        configured,
        shutil.which("docker") or "",
        str(
            Path(os.environ.get("ProgramFiles", "C:/Program Files"))
            / "Docker"
            / "Docker"
            / "resources"
            / "bin"
            / "docker.exe"
        ),
        str(
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Programs"
            / "DockerDesktop"
            / "resources"
            / "bin"
            / "docker.exe"
        ),
        str(
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Programs"
            / "Docker"
            / "Docker"
            / "resources"
            / "bin"
            / "docker.exe"
        ),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            if Path(candidate).is_file():
                return str(Path(candidate).resolve())
        except OSError:
            continue
    return None


def serve(
    *,
    port: int = DEFAULT_PORT,
    destination: Literal["admin", "workbench"] = "admin",
    open_browser: bool = True,
    runtime_root: Path | None = None,
    launch_token: str | None = None,
) -> int:
    """Run one loopback-only server and open its authenticated browser page."""

    if not _port_is_available(DEFAULT_HOST, port):
        print(
            f"启动失败：{DEFAULT_HOST}:{port} 已被其他程序占用。",
            file=sys.stderr,
        )
        return 2
    try:
        bundle = build_local_server(
            port=port,
            destination=destination,
            runtime_root=runtime_root,
            launch_token=launch_token,
        )
    except ServerStartupError as exc:
        print(f"启动失败：{exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            f"启动失败：本地应用组装失败（{type(exc).__name__}）。",
            file=sys.stderr,
        )
        return 2

    if open_browser:
        threading.Thread(
            target=_open_when_ready,
            args=(bundle,),
            daemon=True,
        ).start()
    else:
        print(f"测试启动地址：{bundle.exchange_url}")

    print(f"管理控制台将运行在 {bundle.page_url}")
    print("按 Ctrl+C 可安全停止本地服务。")
    config = uvicorn.Config(
        bundle.app,
        host=bundle.host,
        port=bundle.port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    try:
        server.run()
    except KeyboardInterrupt:
        return 0
    except OSError:
        print("启动失败：本地服务无法绑定指定端口。", file=sys.stderr)
        return 2
    return 0 if server.started else 2


def _port_is_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind((host, port))
        except OSError:
            return False
    return True


def _open_when_ready(bundle: LocalServerBundle) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((bundle.host, bundle.port), timeout=0.25):
                break
        except OSError:
            time.sleep(0.1)
    else:
        print("启动失败：本地服务未能在预期时间内就绪。", file=sys.stderr)
        return
    if not webbrowser.open(bundle.exchange_url, new=2):
        print(f"浏览器未能自动打开，请重新运行启动脚本。页面地址：{bundle.page_url}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="启动网络安全智能体本地控制台")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument("--admin", action="store_true", help="打开部署管理页（默认）")
    destination.add_argument("--workbench", action="store_true", help="打开任务工作台")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    destination: Literal["admin", "workbench"] = (
        "workbench" if args.workbench else "admin"
    )
    runtime_override = os.environ.get("CYBER_AGENT_RUNTIME_ROOT", "").strip()
    token_override = os.environ.get("CYBER_AGENT_LAUNCH_TOKEN", "").strip()
    return serve(
        port=args.port,
        destination=destination,
        open_browser=not args.no_browser,
        runtime_root=Path(runtime_override) if runtime_override else None,
        launch_token=token_override or None,
    )


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "LocalServerBundle",
    "ServerStartupError",
    "build_local_server",
    "main",
    "probe_docker",
    "serve",
]
