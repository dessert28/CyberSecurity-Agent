"""Local-only FastAPI delivery layer for the competition workbench."""

from __future__ import annotations

import hmac
import html
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import BackgroundTasks, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from cyber_agent.application.artifact_upload import (
    ArtifactUploadError,
    ArtifactUploadResponse,
    ArtifactUploadService,
)
from cyber_agent.application.admin_console import (
    AdminConnectionTestResult,
    AdminConsoleError,
    AdminConsoleService,
    AdminHealthResponse,
    AdminModelTraceClearResult,
    AdminModelTraceList,
    AdminModelConfigurationRequest,
    AdminModelConfigurationView,
    AdminProviderCatalog,
)
from cyber_agent.model_gateway.io_trace import ModelIoTrace
from cyber_agent.application.run_management import (
    CompetitionRunManager,
    RunAcceptedResponse,
    RunAuditResponse,
    RunCreateRequest,
    RunManagementError,
    RunSummaryResponse,
)
from cyber_agent.application.runtime_readiness import RuntimeReadinessService
from cyber_agent.application.presentation import (
    CompetitionPresentationService,
    DashboardStatusProjection,
    EvidenceListProjection,
    PresentationError,
    RunDisplayProjection,
    RunRecordSourcePort,
    project_dashboard,
)
from cyber_agent.reporting import ReportProjection
from cyber_agent.workbench.capabilities import ModelCapabilityService
from cyber_agent.workbench.credentials import CredentialBackendError
from cyber_agent.workbench.endpoint_policy import ModelPresetCatalog
from cyber_agent.workbench.profiles import (
    ModelProfileStore,
    ProfileError,
    ProfileInUseError,
    ProfileLockedError,
    ProfileNameConflictError,
    ProfileNotReadyError,
)
from cyber_agent.workbench.schemas import (
    ActiveModelProfileRequest,
    ModelCredentialRequest,
    ModelProfileCreateRequest,
    ModelProfileUpdateRequest,
    ModelRuntimeReadiness,
    ReadinessState,
    RuntimeReadinessResponse,
    ShutdownRequest,
    WorkbenchMode,
)
from cyber_agent.workbench.security import SessionManager

SESSION_COOKIE = "cyber_agent_workbench_session"
CSRF_HEADER = "x-csrf-token"
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_API_DIRECTORY = Path(__file__).resolve().parent
_STATIC_DIRECTORY = (_API_DIRECTORY / "static").resolve()
_WORKBENCH_TEMPLATE = (
    _API_DIRECTORY / "templates" / "workbench.html"
).read_text(encoding="utf-8")
_ADMIN_TEMPLATE = (
    _API_DIRECTORY / "templates" / "admin.html"
).read_text(encoding="utf-8")


def create_workbench_app(
    *,
    launch_token: str,
    origin: str,
    profiles: ModelProfileStore | None = None,
    capabilities: ModelCapabilityService | None = None,
    preset_catalog: ModelPresetCatalog | None = None,
    artifact_uploads: ArtifactUploadService | None = None,
    run_manager: CompetitionRunManager | None = None,
    presentation: CompetitionPresentationService | None = None,
    admin_console: AdminConsoleService | None = None,
    runtime_readiness: RuntimeReadinessService | None = None,
) -> FastAPI:
    """Build an isolated application instance for one launcher process."""

    expected_origin, expected_host = _normalize_origin(origin)
    sessions = SessionManager(launch_token=launch_token)
    app = FastAPI(
        title="Cyber Agent Workbench",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.session_manager = sessions
    app.state.expected_origin = expected_origin
    app.state.expected_host = expected_host
    app.state.model_profiles = profiles
    app.state.model_capabilities = capabilities
    app.state.model_presets = preset_catalog
    app.state.artifact_uploads = artifact_uploads
    app.state.run_manager = run_manager
    app.state.admin_console = admin_console
    if runtime_readiness is None:
        capability_model_probe = getattr(capabilities, "runtime_readiness", None)
        model_probe = (
            capability_model_probe
            if callable(capability_model_probe)
            else lambda: ModelRuntimeReadiness(
                ready=False,
                state=ReadinessState.MODEL_NOT_READY,
                reason_codes=(ReadinessState.MODEL_NOT_READY,),
            )
        )
        runtime_readiness = RuntimeReadinessService(
            model_probe=model_probe,
            core_probe=lambda: ReadinessState.REGISTRY_NOT_READY,
            taskpack_ids=("web.idor", "source.audit.python"),
            taskpack_probe=lambda _: ReadinessState.EXECUTOR_NOT_READY,
        )
    app.state.runtime_readiness = runtime_readiness
    if presentation is None and isinstance(run_manager, RunRecordSourcePort):
        presentation = CompetitionPresentationService(source=run_manager)
    app.state.presentation = presentation

    def current_runtime_data_sources() -> dict[str, str]:
        try:
            readiness = runtime_readiness.status()
            runs_live = run_manager is not None and readiness.runtime_available
        except Exception:
            runs_live = False
        projections_live = presentation is not None and run_manager is not None
        return {
            "admin": "live" if admin_console is not None else "unavailable",
            "model_configuration": "live" if profiles is not None else "unavailable",
            "artifact_upload": "live" if artifact_uploads is not None else "unavailable",
            "runs": "live" if runs_live else "unavailable",
            "projection": "live" if projections_live else "unavailable",
            "evidence": "live" if projections_live else "unavailable",
            "audit": "live" if run_manager is not None else "unavailable",
            "report": "unavailable",
        }

    app.state.runtime_data_source = current_runtime_data_sources
    app.mount(
        "/static",
        StaticFiles(directory=_STATIC_DIRECTORY, check_dir=True),
        name="static",
    )

    if (
        profiles is not None
        and profiles.mode is WorkbenchMode.DEVELOPMENT
        and preset_catalog is not None
        and not profiles.list_views()
    ):
        default = next(item for item in preset_catalog.presets if item.security_default)
        profiles.create(
            ModelProfileCreateRequest(
                display_name=default.display_name,
                provider=default.provider,
                base_url=default.base_url,
                model_id=default.model_id,
            ),
            security_default=True,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
        return _secured(
            _error("REQUEST_INVALID", "The request body or parameters are invalid."),
            422,
        )

    @app.exception_handler(ProfileLockedError)
    async def profile_locked(_: Request, __: ProfileLockedError) -> JSONResponse:
        return _secured(
            _error("MODEL_CONFIG_LOCKED", "Competition model configuration is deployment-locked."),
            423,
        )

    @app.exception_handler(ProfileNameConflictError)
    async def profile_name_conflict(_: Request, __: ProfileNameConflictError) -> JSONResponse:
        return _secured(
            _error("MODEL_PROFILE_NAME_CONFLICT", "A model profile with that name already exists."),
            409,
        )

    @app.exception_handler(ProfileInUseError)
    async def profile_in_use(_: Request, __: ProfileInUseError) -> JSONResponse:
        return _secured(
            _error("MODEL_PROFILE_IN_USE", "Model profiles cannot change while a run is active."),
            409,
        )

    @app.exception_handler(ProfileNotReadyError)
    async def profile_not_ready(_: Request, __: ProfileNotReadyError) -> JSONResponse:
        return _secured(
            _error("MODEL_PROFILE_NOT_READY", "Run a successful capability check before activation."),
            409,
        )

    @app.exception_handler(CredentialBackendError)
    async def credential_unavailable(_: Request, __: CredentialBackendError) -> JSONResponse:
        return _secured(
            _error("CREDENTIAL_STORE_UNAVAILABLE", "Secure credential storage is unavailable."),
            503,
        )

    @app.exception_handler(ArtifactUploadError)
    async def artifact_upload_error(
        _: Request,
        exc: ArtifactUploadError,
    ) -> JSONResponse:
        return _secured(_error(exc.code, str(exc)), exc.status_code)

    @app.exception_handler(RunManagementError)
    async def run_management_error(
        _: Request,
        exc: RunManagementError,
    ) -> JSONResponse:
        return _secured(_error(exc.code, str(exc)), exc.status_code)

    @app.exception_handler(PresentationError)
    async def presentation_error(
        _: Request,
        exc: PresentationError,
    ) -> JSONResponse:
        return _secured(_error(exc.code, str(exc)), exc.status_code)

    @app.exception_handler(AdminConsoleError)
    async def admin_console_error(
        _: Request,
        exc: AdminConsoleError,
    ) -> JSONResponse:
        return _secured(_error(exc.code, str(exc)), exc.status_code)

    @app.exception_handler(KeyError)
    async def profile_not_found(_: Request, __: KeyError) -> JSONResponse:
        return _secured(_error("MODEL_PROFILE_NOT_FOUND", "The model profile was not found."), 404)

    @app.exception_handler(ProfileError)
    async def profile_error(_: Request, __: ProfileError) -> JSONResponse:
        return _secured(_error("MODEL_PROFILE_OPERATION_FAILED", "The model profile operation failed."), 409)

    @app.middleware("http")
    async def enforce_local_session(request: Request, call_next):
        if request.headers.get("host", "").lower() != expected_host:
            return _secured(_error("HOST_INVALID", "The request Host is not allowed."), 400)

        if request.url.path != "/session/exchange":
            session_token = request.cookies.get(SESSION_COOKIE, "")
            csrf_token = sessions.csrf_for_session(session_token)
            if csrf_token is None:
                return _secured(
                    _error("SESSION_INVALID", "The local workbench session is missing or invalid."),
                    401,
                )
            request.state.csrf_token = csrf_token

            if request.method.upper() in _WRITE_METHODS:
                if request.headers.get("origin") != expected_origin:
                    return _secured(
                        _error("ORIGIN_INVALID", "The request Origin is not allowed."),
                        403,
                    )
                media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                expected_media_type = (
                    "application/zip"
                    if artifact_uploads is not None
                    and request.url.path == "/api/v1/artifacts"
                    else "application/json"
                )
                if media_type != expected_media_type:
                    return _secured(
                        _error(
                            "CONTENT_TYPE_INVALID",
                            f"This state change requires {expected_media_type}.",
                        ),
                        415,
                    )
                supplied_csrf = request.headers.get(CSRF_HEADER, "")
                if not supplied_csrf or not hmac.compare_digest(supplied_csrf, csrf_token):
                    return _secured(
                        _error("CSRF_INVALID", "The CSRF token is missing or invalid."),
                        403,
                    )

        response = await call_next(request)
        _apply_security_headers(response)
        return response

    @app.get("/session/exchange", include_in_schema=False)
    async def exchange_session(token: str, destination: str = "workbench") -> Response:
        if destination not in {"workbench", "admin"}:
            return _secured(
                _error("SESSION_DESTINATION_INVALID", "The session destination is invalid."),
                400,
            )
        redeemed = sessions.redeem(token)
        if redeemed is None:
            return _secured(
                _error("LAUNCH_TOKEN_INVALID", "The launch token is invalid or already used."),
                401,
            )
        session_token, _ = redeemed
        response = RedirectResponse(
            url="/admin" if destination == "admin" else "/",
            status_code=303,
        )
        response.set_cookie(
            SESSION_COOKIE,
            session_token,
            httponly=True,
            samesite="strict",
            path="/",
        )
        _apply_security_headers(response)
        return response

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def workbench_page(request: Request) -> HTMLResponse:
        csrf_token = html.escape(request.state.csrf_token, quote=True)
        body = _WORKBENCH_TEMPLATE.replace("__CSRF_TOKEN__", csrf_token)
        return HTMLResponse(body)

    @app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
    async def admin_page(request: Request) -> HTMLResponse:
        csrf_token = html.escape(request.state.csrf_token, quote=True)
        body = _ADMIN_TEMPLATE.replace("__CSRF_TOKEN__", csrf_token)
        return HTMLResponse(body)

    @app.get("/api/v1/status")
    async def status():
        if capabilities is not None:
            return capabilities.status()
        return {"service": "available"}

    @app.get("/api/v1/runtime-data-sources")
    async def runtime_data_sources() -> dict[str, str]:
        return current_runtime_data_sources()

    @app.get(
        "/api/v1/runtime-readiness",
        response_model=RuntimeReadinessResponse,
    )
    async def runtime_readiness_status() -> RuntimeReadinessResponse:
        return runtime_readiness.status()

    @app.get(
        "/api/v1/dashboard",
        response_model=DashboardStatusProjection,
    )
    async def dashboard_status() -> DashboardStatusProjection:
        current = capabilities.status() if capabilities is not None else None
        return project_dashboard(current)

    if admin_console is not None:

        @app.get(
            "/api/v1/admin/providers",
            response_model=AdminProviderCatalog,
        )
        async def admin_providers() -> AdminProviderCatalog:
            return admin_console.providers()

        @app.get(
            "/api/v1/admin/configuration",
            response_model=AdminModelConfigurationView,
        )
        async def admin_configuration() -> AdminModelConfigurationView:
            return admin_console.configuration()

        @app.put(
            "/api/v1/admin/configuration",
            response_model=AdminModelConfigurationView,
        )
        async def save_admin_configuration(
            request: AdminModelConfigurationRequest,
        ) -> AdminModelConfigurationView:
            return admin_console.save_configuration(request)

        @app.post(
            "/api/v1/admin/configuration",
            response_model=AdminModelConfigurationView,
        )
        async def create_admin_configuration(
            request: AdminModelConfigurationRequest,
        ) -> AdminModelConfigurationView:
            return admin_console.save_configuration(request)

        @app.post(
            "/api/v1/admin/connection-test",
            response_model=AdminConnectionTestResult,
        )
        async def test_admin_connection(_: ShutdownRequest) -> AdminConnectionTestResult:
            return await admin_console.test_connection()

        @app.post(
            "/api/v1/admin/capability-test",
            response_model=AdminConnectionTestResult,
        )
        async def test_admin_capability(_: ShutdownRequest) -> AdminConnectionTestResult:
            return await admin_console.verify_structured_output()

        @app.get(
            "/api/v1/admin/health",
            response_model=AdminHealthResponse,
        )
        async def admin_health() -> AdminHealthResponse:
            return admin_console.health()

        @app.get(
            "/api/v1/admin/model-traces",
            response_model=AdminModelTraceList,
        )
        async def admin_model_traces() -> AdminModelTraceList:
            return admin_console.model_traces()

        @app.get(
            "/api/v1/admin/model-traces/{trace_id}",
            response_model=ModelIoTrace,
        )
        async def admin_model_trace(trace_id: UUID) -> ModelIoTrace:
            return admin_console.model_trace(trace_id)

        @app.delete(
            "/api/v1/admin/model-traces",
            response_model=AdminModelTraceClearResult,
        )
        async def clear_admin_model_traces() -> AdminModelTraceClearResult:
            return admin_console.clear_model_traces()

    if preset_catalog is not None:

        @app.get("/api/v1/model-presets")
        async def model_presets() -> ModelPresetCatalog:
            return preset_catalog

    if profiles is not None:

        @app.get("/api/v1/model-profiles")
        async def list_model_profiles():
            return profiles.list_views()

        @app.post("/api/v1/model-profiles", status_code=201)
        async def create_model_profile(request: ModelProfileCreateRequest):
            return profiles.create(request)

        @app.put("/api/v1/model-profiles/{profile_id}")
        async def update_model_profile(profile_id: UUID, request: ModelProfileUpdateRequest):
            return profiles.update(profile_id, request)

        @app.delete("/api/v1/model-profiles/{profile_id}", status_code=204)
        async def delete_model_profile(profile_id: UUID, _: ShutdownRequest) -> Response:
            profiles.delete(profile_id)
            return Response(status_code=204)

        @app.put("/api/v1/model-profiles/{profile_id}/credential")
        async def put_model_credential(profile_id: UUID, request: ModelCredentialRequest):
            return profiles.put_credential(profile_id, request.api_key)

        @app.delete("/api/v1/model-profiles/{profile_id}/credential", status_code=204)
        async def delete_model_credential(profile_id: UUID, _: ShutdownRequest) -> Response:
            profiles.delete_credential(profile_id)
            return Response(status_code=204)

        @app.put("/api/v1/active-model-profile")
        async def activate_model_profile(request: ActiveModelProfileRequest):
            if capabilities is not None:
                return capabilities.activate(request.profile_id)
            return profiles.activate(request.profile_id)

        if capabilities is not None:

            @app.post("/api/v1/model-profiles/{profile_id}/checks")
            async def check_model_profile(profile_id: UUID, _: ShutdownRequest):
                return await capabilities.check_model(profile_id)

    if artifact_uploads is not None:

        @app.post(
            "/api/v1/artifacts",
            response_model=ArtifactUploadResponse,
            status_code=201,
        )
        async def upload_artifact(request: Request) -> ArtifactUploadResponse:
            content = await _read_limited_body(
                request,
                max_bytes=artifact_uploads.max_upload_bytes,
            )
            artifact = await artifact_uploads.upload_zip(
                content,
                media_type="application/zip",
            )
            return ArtifactUploadResponse.from_ref(artifact)

    if run_manager is not None:

        @app.post(
            "/api/v1/runs",
            response_model=RunAcceptedResponse,
            status_code=202,
        )
        async def create_run(
            request: RunCreateRequest,
            background_tasks: BackgroundTasks,
        ) -> RunAcceptedResponse:
            _require_run_readiness(runtime_readiness.status(), request.task_pack_id)
            accepted = await run_manager.create_run(request)
            background_tasks.add_task(run_manager.execute_run, accepted.run_id)
            return accepted

        @app.get(
            "/api/v1/runs/{run_id}",
            response_model=RunSummaryResponse,
        )
        async def get_run(run_id: UUID) -> RunSummaryResponse:
            return await run_manager.get_summary(run_id)

        @app.get(
            "/api/v1/runs/{run_id}/audit",
            response_model=RunAuditResponse,
        )
        async def get_run_audit(
            run_id: UUID,
            after_sequence: int = Query(default=0, ge=0),
        ) -> RunAuditResponse:
            return await run_manager.get_audit(
                run_id,
                after_sequence=after_sequence,
            )

    if presentation is not None:

        @app.get(
            "/api/v1/runs/{run_id}/projection",
            response_model=RunDisplayProjection,
        )
        async def get_run_projection(run_id: UUID) -> RunDisplayProjection:
            return await presentation.get_run(run_id)

        @app.get(
            "/api/v1/runs/{run_id}/evidence",
            response_model=EvidenceListProjection,
        )
        async def get_run_evidence(run_id: UUID) -> EvidenceListProjection:
            return await presentation.get_evidence(run_id)

        @app.get(
            "/api/v1/runs/{run_id}/report",
            response_model=ReportProjection,
        )
        async def get_run_report(run_id: UUID) -> ReportProjection:
            del run_id
            raise RunManagementError(
                "REPORT_UNAVAILABLE",
                "Report generation is not available in this Runtime release.",
                status_code=503,
            )

    @app.post("/api/v1/shutdown")
    async def shutdown(_: ShutdownRequest) -> dict[str, bool]:
        return {"accepted": True}

    return app


def _require_run_readiness(
    readiness: RuntimeReadinessResponse,
    task_pack_id: str,
) -> None:
    selected = next(
        (item for item in readiness.taskpacks if item.task_pack_id == task_pack_id),
        None,
    )
    if selected is None:
        state = ReadinessState.TASKPACK_DISABLED
    elif not readiness.model_ready or not readiness.core_ready:
        state = readiness.state
    elif selected.state is not ReadinessState.READY:
        state = selected.state
    elif not readiness.runtime_available:
        state = readiness.state
    else:
        return
    messages = {
        ReadinessState.MODEL_NOT_READY: "The active model is not ready.",
        ReadinessState.CREDENTIAL_MISSING: "The active model credential is unavailable.",
        ReadinessState.CAPABILITY_STALE: "The active model capability proof is stale.",
        ReadinessState.CAPABILITY_FAILED: "The active model capability proof failed.",
        ReadinessState.ADAPTER_NOT_READY: "The formal model adapter is unavailable.",
        ReadinessState.PLANNER_NOT_READY: "PlannerService is unavailable.",
        ReadinessState.REGISTRY_NOT_READY: "The formal Runtime registry is unavailable.",
        ReadinessState.POLICY_NOT_READY: "The formal Runtime policy is unavailable.",
        ReadinessState.ARTIFACT_RUNTIME_NOT_READY: "The artifact Runtime is unavailable.",
        ReadinessState.EXECUTOR_NOT_READY: "The selected TaskPack executor is unavailable.",
        ReadinessState.TASKPACK_DISABLED: "The selected TaskPack is disabled.",
        ReadinessState.RUNTIME_SNAPSHOT_CONFLICT: "The Runtime identity changed during admission.",
    }
    raise RunManagementError(
        state.value,
        messages.get(state, "The formal Runtime is unavailable."),
        status_code=503,
    )


async def _read_limited_body(request: Request, *, max_bytes: int) -> bytes:
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        try:
            parsed_length = int(declared_length)
        except ValueError as exc:
            raise ArtifactUploadError(
                "ARTIFACT_CONTENT_LENGTH_INVALID",
                "The artifact Content-Length header is invalid.",
                status_code=400,
            ) from exc
        if parsed_length < 0:
            raise ArtifactUploadError(
                "ARTIFACT_CONTENT_LENGTH_INVALID",
                "The artifact Content-Length header is invalid.",
                status_code=400,
            )
        if parsed_length > max_bytes:
            raise ArtifactUploadError(
                "ARTIFACT_SIZE_EXCEEDED",
                "The source artifact exceeds the configured upload limit.",
                status_code=413,
            )
    chunks: list[bytes] = []
    observed = 0
    async for chunk in request.stream():
        observed += len(chunk)
        if observed > max_bytes:
            raise ArtifactUploadError(
                "ARTIFACT_SIZE_EXCEEDED",
                "The source artifact exceeds the configured upload limit.",
                status_code=413,
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _normalize_origin(origin: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("origin is invalid") from exc
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or port is None:
        raise ValueError("origin must be an explicit http://127.0.0.1:<port> URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("origin credentials are not allowed")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("origin cannot contain a path, query, or fragment")
    normalized = f"http://127.0.0.1:{port}"
    return normalized, f"127.0.0.1:{port}"


def _error(code: str, message: str) -> dict[str, dict[str, object]]:
    return {
        "error": {
            "code": code,
            "message": message,
            "retryable": False,
            "next_action": None,
        }
    }


def _secured(payload: dict[str, object], status_code: int) -> JSONResponse:
    response = JSONResponse(payload, status_code=status_code)
    _apply_security_headers(response)
    return response


def _apply_security_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )


__all__ = ["CSRF_HEADER", "SESSION_COOKIE", "create_workbench_app"]
