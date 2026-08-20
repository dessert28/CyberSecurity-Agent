"""Deployment-only administration over existing model and registry boundaries."""

from __future__ import annotations

from enum import Enum
from time import perf_counter
from typing import Literal

from pydantic import Field, SecretStr, field_validator

from cyber_agent.task_packs import TaskPackCatalog
from cyber_agent.tools import HealthState, RegistryError, ToolRegistry
from cyber_agent.verification import VerifierRegistry, VerifierRegistryError
from cyber_agent.workbench.capabilities import ModelCapabilityService
from cyber_agent.workbench.profiles import ModelProfileStore
from cyber_agent.workbench.schemas import (
    ModelCheckStatus,
    ModelProfileCreateRequest,
    ProviderType,
    WorkbenchMode,
    WorkbenchModel,
)

_ADMIN_PROFILE_NAME = "Competition primary model"


class AdminConsoleError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class AdminProviderOption(WorkbenchModel):
    value: ProviderType
    label: str = Field(min_length=1, max_length=64)


class AdminProviderCatalog(WorkbenchModel):
    providers: tuple[AdminProviderOption, ...]


class AdminModelConfigurationRequest(WorkbenchModel):
    provider: ProviderType
    model_name: str
    api_base_url: str
    api_key: SecretStr | None = Field(default=None, repr=False)

    _model_name = field_validator("model_name")(
        ModelProfileCreateRequest.validate_model_id.__func__
    )
    _api_base_url = field_validator("api_base_url")(
        ModelProfileCreateRequest.validate_base_url.__func__
    )

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        secret = value.get_secret_value().strip()
        if (
            not secret
            or len(secret) > 16_384
            or any(character in secret for character in ("\r", "\n", "\x00"))
        ):
            raise ValueError("api_key is empty or contains a forbidden character")
        return SecretStr(secret)


class AdminModelConfigurationView(WorkbenchModel):
    configured: bool
    writable: bool
    mode: WorkbenchMode
    provider: ProviderType | None = None
    model_name: str | None = None
    api_base_url: str | None = None
    credential_configured: bool = False
    connection_status: ModelCheckStatus = ModelCheckStatus.UNCHECKED
    connection_succeeded: bool = False
    active: bool = False
    provider_options: tuple[AdminProviderOption, ...]


class AdminConnectionTestResult(WorkbenchModel):
    status: Literal["ok", "error"]
    success: bool
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,127}$")
    message: str = Field(min_length=1, max_length=2_000)
    api_accessible: bool
    structured_output_detected: bool
    latency_ms: int = Field(ge=0)
    model: str
    model_name: str
    active: bool


class AdminHealthState(str, Enum):
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class AdminHealthCheck(WorkbenchModel):
    component: Literal["model", "docker", "task_packs", "verifiers", "tool_registry"]
    state: AdminHealthState
    message: str = Field(min_length=1, max_length=2_000)
    registered_count: int | None = Field(default=None, ge=0)


class AdminHealthResponse(WorkbenchModel):
    overall_ready: bool
    checks: tuple[AdminHealthCheck, ...]


_PROVIDER_OPTIONS = (
    AdminProviderOption(value=ProviderType.DEEPSEEK, label="DeepSeek"),
    AdminProviderOption(value=ProviderType.KIMI, label="Kimi"),
    AdminProviderOption(value=ProviderType.QWEN, label="Qwen / 通义千问"),
    AdminProviderOption(
        value=ProviderType.DOMESTIC_COMPATIBLE,
        label="其他国产兼容模型",
    ),
)


class AdminConsoleService:
    """Configure one competition model and expose read-only startup health."""

    def __init__(
        self,
        *,
        profiles: ModelProfileStore,
        capabilities: ModelCapabilityService,
        task_packs: TaskPackCatalog | None = None,
        verifier_registry: VerifierRegistry | None = None,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        self._profiles = profiles
        self._capabilities = capabilities
        self._task_packs = task_packs
        self._verifier_registry = verifier_registry
        self._tool_registry = tool_registry

    def providers(self) -> AdminProviderCatalog:
        return AdminProviderCatalog(providers=_PROVIDER_OPTIONS)

    def configuration(self) -> AdminModelConfigurationView:
        views = self._profiles.list_views()
        selected = next((item for item in views if item.active), None)
        if selected is None:
            selected = next((item for item in views if item.security_default), None)
        if selected is None and views:
            selected = views[0]
        if selected is None:
            return AdminModelConfigurationView(
                configured=False,
                writable=self._profiles.mode is WorkbenchMode.DEVELOPMENT,
                mode=self._profiles.mode,
                provider_options=_PROVIDER_OPTIONS,
            )
        return AdminModelConfigurationView(
            configured=True,
            writable=self._profiles.mode is WorkbenchMode.DEVELOPMENT,
            mode=self._profiles.mode,
            provider=selected.provider,
            model_name=selected.model_id,
            api_base_url=selected.base_url,
            credential_configured=selected.credential_present,
            connection_status=selected.check_status,
            connection_succeeded=selected.check_status is ModelCheckStatus.PASSED,
            active=selected.active,
            provider_options=_PROVIDER_OPTIONS,
        )

    def save_configuration(
        self,
        request: AdminModelConfigurationRequest,
    ) -> AdminModelConfigurationView:
        current = self.configuration()
        profile_request = ModelProfileCreateRequest(
            display_name=_ADMIN_PROFILE_NAME,
            provider=request.provider,
            base_url=request.api_base_url,
            model_id=request.model_name,
        )
        selected = self._selected_profile_view()
        if selected is None:
            saved = self._profiles.create(profile_request)
        else:
            saved = self._profiles.update(selected.profile_id, profile_request)
        if request.api_key is not None:
            saved = self._profiles.put_credential(
                saved.profile_id,
                request.api_key.get_secret_value(),
            )
        elif not current.credential_configured:
            saved = saved.model_copy(update={"credential_present": False})
        return self._view_for(saved.profile_id)

    async def test_connection(self) -> AdminConnectionTestResult:
        selected = self._selected_profile_view()
        if selected is None:
            raise AdminConsoleError(
                "MODEL_CONFIGURATION_MISSING",
                "Save a model configuration before testing the connection.",
                status_code=409,
            )
        if not selected.credential_present:
            raise AdminConsoleError(
                "MODEL_CREDENTIAL_MISSING",
                "Save an API credential before testing the connection.",
                status_code=409,
            )
        started = perf_counter()
        result = await self._capabilities.check_model(selected.profile_id)
        latency_ms = max(0, int((perf_counter() - started) * 1_000))
        active = result.active
        if result.passed and not active:
            active = self._capabilities.activate(selected.profile_id).active
        return AdminConnectionTestResult(
            status="ok" if result.passed else "error",
            success=result.passed,
            code=result.code,
            message=result.message,
            api_accessible=(
                result.passed
                or result.code == "MODEL_STRUCTURED_OUTPUT_INCOMPATIBLE"
            ),
            structured_output_detected=result.passed,
            latency_ms=latency_ms,
            model=selected.model_id,
            model_name=selected.model_id,
            active=active,
        )

    def health(self) -> AdminHealthResponse:
        checks = (
            self._model_health(),
            self._docker_health(),
            self._task_pack_health(),
            self._verifier_health(),
            self._tool_health(),
        )
        return AdminHealthResponse(
            overall_ready=all(item.state is AdminHealthState.READY for item in checks),
            checks=checks,
        )

    def _selected_profile_view(self):
        views = self._profiles.list_views()
        return (
            next((item for item in views if item.active), None)
            or next((item for item in views if item.security_default), None)
            or (views[0] if views else None)
        )

    def _view_for(self, profile_id) -> AdminModelConfigurationView:
        view = next(
            item for item in self._profiles.list_views() if item.profile_id == profile_id
        )
        return AdminModelConfigurationView(
            configured=True,
            writable=self._profiles.mode is WorkbenchMode.DEVELOPMENT,
            mode=self._profiles.mode,
            provider=view.provider,
            model_name=view.model_id,
            api_base_url=view.base_url,
            credential_configured=view.credential_present,
            connection_status=view.check_status,
            connection_succeeded=view.check_status is ModelCheckStatus.PASSED,
            active=view.active,
            provider_options=_PROVIDER_OPTIONS,
        )

    def _model_health(self) -> AdminHealthCheck:
        current = self.configuration()
        if not current.configured or not current.credential_configured:
            return AdminHealthCheck(
                component="model",
                state=AdminHealthState.UNAVAILABLE,
                message="Model connection information is not fully configured.",
            )
        if not current.connection_succeeded or not current.active:
            return AdminHealthCheck(
                component="model",
                state=AdminHealthState.DEGRADED,
                message="The configured model has not passed and activated its capability check.",
            )
        return AdminHealthCheck(
            component="model",
            state=AdminHealthState.READY,
            message=f"{current.model_name} is configured and capability-checked.",
        )

    def _docker_health(self) -> AdminHealthCheck:
        try:
            status = self._capabilities.status().docker
        except Exception:
            return AdminHealthCheck(
                component="docker",
                state=AdminHealthState.UNAVAILABLE,
                message="Docker availability check failed safely.",
            )
        return AdminHealthCheck(
            component="docker",
            state=(
                AdminHealthState.READY
                if status.available
                else AdminHealthState.UNAVAILABLE
            ),
            message=status.message,
        )

    def _task_pack_health(self) -> AdminHealthCheck:
        if self._task_packs is None:
            return self._missing_component("task_packs", "TaskPack catalog is unavailable.")
        manifests = self._task_packs.list()
        if not manifests:
            return self._missing_component("task_packs", "No competition TaskPack is registered.")
        return AdminHealthCheck(
            component="task_packs",
            state=AdminHealthState.READY,
            message="Competition TaskPacks are registered through the explicit catalog.",
            registered_count=len(manifests),
        )

    def _verifier_health(self) -> AdminHealthCheck:
        if self._task_packs is None or self._verifier_registry is None:
            return self._missing_component("verifiers", "Verifier registry is unavailable.")
        manifests = self._task_packs.list()
        try:
            for manifest in manifests:
                self._verifier_registry.resolve(manifest.verifier)
        except VerifierRegistryError:
            return self._missing_component(
                "verifiers",
                "A competition TaskPack verifier is not registered.",
            )
        return AdminHealthCheck(
            component="verifiers",
            state=AdminHealthState.READY,
            message="All competition TaskPack verifiers are registered.",
            registered_count=len({item.verifier for item in manifests}),
        )

    def _tool_health(self) -> AdminHealthCheck:
        if self._task_packs is None or self._tool_registry is None:
            return self._missing_component("tool_registry", "Tool Registry is unavailable.")
        tool_ids = {
            tool_id
            for manifest in self._task_packs.list()
            for tool_id in manifest.required_tools
        }
        try:
            statuses = tuple(self._tool_registry.status(tool_id) for tool_id in tool_ids)
        except RegistryError:
            return self._missing_component(
                "tool_registry",
                "A required competition tool is not registered.",
            )
        if any(item.state is not HealthState.HEALTHY for item in statuses):
            return AdminHealthCheck(
                component="tool_registry",
                state=AdminHealthState.DEGRADED,
                message="At least one required competition tool is not healthy.",
                registered_count=len(statuses),
            )
        return AdminHealthCheck(
            component="tool_registry",
            state=AdminHealthState.READY,
            message="All required competition tools passed their health checks.",
            registered_count=len(statuses),
        )

    @staticmethod
    def _missing_component(component, message: str) -> AdminHealthCheck:
        return AdminHealthCheck(
            component=component,
            state=AdminHealthState.UNAVAILABLE,
            message=message,
        )


__all__ = [
    "AdminConnectionTestResult",
    "AdminConsoleError",
    "AdminConsoleService",
    "AdminHealthCheck",
    "AdminHealthResponse",
    "AdminHealthState",
    "AdminModelConfigurationRequest",
    "AdminModelConfigurationView",
    "AdminProviderOption",
    "AdminProviderCatalog",
]
