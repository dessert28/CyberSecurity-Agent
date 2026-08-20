"""Explicit, health-gated tool plugin registry."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from threading import RLock

from cyber_agent.contracts.ports import ToolPlugin
from cyber_agent.contracts.tool import ToolHealth, ToolRef, ToolSpec


class RegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class HealthState(str, Enum):
    PENDING = "pending"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True, slots=True)
class RegistryStatus:
    tool_ref: ToolRef
    state: HealthState
    message: str = ""


@dataclass(slots=True)
class _Registration:
    plugin: ToolPlugin
    spec: ToolSpec
    status: RegistryStatus


class ToolRegistry:
    """Registry that exposes only allowlisted plugins with successful health."""

    def __init__(self) -> None:
        self._registrations: dict[str, _Registration] = {}
        self._lock = RLock()

    def register(self, plugin: ToolPlugin) -> None:
        if not isinstance(plugin, ToolPlugin):
            raise RegistryError("PLUGIN_CONTRACT_INVALID", "plugin does not implement ToolPlugin")
        spec = plugin.get_spec().model_copy(deep=True)
        tool_ref = ToolRef(tool_id=spec.tool_id, version=spec.version)
        with self._lock:
            existing = self._registrations.get(spec.tool_id)
            if existing is not None:
                if existing.spec.version == spec.version:
                    raise RegistryError(
                        "DUPLICATE_TOOL_ID", f"tool id {spec.tool_id!r} is already registered"
                    )
                raise RegistryError(
                    "TOOL_VERSION_CONFLICT",
                    f"tool id {spec.tool_id!r} has a version conflict: "
                    f"{existing.spec.version!r} vs {spec.version!r}",
                )
            self._registrations[spec.tool_id] = _Registration(
                plugin=plugin,
                spec=spec,
                status=RegistryStatus(tool_ref=tool_ref, state=HealthState.PENDING),
            )

    async def register_checked(self, plugin: ToolPlugin) -> RegistryStatus:
        self.register(plugin)
        spec = plugin.get_spec()
        await self.refresh_health(spec.tool_id)
        return self.status(spec.tool_id)

    async def refresh_health(self, tool_id: str | None = None) -> None:
        with self._lock:
            if tool_id is not None and tool_id not in self._registrations:
                raise RegistryError("TOOL_NOT_REGISTERED", f"tool id {tool_id!r} is not registered")
            registrations = [
                registration
                for key, registration in self._registrations.items()
                if tool_id is None or key == tool_id
            ]
        await asyncio.gather(*(self._refresh_one(registration) for registration in registrations))

    async def _refresh_one(self, registration: _Registration) -> None:
        try:
            health = await registration.plugin.health_check()
            expected = ToolRef(tool_id=registration.spec.tool_id, version=registration.spec.version)
            if health.tool_ref != expected:
                health = ToolHealth(
                    tool_ref=expected,
                    available=False,
                    message="plugin health check returned a mismatched tool reference",
                )
        except Exception as exc:  # plugin failure must not crash registry initialization
            health = ToolHealth(
                tool_ref=ToolRef(
                    tool_id=registration.spec.tool_id,
                    version=registration.spec.version,
                ),
                available=False,
                message=f"health check failed: {type(exc).__name__}",
            )
        state = HealthState.HEALTHY if health.available else HealthState.UNHEALTHY
        with self._lock:
            registration.status = RegistryStatus(
                tool_ref=health.tool_ref,
                state=state,
                message=health.message,
            )

    def candidates(self, capability: str) -> tuple[ToolSpec, ...]:
        with self._lock:
            return tuple(
                registration.spec.model_copy(deep=True)
                for registration in self._registrations.values()
                if registration.status.state is HealthState.HEALTHY
                and capability in registration.spec.capabilities
            )

    def status(self, tool_id: str) -> RegistryStatus:
        with self._lock:
            registration = self._registrations.get(tool_id)
            if registration is None:
                raise RegistryError("TOOL_NOT_REGISTERED", f"tool id {tool_id!r} is not registered")
            return registration.status

    def plugin(self, tool_id: str) -> ToolPlugin:
        with self._lock:
            registration = self._registrations.get(tool_id)
            if registration is None:
                raise RegistryError("TOOL_NOT_REGISTERED", f"tool id {tool_id!r} is not registered")
            if registration.status.state is not HealthState.HEALTHY:
                raise RegistryError("TOOL_UNAVAILABLE", f"tool id {tool_id!r} is not healthy")
            return registration.plugin
