"""Credential persistence ports with a fail-closed Windows implementation."""

from __future__ import annotations

import sys
from typing import Protocol, runtime_checkable
from uuid import UUID

import keyring
from keyring.errors import PasswordDeleteError


class CredentialBackendError(RuntimeError):
    """Safe credential failure that never includes backend values."""


@runtime_checkable
class CredentialStore(Protocol):
    def put(self, profile_id: UUID, api_key: str) -> None: ...

    def get(self, profile_id: UUID) -> str | None: ...

    def delete(self, profile_id: UUID) -> None: ...

    def exists(self, profile_id: UUID) -> bool: ...


class MemoryCredentialStore:
    """Default-test credential double; it performs no system I/O."""

    def __init__(self) -> None:
        self._values: dict[UUID, str] = {}

    def put(self, profile_id: UUID, api_key: str) -> None:
        _validate_profile_id(profile_id)
        self._values[profile_id] = _validate_api_key(api_key)

    def get(self, profile_id: UUID) -> str | None:
        _validate_profile_id(profile_id)
        return self._values.get(profile_id)

    def delete(self, profile_id: UUID) -> None:
        _validate_profile_id(profile_id)
        self._values.pop(profile_id, None)

    def exists(self, profile_id: UUID) -> bool:
        return self.get(profile_id) is not None

    def __repr__(self) -> str:
        return f"MemoryCredentialStore(entries={len(self._values)})"


class WindowsCredentialStore:
    """Persist one secret per profile in the current user's WinVault."""

    SERVICE_NAME = "cyber-agent.workbench"

    def __init__(self, *, backend=None, platform: str | None = None) -> None:
        effective_platform = sys.platform if platform is None else platform
        if effective_platform != "win32":
            raise CredentialBackendError("Windows Credential Manager is required")
        selected = keyring.get_keyring() if backend is None else backend
        try:
            from keyring.backends.Windows import WinVaultKeyring
        except ImportError as exc:  # pragma: no cover - guarded by Windows dependency lock
            raise CredentialBackendError("Windows WinVault backend is unavailable") from exc
        if not isinstance(selected, WinVaultKeyring):
            raise CredentialBackendError("Windows WinVault backend is required")
        try:
            priority = float(selected.priority)
        except (TypeError, ValueError, AttributeError) as exc:
            raise CredentialBackendError("Windows WinVault backend is unavailable") from exc
        if priority <= 0:
            raise CredentialBackendError("Windows WinVault backend is unavailable")
        self._backend = selected

    def put(self, profile_id: UUID, api_key: str) -> None:
        username = _profile_username(profile_id)
        secret = _validate_api_key(api_key)
        try:
            self._backend.set_password(self.SERVICE_NAME, username, secret)
        except Exception as exc:
            raise CredentialBackendError("Windows Credential Manager write failed") from exc

    def get(self, profile_id: UUID) -> str | None:
        username = _profile_username(profile_id)
        try:
            value = self._backend.get_password(self.SERVICE_NAME, username)
        except Exception as exc:
            raise CredentialBackendError("Windows Credential Manager read failed") from exc
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            raise CredentialBackendError("Windows Credential Manager returned invalid data")
        return value

    def delete(self, profile_id: UUID) -> None:
        username = _profile_username(profile_id)
        try:
            self._backend.delete_password(self.SERVICE_NAME, username)
        except PasswordDeleteError:
            return
        except Exception as exc:
            raise CredentialBackendError("Windows Credential Manager delete failed") from exc

    def exists(self, profile_id: UUID) -> bool:
        return self.get(profile_id) is not None

    def __repr__(self) -> str:
        return "WindowsCredentialStore(backend=WinVaultKeyring)"


def _profile_username(profile_id: UUID) -> str:
    _validate_profile_id(profile_id)
    return str(profile_id)


def _validate_profile_id(profile_id: UUID) -> None:
    if not isinstance(profile_id, UUID):
        raise TypeError("profile_id must be a UUID")


def _validate_api_key(api_key: str) -> str:
    if not isinstance(api_key, str):
        raise TypeError("api_key must be a string")
    normalized = api_key.strip()
    if (
        not normalized
        or len(normalized) > 16_384
        or any(character in normalized for character in ("\r", "\n", "\x00"))
    ):
        raise ValueError("api_key is empty or contains a forbidden character")
    return normalized


__all__ = [
    "CredentialBackendError",
    "CredentialStore",
    "MemoryCredentialStore",
    "WindowsCredentialStore",
]
