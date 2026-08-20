"""Business rules for named model profiles and explicit activation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from uuid import UUID, uuid4

from cyber_agent.workbench.credentials import CredentialBackendError, CredentialStore
from cyber_agent.workbench.schemas import (
    CapabilityProbeRecord,
    ModelCheckStatus,
    ModelProfileCreateRequest,
    ModelProfileView,
    WorkbenchMode,
)
from cyber_agent.workbench.store import StoredModelProfile, WorkbenchStore


class ProfileError(RuntimeError):
    pass


class ProfileLockedError(ProfileError):
    pass


class ProfileNameConflictError(ProfileError):
    pass


class ProfileNotReadyError(ProfileError):
    pass


class ProfileInUseError(ProfileError):
    pass


class ModelProfileStore:
    """Apply development and competition profile invariants over SQLite."""

    def __init__(
        self,
        *,
        database: WorkbenchStore,
        mode: WorkbenchMode,
        credentials: CredentialStore | None = None,
    ) -> None:
        self._database = database
        self._mode = mode
        self._credentials = credentials

    def create(
        self,
        request: ModelProfileCreateRequest,
        *,
        security_default: bool = False,
    ) -> ModelProfileView:
        self._require_development()
        if security_default and request.provider.value != "kimi":
            raise ValueError("only a Kimi profile can be the security default")
        now = datetime.now(timezone.utc)
        profile = StoredModelProfile(
            profile_id=uuid4(),
            display_name=request.display_name,
            name_key=request.name_key,
            provider=request.provider,
            base_url=request.base_url,
            model_id=request.model_id,
            credential_present=False,
            credential_version=0,
            check_status=ModelCheckStatus.UNCHECKED,
            check_fingerprint=None,
            check_message=None,
            checked_at=None,
            security_default=security_default,
            created_at=now,
            updated_at=now,
        )
        try:
            self._database.upsert_profile(profile)
        except sqlite3.IntegrityError as exc:
            raise ProfileNameConflictError("a model profile with that name already exists") from exc
        return self._view(profile)

    def update(
        self,
        profile_id: UUID,
        request: ModelProfileCreateRequest,
    ) -> ModelProfileView:
        self._require_development()
        self._require_idle()
        current = self._database.get_profile(profile_id)
        updated = StoredModelProfile(
            profile_id=current.profile_id,
            display_name=request.display_name,
            name_key=request.name_key,
            provider=request.provider,
            base_url=request.base_url,
            model_id=request.model_id,
            credential_present=current.credential_present,
            credential_version=current.credential_version,
            check_status=ModelCheckStatus.UNCHECKED,
            check_fingerprint=None,
            check_message=None,
            checked_at=None,
            security_default=current.security_default and request.provider.value == "kimi",
            created_at=current.created_at,
            updated_at=datetime.now(timezone.utc),
            current_probe_id=current.current_probe_id,
        )
        try:
            self._database.upsert_profile(updated)
        except sqlite3.IntegrityError as exc:
            raise ProfileNameConflictError("a model profile with that name already exists") from exc
        if self._database.get_current_profile_id() == profile_id:
            self._database.set_current_profile(None)
        return self._view(updated)

    def record_check(
        self,
        profile_id: UUID,
        *,
        passed: bool,
        message: str,
    ) -> ModelProfileView:
        self._require_development()
        if len(message) > 2_000:
            raise ValueError("check message is too long")
        current = self._database.get_profile(profile_id)
        checked = StoredModelProfile(
            profile_id=current.profile_id,
            display_name=current.display_name,
            name_key=current.name_key,
            provider=current.provider,
            base_url=current.base_url,
            model_id=current.model_id,
            credential_present=current.credential_present,
            credential_version=current.credential_version,
            check_status=ModelCheckStatus.PASSED if passed else ModelCheckStatus.FAILED,
            check_fingerprint=configuration_fingerprint(current) if passed else None,
            check_message=message,
            checked_at=datetime.now(timezone.utc),
            security_default=current.security_default,
            created_at=current.created_at,
            updated_at=datetime.now(timezone.utc),
            current_probe_id=current.current_probe_id,
        )
        self._database.upsert_profile(checked)
        if passed and checked.security_default and self._database.get_current_profile_id() is None:
            self._database.set_current_profile(profile_id)
        return self._view(checked)

    def record_probe(
        self,
        probe: CapabilityProbeRecord,
        *,
        message: str,
    ) -> ModelProfileView:
        """Record an identity-bound probe without discarding older evidence."""

        self._require_development()
        if len(message) > 2_000:
            raise ValueError("check message is too long")
        current = self._database.get_profile(probe.profile_id)
        if (
            probe.provider is not current.provider
            or probe.model_id != current.model_id
            or probe.credential_version != current.credential_version
        ):
            raise ValueError("capability probe identity does not match the current profile")
        checked = StoredModelProfile(
            profile_id=current.profile_id,
            display_name=current.display_name,
            name_key=current.name_key,
            provider=current.provider,
            base_url=current.base_url,
            model_id=current.model_id,
            credential_present=current.credential_present,
            credential_version=current.credential_version,
            check_status=probe.status,
            check_fingerprint=(
                configuration_fingerprint(current)
                if probe.status is ModelCheckStatus.PASSED
                else None
            ),
            check_message=message,
            checked_at=probe.checked_at,
            security_default=current.security_default,
            created_at=current.created_at,
            updated_at=probe.checked_at,
            current_probe_id=current.current_probe_id,
        )
        self._database.upsert_profile(checked)
        self._database.record_capability_probe(probe)
        if (
            probe.status is ModelCheckStatus.PASSED
            and checked.security_default
            and self._database.get_current_profile_id() is None
        ):
            self._database.set_current_profile(probe.profile_id)
        return self._view(self._database.get_profile(probe.profile_id))

    def current_probe(self, profile_id: UUID) -> CapabilityProbeRecord | None:
        return self._database.get_current_capability_probe(profile_id)

    def credential_available(self, profile_id: UUID) -> bool:
        """Check OS-backed presence without exposing or persisting credential material."""

        profile = self._database.get_profile(profile_id)
        if not profile.credential_present or self._credentials is None:
            return False
        try:
            return bool(self._credentials.get(profile_id))
        except CredentialBackendError:
            return False

    def activate(self, profile_id: UUID) -> ModelProfileView:
        self._require_development()
        self._require_idle()
        profile = self._database.get_profile(profile_id)
        if (
            profile.check_status is not ModelCheckStatus.PASSED
            or profile.check_fingerprint != configuration_fingerprint(profile)
        ):
            raise ProfileNotReadyError("model profile has not passed its current capability check")
        self._database.set_current_profile(profile_id)
        return self._view(profile)

    def put_credential(self, profile_id: UUID, api_key: str) -> ModelProfileView:
        self._require_development()
        self._require_idle()
        credentials = self._require_credentials()
        current = self._database.get_profile(profile_id)
        credentials.put(profile_id, api_key)
        updated = self._credential_state(current, present=True)
        try:
            self._database.upsert_profile(updated)
        except Exception:
            try:
                credentials.delete(profile_id)
            except CredentialBackendError:
                pass
            raise
        if self._database.get_current_profile_id() == profile_id:
            self._database.set_current_profile(None)
        return self._view(updated)

    def delete_credential(self, profile_id: UUID) -> ModelProfileView:
        self._require_development()
        self._require_idle()
        credentials = self._require_credentials()
        current = self._database.get_profile(profile_id)
        credentials.delete(profile_id)
        if not current.credential_present:
            return self._view(current)
        updated = self._credential_state(current, present=False)
        self._database.upsert_profile(updated)
        if self._database.get_current_profile_id() == profile_id:
            self._database.set_current_profile(None)
        return self._view(updated)

    def delete(self, profile_id: UUID) -> None:
        self._require_development()
        self._require_idle()
        profile = self._database.get_profile(profile_id)
        if profile.credential_present:
            self._require_credentials().delete(profile_id)
        self._database.delete_profile(profile_id)

    def get(self, profile_id: UUID) -> StoredModelProfile:
        return self._database.get_profile(profile_id)

    @property
    def mode(self) -> WorkbenchMode:
        return self._mode

    def list_views(self) -> list[ModelProfileView]:
        return [self._view(profile) for profile in self._database.list_profiles()]

    def _view(self, profile: StoredModelProfile) -> ModelProfileView:
        return ModelProfileView(
            profile_id=profile.profile_id,
            display_name=profile.display_name,
            provider=profile.provider,
            base_url=profile.base_url,
            model_id=profile.model_id,
            credential_present=profile.credential_present,
            check_status=profile.check_status,
            security_default=profile.security_default,
            active=self._database.get_current_profile_id() == profile.profile_id,
        )

    def _require_development(self) -> None:
        if self._mode is not WorkbenchMode.DEVELOPMENT:
            raise ProfileLockedError("competition model configuration is deployment-locked")

    def _require_idle(self) -> None:
        if self._database.has_active_run():
            raise ProfileInUseError("model profiles cannot change while a run is active")

    def _require_credentials(self) -> CredentialStore:
        if self._credentials is None:
            raise ProfileError("credential persistence is unavailable")
        return self._credentials

    @staticmethod
    def _credential_state(
        current: StoredModelProfile,
        *,
        present: bool,
    ) -> StoredModelProfile:
        return StoredModelProfile(
            profile_id=current.profile_id,
            display_name=current.display_name,
            name_key=current.name_key,
            provider=current.provider,
            base_url=current.base_url,
            model_id=current.model_id,
            credential_present=present,
            credential_version=current.credential_version + 1,
            check_status=ModelCheckStatus.UNCHECKED,
            check_fingerprint=None,
            check_message=None,
            checked_at=None,
            security_default=current.security_default,
            created_at=current.created_at,
            updated_at=datetime.now(timezone.utc),
            current_probe_id=current.current_probe_id,
        )


def configuration_fingerprint(profile: StoredModelProfile) -> str:
    canonical = json.dumps(
        {
            "provider": profile.provider.value,
            "base_url": profile.base_url,
            "model_id": profile.model_id,
            "credential_version": profile.credential_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "ModelProfileStore",
    "ProfileError",
    "ProfileInUseError",
    "ProfileLockedError",
    "ProfileNameConflictError",
    "ProfileNotReadyError",
    "configuration_fingerprint",
]
