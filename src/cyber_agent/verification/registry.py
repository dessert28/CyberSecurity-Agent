"""Explicit registry for trusted verifier implementations."""

from __future__ import annotations

from threading import RLock

from pydantic import TypeAdapter, ValidationError

from cyber_agent.contracts.common import MachineName
from cyber_agent.contracts.ports import VerifierPort


class VerifierRegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_VERIFIER_ID_ADAPTER = TypeAdapter(MachineName)


class VerifierRegistry:
    """Register verifiers by stable ID and resolve them without fallback."""

    def __init__(self) -> None:
        self._verifiers: dict[str, VerifierPort] = {}
        self._lock = RLock()

    def register(self, verifier_id: str, verifier: VerifierPort) -> None:
        normalized_id = self._validate_id(verifier_id)
        if not isinstance(verifier, VerifierPort):
            raise VerifierRegistryError(
                "VERIFIER_CONTRACT_INVALID",
                "verifier does not implement VerifierPort",
            )
        with self._lock:
            if normalized_id in self._verifiers:
                raise VerifierRegistryError(
                    "DUPLICATE_VERIFIER_ID",
                    f"verifier id {normalized_id!r} is already registered",
                )
            self._verifiers[normalized_id] = verifier

    def resolve(self, verifier_id: str) -> VerifierPort:
        normalized_id = self._validate_id(verifier_id)
        with self._lock:
            verifier = self._verifiers.get(normalized_id)
            if verifier is None:
                raise VerifierRegistryError(
                    "VERIFIER_NOT_REGISTERED",
                    f"verifier id {normalized_id!r} is not registered",
                )
            return verifier

    @staticmethod
    def _validate_id(verifier_id: str) -> str:
        try:
            return _VERIFIER_ID_ADAPTER.validate_python(verifier_id, strict=True)
        except ValidationError as exc:
            raise VerifierRegistryError(
                "VERIFIER_ID_INVALID",
                "verifier id must be a valid machine name",
            ) from exc
