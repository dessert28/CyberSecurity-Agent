"""Deterministic, secret-resistant fingerprints for immutable runtime identity."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections.abc import Mapping, Sequence, Set
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from cyber_agent.contracts.common import EnvironmentProfile
from cyber_agent.contracts.tool import ExecutionProfile, ToolSpec
from cyber_agent.workbench.schemas import normalize_model_base_url


class FingerprintInputError(ValueError):
    """Raised when fingerprint input could expose unstable or sensitive state."""


_FORBIDDEN_KEYS = {
    "api_key",
    "apikey",
    "artifact_path",
    "authorization",
    "credential",
    "credentials",
    "environment",
    "host_path",
    "password",
    "runtime_root",
    "secret",
    "token",
    "workspace_path",
    "workspace_root",
}
_WINDOWS_HOST_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
_OBJECT_REPR = re.compile(r"^<[^>]+ object at 0x[0-9A-Fa-f]+>$")


def fingerprint_tool_registry(tools: Sequence[ToolSpec]) -> str:
    """Fingerprint tool contracts independently of registration order."""

    ordered = sorted(tools, key=lambda item: (item.tool_id, item.version))
    identities = [(item.tool_id, item.version) for item in ordered]
    if len(identities) != len(set(identities)):
        raise FingerprintInputError("tool registry contains a duplicate identity")
    return _fingerprint(
        {
            "fingerprint_contract": "tool-registry/v1",
            "tools": [item.model_dump(mode="python") for item in ordered],
        }
    )


def fingerprint_policy(
    policy_version: str,
    policy_config: Mapping[str, object],
) -> str:
    return _fingerprint(
        {
            "fingerprint_contract": "policy/v1",
            "policy_version": _safe_label(policy_version, "policy_version"),
            "policy_config": dict(policy_config),
        }
    )


def fingerprint_executor(
    executor_profile: str,
    execution_profile: ExecutionProfile,
    resource_budget: Mapping[str, object],
) -> str:
    return _fingerprint(
        {
            "fingerprint_contract": "executor/v1",
            "executor_profile": _safe_label(executor_profile, "executor_profile"),
            "execution_profile": execution_profile.model_dump(mode="python"),
            "resource_budget": dict(resource_budget),
        }
    )


def fingerprint_environment(profile: EnvironmentProfile) -> str:
    return _fingerprint(
        {
            "fingerprint_contract": "environment/v1",
            "profile": profile.model_dump(mode="python"),
        }
    )


def fingerprint_endpoint(
    *,
    canonical_base_url: str,
    addresses: Sequence[str],
    policy_version: str,
    observed_at: datetime,
) -> str:
    try:
        normalized_url = normalize_model_base_url(canonical_base_url)
        normalized_addresses = sorted(
            {str(ipaddress.ip_address(address)) for address in addresses},
            key=lambda value: (
                ipaddress.ip_address(value).version,
                ipaddress.ip_address(value).packed,
            ),
        )
    except ValueError as exc:
        raise FingerprintInputError("endpoint identity is invalid") from exc
    if not normalized_addresses:
        raise FingerprintInputError("endpoint identity requires at least one address")
    return _fingerprint(
        {
            "fingerprint_contract": "endpoint/v1",
            "canonical_base_url": normalized_url,
            "addresses": normalized_addresses,
            "policy_version": _safe_label(policy_version, "policy_version"),
            "observed_at": _utc_text(observed_at),
        }
    )


def _fingerprint(value: object) -> str:
    canonical = _normalize(value, path=())
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize(value: object, *, path: tuple[str, ...]) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"), path=path)
    if isinstance(value, Enum):
        return _normalize(value.value, path=path)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return _utc_text(value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise FingerprintInputError("fingerprint input contains a non-finite number")
        return value
    if isinstance(value, str):
        if _WINDOWS_HOST_PATH.match(value):
            raise FingerprintInputError("fingerprint input contains an absolute host path")
        if _OBJECT_REPR.match(value):
            raise FingerprintInputError("fingerprint input contains an object repr")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise FingerprintInputError("fingerprint mapping keys must be strings")
            if key.casefold() in _FORBIDDEN_KEYS:
                raise FingerprintInputError("fingerprint input contains a forbidden field")
            normalized[key] = _normalize(item, path=(*path, key))
        return normalized
    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
        items = [_normalize(item, path=path) for item in value]
        return sorted(items, key=_canonical_sort_key)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item, path=path) for item in value]
    raise FingerprintInputError(
        f"fingerprint input at {'.'.join(path) or '<root>'} is not canonical JSON"
    )


def _canonical_sort_key(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _safe_label(value: str, field: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 255
        or any(ord(char) < 32 for char in normalized)
    ):
        raise FingerprintInputError(f"{field} is invalid")
    if _WINDOWS_HOST_PATH.match(normalized) or _OBJECT_REPR.match(normalized):
        raise FingerprintInputError(f"{field} contains unsafe identity data")
    return normalized


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FingerprintInputError("fingerprint timestamps must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "FingerprintInputError",
    "fingerprint_endpoint",
    "fingerprint_environment",
    "fingerprint_executor",
    "fingerprint_policy",
    "fingerprint_tool_registry",
]
