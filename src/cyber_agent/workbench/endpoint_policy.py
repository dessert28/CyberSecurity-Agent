"""SSRF-resistant model endpoint validation and versioned preset loading."""

from __future__ import annotations

import ipaddress
import hashlib
import json
import socket
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

import yaml
import httpx
from pydantic import Field, field_validator, model_validator

from cyber_agent.workbench.schemas import (
    ProviderType,
    WorkbenchModel,
    normalize_model_base_url,
)


class Resolver(Protocol):
    def resolve(self, hostname: str) -> tuple[str, ...]: ...


_CLASH_FAKE_IP_NETWORK = ipaddress.ip_network("198.18.0.0/15")


class SecureDohFallbackResolver:
    """Resolve through system DNS, falling back only for Clash Fake-IP results."""

    def __init__(
        self,
        *,
        endpoint: str = "https://dns.alidns.com/resolve",
        client: httpx.Client | None = None,
    ) -> None:
        if endpoint != "https://dns.alidns.com/resolve":
            raise ValueError("DoH endpoint is not allowlisted")
        self._endpoint = endpoint
        self._client = client

    def resolve(self, hostname: str) -> tuple[str, ...]:
        system_addresses: tuple[str, ...] = ()
        try:
            system_addresses = tuple(
                sorted(
                    {
                        item[4][0]
                        for item in socket.getaddrinfo(
                            hostname,
                            None,
                            type=socket.SOCK_STREAM,
                        )
                    }
                )
            )
        except OSError:
            pass
        if system_addresses and not all(
            ipaddress.ip_address(value) in _CLASH_FAKE_IP_NETWORK
            for value in system_addresses
        ):
            return system_addresses
        return self._resolve_doh(hostname)

    def _resolve_doh(self, hostname: str) -> tuple[str, ...]:
        own_client = self._client is None
        client = self._client or httpx.Client(
            timeout=10,
            follow_redirects=False,
            trust_env=False,
        )
        try:
            response = client.get(
                self._endpoint,
                params={"name": hostname, "type": "A"},
                headers={"Accept": "application/dns-json"},
            )
            response.raise_for_status()
            if len(response.content) > 65_536:
                raise OSError("DoH response exceeded the safe size limit")
            payload = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise OSError("approved DoH resolution failed") from exc
        finally:
            if own_client:
                client.close()
        if not isinstance(payload, dict) or payload.get("Status") != 0:
            raise OSError("approved DoH resolver returned an invalid status")
        answers = payload.get("Answer", [])
        if not isinstance(answers, list):
            raise OSError("approved DoH resolver returned invalid answers")
        addresses: set[str] = set()
        for answer in answers:
            if not isinstance(answer, dict) or answer.get("type") not in {1, 28}:
                continue
            value = answer.get("data")
            if not isinstance(value, str):
                continue
            try:
                addresses.add(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
        if not addresses:
            raise OSError("approved DoH resolver returned no address")
        return tuple(sorted(addresses))


class EndpointPolicyError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class StructuredOutputMode(str):
    JSON_SCHEMA = "json_schema"
    JSON_OBJECT = "json_object"


class ModelPreset(WorkbenchModel):
    preset_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    display_name: str = Field(min_length=1, max_length=64)
    provider: ProviderType
    base_url: str
    model_id: str = Field(min_length=1, max_length=255)
    structured_output_mode: str = Field(pattern=r"^json_(schema|object)$")
    security_default: bool = False
    source_url: str

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return normalize_model_base_url(value)

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: str) -> str:
        normalized = normalize_model_base_url(value)
        if urlsplit(normalized).hostname not in {
            "platform.kimi.com",
            "api-docs.deepseek.com",
        }:
            raise ValueError("preset source must be an approved official documentation host")
        return normalized


class ModelPresetCatalog(WorkbenchModel):
    schema_version: str = Field(pattern=r"^\d+\.\d+$")
    reviewed_at: date
    presets: list[ModelPreset] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def validate_catalog(self) -> "ModelPresetCatalog":
        ids = [item.preset_id for item in self.presets]
        if len(ids) != len(set(ids)):
            raise ValueError("preset IDs must be unique")
        defaults = [item for item in self.presets if item.security_default]
        if len(defaults) != 1 or defaults[0].provider is not ProviderType.KIMI:
            raise ValueError("catalog must contain exactly one Kimi security default")
        return self


@dataclass(frozen=True, slots=True)
class EndpointSnapshot:
    base_url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]
    competition_gateway: bool = False


def endpoint_snapshot_fingerprint(
    snapshot: EndpointSnapshot,
    *,
    observed_at: datetime,
) -> str:
    """Return a non-secret, deterministic identity for a validated endpoint snapshot."""

    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("endpoint snapshot time must include a timezone")
    canonical = json.dumps(
        {
            "policy_version": "model-endpoint-policy/v1",
            "base_url": snapshot.base_url,
            "hostname": snapshot.hostname,
            "port": snapshot.port,
            "addresses": snapshot.addresses,
            "competition_gateway": snapshot.competition_gateway,
            "observed_at": observed_at.astimezone(timezone.utc).isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class GatewayAllowance:
    base_url: str
    private_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]

    def __post_init__(self) -> None:
        normalized = normalize_model_base_url(self.base_url)
        object.__setattr__(self, "base_url", normalized)
        if not self.private_networks:
            raise ValueError("gateway allowance requires an explicit private network")
        for network in self.private_networks:
            if not network.is_private or network.prefixlen == 0:
                raise ValueError("gateway networks must be scoped private CIDRs")


_DENIED_HOSTS = {
    "localhost",
    "host.docker.internal",
    "gateway.docker.internal",
    "metadata.google.internal",
    "metadata.azure.internal",
}
_METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
}


class ModelEndpointPolicy:
    """Validate model control-plane URLs independently from CTF target scope."""

    def __init__(
        self,
        *,
        resolver: Resolver,
        gateway_allowance: GatewayAllowance | None = None,
    ) -> None:
        self._resolver = resolver
        self._gateway_allowance = gateway_allowance

    def validate_and_snapshot(
        self,
        base_url: str,
        *,
        competition_gateway: bool = False,
    ) -> EndpointSnapshot:
        try:
            normalized = normalize_model_base_url(base_url)
        except ValueError as exc:
            raise EndpointPolicyError("MODEL_ENDPOINT_INVALID", "Model endpoint URL is invalid") from exc
        parsed = urlsplit(normalized)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        if hostname in _DENIED_HOSTS:
            raise EndpointPolicyError("MODEL_ENDPOINT_HOST_DENIED", "Model endpoint host is denied")
        if competition_gateway:
            if self._gateway_allowance is None or normalized != self._gateway_allowance.base_url:
                raise EndpointPolicyError(
                    "MODEL_GATEWAY_NOT_ALLOWED",
                    "Competition gateway does not match the trusted deployment allowlist",
                )
        try:
            addresses = self._resolve(hostname)
        except (OSError, ValueError) as exc:
            raise EndpointPolicyError(
                "MODEL_ENDPOINT_DNS_FAILED", "Model endpoint DNS resolution failed"
            ) from exc
        if not addresses:
            raise EndpointPolicyError(
                "MODEL_ENDPOINT_DNS_FAILED", "Model endpoint DNS resolution returned no address"
            )
        for address in addresses:
            if self._address_denied(address, competition_gateway=competition_gateway):
                raise EndpointPolicyError(
                    "MODEL_ENDPOINT_ADDRESS_DENIED",
                    "Model endpoint resolved to a denied address",
                )
        return EndpointSnapshot(
            base_url=normalized,
            hostname=hostname,
            port=parsed.port or 443,
            addresses=tuple(str(address) for address in addresses),
            competition_gateway=competition_gateway,
        )

    def revalidate(self, snapshot: EndpointSnapshot) -> EndpointSnapshot:
        current = self.validate_and_snapshot(
            snapshot.base_url,
            competition_gateway=snapshot.competition_gateway,
        )
        if current.addresses != snapshot.addresses:
            raise EndpointPolicyError(
                "MODEL_ENDPOINT_DNS_DRIFT",
                "Model endpoint DNS result changed after capability detection",
            )
        return current

    def _resolve(
        self, hostname: str
    ) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            raw = self._resolver.resolve(hostname)
            resolved = {ipaddress.ip_address(value) for value in raw}
        else:
            resolved = {literal}
        return tuple(sorted(resolved, key=lambda item: (item.version, int(item))))

    def _address_denied(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        *,
        competition_gateway: bool,
    ) -> bool:
        if (
            address in _METADATA_ADDRESSES
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            return True
        if not (address.is_private or address.is_reserved):
            return False
        if not competition_gateway or self._gateway_allowance is None:
            return True
        return not any(address in network for network in self._gateway_allowance.private_networks)


def load_model_presets(path: str | Path) -> ModelPresetCatalog:
    """Load non-secret built-in defaults from a strict versioned YAML file."""

    values = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return ModelPresetCatalog.model_validate(values)


__all__ = [
    "EndpointPolicyError",
    "EndpointSnapshot",
    "endpoint_snapshot_fingerprint",
    "GatewayAllowance",
    "ModelEndpointPolicy",
    "ModelPreset",
    "ModelPresetCatalog",
    "SecureDohFallbackResolver",
    "load_model_presets",
]
