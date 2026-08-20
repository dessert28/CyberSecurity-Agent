"""Deterministic scope, risk, argument, DNS, and budget policy checks."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

from cyber_agent.contracts.common import Budget, RiskLevel
from cyber_agent.contracts.task import ScopePolicy, ScopeTarget, TargetKind
from cyber_agent.contracts.tool import (
    PolicyDecision,
    ToolInvocation,
    ToolInvocationStatus,
    ToolResult,
    ToolSpec,
)

from .validation import ArgumentValidationError, validate_arguments


class Resolver(Protocol):
    def resolve(self, hostname: str) -> Sequence[str]: ...


class SocketResolver:
    """System resolver adapter. Tests and replay should inject StaticResolver."""

    def resolve(self, hostname: str) -> tuple[str, ...]:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
        return tuple(sorted(addresses))


class StaticResolver:
    def __init__(self, addresses: Mapping[str, Sequence[str]]) -> None:
        self._addresses = {
            hostname.rstrip(".").lower(): tuple(values)
            for hostname, values in addresses.items()
        }

    def resolve(self, hostname: str) -> tuple[str, ...]:
        key = hostname.rstrip(".").lower()
        if key not in self._addresses:
            raise OSError(f"no test DNS record for {hostname}")
        return self._addresses[key]


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    elapsed_seconds: float = 0
    tool_calls: int = 0
    attempts_for_step: int = 0


_RISK_ORDER = {
    RiskLevel.R0: 0,
    RiskLevel.R1: 1,
    RiskLevel.R2: 2,
    RiskLevel.R3: 3,
}
_DENIED_HOSTNAMES = {
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


class PolicyGate:
    POLICY_VERSION = "scope-policy/1.0"

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        allowed_private_networks: Sequence[str] = (),
    ) -> None:
        self._resolver = resolver or SocketResolver()
        networks = tuple(ipaddress.ip_network(value, strict=True) for value in allowed_private_networks)
        if any(not network.is_private for network in networks):
            raise ValueError("allowed private networks must be non-public CIDR ranges")
        self._allowed_private_networks = networks

    def evaluate(
        self,
        invocation: ToolInvocation,
        spec: ToolSpec,
        scope: ScopePolicy,
        budget: Budget,
        usage: BudgetUsage,
    ) -> PolicyDecision:
        if (
            invocation.status is not ToolInvocationStatus.PROPOSED
            or invocation.policy_decision_ref is not None
        ):
            return self._decision(False, ["INVOCATION_NOT_PROPOSED"])

        reasons: list[str] = []
        constrained: dict[str, object] = {}

        if invocation.deadline <= datetime.now(timezone.utc):
            reasons.append("INVOCATION_DEADLINE_EXCEEDED")
        if (
            invocation.tool_ref.tool_id != spec.tool_id
            or invocation.tool_ref.version != spec.version
        ):
            reasons.append("TOOL_REFERENCE_MISMATCH")
        if spec.tool_id not in scope.allowed_tool_ids:
            reasons.append("TOOL_NOT_AUTHORIZED")
        if spec.risk_level is RiskLevel.R3 or _RISK_ORDER[spec.risk_level] > _RISK_ORDER[scope.maximum_risk]:
            reasons.append("RISK_LEVEL_DENIED")
        if usage.tool_calls >= budget.max_tool_calls:
            reasons.append("TOOL_BUDGET_EXCEEDED")
        if usage.elapsed_seconds >= budget.max_duration_seconds:
            reasons.append("RUN_DEADLINE_EXCEEDED")
        if usage.attempts_for_step >= budget.max_attempts_per_step:
            reasons.append("STEP_ATTEMPT_BUDGET_EXCEEDED")
        if invocation.attempt > budget.max_attempts_per_step:
            reasons.append("STEP_ATTEMPT_BUDGET_EXCEEDED")

        try:
            constrained = validate_arguments(invocation.validated_arguments, spec.input_schema)
        except ArgumentValidationError:
            reasons.append("ARGUMENT_SCHEMA_INVALID")

        if spec.permissions.network:
            if not scope.network_access:
                reasons.append("NETWORK_ACCESS_DENIED")
            for key in ("url", "base_url"):
                value = constrained.get(key)
                if isinstance(value, str):
                    reasons.extend(self._check_url(value, scope))

        if reasons:
            return self._decision(False, reasons)
        return self._decision(True, ["POLICY_ALLOWED"], constrained)

    def check_redirect(
        self,
        *,
        current_url: str,
        location: str,
        scope: ScopePolicy,
    ) -> PolicyDecision:
        redirected = urljoin(current_url, location)
        reasons = self._check_url(redirected, scope)
        if reasons:
            return self._decision(False, reasons)
        return self._decision(True, ["POLICY_ALLOWED"], {"url": redirected})

    def review_result(
        self,
        invocation: ToolInvocation,
        result: ToolResult,
        scope: ScopePolicy,
    ) -> tuple[PolicyDecision, ...]:
        """Review structured follow-up targets without performing another execution."""

        if "redirects" not in result.normalized_output:
            return ()
        current_url = invocation.validated_arguments.get("url")
        redirects = result.normalized_output.get("redirects")
        if not isinstance(current_url, str) or not isinstance(redirects, list):
            return (self._decision(False, ["RESULT_POLICY_INPUT_INVALID"]),)
        if any(not isinstance(location, str) for location in redirects):
            return (self._decision(False, ["RESULT_POLICY_INPUT_INVALID"]),)

        decisions: list[PolicyDecision] = []
        for location in redirects:
            decision = self.check_redirect(
                current_url=current_url,
                location=location,
                scope=scope,
            )
            decisions.append(decision)
            if not decision.allowed:
                break
            redirected = decision.constrained_arguments.get("url")
            if not isinstance(redirected, str):
                decisions.append(
                    self._decision(False, ["RESULT_POLICY_OUTPUT_INVALID"])
                )
                break
            current_url = redirected
        return tuple(decisions)

    def _check_url(self, raw_url: str, scope: ScopePolicy) -> list[str]:
        if any(character in raw_url for character in ("\\", "\r", "\n", "\t", "\x00")):
            return ["URL_INVALID"]
        try:
            parsed = urlsplit(raw_url)
            port = parsed.port
        except ValueError:
            return ["URL_INVALID"]
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").rstrip(".").lower()
        if scheme not in {"http", "https"}:
            return ["URL_SCHEME_DENIED"]
        if not hostname:
            return ["URL_HOST_MISSING"]
        if parsed.username is not None or parsed.password is not None:
            return ["URL_CREDENTIALS_DENIED"]
        if hostname in _DENIED_HOSTNAMES:
            return ["HOSTNAME_DENIED"]
        effective_port = port or (443 if scheme == "https" else 80)
        if not self._target_is_allowed(
            parsed=parsed,
            scheme=scheme,
            hostname=hostname,
            port=effective_port,
            targets=scope.allowed_targets,
        ):
            return ["TARGET_NOT_AUTHORIZED"]
        if self._target_is_allowed(
            parsed=parsed,
            scheme=scheme,
            hostname=hostname,
            port=effective_port,
            targets=scope.denied_targets,
        ):
            return ["TARGET_EXPLICITLY_DENIED"]
        try:
            addresses = self._resolved_addresses(hostname)
        except (OSError, ValueError):
            return ["DNS_RESOLUTION_FAILED"]
        if not addresses:
            return ["DNS_RESOLUTION_FAILED"]
        if any(self._address_is_denied(address) for address in addresses):
            return ["RESOLVED_ADDRESS_DENIED"]
        return []

    def _resolved_addresses(self, hostname: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        try:
            return (ipaddress.ip_address(hostname),)
        except ValueError:
            return tuple(ipaddress.ip_address(value) for value in self._resolver.resolve(hostname))

    def _address_is_denied(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if (
            address in _METADATA_ADDRESSES
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            return True
        if address.is_private or address.is_reserved:
            return not any(address in network for network in self._allowed_private_networks)
        return False

    @staticmethod
    def _target_is_allowed(
        *,
        parsed,
        scheme: str,
        hostname: str,
        port: int,
        targets: Sequence[ScopeTarget],
    ) -> bool:
        for target in targets:
            if target.protocols and scheme not in target.protocols:
                continue
            if target.ports and port not in target.ports:
                continue
            if target.kind is TargetKind.URL:
                try:
                    allowed = urlsplit(target.value)
                    allowed_port = allowed.port
                except ValueError:
                    continue
                if allowed_port is not None:
                    port_matches = allowed_port == port
                elif target.ports:
                    # An explicit ScopeTarget.ports set is authoritative when
                    # the URL value itself omits a port.
                    port_matches = True
                else:
                    default_port = 443 if allowed.scheme.lower() == "https" else 80
                    port_matches = default_port == port
                allowed_path = allowed.path or "/"
                request_path = parsed.path or "/"
                path_matches = (
                    allowed_path == "/"
                    or request_path == allowed_path
                    or request_path.startswith(allowed_path.rstrip("/") + "/")
                )
                if (
                    allowed.scheme.lower() == scheme
                    and (allowed.hostname or "").rstrip(".").lower() == hostname
                    and port_matches
                    and path_matches
                ):
                    return True
            elif target.kind in {TargetKind.HOST, TargetKind.IP}:
                if target.value.rstrip(".").lower() == hostname:
                    return True
        return False

    def _decision(
        self,
        allowed: bool,
        reasons: Sequence[str],
        constrained: Mapping[str, object] | None = None,
    ) -> PolicyDecision:
        # Preserve order while removing duplicates so audit output is stable.
        unique_reasons = list(dict.fromkeys(reasons))
        return PolicyDecision(
            allowed=allowed,
            policy_version=self.POLICY_VERSION,
            reason_codes=unique_reasons,
            constrained_arguments=dict(constrained or {}),
        )
