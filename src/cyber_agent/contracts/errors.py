"""Stable exception types at public module boundaries."""

from __future__ import annotations

from .common import ErrorInfo


class CyberAgentError(Exception):
    """Base exception carrying a safe, serializable error contract."""

    def __init__(self, error: ErrorInfo) -> None:
        super().__init__(error.safe_message)
        self.error = error


class ContractValidationError(CyberAgentError):
    """Raised when a boundary value cannot satisfy its public contract."""


class PolicyDeniedError(CyberAgentError):
    """Raised when a proposed action is rejected by policy."""
