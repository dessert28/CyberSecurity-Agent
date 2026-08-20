"""Verification implementation boundary."""
"""Independent, deterministic result verification."""

from .registry import VerifierRegistry, VerifierRegistryError
from .source_audit import SOURCE_AUDIT_VERIFIER_ID, SourceAuditVerifier
from .web_idor import WebIdorVerifier, canonical_json_sha256

__all__ = [
    "VerifierRegistry",
    "VerifierRegistryError",
    "SOURCE_AUDIT_VERIFIER_ID",
    "SourceAuditVerifier",
    "WebIdorVerifier",
    "canonical_json_sha256",
]
