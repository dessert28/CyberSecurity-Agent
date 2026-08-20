"""Immutable trusted resource ceilings for the formal Source Audit Runtime."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .common import StrictModel


class SourceAuditResourceBudget(StrictModel):
    """Server-owned limits; callers may tighten but never exceed these ceilings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    budget_version: Literal["source-audit-resource/v1"] = "source-audit-resource/v1"
    max_upload_bytes: int = Field(default=10_000_000, ge=1, le=10_000_000)
    max_uncompressed_bytes: int = Field(default=50_000_000, ge=1, le=50_000_000)
    max_members: int = Field(default=2_000, ge=1, le=2_000)
    max_member_bytes: int = Field(default=5_000_000, ge=1, le=5_000_000)
    max_python_file_bytes: int = Field(default=1_000_000, ge=1, le=1_000_000)
    max_ast_nodes_per_file: int = Field(default=200_000, ge=1, le=200_000)
    inventory_timeout_seconds: int = Field(default=30, ge=1, le=30)
    dataflow_timeout_seconds: int = Field(default=30, ge=1, le=30)
    validation_timeout_seconds: int = Field(default=10, ge=1, le=10)
    cpu_cores: float = Field(default=1.0, gt=0, le=1.0)
    memory_megabytes: int = Field(default=256, ge=16, le=256)
    max_processes: Literal[1] = 1
    inventory_output_bytes: int = Field(default=5_000_000, ge=1, le=5_000_000)
    dataflow_output_bytes: int = Field(default=5_000_000, ge=1, le=5_000_000)
    validation_output_bytes: int = Field(default=2_000_000, ge=1, le=2_000_000)

    @model_validator(mode="after")
    def validate_nested_limits(self) -> "SourceAuditResourceBudget":
        if self.max_member_bytes > self.max_uncompressed_bytes:
            raise ValueError("member limit cannot exceed total expanded-size limit")
        if self.max_python_file_bytes > self.max_member_bytes:
            raise ValueError("Python file limit cannot exceed member-size limit")
        return self

    def timeout_for(self, handler_id: str) -> int:
        try:
            return {
                "source.project_inventory": self.inventory_timeout_seconds,
                "source.python_dataflow": self.dataflow_timeout_seconds,
                "source.hypothesis_validate": self.validation_timeout_seconds,
            }[handler_id]
        except KeyError as exc:
            raise ValueError("source handler is not allowlisted") from exc

    def output_limit_for(self, handler_id: str) -> int:
        try:
            return {
                "source.project_inventory": self.inventory_output_bytes,
                "source.python_dataflow": self.dataflow_output_bytes,
                "source.hypothesis_validate": self.validation_output_bytes,
            }[handler_id]
        except KeyError as exc:
            raise ValueError("source handler is not allowlisted") from exc

    def fingerprint_input(self) -> dict[str, object]:
        values = self.model_dump(mode="python")
        return {
            "budget_contract": values.pop("budget_version"),
            **values,
        }


__all__ = ["SourceAuditResourceBudget"]
