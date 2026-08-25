"""Shared probe-based health behavior for built-in tool plugins."""

from __future__ import annotations

import traceback
from collections.abc import Callable
from typing import Any

from cyber_agent.contracts.tool import ToolHealth, ToolRef


class ToolHealthMixin:
    """Catch probe exceptions and keep the full stack for diagnostics."""

    last_health_exception: str | None = None

    def probe_health(
        self,
        *,
        probe: Callable[[], Any],
        success_message: str,
        failure_message: str,
        tool_ref: ToolRef,
    ) -> ToolHealth:
        available = False
        detail = ""
        try:
            result = probe()
        except Exception:
            available = False
            self.last_health_exception = traceback.format_exc()
        else:
            self.last_health_exception = None
            if isinstance(result, tuple) and result:
                available = bool(result[0])
                detail = str(result[1] or "")
            else:
                available = bool(result)
        if available:
            message = success_message
        else:
            message = failure_message
            if detail:
                message = f"{message}: {detail.strip()}"
            elif self.last_health_exception:
                last_line = self.last_health_exception.strip().splitlines()[-1]
                message = f"{message}: {last_line}"
        return ToolHealth(tool_ref=tool_ref, available=available, message=message)


__all__ = ["ToolHealthMixin"]
