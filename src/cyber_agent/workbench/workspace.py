"""Workspace isolation for multi-task execution.

Each task gets an independent directory to prevent file conflicts and
enable clean audit trails. Borrowed from CTF-BTFly's workspace design.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Protocol


class WorkspaceManager(Protocol):
    """Protocol for workspace lifecycle management."""

    def create_workspace(self, task_id: str) -> Path:
        """Create an isolated workspace for a task."""
        ...

    def get_workspace(self, task_id: str) -> Path | None:
        """Retrieve workspace path if it exists."""
        ...

    def cleanup_workspace(self, task_id: str) -> None:
        """Remove workspace and all contents."""
        ...


class LocalWorkspaceManager:
    """File-system backed workspace manager.

    Creates directory structure:
        workspaces/
            task_{task_id}/
                attachments/  # User-uploaded files
                artifacts/    # Tool outputs
                logs/         # Execution logs
    """

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def create_workspace(self, task_id: str) -> Path:
        """Create workspace with standard subdirectories."""
        workspace = self.root / f"task_{task_id}"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "attachments").mkdir(exist_ok=True)
        (workspace / "artifacts").mkdir(exist_ok=True)
        (workspace / "logs").mkdir(exist_ok=True)
        return workspace

    def get_workspace(self, task_id: str) -> Path | None:
        """Return workspace path if it exists, None otherwise."""
        workspace = self.root / f"task_{task_id}"
        return workspace if workspace.exists() else None

    def cleanup_workspace(self, task_id: str) -> None:
        """Remove workspace directory tree."""
        workspace = self.root / f"task_{task_id}"
        if workspace.exists():
            shutil.rmtree(workspace, ignore_errors=True)

    def list_workspaces(self) -> list[str]:
        """Return all task IDs with active workspaces."""
        return [
            d.name.removeprefix("task_")
            for d in self.root.iterdir()
            if d.is_dir() and d.name.startswith("task_")
        ]
