from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_integration_script_runs_with_a_gbk_console_encoding() -> None:
    """The repository smoke-test entrypoint must work on a default Windows console."""

    root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "gbk"
    environment["PYTHONUTF8"] = "0"
    completed = subprocess.run(
        [sys.executable, "test_integration.py"],
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )

    output = completed.stdout.decode("utf-8", errors="replace")
    assert completed.returncode == 0, output
