#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Integration test script - Verify 5 scenarios"""

import asyncio
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Force UTF-8 output
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from cyber_agent.task_packs import build_competition_task_pack_catalog
from cyber_agent.tools import ToolRegistry
from cyber_agent.audit_store import SQLiteAuditStore
from cyber_agent.workbench import LocalWorkspaceManager


async def test_catalog():
    """Test scenario catalog"""
    print("\n=== Test Scenario Catalog ===")
    catalog = build_competition_task_pack_catalog()
    manifests = catalog.list()
    print(f"[OK] Registered scenarios: {len(manifests)}")

    expected_ids = [
        "source.audit.python",
        "web.idor",
        "pwn.ret2win",
        "reverse.keycheck",
        "incident.login_chain"
    ]

    registered_ids = [m.task_pack_id for m in manifests]
    for expected_id in expected_ids:
        if expected_id in registered_ids:
            print(f"  [OK] {expected_id}")
        else:
            print(f"  [FAIL] {expected_id} (missing)")
            return False

    return len(manifests) == 5


async def test_tools():
    """Test tool registration"""
    print("\n=== Test Tool Registration ===")
    from cyber_agent.tools import (
        HttpRequestPlugin,
        ProjectInventoryPlugin,
        PythonDataflowPlugin,
        BinaryPropertiesPlugin,
        ProcessInteractionPlugin,
    )

    registry = ToolRegistry()
    plugins = [
        HttpRequestPlugin(runtime_available=lambda: False),
        ProjectInventoryPlugin(runtime_available=lambda: False),
        PythonDataflowPlugin(runtime_available=lambda: False),
        BinaryPropertiesPlugin(runtime_available=lambda: False),
        ProcessInteractionPlugin(runtime_available=lambda: False),
    ]

    for plugin in plugins:
        try:
            await registry.register_checked(plugin)
            spec = plugin.get_spec()
            print(f"  [OK] {spec.tool_id}")
        except Exception as e:
            print(f"  [FAIL] {plugin.__class__.__name__}: {e}")
            return False

    return True


def test_workspace():
    """Test workspace management"""
    print("\n=== Test Workspace Management ===")
    import tempfile
    import shutil

    temp_root = Path(tempfile.mkdtemp())
    try:
        manager = LocalWorkspaceManager(root=temp_root)

        # Create workspace
        task_id = "test_task_001"
        workspace = manager.create_workspace(task_id)

        if not workspace.exists():
            print(f"  [FAIL] Workspace creation failed")
            return False

        required_dirs = ["attachments", "artifacts", "logs"]
        for dir_name in required_dirs:
            if not (workspace / dir_name).exists():
                print(f"  [FAIL] Missing subdirectory: {dir_name}")
                return False

        print(f"  [OK] Workspace created")

        # Get workspace
        retrieved = manager.get_workspace(task_id)
        if retrieved != workspace:
            print(f"  [FAIL] Workspace retrieval failed")
            return False

        print(f"  [OK] Workspace retrieved")

        # Cleanup workspace
        manager.cleanup_workspace(task_id)
        if workspace.exists():
            print(f"  [FAIL] Workspace cleanup failed")
            return False

        print(f"  [OK] Workspace cleaned up")

        return True
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def test_audit_store():
    """Test audit store"""
    print("\n=== Test Audit Store ===")
    import tempfile
    from datetime import datetime
    from cyber_agent.audit_store import TaskRecord, DecisionRecord, ToolCallRecord

    temp_db = Path(tempfile.mktemp(suffix=".db"))
    try:
        store = SQLiteAuditStore(db_path=temp_db)

        # Create task
        task = TaskRecord(
            id="task_001",
            title="Test Task",
            category="source_audit",
            status="running",
            workspace_path="/tmp/task_001",
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
        )
        store.create_task(task)
        print(f"  [OK] Task record created")

        # Append decision
        decision = DecisionRecord(
            id="decision_001",
            task_id="task_001",
            sequence=1,
            planner_output='{"plan": "test"}',
            risk_level="R1",
            approved=True,
            created_at=datetime.utcnow().isoformat(),
        )
        store.append_decision(decision)
        print(f"  [OK] Decision record appended")

        # Append tool call
        tool_call = ToolCallRecord(
            id="call_001",
            task_id="task_001",
            decision_id="decision_001",
            tool_name="http.request",
            arguments='{"url": "http://test"}',
            result='{"status": 200}',
            status="succeeded",
            created_at=datetime.utcnow().isoformat(),
        )
        store.append_tool_call(tool_call)
        print(f"  [OK] Tool call record appended")

        # Get timeline
        timeline = store.get_task_timeline("task_001")
        if len(timeline) < 2:
            print(f"  [FAIL] Timeline retrieval failed: {len(timeline)} records")
            return False

        print(f"  [OK] Timeline retrieved: {len(timeline)} records")

        # Get task
        retrieved_task = store.get_task("task_001")
        if retrieved_task is None or retrieved_task.id != "task_001":
            print(f"  [FAIL] Task retrieval failed")
            return False

        print(f"  [OK] Task retrieved")

        store.close()
        return True
    finally:
        if temp_db.exists():
            temp_db.unlink()


async def main():
    """Run all tests"""
    print("=" * 60)
    print("CyberSecurity Agent - Integration Test")
    print("XH-202609 Competition Submission")
    print("=" * 60)

    tests = [
        ("Scenario Catalog", test_catalog),
        ("Tool Registration", test_tools),
        ("Workspace Management", test_workspace),
        ("Audit Store", test_audit_store),
    ]

    results = []
    for name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n[FAIL] {name} exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status}: {name}")

    print(f"\nTotal: {passed}/{total} passed")

    if passed == total:
        print("\n[OK] All tests passed! System ready.")
        return 0
    else:
        print(f"\n[FAIL] {total - passed} test(s) failed. Please check system configuration.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
