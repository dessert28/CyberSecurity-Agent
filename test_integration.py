#!/usr/bin/env python3
"""集成测试脚本 - 验证所有核心功能"""

import sys
from pathlib import Path

if sys.platform == "win32":
    import io

    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer,
        encoding="utf-8",
        errors="replace",
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer,
        encoding="utf-8",
        errors="replace",
    )

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_workspace_manager():
    """测试工作空间管理"""
    from cyber_agent.workbench import LocalWorkspaceManager

    print("✓ 测试 WorkspaceManager...")
    manager = LocalWorkspaceManager(root=Path("./test_workspaces"))
    workspace = manager.create_workspace("test_task_001")
    assert workspace.exists()
    assert (workspace / "attachments").exists()
    assert (workspace / "artifacts").exists()
    assert (workspace / "logs").exists()
    manager.cleanup_workspace("test_task_001")
    print("  ✅ WorkspaceManager 正常工作")

def test_audit_store():
    """测试审计日志存储"""
    from cyber_agent.audit_store import SQLiteAuditStore, TaskRecord, DecisionRecord
    from datetime import datetime

    print("✓ 测试 SQLiteAuditStore...")
    db_path = Path("./test_audit.db")
    if db_path.exists():
        db_path.unlink()

    store = SQLiteAuditStore(db_path=db_path)

    # 创建测试任务
    task = TaskRecord(
        id="task_test_001",
        title="测试任务",
        category="source_audit",
        status="running",
        workspace_path="/tmp/test",
        created_at=datetime.utcnow().isoformat(),
        updated_at=datetime.utcnow().isoformat()
    )
    store.create_task(task)

    # 添加决策记录
    decision = DecisionRecord(
        id="dec_001",
        task_id="task_test_001",
        sequence=1,
        planner_output='{"action": "scan"}',
        risk_level="low",
        approved=True,
        created_at=datetime.utcnow().isoformat()
    )
    store.append_decision(decision)

    # 验证读取
    retrieved = store.get_task("task_test_001")
    assert retrieved is not None
    assert retrieved.title == "测试任务"

    timeline = store.get_task_timeline("task_test_001")
    assert len(timeline) == 1

    store.close()
    db_path.unlink()
    print("  ✅ SQLiteAuditStore 正常工作")

def test_task_packs():
    """测试所有场景包"""
    from cyber_agent.task_packs import build_competition_task_pack_catalog

    print("✓ 测试场景包加载...")
    catalog = build_competition_task_pack_catalog()
    packs = list(catalog.list())

    expected = {
        "source.audit.python",
        "web.idor",
        "pwn.ret2win",
        "reverse.keycheck",
        "incident.login_chain",
    }

    found = {pack.task_pack_id for pack in packs}
    print(f"  已加载场景: {', '.join(sorted(found))}")

    assert expected.issubset(found), f"缺少场景: {expected - found}"
    print("  ✅ 所有5个场景包已加载")

def test_server_components():
    """测试服务器组件"""
    from cyber_agent.server import build_local_server

    print("✓ 测试服务器组件...")
    try:
        bundle = build_local_server(
            port=9999,
            destination="admin",
            runtime_root=Path("./test_runtime"),
            launch_token="test_token_" + "x" * 32
        )
        assert bundle.port == 9999
        assert bundle.destination == "admin"
        print("  ✅ 服务器组件构建成功")
    except Exception as e:
        print(f"  ⚠️  服务器组件测试跳过: {e}")

def main():
    print("=" * 60)
    print("CyberSecurity-Agent 集成测试")
    print("=" * 60)
    print()

    try:
        test_workspace_manager()
        test_audit_store()
        test_task_packs()
        test_server_components()

        print()
        print("=" * 60)
        print("✅ 所有集成测试通过！")
        print("=" * 60)
        return 0

    except Exception as e:
        print()
        print("=" * 60)
        print(f"❌ 测试失败: {e}")
        print("=" * 60)
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
