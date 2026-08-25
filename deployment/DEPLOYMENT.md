# 网络安全智能体部署指南

**XH-202609 比赛提交版本**  
**截止日期：2026-09-05**

---

## 📋 系统要求

- **操作系统**: Windows 10 22H2+ / Windows 11
- **Python**: 3.11 - 3.13
- **内存**: 最低 4GB RAM（推荐 8GB+）
- **磁盘**: 最低 2GB 可用空间
- **Docker**: 可选（用于容器隔离场景）

---

## 🚀 快速启动

### 方法一：一键启动（推荐）

```bash
# 1. 安装依赖
uv sync

# 2. 双击运行启动脚本
deployment\start.bat
```

### 方法二：命令行启动

```bash
# 激活虚拟环境
.venv\Scripts\activate

# 启动管理控制台
python -m cyber_agent.server --admin

# 或启动任务工作台
python -m cyber_agent.server --workbench
```

---

## 🏗️ 架构概览

```
┌─────────────────────────────────────────────────┐
│           Web UI (React + FastAPI)              │
├─────────────────────────────────────────────────┤
│  Planner → Policy Gate → Executor → Verifier   │
├─────────────────────────────────────────────────┤
│     Workspace Isolation + Audit Store           │
└─────────────────────────────────────────────────┘
```

### 核心组件

1. **Planner**: 基于 LLM 的决策规划器
2. **Policy Gate**: 风险评估与策略门禁
3. **Executor**: 工具执行器（沙箱隔离）
4. **Verifier**: 结果验证器

---

## 📦 支持场景

| 场景 ID | 名称 | 状态 |
|---------|------|------|
| `source_audit` | 源代码安全审计 | ✅ 完整实现 |
| `web_idor` | Web IDOR 漏洞检测 | ✅ 完整实现 |
| `pwn_ret2win` | Pwn Ret2win 利用 | ✅ 完整实现 |
| `reverse_keycheck` | 逆向密钥检测 | ✅ 完整实现 |
| `incident_login_chain` | 应急响应-登录链分析 | ✅ 完整实现 |

---

## 🔧 配置说明

### 环境变量

复制 `deployment/.env.example` 为 `.env` 并修改：

```bash
# 运行时数据目录
CYBER_AGENT_RUNTIME_ROOT=D:\cybersec\runtime

# 模型 API 密钥
KIMI_API_KEY=your_key_here
DEEPSEEK_API_KEY=your_key_here
```

### 数据目录结构

```
var/workbench/
├── state.db              # 工作台状态数据库
├── audit.db              # 审计日志数据库
├── workspaces/           # 任务隔离工作空间
│   ├── task_xxx/
│   │   ├── attachments/  # 用户上传文件
│   │   ├── artifacts/    # 工具输出
│   │   └── logs/         # 执行日志
├── source-artifacts/     # 源代码审计临时文件
└── ...
```

---

## 🛡️ 安全特性

### 1. Workspace 隔离
每个任务运行在独立目录，防止文件冲突和交叉污染。

### 2. SQLite 审计日志
- 三表设计：tasks / decisions / tool_calls
- 外键约束 + WAL 模式
- 完整决策链可追溯

### 3. 沙箱执行
- **Source Audit**: Windows Job Object 资源限制
- **Web/Pwn**: Docker + gVisor 双重隔离
- **Incident**: 只读日志分析

### 4. 策略门禁
- 风险等级评估（R0-R4）
- 自动拒绝 R3/R4 高危操作
- 用户审批机制

---

## 📊 监控与调试

### 查看审计日志

```python
from cyber_agent.audit_store import SQLiteAuditStore

store = SQLiteAuditStore(db_path="var/workbench/audit.db")
timeline = store.get_task_timeline(task_id="xxx")
print(timeline)
```

### 查看工作空间

```bash
# 列出所有任务工作空间
dir var\workbench\workspaces\

# 查看特定任务的输出
type var\workbench\workspaces\task_xxx\artifacts\*
```

---

## 🧪 测试验证

### 功能测试

```bash
# 运行单元测试
pytest tests/ -v

# 运行场景集成测试
pytest tests/integration/ -k source_audit
pytest tests/integration/ -k web_idor
```

### 健康检查

访问 `http://127.0.0.1:8765/health` 查看系统状态。

---

## 📝 比赛提交检查清单

- [x] 5个场景全部实现
- [x] Workspace 隔离
- [x] SQLite 持久化审计
- [x] 策略门禁机制
- [x] 前端决策可视化
- [x] 部署脚本和文档
- [ ] 答辩演示材料
- [ ] 录屏视频

---

## 🐛 故障排查

### 问题：端口 8765 被占用

```bash
# 使用其他端口
python -m cyber_agent.server --port 9000
```

### 问题：Docker 不可用

Source Audit 和 Incident 场景不需要 Docker，仍可运行。  
Web IDOR 和 Pwn 场景需要 Docker Desktop。

### 问题：模型 API 调用失败

检查 `.env` 文件中的 API 密钥是否正确配置。

---

## 📞 联系方式

**项目名称**: CyberSecurity-Agent  
**版本**: 0.1.0-alpha.1  
**比赛**: XH-202609  
**提交日期**: 2026-09-05
