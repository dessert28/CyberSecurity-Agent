# 技术架构文档

**XH-202609 网络安全智能体**  
**CyberSecurity-Agent v0.1.0-alpha.1**

---

## 1. 整体架构

### 1.1 四层架构设计

```
┌──────────────────────────────────────────────────────────┐
│                    Presentation Layer                     │
│         React Frontend + FastAPI REST API                │
├──────────────────────────────────────────────────────────┤
│                     Decision Layer                        │
│  Planner (LLM) → Policy Gate → Executor → Verifier      │
├──────────────────────────────────────────────────────────┤
│                   Infrastructure Layer                    │
│  Workspace Manager + Audit Store + Tool Registry         │
├──────────────────────────────────────────────────────────┤
│                     Execution Layer                       │
│  Windows Job Object / Docker + gVisor Sandbox            │
└──────────────────────────────────────────────────────────┘
```

### 1.2 契约驱动设计

所有组件通过 **JSON Schema 契约** 交互，确保类型安全和可验证性：

- **Planner Output**: 结构化决策提案（JSON Schema 验证）
- **Tool Input/Output**: 强类型参数和结果
- **Audit Record**: 标准化审计日志格式

---

## 2. 核心组件详解

### 2.1 Planner（规划器）

**职责**: 理解任务需求，生成结构化执行计划

**实现**:
- 基于 LLM（Kimi/DeepSeek）的自然语言理解
- JSON Schema 约束输出格式
- 上下文管理：任务历史 + 工具能力 + 场景知识

**输出示例**:
```json
{
  "task_understanding": "检测 IDOR 漏洞",
  "execution_plan": {
    "steps": [
      {
        "tool": "endpoint_discovery",
        "arguments": {"base_url": "http://target"}
      },
      {
        "tool": "http_request",
        "arguments": {"method": "GET", "url": "..."}
      }
    ]
  },
  "risk_assessment": {
    "level": "R1",
    "justification": "只读 HTTP 请求"
  }
}
```

### 2.2 Policy Gate（策略门禁）

**职责**: 风险评估，决定是否允许工具执行

**实现**:
```python
class PolicyGate:
    def evaluate(self, proposal: PlannerOutput) -> PolicyDecision:
        risk = proposal.risk_assessment.level
        if risk in ("R3", "R4"):
            return PolicyDecision(approved=False, reason="高危操作")
        if risk == "R2" and not user_approved:
            return PolicyDecision(approved=False, reason="需要用户审批")
        return PolicyDecision(approved=True)
```

**风险等级**:
- **R0**: 无风险（只读查询）
- **R1**: 低风险（本地文件读取）
- **R2**: 中风险（网络请求）
- **R3**: 高风险（文件写入）
- **R4**: 极高风险（代码执行）

### 2.3 Executor（执行器）

**职责**: 在沙箱中安全执行工具调用

**隔离机制**:

| 场景 | 隔离方式 | 资源限制 |
|------|----------|----------|
| Source Audit | Windows Job Object | CPU 1核, 内存 256MB, 进程数 1 |
| Web IDOR | Docker + gVisor | 无网络, tmpfs 文件系统 |
| Pwn Ret2win | Docker + gVisor | 交互式 I/O, 超时 30s |
| Reverse | Docker + gVisor | 只读文件系统 |
| Incident | 本地进程 | 只读日志文件 |

**执行流程**:
```python
request = executor_provider.prepare(invocation)
# 1. 创建隔离环境
# 2. 挂载必要文件（只读）
# 3. 设置资源限制
# 4. 执行工具
# 5. 收集输出
# 6. 清理环境
result = await executor_provider.execute(request)
```

### 2.4 Verifier（验证器）

**职责**: 验证执行结果的正确性和完整性

**场景验证器**:

```python
# Web IDOR Verifier
class WebIdorVerifier:
    def verify(self, result: ToolResult) -> VerificationOutcome:
        # 1. 检查是否成功访问其他用户资源
        # 2. 对比不同用户 ID 的响应
        # 3. 确认漏洞存在性
        return VerificationOutcome(...)

# Source Audit Verifier
class SourceAuditVerifier:
    def verify(self, result: ToolResult) -> VerificationOutcome:
        # 1. 验证发现的漏洞位置
        # 2. 检查误报率
        # 3. 生成审计报告
        return VerificationOutcome(...)
```

---

## 3. 持久化设计

### 3.1 Workspace 隔离

每个任务运行在独立工作空间：

```
var/workbench/workspaces/
└── task_{uuid}/
    ├── attachments/    # 用户上传的文件
    ├── artifacts/      # 工具生成的输出
    └── logs/           # 执行日志
```

**实现**:
```python
class LocalWorkspaceManager:
    def create_workspace(self, task_id: str) -> Path:
        workspace = self.root / f"task_{task_id}"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "attachments").mkdir()
        (workspace / "artifacts").mkdir()
        (workspace / "logs").mkdir()
        return workspace
```

### 3.2 SQLite 审计日志

**三表设计**:

```sql
-- 任务元数据
CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,  -- source_audit, web_idor, ...
    status TEXT NOT NULL,    -- pending, running, completed, failed
    workspace_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 决策记录（Planner 输出）
CREATE TABLE decisions (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id),
    sequence INTEGER NOT NULL,  -- 决策序号
    planner_output TEXT NOT NULL,  -- JSON 序列化的提案
    risk_level TEXT NOT NULL,
    approved BOOLEAN NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(task_id, sequence)
);

-- 工具调用记录（Executor 执行）
CREATE TABLE tool_calls (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id),
    decision_id TEXT REFERENCES decisions(id),
    tool_name TEXT NOT NULL,
    arguments TEXT NOT NULL,  -- JSON
    result TEXT NOT NULL,
    status TEXT NOT NULL,  -- succeeded, failed, timeout
    created_at TEXT NOT NULL
);
```

**索引优化**:
```sql
CREATE INDEX idx_decisions_task_seq ON decisions(task_id, sequence);
CREATE INDEX idx_tool_calls_task ON tool_calls(task_id, created_at);
```

**查询示例**:
```python
# 获取任务的完整决策链
timeline = store.get_task_timeline(task_id="xxx")
# [
#   {"type": "decision", "sequence": 1, ...},
#   {"type": "tool_call", "tool_name": "http_request", ...},
#   {"type": "decision", "sequence": 2, ...},
#   ...
# ]
```

---

## 4. 工具插件系统

### 4.1 工具注册

```python
class ToolRegistry:
    async def register_checked(self, plugin: ToolPlugin):
        spec = plugin.get_spec()
        # 验证 JSON Schema
        validate_schema(spec.input_schema)
        validate_schema(spec.output_schema)
        self._plugins[spec.tool_id] = plugin
```

### 4.2 内置工具

| 工具 ID | 功能 | 场景 |
|---------|------|------|
| `http.request` | HTTP 请求 | Web IDOR |
| `http.endpoint_discovery` | API 端点发现 | Web IDOR |
| `python.dataflow` | Python 数据流分析 | Source Audit |
| `project.inventory` | 项目文件清单 | Source Audit |
| `pwn.binary_properties` | ELF 二进制分析 | Pwn Ret2win |
| `pwn.process_interaction` | 进程交互 | Pwn Ret2win |
| `reverse.static_extract` | 静态字符串提取 | Reverse |
| `reverse.run_verify` | 运行时验证 | Reverse |
| `incident.log_inventory` | 日志文件清单 | Incident |
| `incident.log_search` | 日志搜索 | Incident |

### 4.3 工具生命周期

```python
# 1. 准备阶段
invocation = ToolInvocation(...)
request = plugin.prepare(invocation)

# 2. 执行阶段
raw_result = await executor.execute(request)

# 3. 解析阶段
result = plugin.parse(raw_result)

# 4. 审计记录
await audit_store.append_tool_call(...)
```

---

## 5. 模型适配层

### 5.1 统一接口

```python
class ModelAdapter(Protocol):
    async def complete(
        self,
        messages: list[Message],
        schema: dict | None = None,
    ) -> CompletionResult:
        ...
```

### 5.2 支持的模型

- **Kimi**: Moonshot AI (国产)
- **DeepSeek**: DeepSeek (国产)
- **GPT-4**: OpenAI (需翻墙)
- **Claude**: Anthropic (需翻墙)

### 5.3 JSON Schema 强制输出

```python
# 确保 LLM 输出结构化 JSON
result = await adapter.complete(
    messages=[...],
    schema={
        "type": "object",
        "properties": {
            "task_understanding": {"type": "string"},
            "execution_plan": {"type": "object", ...}
        },
        "required": ["task_understanding", "execution_plan"]
    }
)
```

---

## 6. 安全设计

### 6.1 Fail-Closed 原则

**LLM 不直接执行工具**，所有操作必须经过：

1. Planner 生成提案
2. Policy Gate 评估风险
3. 用户审批（R2+ 风险）
4. Executor 沙箱执行

### 6.2 沙箱逃逸防护

- **Windows Job Object**: 限制 CPU/内存/进程数
- **Docker**: 容器隔离
- **gVisor**: 系统调用拦截
- **tmpfs**: 内存文件系统，重启自动清空

### 6.3 输入验证

```python
# 所有工具输入必须通过 JSON Schema 验证
def validate_arguments(args: dict, schema: dict) -> dict:
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(args))
    if errors:
        raise ArgumentValidationError(...)
    return args
```

---

## 7. 性能优化

### 7.1 数据库优化

- **WAL 模式**: 并发读写
- **外键约束**: 数据完整性
- **索引**: task_id, created_at

### 7.2 工作空间清理

```python
# 任务完成后自动清理
def cleanup_workspace(self, task_id: str):
    workspace = self.root / f"task_{task_id}"
    if workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)
```

### 7.3 并发控制

- 每个任务独立工作空间，无竞争
- SQLite 连接池（check_same_thread=False）
- 异步 I/O（asyncio）

---

## 8. 可扩展性

### 8.1 新增场景

```python
# 1. 创建场景目录
task_packs/new_scenario/

# 2. 定义场景适配器
class NewScenarioAdapter(ScenarioAdapter):
    def prepare_context(self, task: Task) -> dict:
        return {"scenario_specific_info": ...}

# 3. 注册到 catalog
catalog.register(NewScenarioManifest(...))
```

### 8.2 新增工具

```python
# 1. 实现 ToolPlugin 接口
class NewToolPlugin:
    def get_spec(self) -> ToolSpec: ...
    def prepare(self, invocation) -> ExecutionRequest: ...
    def parse(self, result) -> ToolResult: ...

# 2. 注册到 ToolRegistry
await registry.register_checked(NewToolPlugin())
```

---

## 9. 技术栈总结

| 层级 | 技术选型 | 理由 |
|------|----------|------|
| 前端 | React 18 + TypeScript | 组件化、类型安全 |
| 后端 | FastAPI + Pydantic | 异步性能、自动验证 |
| 数据库 | SQLite 3 (WAL) | 轻量、嵌入式、ACID |
| 隔离 | Docker + gVisor | 行业标准沙箱 |
| 模型 | Kimi / DeepSeek | 国产、稳定 |
| 构建 | uv | 快速依赖管理 |

---

## 10. 未来改进方向

- [ ] 分布式任务调度
- [ ] 多租户隔离
- [ ] 实时协作编辑
- [ ] 更多 LLM 支持
- [ ] GPU 加速推理
- [ ] 云端部署方案

---

**文档版本**: v1.0  
**最后更新**: 2026-08-24
