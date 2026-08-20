# 更新日志

公开版本的重要变化记录在此文件中。

## 未发布

- 将主要用户文档中文化，并重新组织 README 的项目介绍、架构、快速开始、Source Audit、安全设计和限制说明。
- 未修改 Runtime、API Schema、TaskPack、测试或既有 Release 资产。

## v0.1.0-alpha.1 - 2026-08-20

### 新增

- 提供本地 Admin 和 Workbench 启动入口。
- 增加真实 Model Gateway、PlannerService、PolicyGate、ControlledExecutor、Evidence、Audit 和 Runtime readiness 边界。
- 提供 Source Audit 正式 Runtime 路径。
- 对尚未完成的能力提供明确的 unavailable 或未就绪状态。
- 提供最小公开测试集和发布安全文件。

### 当前限制

- 模型必须完成本地配置并通过 Capability Probe，任务才允许进入执行状态。
- Web-IDOR = `EXECUTOR_NOT_READY`。
- Report 尚未实现。
- Replan 尚未实现。
- `start_admin.bat` 和 `start_workbench.bat` 只负责启动已安装环境，不负责安装依赖。
- 当前主要面向 Windows 环境和源码快速启动。
