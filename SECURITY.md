# 安全策略

## 当前支持状态

CyberSecurity-Agent 当前属于公开 Alpha 预览版。安全修复目前仅面向最新公开代码；接口、能力边界和支持策略仍可能在后续版本中调整。

## 凭据处理

不要向仓库提交真实 API Key、Password、Token、Private Key 或 Credential export。

模型 API Key 应由用户通过本地 Admin 输入，并由服务端交给 Windows Credential Manager 保存。凭据不应写入以下位置：

- 源代码或公开文档
- `.env` 或 `.env.example`
- YAML 配置
- 浏览器存储
- SQLite 数据库
- 日志、截图、测试或 fixture

`.env.example` 只包含非 Secret 路径变量，不得添加真实凭据值。

## Runtime 安全边界

本地服务只绑定 loopback 地址，并通过短期启动交换建立认证会话。修改状态的请求需要有效会话和 CSRF 保护。

模型与执行器 readiness 会在任务准入前检查。任何必要组件缺失或不可用时，Runtime 保持 fail-closed，不会使用 Fake/Replay production fallback 代替正式结果。

请把 `CYBER_AGENT_RUNTIME_ROOT` 配置到仓库之外，不要公开其中的数据库、上传材料、Evidence、Audit、日志或其他运行时产物。

## 合法授权使用

仅可对自己拥有或已获得明确授权的系统、接口和源码使用 CyberSecurity-Agent。用户需要自行确认测试范围、目标和数据处理行为符合适用法律与授权约束。

## 报告安全问题

对于不包含敏感信息的一般安全问题，可以通过公开 GitHub Issue 报告，并提供受影响版本、复现步骤、影响和建议修复方式。

不要在公开 Issue 中提交以下内容：

- 真实 Secret 或凭据
- 可直接利用且尚未修复的敏感细节
- 个人数据或私有业务数据
- 未脱敏的日志、数据库或截图

敏感漏洞的私密报告渠道尚待完善。在正式私密渠道公布前，请不要通过公开 Issue 披露敏感漏洞细节，也不要虚构或猜测安全联系邮箱。
