@echo off
chcp 65001 >nul
title 网络安全智能体 - XH-202609

echo ========================================
echo   网络安全智能体启动脚本
echo   XH-202609 比赛提交版本
echo ========================================
echo.

REM 检查Python虚拟环境
if not exist ".venv\Scripts\python.exe" (
    echo [错误] 未找到虚拟环境，请先运行 uv sync
    pause
    exit /b 1
)

REM 设置环境变量
set CYBER_AGENT_RUNTIME_ROOT=%cd%\var\workbench
set CYBER_AGENT_LAUNCH_TOKEN=

REM 启动服务器
echo [信息] 正在启动本地服务器...
echo [信息] 管理控制台: http://127.0.0.1:8765/admin
echo [信息] 按 Ctrl+C 停止服务
echo.

.venv\Scripts\python.exe -m cyber_agent.server --admin --no-browser

pause
