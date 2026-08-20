@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Startup failed: .venv\Scripts\python.exe was not found.
  echo Install the project environment before starting the Workbench.
  pause
  exit /b 2
)

".venv\Scripts\python.exe" -m cyber_agent.server --workbench
set "CYBER_AGENT_EXIT=%ERRORLEVEL%"
if not "%CYBER_AGENT_EXIT%"=="0" (
  echo.
  echo Workbench stopped with an error. See the message above.
  pause
)
exit /b %CYBER_AGENT_EXIT%
