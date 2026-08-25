"""临时启动脚本，用于测试服务器"""
import os
import sys
import secrets

# 每次启动生成新token（至少32字符）
token = secrets.token_urlsafe(48)
os.environ["CYBER_AGENT_LAUNCH_TOKEN"] = token

print(f"=== CyberSecurity Agent 启动 ===")
print(f"管理控制台: http://127.0.0.1:9000/admin")
print(f"任务工作台: http://127.0.0.1:9000/")
print(f"Exchange URL: http://127.0.0.1:9000/session/exchange?token={token}&destination=admin")
print("=" * 50)

# 启动服务器
from cyber_agent.server import main

if __name__ == "__main__":
    sys.exit(main(["--admin", "--port", "9000", "--no-browser"]))
