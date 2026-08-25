# CyberSecurity Agent

CyberSecurity Agent is a local, auditable cybersecurity-agent runtime. It combines a real model gateway, constrained planning, policy gates, controlled tools, verification, evidence, and audit records behind a FastAPI Admin Console and Workbench.

This repository is a source distribution. It does not include credentials, runtime databases, private scenarios, or internal development material.

## Current capability boundary

**✅ Fully Implemented (v0.1.0-alpha.1)**

- **Admin Console**: Available without a configured model so that local model settings and readiness can be inspected.
- **Workbench**: Available without credentials, but task execution remains unavailable until the model and the selected executor both pass readiness checks.
- **Source Audit**: Implemented for authorized Python source archives when the model is configured and the isolated source worker is available.
- **Web IDOR**: Fully implemented with Docker + gVisor sandbox executor.
- **Pwn Ret2win**: Fully implemented with interactive process execution in isolated container.
- **Reverse Keycheck**: Fully implemented with static analysis and runtime verification.
- **Incident Login Chain**: Fully implemented with log analysis and timeline reconstruction.
- **Workspace Isolation**: Each task runs in independent directory with automatic cleanup.
- **SQLite Audit Store**: Persistent decision trails with 3-table design (tasks/decisions/tool_calls).
- **Policy Gate**: Risk-based execution control with R0-R4 levels.

**⏳ Future Work**

- Report generation and replanning: unavailable.
- Production fallback: unavailable. The runtime does not replace an unavailable model or executor with fake or replay behavior.

## Requirements

- Windows 10 or newer
- Python 3.11, 3.12, or 3.13
- [uv](https://docs.astral.sh/uv/)
- Windows Credential Manager for local API-key storage

Docker is not required for the currently available Source Audit path. The optional Docker path setting is reserved for controlled executors that require it.

## Install

From an ordinary PowerShell window in the repository directory:

```powershell
uv sync --dev --locked
```

The lock file is part of the release and should not be regenerated during a normal install.

## Start

Open the Admin Console:

```powershell
uv run python -m cyber_agent.server --admin
```

Open the Workbench:

```powershell
uv run python -m cyber_agent.server --workbench
```

After installation, `start_admin.bat` and `start_workbench.bat` provide equivalent launch shortcuts. They are startup helpers, not dependency installers or one-click deployment tools.

**Quick Start (Competition Version):**

```bash
# One-click startup
deployment\start.bat

# Or use Python directly
.venv\Scripts\python.exe -m cyber_agent.server --admin
```

The local server binds only to the loopback interface. The launcher opens a one-time exchange URL and then establishes a local authenticated session.

## Configure a model

1. Start the Admin Console.
2. Select a provider and enter the model name and API base URL.
3. Enter your own API key and save the configuration.
4. Run the connection check. Task execution remains closed unless the required structured-output check succeeds.

The API key is submitted to the local server and stored through Windows Credential Manager. Do not place it in `.env`, `.env.example`, YAML, source code, tests, browser storage, logs, or runtime databases.

The public environment template contains only optional path settings:

```text
CYBER_AGENT_RUNTIME_ROOT=
CYBER_AGENT_DOCKER_PATH=
```

If `CYBER_AGENT_RUNTIME_ROOT` is blank, the application chooses its local default. Keep any configured runtime root outside the repository because it can contain databases and artifacts.

## Verify

Run the public tests after installation:

```powershell
uv run pytest -p no:cacheprovider
```

The minimal suite covers imports, server startup wiring, local session boundaries, readiness, source-audit policy checks, and the absence of fake or replay production fallback.

**Integration Test (Competition Version):**

```bash
.venv\Scripts\python.exe deployment\test_integration.py
```

This validates all 5 scenarios, tool registration, workspace isolation, and audit store persistence.

## Repository map

```text
.
|-- config/                 Model-provider presets without credentials
|-- deployment/             Quick start scripts and documentation
|   |-- start.bat           One-click startup (Competition version)
|   |-- .env.example        Environment configuration template
|   |-- DEPLOYMENT.md       Deployment guide
|   |-- ARCHITECTURE.md     Technical architecture documentation
|   `-- test_integration.py Integration test suite
|-- src/cyber_agent/        Runtime, API, planner, gateway, tools, verification
|   |-- task_packs/         5 scenario implementations
|   |   |-- source_audit/   Python source code audit
|   |   |-- web_idor/       Web IDOR detection
|   |   |-- pwn_ret2win/    Pwn exploitation
|   |   |-- reverse_keycheck/ Reverse engineering
|   |   `-- incident_login_chain/ Incident response
|   |-- workbench/
|   |   `-- workspace.py    Task isolation manager
|   |-- audit_store/
|   |   `-- sqlite_store.py Persistent audit trails
|   `-- tools/              Tool plugins (10+)
|-- tests/                  Minimal public smoke and security-boundary tests
|-- pyproject.toml          Package and dependency declaration
`-- PROJECT_COMPLETION.md   Project completion report
|-- uv.lock                 Reproducible dependency lock
|-- start_admin.bat         Installed-environment Admin launcher
|-- start_workbench.bat     Installed-environment Workbench launcher
`-- PUBLIC_MANIFEST.txt     Checksums for the other public files
```

## Release integrity

`PUBLIC_MANIFEST.txt` records a SHA-256 digest and relative path for every other file in the public staging tree. It intentionally does not contain a self-digest, because changing the manifest would invalidate that digest.

## Responsible use

Run the agent only against systems and source material you own or are explicitly authorized to test. Review [SECURITY.md](SECURITY.md) before configuring credentials or runtime storage.

## License status

A public license has not yet been approved. See [LICENSE_PENDING.md](LICENSE_PENDING.md). Do not assume permission beyond applicable law until a final license is published.
