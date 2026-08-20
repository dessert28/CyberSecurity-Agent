# Security Policy

## Supported version

Security fixes currently target the latest public release only.

## Credential handling

Do not place API keys, passwords, tokens, private keys, or credential exports in this repository. Model API keys are entered locally through the Admin Console and stored by the server through Windows Credential Manager. They are not intended for source files, environment files, browser storage, SQLite databases, logs, fixtures, or screenshots.

The example environment file contains paths only. It must never be extended with a real credential value.

## Runtime boundary

The server binds to the loopback interface and uses a short-lived launch exchange before issuing an authenticated local session. State-changing requests require the session and CSRF protection. Model and executor readiness are checked before work is admitted. If required components are absent or unavailable, execution remains closed; there is no fake or replay production fallback.

Only use the agent against systems and source material that you are authorized to assess. Keep the runtime root outside the repository, and do not publish its databases, artifacts, logs, or credential material.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue when it could expose users or credentials. Contact the repository owner through a private GitHub security advisory. Include a concise reproduction, affected version, impact, and proposed mitigation, but remove all real secrets and personal data.
