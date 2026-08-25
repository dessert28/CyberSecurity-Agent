# Changelog

All notable changes to the public distribution will be documented in this file.

## 0.1.0 - 2026-08-20

- Added the local Admin Console and Workbench launch paths.
- Added a real model gateway, policy-gated planning, controlled execution, evidence, audit, and readiness boundaries.
- Added the Source Audit runtime path and explicit unavailable states for incomplete capabilities.
- Added a minimal public test suite and release hygiene files.

Known limitations:

- A model must be configured and successfully checked before task execution is admitted.
- The Web IDOR executor is not available in this release.
- Report generation and replanning are not available.
- The batch files start an installed environment; they do not install dependencies.
