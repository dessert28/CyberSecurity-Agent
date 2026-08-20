"""Single-user local browser session primitives for the workbench."""

from __future__ import annotations

import hashlib
import hmac
import secrets


class SessionManager:
    """Redeem one launch secret and retain only hashed browser sessions."""

    def __init__(self, *, launch_token: str) -> None:
        if len(launch_token) < 32:
            raise ValueError("launch_token must contain at least 32 characters")
        self._launch_token_digest = self._digest(launch_token)
        self._launch_token_consumed = False
        self._sessions: dict[str, str] = {}

    @property
    def launch_token_digest(self) -> str:
        return self._launch_token_digest

    def redeem(self, candidate: str) -> tuple[str, str] | None:
        candidate_digest = self._digest(candidate)
        if self._launch_token_consumed or not hmac.compare_digest(
            candidate_digest, self._launch_token_digest
        ):
            return None
        self._launch_token_consumed = True
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        self._sessions[self._digest(session_token)] = csrf_token
        return session_token, csrf_token

    def csrf_for_session(self, session_token: str) -> str | None:
        if not session_token:
            return None
        return self._sessions.get(self._digest(session_token))

    def invalidate(self, session_token: str) -> None:
        if session_token:
            self._sessions.pop(self._digest(session_token), None)

    def __repr__(self) -> str:
        return (
            "SessionManager(launch_token_consumed="
            f"{self._launch_token_consumed!r}, active_sessions={len(self._sessions)})"
        )

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = ["SessionManager"]
