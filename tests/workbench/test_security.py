from __future__ import annotations

import hashlib

from cyber_agent.workbench.security import SessionManager


def test_session_manager_stores_only_launch_token_digest_and_redeems_once() -> None:
    launch_token = "a" * 64
    manager = SessionManager(launch_token=launch_token)

    assert manager.launch_token_digest == hashlib.sha256(launch_token.encode()).hexdigest()
    assert launch_token not in repr(manager)

    session_token, csrf_token = manager.redeem(launch_token)
    assert session_token != launch_token
    assert len(session_token) >= 43
    assert len(csrf_token) >= 43
    assert manager.csrf_for_session(session_token) == csrf_token
    assert manager.redeem(launch_token) is None


def test_unknown_session_has_no_csrf_and_explicit_invalidation_works() -> None:
    manager = SessionManager(launch_token="b" * 64)
    session_token, csrf_token = manager.redeem("b" * 64)

    assert manager.csrf_for_session("unknown") is None
    assert manager.csrf_for_session(session_token) == csrf_token
    manager.invalidate(session_token)
    assert manager.csrf_for_session(session_token) is None
