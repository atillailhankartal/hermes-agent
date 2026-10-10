"""A route key for Bee is available only from the current Gateway tool turn."""

from contextvars import copy_context
from datetime import datetime
import json

import pytest

from agent.delegation_context import delegated_child_context
from gateway.config import GatewayConfig, Platform
from gateway.route_claim import gateway_route_scope
from gateway.run import GatewayRunner
from gateway.session import SessionEntry, SessionSource, SessionStore
from gateway.session_context import (
    clear_session_vars,
    get_bound_session_key,
    set_session_vars,
)
from gateway.turn_lease import SessionTurnLeaseRegistry


def _gateway(tmp_path, monkeypatch):
    home = tmp_path / "profile-a"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(SessionStore, "_open_session_db_for_active_scope", lambda *_a, **_k: None)
    store = SessionStore(tmp_path / "sessions", GatewayConfig())
    store._db = None
    source = SessionSource(platform=Platform.TELEGRAM, chat_id="chat", user_id="user")
    entry = SessionEntry(
        session_key="agent:a:telegram:dm:chat", session_id="A",
        created_at=datetime.now(), updated_at=datetime.now(),
        origin=source, platform=Platform.TELEGRAM,
    )
    store._entries[entry.session_key] = entry
    store._loaded = True
    store._save_entries()
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: home
    runner._session_state(entry.session_key).persistent.run_generation = 1
    return runner, entry, home


def test_bound_key_never_reads_environment_or_untrusted_context(tmp_path, monkeypatch):
    runner, entry, _home = _gateway(tmp_path, monkeypatch)
    monkeypatch.setenv("HERMES_SESSION_KEY", "agent:foreign:telegram:dm:chat")
    assert get_bound_session_key() is None

    tokens = set_session_vars(session_key=entry.session_key, session_id=entry.session_id)
    try:
        assert get_bound_session_key() is None  # A ContextVar alone is not a Gateway turn.
        runner._resolve_profile_home_for_source = lambda _source: tmp_path / "profile-b"
        with gateway_route_scope(runner, entry.session_key, 1, entry.origin):
            assert get_bound_session_key() is None  # Foreign profile cannot borrow this route.
    finally:
        clear_session_vars(tokens)


@pytest.mark.asyncio
async def test_bound_key_requires_live_gateway_lease_and_rejects_child_and_aba(tmp_path, monkeypatch):
    runner, entry, _home = _gateway(tmp_path, monkeypatch)
    key = entry.session_key
    lease = await runner._turn_leases.acquire("A", owner_key=key, generation=1, timeout=1)
    runner._session_state(key).turn.lease_tokens[1] = lease
    tokens = set_session_vars(session_key=key, session_id="A")
    try:
        with gateway_route_scope(runner, key, 1, entry.origin):
            assert get_bound_session_key() == key
            with delegated_child_context("A"):
                assert get_bound_session_key() is None
            old_turn = copy_context()
            original_epoch = entry.route_epoch
            second = runner.session_store.switch_session(key, "B", expected_session_id="A")
            assert second is not None and second.session_id == "B"
            resumed = runner.session_store.switch_session(key, "A", expected_session_id="B")
            assert resumed is not None and resumed.session_id == "A"
            assert resumed.route_epoch != original_epoch
            before = runner.session_store.snapshot_route_entry(key)
            assert (before.route_claim_blocked, before.route_claim_recoverable) == (True, True)
            # A stale task still has its original key, native ID and live lease. Only the
            # epoch snapshot at scope entry distinguishes it from the resumed A route.
            assert old_turn.run(get_bound_session_key) is None
            after = runner.session_store.snapshot_route_entry(key)
            durable = json.loads((runner.session_store.sessions_dir / "sessions.json").read_text())[key]
            assert (after.route_claim_blocked, after.route_claim_recoverable, after.route_epoch) == (
                before.route_claim_blocked, before.route_claim_recoverable, before.route_epoch,
            )
            assert (durable["route_claim_blocked"], durable["route_claim_recoverable"], durable["route_epoch"]) == (
                before.route_claim_blocked, before.route_claim_recoverable, before.route_epoch,
            )
    finally:
        clear_session_vars(tokens)
        runner._turn_leases.release(lease)
        runner._session_state(key).turn.lease_tokens.pop(1)

    assert old_turn.run(get_bound_session_key) is None

    runner._session_state(key).persistent.run_generation = 2
    current_lease = await runner._turn_leases.acquire("A", owner_key=key, generation=2, timeout=1)
    runner._session_state(key).turn.lease_tokens[2] = current_lease
    current_tokens = set_session_vars(session_key=key, session_id="A")
    try:
        with gateway_route_scope(runner, key, 2, resumed.origin):
            assert get_bound_session_key() == key
            current = runner.session_store.snapshot_route_entry(key)
            assert (current.route_claim_blocked, current.route_claim_recoverable) == (False, False)
            assert old_turn.run(get_bound_session_key) is None
    finally:
        clear_session_vars(current_tokens)
        runner._turn_leases.release(current_lease)


@pytest.mark.asyncio
async def test_bound_key_epoch_check_is_atomic_with_reopen(tmp_path, monkeypatch):
    runner, entry, _home = _gateway(tmp_path, monkeypatch)
    store, key = runner.session_store, entry.session_key
    lease = await runner._turn_leases.acquire("A", owner_key=key, generation=1, timeout=1)
    runner._session_state(key).turn.lease_tokens[1] = lease
    tokens = set_session_vars(session_key=key, session_id="A")
    try:
        with gateway_route_scope(runner, key, 1, entry.origin):
            assert get_bound_session_key() == key
            bound_epoch = entry.route_epoch
            reopen = store._reopen_route_claim_with_lease

            def repoint_before_locked_reopen(session_key, native_id, token, *, expected_route_epoch=None):
                assert expected_route_epoch == bound_epoch
                assert store.switch_session(key, "B", expected_session_id="A")
                assert store.switch_session(key, "A", expected_session_id="B")
                return reopen(
                    session_key, native_id, token, expected_route_epoch=expected_route_epoch,
                )

            monkeypatch.setattr(store, "_reopen_route_claim_with_lease", repoint_before_locked_reopen)
            assert get_bound_session_key() is None
            current = store.snapshot_route_entry(key)
            durable = json.loads((store.sessions_dir / "sessions.json").read_text())[key]
            assert current.route_epoch != bound_epoch
            assert (current.route_claim_blocked, current.route_claim_recoverable) == (True, True)
            assert (durable["route_epoch"], durable["route_claim_blocked"], durable["route_claim_recoverable"]) == (
                current.route_epoch, True, True,
            )
    finally:
        clear_session_vars(tokens)
        runner._turn_leases.release(lease)
