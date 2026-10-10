"""A compression child cannot become a live Gateway route without its turn lease."""

import asyncio
from datetime import datetime
import json
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from gateway.config import GatewayConfig, Platform
from gateway.run import GatewayRunner
from gateway.session import AsyncSessionStore, SessionEntry, SessionSource, SessionStore
from gateway.turn_lease import SessionTurnLeaseRegistry, TurnLeaseTimeoutError


_HISTORY = [{"role": "user", "content": "a" * 1000}] * 4
_COMPRESSED = [{"role": "assistant", "content": "summary"}]


async def _runner(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    # Exercise real SessionStore routing + durable JSON fallback without opening SQLite for
    # synthetic session IDs. The slow state.db WAL holder scan is unrelated to route handoff.
    monkeypatch.setattr(SessionStore, "_open_session_db_for_active_scope", lambda *_a, **_k: None)
    store = SessionStore(tmp_path / "sessions", GatewayConfig())
    store._db = None
    source = SessionSource(platform=Platform.TELEGRAM, chat_id="chat", user_id="user")
    entry = SessionEntry(
        session_key="route", session_id="old", created_at=datetime.now(),
        updated_at=datetime.now(), origin=source, platform=Platform.TELEGRAM,
    )
    store._entries["route"] = entry
    store._loaded = True
    store._save_entries()
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._sync_telegram_topic_binding = Mock()
    runner._session_state("route").persistent.run_generation = 1
    token = await runner._turn_leases.acquire("old", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    return runner, store, entry, source, token


async def _hygiene(runner, entry, source):
    attempt = SimpleNamespace(
        agent=SimpleNamespace(session_id="child", _last_compaction_in_place=False),
        history=_HISTORY,
    )
    plan = SimpleNamespace(msg_count=4, approx_tokens=4000, warn_token_threshold=10**9)
    result = await runner._hmwa_hygiene_adopt_transcript(
        attempt, _COMPRESSED, _HISTORY, plan, session_entry=entry, source=source,
        _quick_key="route", run_generation=1,
    )
    return attempt, result


async def _agent_result(runner, entry, source):
    runner._clear_restart_failure_count = AsyncMock()
    return await runner._hmwa_shape_agent_response(
        {"final_response": "done", "session_id": "child", "messages": [], "api_calls": 1},
        source, _HISTORY, entry, "route", "route", 1, "old", "telegram", 0.0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["hygiene", "agent_result"])
async def test_child_route_is_published_only_after_held_lease_rebind(tmp_path, monkeypatch, path):
    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    if path == "hygiene":
        runner.async_session_store.persist_rotated_compression_child = AsyncMock(return_value=True)
    observed = []
    original = runner._rebind_turn_lease

    def observe(key, generation, child):
        observed.append((store.peek_session_id("route"), token.session_id))
        return original(key, generation, child)

    runner._rebind_turn_lease = observe
    try:
        if path == "hygiene":
            _, result = await _hygiene(runner, entry, source)
            assert result[0] is True
        else:
            response, _, _ = await _agent_result(runner, entry, source)
            assert response == "done"
        assert observed == [("old", "old")]
        assert store.peek_session_id("route") == "child"
        assert json.loads((tmp_path / "sessions" / "sessions.json").read_text())["route"]["session_id"] == "child"
        assert token.session_id == "child"
        assert runner._turn_leases._leases["old"] is runner._turn_leases._leases["child"]
        with pytest.raises(TurnLeaseTimeoutError):
            await runner._turn_leases.acquire("child", owner_key="alias", generation=1, timeout=0.02)
    finally:
        runner._turn_leases.release(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["hygiene", "agent_result"])
async def test_target_conflict_cannot_publish_or_ack_child(tmp_path, monkeypatch, path):
    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    blocker = await runner._turn_leases.acquire("child", owner_key="alias", generation=1, timeout=1)
    if path == "hygiene":
        runner.async_session_store.persist_rotated_compression_child = AsyncMock(return_value=True)
    try:
        with pytest.raises(RuntimeError, match="compression.*lease|lease.*compression"):
            if path == "hygiene":
                await _hygiene(runner, entry, source)
            else:
                await _agent_result(runner, entry, source)
        assert store.peek_session_id("route") == "old"
        assert json.loads((tmp_path / "sessions" / "sessions.json").read_text())["route"]["session_id"] == "old"
        assert token.session_id == "old"
    finally:
        runner._turn_leases.release(blocker)
        runner._turn_leases.release(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["hygiene", "agent_result"])
async def test_failed_route_save_keeps_old_route_and_no_success(tmp_path, monkeypatch, path):
    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    if path == "hygiene":
        runner.async_session_store.persist_rotated_compression_child = AsyncMock(return_value=True)
    monkeypatch.setattr(store, "_save", Mock(side_effect=OSError("routing storage failed")))
    monkeypatch.setattr(store, "_save_entry", Mock(side_effect=OSError("routing storage failed")))
    try:
        with pytest.raises(OSError, match="routing storage failed"):
            if path == "hygiene":
                await _hygiene(runner, entry, source)
            else:
                await _agent_result(runner, entry, source)
        assert store.peek_session_id("route") == "old"
        assert token.lease.lock.locked()
        assert runner._turn_leases._leases["old"] is runner._turn_leases._leases["child"]
        with pytest.raises(TurnLeaseTimeoutError):
            await runner._turn_leases.acquire("old", owner_key="alias-old", generation=1, timeout=0.02)
        assert json.loads((tmp_path / "sessions" / "sessions.json").read_text())["route"]["session_id"] == "old"
    finally:
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_new_during_durable_route_write_cannot_unlock_child_or_publish_stale_result(tmp_path, monkeypatch):
    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    runner.async_session_store.persist_rotated_compression_child = AsyncMock(return_value=True)
    entered = threading.Event()
    release = threading.Event()
    original_save = store._save_entry

    def gated_save(*args, **kwargs):
        if kwargs.get("entry_data", {}).get("session_id") == "child":
            entered.set()
            assert release.wait(3)
        return original_save(*args, **kwargs)

    monkeypatch.setattr(store, "_save_entry", gated_save)
    task = asyncio.create_task(_hygiene(runner, entry, source))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        assert token.session_id == "child"
        assert runner._turn_leases._leases["old"] is runner._turn_leases._leases["child"]
        with pytest.raises(TurnLeaseTimeoutError):
            await runner._turn_leases.acquire("old", owner_key="alias-old", generation=1, timeout=0.02)
        runner._invalidate_session_run_generation("route", reason="test /new")
        assert runner._release_turn_lease("route", 1) is True
        assert token.lease.lock.locked()
        with pytest.raises(TurnLeaseTimeoutError):
            await runner._turn_leases.acquire("child", owner_key="alias", generation=1, timeout=0.02)
        release.set()
        with pytest.raises(RuntimeError, match="compression route changed"):
            await asyncio.wait_for(task, 3)
        assert store.peek_session_id("route") == "old"
        assert json.loads((tmp_path / "sessions" / "sessions.json").read_text())["route"]["session_id"] == "old"
        assert token.released is True
    finally:
        release.set()
        if not task.done():
            task.cancel()
        runner._turn_leases.release(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("release_mode", ["finalizer", "new_drop"])
async def test_cancelled_handoff_keeps_child_lease_until_offloaded_write_finishes(
    tmp_path, monkeypatch, release_mode,
):
    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    runner.async_session_store.persist_rotated_compression_child = AsyncMock(return_value=True)
    entered = threading.Event()
    release = threading.Event()
    original_save = store._save_entry

    def gated_save(*args, **kwargs):
        if kwargs.get("entry_data", {}).get("session_id") == "child":
            entered.set()
            assert release.wait(3)
        return original_save(*args, **kwargs)

    monkeypatch.setattr(store, "_save_entry", gated_save)
    task = asyncio.create_task(_hygiene(runner, entry, source))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        runner._invalidate_session_run_generation("route", reason="test cancellation")
        if release_mode == "new_drop":
            runner._persist_active_agents = Mock()
            runner._evict_cached_agent = Mock()
            runner._drop_turn_slot("route", run_generation=2)
        else:
            assert runner._release_turn_lease("route", 1) is True
        task.cancel()
        await asyncio.sleep(0)
        assert token.lease.lock.locked(), "cancelled await must not release the live child lease"
        with pytest.raises(TurnLeaseTimeoutError):
            await runner._turn_leases.acquire("child", owner_key="alias", generation=1, timeout=0.02)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        assert store.peek_session_id("route") == "old"
        assert token.released is True
    finally:
        release.set()
        if not task.done():
            task.cancel()
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_reset_during_child_persistence_cannot_republish_old_turn(tmp_path, monkeypatch):
    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def persist(*_args):
        entered.set()
        await release.wait()
        return True

    runner.async_session_store.persist_rotated_compression_child = persist
    task = asyncio.create_task(_hygiene(runner, entry, source))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        new_entry = await asyncio.to_thread(store.reset_session, "route")
        runner._invalidate_session_run_generation("route", reason="test /new")
        release.set()
        with pytest.raises(RuntimeError, match="compression.*route|route.*compression"):
            await asyncio.wait_for(task, 3)
        assert store.lookup_by_session_key("route") is new_entry
        assert store.peek_session_id("route") == new_entry.session_id
        assert token.session_id == "old"
    finally:
        release.set()
        if not task.done():
            task.cancel()
        runner._turn_leases.release(token)
