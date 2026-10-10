"""A compression child cannot become a live Gateway route without its turn lease."""

import asyncio
from datetime import datetime
import json
import threading
import time
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
    reset_entry = []

    async def do_new():
        await runner._invalidate_session_run_generation_async("route", reason="test /new")
        runner._release_turn_lease("route", 1)
        reset_entry.append(await runner.async_session_store.reset_session("route"))

    invalidator = None
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        assert token.session_id == "child"
        assert runner._turn_leases._leases["old"] is runner._turn_leases._leases["child"]
        with pytest.raises(TurnLeaseTimeoutError):
            await runner._turn_leases.acquire("old", owner_key="alias-old", generation=1, timeout=0.02)
        invalidator = asyncio.create_task(do_new())
        assert token.lease.lock.locked()
        with pytest.raises(TurnLeaseTimeoutError):
            await runner._turn_leases.acquire("child", owner_key="alias", generation=1, timeout=0.02)
        release.set()
        try:
            await asyncio.wait_for(task, 3)
        except RuntimeError as exc:
            assert "compression route changed" in str(exc)
        await asyncio.wait_for(invalidator, 3)
        assert len(reset_entry) == 1
        assert store.lookup_by_session_key("route") is reset_entry[0]
        assert store.peek_session_id("route") == reset_entry[0].session_id
        assert json.loads((tmp_path / "sessions" / "sessions.json").read_text())["route"]["session_id"] == reset_entry[0].session_id
        assert token.released is True
    finally:
        release.set()
        if not task.done():
            task.cancel()
        if invalidator is not None and not invalidator.done():
            invalidator.cancel()
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
    events = []
    original_save = store._save_entry
    original_publish = store.publish_compression_child_route

    def gated_save(*args, **kwargs):
        if kwargs.get("entry_data", {}).get("session_id") == "child":
            entered.set()
            assert release.wait(3)
        return original_save(*args, **kwargs)

    monkeypatch.setattr(store, "_save_entry", gated_save)

    def watched_publish(*args, **kwargs):
        outcome = original_publish(*args, **kwargs)
        events.append("route_published")
        return outcome

    monkeypatch.setattr(store, "publish_compression_child_route", watched_publish)
    task = asyncio.create_task(_hygiene(runner, entry, source))
    async def invalidate_and_drop():
        await runner._invalidate_session_run_generation_async("route", reason="test cancellation")
        events.append("invalidated")
        if release_mode == "new_drop":
            runner._drop_turn_slot("route", run_generation=2)

    invalidator = None
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        invalidator = asyncio.create_task(invalidate_and_drop())
        if release_mode == "new_drop":
            runner._persist_active_agents = Mock()
            runner._evict_cached_agent = Mock()
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
        await asyncio.wait_for(invalidator, 3)
        assert events == ["route_published", "invalidated"]
        assert store.peek_session_id("route") == "child"
        assert json.loads((tmp_path / "sessions" / "sessions.json").read_text())["route"]["session_id"] == "child"
        reopened = SessionStore(tmp_path / "sessions", GatewayConfig())
        reopened._db = None
        assert reopened.peek_session_id("route") == "child"
        assert token.released is True
    finally:
        release.set()
        if not task.done():
            task.cancel()
        if invalidator is not None and not invalidator.done():
            invalidator.cancel()
        runner._turn_leases.release(token)


def test_route_gate_is_scoped_to_event_loop_and_does_not_retain_idle_gates():
    import gc
    import weakref

    runner = object.__new__(GatewayRunner)

    async def acquire_gate():
        return runner._session_route_gate("route")

    first = asyncio.run(acquire_gate())
    second = asyncio.run(acquire_gate())
    assert first is not second
    assert len(runner._session_route_gates) == 2
    first_ref = weakref.ref(first)
    del first
    gc.collect()
    assert first_ref() is None
    assert len(runner._session_route_gates) == 1
    del second
    gc.collect()
    assert len(runner._session_route_gates) == 0


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
        await runner._invalidate_session_run_generation_async("route", reason="test /new")
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


@pytest.mark.asyncio
@pytest.mark.parametrize("barrier", ["durable_write", "live_assignment"])
async def test_new_generation_follows_child_route_publication(tmp_path, monkeypatch, barrier):
    runner, store, entry, _source, token = await _runner(tmp_path, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    events = []
    restore_attempts = []
    original_save = store._save_entry
    original_setattr = SessionEntry.__setattr__

    def gated_save(*args, **kwargs):
        target = kwargs.get("entry_data", {}).get("session_id")
        if target == "child":
            original_save(*args, **kwargs)
            if barrier == "durable_write":
                entered.set()
                assert release.wait(3)
            return
        if target == "old":
            restore_attempts.append(target)
            raise OSError("restore write failed")
        return original_save(*args, **kwargs)

    def gated_setattr(self, name, value):
        if self is entry and name == "session_id" and value == "child" and barrier == "live_assignment":
            entered.set()
            assert release.wait(3)
        result = original_setattr(self, name, value)
        if self is entry and name == "session_id" and value == "child":
            events.append("child_published")
        return result

    monkeypatch.setattr(store, "_save_entry", gated_save)
    monkeypatch.setattr(SessionEntry, "__setattr__", gated_setattr)
    publish = asyncio.create_task(runner._hmwa_publish_compression_child_route(entry, "child", "route", 1))
    new_started = asyncio.Event()

    async def do_new():
        new_started.set()
        await runner._invalidate_session_run_generation_async("route", reason="test /new")
        events.append("invalidated")
        runner._release_turn_lease("route", 1)
        await runner.async_session_store.reset_session("route")

    new_task = None
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        assert token.lease.lock.locked()
        assert runner._turn_leases._leases["old"] is runner._turn_leases._leases["child"]
        new_task = asyncio.create_task(do_new())
        await asyncio.wait_for(new_started.wait(), 3)
        release.set()
        await asyncio.wait_for(publish, 3)
        await asyncio.wait_for(new_task, 3)
        assert events == ["child_published", "invalidated"]
        assert restore_attempts == []
        assert token.released is True
        assert store.peek_session_id("route") != "child"
        reopened = SessionStore(tmp_path / "sessions", GatewayConfig())
        reopened._db = None
        assert reopened.peek_session_id("route") == store.peek_session_id("route")
    finally:
        release.set()
        if not publish.done():
            publish.cancel()
        if new_task is not None and not new_task.done():
            new_task.cancel()
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_actual_new_keeps_event_loop_live_during_child_route_write(tmp_path, monkeypatch):
    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    original_save = store._save_entry

    def gated_save(*args, **kwargs):
        if kwargs.get("entry_data", {}).get("session_id") == "child":
            entered.set()
            assert release.wait(3)
        return original_save(*args, **kwargs)

    monkeypatch.setattr(store, "_save_entry", gated_save)
    runner._session_key_for_source = Mock(return_value="route")
    runner._release_running_agent_state = Mock()
    runner._cleanup_old_agent_for_reset = AsyncMock()
    runner._evict_cached_agent = Mock()
    runner._clear_conversation_scope = Mock()
    runner._fire_session_reset_hooks = AsyncMock()
    runner._reset_notice_session_info = Mock(return_value="")
    runner._telegram_topic_new_header = Mock(return_value="")
    runner._is_telegram_topic_lane = Mock(return_value=False)
    monkeypatch.setattr("gateway.slash_commands_session._reset_process_scoped_tool_state", Mock())
    monkeypatch.setattr("tools.async_delegation.interrupt_for_session", Mock())
    event = SimpleNamespace(source=source, get_command_args=lambda: "")
    publish = asyncio.create_task(runner._hmwa_publish_compression_child_route(entry, "child", "route", 1))
    timer = threading.Timer(2.1, release.set)
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        heartbeat_before_release = []
        asyncio.get_running_loop().call_later(
            0.05, lambda: heartbeat_before_release.append(not release.is_set()),
        )
        timer.start()
        await asyncio.wait_for(runner._handle_reset_command(event), 5)
        try:
            await asyncio.wait_for(publish, 3)
        except RuntimeError as exc:
            assert "compression route changed" in str(exc)
        assert heartbeat_before_release == [True]
        assert store.peek_session_id("route") != "child"
        assert token.lease.lock.locked()
    finally:
        release.set()
        timer.cancel()
        if not publish.done():
            publish.cancel()
        runner._turn_leases.release(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["stop", "inbound"])
async def test_actual_gateway_admission_keeps_heartbeat_before_route_write_finishes(
    tmp_path, monkeypatch, path,
):
    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    original_save = store._save_entry

    def gated_save(*args, **kwargs):
        if kwargs.get("entry_data", {}).get("session_id") == "child":
            entered.set()
            assert release.wait(3)
        return original_save(*args, **kwargs)

    monkeypatch.setattr(store, "_save_entry", gated_save)
    event = SimpleNamespace(source=source)
    if path == "stop":
        runner._delivery_adapter_for = Mock(return_value=None)
        runner._drop_turn_slot = Mock()
        monkeypatch.setattr("tools.async_delegation.interrupt_for_session", Mock())
        operation = runner._interrupt_and_clear_session(
            "route", source, interrupt_reason="test stop", invalidation_reason="test stop",
        )
    else:
        runner._hm_admit_event = AsyncMock(return_value=(event, source, True))
        runner._hm_estop_gate = Mock(return_value=None)
        runner._session_key_for_source = Mock(return_value="route")
        runner._hm_pending_reply_intercepts = AsyncMock(return_value=None)
        runner._is_session_running = Mock(return_value=False)
        runner._hm_dispatch_idle_commands = AsyncMock(return_value=(False, None))
        runner._claim_active_session_slot = Mock(return_value=(None, None))
        runner._hm_rescue_orphaned_fifo = Mock(return_value=(event, source, True))
        runner._persist_active_agents = Mock()
        runner._handle_message_with_agent = AsyncMock(return_value="done")
        runner._run_post_turn_hooks = AsyncMock()
        runner._clear_durable_active_turn = AsyncMock()
        runner._release_running_agent_state = Mock()
        operation = runner._handle_message(event)

    publish = asyncio.create_task(runner._hmwa_publish_compression_child_route(entry, "child", "route", 1))
    timer = threading.Timer(2.1, release.set)
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        heartbeat_before_release = []
        asyncio.get_running_loop().call_later(
            0.05, lambda: heartbeat_before_release.append(not release.is_set()),
        )
        timer.start()
        await asyncio.wait_for(operation, 5)
        try:
            await asyncio.wait_for(publish, 3)
        except RuntimeError as exc:
            assert "compression route changed" in str(exc)
        assert heartbeat_before_release == [True]
        assert token.lease.lock.locked()
    finally:
        release.set()
        timer.cancel()
        if not publish.done():
            publish.cancel()
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_final_route_lookup_keeps_heartbeat_while_store_lock_is_held(tmp_path, monkeypatch):
    runner, store, entry, _source, token = await _runner(tmp_path, monkeypatch)
    held = threading.Event()
    release = threading.Event()
    heartbeat_before_release = []
    loop = asyncio.get_running_loop()
    original_publish = store.publish_compression_child_route
    original_lookup = store.lookup_by_session_key
    holder = None
    watchdog = threading.Timer(2.1, release.set)

    def hold_store_lock():
        with store._lock:
            held.set()
            assert release.wait(3)

    def publish_then_hold(*args, **kwargs):
        nonlocal holder
        committed = original_publish(*args, **kwargs)
        if committed:
            holder = threading.Thread(target=hold_store_lock)
            holder.start()
            assert held.wait(3)
            watchdog.start()
        return committed

    def observed_lookup(session_key):
        loop.call_soon_threadsafe(
            lambda: heartbeat_before_release.append(not release.is_set()),
        )
        return original_lookup(session_key)

    monkeypatch.setattr(store, "publish_compression_child_route", publish_then_hold)
    monkeypatch.setattr(store, "lookup_by_session_key", observed_lookup)
    publish = asyncio.create_task(runner._hmwa_publish_compression_child_route(entry, "child", "route", 1))
    try:
        await asyncio.wait_for(publish, 5)
        assert heartbeat_before_release == [True]
        assert entry.session_id == "child"
        assert token.session_id == "child"
        assert json.loads((tmp_path / "sessions" / "sessions.json").read_text())["route"]["session_id"] == "child"
    finally:
        release.set()
        watchdog.cancel()
        if not publish.done():
            publish.cancel()
        if holder is not None:
            await asyncio.to_thread(holder.join, 3)
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_inbound_pending_sentinel_blocks_duplicate_while_route_gate_is_held(tmp_path, monkeypatch):
    from gateway.run import _AGENT_PENDING_SENTINEL

    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    claimed = asyncio.Event()
    original_save = store._save_entry

    def gated_save(*args, **kwargs):
        if kwargs.get("entry_data", {}).get("session_id") == "child":
            entered.set()
            assert release.wait(3)
        return original_save(*args, **kwargs)

    monkeypatch.setattr(store, "_save_entry", gated_save)
    event = SimpleNamespace(source=source)
    runner._hm_admit_event = AsyncMock(return_value=(event, source, True))
    runner._hm_estop_gate = Mock(return_value=None)
    runner._session_key_for_source = Mock(return_value="route")
    runner._hm_pending_reply_intercepts = AsyncMock(return_value=None)
    runner._hm_dispatch_idle_commands = AsyncMock(return_value=(False, None))
    runner._claim_active_session_slot = Mock(return_value=(None, None))
    runner._hm_rescue_orphaned_fifo = Mock(return_value=(event, source, True))
    runner._persist_active_agents = Mock(side_effect=claimed.set)
    runner._handle_message_with_agent = AsyncMock(return_value="done")
    runner._hm_handle_running_session_message = AsyncMock(return_value="busy")
    runner._run_post_turn_hooks = AsyncMock()
    runner._clear_durable_active_turn = AsyncMock()
    runner._release_running_agent_state = Mock()

    publish = asyncio.create_task(runner._hmwa_publish_compression_child_route(entry, "child", "route", 1))
    first = second = None
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        first = asyncio.create_task(runner._handle_message(event))
        await asyncio.wait_for(claimed.wait(), 3)
        assert runner._session_state("route").turn.agent is _AGENT_PENDING_SENTINEL
        second = asyncio.create_task(runner._handle_message(event))
        release.set()
        assert await asyncio.wait_for(first, 3) == "done"
        assert await asyncio.wait_for(second, 3) == "busy"
        await asyncio.wait_for(publish, 3)
        assert runner._handle_message_with_agent.await_count == 1
    finally:
        release.set()
        for task in (first, second, publish):
            if task is not None and not task.done():
                task.cancel()
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_cancelled_inbound_wait_releases_only_its_claim_and_allows_next_turn(tmp_path, monkeypatch):
    from gateway.run import _AGENT_PENDING_SENTINEL

    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    claimed = asyncio.Event()
    original_save = store._save_entry
    first_lease, second_lease = Mock(), Mock()

    def gated_save(*args, **kwargs):
        if kwargs.get("entry_data", {}).get("session_id") == "child":
            entered.set()
            assert release.wait(3)
        return original_save(*args, **kwargs)

    monkeypatch.setattr(store, "_save_entry", gated_save)
    event = SimpleNamespace(source=source)
    runner._hm_admit_event = AsyncMock(return_value=(event, source, True))
    runner._hm_estop_gate = Mock(return_value=None)
    runner._session_key_for_source = Mock(return_value="route")
    runner._hm_pending_reply_intercepts = AsyncMock(return_value=None)
    runner._hm_dispatch_idle_commands = AsyncMock(return_value=(False, None))
    runner._claim_active_session_slot = Mock(side_effect=[(first_lease, None), (second_lease, None)])
    runner._hm_rescue_orphaned_fifo = Mock(return_value=(event, source, True))
    runner._persist_active_agents = Mock(side_effect=claimed.set)
    runner._handle_message_with_agent = AsyncMock(return_value="done")
    runner._hm_handle_running_session_message = AsyncMock(return_value="busy")
    runner._run_post_turn_hooks = AsyncMock()
    runner._clear_durable_active_turn = AsyncMock()

    publish = asyncio.create_task(runner._hmwa_publish_compression_child_route(entry, "child", "route", 1))
    first = None
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        first = asyncio.create_task(runner._handle_message(event))
        await asyncio.wait_for(claimed.wait(), 3)
        state = runner._session_state("route")
        assert state.turn.agent is _AGENT_PENDING_SENTINEL
        assert state.turn.event is event
        assert state.turn.lease is first_lease

        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        first_lease.release.assert_called_once_with()
        assert state.turn.agent is None
        assert state.turn.lease is None

        release.set()
        await asyncio.wait_for(publish, 3)
        assert await asyncio.wait_for(runner._handle_message(event), 3) == "done"
        assert runner._handle_message_with_agent.await_count == 1
        second_lease.release.assert_called_once_with()
    finally:
        release.set()
        if first is not None and not first.done():
            first.cancel()
        if not publish.done():
            publish.cancel()
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_cancelled_inbound_wait_does_not_release_replacement_slot(tmp_path, monkeypatch):
    from gateway.run import _AGENT_PENDING_SENTINEL

    runner, store, entry, source, token = await _runner(tmp_path, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    claimed = asyncio.Event()
    original_save = store._save_entry
    first_lease, replacement_lease = Mock(), Mock()
    first_event = SimpleNamespace(source=source)
    replacement_event = SimpleNamespace(source=source)

    def gated_save(*args, **kwargs):
        if kwargs.get("entry_data", {}).get("session_id") == "child":
            entered.set()
            assert release.wait(3)
        return original_save(*args, **kwargs)

    monkeypatch.setattr(store, "_save_entry", gated_save)
    runner._hm_admit_event = AsyncMock(return_value=(first_event, source, True))
    runner._hm_estop_gate = Mock(return_value=None)
    runner._session_key_for_source = Mock(return_value="route")
    runner._hm_pending_reply_intercepts = AsyncMock(return_value=None)
    runner._hm_dispatch_idle_commands = AsyncMock(return_value=(False, None))
    runner._claim_active_session_slot = Mock(return_value=(first_lease, None))
    runner._hm_rescue_orphaned_fifo = Mock(return_value=(first_event, source, True))
    runner._persist_active_agents = Mock(side_effect=claimed.set)

    publish = asyncio.create_task(runner._hmwa_publish_compression_child_route(entry, "child", "route", 1))
    first = None
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        first = asyncio.create_task(runner._handle_message(first_event))
        await asyncio.wait_for(claimed.wait(), 3)
        state = runner._session_state("route")
        assert runner._release_running_agent_state("route") is True  # /new or /stop slot boundary
        state.turn.agent = _AGENT_PENDING_SENTINEL
        state.turn.event = replacement_event
        state.turn.lease = replacement_lease
        state.turn.started_ts = time.time()
        persisted_before_cancel = runner._persist_active_agents.call_count

        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert state.turn.agent is _AGENT_PENDING_SENTINEL
        assert state.turn.event is replacement_event
        assert state.turn.lease is replacement_lease
        assert runner._persist_active_agents.call_count == persisted_before_cancel
        first_lease.release.assert_called_once_with()
        replacement_lease.release.assert_not_called()
        release.set()
        await asyncio.wait_for(publish, 3)
    finally:
        release.set()
        if first is not None and not first.done():
            first.cancel()
        if not publish.done():
            publish.cancel()
        runner._release_running_agent_state("route")
        runner._turn_leases.release(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["before_state", "setup", "marker_cancel"])
async def test_inbound_claim_released_on_setup_error_or_marker_cancellation(tmp_path, monkeypatch, failure):
    runner, _store, _entry, source, token = await _runner(tmp_path, monkeypatch)
    event = SimpleNamespace(source=source)
    active_lease = Mock()
    runner._hm_admit_event = AsyncMock(return_value=(event, source, True))
    runner._hm_estop_gate = Mock(return_value=None)
    runner._session_key_for_source = Mock(return_value="route")
    runner._hm_pending_reply_intercepts = AsyncMock(return_value=None)
    runner._hm_dispatch_idle_commands = AsyncMock(return_value=(False, None))
    runner._claim_active_session_slot = Mock(return_value=(active_lease, None))
    runner._hm_rescue_orphaned_fifo = Mock(return_value=(event, source, True))
    runner._persist_active_agents = Mock()
    runner._handle_message_with_agent = AsyncMock(return_value="done")
    runner._run_post_turn_hooks = AsyncMock()
    if failure == "before_state":
        runner._sessions_map().pop("route", None)
        runner._hm_rescue_orphaned_fifo = Mock(side_effect=RuntimeError("rescue failed"))
        expected = RuntimeError
    elif failure == "setup":
        monkeypatch.setattr(
            "hermes_cli.observability.shared_metrics_gateway.start_reply_clock",
            Mock(side_effect=RuntimeError("clock setup failed")),
        )
        expected = RuntimeError
    else:
        runner._clear_durable_active_turn = AsyncMock(side_effect=asyncio.CancelledError)
        expected = asyncio.CancelledError

    try:
        with pytest.raises(expected):
            await runner._handle_message(event)
        active_lease.release.assert_called_once_with()
        assert runner._session_state("route").turn.agent is None
        assert runner._session_state("route").turn.lease is None
    finally:
        runner._turn_leases.release(token)
