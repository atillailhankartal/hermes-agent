"""A Gateway route epoch changes only with a durable structural publication."""

import asyncio
import threading
from datetime import datetime
from dataclasses import replace
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from gateway.config import GatewayConfig, Platform
from gateway.session import AsyncSessionStore, SessionEntry, SessionSource, SessionStore
from gateway.route_claim import claim_for_tool, gateway_route_scope
from gateway.run import GatewayRunner
from gateway.turn_lease import SessionTurnLeaseRegistry


def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(SessionStore, "_open_session_db_for_active_scope", lambda *_a, **_k: None)
    store = SessionStore(tmp_path / "sessions", GatewayConfig())
    store._db = None
    source = SessionSource(platform=Platform.TELEGRAM, chat_id="chat", user_id="user")
    entry = SessionEntry(
        session_key="route", session_id="A", created_at=datetime.now(),
        updated_at=datetime.now(), origin=source, platform=Platform.TELEGRAM,
    )
    store._entries["route"] = entry
    store._loaded = True
    store._save_entries()
    return store, entry


def _durable(tmp_path):
    return json.loads((tmp_path / "sessions" / "sessions.json").read_text())["route"]


def test_route_epoch_round_trips_and_aba_resume_mints_new_epoch(tmp_path, monkeypatch):
    store, first = _store(tmp_path, monkeypatch)
    first_epoch = first.route_epoch
    assert first_epoch and _durable(tmp_path)["route_epoch"] == first_epoch
    assert SessionEntry.from_dict(_durable(tmp_path)).route_epoch == first_epoch

    second = store.switch_session("route", "B", expected_session_id="A")
    assert second and second.route_epoch not in (None, first_epoch)
    assert _durable(tmp_path)["route_epoch"] == second.route_epoch
    third = store.switch_session("route", "A", expected_session_id="B")
    assert third and len({first_epoch, second.route_epoch, third.route_epoch}) == 3
    assert _durable(tmp_path)["session_id"] == "A"
    assert _durable(tmp_path)["route_epoch"] == third.route_epoch


def test_failed_reset_save_keeps_old_live_and_durable_epoch(tmp_path, monkeypatch):
    store, first = _store(tmp_path, monkeypatch)
    epoch = first.route_epoch
    monkeypatch.setattr(store, "_persist_routing_data", Mock(side_effect=OSError("route save failed")))
    with pytest.raises(OSError, match="route save failed"):
        store.reset_session("route")
    assert store.lookup_by_session_key("route") is first
    assert first.route_epoch == epoch
    assert _durable(tmp_path)["session_id"] == "A"
    assert _durable(tmp_path)["route_epoch"] == epoch


def test_compression_child_publishes_new_epoch_with_native_id(tmp_path, monkeypatch):
    store, first = _store(tmp_path, monkeypatch)
    epoch = first.route_epoch
    assert store.publish_compression_child_route("route", first, "A", "B") is True
    assert first.session_id == "B"
    assert first.route_epoch and first.route_epoch != epoch
    assert _durable(tmp_path)["session_id"] == "B"
    assert _durable(tmp_path)["route_epoch"] == first.route_epoch


@pytest.mark.asyncio
async def test_host_claim_fences_old_a_before_first_b_tool_and_allows_resumed_a(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    first_token = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = first_token
    try:
        with gateway_route_scope(runner, "route", 1, entry.origin):
            first_a = claim_for_tool("A")
            assert first_a is not None and first_a.is_current()
            assert first_a.is_current(profile_home_key="foreign-home") is False
            assert replace(first_a, _proof=object()).is_current() is False
            assert claim_for_tool("wrong-native") is None

            assert runner._turn_leases.rebind(first_token, "B") is True
            assert store.publish_compression_child_route("route", entry, "A", "B") is True
            assert first_a.is_current() is False  # no B tool was called yet
            second_b = claim_for_tool("B")
            assert second_b is not None and second_b.is_current()
            assert second_b.route_epoch != first_a.route_epoch
        runner._turn_leases.release(first_token)
        runner._session_state("route").turn.lease_tokens.pop(1)
        runner._session_state("route").persistent.run_generation = 2
        resumed = store.switch_session("route", "A", expected_session_id="B")
        assert resumed is not None
        second_token = await runner._turn_leases.acquire("A", owner_key="route", generation=2, timeout=1)
        runner._session_state("route").turn.lease_tokens[2] = second_token
        try:
            with gateway_route_scope(runner, "route", 2, resumed.origin):
                resumed_a = claim_for_tool("A")
                assert resumed_a is not None and resumed_a.is_current()
                assert len({first_a.route_epoch, second_b.route_epoch, resumed_a.route_epoch}) == 3
                assert first_a.is_current() is False
                assert second_b.is_current() is False
                store.retire_route_owner()
                assert resumed_a.is_current() is False
        finally:
            runner._turn_leases.release(second_token)
        restarted = SessionStore(tmp_path / "sessions", GatewayConfig())
        restarted._db = None
        assert restarted.lookup_by_session_key("route").route_epoch == resumed.route_epoch
        assert restarted._route_owner_id != store._route_owner_id
    finally:
        runner._turn_leases.release(first_token)


@pytest.mark.asyncio
async def test_in_place_compaction_revokes_in_flight_claim_before_next_tool(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    token = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    agent = SimpleNamespace(_last_compaction_in_place=False)
    try:
        with gateway_route_scope(runner, "route", 1, entry.origin, agent_holder=[agent]):
            old = claim_for_tool("A")
            assert old is not None and old.is_current()
            agent._last_compaction_in_place = True
            assert old.is_current() is False
            assert claim_for_tool("A") is None
            assert store.publish_in_place_compaction_epoch("route", entry, "A") is True
            assert old.is_current() is False
    finally:
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_bee_tool_dispatch_gets_private_current_claim_not_model_args(tmp_path, monkeypatch):
    from model_tools import _CallIds, _execute_tool
    from model_tools import registry

    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    token = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    captured = []

    def dispatch(name, args, **kwargs):
        captured.append((name, args, kwargs))
        return "ok"

    monkeypatch.setattr(registry, "dispatch", dispatch)
    ids = _CallIds(session_id="A", task_id="turn", tool_call_id="tool")
    try:
        with gateway_route_scope(runner, "route", 1, entry.origin):
            assert _execute_tool("bee_peers", {}, {}, ids, user_task=None,
                                 enabled_tools=None, skip_tool_execution_middleware=True) == "ok"
            assert captured[0][1] == {}
            issued = captured[0][2].get("route_claim")
            assert issued is not None and issued.is_current()
            assert store.publish_compression_child_route("route", entry, "A", "B") is True
            denied = _execute_tool("bee_peers", {}, {}, ids, user_task=None,
                                   enabled_tools=None, skip_tool_execution_middleware=True)
            assert "route" in denied.lower() or "session" in denied.lower()
            assert len(captured) == 1
    finally:
        runner._turn_leases.release(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("writer", ["advance", "retry_reroute"])
async def test_unleased_store_level_compression_repoint_stays_closed_to_bee(tmp_path, monkeypatch, writer):
    """These background writers lack a proven A→B turn-lease transfer: deny claims."""
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    if writer == "advance":
        assert store.advance_compression_session("route", "A", "B") is entry
    else:
        store._publish_transcript_reroute("A", "B")
    assert entry.session_id == "B" and entry.route_claim_blocked is True
    assert _durable(tmp_path)["route_claim_blocked"] is True
    token = await runner._turn_leases.acquire("B", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    try:
        with gateway_route_scope(runner, "route", 1, entry.origin):
            assert claim_for_tool("B") is None
    finally:
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_manual_compression_refuses_child_when_alias_lease_is_held(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._sync_telegram_topic_binding = Mock()
    blocker = await runner._turn_leases.acquire("B", owner_key="alias", generation=1, timeout=1)
    try:
        with pytest.raises(RuntimeError, match="lease|compression route"):
            await runner._persist_manual_compression(
                type("Agent", (), {"session_id": "B", "_last_compaction_in_place": False})(),
                entry, entry.origin, [],
            )
        assert entry.session_id == "A"
        assert _durable(tmp_path)["session_id"] == "A"
    finally:
        runner._turn_leases.release(blocker)


@pytest.mark.asyncio
async def test_manual_in_place_compression_mints_new_epoch(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    runner._turn_leases = SessionTurnLeaseRegistry()
    old_epoch = entry.route_epoch
    await runner._persist_manual_compression(
        type("Agent", (), {"session_id": "A", "_last_compaction_in_place": True})(),
        entry, entry.origin, [],
    )
    assert entry.route_epoch != old_epoch
    assert _durable(tmp_path)["route_epoch"] == entry.route_epoch


@pytest.mark.asyncio
async def test_manual_compression_holds_a_lease_until_cancelled_worker_drains(tmp_path, monkeypatch):
    """Cancellation cannot expose A to an alias while the offloaded compressor still writes."""
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._session_key_for_source = lambda _source: "route"
    runner._resolve_session_agent_runtime = lambda **_kw: ("model", {"api_key": "test"})
    runner._resolve_session_reasoning_config = lambda **_kw: None
    agent = MagicMock()
    agent.session_id = "A"
    runner._build_manual_compression_agent = AsyncMock(return_value=agent)
    runner._cleanup_agent_resources_off_loop = AsyncMock()
    runner._evict_cached_agent = Mock()

    async def offload(fn):
        return await asyncio.to_thread(fn)

    runner._run_in_executor_with_context = offload
    monkeypatch.setattr(store, "load_transcript", Mock(return_value=[
        {"role": "user", "content": str(i)} for i in range(8)
    ]))
    started, release = threading.Event(), threading.Event()

    def blocked_compressor(*_a, **_kw):
        started.set()
        assert release.wait(2), "test worker was not released"
        return SimpleNamespace(status="nothing_to_do")

    monkeypatch.setattr("agent.conversation_compression_manual.compress_now", blocked_compressor)
    task = asyncio.create_task(runner._run_manual_compression(entry.origin, entry, [], SimpleNamespace()))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        assert runner._turn_leases._leases["A"].holder is not None
        task.cancel()
        await asyncio.sleep(0)
        heartbeat = asyncio.Event()
        asyncio.get_running_loop().call_later(0.01, heartbeat.set)
        await asyncio.wait_for(heartbeat.wait(), 0.1)
        assert not task.done()
        with pytest.raises(TimeoutError):
            await runner._turn_leases.acquire("A", owner_key="alias", generation=1, timeout=0.05)
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert runner._turn_leases._leases["A"].holder is None
    successor = await runner._turn_leases.acquire("A", owner_key="alias", generation=1, timeout=0.1)
    assert successor is not None
    runner._turn_leases.release(successor)


@pytest.mark.asyncio
async def test_manual_child_persist_cancellation_drains_before_releasing_lease(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._sync_telegram_topic_binding = Mock()
    started, release = threading.Event(), threading.Event()
    real_persist = store.persist_rotated_compression_child

    def blocked_persist(*args, **kwargs):
        started.set()
        assert release.wait(2), "test writer was not released"
        return real_persist(*args, **kwargs)

    monkeypatch.setattr(store, "persist_rotated_compression_child", blocked_persist)
    task = asyncio.create_task(runner._persist_manual_compression(
        SimpleNamespace(session_id="B"), entry, entry.origin,
        [{"role": "assistant", "content": "summary"}],
    ))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        task.cancel()
        await asyncio.sleep(0)
        heartbeat = asyncio.Event()
        asyncio.get_running_loop().call_later(0.01, heartbeat.set)
        await asyncio.wait_for(heartbeat.wait(), 0.1)
        assert not task.done()
        assert runner._turn_leases._leases["A"].holder is not None
        assert entry.session_id == "A" and _durable(tmp_path)["session_id"] == "A"
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert entry.session_id == "A" and _durable(tmp_path)["session_id"] == "A"
    assert runner._turn_leases._leases["A"].holder is None
