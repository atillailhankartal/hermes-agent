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
from gateway.platforms.event import MessageEvent
from gateway.session import AsyncSessionStore, SessionEntry, SessionSource, SessionStore
from gateway.route_claim import claim_for_tool, gateway_route_scope
from gateway.run import GatewayRunner
from gateway.turn_lease import SessionTurnLeaseRegistry
from model_tools import _CallIds, _execute_tool, registry


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
async def test_delayed_route_validation_requires_exact_epoch_owner_and_private_proof(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    token = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    with gateway_route_scope(runner, "route", 1, entry.origin):
        claim = claim_for_tool("A")
    assert claim is not None and claim.is_current() and claim.is_route_current()
    runner._turn_leases.release(token)
    assert claim.is_current() is False
    assert claim.is_route_current() is True
    for altered in (
        replace(claim, surface="cli"), replace(claim, profile_home_key="other"),
        replace(claim, session_key="other"), replace(claim, native_session_id="B"),
        replace(claim, route_epoch="old"), replace(claim, host_owner_id="other"),
        replace(claim, _proof=object()),
    ):
        assert altered.is_route_current() is False
    assert store.switch_session("route", "B", expected_session_id="A")
    assert claim.is_route_current() is False

    # A new process can read the same durable epoch but must not reuse its old owner proof.
    restarted = SessionStore(tmp_path / "sessions", GatewayConfig())
    restarted._db = None
    assert restarted.lookup_by_session_key("route").route_epoch == store.lookup_by_session_key("route").route_epoch
    assert restarted._route_owner_id != store._route_owner_id
    assert store.switch_session("route", "A", expected_session_id="B")
    runner._session_state("route").persistent.run_generation = 2
    second = await runner._turn_leases.acquire("A", owner_key="route", generation=2, timeout=1)
    runner._session_state("route").turn.lease_tokens[2] = second
    try:
        with gateway_route_scope(runner, "route", 2, entry.origin):
            successor = claim_for_tool("A")
        assert successor is not None and successor.is_route_current()
        store.retire_route_owner()
        assert successor.is_route_current() is False
    finally:
        runner._turn_leases.release(second)


@pytest.mark.asyncio
async def test_unverified_switch_stays_closed_until_exact_durable_route_and_new_turn_lease(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    switched = store.switch_session("route", "B", expected_session_id="A")
    assert switched is not None and switched.route_claim_blocked is True
    assert _durable(tmp_path)["route_claim_blocked"] is True
    with gateway_route_scope(runner, "route", 1, entry.origin):
        assert claim_for_tool("B") is None
    token = await runner._turn_leases.acquire("B", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    try:
        route_file = tmp_path / "sessions" / "sessions.json"
        original = route_file.read_text()
        tampered = json.loads(original)
        tampered["route"]["route_epoch"] = "unrelated-durable-epoch"
        route_file.write_text(json.dumps(tampered))
        with gateway_route_scope(runner, "route", 1, switched.origin):
            assert claim_for_tool("B") is None
        assert switched.route_claim_blocked is True
        route_file.write_text(original)
        with gateway_route_scope(runner, "route", 1, switched.origin):
            # A new turn proves native ownership and reads back the exact durable epoch.
            recovered = claim_for_tool("B")
            assert recovered is not None and recovered.is_current()
            assert switched.route_claim_blocked is False
            assert _durable(tmp_path)["route_claim_blocked"] is False
    finally:
        runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_revocation_drains_offloaded_write_without_blocking_loop_or_opening_gate(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    started, release = threading.Event(), threading.Event()
    real_revoke = store.revoke_route_claim

    def held_writer(key):
        started.set()
        assert release.wait(2)
        return real_revoke(key)

    monkeypatch.setattr(store, "revoke_route_claim", held_writer)
    task = asyncio.create_task(runner._invalidate_session_run_generation_async("route", reason="session_reset"))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        gate_entered = asyncio.Event()

        async def try_gate():
            async with runner._session_route_gate("route"):
                gate_entered.set()

        contender = asyncio.create_task(try_gate())
        task.cancel()
        heartbeat = asyncio.Event()
        asyncio.get_running_loop().call_later(0.01, heartbeat.set)
        await asyncio.wait_for(heartbeat.wait(), 0.1)
        assert not task.done() and not gate_entered.is_set()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(contender, 0.1)
    assert gate_entered.is_set()
    assert store.lookup_by_session_key("route") is entry
    assert entry.route_claim_blocked and _durable(tmp_path)["route_claim_blocked"]


def test_failed_route_revocation_closes_old_proof_in_memory(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    old_epoch = entry.route_epoch
    monkeypatch.setattr(store, "_save_entry", Mock(side_effect=OSError("disk unavailable")))
    assert store.revoke_route_claim("route") is False
    assert entry.route_epoch == old_epoch
    assert entry.route_claim_blocked is True
    assert entry.route_claim_recoverable is False
    assert _durable(tmp_path)["route_epoch"] == old_epoch


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["stop", "new", "evict"])
async def test_interrupt_boundary_revokes_delayed_route_claim_and_next_turn_recovers(tmp_path, monkeypatch, boundary):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    first = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = first
    with gateway_route_scope(runner, "route", 1, entry.origin):
        old = claim_for_tool("A")
    assert old and old.is_route_current()
    if boundary == "new":
        await runner._invalidate_session_run_generation_async("route", reason="session_reset")
    elif boundary == "stop":
        await runner._interrupt_running_turn_async(
            "route", interrupt_reason="stop", invalidation_reason="stop_command",
        )
    else:
        runner._drop_turn_slot = Mock()
        await runner._hm_evict_running_agent("route", "stale_running_agent_eviction")
    assert old.is_route_current() is False
    assert entry.route_epoch != old.route_epoch
    assert entry.route_claim_blocked is True
    assert _durable(tmp_path)["route_epoch"] == entry.route_epoch
    runner._turn_leases.release(first)
    runner._session_state("route").turn.lease_tokens.pop(1, None)
    generation = runner._current_session_run_generation("route")
    successor = await runner._turn_leases.acquire("A", owner_key="route", generation=generation, timeout=1)
    runner._session_state("route").turn.lease_tokens[generation] = successor
    try:
        with gateway_route_scope(runner, "route", generation, entry.origin):
            fresh = claim_for_tool("A")
        assert fresh and fresh.is_current() and fresh.is_route_current()
        assert fresh.route_epoch != old.route_epoch
    finally:
        runner._turn_leases.release(successor)


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
            assert store.revoke_route_claim("route") is True
            assert entry.route_claim_blocked is True
            assert entry.route_claim_recoverable is False
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
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    emitted = AsyncMock()
    monkeypatch.setattr("gateway.route_lifecycle.emit_route_lifecycle", emitted)
    old_epoch = entry.route_epoch
    await runner._persist_manual_compression(
        type("Agent", (), {"session_id": "A", "_last_compaction_in_place": True})(),
        entry, entry.origin, [],
    )
    assert entry.route_epoch != old_epoch
    assert _durable(tmp_path)["route_epoch"] == entry.route_epoch
    emitted.assert_awaited_once()
    _, name, payload = emitted.await_args.args
    assert name == "on_session_compacted"
    assert payload["old_session_id"] == payload["session_id"] == "A"
    assert payload["old_route_epoch"] == old_epoch and payload["route_epoch"] == entry.route_epoch
    assert payload["in_place"] is True
    assert payload["route_claim"].is_current() is False
    assert payload["route_claim"].is_route_current() is True


@pytest.mark.asyncio
async def test_child_compaction_lifecycle_follows_durable_lease_handoff(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    token = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    emitted = AsyncMock()
    monkeypatch.setattr("gateway.route_lifecycle.emit_route_lifecycle", emitted)
    old_epoch = entry.route_epoch
    try:
        await runner._hmwa_publish_compression_child_route(entry, "B", "route", 1)
        emitted.assert_awaited_once()
        _, name, payload = emitted.await_args.args
        assert name == "on_session_compacted"
        assert payload["old_session_id"] == "A" and payload["session_id"] == "B"
        assert payload["old_route_epoch"] == old_epoch and payload["route_epoch"] == entry.route_epoch
        assert payload["in_place"] is False
        assert payload["route_claim"].is_route_current()
        assert _durable(tmp_path)["route_epoch"] == entry.route_epoch
    finally:
        runner._turn_leases.release(token)


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


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_resume_revokes_old_claim_before_durable_b_switch(tmp_path, monkeypatch, cancel):
    store, entry = _store(tmp_path, monkeypatch)
    monkeypatch.setattr(store, "get_or_create_session", Mock(return_value=entry))
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._session_db = SimpleNamespace(get_session_title=AsyncMock(return_value="B"))
    runner._normalize_source_for_session_key = lambda source: source
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_key_for_source = lambda _source: "route"
    runner._resolve_resume_target = AsyncMock(return_value=("B", "B"))
    runner._resume_access_denied_reply = AsyncMock(return_value=None)
    runner._persist_active_agents = Mock()
    runner._clear_conversation_scope = Mock()
    runner._evict_cached_agent = Mock()
    emitted = AsyncMock()
    monkeypatch.setattr("gateway.route_lifecycle.emit_route_lifecycle", emitted)
    runner._session_state("route").persistent.run_generation = 1
    token = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    with gateway_route_scope(runner, "route", 1, entry.origin):
        old_claim = claim_for_tool("A")
    assert old_claim and old_claim.is_current()
    started, release = threading.Event(), threading.Event()
    real_switch = store.switch_session

    def delayed_switch(*args, **kwargs):
        started.set()
        assert release.wait(2), "test switch was not released"
        return real_switch(*args, **kwargs)

    monkeypatch.setattr(store, "switch_session", delayed_switch)
    task = asyncio.create_task(runner._handle_resume_command(MessageEvent(
        text="/resume B", source=entry.origin,
    )))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        assert old_claim.is_current() is False
        assert entry.session_id == "A" and _durable(tmp_path)["session_id"] == "A"
        if cancel:
            task.cancel()
            heartbeat = asyncio.Event()
            asyncio.get_running_loop().call_later(0.01, heartbeat.set)
            await asyncio.wait_for(heartbeat.wait(), 0.1)
            assert not task.done()
    finally:
        release.set()
    if cancel:
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await task
    assert store.lookup_by_session_key("route").session_id == "B"
    emitted.assert_awaited_once()
    _, hook_name, payload = emitted.await_args.args
    assert hook_name == "on_session_resumed"
    assert payload["session_key"] == "route" and payload["session_id"] == "B"
    assert payload["old_session_id"] == "A"
    assert payload["old_route_epoch"] == old_claim.route_epoch
    assert payload["route_epoch"] != old_claim.route_epoch
    assert payload["route_is_current"]() is True
    assert payload["route_claim"].is_current() is False
    assert payload["route_claim"].is_route_current() is True
    runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_reset_hooks_carry_distinct_keyed_old_and_new_epochs(tmp_path, monkeypatch):
    store, old = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._finalize_session_off_loop = AsyncMock()
    runner.hooks = SimpleNamespace(emit=AsyncMock())
    emitted = AsyncMock()
    monkeypatch.setattr("gateway.route_lifecycle.emit_route_lifecycle", emitted)
    new = store.reset_session("route")
    assert new and new.route_epoch != old.route_epoch

    await runner._fire_session_reset_hooks(old.origin, "route", old, new)
    finalize = runner._finalize_session_off_loop.await_args.kwargs
    assert finalize["session_key"] == "route"
    assert finalize["session_id"] == old.session_id
    assert finalize["route_epoch"] == old.route_epoch
    assert finalize["route_is_current"]() is False
    _, hook_name, payload = emitted.await_args.args
    assert hook_name == "on_session_reset"
    assert payload["session_key"] == "route"
    assert payload["session_id"] == new.session_id
    assert payload["route_epoch"] == new.route_epoch
    assert payload["route_is_current"]() is True
    assert store.switch_session("route", old.session_id, expected_session_id=new.session_id)
    assert payload["route_is_current"]() is False  # late reset cannot retire resumed A


@pytest.mark.asyncio
async def test_legacy_route_epoch_requires_held_exact_lease_and_durable_save(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    entry.route_epoch = None
    store._save_entries()
    store = SessionStore(tmp_path / "sessions", GatewayConfig())
    store._db = None
    entry = store.lookup_by_session_key("route")
    assert entry.route_epoch is None
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    with gateway_route_scope(runner, "route", 1, entry.origin):
        assert claim_for_tool("A") is None

    wrong = await runner._turn_leases.acquire("B", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = wrong
    with gateway_route_scope(runner, "route", 1, entry.origin):
        assert claim_for_tool("A") is None
    runner._turn_leases.release(wrong)
    runner._session_state("route").turn.lease_tokens.pop(1)

    stale = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = stale
    runner._turn_leases.release(stale)
    with gateway_route_scope(runner, "route", 1, entry.origin):
        assert claim_for_tool("A") is None
    assert entry.route_epoch is None
    runner._session_state("route").turn.lease_tokens.pop(1)

    token = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    real_save = store._save_entry
    monkeypatch.setattr(store, "_save_entry", Mock(side_effect=OSError("save failed")))
    with gateway_route_scope(runner, "route", 1, entry.origin):
        assert claim_for_tool("A") is None
    assert entry.route_epoch is None and _durable(tmp_path)["route_epoch"] is None
    monkeypatch.setattr(store, "_save_entry", real_save)
    with gateway_route_scope(runner, "route", 1, entry.origin):
        claim = claim_for_tool("A")
    assert claim and claim.is_current()
    assert entry.route_epoch == claim.route_epoch == _durable(tmp_path)["route_epoch"]
    runner._turn_leases.release(token)


@pytest.mark.asyncio
async def test_actual_new_finalizes_pre_revoke_epoch(tmp_path, monkeypatch):
    store, old = _store(tmp_path, monkeypatch)
    original_epoch = old.route_epoch
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._async_session_store = AsyncSessionStore(store)
    runner._session_key_for_source = lambda _source: "route"
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._release_running_agent_state = Mock()
    runner._cleanup_old_agent_for_reset = AsyncMock()
    runner._evict_cached_agent = Mock()
    runner._clear_conversation_scope = Mock()
    runner._reset_notice_session_info = Mock(return_value="")
    runner._telegram_topic_new_header = Mock(return_value=None)
    runner._is_telegram_topic_lane = Mock(return_value=False)
    runner._session_db = None
    runner._finalize_session_off_loop = AsyncMock()
    runner.hooks = SimpleNamespace(emit=AsyncMock())
    emitted = AsyncMock()
    monkeypatch.setattr("gateway.route_lifecycle.emit_route_lifecycle", emitted)
    runner._session_state("route").persistent.run_generation = 1

    started, release = threading.Event(), threading.Event()
    real_revoke = store.revoke_route_claim

    def held_revoke(key):
        started.set()
        assert release.wait(2)
        return real_revoke(key)

    monkeypatch.setattr(store, "revoke_route_claim", held_revoke)
    reset = asyncio.create_task(runner._handle_reset_command(MessageEvent(text="/new", source=old.origin)))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        heartbeat = asyncio.Event()
        asyncio.get_running_loop().call_later(0.01, heartbeat.set)
        await asyncio.wait_for(heartbeat.wait(), 0.1)
        assert not reset.done() and not emitted.await_count
        assert store.lookup_by_session_key("route").route_epoch == original_epoch
    finally:
        release.set()
    await reset
    new = store.lookup_by_session_key("route")
    assert new.session_id != old.session_id
    assert new.route_epoch not in (None, original_epoch)
    assert runner._finalize_session_off_loop.await_args.kwargs["route_epoch"] == original_epoch
    assert emitted.await_args.args[2]["old_route_epoch"] == original_epoch
    assert emitted.await_args.args[2]["route_epoch"] == new.route_epoch


@pytest.mark.asyncio
async def test_post_dispatch_route_change_reports_unknown_before_retry(tmp_path, monkeypatch):
    store, entry = _store(tmp_path, monkeypatch)
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner._turn_leases = SessionTurnLeaseRegistry()
    runner._resolve_profile_home_for_source = lambda _source: tmp_path
    runner._session_state("route").persistent.run_generation = 1
    token = await runner._turn_leases.acquire("A", owner_key="route", generation=1, timeout=1)
    runner._session_state("route").turn.lease_tokens[1] = token
    calls = []

    def dispatch(_name, _args, **kwargs):
        calls.append(kwargs["route_claim"])
        assert store.revoke_route_claim("route")
        return json.dumps({"error": "operation may have committed", "error_type": "outcome_unknown"})

    monkeypatch.setattr(registry, "dispatch", dispatch)
    ids = _CallIds(session_id="A", task_id="turn", tool_call_id="tool")
    try:
        with gateway_route_scope(runner, "route", 1, entry.origin):
            result = _execute_tool("bee_peers", {}, {}, ids, user_task=None,
                                   enabled_tools=None, skip_tool_execution_middleware=True)
        assert len(calls) == 1
        assert json.loads(result)["error_type"] == "outcome_unknown"
        runner._session_state("route").persistent.run_generation = 2
        with gateway_route_scope(runner, "route", 1, entry.origin):
            rejected = _execute_tool("bee_peers", {}, {}, ids, user_task=None,
                                     enabled_tools=None, skip_tool_execution_middleware=True)
        assert len(calls) == 1
        assert json.loads(rejected)["error_type"] == "session_closed"
    finally:
        runner._turn_leases.release(token)
