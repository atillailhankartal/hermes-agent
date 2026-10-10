"""A Gateway route epoch changes only with a durable structural publication."""

from datetime import datetime
from dataclasses import replace
import json
from unittest.mock import Mock

import pytest

from gateway.config import GatewayConfig, Platform
from gateway.session import SessionEntry, SessionSource, SessionStore
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
