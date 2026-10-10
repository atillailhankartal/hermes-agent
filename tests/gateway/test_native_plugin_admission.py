"""Native admission uses a real on-disk queue and real Gateway route store."""
import asyncio
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from gateway.config import GatewayConfig, Platform
from gateway.route_claim import claim_for_route
from gateway.run import GatewayRunner
from gateway.session import SessionStore, SessionSource
from hermes_constants import hermes_home_key
from hermes_cli.plugins import PluginManager, PluginManifest, LoadedPlugin


def test_pre_model_grant_uses_exact_reserved_candidate_without_authorizing_proof(tmp_path):
    from gateway.native_plugin_queue import NativePluginQueue
    from hermes_cli.trusted_inbound_broker import PreModelBrokerGrant

    queue = NativePluginQueue(tmp_path)
    grant = PreModelBrokerGrant(
        "delivery", "gateway", "profile", "key", "native", "owner", "epoch",
        queue.payload_digest("payload"), "enrollment", "bee-reserved", "private-capability",
        int(time.time() * 1000) + 60_000,
    )
    assert queue.install_pre_model_grant(grant)
    row = queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                      native_id="native", owner="owner", plugin="bee", content="payload")
    assert row["candidate"] == "bee-reserved" and row["enrollment_id"] == "enrollment"
    assert row["state"] == "unknown" and row["native_event_id"] is None
    assert queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                       native_id="native", owner="owner", plugin="bee", content="payload") == row
    assert b"private-capability" not in queue.path.read_bytes()


def test_pre_model_grant_route_change_fails_closed(tmp_path):
    from gateway.native_plugin_queue import NativePluginQueue
    from hermes_cli.trusted_inbound_broker import PreModelBrokerGrant

    queue = NativePluginQueue(tmp_path)
    grant = PreModelBrokerGrant(
        "delivery", "gateway", "profile", "key", "native", "owner", "epoch",
        queue.payload_digest("payload"), "enrollment", "bee-reserved", "capability",
        int(time.time() * 1000) + 60_000,
    )
    assert queue.install_pre_model_grant(grant)
    row = queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                      native_id="native", owner="new-owner", plugin="bee", content="payload")
    assert row["state"] == "rejected" and row["candidate"] is None
    assert row["native_event_id"] is None


def test_native_event_id_commits_once_and_survives_sqlite_restart(tmp_path):
    from gateway.native_plugin_queue import NativePluginQueue
    from hermes_cli.trusted_inbound_broker import (
        NativeCandidateSnapshot, PreModelBrokerGrant, TrustedInboundBrokerClient,
    )
    from hermes_cli.trusted_inbound_wire import decode_request

    queue = NativePluginQueue(tmp_path)
    grant = PreModelBrokerGrant(
        "delivery", "gateway", "profile", "key", "native", "owner", "epoch",
        queue.payload_digest("payload"), "enrollment", "bee-reserved", "capability",
        int(time.time() * 1000) + 60_000,
    )
    assert queue.install_pre_model_grant(grant)
    row = queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                      native_id="native", owner="owner", plugin="bee", content="payload")
    assert row["native_event_id"] is None
    assert queue.transition(row["candidate"], "queued", "running")
    running = queue.lookup("profile", "epoch", "delivery")
    assert queue.settle(running)
    settled = queue.lookup("profile", "epoch", "delivery")
    assert settled["native_event_id"] and settled["state"] == "admitted"
    restarted = NativePluginQueue(tmp_path)
    recovered = restarted.lookup("profile", "epoch", "delivery")
    assert recovered["native_event_id"] == settled["native_event_id"]
    assert recovered["enrollment_id"] == "enrollment"
    snapshot = NativeCandidateSnapshot.from_running_row(recovered, surface="gateway", content="payload")
    requests = []

    class LostBroker:
        def exchange(self, request):
            requests.append(decode_request(request))
            return None

    client = TrustedInboundBrokerClient()
    client.transport = LostBroker()
    assert client.query_native_event(snapshot).state == "unknown"
    assert [(request.kind, request.fields[2]) for request in requests] == [
        (4, settled["native_event_id"])]
    assert not restarted.settle(running)
    assert restarted.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                           native_id="native", owner="owner", plugin="bee", content="payload")[
                               "native_event_id"] == settled["native_event_id"]


def host(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(SessionStore, "_open_session_db_for_active_scope", lambda *_a, **_k: None)
    runner = object.__new__(GatewayRunner)
    runner.session_store = SessionStore(tmp_path / "sessions", GatewayConfig())
    runner._running = True
    runner._draining = False
    runner._background_tasks = set()
    runner._resolve_profile_home_for_source = lambda source: tmp_path
    runner._is_user_authorized_for_source = lambda *a, **kw: True
    runner._is_session_running = lambda key: False
    source = SessionSource(platform=Platform.TELEGRAM, chat_id="42", user_id="42")
    entry = runner.session_store.get_or_create_session(source)
    adapter = SimpleNamespace(_active_sessions={}, _pending_messages={}, _session_tasks={})
    adapter._start_session_processing = Mock(return_value=True)
    runner._delivery_adapter_for = lambda source: adapter
    runner._plugin_injection_scope = lambda source: _Scope()
    runner._plugin_injection_authorized = lambda *args, **kwargs: True
    (tmp_path / "config.yaml").write_text("plugins:\n  entries:\n    bee:\n      allow_gateway_injection: true\n")
    manager = PluginManager(scope_key=hermes_home_key(tmp_path))
    manifest = PluginManifest(name="bee", key="bee", source="user")
    manager._plugins["bee"] = LoadedPlugin(manifest, enabled=True)
    claim = claim_for_route(runner, entry, source)
    manager.set_admission_host("gateway", runner, runner._admit_plugin_message, claim.host_owner_id)
    return runner, adapter, manager, claim


class _Scope:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


async def admit(runner, manager, claim, delivery="delivery", content="one"):
    return await runner._admit_native_plugin_candidate(
        content=content, surface="gateway", route_claim=claim,
        expected_session_id=claim.native_session_id, delivery_id=delivery,
        plugin_id="bee", manager=manager,
    )


@pytest.mark.asyncio
async def test_exact_commit_duplicate_and_restart_readback(tmp_path, monkeypatch):
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    first = await admit(runner, manager, claim)
    assert first.state == "unknown" and first.candidate_id is None
    second = await admit(runner, manager, claim, content="one")
    assert second == first
    adapter._start_session_processing.assert_not_called()
    restarted, _, restarted_manager, new_claim = host(tmp_path, monkeypatch)
    assert new_claim.route_epoch == claim.route_epoch
    assert new_claim.host_owner_id != claim.host_owner_id
    assert await admit(restarted, restarted_manager, new_claim) == first
    status = restarted._query_native_plugin_admission(
        manager=restarted_manager, route_claim=new_claim, delivery_id="delivery", expected_content="one")
    assert status == first
    assert len(restarted._native_plugin_queue().queued()) == 1
    row = restarted._native_plugin_queue().lookup(manager.scope_key, claim.route_epoch, "delivery")
    assert row["owner"] == claim.host_owner_id  # restart readback never relabels the original admission


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("profile_home_key", "wrong"), ("native_session_id", "wrong"),
    ("host_owner_id", "wrong"), ("session_key", "wrong"), ("route_epoch", "wrong"), ("_proof", object())])
async def test_wrong_claim_no_insertion(tmp_path, monkeypatch, field, value):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    receipt = await admit(runner, manager, replace(claim, **{field: value}))
    assert receipt.state == "rejected" and receipt.candidate_id is None
    assert runner._native_plugin_queue().queued() == []


@pytest.mark.asyncio
async def test_busy_candidates_stay_distinct_and_drain_on_real_adapter_path(tmp_path, monkeypatch):
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    adapter._active_sessions[claim.session_key] = asyncio.Event()
    first = await admit(runner, manager, claim, "one", "first")
    second = await admit(runner, manager, claim, "two", "second")
    assert first.state == second.state == "unknown"
    assert len({runner._native_plugin_queue().lookup(manager.scope_key, claim.route_epoch, d)["candidate"] for d in ("one", "two")}) == 2
    await runner._drain_native_plugin_candidates_once()
    adapter._start_session_processing.assert_not_called()
    adapter._active_sessions.clear()
    events = []
    def start(event, key):
        events.append(event)
        adapter._active_sessions[key] = asyncio.Event()
        return True
    adapter._start_session_processing.side_effect = start
    await runner._drain_native_plugin_candidates_once()
    assert [e.text for e in events] == ["first"]
    assert events[0].metadata["hermes_native_candidate_id"] == runner._native_plugin_queue().lookup(manager.scope_key, claim.route_epoch, "one")["candidate"]
    adapter._active_sessions.clear()
    await runner._drain_native_plugin_candidates_once()
    assert [e.text for e in events] == ["first", "second"]
    await runner._drain_native_plugin_candidates_once()
    assert len(events) == 2


@pytest.mark.asyncio
async def test_stale_epoch_never_drains_after_aba(tmp_path, monkeypatch):
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    first = await admit(runner, manager, claim)
    runner.session_store.switch_session(claim.session_key, "B", expected_session_id=claim.native_session_id)
    runner.session_store.switch_session(claim.session_key, claim.native_session_id, expected_session_id="B")
    await runner._drain_native_plugin_candidates_once()
    adapter._start_session_processing.assert_not_called()
    assert runner._query_native_plugin_admission(manager=manager, route_claim=claim,
        delivery_id="delivery", expected_content="one") == first
    assert runner._native_plugin_queue().queued() == []


@pytest.mark.asyncio
async def test_post_commit_error_same_id_readback_and_no_second_candidate(tmp_path, monkeypatch):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    queue = runner._native_plugin_queue()
    original = queue.admit
    def fail_after(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("after durable commit")
    monkeypatch.setattr(queue, "admit", fail_after)
    receipt = await admit(runner, manager, claim)
    assert receipt.state in ("admitted", "unknown")
    monkeypatch.setattr(queue, "admit", original)
    retry = await admit(runner, manager, claim)
    assert retry.state == "unknown"
    assert len(queue.queued()) == 1


@pytest.mark.asyncio
async def test_failed_start_is_not_replayed_after_restart(tmp_path, monkeypatch):
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    receipt = await admit(runner, manager, claim)
    adapter._start_session_processing.side_effect = RuntimeError("possibly started")
    await runner._drain_native_plugin_candidates_once()
    restarted, new_adapter, manager, new_claim = host(tmp_path, monkeypatch)
    await restarted._drain_native_plugin_candidates_once()
    new_adapter._start_session_processing.assert_not_called()
    assert await admit(restarted, manager, new_claim) == receipt


@pytest.mark.asyncio
async def test_real_adapter_to_gateway_handler_once_and_pending_human_preserved(tmp_path, monkeypatch):
    from gateway.platforms.base import BasePlatformAdapter, PlatformConfig
    from gateway.platforms.event import MessageEvent, MessageType

    class Adapter(BasePlatformAdapter):
        async def connect(self, **kwargs):
            return True
        async def disconnect(self):
            pass
        async def send(self, *args, **kwargs):
            raise AssertionError("no network expected")
        async def get_chat_info(self, chat_id):
            return {"id": chat_id}

    runner, _, manager, claim = host(tmp_path, monkeypatch)
    adapter = Adapter(PlatformConfig(enabled=True, token="test"), Platform.TELEGRAM)
    adapter.set_message_handler(runner._handle_message)
    runner._delivery_adapter_for = lambda source: adapter
    runner._handle_message_admitted = AsyncMock(return_value=None)
    human = MessageEvent(text="human photo", message_type=MessageType.PHOTO,
                         source=runner.session_store.lookup_by_session_key(claim.session_key).origin,
                         media_urls=["human.jpg"], media_types=["image/jpeg"])
    adapter._pending_messages[claim.session_key] = human
    receipt = await admit(runner, manager, claim)
    await runner._drain_native_plugin_candidates_once()
    assert adapter._pending_messages[claim.session_key] is human
    assert human.text == "human photo" and human.media_urls == ["human.jpg"]
    runner._handle_message_admitted.assert_not_awaited()
    adapter._pending_messages.pop(claim.session_key)
    await runner._drain_native_plugin_candidates_once()
    task = adapter._session_tasks[claim.session_key]
    await task
    runner._handle_message_admitted.assert_awaited_once()
    event = runner._handle_message_admitted.await_args.args[0]
    assert event.metadata["hermes_native_candidate_id"] == runner._native_plugin_queue().lookup(manager.scope_key, claim.route_epoch, "delivery")["candidate"]
    assert event.text == "one" and event.allow_gateway_control is False
    # Even replay of the exact in-process event cannot re-enter the Gateway handler.
    await runner._handle_message(event)
    runner._handle_message_admitted.assert_awaited_once()
    assert await admit(runner, manager, claim) == receipt
    await runner._drain_native_plugin_candidates_once()
    runner._handle_message_admitted.assert_awaited_once()


@pytest.mark.asyncio
async def test_cap_rejection_is_durable_and_distinct_candidates_never_merge(tmp_path, monkeypatch):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    for i in range(100):
        assert (await admit(runner, manager, claim, str(i), "text")).state == "unknown"
    rejected = await admit(runner, manager, claim, "overflow", "last")
    assert rejected.state == "rejected" and rejected.reason == "native_queue_full"
    assert rejected.candidate_id is None
    queue = runner._native_plugin_queue()
    head = queue.queued()[0]
    queue.transition(head["candidate"], "queued", "stale_route")
    assert await admit(runner, manager, claim, "overflow", "last") == rejected


@pytest.mark.asyncio
async def test_route_gate_delays_insert_and_transition_wins(tmp_path, monkeypatch):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    async with runner._session_route_gate(claim.session_key):
        pending = asyncio.create_task(admit(runner, manager, claim))
        await asyncio.sleep(0)
        assert not pending.done()
        runner.session_store.reset_session(claim.session_key)
    receipt = await pending
    assert receipt.state == "rejected"
    assert runner._native_plugin_queue().queued() == []


@pytest.mark.asyncio
async def test_cancellation_before_gate_has_no_candidate(tmp_path, monkeypatch):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    async with runner._session_route_gate(claim.session_key):
        pending = asyncio.create_task(admit(runner, manager, claim))
        await asyncio.sleep(0)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
    assert runner._native_plugin_queue().queued() == []


@pytest.mark.asyncio
async def test_public_typed_callback_publisher_and_late_readback(tmp_path, monkeypatch):
    from hermes_cli.plugins import PluginContext
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    runner._gateway_loop = asyncio.get_running_loop()
    runner._install_plugin_message_injector()
    # Test manager is intentionally standalone; attach the real published owner API.
    from hermes_cli.plugins_injection import attach_published_host_apis
    attach_published_host_apis(manager)
    context = PluginContext(manager._plugins["bee"].manifest, manager)
    try:
        receipt = await asyncio.to_thread(context.inject_message_admitted, "hello", surface="gateway",
            route_claim=claim, expected_session_id=claim.native_session_id, delivery_id="public")
        assert receipt.state == "unknown"
        assert runner._query_native_plugin_admission(manager=manager, route_claim=claim,
                                                     delivery_id="public", expected_content="hello") == receipt
    finally:
        runner._clear_plugin_message_injector()
        await asyncio.gather(runner._native_plugin_drain_task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["stop", "evict", "new", "resume"])
async def test_boundaries_revoke_queued_execution_but_keep_admission(tmp_path, monkeypatch, boundary):
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    receipt = await admit(runner, manager, claim)
    if boundary in ("stop", "evict"):
        await runner._invalidate_session_run_generation_async(claim.session_key, reason=boundary)
    elif boundary == "new":
        runner.session_store.reset_session(claim.session_key)
    else:
        runner.session_store.switch_session(claim.session_key, "resumed", route_claim_blocked=False)
    await runner._drain_native_plugin_candidates_once()
    adapter._start_session_processing.assert_not_called()
    assert runner._query_native_plugin_admission(manager=manager, route_claim=claim,
                                                delivery_id="delivery", expected_content="one") == receipt


@pytest.mark.asyncio
async def test_restart_status_of_old_epoch_with_new_host_owned_claim(tmp_path, monkeypatch):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    receipt = await admit(runner, manager, claim)
    runner.session_store.switch_session(claim.session_key, "B", route_claim_blocked=False)
    restarted, _, manager, current = host(tmp_path, monkeypatch)
    assert current.native_session_id == "B"
    assert restarted._query_native_plugin_admission(manager=manager, route_claim=current,
        delivery_id="delivery", route_epoch=claim.route_epoch,
        expected_session_id=claim.native_session_id, expected_content="one") == receipt
    assert restarted._query_native_plugin_admission(manager=manager, route_claim=claim,
        delivery_id="delivery", expected_content="one").state == "unknown"  # prior owner's proof has no authority


@pytest.mark.asyncio
async def test_timeout_then_late_commit_is_queryable_without_second_insertion(tmp_path, monkeypatch):
    from hermes_cli.plugins import PluginContext
    from hermes_cli import plugins_injection
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    runner._gateway_loop = asyncio.get_running_loop()
    manager.set_admission_host("gateway", runner, runner._admit_plugin_message, claim.host_owner_id)
    monkeypatch.setattr(plugins_injection, "_ADMISSION_WAIT_SECONDS", 0.02)
    context = PluginContext(manager._plugins["bee"].manifest, manager)
    async with runner._session_route_gate(claim.session_key):
        unknown = await asyncio.to_thread(context.inject_message_admitted, "late", surface="gateway",
            route_claim=claim, expected_session_id=claim.native_session_id, delivery_id="late")
        assert unknown.state == "unknown" and unknown.reason == "admission_timeout"
        assert runner._native_plugin_queue().queued() == []
    for _ in range(100):
        status = runner._query_native_plugin_admission(manager=manager, route_claim=claim, delivery_id="late", expected_content="late")
        if status.reason == "native_queue_pending":
            break
        await asyncio.sleep(0.01)
    assert status.state == "unknown"
    assert await admit(runner, manager, claim, "late", "late") == status
    adapter._start_session_processing.assert_not_called()


@pytest.mark.asyncio
async def test_gate_rechecks_grant_profile_and_slot_absence(tmp_path, monkeypatch):
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    (tmp_path / "config.yaml").write_text("plugins: {}\n")
    rejected = await admit(runner, manager, claim)
    assert rejected.state == "rejected"
    assert runner._native_plugin_queue().queued() == []
    (tmp_path / "config.yaml").write_text("plugins:\n  entries:\n    bee:\n      allow_gateway_injection: true\n")
    assert await admit(runner, manager, claim) == rejected
    assert runner._query_native_plugin_admission(manager=manager, route_claim=claim,
                                                delivery_id="delivery", expected_content="one") == rejected


@pytest.mark.asyncio
async def test_restarted_queued_candidate_enters_real_gateway_native_wrapper(tmp_path, monkeypatch):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    receipt = await admit(runner, manager, claim)
    assert receipt.state == "unknown"
    restarted, adapter, _, _ = host(tmp_path, monkeypatch)
    restarted._handle_message_admitted = AsyncMock(return_value=None)
    events = []
    def start(event, key):
        events.append(event)
        return True
    adapter._start_session_processing.side_effect = start
    await restarted._drain_native_plugin_candidates_once()
    assert len(events) == 1
    await restarted._handle_message(events[0])
    restarted._handle_message_admitted.assert_awaited_once_with(events[0])
    assert events[0].metadata["hermes_native_candidate_id"] == runner._native_plugin_queue().lookup(manager.scope_key, claim.route_epoch, "delivery")["candidate"]


@pytest.mark.asyncio
async def test_execution_cancelled_after_claim_never_replays(tmp_path, monkeypatch):
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    receipt = await admit(runner, manager, claim)
    assert receipt.state == "unknown" and receipt.candidate_id is None
    events = []
    adapter._start_session_processing.side_effect = lambda event, key: events.append(event) or True
    await runner._drain_native_plugin_candidates_once()
    runner._handle_message_admitted = AsyncMock(side_effect=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await runner._handle_message(events[0])
    await runner._handle_message(events[0])
    runner._handle_message_admitted.assert_awaited_once()
    restarted, adapter, manager, claim = host(tmp_path, monkeypatch)
    await restarted._drain_native_plugin_candidates_once()
    adapter._start_session_processing.assert_not_called()
    assert await admit(restarted, manager, claim) == receipt


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", [None, "slot", "turn_lease", "post_read_mutation", "observer_failure"])
async def test_real_runner_and_adapter_drain_two_durable_candidates(tmp_path, monkeypatch, missing):
    """Only the external model call is replaced; route, leases, history and adapter are real."""
    import gateway.run as gateway_run
    from gateway.platforms.base import BasePlatformAdapter, PlatformConfig, SendResult
    from hermes_cli.plugins import PluginContext
    from hermes_cli.trusted_inbound_broker import TrustedInboundBrokerClient

    class RecordingAdapter(BasePlatformAdapter):
        async def connect(self, **kwargs):
            return True
        async def disconnect(self):
            self._mark_disconnected()
        async def send(self, chat_id, content, **kwargs):
            return SendResult(success=True, message_id="response")
        async def send_typing(self, *args, **kwargs):
            return None
        async def get_chat_info(self, chat_id):
            return {"id": chat_id, "type": "dm"}

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "42")
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    (tmp_path / "config.yaml").write_text("plugins:\n  entries:\n    bee:\n      allow_gateway_injection: true\n")
    runner = GatewayRunner(GatewayConfig(multiplex_profiles=False, sessions_dir=tmp_path / "sessions"))
    observations = []
    original_observe = TrustedInboundBrokerClient.observe_native_turn
    def observe(client, snapshot):
        state = runner._peek_session_state(snapshot.session_key)
        assert state is not None
        assert runner._held_turn_lease(snapshot.session_key, state.persistent.run_generation) is not None
        observations.append(snapshot)
        row = runner._native_plugin_queue().lookup(manager.scope_key, snapshot.route_epoch,
                                                   snapshot.delivery_id)
        assert row["state"] == "admitted" and snapshot.native_event_id == row["native_event_id"]
        if missing == "observer_failure":
            raise OSError("broker unavailable")
        return original_observe(client, snapshot)
    monkeypatch.setattr(TrustedInboundBrokerClient, "observe_native_turn", observe)
    adapter = RecordingAdapter(PlatformConfig(enabled=True, token="test"), Platform.TELEGRAM)
    adapter.gateway_runner = runner
    adapter.set_message_handler(runner._handle_message)
    runner.adapters = {Platform.TELEGRAM: adapter}
    runner._running = True
    runner._gateway_loop = asyncio.get_running_loop()
    source = adapter.build_source(chat_id="42", user_id="42", chat_type="dm")
    entry = runner.session_store.get_or_create_session(source)
    claim = claim_for_route(runner, entry, source)
    manager = PluginManager(scope_key=hermes_home_key(tmp_path))
    manifest = PluginManifest(name="bee", key="bee", source="user")
    manager._plugins["bee"] = LoadedPlugin(manifest, enabled=True)
    manager.set_admission_host("gateway", runner, runner._admit_plugin_message, claim.host_owner_id)
    observed = []
    async def model(message, context_prompt, history, source, session_id, **kwargs):
        status = runner._query_native_plugin_admission(manager=manager, route_claim=claim,
            delivery_id="first" if message == "first native" else "second", expected_content=message)
        assert status.state == "admitted" and status.candidate_id
        observed.append((message, session_id))
        return {"final_response": "", "messages": [], "tools": [], "history_offset": len(history),
                "last_prompt_tokens": 0}
    runner._run_agent_inner = model
    if missing == "slot":
        runner._claim_active_session_slot = lambda *args: (None, None)
    elif missing == "turn_lease":
        runner._turn_leases.acquire = AsyncMock(return_value=None)
    elif missing == "post_read_mutation":
        queue = runner._native_plugin_queue()
        original_settle = queue.settle
        def mutate_then_settle(row):
            with queue._connection() as db:
                db.execute("UPDATE candidates SET session_key=? WHERE candidate=?",
                           ("forged-key", row["candidate"]))
            return original_settle(row)
        monkeypatch.setattr(queue, "settle", mutate_then_settle)
    first = await admit(runner, manager, claim, "first", "first native")
    second = await admit(runner, manager, claim, "second", "second native")
    assert first.state == second.state == "unknown"
    for _ in range(2):
        await runner._drain_native_plugin_candidates_once()
        await adapter._session_tasks[entry.session_key]
    if missing == "observer_failure":
        assert observed == []
        assert [item.delivery_id for item in observations] == ["first", "second"]
        assert (await admit(runner, manager, claim, "first", "first native")).state == "admitted"
        assert (await admit(runner, manager, claim, "second", "second native")).state == "admitted"
        assert runner._native_plugin_queue().queued() == []
        return
    if missing:
        assert observations == []
        assert observed == []
        assert (await admit(runner, manager, claim, "first", "first native")).state == "unknown"
        assert len(runner._native_plugin_queue().queued()) == 0
        return
    assert observed == [("first native", entry.session_id), ("second native", entry.session_id)]
    assert [item.delivery_id for item in observations] == ["first", "second"]
    assert all(original_observe(TrustedInboundBrokerClient(), item).state == "unknown"
               for item in observations)
    assert (await admit(runner, manager, claim, "first", "first native")).state == "admitted"
    await runner._drain_native_plugin_candidates_once()
    assert len(observed) == 2
    restarted, _, restarted_manager, restarted_claim = host(tmp_path, monkeypatch)
    assert restarted._query_native_plugin_admission(manager=restarted_manager, route_claim=restarted_claim,
        delivery_id="first", expected_content="first native").state == "admitted"
    assert restarted._query_native_plugin_admission(manager=restarted_manager, route_claim=restarted_claim,
        delivery_id="first", expected_content="wrong").state == "unknown"


def test_process_dies_after_commit_receipt_and_candidate_survive(tmp_path):
    import subprocess
    import sys
    import sqlite3
    from gateway.native_plugin_queue import NativePluginQueue
    child = '''
import os, sys
from pathlib import Path
from gateway.native_plugin_queue import NativePluginQueue
queue = NativePluginQueue(Path(sys.argv[1]))
queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
            native_id="native", owner="owner", plugin="bee", content="durable prompt")
os._exit(23)
'''
    result = subprocess.run([sys.executable, "-c", child, str(tmp_path)], timeout=10, check=False)
    assert result.returncode == 23
    queue = NativePluginQueue(tmp_path)
    row = queue.lookup("profile", "epoch", "delivery")
    assert row["content"] == "durable prompt" and row["execution"] == "queued"
    retry = queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                        native_id="native", owner="new-owner", plugin="bee", content="durable prompt")
    assert retry["candidate"] == row["candidate"]
    with sqlite3.connect(queue.path) as db:
        assert db.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 1


@pytest.mark.asyncio
async def test_replaced_publisher_cannot_commit_old_owner_request(tmp_path, monkeypatch):
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    async with runner._session_route_gate(claim.session_key):
        pending = asyncio.create_task(admit(runner, manager, claim))
        await asyncio.sleep(0)
        manager.set_admission_host("gateway", object(), lambda **kw: None, "replacement-owner")
    receipt = await pending
    assert receipt.state == "rejected" and receipt.reason == "admission_host_replaced"
    assert runner._native_plugin_queue().queued() == []


@pytest.mark.asyncio
async def test_slot_rejection_after_durable_admission_never_merges_or_reinserts(tmp_path, monkeypatch):
    runner, adapter, manager, claim = host(tmp_path, monkeypatch)
    receipt = await admit(runner, manager, claim)
    assert receipt.state == "unknown" and receipt.candidate_id is None
    events = []
    adapter._start_session_processing.side_effect = lambda event, key: events.append(event) or True
    await runner._drain_native_plugin_candidates_once()
    event = events[0]
    runner._hm_admit_event = AsyncMock(return_value=(event, event.source, True))
    runner._hm_estop_gate = lambda *args: None
    runner._session_key_for_source = lambda source: claim.session_key
    runner._hm_pending_reply_intercepts = AsyncMock(return_value=None)
    runner._hm_evict_idle_stale_agent = AsyncMock()
    runner._hm_dispatch_idle_commands = AsyncMock(return_value=(False, None))
    runner._claim_active_session_slot = lambda *args: (None, "slot full")
    runner._hm_handle_running_session_message = AsyncMock()
    assert await runner._handle_message(event) == "slot full"
    runner._hm_handle_running_session_message.assert_not_awaited()
    assert await admit(runner, manager, claim) == receipt
    await runner._drain_native_plugin_candidates_once()
    assert len(events) == 1


def test_simultaneous_sqlite_writers_create_one_candidate(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from gateway.native_plugin_queue import NativePluginQueue
    queues = [NativePluginQueue(tmp_path) for _ in range(4)]
    def put(queue):
        return queue.admit(profile="p", epoch="e", delivery="d", session_key="k", native_id="n",
                           owner="o", plugin="bee", content="one")
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(put, queues))
    assert len({row["candidate"] for row in rows}) == 1
    assert len(queues[0].queued()) == 1


@pytest.mark.asyncio
async def test_same_id_different_payload_returns_conflict_without_second_candidate(tmp_path, monkeypatch):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    first = await admit(runner, manager, claim, content="approved body")
    conflict = await admit(runner, manager, claim, content="different body")
    assert conflict.state == "unknown" and conflict.reason == "native_delivery_conflict"
    assert conflict.candidate_id is None
    assert runner._query_native_plugin_admission(manager=manager, route_claim=claim,
        delivery_id="delivery", expected_content="different body").state == "unknown"
    assert runner._query_native_plugin_admission(manager=manager, route_claim=claim,
        delivery_id="delivery", expected_content="approved body") == first
    assert runner._native_plugin_queue().queued()[0]["content"] == "approved body"


def test_sqlite_racing_payload_conflict_cannot_reuse_positive_receipt(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from gateway.native_plugin_queue import NativePluginQueue
    queue = NativePluginQueue(tmp_path)
    def put(body):
        return queue.admit(profile="p", epoch="e", delivery="d", session_key="k", native_id="n",
                           owner="o", plugin="bee", content=body)
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(put, ["one", "two"]))
    assert sorted(row["state"] for row in rows) == ["unknown", "unknown"]
    assert next(row for row in rows if row["reason"] == "native_delivery_conflict")["candidate"] is None
    assert len(queue.queued()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["native_session_id", "session_key"])
async def test_same_delivery_wrong_native_or_key_never_reuses_admitted_receipt(tmp_path, monkeypatch, field):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    first = await admit(runner, manager, claim)
    conflict = await admit(runner, manager, replace(claim, **{field: "other"}))
    assert conflict.state == "unknown" and conflict.reason == "native_delivery_conflict"
    assert conflict.candidate_id is None
    assert runner._query_native_plugin_admission(manager=manager, route_claim=claim,
        delivery_id="delivery", expected_session_id="other", expected_content="one").state == "unknown"
    assert runner._query_native_plugin_admission(manager=manager, route_claim=claim,
        delivery_id="delivery", expected_content="one") == first


@pytest.mark.asyncio
async def test_busy_page_does_not_starve_idle_route(tmp_path, monkeypatch):
    runner, adapter, manager, _ = host(tmp_path, monkeypatch)
    for i in range(101):
        source = SessionSource(platform=Platform.TELEGRAM, chat_id=str(1000+i), user_id="42")
        entry = runner.session_store.get_or_create_session(source)
        claim = claim_for_route(runner, entry, source)
        await admit(runner, manager, claim, str(i))
        if i < 100:
            adapter._active_sessions[entry.session_key] = asyncio.Event()
    await runner._drain_native_plugin_candidates_once()
    await runner._drain_native_plugin_candidates_once()
    adapter._start_session_processing.assert_called_once()
    assert adapter._start_session_processing.call_args.args[1] == entry.session_key


@pytest.mark.asyncio
async def test_status_requires_payload_binding(tmp_path, monkeypatch):
    runner, _, manager, claim = host(tmp_path, monkeypatch)
    await admit(runner, manager, claim)
    with pytest.raises(TypeError):
        runner._query_native_plugin_admission(manager=manager, route_claim=claim, delivery_id="delivery")


@pytest.mark.asyncio
async def test_busy_route_gets_next_cycle_despite_sustained_new_arrivals(tmp_path, monkeypatch):
    runner, adapter, manager, target = host(tmp_path, monkeypatch)
    await admit(runner, manager, target, "target")
    adapter._active_sessions[target.session_key] = asyncio.Event()

    async def arrival(index, busy=False):
        source = SessionSource(platform=Platform.TELEGRAM, chat_id=str(2000 + index), user_id="42")
        entry = runner.session_store.get_or_create_session(source)
        claim = claim_for_route(runner, entry, source)
        await admit(runner, manager, claim, str(index))
        if busy:
            adapter._active_sessions[entry.session_key] = asyncio.Event()

    # One cycle needs two pages; new routes must not extend that cycle forever.
    for index in range(100):
        await arrival(index, busy=True)
    await runner._drain_native_plugin_candidates_once()
    adapter._start_session_processing.assert_not_called()
    adapter._active_sessions.pop(target.session_key)
    first_target_poll = None
    for poll in range(8):
        await arrival(100 + poll)
        await runner._drain_native_plugin_candidates_once()
        keys = [call.args[1] for call in adapter._start_session_processing.call_args_list]
        if target.session_key in keys and first_target_poll is None:
            first_target_poll = poll
    assert first_target_poll is not None and first_target_poll <= 1
    assert keys.count(target.session_key) == 1
    row = runner._native_plugin_queue().lookup(manager.scope_key, target.route_epoch, "target")
    assert row["execution"] == "dispatching"
    assert row["state"] == "unknown"  # Scheduling still cannot prove slot/turn admission.
