"""Tests for plugin-triggered turns in existing gateway sessions."""

import asyncio
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from gateway.config import GatewayConfig, Platform
from gateway.platforms.base import (
    BasePlatformAdapter,
    PlatformConfig,
)
from gateway.platforms.event import MessageEvent, MessageType
from gateway.run import GatewayRunner
from gateway.session import SessionEntry, SessionSource, SessionStore, build_session_key
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest


def _entry(*, origin=True) -> SessionEntry:
    source = None
    if origin:
        source = SessionSource(
            platform=Platform.TELEGRAM,
            chat_id="42",
            chat_type="dm",
            user_id="42",
            user_name="tester",
        )
    now = datetime.now()
    return SessionEntry(
        session_key="agent:main:telegram:dm:42",
        session_id="session-42",
        created_at=now,
        updated_at=now,
        origin=source,
        platform=Platform.TELEGRAM,
    )


def _runner(entry: SessionEntry | None, adapter=None) -> GatewayRunner:
    runner = object.__new__(GatewayRunner)
    runner.session_store = SimpleNamespace()
    runner._async_session_store = SimpleNamespace(
        _store=runner.session_store, lookup_by_session_key=AsyncMock(return_value=entry)
    )
    runner.adapters = {Platform.TELEGRAM: adapter} if adapter else {}
    runner._profile_adapters = {}
    runner._running = True
    runner._draining = False
    runner._background_tasks = set()
    runner._is_user_authorized = MagicMock(return_value=True)
    return runner


class _RoutingAdapter(BasePlatformAdapter):
    def __init__(self):
        super().__init__(PlatformConfig(enabled=True, token="test"), Platform.TELEGRAM)

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        return True

    async def disconnect(self) -> None:
        self._mark_disconnected()

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        raise AssertionError("network send is not expected")

    async def get_chat_info(self, chat_id):
        return {"id": chat_id, "type": "dm"}


@pytest.mark.asyncio
@pytest.mark.parametrize("pinned", [False, True])
async def test_plugin_context_routes_through_live_gateway_to_existing_session(
    tmp_path,
    monkeypatch,
    pinned,
):
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir()
    (hermes_home / "config.yaml").write_text(
        yaml.safe_dump({
            "plugins": {"entries": {"notify-plugin": {"allow_gateway_injection": True}}}
        })
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    store = SessionStore(sessions_dir=tmp_path / "sessions", config=GatewayConfig())
    source = _entry().origin
    entry = store.get_or_create_session(source)
    adapter = _RoutingAdapter()
    adapter.set_message_handler(AsyncMock())
    adapter._active_sessions[entry.session_key] = asyncio.Event()
    pending_user_event = MessageEvent(
        text="human follow-up",
        message_type=MessageType.PHOTO,
        source=source,
        media_urls=["human.jpg"],
        media_types=["image/jpeg"],
    )
    adapter._pending_messages[entry.session_key] = pending_user_event

    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner.adapters = {Platform.TELEGRAM: adapter}
    runner._profile_adapters = {}
    runner._gateway_loop = asyncio.get_running_loop()
    runner._running = True
    runner._draining = False
    runner._background_tasks = set()
    runner._queued_events = {}
    runner._is_user_authorized = MagicMock(return_value=True)
    adapter.set_busy_session_handler(runner._handle_active_session_busy_message)

    manager = PluginManager()
    context = PluginContext(
        PluginManifest(name="notify-plugin", key="notify-plugin", source="user"),
        manager,
    )

    with patch("hermes_cli.plugins.get_plugin_manager", return_value=manager):
        runner._install_plugin_message_injector()
        assert (
            context.inject_message(
                "/approve always",
                session_key=entry.session_key,
                **({"expected_session_id": entry.session_id} if pinned else {}),
            )
            is True
        )
        task = next(iter(runner._background_tasks))
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0)

        assert adapter._pending_messages[entry.session_key] is pending_user_event
        queued = runner._queued_events[entry.session_key][0]
        assert pending_user_event.text == "human follow-up"
        assert pending_user_event.media_urls == ["human.jpg"]
        assert pending_user_event.allow_gateway_control is True
        assert queued.text == "/approve always"
        assert queued.allow_gateway_control is False
        assert queued.metadata["gateway_session_id"] == entry.session_id
        adapter._message_handler.assert_not_awaited()

        runner._clear_plugin_message_injector()
        assert manager.has_gateway_message_injector is False


@pytest.mark.asyncio
async def test_dispatch_uses_stored_origin_and_adapter_message_path():
    adapter = SimpleNamespace(handle_message=AsyncMock())
    entry = _entry()
    runner = _runner(entry, adapter)

    accepted = await runner._dispatch_plugin_message_injection(
        session_key=entry.session_key,
        content="check the deployment",
        plugin_id="notify-plugin",
    )

    assert accepted is True
    adapter.handle_message.assert_awaited_once()
    event = adapter.handle_message.await_args.args[0]
    assert event.text == "check the deployment"
    assert event.internal is True
    assert event.allow_gateway_control is False
    assert event.get_command() is None
    assert event.source == entry.origin
    assert event.source is not entry.origin
    runner._is_user_authorized.assert_called_once_with(
        event.source,
        allow_adapter_delegation=False,
    )
    assert event.metadata == {
        "hermes_plugin_id": "notify-plugin",
        "hermes_plugin_injection": True,
        "gateway_session_key": entry.session_key,
        "gateway_session_id": entry.session_id,
        "gateway_session_strict": True,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entry", "with_adapter"),
    [
        (None, True),
        (_entry(origin=False), True),
        (_entry(), False),
    ],
)
async def test_dispatch_rejects_unroutable_session(entry, with_adapter):
    adapter = SimpleNamespace(handle_message=AsyncMock())
    runner = _runner(entry, adapter if with_adapter else None)

    accepted = await runner._dispatch_plugin_message_injection(
        session_key="agent:main:telegram:dm:42",
        content="wake up",
        plugin_id="notify-plugin",
    )

    assert accepted is False
    adapter.handle_message.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("raises", [False, True])
async def test_dispatch_rechecks_current_authorization(raises):
    adapter = SimpleNamespace(handle_message=AsyncMock())
    runner = _runner(_entry(), adapter)
    if raises:
        runner._is_user_authorized.side_effect = RuntimeError("config unavailable")
    else:
        runner._is_user_authorized.return_value = False

    accepted = await runner._dispatch_plugin_message_injection(
        session_key="agent:main:telegram:dm:42",
        content="wake up",
        plugin_id="notify-plugin",
    )

    assert accepted is False
    adapter.handle_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatch_rejects_stored_role_only_authorization(monkeypatch):
    """A stored adapter role grant must be revalidated against current core auth."""
    for key in (
        "DISCORD_ALLOWED_USERS",
        "DISCORD_ALLOW_ALL_USERS",
        "GATEWAY_ALLOWED_USERS",
        "GATEWAY_ALLOW_ALL_USERS",
    ):
        monkeypatch.delenv(key, raising=False)

    adapter = MagicMock(spec=BasePlatformAdapter)
    adapter.handle_message = AsyncMock()
    entry = _entry()
    entry.session_key = "agent:main:discord:dm:42"
    entry.platform = Platform.DISCORD
    source = entry.origin
    assert source is not None
    source.platform = Platform.DISCORD
    source.role_authorized = True

    runner = _runner(entry)
    runner.adapters = {Platform.DISCORD: adapter}
    runner.config = GatewayConfig()
    runner.pairing_store = MagicMock()
    runner.pairing_store.is_approved.return_value = False
    del runner._is_user_authorized

    accepted = await runner._dispatch_plugin_message_injection(
        session_key=entry.session_key,
        content="wake up",
        plugin_id="notify-plugin",
    )

    assert accepted is False
    adapter.handle_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatch_stops_when_gateway_drains_during_lookup():
    adapter = SimpleNamespace(handle_message=AsyncMock())
    runner = _runner(_entry(), adapter)
    lookup_started = asyncio.Event()
    release_lookup = asyncio.Event()

    async def _lookup(_session_key):
        lookup_started.set()
        await release_lookup.wait()
        return _entry()

    runner._async_session_store.lookup_by_session_key = _lookup
    dispatch = asyncio.create_task(
        runner._dispatch_plugin_message_injection(
            session_key="agent:main:telegram:dm:42",
            content="wake up",
            plugin_id="notify-plugin",
        )
    )

    await lookup_started.wait()
    runner._draining = True
    release_lookup.set()

    assert await dispatch is False
    adapter.handle_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_base_adapter_queues_non_control_plugin_text_for_exact_session():
    adapter = _RoutingAdapter()
    adapter.set_message_handler(AsyncMock())
    source = _entry().origin
    session_key = build_session_key(source)
    adapter._active_sessions[session_key] = asyncio.Event()
    event = MessageEvent(
        text="/approve always",
        message_type=MessageType.TEXT,
        source=source,
        internal=True,
        allow_gateway_control=False,
        metadata={"gateway_session_key": session_key},
    )

    await adapter.handle_message(event)

    adapter._message_handler.assert_not_awaited()
    assert adapter._pending_messages[session_key] is event
    assert adapter._active_sessions[session_key].is_set() is False


@pytest.mark.asyncio
async def test_base_adapter_rejects_derived_session_mismatch():
    adapter = _RoutingAdapter()
    adapter.set_message_handler(AsyncMock())
    event = MessageEvent(
        text="ordinary input",
        source=_entry().origin,
        internal=True,
        allow_gateway_control=False,
        metadata={"gateway_session_key": "agent:main:telegram:dm:other"},
    )

    await adapter.handle_message(event)

    adapter._message_handler.assert_not_awaited()
    assert adapter._active_sessions == {}






@pytest.mark.asyncio
async def test_scheduler_logs_async_failure_without_callback_error():
    runner = _runner(_entry())
    loop = asyncio.get_running_loop()
    runner._gateway_loop = loop
    callback_errors = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: callback_errors.append(context))
    runner._dispatch_plugin_message_injection = AsyncMock(
        side_effect=RuntimeError("adapter failed")
    )

    try:
        assert (
            runner._schedule_plugin_message_injection(
                session_key="key",
                content="wake up",
                plugin_id="notify-plugin",
            )
            is True
        )
        task = next(iter(runner._background_tasks))
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous_handler)

    assert callback_errors == []






def test_scheduler_rejects_stopped_or_closed_gateway():
    runner = _runner(_entry())
    loop = MagicMock()
    loop.is_closed.return_value = False
    runner._gateway_loop = loop
    runner._running = False

    assert (
        runner._schedule_plugin_message_injection(
            session_key="key",
            content="wake up",
            plugin_id="notify-plugin",
        )
        is False
    )
    loop.call_soon_threadsafe.assert_not_called()

    runner._running = True
    runner._gateway_loop = None
    assert (
        runner._schedule_plugin_message_injection(
            session_key="key",
            content="wake up",
            plugin_id="notify-plugin",
        )
        is False
    )

    runner._gateway_loop = loop
    loop.is_closed.return_value = True
    assert (
        runner._schedule_plugin_message_injection(
            session_key="key",
            content="wake up",
            plugin_id="notify-plugin",
        )
        is False
    )
    loop.call_soon_threadsafe.assert_not_called()


def test_scheduler_rejects_submission_failure():
    runner = _runner(_entry())
    loop = MagicMock()
    loop.is_closed.return_value = False
    runner._gateway_loop = loop

    def _reject(coro, _target_loop, **_kwargs):
        coro.close()
        return None

    with patch("gateway.run.safe_schedule_threadsafe", side_effect=_reject):
        assert (
            runner._schedule_plugin_message_injection(
                session_key="key",
                content="wake up",
                plugin_id="notify-plugin",
            )
            is False
        )


def test_install_and_clear_gateway_injector_preserves_newer_owner():
    runner = _runner(_entry())
    manager = PluginManager()

    with patch("hermes_cli.plugins.get_plugin_manager", return_value=manager):
        runner._install_plugin_message_injector()
        assert manager.has_gateway_message_injector is True

        runner._clear_plugin_message_injector()
        assert manager.has_gateway_message_injector is False

        runner._install_plugin_message_injector()

        newer_owner = MagicMock()
        newer_injector = MagicMock(return_value=True)
        manager.set_gateway_message_injector(newer_owner, newer_injector)
        runner._clear_plugin_message_injector()

    assert manager.has_gateway_message_injector is True
    assert manager.inject_gateway_message(value="kept") is True
    newer_injector.assert_called_once_with(value="kept")


@pytest.mark.asyncio
@pytest.mark.parametrize("rotation", [None, "new", "compression", "missing", "empty"])
async def test_pinned_scheduler_checks_current_session(tmp_path, rotation):
    store = SessionStore(sessions_dir=tmp_path / "sessions", config=GatewayConfig())
    entry = store.get_or_create_session(_entry().origin)
    expected = entry.session_id
    if rotation == "new":
        store.reset_session(entry.session_key)
    elif rotation == "compression":
        entry.session_id = "compressed-native-id"
    elif rotation == "missing":
        expected = "unknown-native-id"
    elif rotation == "empty":
        expected = ""
    adapter = SimpleNamespace(handle_message=AsyncMock())
    runner = _runner(entry, adapter)
    runner.session_store = store
    del runner._async_session_store
    runner._gateway_loop = asyncio.get_running_loop()

    accepted = runner._schedule_plugin_message_injection(
        session_key=entry.session_key, content="wake", plugin_id="notify-plugin",
        expected_session_id=expected,
    )
    assert accepted is (rotation is None)
    if accepted:
        await asyncio.gather(*runner._background_tasks)
        event = adapter.handle_message.await_args.args[0]
        assert event.metadata["gateway_session_id"] == expected
        assert event.metadata["gateway_session_strict"] is True
    else:
        assert not runner._background_tasks
        adapter.handle_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_pinned_dispatch_rejects_rotation_after_scheduling(tmp_path):
    store = SessionStore(sessions_dir=tmp_path / "sessions", config=GatewayConfig())
    entry = store.get_or_create_session(_entry().origin)
    expected = entry.session_id
    adapter = SimpleNamespace(handle_message=AsyncMock())
    runner = _runner(entry, adapter)
    runner.session_store = store
    del runner._async_session_store
    runner._gateway_loop = asyncio.get_running_loop()

    assert runner._schedule_plugin_message_injection(
        session_key=entry.session_key, content="wake", plugin_id="notify-plugin",
        expected_session_id=expected,
    ) is True
    tasks = list(runner._background_tasks)
    entry.session_id = "replacement-id"
    assert await asyncio.gather(*tasks) == [False]
    adapter.handle_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_pinned_dispatch_rechecks_before_adapter():
    entry = _entry()
    adapter = SimpleNamespace(handle_message=AsyncMock())
    runner = _runner(entry, adapter)
    runner.session_store.peek_session_id = MagicMock(return_value="replacement-id")

    assert await runner._dispatch_plugin_message_injection(
        session_key=entry.session_key, content="wake", plugin_id="notify-plugin",
        expected_session_id=entry.session_id,
    ) is False
    adapter.handle_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_strict_handler_drops_injection_rotated_after_adapter_queue():
    entry = _entry()
    runner = _runner(entry)
    runner._recover_telegram_topic_thread_id = MagicMock(return_value=None)
    runner._session_key_for_source = MagicMock(return_value=entry.session_key)
    runner._cache_session_source = MagicMock(side_effect=AssertionError("stale turn started"))
    event = MessageEvent(
        text="wake", source=entry.origin, internal=True, allow_gateway_control=False,
        metadata={"gateway_session_key": entry.session_key,
                  "gateway_session_id": "old-native-id", "gateway_session_strict": True},
    )

    await runner._handle_message_with_agent(event, entry.origin, entry.session_key, 1)
    runner._cache_session_source.assert_not_called()


def test_bound_session_key_never_uses_ambient_environment(monkeypatch):
    from contextvars import Context
    from gateway.session_context import (
        clear_session_vars, get_bound_session_key, reset_session_vars, set_session_vars,
    )
    monkeypatch.setenv("HERMES_SESSION_KEY", "ambient-route")

    def check():
        assert get_bound_session_key() is None
        tokens = set_session_vars(session_key="task-route")
        assert get_bound_session_key() == "task-route"
        clear_session_vars(tokens)
        assert get_bound_session_key() is None
        reset_session_vars()
        assert get_bound_session_key() is None

    Context().run(check)


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["topic", "session_hook", "history", "prepare", "agent_hook"])
@pytest.mark.parametrize("rotation", ["reset", "compression", "generation", "none"])
async def test_strict_turn_rechecks_after_await(tmp_path, boundary, rotation):
    """Rotate at a deterministic await boundary, before any model invocation."""
    from threading import Event

    store = SessionStore(sessions_dir=tmp_path / "sessions", config=GatewayConfig())
    entry = store.get_or_create_session(_entry().origin)
    original_id = entry.session_id
    runner = _runner(entry)
    runner.session_store = store
    del runner._async_session_store
    runner.config = GatewayConfig()
    runner._recover_telegram_topic_thread_id = MagicMock(return_value=None)
    runner._session_key_for_source = MagicMock(return_value=entry.session_key)
    runner._cache_session_source = MagicMock()
    runner._is_telegram_topic_lane = MagicMock(return_value=False)
    runner._is_session_run_current = MagicMock(return_value=True)
    runner._set_session_env = MagicMock(return_value=["test-token"])
    runner._clear_session_env = MagicMock()
    runner._pinned_session_context_prompt = MagicMock(return_value="")
    runner._mark_durable_active_turn = AsyncMock()
    runner._voice_channel_sidecar_note = MagicMock(return_value=None)
    runner._prepare_profile_scoped_inbound_message_text = AsyncMock(return_value="wake")
    runner._bind_adapter_run_generation = MagicMock()
    class AgentReached(BaseException):
        pass

    runner._run_agent = AsyncMock(side_effect=AgentReached)
    runner.hooks = SimpleNamespace(emit=AsyncMock())
    runner.async_session_store.load_transcript = AsyncMock(
        return_value=[{"role": "user", "content": "prior"}]
    )
    event = MessageEvent(
        text="wake", source=entry.origin, internal=True, allow_gateway_control=False,
        metadata={"gateway_session_key": entry.session_key,
                  "gateway_session_id": original_id, "gateway_session_strict": True},
    )
    entered = asyncio.Event()
    release = asyncio.Event()
    thread_entered = Event()
    thread_release = Event()

    async def pause(result=None):
        entered.set()
        await release.wait()
        return result

    if boundary == "topic":
        def topic_probe(source):
            thread_entered.set()
            assert thread_release.wait(5)
            return False
        runner._is_telegram_topic_lane.side_effect = topic_probe
    elif boundary == "history":
        async def history(*_):
            return await pause([{"role": "user", "content": "prior"}])
        runner.async_session_store.load_transcript.side_effect = history
    elif boundary == "prepare":
        async def prepare(**_):
            return await pause("wake")
        runner._prepare_profile_scoped_inbound_message_text.side_effect = prepare
    else:
        async def hook(name, payload):
            if name == ("session:start" if boundary == "session_hook" else "agent:start"):
                await pause()
        runner.hooks.emit.side_effect = hook

    with patch("gateway.run._load_gateway_config", return_value={}):
        task = asyncio.create_task(runner._handle_message_with_agent(
            event, entry.origin, entry.session_key, 1
        ))
        try:
            if boundary == "topic":
                assert await asyncio.to_thread(thread_entered.wait, 5)
            else:
                await asyncio.wait_for(entered.wait(), 5)
            if rotation == "reset":
                store.reset_session(entry.session_key)
            elif rotation == "compression":
                entry.session_id = "compressed-id"
            elif rotation == "generation":
                runner._is_session_run_current.return_value = False
            thread_release.set()
            release.set()
            if rotation == "none":
                with pytest.raises(AgentReached):
                    await asyncio.wait_for(task, 5)
            else:
                assert await asyncio.wait_for(task, 5) is None
        finally:
            thread_release.set()
            release.set()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    if rotation == "none":
        runner._run_agent.assert_awaited_once()
        assert runner._run_agent.await_args.kwargs["session_id"] == original_id
        return
    runner._run_agent.assert_not_awaited()
    if boundary == "topic":
        runner.hooks.emit.assert_not_awaited()
    elif boundary == "session_hook":
        runner._set_session_env.assert_not_called()
    else:
        runner._clear_session_env.assert_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["settings", "plan"])
async def test_strict_hygiene_drops_rotation_during_preflight(tmp_path, boundary):
    store = SessionStore(sessions_dir=tmp_path / "sessions", config=GatewayConfig())
    entry = store.get_or_create_session(_entry().origin)
    runner = _runner(entry)
    runner.session_store = store
    runner._is_session_run_current = MagicMock(return_value=True)
    event = MessageEvent(
        text="wake", source=entry.origin, internal=True,
        metadata={"gateway_session_key": entry.session_key,
                  "gateway_session_id": entry.session_id, "gateway_session_strict": True},
    )
    settings = SimpleNamespace(compression_enabled=True)
    plan = SimpleNamespace(needs_compress=True)
    entered, release = asyncio.Event(), asyncio.Event()

    async def suspended(*args):
        entered.set()
        await release.wait()
        return settings if boundary == "settings" else plan

    runner._hmwa_hygiene_settings = AsyncMock(return_value=settings)
    runner._hmwa_hygiene_plan = AsyncMock(return_value=plan)
    getattr(runner, "_hmwa_hygiene_" + boundary).side_effect = suspended
    runner._resolve_session_agent_runtime = MagicMock(side_effect=AssertionError("stale compression started"))
    runner._bound_hygiene_payload = MagicMock(side_effect=AssertionError("stale history bounded"))
    history = [{"role": "user", "content": "prior"}] * 4
    task = asyncio.create_task(runner._hmwa_run_session_hygiene(
        event, entry.origin, entry, entry.session_key, history, entry.session_key, 1,
    ))
    await asyncio.wait_for(entered.wait(), 5)
    store.reset_session(entry.session_key)
    release.set()
    assert await asyncio.wait_for(task, 5) is history
    runner._resolve_session_agent_runtime.assert_not_called()
    if boundary == "settings":
        runner._hmwa_hygiene_plan.assert_not_awaited()


@pytest.mark.asyncio
async def test_strict_hygiene_rechecks_after_build_before_compressor(tmp_path):
    store = SessionStore(sessions_dir=tmp_path / "sessions", config=GatewayConfig())
    entry = store.get_or_create_session(_entry().origin)
    runner = _runner(entry)
    runner.session_store = store
    runner._is_session_run_current = MagicMock(return_value=True)
    event = MessageEvent(
        text="wake", source=entry.origin, internal=True,
        metadata={"gateway_session_key": entry.session_key,
                  "gateway_session_id": entry.session_id, "gateway_session_strict": True},
    )
    entered, release = asyncio.Event(), asyncio.Event()
    agent = object()  # Any attempt to configure or run this compressor fails.

    async def build(*args):
        entered.set()
        await release.wait()
        return agent, None

    runner._hmwa_hygiene_build_agent = AsyncMock(side_effect=build)
    runner._evict_cached_agent = MagicMock()
    runner._cleanup_agent_resources_off_loop = AsyncMock()
    attempt = SimpleNamespace(agent=None, cleanup_deferred=False)
    task = asyncio.create_task(runner._hmwa_hygiene_detached_attempt(
        attempt, None, None, [], [], None, {}, entry.origin, entry,
        entry.session_key, entry.session_key, 1, strict_event=event,
    ))
    await asyncio.wait_for(entered.wait(), 5)
    store.reset_session(entry.session_key)
    release.set()
    assert await asyncio.wait_for(task, 5) is None
    runner._cleanup_agent_resources_off_loop.assert_awaited_once_with(agent, context="session hygiene")
