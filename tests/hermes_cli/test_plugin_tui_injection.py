"""The real PluginManager exposes a separately granted, host-owned TUI ingress."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import hermes_yaml as yaml

from hermes_cli.plugins import LoadedPlugin, PluginContext, PluginManager, PluginManifest
from hermes_cli.plugins_loader import _plugin_home_scope


def _pair(home, entry: dict | None = None):
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(yaml.safe_dump({
        "plugins": {"enabled": ["notify-plugin"], "entries": {"notify-plugin": entry or {}}},
    }), encoding="utf-8")
    manager = PluginManager(scope_key=str(home.resolve()))
    manifest = PluginManifest(name="notify-plugin", key="notify-plugin", source="user")
    manager._plugins["notify-plugin"] = LoadedPlugin(manifest, enabled=True)
    return PluginContext(manifest, manager), manager


def _defer_hook_workers(monkeypatch):
    deferred = []

    class DeferredThread:
        def __init__(self, *, target, name, daemon):
            deferred.append(target)

        def start(self):
            pass

    monkeypatch.setattr("hermes_cli.plugins_dispatch.threading.Thread", DeferredThread)
    return deferred


def test_tui_callback_has_owner_pinned_lifecycle(tmp_path):
    _context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    first_owner, second_owner = object(), object()
    first, second = Mock(return_value=True), Mock(return_value=True)

    assert manager.has_tui_message_injector is False
    manager.set_tui_message_injector(first_owner, first)
    assert manager.has_tui_message_injector is True
    manager.set_tui_message_injector(second_owner, second)
    manager.clear_tui_message_injector(first_owner)
    assert manager.inject_tui_message(
        session_key="route", expected_session_id="native", content="wake", plugin_id="notify-plugin",
    ) is True
    first.assert_not_called()
    second.assert_called_once()
    manager.clear_tui_message_injector(second_owner)
    assert manager.has_tui_message_injector is False


def test_tui_context_requires_exact_route_and_receipt(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    callback = Mock(return_value=True)
    manager.set_tui_message_injector(object(), callback)

    assert context.inject_message(
        "wake", role="system", surface="tui", session_key="route", expected_session_id="native",
    ) is True
    callback.assert_called_once_with(
        session_key="route", expected_session_id="native", content="[system] wake",
        plugin_id="notify-plugin",
    )
    callback.reset_mock()
    for kwargs in (
        {"session_key": "", "expected_session_id": "native"},
        {"session_key": "route", "expected_session_id": None},
        {"session_key": "route", "expected_session_id": " "},
    ):
        assert context.inject_message("wake", surface="tui", **kwargs) is False
    assert context.inject_message(" ", surface="tui", session_key="route", expected_session_id="native") is False
    assert context.inject_message("wake", surface="web", session_key="route", expected_session_id="native") is False
    callback.assert_not_called()


def test_explicit_tui_surface_bypasses_cli_queue_without_gateway_fallback(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    cli_queue = Mock()
    manager._cli_ref = SimpleNamespace(_agent_running=False, _pending_input=cli_queue)
    callback = Mock(return_value=True)
    manager.set_tui_message_injector(object(), callback)

    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native",
    ) is True
    callback.assert_called_once()
    cli_queue.put.assert_not_called()


def test_explicit_gateway_surface_preserves_gateway_grant_with_cli_present(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_gateway_injection": True})
    cli_queue = Mock()
    manager._cli_ref = SimpleNamespace(_agent_running=False, _pending_input=cli_queue)
    gateway = Mock(return_value=True)
    manager.set_gateway_message_injector(object(), gateway)

    assert context.inject_message("wake", surface="gateway", session_key="route") is True
    gateway.assert_called_once()
    cli_queue.put.assert_not_called()


@pytest.mark.parametrize("tui_grant,tui_receipt", [(False, True), (True, False)])
def test_explicit_tui_denial_never_falls_through_to_gateway(tmp_path, tui_grant, tui_receipt):
    context, manager = _pair(
        tmp_path / "home",
        {"allow_gateway_injection": True, "allow_tui_injection": tui_grant},
    )
    tui = Mock(return_value=tui_receipt)
    gateway = Mock(return_value=True)
    manager.set_tui_message_injector(object(), tui)
    manager.set_gateway_message_injector(object(), gateway)

    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native",
    ) is False
    gateway.assert_not_called()
    if not tui_grant:
        tui.assert_not_called()


def test_tui_route_claim_is_forwarded_without_rewriting_identity(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    host = Mock(return_value=True)
    manager.set_tui_message_injector(object(), host)
    claim = {"epoch": "e-2", "native": "native", "profile": "p"}

    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native",
        route_claim=claim,
    ) is True
    host.assert_called_once_with(
        session_key="route", expected_session_id="native", content="wake",
        plugin_id="notify-plugin", route_claim=claim,
    )


def test_origin_is_gateway_only_even_when_tui_is_present(tmp_path):
    context, manager = _pair(
        tmp_path / "home", {"allow_gateway_injection": True, "allow_tui_injection": True},
    )
    origin = {"platform": "discord", "chat_id": "42", "chat_type": "thread", "thread_id": "42"}
    tui = Mock(return_value=True)
    gateway = Mock(return_value=True)
    manager.set_tui_message_injector(object(), tui)
    manager.set_gateway_message_injector(object(), gateway)

    assert context.inject_message("wake", surface="gateway", origin=origin) is True
    gateway.assert_called_once_with(
        origin=origin, plugin_home=manager.home_path, content="wake", plugin_id="notify-plugin",
    )
    assert context.inject_message("wake", surface="tui", origin=origin,
                                  session_key="route", expected_session_id="native") is False
    tui.assert_not_called()


def test_gateway_native_pin_and_claim_are_passed_to_gateway_callback(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_gateway_injection": True})
    gateway = Mock(return_value=True)
    manager.set_gateway_message_injector(object(), gateway)
    claim = {"epoch": "e-3"}

    assert context.inject_message(
        "wake", surface="gateway", session_key="route", expected_session_id="native",
        route_claim=claim,
    ) is True
    gateway.assert_called_once_with(
        session_key="route", expected_session_id="native", route_claim=claim,
        content="wake", plugin_id="notify-plugin",
    )


def test_cli_queue_does_not_accept_unverified_native_pin_or_claim(tmp_path):
    context, manager = _pair(tmp_path / "home")
    cli_queue = Mock()
    manager._cli_ref = SimpleNamespace(_agent_running=False, _pending_input=cli_queue)

    assert context.inject_message("wake", expected_session_id="native") is False
    assert context.inject_message("wake", route_claim={"epoch": "e-3"}) is False
    cli_queue.put.assert_not_called()


@pytest.mark.parametrize("receipt", [False, None, "queued", {"status": "queued"}, 1])
def test_tui_receipt_requires_literal_true(tmp_path, receipt):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    manager.set_tui_message_injector(object(), Mock(return_value=receipt))
    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native",
    ) is False


def test_tui_callback_exception_and_missing_host_have_no_ack(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native",
    ) is False
    manager.set_tui_message_injector(object(), Mock(side_effect=RuntimeError("host gone")))
    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native",
    ) is False


def test_tui_callback_failure_does_not_log_message_content(tmp_path, caplog):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    content = "synthetic-sensitive-message"
    manager.set_tui_message_injector(object(), Mock(side_effect=RuntimeError(content)))

    assert context.inject_message(
        content, surface="tui", session_key="route", expected_session_id="native",
    ) is False
    assert content not in caplog.text


@pytest.mark.parametrize("entry", [
    {"allow_gateway_injection": True},
    {"allow_tui_injection": "true"},
    {"allow_tui_injection": False},
    {},
])
def test_gateway_grant_or_nonboolean_tui_grant_cannot_enter_tui(tmp_path, entry):
    context, manager = _pair(tmp_path / "home", entry)
    callback = Mock(return_value=True)
    manager.set_tui_message_injector(object(), callback)
    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native",
    ) is False
    callback.assert_not_called()


def test_tui_grant_cannot_enter_messaging_gateway(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    gateway = Mock(return_value=True)
    manager.set_gateway_message_injector(object(), gateway)
    assert context.inject_message("wake", session_key="route", expected_session_id="native") is False
    assert context.inject_message(
        "wake", surface="gateway", session_key="route", expected_session_id="native",
    ) is False
    gateway.assert_not_called()


def test_tui_grant_read_failure_and_disabled_loaded_plugin_fail_closed(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    callback = Mock(return_value=True)
    manager.set_tui_message_injector(object(), callback)
    with patch("hermes_cli.plugins.load_config_readonly", side_effect=OSError("unreadable")):
        assert context.inject_message(
            "wake", surface="tui", session_key="route", expected_session_id="native",
        ) is False
    manager._plugins["notify-plugin"].enabled = False
    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native",
    ) is False
    callback.assert_not_called()


def test_direct_manager_tui_call_cannot_bypass_plugin_grant(tmp_path):
    _context, manager = _pair(tmp_path / "home", {"allow_gateway_injection": True})
    callback = Mock(return_value=True)
    manager.set_tui_message_injector(object(), callback)

    assert manager.inject_tui_message(
        session_key="route", expected_session_id="native", content="wake", plugin_id="notify-plugin",
    ) is False
    callback.assert_not_called()


def test_tui_grant_and_callback_are_pinned_to_manager_home(tmp_path):
    allowed, allowed_manager = _pair(tmp_path / "allowed", {"allow_tui_injection": True})
    denied, denied_manager = _pair(tmp_path / "denied", {"allow_gateway_injection": True})
    allowed_callback, denied_callback = Mock(return_value=True), Mock(return_value=True)
    allowed_manager.set_tui_message_injector(object(), allowed_callback)
    denied_manager.set_tui_message_injector(object(), denied_callback)

    with _plugin_home_scope(denied_manager.home_path):
        assert allowed.inject_message(
            "wake", surface="tui", session_key="route", expected_session_id="native",
        ) is True
    with _plugin_home_scope(allowed_manager.home_path):
        assert denied.inject_message(
            "wake", surface="tui", session_key="route", expected_session_id="native",
        ) is False
    allowed_callback.assert_called_once()
    denied_callback.assert_not_called()


def test_stale_native_id_is_refused_by_exact_host_callback(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    seen = []

    def host(**kwargs):
        seen.append(kwargs)
        return kwargs["session_key"] == "route" and kwargs["expected_session_id"] == "native-current"

    manager.set_tui_message_injector(object(), host)
    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native-stale",
    ) is False
    assert context.inject_message(
        "wake", surface="tui", session_key="route", expected_session_id="native-current",
    ) is True
    assert [call["expected_session_id"] for call in seen] == ["native-stale", "native-current"]


def test_lifecycle_hooks_require_live_route_and_are_profile_scoped(tmp_path):
    context, manager = _pair(tmp_path / "home", {"allow_tui_injection": True})
    manager._discovered = True
    seen = []
    live = SimpleNamespace(value=True)
    context.register_hook("on_session_resumed", lambda **kwargs: seen.append(("resume", kwargs)))
    context.register_hook("on_session_compacted", lambda **kwargs: seen.append(("compact", kwargs)))
    guard = lambda: live.value

    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default", route_is_current=guard)
    manager.on_session_compacted(
        session_key="new-route", old_session_id="native", session_id="new-native",
        profile="default", in_place=False, route_is_current=guard)
    assert [kind for kind, _ in seen] == ["resume", "compact"]
    assert seen[0][1]["route_is_current"]() is True
    assert "turn_id" not in seen[0][1]
    assert {key: seen[1][1][key] for key in (
        "session_key", "old_session_id", "session_id", "profile", "in_place",
    )} == {
        "session_key": "new-route", "old_session_id": "native",
        "session_id": "new-native", "profile": "default", "in_place": False,
    }
    live.value = False  # /new happened after the callbacks were queued by the plugin.
    assert seen[0][1]["route_is_current"]() is False
    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default", route_is_current=guard)
    assert len(seen) == 2


def test_lifecycle_rechecks_route_before_each_callback(tmp_path):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    live = SimpleNamespace(value=True)
    calls = []

    def first(**_kwargs):
        calls.append("first")
        live.value = False

    context.register_hook("on_session_resumed", first)
    context.register_hook("on_session_resumed", lambda **_kwargs: calls.append("second"))
    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default", route_is_current=lambda: live.value)
    assert calls == ["first"]


def test_stale_lifecycle_route_does_not_trigger_discovery(tmp_path, monkeypatch):
    _context, manager = _pair(tmp_path / "home")
    discover = Mock()
    monkeypatch.setattr(manager, "discover_and_load", discover)

    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default", route_is_current=lambda: False)
    discover.assert_not_called()


def test_lifecycle_hook_exception_isolated_and_narrow_callback_runs(tmp_path):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    seen = []

    def broken(**_kwargs):
        raise RuntimeError("synthetic observer failure")

    def narrow(session_key, session_id):
        seen.append((session_key, session_id))

    context.register_hook("on_session_resumed", broken)
    context.register_hook("on_session_resumed", narrow)
    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default", route_is_current=lambda: True)
    assert seen == [("route", "native")]


def test_lifecycle_lazily_discovers_under_its_manager_profile(tmp_path, monkeypatch):
    context, manager = _pair(tmp_path / "home")
    other = tmp_path / "other"
    other.mkdir()
    seen = []

    def discover():
        from hermes_constants import get_hermes_home
        seen.append(("discover", get_hermes_home()))
        context.register_hook("on_session_resumed", lambda **kwargs: seen.append(("hook", kwargs["session_id"])))
        manager._discovered = True

    monkeypatch.setattr(manager, "discover_and_load", discover)
    with _plugin_home_scope(other):
        manager.on_session_resumed(
            session_key="route", session_id="native", profile="default", route_is_current=lambda: True)
    assert seen == [("discover", manager.home_path), ("hook", "native")]


def test_lifecycle_hung_observer_has_deadline_and_does_not_block_next(tmp_path, monkeypatch):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    monkeypatch.setattr("hermes_cli.plugins._resolve_hook_callback_timeout", lambda: 0.03)
    entered, release, exited = threading.Event(), threading.Event(), threading.Event()
    calls = []

    def hung(**_kwargs):
        entered.set()
        release.wait(timeout=2)
        exited.set()

    context.register_hook("on_session_resumed", hung)
    context.register_hook("on_session_resumed", lambda **_kwargs: calls.append("second"))
    started = time.monotonic()
    try:
        manager.on_session_resumed(
            session_key="route", session_id="native", profile="default",
            route_is_current=lambda: True)
        assert time.monotonic() - started < 0.5
        assert entered.is_set()
        assert calls == ["second"]
    finally:
        release.set()
        exited.wait(timeout=2)


def test_lifecycle_timeout_suppresses_same_observer_but_keeps_others(tmp_path, monkeypatch):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    monkeypatch.setattr("hermes_cli.plugins._resolve_hook_callback_timeout", lambda: 0.03)
    release = threading.Event()
    calls = []

    def hung(**_kwargs):
        calls.append("hung")
        release.wait(timeout=2)

    context.register_hook("on_session_resumed", hung)
    context.register_hook("on_session_resumed", lambda **_kwargs: calls.append("next"))
    try:
        for _ in range(2):
            manager.on_session_resumed(
                session_key="route", session_id="native", profile="default",
                route_is_current=lambda: True)
        assert calls == ["hung", "next", "next"]
    finally:
        release.set()


def test_lifecycle_distinct_routes_do_not_share_running_gate(tmp_path, monkeypatch):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    monkeypatch.setattr("hermes_cli.plugins._resolve_hook_callback_timeout", lambda: 0.5)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def observer(session_key):
        calls.append(session_key)
        if session_key == "route-a":
            entered.set()
            release.wait(timeout=2)

    context.register_hook("on_session_resumed", observer)
    first = threading.Thread(target=lambda: manager.on_session_resumed(
        session_key="route-a", session_id="native-a", profile="default", route_is_current=lambda: True))
    first.start()
    try:
        assert entered.wait(timeout=1)
        manager.on_session_resumed(
            session_key="route-b", session_id="native-b", profile="default",
            route_is_current=lambda: True)
        assert calls == ["route-a", "route-b"]
    finally:
        release.set()
        first.join(timeout=2)
    assert not first.is_alive()


def test_lifecycle_wrapper_cache_is_cleared_on_unload(tmp_path):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    context.register_hook("on_session_resumed", lambda **_kwargs: None)
    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default", route_is_current=lambda: True)
    assert manager._tui_hook_wrappers

    assert manager.unload("notify-plugin") is True
    assert manager._tui_hook_wrappers == {}


@pytest.mark.parametrize("configured_timeout", [0, -1])
def test_lifecycle_nonpositive_timeout_still_bounds_observer(tmp_path, monkeypatch, configured_timeout):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    monkeypatch.setattr("hermes_cli.plugins._resolve_hook_callback_timeout", lambda: configured_timeout)
    monkeypatch.setattr("hermes_cli.plugins._HOOK_CALLBACK_TIMEOUT_SECS", 0.03)
    release = threading.Event()
    context.register_hook("on_session_compacted", lambda **_kwargs: release.wait(timeout=2))
    started = time.monotonic()
    try:
        manager.on_session_compacted(
            session_key="route-b", old_session_id="native-a", session_id="native-b",
            profile="default", in_place=False, route_is_current=lambda: True)
        assert time.monotonic() - started < 0.5
    finally:
        release.set()


def test_lifecycle_worker_rechecks_route_when_start_is_delayed(tmp_path, monkeypatch):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    monkeypatch.setattr("hermes_cli.plugins._resolve_hook_callback_timeout", lambda: 0.01)
    live = SimpleNamespace(value=True)
    calls, deferred = [], _defer_hook_workers(monkeypatch)
    context.register_hook("on_session_resumed", lambda **_kwargs: calls.append("stale"))
    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default",
        route_is_current=lambda: live.value)
    assert calls == []
    assert len(deferred) == 1
    live.value = False  # /new before the bounded worker reaches the callback.
    deferred[0]()
    assert calls == []


@pytest.mark.parametrize("unload_target", ["notify-plugin", None])
def test_lifecycle_deferred_worker_skips_unloaded_callback(tmp_path, monkeypatch, unload_target):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    monkeypatch.setattr("hermes_cli.plugins._resolve_hook_callback_timeout", lambda: 0.01)
    deferred = _defer_hook_workers(monkeypatch)
    calls = []
    context.register_hook("on_session_resumed", lambda **_kwargs: calls.append("unloaded"))
    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default", route_is_current=lambda: True)
    assert calls == [] and len(deferred) == 1

    assert manager.unload(unload_target) is True
    assert manager.iter_hook_callbacks("on_session_resumed") == ()
    deferred[0]()  # The route is still live, but registration no longer is.
    assert calls == []


def test_lifecycle_deferred_worker_skips_replaced_same_callable(tmp_path, monkeypatch):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    monkeypatch.setattr("hermes_cli.plugins._resolve_hook_callback_timeout", lambda: 0.01)
    deferred = _defer_hook_workers(monkeypatch)
    calls = []

    def reused(**_kwargs):
        calls.append("current")

    old_registration = context.register_hook("on_session_resumed", reused)
    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default", route_is_current=lambda: True)
    old_registration.dispose()
    context.register_hook("on_session_resumed", reused)
    manager.on_session_resumed(
        session_key="route", session_id="native", profile="default", route_is_current=lambda: True)
    assert len(deferred) == 2

    deferred[0]()
    assert calls == []
    deferred[1]()
    assert calls == ["current"]


def test_lifecycle_deferred_worker_runs_retained_callback(tmp_path, monkeypatch):
    context, manager = _pair(tmp_path / "home")
    manager._discovered = True
    monkeypatch.setattr("hermes_cli.plugins._resolve_hook_callback_timeout", lambda: 0.01)
    deferred = _defer_hook_workers(monkeypatch)
    calls = []
    context.register_hook("on_session_compacted", lambda **_kwargs: calls.append("retained"))
    manager.on_session_compacted(
        session_key="route", old_session_id="old", session_id="native", profile="default",
        in_place=False, route_is_current=lambda: True)
    assert calls == [] and len(deferred) == 1
    deferred[0]()
    assert calls == ["retained"]
