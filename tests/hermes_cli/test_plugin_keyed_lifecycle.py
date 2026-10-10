"""Keyed lifecycle events preserve old/new route identity and legacy observers."""

import json
from dataclasses import dataclass
from unittest.mock import Mock

from hermes_cli.plugins import (
    PluginManager, _reset_plugin_managers_for_tests, clear_published_keyed_lifecycle_host,
    get_plugin_manager, publish_keyed_lifecycle_host,
)
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from agent import outbound_webhooks, shell_hooks


@dataclass
class Claim:
    surface: str
    profile_home_key: str
    session_key: str
    native_session_id: str
    route_epoch: str
    host_owner_id: str = "owner-1"
    current: bool = True

    def is_route_current(self):
        return self.current


def _route(manager, native, epoch):
    return Claim("gateway", manager.scope_key, "chat-1", native, epoch)


def test_keyed_finalize_reset_resume_a_keeps_epochs_distinct(tmp_path):
    manager = PluginManager(scope_key=str(tmp_path.resolve()))
    owner = object()
    manager.set_keyed_lifecycle_host("gateway", owner, "owner-1")
    observed = []
    manager._hooks["on_session_finalize"] = [lambda **kw: observed.append(("finalize", kw))]
    manager._hooks["on_session_reset"] = [lambda **kw: observed.append(("reset", kw))]
    manager._hooks["on_session_resumed"] = [lambda **kw: observed.append(("resumed", kw))]
    b = _route(manager, "B", "epoch-B")
    a2 = _route(manager, "A", "epoch-A2")

    assert manager.notify_keyed_session_finalize(
        "gateway", owner, session_key="chat-1", session_id="A", route_epoch="epoch-A1",
        reason="new", old_route_revoked=True,
    )
    assert manager.notify_keyed_session_reset(
        "gateway", owner, session_key="chat-1", old_session_id="A", session_id="B",
        old_route_epoch="epoch-A1", route_epoch="epoch-B", route_claim=b,
        route_is_current=b.is_route_current,
    )
    assert manager.notify_keyed_session_resumed(
        "gateway", owner, session_key="chat-1", old_session_id="B", session_id="A",
        old_route_epoch="epoch-B", route_epoch="epoch-A2", route_claim=a2,
        route_is_current=a2.is_route_current,
    )
    assert manager.notify_keyed_session_finalize(
        "gateway", owner, session_key="chat-1", session_id="A", route_epoch="epoch-A1",
        reason="late", old_route_revoked=True,
    )
    assert [event for event, _ in observed] == ["finalize", "reset", "resumed", "finalize"]
    assert observed[0][1]["route_epoch"] == "epoch-A1"
    assert observed[1][1]["session_id"] == "B"
    assert observed[1][1]["route_epoch"] == "epoch-B"
    assert observed[2][1]["route_epoch"] == "epoch-A2"
    assert observed[3][1]["route_epoch"] == "epoch-A1"


def test_stale_or_wrong_route_and_owner_never_dispatch(tmp_path):
    manager = PluginManager(scope_key=str(tmp_path.resolve()))
    owner, successor = object(), object()
    manager.set_keyed_lifecycle_host("gateway", owner, "owner-1")
    callback = Mock()
    manager._hooks["on_session_reset"] = [callback]
    claim = _route(manager, "B", "epoch-B")
    args = dict(session_key="chat-1", old_session_id="A", session_id="B",
                old_route_epoch="epoch-A", route_epoch="epoch-B", route_claim=claim,
                route_is_current=claim.is_route_current)
    assert not manager.notify_keyed_session_reset("gateway", successor, **args)
    claim.current = False
    assert not manager.notify_keyed_session_reset("gateway", owner, **args)
    claim.current = True
    assert not manager.notify_keyed_session_reset("tui", owner, **args)
    assert not manager.notify_keyed_session_finalize(
        "gateway", owner, session_key="chat-1", session_id="A", route_epoch="epoch-A",
        reason="new", old_route_revoked=False,
    )
    callback.assert_not_called()
    manager.set_keyed_lifecycle_host("gateway", successor, "owner-2")
    manager.clear_keyed_lifecycle_host("gateway", owner)
    assert not manager.notify_keyed_session_reset("gateway", owner, **args)


def test_compaction_once_and_legacy_narrow_callback_still_runs(tmp_path):
    manager = PluginManager(scope_key=str(tmp_path.resolve()))
    owner = object()
    manager.set_keyed_lifecycle_host("gateway", owner, "owner-1")
    claim = _route(manager, "A", "epoch-A2")
    narrow = Mock()
    modern = Mock()
    manager._hooks["on_session_compacted"] = [
        lambda session_key, session_id: narrow(session_key, session_id), modern,
    ]
    assert manager.notify_keyed_session_compacted(
        "gateway", owner, session_key="chat-1", old_session_id="A", session_id="A",
        old_route_epoch="epoch-A1", route_epoch="epoch-A2", in_place=True,
        route_claim=claim, route_is_current=claim.is_route_current,
    )
    narrow.assert_called_once_with("chat-1", "A")
    modern.assert_called_once()
    manager.clear_keyed_lifecycle_host("gateway", owner)
    assert not manager.notify_keyed_session_compacted(
        "gateway", owner, session_key="chat-1", old_session_id="A", session_id="A",
        old_route_epoch="epoch-A1", route_epoch="epoch-A2", in_place=True,
        route_claim=claim, route_is_current=claim.is_route_current,
    )
    narrow.assert_called_once()


def test_private_claim_is_not_serialized_to_external_observer(tmp_path):
    manager = PluginManager(scope_key=str(tmp_path.resolve()))
    owner = object()
    manager.set_keyed_lifecycle_host("gateway", owner, "owner-1")
    claim = _route(manager, "B", "epoch-B")
    external = Mock()
    external.__module__ = "agent.outbound_webhooks"
    internal = Mock()
    manager._hooks["on_session_reset"] = [external, internal]
    assert manager.notify_keyed_session_reset(
        "gateway", owner, session_key="chat-1", old_session_id="A", session_id="B",
        old_route_epoch="epoch-A", route_epoch="epoch-B", route_claim=claim,
        route_is_current=claim.is_route_current,
    )
    assert "route_claim" not in external.call_args.kwargs
    assert "route_is_current" not in external.call_args.kwargs
    assert external.call_args.kwargs["route_epoch"] == "epoch-B"
    assert internal.call_args.kwargs["route_claim"] is claim


def test_process_keyed_publication_is_owner_pinned_for_future_manager(tmp_path):
    _reset_plugin_managers_for_tests()
    token = set_hermes_home_override(str(tmp_path.resolve()))
    first, second = object(), object()
    try:
        publish_keyed_lifecycle_host("gateway", first, "owner-1")
        publish_keyed_lifecycle_host("gateway", second, "owner-2")
        manager = get_plugin_manager()
        clear_published_keyed_lifecycle_host("gateway", first)
        assert manager._keyed_lifecycle_owner("gateway", second) == "owner-2"
        clear_published_keyed_lifecycle_host("gateway", second)
        assert manager._keyed_lifecycle_owner("gateway", second) is None
    finally:
        clear_published_keyed_lifecycle_host("gateway", first)
        clear_published_keyed_lifecycle_host("gateway", second)
        reset_hermes_home_override(token)
        _reset_plugin_managers_for_tests()


def test_registered_shell_and_webhook_observers_never_receive_private_claim(tmp_path, monkeypatch):
    """Exercise the real config registration closures and their JSON serialization."""
    _reset_plugin_managers_for_tests()
    shell_hooks.reset_for_tests()
    outbound_webhooks.reset_for_tests()
    token = set_hermes_home_override(str(tmp_path.resolve()))
    shell_payloads, webhooks = [], []
    monkeypatch.setattr(shell_hooks, "_is_allowlisted", lambda *_args: True)

    def capture_shell(_spec, stdin_json):
        shell_payloads.append(json.loads(stdin_json))
        return dict(returncode=0, stdout="", stderr="", timed_out=False,
                    elapsed_seconds=0.0, error=None)

    monkeypatch.setattr(shell_hooks, "_spawn", capture_shell)
    monkeypatch.setattr(outbound_webhooks, "_enqueue", webhooks.append)
    try:
        assert len(shell_hooks.register_from_config({
            "hooks": {"on_session_reset": [{"command": "echo safe"}]},
        }, accept_hooks=True)) == 1
        assert len(outbound_webhooks.register_from_config({
            "hooks": {"outbound": [{"url": "https://example.invalid/hook", "events": ["on_session_reset"]}]},
        })) == 1
        manager = get_plugin_manager()
        owner = object()
        manager.set_keyed_lifecycle_host("gateway", owner, "owner-1")
        claim = _route(manager, "B", "epoch-B")
        assert manager.notify_keyed_session_reset(
            "gateway", owner, session_key="chat-1", old_session_id="A", session_id="B",
            old_route_epoch="epoch-A", route_epoch="epoch-B", route_claim=claim,
            route_is_current=claim.is_route_current,
        )
        assert len(shell_payloads) == len(webhooks) == 1
        shell_extra = shell_payloads[0]["extra"]
        webhook_extra = json.loads(webhooks[0]["body"])["extra"]
        for extra in (shell_extra, webhook_extra):
            assert extra["route_epoch"] == "epoch-B"
            assert "route_claim" not in extra
            assert "route_is_current" not in extra
    finally:
        reset_hermes_home_override(token)
        shell_hooks.reset_for_tests()
        outbound_webhooks.reset_for_tests()
        _reset_plugin_managers_for_tests()
