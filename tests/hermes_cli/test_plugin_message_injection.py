"""Tests for plugin message injection across CLI and gateway hosts."""

from queue import SimpleQueue
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import yaml

from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from hermes_cli.plugins_loader import _plugin_home_scope


def _context(name: str = "notify-plugin") -> tuple[PluginContext, PluginManager]:
    manager = PluginManager()
    manifest = PluginManifest(name=name, key=name, source="user")
    return PluginContext(manifest, manager), manager


def _write_plugin_config(tmp_path, monkeypatch, entry: dict) -> None:
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir()
    (hermes_home / "config.yaml").write_text(
        yaml.safe_dump({"plugins": {"entries": {"notify-plugin": entry}}})
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))


def test_cli_idle_injection_keeps_existing_queue_behaviour():
    context, manager = _context()
    cli = SimpleNamespace(
        _agent_running=False,
        _pending_input=SimpleQueue(),
        _interrupt_queue=SimpleQueue(),
    )
    manager._cli_ref = cli

    assert context.inject_message("new input") is True
    assert cli._pending_input.get_nowait() == "new input"
    assert cli._interrupt_queue.empty()


def test_cli_running_injection_keeps_existing_interrupt_behaviour():
    context, manager = _context()
    cli = SimpleNamespace(
        _agent_running=True,
        _pending_input=SimpleQueue(),
        _interrupt_queue=SimpleQueue(),
    )
    manager._cli_ref = cli

    assert context.inject_message("status", "system") is True
    assert cli._interrupt_queue.get_nowait() == "[system] status"
    assert cli._pending_input.empty()


def test_gateway_injection_requires_session_key(tmp_path, monkeypatch):
    _write_plugin_config(
        tmp_path,
        monkeypatch,
        {"allow_gateway_injection": True},
    )
    context, manager = _context()
    injector = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), injector)

    assert context.inject_message("wake up") is False
    injector.assert_not_called()


def test_gateway_injection_requires_explicit_permission(tmp_path, monkeypatch):
    _write_plugin_config(tmp_path, monkeypatch, {})
    context, manager = _context()
    injector = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), injector)

    assert (
        context.inject_message(
            "wake up",
            session_key="agent:main:telegram:dm:42",
        )
        is False
    )
    injector.assert_not_called()


def test_gateway_injection_consent_is_pinned_to_origin_manager_home(tmp_path):
    denied_home = tmp_path / "denied"
    allowed_home = tmp_path / "allowed"
    for home, allowed in ((denied_home, False), (allowed_home, True)):
        home.mkdir()
        (home / "config.yaml").write_text(yaml.safe_dump({
            "plugins": {"entries": {"notify-plugin": {"allow_gateway_injection": allowed}}}
        }))
    with _plugin_home_scope(denied_home):
        denied_context, denied_manager = _context()
    with _plugin_home_scope(allowed_home):
        allowed_context, allowed_manager = _context()
    denied_injector = MagicMock(return_value=True)
    allowed_injector = MagicMock(return_value=True)
    denied_manager.set_gateway_message_injector(object(), denied_injector)
    allowed_manager.set_gateway_message_injector(object(), allowed_injector)

    with _plugin_home_scope(allowed_home):
        assert denied_context.inject_message("wake", session_key="route") is False
    with _plugin_home_scope(denied_home):
        assert allowed_context.inject_message("wake", session_key="route") is True

    denied_injector.assert_not_called()
    allowed_injector.assert_called_once()


def test_gateway_injection_does_not_treat_string_as_permission(tmp_path, monkeypatch):
    _write_plugin_config(
        tmp_path,
        monkeypatch,
        {"allow_gateway_injection": "false"},
    )
    context, manager = _context()
    injector = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), injector)

    assert (
        context.inject_message(
            "wake up",
            session_key="agent:main:telegram:dm:42",
        )
        is False
    )
    injector.assert_not_called()


def test_gateway_injection_fails_closed_when_config_cannot_be_read():
    context, manager = _context()
    injector = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), injector)

    with patch(
        "hermes_cli.plugins.load_config_readonly",
        side_effect=OSError("config unavailable"),
    ):
        assert (
            context.inject_message(
                "wake up",
                session_key="agent:main:telegram:dm:42",
            )
            is False
        )

    injector.assert_not_called()


def test_gateway_injection_requires_live_host(tmp_path, monkeypatch):
    _write_plugin_config(
        tmp_path,
        monkeypatch,
        {"allow_gateway_injection": True},
    )
    context, manager = _context()

    assert manager.has_gateway_message_injector is False
    assert (
        context.inject_message(
            "wake up",
            session_key="agent:main:telegram:dm:42",
        )
        is False
    )


def test_gateway_injection_passes_host_owned_plugin_identity(tmp_path, monkeypatch):
    _write_plugin_config(
        tmp_path,
        monkeypatch,
        {"allow_gateway_injection": True},
    )
    context, manager = _context()
    injector = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), injector)

    result = context.inject_message(
        "wake up",
        role="system",
        session_key="agent:main:telegram:dm:42",
    )

    assert result is True
    injector.assert_called_once_with(
        session_key="agent:main:telegram:dm:42",
        content="[system] wake up",
        plugin_id="notify-plugin",
    )


def test_gateway_injection_fails_closed_on_host_exception(tmp_path, monkeypatch):
    _write_plugin_config(
        tmp_path,
        monkeypatch,
        {"allow_gateway_injection": True},
    )
    context, manager = _context()
    injector = MagicMock(side_effect=RuntimeError("gateway unavailable"))
    manager.set_gateway_message_injector(object(), injector)

    assert (
        context.inject_message(
            "wake up",
            session_key="agent:main:telegram:dm:42",
        )
        is False
    )


def test_gateway_injection_forwards_expected_session_id(tmp_path, monkeypatch):
    _write_plugin_config(tmp_path, monkeypatch, {"allow_gateway_injection": True})
    context, manager = _context()
    injector = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), injector)

    assert context.inject_message(
        "wake up", session_key="route", expected_session_id="native-id"
    ) is True
    injector.assert_called_once_with(
        session_key="route", content="wake up", plugin_id="notify-plugin",
        expected_session_id="native-id",
    )


def test_cli_rejects_gateway_session_pin():
    context, manager = _context()
    cli = SimpleNamespace(
        _agent_running=False, _pending_input=SimpleQueue(),
        _interrupt_queue=SimpleQueue(),
    )
    manager._cli_ref = cli

    assert context.inject_message("wake", expected_session_id="gateway-id") is False
    assert cli._pending_input.empty()
    assert cli._interrupt_queue.empty()
