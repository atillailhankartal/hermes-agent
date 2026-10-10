"""TUI startup must not restore its host after another process owner replaces it."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import hermes_cli.plugins as plugins
import tui_gateway.plugin_inject as tui_host
from hermes_constants import reset_hermes_home_override, set_hermes_home_override


def test_no_arg_startup_cannot_restamp_after_successor_publication(tmp_path, monkeypatch):
    launch_home = tmp_path / "launch"
    late_home = tmp_path / "late"
    launch_home.mkdir()
    late_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(launch_home))
    manager = plugins.get_plugin_manager()
    monkeypatch.setattr(tui_host, "_atexit_registered", True)

    owner_a = tui_host._TUI_INJECT_OWNER
    owner_b, gateway_owner = object(), object()
    calls = []

    def inject_b(**_kwargs):
        calls.append("B")
        return True

    def inject_gateway(**_kwargs):
        calls.append("gateway")
        return True

    a_published = Event()
    resume_a = Event()
    publish = plugins.publish_tui_message_host

    def pause_after_publish(owner, injector):
        publish(owner, injector)
        if owner is owner_a:
            a_published.set()
            assert resume_a.wait(10), "TUI startup was not released"

    monkeypatch.setattr(plugins, "publish_tui_message_host", pause_after_publish)
    plugins.publish_gateway_message_host(gateway_owner, inject_gateway)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(tui_host.install_tui_message_injector)
            try:
                assert a_published.wait(10), "TUI startup did not publish"
                publish(owner_b, inject_b)
                token = set_hermes_home_override(str(late_home))
                try:
                    late_manager = plugins.get_plugin_manager()
                finally:
                    reset_hermes_home_override(token)
            finally:
                resume_a.set()
            future.result(timeout=10)

        assert plugins._published_tui_message_injector[0] is owner_b
        assert manager._tui_message_injector[0] is owner_b
        assert late_manager._tui_message_injector[0] is owner_b

        tui_host.clear_tui_message_injector()
        assert manager.inject_tui_message(content="probe") is True
        assert late_manager.inject_tui_message(content="probe") is True
        assert calls[-2:] == ["B", "B"]

        plugins.clear_published_tui_message_host(owner_b)
        assert manager.inject_tui_message(content="probe") is False
        assert late_manager.inject_tui_message(content="probe") is False
        assert manager.inject_gateway_message(content="probe") is True
        assert late_manager.inject_gateway_message(content="probe") is True
        assert calls[-2:] == ["gateway", "gateway"]
    finally:
        resume_a.set()
        plugins.clear_published_tui_message_host(owner_a)
        plugins.clear_published_tui_message_host(owner_b)
        plugins.clear_published_gateway_message_host(gateway_owner)
