"""The live TUI host has one owner across existing and newly resolved managers."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import hermes_cli.plugins as plugins
import hermes_yaml as yaml
from hermes_constants import reset_hermes_home_override, set_hermes_home_override


def test_concurrent_tui_publication_does_not_restore_an_old_host(tmp_path, monkeypatch):
    launch_home = tmp_path / "launch"
    late_home = tmp_path / "late"
    launch_home.mkdir()
    late_home.mkdir()
    for home in (launch_home, late_home):
        (home / "config.yaml").write_text(yaml.safe_dump({
            "plugins": {
                "enabled": ["probe-plugin"],
                "entries": {"probe-plugin": {"allow_tui_injection": True}},
            },
        }))
    monkeypatch.setenv("HERMES_HOME", str(launch_home))
    manager = plugins.get_plugin_manager()

    def prepare(manager):
        manifest = plugins.PluginManifest(name="probe-plugin", key="probe-plugin", source="user")
        manager._plugins["probe-plugin"] = plugins.LoadedPlugin(manifest, enabled=True)

    def send(manager):
        return manager.inject_tui_message(
            session_key="route", expected_session_id="native",
            content="probe", plugin_id="probe-plugin",
        )

    prepare(manager)

    owner_a, owner_b, gateway_owner = object(), object(), object()
    calls = []

    def inject_a(**_kwargs):
        calls.append("A")
        return True

    def inject_b(**_kwargs):
        calls.append("B")
        return True

    def inject_gateway(**_kwargs):
        calls.append("gateway")
        return True

    # Hold A at the manager callback boundary while B publishes and a new
    # profile manager resolves. A must not be able to stamp over B afterward.
    a_at_manager = Event()
    release_a = Event()
    b_started = Event()
    b_finished = Event()
    original_set = manager.set_tui_message_injector

    def paused_set(owner, injector):
        if owner is owner_a:
            a_at_manager.set()
            assert release_a.wait(10), "A publication was never released"
        original_set(owner, injector)

    monkeypatch.setattr(manager, "set_tui_message_injector", paused_set)

    def publish_b():
        b_started.set()
        plugins.publish_tui_message_host(owner_b, inject_b)
        b_finished.set()

    def create_late_manager():
        token = set_hermes_home_override(str(late_home))
        try:
            return plugins.get_plugin_manager()
        finally:
            reset_hermes_home_override(token)

    plugins.publish_gateway_message_host(gateway_owner, inject_gateway)
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            future_a = pool.submit(plugins.publish_tui_message_host, owner_a, inject_a)
            try:
                assert a_at_manager.wait(10), "A did not reach the manager"
                future_b = pool.submit(publish_b)
                assert b_started.wait(10), "B was not scheduled"
                future_late = pool.submit(create_late_manager)
                # On the unfixed host, B finishes while A is paused. Under an
                # atomic publication, B waits for A's lock, then wins last.
                b_finished.wait(2)
            finally:
                release_a.set()
            future_a.result(timeout=10)
            future_b.result(timeout=10)
            late_manager = future_late.result(timeout=10)
        prepare(late_manager)

        assert send(manager) is True
        assert send(late_manager) is True
        assert calls[-2:] == ["B", "B"]

        plugins.clear_published_tui_message_host(owner_a)
        assert send(manager) is True
        assert send(late_manager) is True
        assert calls[-2:] == ["B", "B"]

        # Clearing the successor cannot leave A's late callback live. TUI
        # publication and clearing must not affect the Gateway host slot.
        plugins.clear_published_tui_message_host(owner_b)
        assert send(manager) is False
        assert send(late_manager) is False
        assert manager.inject_gateway_message(content="probe") is True
        assert late_manager.inject_gateway_message(content="probe") is True
        assert calls[-2:] == ["gateway", "gateway"]
    finally:
        release_a.set()
        plugins.clear_published_tui_message_host(owner_a)
        plugins.clear_published_tui_message_host(owner_b)
        plugins.clear_published_gateway_message_host(gateway_owner)
