"""plugins.isolation: host — third-party plugins run in a per-profile host process, reached only via ctx."""

import json
import os
import sys
import time

import hermes_yaml as yaml
import pytest

from hermes_cli import plugins as plugins_mod
from hermes_cli.plugins import PluginManager

PROBE_PLUGIN = '''
import json, os
from agent.image_gen_provider import ImageGenProvider

class Painter(ImageGenProvider):
    @property
    def name(self):
        return "hostpainter"
    def generate(self, prompt, aspect_ratio="landscape", **kw):
        return {"success": True, "image": f"{prompt}@{os.getpid()}"}

SEEN = []

def register(ctx):
    ctx.register_tool(name="hostprobe_pid", toolset="hostprobe", schema={"name": "hostprobe_pid",
        "description": "d", "parameters": {"type": "object", "properties": {}}},
        handler=lambda args, **kw: json.dumps({"pid": os.getpid(), "seen": SEEN, "x": args.get("x")}))
    ctx.register_tool(name="hostprobe_nested", toolset="hostprobe", schema={"name": "hostprobe_nested",
        "description": "d", "parameters": {"type": "object", "properties": {}}},
        handler=lambda args, **kw: ctx.dispatch_tool("hostprobe_pid", {"x": "nested"}))
    ctx.register_tool(name="hostprobe_crash", toolset="hostprobe", schema={"name": "hostprobe_crash",
        "description": "d", "parameters": {"type": "object", "properties": {}}},
        handler=lambda args, **kw: os._exit(3))
    ctx.register_hook("post_tool_call", lambda tool_name=None, **kw: SEEN.append(tool_name))
    ctx.register_image_gen_provider(Painter())
'''

PLATFORM_PLUGIN = '''
def register(ctx):
    ctx.register_platform("x", "X", adapter_factory=lambda cfg: None, check_fn=lambda: True)
'''


def _home_with_plugins(tmp_path, monkeypatch, plugins: dict, isolation="host"):
    home = tmp_path / ".hermes"
    home.mkdir(parents=True, exist_ok=True)
    for name, body in plugins.items():
        plugin_dir = home / "plugins" / name
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "plugin.yaml").write_text(yaml.safe_dump({"name": name, "version": "1.0"}), encoding="utf-8")
        (plugin_dir / "__init__.py").write_text(body, encoding="utf-8")
    (home / "config.yaml").write_text(yaml.safe_dump(
        {"plugins": {"enabled": list(plugins), "isolation": isolation}}), encoding="utf-8")
    empty_bundled = tmp_path / "bundled"
    empty_bundled.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "os-home"))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(plugins_mod, "get_bundled_plugins_dir", lambda: empty_bundled)
    return home


ROUTE_PLUGIN = '''
import json, os, threading

saved_claim = None

def register(ctx):
    def inspect_route(args, route_claim=None):
        global saved_claim
        saved_claim = route_claim
        coordinates = {name: getattr(route_claim, name) for name in (
            "surface", "profile_home_key", "session_key", "native_session_id",
            "route_epoch", "host_owner_id")}
        check = lambda handle, operation, coords: ctx._runtime.channel.call(
            "route_cap.check", {"handle": handle, "operation": operation,
                                "coordinates": coords})
        detached_result = []
        detached = threading.Thread(target=lambda: detached_result.append(
            check(route_claim._handle, "tool-current", coordinates)))
        detached.start()
        detached.join(timeout=5)
        return json.dumps({
            "current": route_claim.is_current(
                profile_home_key=route_claim.profile_home_key,
                session_key=route_claim.session_key,
                native_session_id=route_claim.native_session_id,
            ),
            "route_current": route_claim.is_route_current(),
            "private_absent": not hasattr(route_claim, "_proof")
                and not hasattr(route_claim, "_validate")
                and not hasattr(route_claim, "_host"),
            "wrong_session": route_claim.is_current(native_session_id="other"),
            "surface": route_claim.surface,
            "epoch": route_claim.route_epoch,
            "nested_claim_type": ctx.dispatch_tool("route_claim_sink", {}, route_claim=route_claim),
            "fake_token": check("forged", "tool-current", coordinates),
            "wrong_coordinates": check(route_claim._handle, "tool-current",
                                       {**coordinates, "route_epoch": "other"}),
            "wrong_mode": check(route_claim._handle, "route-observe", coordinates),
            "detached_origin": detached_result[0],
        })

    def replay_route(args):
        coordinates = {name: getattr(saved_claim, name) for name in (
            "surface", "profile_home_key", "session_key", "native_session_id",
            "route_epoch", "host_owner_id")}
        return json.dumps({"current": saved_claim.is_current(),
                           "route_current": saved_claim.is_route_current(),
                           "direct_replay": ctx._runtime.channel.call(
                               "route_cap.check", {"handle": saved_claim._handle,
                                                   "operation": "tool-current",
                                                   "coordinates": coordinates})})

    def turn_flip(args, route_claim=None):
        before = route_claim.is_current()
        ctx.dispatch_tool("route_flip_trigger", {})
        return json.dumps({"before": before, "after": route_claim.is_current()})

    def hold_route(args, route_claim=None):
        before = route_claim.is_current()
        ctx.dispatch_tool("route_hold_gate", {})
        return json.dumps({"before": before, "after": route_claim.is_current()})

    def check_foreign(args):
        return json.dumps({"accepted": ctx._runtime.channel.call("route_cap.check", {
            "handle": args["handle"], "operation": "tool-current",
            "coordinates": args["coordinates"]})})

    def crash_route(args, route_claim=None):
        ctx.dispatch_tool("route_token_capture", {"handle": route_claim._handle})
        os._exit(3)

    schema = {"name": "route_inspect", "description": "route probe",
              "parameters": {"type": "object", "properties": {}}}
    ctx.register_tool(name="route_inspect", toolset="routeprobe", schema=schema,
                      handler=inspect_route)
    ctx.register_tool(name="route_replay", toolset="routeprobe", schema=schema,
                      handler=replay_route)
    ctx.register_tool(name="route_turn_flip", toolset="routeprobe", schema=schema,
                      handler=turn_flip)
    ctx.register_tool(name="route_hold", toolset="routeprobe", schema=schema,
                      handler=hold_route)
    ctx.register_tool(name="route_check_foreign", toolset="routeprobe", schema=schema,
                      handler=check_foreign)
    ctx.register_tool(name="route_crash", toolset="routeprobe", schema=schema,
                      handler=crash_route)
'''


ROUTE_LIFECYCLE_PLUGIN = '''
import json

observed = {}

def register(ctx):
    def on_reset(route_claim=None, route_is_current=None, **kwargs):
        global observed
        observed = {"current": route_claim.is_current(),
                    "route_current": route_claim.is_route_current(),
                    "guard_current": route_is_current(),
                    "private_absent": not hasattr(route_claim, "_proof")}

    ctx.register_hook("on_session_reset", on_reset)
    ctx.register_tool(name="route_lifecycle_seen", toolset="routeprobe",
                      schema={"name": "route_lifecycle_seen", "description": "route probe",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=lambda args: json.dumps(observed))
'''


@pytest.mark.platforms("any")
def test_default_in_process_route_claim_keeps_native_identity(tmp_path, monkeypatch):
    from gateway.route_claim import RouteClaim
    from tools.registry import registry

    body = '''
import json

def register(ctx):
    ctx.register_tool(name="route_native_identity", toolset="routeprobe",
                      schema={"name": "route_native_identity", "description": "route probe",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=lambda args, route_claim=None: json.dumps({
                          "native": type(route_claim).__name__ == "RouteClaim",
                          "proof_visible": hasattr(route_claim, "_proof"),
                          "current": route_claim.is_current()}))
'''
    home = _home_with_plugins(tmp_path, monkeypatch, {"routeprobe": body}, isolation="in_process")
    (home / "config.yaml").write_text(yaml.safe_dump({"plugins": {"enabled": ["routeprobe"]}}),
                                       encoding="utf-8")
    manager = PluginManager()
    manager.discover_and_load()
    claim = RouteClaim("gateway", manager.scope_key, "route", "native", "epoch-1", "owner-1",
                       object(), lambda _claim: True, lambda _claim: True)
    try:
        assert json.loads(registry.dispatch("route_native_identity", {}, scope=manager.scope_key,
                                            route_claim=claim)) == {
            "native": True, "proof_visible": True, "current": True}
    finally:
        manager.unload()


@pytest.mark.platforms("any")
def test_host_route_claim_is_read_only_current_and_revoked_after_callback(tmp_path, monkeypatch):
    from gateway.route_claim import RouteClaim
    from tools.registry import registry

    _home_with_plugins(tmp_path, monkeypatch, {"routeprobe": ROUTE_PLUGIN})
    manager = PluginManager()
    manager.discover_and_load()
    state = {"current": True}
    proof = object()
    claim = RouteClaim("gateway", manager.scope_key, "route", "native", "epoch-1", "owner-1",
                       proof, lambda _claim: state["current"],
                       lambda _claim: state["current"])
    registry.register(name="route_claim_sink", toolset="routeprobe",
                      schema={"name": "route_claim_sink", "description": "sink",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=lambda _args, route_claim=None: type(route_claim).__name__,
                      scope=manager.scope_key)
    try:
        result = json.loads(registry.dispatch("route_inspect", {}, scope=manager.scope_key,
                                              route_claim=claim))
        assert result == {"current": True, "route_current": False, "private_absent": True,
                          "wrong_session": False, "surface": "gateway", "epoch": "epoch-1",
                          "nested_claim_type": "Opaque", "fake_token": False,
                          "wrong_coordinates": False, "wrong_mode": False,
                          "detached_origin": False}
        # The child retains a Python object, but the parent-held handle expires with this call.
        assert json.loads(registry.dispatch("route_replay", {}, scope=manager.scope_key)) == {
            "current": False, "route_current": False, "direct_replay": False}
        state["current"] = False
        stale = registry.dispatch("route_inspect", {}, scope=manager.scope_key,
                                  route_claim=claim)
        assert "route claim is no longer current" in stale
        state["current"] = True
        registry.register(name="route_flip_trigger", toolset="routeprobe",
                          schema={"name": "route_flip_trigger", "description": "flip",
                                  "parameters": {"type": "object", "properties": {}}},
                          handler=lambda _args: state.__setitem__("current", False) or "ok",
                          scope=manager.scope_key)
        assert json.loads(registry.dispatch("route_turn_flip", {}, scope=manager.scope_key,
                                            route_claim=claim)) == {"before": True, "after": False}
    finally:
        registry.deregister("route_flip_trigger", scope=manager.scope_key)
        registry.deregister("route_claim_sink", scope=manager.scope_key)
        manager.unload()
        manager._plugin_host().shutdown()


@pytest.mark.platforms("any")
def test_host_lifecycle_uses_local_observer_without_promoting_tool_authority(tmp_path, monkeypatch):
    from gateway.route_claim import RouteClaim
    from tools.registry import registry

    _home_with_plugins(tmp_path, monkeypatch, {"routeprobe": ROUTE_LIFECYCLE_PLUGIN})
    manager = PluginManager()
    manager.discover_and_load()
    owner = object()
    manager.set_keyed_lifecycle_host("gateway", owner, "owner-1")
    current = {"route": True}
    proof = object()
    claim = RouteClaim("gateway", manager.scope_key, "route", "native", "epoch-1", "owner-1",
                       proof, lambda _claim: False, lambda _claim: current["route"])
    try:
        assert manager.notify_keyed_session_reset(
            "gateway", owner, session_key="route", session_id="native", route_epoch="epoch-1",
            old_session_id="old", old_route_epoch="epoch-0", route_claim=claim,
            route_is_current=lambda: current["route"],
        ) is True
        assert json.loads(registry.dispatch("route_lifecycle_seen", {}, scope=manager.scope_key)) == {
            "current": False, "route_current": True, "guard_current": True,
            "private_absent": True}
        current["route"] = False
        assert manager.notify_keyed_session_reset(
            "gateway", owner, session_key="route", session_id="native", route_epoch="epoch-1",
            old_session_id="old", old_route_epoch="epoch-0", route_claim=claim,
            route_is_current=lambda: current["route"],
        ) is False
    finally:
        manager.unload()
        manager._plugin_host().shutdown()


@pytest.mark.platforms("any")
def test_host_cli_route_claim_uses_parent_validator_and_hides_host_proof(tmp_path, monkeypatch):
    from hermes_cli.cli_plugin_admission import CliRouteClaim
    from tools.registry import registry

    _home_with_plugins(tmp_path, monkeypatch, {"routeprobe": ROUTE_PLUGIN})
    manager = PluginManager()
    manager.discover_and_load()

    class NativeOwner:
        active = True

        def tool_claim_current(self, _claim):
            return self.active

        def route_current(self, _claim):
            return self.active

    owner = NativeOwner()
    claim = CliRouteClaim("cli", manager.scope_key, "native", "native", "epoch-cli", "owner-cli",
                          owner, object())
    registry.register(name="route_claim_sink", toolset="routeprobe",
                      schema={"name": "route_claim_sink", "description": "sink",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=lambda _args, route_claim=None: type(route_claim).__name__,
                      scope=manager.scope_key)
    try:
        result = json.loads(registry.dispatch("route_inspect", {}, scope=manager.scope_key,
                                              route_claim=claim))
        assert result["current"] is True and result["private_absent"] is True
        assert result["surface"] == "cli" and result["epoch"] == "epoch-cli"
        owner.active = False
        assert "route claim is no longer current" in registry.dispatch(
            "route_inspect", {}, scope=manager.scope_key, route_claim=claim)
    finally:
        registry.deregister("route_claim_sink", scope=manager.scope_key)
        manager.unload()
        manager._plugin_host().shutdown()


@pytest.mark.platforms("any")
def test_route_cap_rejects_other_profile_and_unload_during_callback(tmp_path, monkeypatch):
    import threading
    from gateway.route_claim import RouteClaim
    from tools.registry import registry

    first_dir, second_dir = tmp_path / "first", tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    first_home = _home_with_plugins(first_dir, monkeypatch, {"routeprobe": ROUTE_PLUGIN})
    first = PluginManager()
    first.discover_and_load()
    _home_with_plugins(second_dir, monkeypatch, {"routeprobe": ROUTE_PLUGIN})
    second = PluginManager()
    second.discover_and_load()
    monkeypatch.setenv("HERMES_HOME", str(first_home))
    entered, release = threading.Event(), threading.Event()
    state = {"current": True}
    claim = RouteClaim("gateway", first.scope_key, "route", "native", "epoch-1", "owner-1",
                       object(), lambda _claim: state["current"],
                       lambda _claim: state["current"])

    def gate(_args):
        entered.set()
        assert release.wait(10)
        return "ok"

    registry.register(name="route_hold_gate", toolset="routeprobe",
                      schema={"name": "route_hold_gate", "description": "gate",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=gate, scope=first.scope_key)
    result = []
    worker = threading.Thread(target=lambda: result.append(
        registry.dispatch("route_hold", {}, scope=first.scope_key, route_claim=claim)))
    try:
        worker.start()
        assert entered.wait(10)
        host = first._plugin_host()
        with host._route_lock:
            token, cap = next(iter(host._route_caps.items()))
        assert host._check_route_cap({"handle": token, "operation": "tool-current",
                                      "coordinates": cap.coordinates}, cap.request_id) is True
        foreign = json.loads(registry.dispatch(
            "route_check_foreign", {"handle": token, "coordinates": cap.coordinates},
            scope=second.scope_key))
        assert foreign == {"accepted": False}
        assert first.unload("routeprobe") is True
        assert host._check_route_cap({"handle": token, "operation": "tool-current",
                                      "coordinates": cap.coordinates}, cap.request_id) is False
    finally:
        release.set()
        worker.join(timeout=10)
        registry.deregister("route_hold_gate", scope=first.scope_key)
        first.unload()
        second.unload()
        first._plugin_host().shutdown()
        second._plugin_host().shutdown()
    assert not worker.is_alive()
    assert json.loads(result[0]) == {"before": True, "after": False}


@pytest.mark.platforms("posix")
def test_route_cap_from_crashed_host_cannot_be_replayed_after_restart(tmp_path, monkeypatch):
    from gateway.route_claim import RouteClaim
    from tools.registry import registry

    _home_with_plugins(tmp_path, monkeypatch, {"routeprobe": ROUTE_PLUGIN})
    manager = PluginManager()
    manager.discover_and_load()
    claim = RouteClaim("gateway", manager.scope_key, "route", "native", "epoch-1", "owner-1",
                       object(), lambda _claim: True, lambda _claim: True)
    captured = []
    registry.register(name="route_token_capture", toolset="routeprobe",
                      schema={"name": "route_token_capture", "description": "capture",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=lambda args: captured.append(args["handle"]) or "ok",
                      scope=manager.scope_key)
    host = manager._plugin_host()
    try:
        assert "plugin host" in registry.dispatch("route_crash", {}, scope=manager.scope_key,
                                                   route_claim=claim)
        assert len(captured) == 1
        coordinates = {name: getattr(claim, name) for name in (
            "surface", "profile_home_key", "session_key", "native_session_id",
            "route_epoch", "host_owner_id")}
        assert host._check_route_cap({"handle": captured[0], "operation": "tool-current",
                                      "coordinates": coordinates}, None) is False
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            replay = registry.dispatch("route_inspect", {}, scope=manager.scope_key,
                                       route_claim=claim)
            if '"current": true' in replay:
                break
            time.sleep(0.2)
        assert '"current": true' in replay
        assert host._check_route_cap({"handle": captured[0], "operation": "tool-current",
                                      "coordinates": coordinates}, None) is False
    finally:
        registry.deregister("route_token_capture", scope=manager.scope_key)
        manager.unload()
        host.shutdown()


@pytest.mark.platforms("posix")  # os._exit / SIGKILL process semantics
def test_plugin_runs_out_of_process_with_ctx_round_trips_and_survives_host_crash(tmp_path, monkeypatch):
    from agent import image_gen_registry
    from agent.image_gen_provider import ImageGenProvider
    from tools.registry import registry

    _home_with_plugins(tmp_path, monkeypatch, {"hostprobe": PROBE_PLUGIN, "platformprobe": PLATFORM_PLUGIN})
    manager = PluginManager()
    manager.discover_and_load()
    try:
        # The plugin's code never entered this interpreter, yet its registrations are ordinary.
        assert not any("hostprobe" in name for name in sys.modules)
        assert manager._plugins["hostprobe"].error is None
        first = json.loads(registry.dispatch("hostprobe_pid", {"x": 1}, scope=manager.scope_key))
        host_pid = first["pid"]
        assert host_pid != os.getpid()
        # A handler calling back into Hermes while Hermes waits on it (nested ctx.dispatch_tool).
        nested = json.loads(registry.dispatch("hostprobe_nested", {}, scope=manager.scope_key))
        assert nested["pid"] == host_pid and nested["x"] == "nested"
        # Hooks fire in the host; provider objects arrive as instances of the ABC Hermes checks.
        manager.invoke_hook("post_tool_call", tool_name="read_file", args={}, result="ok")
        assert "read_file" in json.loads(registry.dispatch("hostprobe_pid", {}, scope=manager.scope_key))["seen"]
        painter = image_gen_registry.get_provider("hostpainter")
        assert isinstance(painter, ImageGenProvider)
        assert painter.generate("cat") == {"success": True, "image": f"cat@{host_pid}"}
        # Live-object ctx surfaces fail the plugin with the boundary's reason, not a crash.
        assert "register_platform" in str(manager._plugins["platformprobe"].error)

        # A plugin killing its host costs one tool error; Hermes keeps running and the host restarts.
        crashed = registry.dispatch("hostprobe_crash", {}, scope=manager.scope_key)
        assert "plugin host" in crashed
        deadline, result = time.monotonic() + 15, ""
        while time.monotonic() < deadline:
            result = registry.dispatch("hostprobe_pid", {}, scope=manager.scope_key)
            if '"pid"' in result:
                break
            time.sleep(0.2)
        assert json.loads(result)["pid"] not in {host_pid, os.getpid()}
    finally:
        manager.unload()
        manager._plugin_host().shutdown()


@pytest.mark.platforms("any")  # the host is a child process: its env/home resolution is per-OS
def test_isolation_host_keeps_every_user_import_path_out_of_process(tmp_path, monkeypatch):
    from hermes_cli.plugin_isolation_audit import audit_plugin_dir
    from plugins import plugin_loader

    home = _home_with_plugins(tmp_path, monkeypatch, {"platformprobe": PLATFORM_PLUGIN, "fine": PROBE_PLUGIN})
    # Category loaders' in-process import refuses user code under host isolation (the backstop
    # behind the memory / context-engine / cron host routes).
    import logging
    assert plugin_loader.load_plugin_module(
        "_hermes_user_x.fine", home / "plugins" / "fine", parents=("_hermes_user_x",),
        logger=logging.getLogger("t"), synthetic_namespace="_hermes_user_x") is None
    assert "_hermes_user_x.fine" not in sys.modules
    # The static audit reads the same boundary table the host enforces.
    assert audit_plugin_dir(home / "plugins" / "fine").verdict == "host"
    blocked = audit_plugin_dir(home / "plugins" / "platformprobe")
    assert blocked.verdict == "in_process" and "register_platform" in blocked.reasons[0]



def test_managed_scope_pins_host_isolation_over_the_profiles_own_config(tmp_path, monkeypatch):
    """The isolated party must not be able to opt out: an operator pin in the managed scope
    (/etc/hermes/config.yaml) wins over a profile config that says in_process."""
    from hermes_cli import managed_scope
    from tools.registry import registry

    _home_with_plugins(tmp_path, monkeypatch, {"hostprobe": PROBE_PLUGIN}, isolation="in_process")
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "config.yaml").write_text(yaml.safe_dump({"plugins": {"isolation": "host"}}), encoding="utf-8")
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    managed_scope.invalidate_managed_cache()
    manager = PluginManager()
    manager.discover_and_load()
    try:
        assert not any("hostprobe" in name for name in sys.modules)
        result = json.loads(registry.dispatch("hostprobe_pid", {}, scope=manager.scope_key))
        assert result["pid"] != os.getpid()
    finally:
        host = getattr(manager, "_plugin_host_instance", None)
        if host is not None:
            host.shutdown()
        managed_scope.invalidate_managed_cache()

MODEL_PROVIDER_PLUGIN = '''
import os
from providers import register_provider
from providers.base import ProviderProfile

class HostModel(ProviderProfile):
    def build_extra_body(self, *, session_id=None, **context):
        return {"pid": os.getpid(), "session_id": session_id}

register_provider(HostModel(name="hostmodel", base_url="https://hostmodel.example/v1", env_vars=("HOSTMODEL_KEY",)))
'''


@pytest.mark.platforms("any")  # the host is a child process: its env/home resolution is per-OS
def test_model_provider_profile_data_is_local_and_overrides_run_in_the_host(tmp_path, monkeypatch):
    import providers

    home = _home_with_plugins(tmp_path, monkeypatch, {})
    plugin_dir = home / "plugins" / "model-providers" / "hostmodel"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.yaml").write_text("name: hostmodel\nkind: model-provider\n", encoding="utf-8")
    (plugin_dir / "__init__.py").write_text(MODEL_PROVIDER_PLUGIN, encoding="utf-8")
    profile = providers.get_provider_profile("hostmodel")
    try:
        assert isinstance(profile, providers.ProviderProfile)
        # Discovery never started a host: data came from the cached, credential-free extraction.
        assert profile.base_url == "https://hostmodel.example/v1" and tuple(profile.env_vars) == ("HOSTMODEL_KEY",)
        assert list((home / "cache" / "plugin_host" / "model-providers").glob("hostmodel-*.json"))
        assert not any("hostmodel" in name for name in sys.modules)
        body = profile.build_extra_body(session_id="s1")
        assert body["session_id"] == "s1" and body["pid"] != os.getpid()
    finally:
        host = getattr(plugins_mod.get_plugin_manager(), "_plugin_host_instance", None)
        if host is not None:
            host.shutdown()


ASYNC_PLUGIN = '''
import asyncio, json
S = {"type": "object", "properties": {}}

def register(ctx):
    async def whoami(args, **kw):  # async plugin code calling back into Hermes
        return json.dumps({"inner": json.loads(ctx.dispatch_tool("session_probe", {})),
                           "acomplete_awaitable": asyncio.iscoroutinefunction(ctx.llm.acomplete)})
    ctx.register_tool(name="async_whoami", toolset="asyncprobe", schema={"name": "async_whoami",
        "description": "d", "parameters": S}, handler=whoami, is_async=True)
'''


@pytest.mark.platforms("any")  # the host is a child process: its env/home resolution is per-OS
def test_async_plugin_code_calls_back_in_the_callers_session(tmp_path, monkeypatch):
    import contextvars
    from tools.registry import registry

    session = contextvars.ContextVar("session", default="<unset>")
    session.set("host-creator")  # whoever first touches the host must not leak into later calls
    registry.register(name="session_probe", toolset="asyncprobe", schema={"name": "session_probe",
                      "description": "d", "parameters": {"type": "object", "properties": {}}},
                      handler=lambda args, **kw: json.dumps({"session": session.get()}))
    _home_with_plugins(tmp_path, monkeypatch, {"asyncprobe": ASYNC_PLUGIN})
    manager = PluginManager()
    manager.discover_and_load()
    try:
        def call_as(name):
            def run():
                session.set(name)
                return json.loads(registry.dispatch("async_whoami", {}, scope=manager.scope_key))
            return contextvars.copy_context().run(run)

        assert call_as("session-B") == {"inner": {"session": "session-B"}, "acomplete_awaitable": True}
        assert call_as("session-C")["inner"] == {"session": "session-C"}
    finally:
        registry.deregister("session_probe")
        manager.unload()
        manager._plugin_host().shutdown()


MEMORY_PLUGIN = '''
import os
from agent.memory_provider import MemoryProvider

class Probe(MemoryProvider):
    level = 0  # a class-level default the provider changes later
    @property
    def name(self): return "memprobe"
    def is_available(self): return True
    def initialize(self, session_id, **kw): pass
    def get_tool_schemas(self): return []
    def whoami(self):
        self.level += 1
        return os.getpid()

def register(ctx):
    ctx.register_memory_provider(Probe())
'''


MEMORY_ROUTE_PLUGIN = '''
import json
from pathlib import Path
from agent.memory_provider import MemoryProvider

class Probe(MemoryProvider):
    @property
    def name(self): return "memprobe"
    def is_available(self): return True
    def initialize(self, session_id, **kw): pass
    def get_tool_schemas(self): return []

def register(ctx):
    ctx.register_memory_provider(Probe())
    ctx.register_tool(name="memory_route_tool", toolset="memprobe",
                      schema={"name": "memory_route_tool", "description": "route probe",
                              "parameters": {"type": "object", "properties": {}}},
                      handler=lambda args, route_claim=None: json.dumps({
                          "current": route_claim.is_current(),
                          "route_current": route_claim.is_route_current()}))
    def on_reset(route_claim=None, route_is_current=None, **kwargs):
        Path(__file__).with_name("route-observed.json").write_text(json.dumps({
            "route_current": route_claim.is_route_current(),
            "tool_current": route_claim.is_current(),
            "guard_current": route_is_current(),
            "private_absent": not hasattr(route_claim, "_proof"),
        }), encoding="utf-8")
    ctx.register_hook("on_session_reset", on_reset)
'''


@pytest.mark.platforms("any")
def test_memory_only_host_hook_gets_parent_checked_lifecycle_claim(tmp_path, monkeypatch):
    from gateway.route_claim import RouteClaim
    from hermes_cli.plugin_host_wire import PluginHostUnsupported
    from hermes_cli.plugins_ledger import PluginRegistration
    from plugins.memory import load_memory_provider
    from tools.registry import registry

    home = _home_with_plugins(tmp_path, monkeypatch, {})
    provider_dir = home / "plugins" / "memprobe"
    provider_dir.mkdir(parents=True)
    (provider_dir / "__init__.py").write_text(MEMORY_ROUTE_PLUGIN, encoding="utf-8")
    observed = provider_dir / "route-observed.json"
    manager = plugins_mod.get_plugin_manager()
    host = manager._plugin_host()
    owner = object()
    try:
        assert load_memory_provider("memprobe").name == "memprobe"
        assert "memprobe" not in manager._plugins  # loaded by category, not general plugin discovery
        tool_claim = RouteClaim("gateway", manager.scope_key, "route", "native", "epoch-1", "owner-1",
                                object(), lambda _claim: True, lambda _claim: True)
        assert json.loads(registry.dispatch("memory_route_tool", {}, scope=manager.scope_key,
                                            route_claim=tool_claim)) == {
            "current": True, "route_current": False}
        manager.set_keyed_lifecycle_host("gateway", owner, "owner-1")
        current = {"route": True}
        claim = RouteClaim("gateway", manager.scope_key, "route", "native", "epoch-1", "owner-1",
                           object(), lambda _claim: False, lambda _claim: current["route"])
        assert manager.notify_keyed_session_reset(
            "gateway", owner, session_key="route", session_id="native", route_epoch="epoch-1",
            old_session_id="old", old_route_epoch="epoch-0", route_claim=claim,
            route_is_current=lambda: current["route"],
        ) is True
        assert json.loads(observed.read_text(encoding="utf-8")) == {
            "route_current": True, "tool_current": False,
            "guard_current": True, "private_absent": True}
        ref, (key, registration) = next(
            (ref, owned) for ref, owned in host._registered_refs.items()
            if owned[0] == "register_memory_provider:memprobe")
        impostor = PluginRegistration("hook", "on_session_reset", lambda: None, plugin_key="memprobe")
        host._registered_refs[ref] = (key, impostor)
        try:
            with pytest.raises(PluginHostUnsupported, match="outside this plugin host scope"):
                host._issue_route_cap(ref, {"route_claim": claim, "route_is_current": lambda: True},
                                      host._generation)
        finally:
            host._registered_refs[ref] = (key, registration)
        foreign = RouteClaim("gateway", "foreign-profile", "route", "native", "epoch-1", "owner-1",
                             object(), lambda _claim: False, lambda _claim: True)
        with pytest.raises(PluginHostUnsupported, match="outside this plugin host scope"):
            host._issue_route_cap(ref, {"route_claim": foreign, "route_is_current": lambda: True},
                                  host._generation)
        current["route"] = False
        assert manager.notify_keyed_session_reset(
            "gateway", owner, session_key="route", session_id="native", route_epoch="epoch-1",
            old_session_id="old", old_route_epoch="epoch-0", route_claim=claim,
            route_is_current=lambda: current["route"],
        ) is False
    finally:
        manager.unload()
        host.shutdown()


@pytest.mark.platforms("posix")  # SIGKILL
def test_hosted_memory_provider_stays_live_across_a_host_crash(tmp_path, monkeypatch):
    import signal
    from plugins.memory import load_memory_provider
    from plugins.memory.config_schema import get_provider_config_schema

    home = _home_with_plugins(tmp_path, monkeypatch, {})
    provider_dir = home / "plugins" / "memprobe"
    provider_dir.mkdir(parents=True)
    (provider_dir / "__init__.py").write_text(MEMORY_PLUGIN, encoding="utf-8")
    marker = tmp_path / "schema_pid"
    (provider_dir / "config_schema.py").write_text(
        f"import os, pathlib\npathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\nCONFIG_SCHEMA = None\n",
        encoding="utf-8")
    host = plugins_mod.get_plugin_manager()._plugin_host()
    try:
        provider = load_memory_provider("memprobe")
        first_pid = provider.whoami()
        assert first_pid == host.pid != os.getpid()
        assert provider.level == 1  # read live from the plugin's object, not the class default
        # The provider's schema file is user code too: it runs in the host, never here.
        get_provider_config_schema("memprobe")
        assert int(marker.read_text(encoding="utf-8-sig")) == host.pid

        os.kill(first_pid, signal.SIGKILL)  # windows-footgun: ok — posix-only test (platforms marker)
        deadline = time.monotonic() + 10
        while host.alive and time.monotonic() < deadline:
            time.sleep(0.1)
        # The proxy Hermes already holds reloads the provider into the new host on next use.
        assert provider.whoami() not in {first_pid, os.getpid()}
    finally:
        host.shutdown()
