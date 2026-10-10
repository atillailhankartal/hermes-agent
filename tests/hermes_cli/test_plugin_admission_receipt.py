"""A Bee delivery is accepted only by an exact host admission receipt."""

from dataclasses import FrozenInstanceError
from dataclasses import dataclass
from contextvars import ContextVar
from threading import Event
from time import monotonic, sleep
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import hermes_yaml as yaml

from hermes_cli.plugins import (
    AdmissionReceipt, LoadedPlugin, PluginContext, PluginManager, PluginManifest,
    _reset_plugin_managers_for_tests, clear_published_admission_host,
    get_plugin_manager, publish_admission_host,
)
from hermes_constants import get_hermes_home, reset_hermes_home_override, set_hermes_home_override
from hermes_cli import plugins_injection


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


def pair(tmp_path, *, gateway=True, tui=False):
    home = tmp_path / "profile"
    home.mkdir()
    (home / "config.yaml").write_text(yaml.safe_dump({
        "plugins": {"enabled": ["bee"], "entries": {"bee": {
            "allow_gateway_injection": gateway, "allow_tui_injection": tui,
        }}},
    }), encoding="utf-8")
    manager = PluginManager(scope_key=str(home.resolve()))
    manifest = PluginManifest(name="bee", key="bee", source="user")
    manager._plugins["bee"] = LoadedPlugin(manifest, enabled=True)
    return PluginContext(manifest, manager), manager


def route(manager, surface="gateway"):
    return Claim(surface, manager.scope_key, "chat-1", "native-1", "epoch-1")


def ask(ctx, claim, delivery_id="delivery-1"):
    return ctx.inject_message_admitted(
        "wake", surface=claim.surface, route_claim=claim,
        expected_session_id=claim.native_session_id, delivery_id=delivery_id,
    )


def test_legacy_scheduler_bool_does_not_ack_and_typed_receipt_is_immutable(tmp_path):
    ctx, manager = pair(tmp_path)
    old = Mock(return_value=True)
    manager.set_gateway_message_injector(object(), old)
    receipt = ask(ctx, route(manager))
    assert receipt.state == "rejected"
    assert receipt.reason == "admission_host_unavailable"
    old.assert_not_called()
    assert ctx.inject_message("wake", surface="gateway", session_key="chat-1") is True
    old.assert_called_once()
    with pytest.raises(FrozenInstanceError):
        receipt.state = "admitted"
    with pytest.raises(TypeError):
        bool(receipt)


def test_exact_host_receipt_passes_and_wrong_results_fail_closed(tmp_path):
    ctx, manager = pair(tmp_path)
    claim = route(manager)
    owner = object()
    host = Mock(return_value=AdmissionReceipt(
        "admitted", "inserted", "delivery-1", "epoch-1", "candidate-1",
    ))
    manager.set_admission_host("gateway", owner, host, "owner-1")
    assert ask(ctx, claim).state == "admitted"
    assert host.call_count == 1
    for result in (True, None, AdmissionReceipt("admitted", "inserted", "other", "epoch-1", "candidate-1"),
                   AdmissionReceipt("admitted", "inserted", "delivery-1", "wrong", "candidate-1"),
                   AdmissionReceipt("admitted", "inserted", "delivery-1", "epoch-1", None)):
        host.return_value = result
        assert ask(ctx, claim).state == "unknown"
    host.side_effect = RuntimeError("maybe inserted")
    assert ask(ctx, claim).state == "unknown"


def test_wrong_profile_native_surface_and_stale_claim_are_rejected_before_host(tmp_path):
    ctx, manager = pair(tmp_path, tui=True)
    host = Mock(return_value=AdmissionReceipt("admitted", "inserted", "delivery-1", "epoch-1", "candidate-1"))
    manager.set_admission_host("gateway", object(), host, "owner-1")
    claim = route(manager)
    for change in ({"profile_home_key": "other"}, {"native_session_id": "other"},
                   {"surface": "tui"}, {"current": False}, {"host_owner_id": "other"}):
        candidate = Claim(**(vars(claim) | change))
        assert ctx.inject_message_admitted(
            "wake", surface="gateway", route_claim=candidate,
            expected_session_id="native-1", delivery_id="delivery-1",
        ).state == "rejected"
    assert ctx.inject_message_admitted(
        "wake", surface="gateway", route_claim={"epoch": "epoch-1"},
        expected_session_id="native-1", delivery_id="delivery-1",
    ).state == "rejected"
    host.assert_not_called()


def test_route_change_after_dispatch_is_unknown_and_callback_runs_outside_lock(tmp_path):
    ctx, manager = pair(tmp_path)
    claim = route(manager)
    owner = object()

    def host(**_kwargs):
        manager.clear_admission_host("gateway", owner)
        claim.current = False
        return AdmissionReceipt("admitted", "inserted", "delivery-1", "epoch-1", "candidate-1")

    manager.set_admission_host("gateway", owner, host, "owner-1")
    assert ask(ctx, claim).state == "unknown"


def test_host_replacement_after_dispatch_is_unknown_even_if_route_guard_lags(tmp_path):
    ctx, manager = pair(tmp_path)
    owner, successor = object(), object()

    def old_host(**_kwargs):
        manager.set_admission_host("gateway", successor, Mock(return_value=True), "owner-2")
        return AdmissionReceipt("admitted", "inserted", "delivery-1", "epoch-1", "candidate-1")

    manager.set_admission_host("gateway", owner, old_host, "owner-1")
    receipt = ask(ctx, route(manager))
    assert receipt.state == "unknown"
    assert receipt.reason == "admission_host_replaced"


def test_timeout_and_saturation_are_unknown_until_late_worker_releases_capacity(tmp_path, monkeypatch):
    ctx, manager = pair(tmp_path)
    monkeypatch.setattr("hermes_cli.plugins_injection._ADMISSION_WAIT_SECONDS", 0.01, raising=False)
    monkeypatch.setattr("hermes_cli.plugins_injection._MAX_ADMISSION_WORKERS_PER_SURFACE", 1, raising=False)
    release, completed = Event(), Event()
    called = []

    def host(**kwargs):
        called.append(kwargs["delivery_id"])
        if kwargs["delivery_id"] == "delivery-1":
            release.wait(0.2)
            completed.set()
        return AdmissionReceipt("admitted", "inserted", kwargs["delivery_id"],
                                "epoch-1", "candidate-" + kwargs["delivery_id"])

    manager.set_admission_host("gateway", object(), host, "owner-1")
    try:
        first = ask(ctx, route(manager))
        assert (first.state, first.reason) == ("unknown", "admission_timeout")
        saturated = ask(ctx, route(manager), "delivery-2")
        assert (saturated.state, saturated.reason) == ("unknown", "admission_workers_saturated")
        assert called == ["delivery-1"]
    finally:
        release.set()
    assert completed.wait(1)
    deadline = monotonic() + 1
    while monotonic() < deadline:
        with plugins_injection._admission_workers_lock:
            if not plugins_injection._admission_workers.get(manager, {}).get("gateway"):
                break
        sleep(0.001)
    else:
        pytest.fail("late host callback kept its worker capacity")
    third = ask(ctx, route(manager), "delivery-3")
    assert third.state == "admitted"
    assert called == ["delivery-1", "delivery-3"]


def test_admission_worker_preserves_task_local_context(tmp_path):
    ctx, manager = pair(tmp_path)
    marker = ContextVar("plugin_admission_marker", default="missing")
    token = marker.set("profile-token")

    def host(**kwargs):
        assert marker.get() == "profile-token"
        return AdmissionReceipt("admitted", "inserted", kwargs["delivery_id"], "epoch-1", "candidate-1")

    manager.set_admission_host("gateway", object(), host, "owner-1")
    try:
        assert ask(ctx, route(manager)).state == "admitted"
    finally:
        marker.reset(token)


def test_typed_host_callback_uses_manager_profile_when_caller_is_in_another_profile(tmp_path):
    ctx, manager = pair(tmp_path)
    other_home = tmp_path / "other-profile"
    other_home.mkdir()
    marker = ContextVar("profile-crossing-marker", default="missing")
    marker_token = marker.set("caller-context")
    seen = []

    def host(**kwargs):
        seen.append((get_hermes_home().resolve(), marker.get(), kwargs["manager"].scope_key))
        return AdmissionReceipt("admitted", "inserted", kwargs["delivery_id"], "epoch-1", "candidate-1")

    manager.set_admission_host("gateway", object(), host, "owner-1")
    home_token = set_hermes_home_override(other_home)
    try:
        receipt = ask(ctx, route(manager))
        assert get_hermes_home().resolve() == other_home.resolve()
    finally:
        reset_hermes_home_override(home_token)
        marker.reset(marker_token)
    assert receipt.state == "admitted"
    assert (receipt.admission_id, receipt.candidate_id) == ("candidate-1", "candidate-1")
    assert seen == [(manager.home_path.resolve(), "caller-context", manager.scope_key)]


def test_route_guards_use_manager_profile_before_and_after_host_dispatch(tmp_path):
    ctx, manager = pair(tmp_path)
    other_home = tmp_path / "other-profile"
    other_home.mkdir()
    claim = route(manager)
    seen = []

    def check_route():
        seen.append(get_hermes_home().resolve())
        return get_hermes_home().resolve() == manager.home_path.resolve()

    claim.is_route_current = check_route
    manager.set_admission_host(
        "gateway", object(),
        lambda **kwargs: AdmissionReceipt(
            "admitted", "inserted", kwargs["delivery_id"], "epoch-1", "candidate-1",
        ), "owner-1",
    )
    token = set_hermes_home_override(other_home)
    try:
        receipt = ask(ctx, claim)
    finally:
        reset_hermes_home_override(token)
    assert receipt.state == "admitted"
    assert len(seen) == 3
    assert seen == [manager.home_path.resolve()] * 3


@pytest.mark.parametrize("state", ["rejected", "unknown"])
def test_host_receipt_with_nonadmitted_candidate_is_unknown(tmp_path, state):
    ctx, manager = pair(tmp_path)
    manager.set_admission_host(
        "gateway", object(),
        lambda **kwargs: AdmissionReceipt(
            state, "inconsistent", kwargs["delivery_id"], "epoch-1", "candidate-maybe-inserted",
        ), "owner-1",
    )
    receipt = ask(ctx, route(manager))
    assert (receipt.state, receipt.reason, receipt.admission_id, receipt.candidate_id) == (
        "unknown", "invalid_host_receipt", None, None,
    )


def test_confirmed_insertion_then_route_revocation_remains_unknown_without_retry_proof(tmp_path):
    ctx, manager = pair(tmp_path)
    claim = route(manager)

    def host(**kwargs):
        claim.current = False
        return AdmissionReceipt("admitted", "inserted", kwargs["delivery_id"], "epoch-1", "candidate-1")

    manager.set_admission_host("gateway", object(), host, "owner-1")
    receipt = ask(ctx, claim)
    assert (receipt.state, receipt.reason, receipt.delivery_id, receipt.route_epoch) == (
        "unknown", "route_changed_after_dispatch", "delivery-1", "epoch-1",
    )
    assert receipt.admission_id is None  # Status query by this exact delivery is required before retry.


def test_worker_start_failure_is_unknown_and_releases_capacity(tmp_path, monkeypatch):
    ctx, manager = pair(tmp_path)
    host = Mock(return_value=AdmissionReceipt("admitted", "inserted", "delivery-1", "epoch-1", "candidate-1"))
    manager.set_admission_host("gateway", object(), host, "owner-1")

    def fail_start(_thread):
        raise RuntimeError("synthetic scheduler failure")

    with monkeypatch.context() as patch:
        patch.setattr(plugins_injection.threading.Thread, "start", fail_start)
        receipt = ask(ctx, route(manager))
    assert (receipt.state, receipt.reason) == ("unknown", "host_worker_start_failed")
    host.assert_not_called()
    assert ask(ctx, route(manager)).state == "admitted"


def test_worker_start_error_after_schedule_keeps_capacity_until_late_callback_finishes(tmp_path, monkeypatch):
    ctx, manager = pair(tmp_path)
    monkeypatch.setattr(plugins_injection, "_MAX_ADMISSION_WORKERS_PER_SURFACE", 1)
    entered, release, finished = Event(), Event(), Event()
    called = []

    def host(**kwargs):
        called.append(kwargs["delivery_id"])
        if kwargs["delivery_id"] == "delivery-1":
            entered.set()
            release.wait(1)
            finished.set()
        return AdmissionReceipt("admitted", "inserted", kwargs["delivery_id"],
                                "epoch-1", "candidate-" + kwargs["delivery_id"])

    manager.set_admission_host("gateway", object(), host, "owner-1")
    real_start = plugins_injection.threading.Thread.start

    def start_then_raise(thread):
        real_start(thread)
        assert entered.wait(1)
        raise RuntimeError("completion lost after scheduling")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(plugins_injection.threading.Thread, "start", start_then_raise)
            first = ask(ctx, route(manager))
        assert (first.state, first.reason) == ("unknown", "host_worker_start_failed")
        second = ask(ctx, route(manager), "delivery-2")
        assert (second.state, second.reason) == ("unknown", "admission_workers_saturated")
        assert called == ["delivery-1"]
    finally:
        release.set()
    assert finished.wait(1)
    deadline = monotonic() + 1
    while monotonic() < deadline:
        with plugins_injection._admission_workers_lock:
            if not plugins_injection._admission_workers.get(manager, {}).get("gateway"):
                break
        sleep(0.001)
    else:
        pytest.fail("late callback kept a completed capacity slot")
    assert ask(ctx, route(manager), "delivery-3").state == "admitted"


@pytest.mark.asyncio
async def test_sync_admission_api_fails_closed_on_host_event_loop(tmp_path):
    ctx, manager = pair(tmp_path)
    host = Mock(return_value=AdmissionReceipt("admitted", "inserted", "delivery-1", "epoch-1", "candidate-1"))
    manager.set_admission_host("gateway", object(), host, "owner-1")
    receipt = ask(ctx, route(manager))
    assert receipt.state == "rejected"
    assert receipt.reason == "sync_event_loop_unavailable"
    host.assert_not_called()


def test_tui_and_gateway_grants_and_slots_are_isolated(tmp_path):
    ctx, manager = pair(tmp_path, gateway=False, tui=True)
    gateway = Mock(return_value=True)
    tui = Mock(return_value=AdmissionReceipt("admitted", "inserted", "delivery-1", "epoch-1", "candidate-1"))
    manager.set_gateway_message_injector(object(), gateway)
    manager.set_admission_host("tui", object(), tui, "owner-1")
    assert ask(ctx, route(manager, "gateway")).state == "rejected"
    assert ask(ctx, route(manager, "tui")).state == "admitted"
    gateway.assert_not_called()


def test_cli_typed_slot_does_not_fall_back_to_legacy_local_queue(tmp_path):
    ctx, manager = pair(tmp_path)
    queue = Mock()
    manager._cli_ref = SimpleNamespace(_agent_running=False, _pending_input=queue)
    receipt = ask(ctx, route(manager, "cli"))
    assert (receipt.state, receipt.reason) == ("rejected", "admission_host_unavailable")
    queue.put.assert_not_called()


def test_process_publication_and_clear_are_owner_pinned(tmp_path):
    local_ctx, local_manager = pair(tmp_path)
    _reset_plugin_managers_for_tests()
    home_token = set_hermes_home_override(str(local_manager.home_path))
    manager = get_plugin_manager()
    manager._plugins["bee"] = local_manager._plugins["bee"]
    ctx = PluginContext(local_ctx.manifest, manager)
    a, b = object(), object()
    callback_a = Mock(return_value=True)
    callback_b = Mock(return_value=AdmissionReceipt("admitted", "inserted", "delivery-1", "epoch-1", "candidate-1"))
    try:
        publish_admission_host("gateway", a, callback_a, "owner-1")
        publish_admission_host("gateway", b, callback_b, "owner-1")
        clear_published_admission_host("gateway", a)
        assert ask(ctx, route(manager)).state == "admitted"
        callback_a.assert_not_called()
        callback_b.assert_called_once()
        clear_published_admission_host("gateway", b)
        assert ask(ctx, route(manager)).state == "rejected"
    finally:
        clear_published_admission_host("gateway", a)
        clear_published_admission_host("gateway", b)
        reset_hermes_home_override(home_token)
        _reset_plugin_managers_for_tests()
