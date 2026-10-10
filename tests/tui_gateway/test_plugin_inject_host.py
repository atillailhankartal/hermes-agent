"""A plugin enters only its exact live TUI/Desktop route and gets an admission receipt."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import hermes_yaml as yaml
import pytest

from hermes_cli.plugins import LoadedPlugin, PluginContext, PluginManager, PluginManifest
from tui_gateway import server


class _Transport:
    _closed = False

    def write(self, _message):
        return True


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text(yaml.safe_dump({
        "plugins": {"enabled": ["notify-plugin"],
                    "entries": {"notify-plugin": {"allow_tui_injection": True}}},
    }), encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(server, "_hermes_home", home)
    monkeypatch.setattr(server, "_sessions", {})
    monkeypatch.setattr(server, "_load_dashboard_process_isolation_config", lambda: {})
    manifest = PluginManifest(name="notify-plugin", key="notify-plugin", source="user")
    manager = PluginManager(scope_key=str(home.resolve()))
    manager._plugins["notify-plugin"] = LoadedPlugin(manifest, enabled=True)
    context = PluginContext(manifest, manager)
    session = {
        "agent": SimpleNamespace(session_id="native-a"),
        "session_key": "key-a", "profile_home": str(home), "source": "tui",
        "transport": _Transport(), "history_lock": threading.Lock(),
        "history": [], "history_version": 0, "running": True,
        "attached_images": [], "last_active": 1.0,
    }
    server._sessions["ui-a"] = session
    server.install_tui_message_injector(manager)
    try:
        yield context, manager, session
    finally:
        server.clear_tui_message_injector(manager)
        server._release_active_session_slot(session)


def _deliver(context, *, content="Bee delivery 7", **kwargs):
    return context.inject_message(
        content, surface="tui", session_key=kwargs.get("session_key", "key-a"),
        expected_session_id=kwargs.get("expected_session_id", "native-a"),
        route_claim=kwargs.get("route_claim"),
    )


def _wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.01)
    return predicate()


def test_tui_injector_slot_does_not_replace_the_gateway_slot(runtime):
    _context, manager, _session = runtime
    gateway = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), gateway)
    assert manager.has_tui_message_injector is True
    assert manager.inject_gateway_message(session_key="gateway-key") is True
    manager.clear_tui_message_injector(object())
    assert manager.has_tui_message_injector is True
    assert manager.inject_gateway_message(session_key="kept") is True
    assert gateway.call_count == 2


def test_reported_key_queues_exact_native_route_without_gateway_fallback(runtime):
    context, manager, session = runtime
    gateway = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), gateway)
    server._sessions["ui-b"] = {**session, "session_key": "key-b",
                                "agent": SimpleNamespace(session_id="native-b"),
                                "history_lock": threading.Lock(), "queued_prompt": None}
    assert _deliver(context) is True
    assert session["queued_prompt"]["text"] == "Bee delivery 7"
    assert session["queued_prompt"]["plugin_origin"] == "notify-plugin"
    assert server._sessions["ui-b"].get("queued_prompt") is None
    gateway.assert_not_called()


def test_unknown_key_or_native_id_is_rejected_without_gateway_fallback(runtime):
    context, manager, session = runtime
    gateway = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), gateway)
    assert _deliver(context, session_key="gone") is False
    assert _deliver(context, expected_session_id="wrong") is False
    assert session.get("queued_prompt") is None
    gateway.assert_not_called()


def test_default_gateway_and_cli_routes_remain_separate(runtime):
    context, manager, session = runtime
    gateway = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), gateway)
    # Gateway requires its own grant, even when TUI has one.
    assert context.inject_message("wake", surface="gateway", session_key="chat") is False
    assert session.get("queued_prompt") is None
    pending = []
    manager._cli_ref = SimpleNamespace(
        _agent_running=False, _pending_input=SimpleNamespace(put=pending.append),
        _interrupt_queue=SimpleNamespace(put=lambda _value: None))
    assert context.inject_message("typed", session_key="key-a") is True
    assert pending == ["typed"]
    assert session.get("queued_prompt") is None


def test_explicit_gateway_surface_keeps_its_own_positive_path(runtime):
    context, manager, session = runtime
    home = manager.home_path
    (home / "config.yaml").write_text(yaml.safe_dump({
        "plugins": {"enabled": ["notify-plugin"], "entries": {
            "notify-plugin": {"allow_tui_injection": True, "allow_gateway_injection": True}}},
    }), encoding="utf-8")
    gateway = MagicMock(return_value=True)
    manager.set_gateway_message_injector(object(), gateway)
    assert context.inject_message("wake", surface="gateway", session_key="chat") is True
    gateway.assert_called_once_with(session_key="chat", content="wake", plugin_id="notify-plugin")
    assert session.get("queued_prompt") is None


def test_idle_route_admits_queue_candidate_then_drains_without_human_images(runtime, monkeypatch):
    _context, manager, session = runtime
    fired = {}
    drained = {}
    session["running"] = False
    session["attached_images"] = ["/tmp/human-draft.png"]
    monkeypatch.setattr(server, "_session_uses_compute_host", lambda _session: False)
    monkeypatch.setattr(server, "_run_prompt_submit", lambda _rid, sid, _session, text, **kw:
                        fired.update(sid=sid, text=text, images=kw.get("image_paths")))
    real_drain = server._drain_queued_prompt

    def observed_drain(rid, sid, target):
        with target["history_lock"]:
            drained["candidate_id"] = target["queued_prompt"]["plugin_candidate_id"]
        return real_drain(rid, sid, target)

    monkeypatch.setattr(server, "_drain_queued_prompt", observed_drain)
    receipt = _receipt(manager)
    assert receipt.status == "admitted"
    # The accepted queue row may spend several seconds in a state.db WAL-holder
    # scan before the drain can acquire history_lock; admission is the insertion.
    assert _wait_until(lambda: fired.get("text") == "Bee delivery 7", timeout=30)
    assert drained["candidate_id"] == receipt.candidate_id
    assert fired == {"sid": "ui-a", "text": "Bee delivery 7", "images": []}
    assert session["attached_images"] == ["/tmp/human-draft.png"]


@pytest.mark.parametrize("change", ["profile", "source", "closed", "duplicate", "native", "generation"])
def test_stale_or_foreign_route_never_gets_candidate(runtime, monkeypatch, change):
    context, manager, session = runtime
    def foreign_profile():
        other = manager.home_path / "other"
        other.mkdir()
        session["profile_home"] = str(other)

    mutations = {
        "profile": foreign_profile,
        "source": lambda: session.update(source="gateway"),
        "closed": lambda: session.update(_closing=True),
        "duplicate": lambda: server._sessions.update(
            {"ui-b": {**session, "history_lock": threading.Lock()}}),
        "native": lambda: setattr(session["agent"], "session_id", "native-b"),
    }
    if change == "generation":
        original = server._ensure_active_session_slot

        def rotate_during_claim(sid, target, **kwargs):
            session["_queued_prompt_generation"] = 1
            return original(sid, target, **kwargs)

        monkeypatch.setattr(server, "_ensure_active_session_slot", rotate_during_claim)
    else:
        mutations[change]()
    assert _deliver(context) is False
    assert session.get("queued_prompt") is None


@pytest.mark.parametrize("bee_first", [True, False])
def test_busy_bee_and_human_prompts_keep_fifo_provenance_and_images(runtime, bee_first):
    context, _manager, session = runtime
    session["attached_images"] = ["/tmp/human-draft.png"]
    if bee_first:
        assert _deliver(context) is True
        assert server._enqueue_prompt(session, "human follow-up", session["transport"]) is not None
    else:
        assert server._enqueue_prompt(session, "human follow-up", session["transport"]) is not None
        assert _deliver(context) is True
    envelopes = [session["queued_prompt"], *(session.get("queued_prompts") or [])]
    assert [e["text"] for e in envelopes] == (
        ["Bee delivery 7", "human follow-up"] if bee_first
        else ["human follow-up", "Bee delivery 7"])
    bee = next(e for e in envelopes if e["text"] == "Bee delivery 7")
    human = next(e for e in envelopes if e["text"] == "human follow-up")
    assert bee["plugin_origin"] == "notify-plugin"
    assert bee["image_paths"] == []
    assert "plugin_origin" not in human
    assert session["attached_images"] == ["/tmp/human-draft.png"]


def test_plugin_copy_of_inflight_human_text_keeps_its_candidate_and_no_images(runtime):
    context, _manager, session = runtime
    session["inflight_turn"] = {
        "user": "same text", "assistant": "", "streaming": True, "error": "",
    }
    session["attached_images"] = ["/tmp/human-draft.png"]

    assert _deliver(context, content="same text") is True
    queued = session["queued_prompt"]
    assert queued["text"] == "same text"
    assert queued["plugin_origin"] == "notify-plugin"
    assert queued["plugin_candidate_id"]
    assert queued["image_paths"] == []
    assert session["attached_images"] == ["/tmp/human-draft.png"]


def test_ignored_enqueue_and_unsupported_claim_have_no_receipt(runtime, monkeypatch):
    context, _manager, session = runtime
    assert _deliver(context, route_claim={"epoch": "not-host-issued"}) is False
    monkeypatch.setattr(server, "_enqueue_prompt", lambda *_args, **_kwargs: None)
    assert _deliver(context) is False
    assert session.get("queued_prompt") is None


def test_cold_child_without_native_attestation_has_no_receipt(runtime):
    context, _manager, session = runtime
    session["agent"] = None
    assert _deliver(context, expected_session_id="key-a") is False
    assert session.get("queued_prompt") is None


def test_idle_candidate_is_rejected_when_drain_reservation_fails(runtime, monkeypatch):
    context, _manager, session = runtime
    session["running"] = False
    monkeypatch.setattr(server, "_start_session_work", lambda *_args, **_kwargs: None)
    assert _deliver(context) is False
    assert session.get("queued_prompt") is None


def test_revoked_registry_lease_cannot_admit_another_candidate(runtime):
    context, _manager, session = runtime
    assert _deliver(context) is True
    first = session["queued_prompt"]
    session["active_session_lease"].release()
    assert _deliver(context, content="another delivery") is False
    assert session["queued_prompt"] is first


def _receipt(manager, **kwargs):
    return server.admit_tui_session_message(
        manager=manager, session_key=kwargs.get("session_key", "key-a"),
        expected_session_id=kwargs.get("expected_session_id", "native-a"),
        content=kwargs.get("content", "Bee delivery 7"), plugin_id="notify-plugin",
        delivery_id=kwargs.get("delivery_id", "bee-delivery-7"),
        route_claim=kwargs.get("route_claim"),
        timeout_seconds=kwargs.get("timeout_seconds", 5.0),
    )


def test_receipt_names_exact_inserted_candidate_and_delivery(runtime):
    _context, manager, session = runtime
    receipt = _receipt(manager)
    assert receipt.status == "admitted"
    assert receipt.reason == "candidate_inserted"
    assert receipt.delivery_id == "bee-delivery-7"
    assert session["queued_prompt"]["plugin_candidate_id"] == receipt.candidate_id
    assert session["queued_prompt"]["plugin_delivery_id"] == receipt.delivery_id


def test_pre_admission_denials_and_noop_are_definite_rejections(runtime, monkeypatch):
    _context, manager, session = runtime
    wrong = _receipt(manager, expected_session_id="foreign")
    claim = _receipt(manager, route_claim={"epoch": "foreign"})
    monkeypatch.setattr(server, "_enqueue_prompt", lambda *_args, **_kwargs: None)
    noop = _receipt(manager)
    assert (wrong.status, wrong.reason) == ("rejected", "route_not_current")
    assert (claim.status, claim.reason) == ("rejected", "host_epoch_unavailable")
    assert (noop.status, noop.reason) == ("rejected", "candidate_not_inserted")
    assert session.get("queued_prompt") is None


def test_idle_drain_reservation_failure_is_definite_rejection(runtime, monkeypatch):
    _context, manager, session = runtime
    session["running"] = False
    monkeypatch.setattr(server, "_start_session_work", lambda *_args, **_kwargs: None)
    receipt = _receipt(manager)
    assert (receipt.status, receipt.reason) == ("rejected", "drain_not_reserved")
    assert session.get("queued_prompt") is None


def test_timeout_is_unknown_even_if_candidate_later_lands(runtime, monkeypatch):
    _context, manager, session = runtime
    entered, release = threading.Event(), threading.Event()
    original = server._enqueue_prompt

    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(5), "release the delayed insertion"
        return original(*args, **kwargs)

    monkeypatch.setattr(server, "_enqueue_prompt", delayed)
    result = []
    caller = threading.Thread(target=lambda: result.append(_receipt(manager, timeout_seconds=0.2)))
    try:
        caller.start()
        assert entered.wait(10), "admission worker did not reach queue insertion"
        caller.join(5)
        assert not caller.is_alive()
        receipt = result[0]
        assert (receipt.status, receipt.reason) == ("unknown", "admission_timeout")
    finally:
        release.set()
    assert _wait_until(lambda: session.get("queued_prompt") is not None)
    assert session["queued_prompt"]["plugin_candidate_id"] == receipt.candidate_id
    assert session["queued_prompt"]["plugin_delivery_id"] == receipt.delivery_id


def test_enqueue_exception_after_possible_mutation_is_unknown(runtime, monkeypatch):
    _context, manager, session = runtime

    def partial(*_args, **_kwargs):
        session["queued_prompt"] = {"text": "possibly inserted", "transport": session["transport"]}
        raise RuntimeError("interrupted after mutation")

    monkeypatch.setattr(server, "_enqueue_prompt", partial)
    receipt = _receipt(manager)
    assert (receipt.status, receipt.reason) == ("unknown", "admission_exception")
    assert session["queued_prompt"]["text"] == "possibly inserted"


def _direct_admit(manager, candidate_id, publish):
    server._admit_tui_candidate(
        manager=manager, session_key="key-a", expected_session_id="native-a",
        content=candidate_id, plugin_id="notify-plugin", route_claim=None,
        candidate_id=candidate_id, delivery_id=f"delivery-{candidate_id}", publish=publish,
    )


def _assert_candidate_can_drain(monkeypatch, session, candidate_id):
    from hermes_cli.active_sessions import active_session_registry_snapshot

    lease = session["active_session_lease"]
    fired = {}
    monkeypatch.setattr(server, "_session_uses_compute_host", lambda _session: False)
    monkeypatch.setattr(server, "_run_prompt_submit", lambda _rid, sid, _session, text, **kw:
                        fired.update(sid=sid, text=text, images=kw.get("image_paths")))
    assert server._drain_queued_prompt("race-drain", "ui-a", session) is True
    assert fired == {"sid": "ui-a", "text": candidate_id, "images": []}
    assert session["active_session_lease"] is lease and not lease.released
    assert any(row["lease_id"] == lease.lease_id for row in
               active_session_registry_snapshot(session["profile_home"], strict=True))
    assert server._release_active_session_slot(session) is True
    assert lease.released
    assert not any(row["lease_id"] == lease.lease_id for row in
                   active_session_registry_snapshot(session["profile_home"], strict=True))


def test_rejected_waiter_cannot_release_admitted_candidates_lease(runtime, monkeypatch):
    """The waiter snapshots no lease, but must not own the lease another turn creates."""
    from hermes_cli.active_sessions import active_session_registry_snapshot

    _context, manager, session = runtime
    session["running"] = False
    monkeypatch.setattr(server, "_start_session_work", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(server, "_persist_queued_user_row", lambda *_args, **_kwargs: None)
    real_ensure = server._ensure_active_session_slot
    real_grant = manager._tui_injection_allowed
    waiter_at_ensure, release_waiter, accepted = threading.Event(), threading.Event(), threading.Event()
    receipts = {"accepted": [], "waiter": []}
    waiter_grants = []

    def gated_ensure(sid, target, **kwargs):
        if threading.current_thread().name == "race-waiter":
            waiter_at_ensure.set()
            assert release_waiter.wait(5), "release the waiting admission"
        return real_ensure(sid, target, **kwargs)

    def grant(plugin_id):
        if threading.current_thread().name == "race-waiter":
            waiter_grants.append(plugin_id)
            return len(waiter_grants) == 1
        return real_grant(plugin_id)

    monkeypatch.setattr(server, "_ensure_active_session_slot", gated_ensure)
    monkeypatch.setattr(manager, "_tui_injection_allowed", grant)
    waiter = threading.Thread(target=lambda: _direct_admit(manager, "waiter", receipts["waiter"].append),
                              name="race-waiter")
    first = threading.Thread(target=lambda: _direct_admit(
        manager, "accepted", lambda receipt: (receipts["accepted"].append(receipt), accepted.set())),
        name="race-accepted")
    try:
        waiter.start()
        assert waiter_at_ensure.wait(5)
        assert session.get("active_session_lease") is None
        first.start()
        # The reviewed implementation admits `first` during this wait. A fixed
        # implementation may serialize acquisition, so release the waiter at
        # the bound even when `first` has not yet completed.
        accepted.wait(2)
    finally:
        release_waiter.set()
        waiter.join(10)
        if first.ident is not None:
            first.join(10)

    assert not waiter.is_alive() and not first.is_alive()
    assert (receipts["accepted"][0].status, receipts["waiter"][0].status) == ("admitted", "rejected")
    assert receipts["waiter"][0].reason == "route_changed_before_insert"
    assert session["queued_prompt"]["plugin_candidate_id"] == "accepted"
    lease = session.get("active_session_lease")
    assert lease is not None and not lease.released
    assert any(row["lease_id"] == lease.lease_id and row["session_id"] == "key-a"
               for row in active_session_registry_snapshot(manager.home_path, strict=True))
    _assert_candidate_can_drain(monkeypatch, session, "accepted")


def test_rejected_lease_creator_cannot_release_borrowers_candidate(runtime, monkeypatch):
    """A creator rejected after a borrower admits must keep the borrower's fence."""
    from hermes_cli import input_sanitize
    from hermes_cli.active_sessions import active_session_registry_snapshot

    _context, manager, session = runtime
    session["running"] = False
    monkeypatch.setattr(server, "_start_session_work", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(server, "_persist_queued_user_row", lambda *_args, **_kwargs: None)
    real_sanitize = input_sanitize.sanitize_user_prompt_text
    creator_at_sanitize, release_creator = threading.Event(), threading.Event()
    receipts = {"creator": [], "borrower": []}

    def gated_sanitize(content):
        if threading.current_thread().name == "race-creator":
            creator_at_sanitize.set()
            assert release_creator.wait(5), "release the original lease claimant"
        return real_sanitize(content)

    monkeypatch.setattr(input_sanitize, "sanitize_user_prompt_text", gated_sanitize)
    creator = threading.Thread(target=lambda: _direct_admit(manager, "creator", receipts["creator"].append),
                               name="race-creator")
    creator.start()
    try:
        assert creator_at_sanitize.wait(5)
        lease = session["active_session_lease"]
        _direct_admit(manager, "borrower", receipts["borrower"].append)
        assert receipts["borrower"][0].status == "admitted"
        assert session["queued_prompt"]["plugin_candidate_id"] == "borrower"
        # This changes the exact native route after the creator observed it.
        session["agent"].session_id = "native-b"
    finally:
        release_creator.set()
        creator.join(10)
        session["agent"].session_id = "native-a"

    assert not creator.is_alive()
    assert (receipts["creator"][0].status, receipts["creator"][0].reason) == (
        "rejected", "route_changed_before_insert")
    assert session.get("active_session_lease") is lease and not lease.released
    assert any(row["lease_id"] == lease.lease_id and row["session_id"] == "key-a"
               for row in active_session_registry_snapshot(manager.home_path, strict=True))
    _assert_candidate_can_drain(monkeypatch, session, "borrower")


def test_human_slot_claim_and_plugin_admission_share_one_exact_lease(runtime, monkeypatch):
    """A human claimant cannot replace a paused plugin's same-writer registry row."""
    from hermes_cli.active_sessions import active_session_registry_snapshot

    _context, manager, session = runtime
    session["running"] = False
    monkeypatch.setattr(server, "_start_session_work", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(server, "_persist_queued_user_row", lambda *_args, **_kwargs: None)
    real_claim = server._claim_active_session_slot
    plugin_at_claim, release_plugin, human_done = threading.Event(), threading.Event(), threading.Event()
    plugin_receipts, human_results = [], []

    def gated_claim(*args, **kwargs):
        if threading.current_thread().name == "race-plugin":
            plugin_at_claim.set()
            assert release_plugin.wait(5), "release the plugin's registry claim"
        return real_claim(*args, **kwargs)

    monkeypatch.setattr(server, "_claim_active_session_slot", gated_claim)
    plugin = threading.Thread(target=lambda: _direct_admit(manager, "plugin", plugin_receipts.append),
                              name="race-plugin")

    def human_claim():
        human_results.append(server._ensure_active_session_slot("ui-a", session))
        human_results.append(session.get("active_session_lease"))
        human_done.set()

    human = threading.Thread(target=human_claim, name="race-human")
    try:
        plugin.start()
        assert plugin_at_claim.wait(5)
        human.start()
        human_done.wait(2)
    finally:
        release_plugin.set()
        plugin.join(10)
        if human.ident is not None:
            human.join(10)

    assert not plugin.is_alive() and not human.is_alive()
    assert plugin_receipts[0].status == "admitted"
    assert human_results[0] is None
    lease = session["active_session_lease"]
    assert human_results[1] is lease and not lease.released
    assert any(row["lease_id"] == lease.lease_id and row["session_id"] == "key-a"
               for row in active_session_registry_snapshot(manager.home_path, strict=True))
    assert session["queued_prompt"]["plugin_candidate_id"] == "plugin"
    _assert_candidate_can_drain(monkeypatch, session, "plugin")


def test_detached_takeover_interrupt_runs_outside_slot_claim_lock(runtime, monkeypatch):
    """A refused claim may interrupt an old turn only after releasing its claim lock."""
    from hermes_cli.active_sessions import SESSION_NOT_OWNED

    _context, _manager, session = runtime
    monkeypatch.setattr(server, "_claim_active_session_slot",
                        lambda *_args, **_kwargs: (None, SimpleNamespace(reason=SESSION_NOT_OWNED)))
    observed = []

    def takeover(_sid, target, _key):
        observed.append(not target["_active_session_slot_claim_lock"].locked())
        return True

    monkeypatch.setattr(server, "_take_over_detached_runtime_lease", takeover)
    created_leases = []
    assert server._ensure_active_session_slot("ui-a", session, created_leases=created_leases) is None
    assert observed == [True]
    assert created_leases == []
