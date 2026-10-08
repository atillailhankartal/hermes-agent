"""A plugin may submit only to the exact live TUI/Desktop conversation it owns."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from tui_gateway import server
from tui_gateway.plugin_injection import (
    inject_plugin_message, notify_tui_session_resumed, register_tui_plugin_injector,
)


class _Transport:
    _closed = False

    def write(self, _message):
        return True

    def close(self):
        self._closed = True


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    home = tmp_path / "hermes-a"
    home.mkdir()
    (home / "config.yaml").write_text(
        "plugins:\n  enabled: [bee-collaborate]\n  entries:\n"
        "    bee-collaborate:\n      allow_tui_injection: true\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(server, "_hermes_home", home)
    monkeypatch.setattr(server, "_sessions", {})
    monkeypatch.setattr(server, "_ensure_active_session_slot", lambda *_: None)
    monkeypatch.setattr(server, "_load_dashboard_process_isolation_config", lambda: {})
    transport = _Transport()
    session = {
        "agent": SimpleNamespace(session_id="native-a"),
        "session_key": "key-a", "profile_home": None, "source": "tui",
        "transport": transport, "history_lock": threading.Lock(),
        "running": True, "attached_images": [], "history": [],
    }
    server._sessions["ui-a"] = session
    manager = SimpleNamespace(
        home_path=home,
        _plugins={"bee-collaborate": SimpleNamespace(enabled=True, error=None)},
    )
    return manager, session


def _deliver(manager, **changes):
    return inject_plugin_message(
        manager=manager, session_key=changes.get("session_key", "key-a"),
        expected_session_id=changes.get("expected_session_id", "native-a"),
        content="Bee delivery 7", plugin_id="bee-collaborate")


def test_busy_delivery_receipt_follows_real_queue_admission(runtime):
    manager, session = runtime
    assert _deliver(manager) is True
    assert session["queued_prompt"]["text"] == "Bee delivery 7"


def test_idle_delivery_receipt_follows_turn_claim(runtime, monkeypatch):
    manager, session = runtime
    session["running"] = False
    started = []

    class _DeferredThread:
        def __init__(self, target, daemon):
            self.target = target

        def start(self):
            started.append(self)

    monkeypatch.setattr(server.threading, "Thread", _DeferredThread)
    monkeypatch.setattr(server, "_persist_session_row_for_submit", lambda *_: None)
    monkeypatch.setattr(server, "_restart_completed_failed_agent_build", lambda *_: True)
    assert _deliver(manager) is True
    assert session["running"] is True
    assert session["inflight_turn"]["user"] == "Bee delivery 7"
    assert len(started) == 1


def test_idle_delivery_runs_fake_local_agent(runtime, monkeypatch):
    manager, session = runtime
    session.update(running=False, history_version=0, cols=80, slash_worker=None,
                   show_reasoning=False, tool_progress_mode="all")
    session["attached_images"] = ["/tmp/human-draft.png"]
    seen = []
    session["agent"].clear_interrupt = lambda: None
    session["agent"].run_conversation = lambda message, **_kw: (
        seen.append(message) or {"final_response": "local fake reply", "messages": []})

    class _InlineThread:
        def __init__(self, target=None, daemon=None, **_kw):
            self.target = target

        def start(self):
            self.target()

        def is_alive(self):
            return False

        def join(self, timeout=None):
            return None

    monkeypatch.setattr(server.threading, "Thread", _InlineThread)
    monkeypatch.setattr(server, "_persist_session_row_for_submit", lambda *_: None)
    monkeypatch.setattr(server, "_ensure_session_db_row", lambda *_: True)
    monkeypatch.setattr(server, "_restart_completed_failed_agent_build", lambda *_: True)
    monkeypatch.setattr(server, "_emit", lambda *a, **k: None)
    monkeypatch.setattr(server, "_wire_callbacks", lambda *_: None)
    monkeypatch.setattr(server, "_sync_agent_model_with_config", lambda *_: None)
    monkeypatch.setattr(server, "_register_session_cwd", lambda *_: None)
    monkeypatch.setattr(server, "_tts_stream_begin", lambda: None)
    monkeypatch.setattr(server, "_sync_session_key_after_compress", lambda *_a, **_k: None)
    monkeypatch.setattr(server, "_get_usage", lambda *_: {})
    assert _deliver(manager) is True
    assert seen == ["Bee delivery 7"]
    assert session["attached_images"] == ["/tmp/human-draft.png"]


def test_normal_idle_prompt_still_claims_its_staged_image(runtime):
    _manager, session = runtime
    session["attached_images"] = ["/tmp/human-draft.png"]
    admitted = server._admit_prompt_turn(
        "ui-a", session, "human prompt", None, None, None, None)
    assert admitted is not None
    images, _agent = admitted
    assert images == ["/tmp/human-draft.png"]
    assert session["attached_images"] == []


def test_normal_public_prompt_still_queues_without_plugin_grant(runtime):
    manager, session = runtime
    manager._plugins["bee-collaborate"].enabled = False
    response = server.dispatch({
        "jsonrpc": "2.0", "id": "user-1", "method": "prompt.submit",
        "params": {"session_id": "ui-a", "text": "ordinary user prompt", "queued": True},
    }, transport=session["transport"])
    assert response["result"]["status"] == "queued"
    assert session["queued_prompt"]["text"] == "ordinary user prompt"


def test_public_rpc_cannot_forge_plugin_admission(runtime):
    _manager, session = runtime
    response = server.dispatch({
        "jsonrpc": "2.0", "id": "forged-1", "method": "prompt.submit",
        "params": {"session_id": "ui-a", "text": "injected", "_plugin_admission": {}},
    }, transport=session["transport"])
    assert response["error"]["code"] == 4000
    assert session.get("queued_prompt") is None


@pytest.mark.parametrize("change", [
    {"expected_session_id": "stale"},
    {"session_key": "wrong-key"},
])
def test_stale_identity_refused_without_queue(runtime, change):
    manager, session = runtime
    assert _deliver(manager, **change) is False
    assert session.get("queued_prompt") is None


def test_cross_profile_and_hidden_session_refused(runtime, tmp_path):
    manager, session = runtime
    other = tmp_path / "hermes-b"
    other.mkdir()
    session["profile_home"] = str(other)
    assert _deliver(manager) is False
    session["profile_home"] = None
    session["pending_hidden"] = True
    assert _deliver(manager) is False
    assert session.get("queued_prompt") is None


def test_disabled_plugin_and_missing_grant_refused(runtime):
    manager, session = runtime
    manager._plugins["bee-collaborate"].enabled = False
    assert _deliver(manager) is False
    manager._plugins["bee-collaborate"].enabled = True
    (manager.home_path / "config.yaml").write_text(
        "plugins:\n  enabled: [bee-collaborate]\n  entries:\n"
        "    bee-collaborate:\n      allow_tui_injection: false\n", encoding="utf-8")
    assert _deliver(manager) is False
    assert session.get("queued_prompt") is None


def test_gateway_only_grant_cannot_enter_tui(runtime):
    manager, session = runtime
    (manager.home_path / "config.yaml").write_text(
        "plugins:\n  enabled: [bee-collaborate]\n  entries:\n"
        "    bee-collaborate:\n      allow_gateway_injection: true\n", encoding="utf-8")
    assert _deliver(manager) is False
    assert session.get("queued_prompt") is None


def test_new_conversation_during_preflight_gets_no_receipt(runtime, monkeypatch):
    manager, old = runtime

    def reset_before_admission(*_args):
        server._sessions.pop("ui-a")
        old["_closing"] = True
        server._sessions["ui-new"] = {
            **old, "session_key": "key-new", "agent": SimpleNamespace(session_id="native-new"),
            "_closing": False, "queued_prompt": None,
        }
        return None

    monkeypatch.setattr(server, "_ensure_active_session_slot", reset_before_admission)
    assert _deliver(manager) is False
    assert old.get("queued_prompt") is None
    assert server._sessions["ui-new"].get("queued_prompt") is None


def test_native_rotation_during_preflight_gets_no_receipt(runtime, monkeypatch):
    manager, session = runtime

    def rotate_before_admission(*_args):
        session["agent"].session_id = "native-new"
        session["session_key"] = "key-new"
        return None

    monkeypatch.setattr(server, "_ensure_active_session_slot", rotate_before_admission)
    assert _deliver(manager) is False
    assert session.get("queued_prompt") is None


def test_generation_change_during_preflight_gets_no_receipt(runtime, monkeypatch):
    manager, session = runtime

    def reset_before_admission(*_args):
        session["_queued_prompt_generation"] = 1
        return None

    monkeypatch.setattr(server, "_ensure_active_session_slot", reset_before_admission)
    assert _deliver(manager) is False
    assert session.get("queued_prompt") is None


def test_duplicate_of_inflight_prompt_is_not_acknowledged(runtime):
    manager, session = runtime
    session["inflight_turn"] = {"user": "Bee delivery 7"}
    assert _deliver(manager) is False
    assert session.get("queued_prompt") is None


def test_scrubbed_stale_duplicate_does_not_ack_new_candidate(runtime):
    manager, session = runtime
    session["inflight_turn"] = {"user": "Bee delivery 7"}
    session["queued_prompt"] = {"text": "Bee delivery 7", "transport": session["transport"]}
    assert _deliver(manager) is False
    assert session["queued_prompt"] is None


def test_busy_plugin_does_not_claim_human_draft_images(runtime):
    manager, session = runtime
    session["attached_images"] = ["/tmp/human-draft.png"]
    assert _deliver(manager) is True
    assert session["queued_prompt"]["text"] == "Bee delivery 7"
    assert session["queued_prompt"]["image_paths"] == []
    assert session["queued_prompt"]["plugin_origin"] == "bee-collaborate"
    assert session["attached_images"] == ["/tmp/human-draft.png"]


@pytest.mark.parametrize("bee_first", [False, True])
def test_busy_plugin_and_human_text_keep_separate_queue_envelopes(runtime, bee_first):
    manager, session = runtime

    def human_send():
        response = server.dispatch({
            "jsonrpc": "2.0", "id": "human", "method": "prompt.submit",
            "params": {"session_id": "ui-a", "text": "human follow-up", "queued": True},
        }, transport=session["transport"])
        assert response["result"]["status"] == "queued"

    if bee_first:
        assert _deliver(manager) is True
        human_send()
    else:
        human_send()
        assert _deliver(manager) is True

    envelopes = [session["queued_prompt"], *(session.get("queued_prompts") or [])]
    assert [entry["text"] for entry in envelopes] == (
        ["Bee delivery 7", "human follow-up"] if bee_first
        else ["human follow-up", "Bee delivery 7"])
    bee_entry = next(entry for entry in envelopes if entry["text"] == "Bee delivery 7")
    human_entry = next(entry for entry in envelopes if entry["text"] == "human follow-up")
    assert bee_entry["plugin_origin"] == "bee-collaborate"
    assert bee_entry["image_paths"] == []
    assert "plugin_origin" not in human_entry


def test_busy_plugin_drain_after_turn_end_keeps_later_human_draft(runtime, monkeypatch):
    manager, session = runtime
    session.update(_compute_host_active=True, cwd=str(manager.home_path))
    frames = []

    class _Supervisor:
        def submit_turn(self, frame, *, on_complete):
            frames.append(frame)

    monkeypatch.setattr(server, "_load_dashboard_process_isolation_config", lambda: {"turn_isolation": True})
    monkeypatch.setattr(server, "_get_compute_host_supervisor", lambda *_args: _Supervisor())
    monkeypatch.setattr(server, "_compute_host_session_info", lambda *_args: {})
    monkeypatch.setattr(server, "_release_deferred_active_session_lease", lambda *_args: None)
    monkeypatch.setattr(server, "_emit", lambda *_args, **_kwargs: None)

    assert _deliver(manager) is True
    session["attached_images"].append("/tmp/human-draft.png")
    server._on_compute_host_turn_done("turn-end", "ui-a", session, {"type": "turn.end"})

    assert len(frames) == 1
    assert frames[0]["text"] == "Bee delivery 7"
    assert frames[0]["attached_images"] == []
    assert session["attached_images"] == ["/tmp/human-draft.png"]


@pytest.mark.parametrize("dispatch_fails", [False, True])
def test_isolated_plugin_frame_never_claims_human_draft_images(runtime, monkeypatch, dispatch_fails):
    manager, session = runtime
    session.update(running=False, _compute_host_active=True, cwd=str(manager.home_path))
    session["attached_images"] = ["/tmp/human-draft.png"]
    frames = []

    class _Supervisor:
        def submit_turn(self, frame, *, on_complete):
            frames.append(frame)
            if dispatch_fails:
                raise RuntimeError("synthetic compute send failure")

    monkeypatch.setattr(server, "_load_dashboard_process_isolation_config", lambda: {"turn_isolation": True})
    monkeypatch.setattr(server, "_get_compute_host_supervisor", lambda *_args: _Supervisor())
    monkeypatch.setattr(server, "_persist_session_row_for_submit", lambda *_args: None)
    monkeypatch.setattr(server, "_restart_completed_failed_agent_build", lambda *_args: True)
    monkeypatch.setattr(server, "_run_after_agent_ready", lambda *_args: None)

    assert _deliver(manager) is True
    assert len(frames) == 1
    assert frames[0]["attached_images"] == []
    assert session["attached_images"] == ["/tmp/human-draft.png"]


def test_cold_isolated_session_without_child_identity_proof_has_no_ack_or_frame(runtime, monkeypatch):
    manager, session = runtime
    session.update(agent=None, agent_ready=threading.Event(), running=False,
                   source="desktop", cwd=str(manager.home_path))
    frames = []

    class _Supervisor:
        def submit_turn(self, frame, *, on_complete):
            frames.append(frame)

    monkeypatch.setattr(server, "_load_dashboard_process_isolation_config", lambda: {"turn_isolation": True})
    monkeypatch.setattr(server, "_get_compute_host_supervisor", lambda *_args: _Supervisor())

    assert _deliver(manager, expected_session_id="key-a") is False
    assert frames == []
    assert session.get("inflight_turn") is None


@pytest.mark.parametrize("running", [True, False])
def test_plugin_admission_never_waits_for_history_under_sessions_lock(runtime, monkeypatch, running):
    manager, session = runtime
    session["running"] = running

    class _CheckedHistoryLock:
        def __init__(self):
            self.inner = threading.Lock()

        def __enter__(self):
            assert not server._sessions_lock._is_owned(), "sessions_lock -> history_lock inversion"
            self.inner.acquire()
            return self

        def __exit__(self, *_args):
            self.inner.release()

    session["history_lock"] = _CheckedHistoryLock()
    if not running:
        monkeypatch.setattr(server, "_persist_session_row_for_submit", lambda *_: None)
        monkeypatch.setattr(server, "_restart_completed_failed_agent_build", lambda *_: True)
        monkeypatch.setattr(server, "_run_after_agent_ready", lambda *_args: None)
    assert _deliver(manager) is True


def test_secondary_profile_uses_its_own_grant(runtime, tmp_path):
    manager, session = runtime
    other = tmp_path / "hermes-b"
    other.mkdir()
    (other / "config.yaml").write_text(
        "plugins:\n  enabled: [bee-collaborate]\n  entries:\n"
        "    bee-collaborate:\n      allow_tui_injection: true\n", encoding="utf-8")
    session["profile_home"] = str(other)
    manager.home_path = other
    assert _deliver(manager) is True
    assert session["queued_prompt"]["text"] == "Bee delivery 7"


def test_registers_callback_on_current_plugin_manager(runtime, monkeypatch):
    manager, session = runtime
    published = {}
    manager.set_tui_message_injector = lambda owner, callback: published.update(owner=owner, callback=callback)
    from hermes_cli import plugins
    monkeypatch.setattr(plugins, "get_plugin_manager", lambda: manager)
    register_tui_plugin_injector()
    assert published["callback"](
        session_key="key-a", expected_session_id="native-a",
        content="registered route", plugin_id="bee-collaborate") is True
    assert session["queued_prompt"]["text"] == "registered route"


def test_compression_emits_after_route_switch_with_live_proof(runtime, monkeypatch):
    manager, session = runtime
    from hermes_cli import plugins

    events = []
    manager.on_session_compacted = lambda **kwargs: events.append(kwargs)
    monkeypatch.setattr(plugins, "get_plugin_manager", lambda: manager)
    monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *_a, **_k: True)
    monkeypatch.setattr(server, "_restart_slash_worker", lambda *_a, **_k: None)
    session["agent"].session_id = "native-b"

    server._sync_session_key_after_compress("ui-a", session)

    assert session["session_key"] == "native-b"
    assert len(events) == 1
    event = events[0]
    assert {key: event[key] for key in (
        "session_key", "old_session_id", "session_id", "profile", "in_place"
    )} == {
        "session_key": "native-b", "old_session_id": "key-a",
        "session_id": "native-b", "profile": "default", "in_place": False,
    }
    assert event["route_is_current"]() is True


def test_failed_inline_compression_lease_transfer_keeps_old_route_and_suppresses_hook(runtime, monkeypatch):
    manager, session = runtime
    from hermes_cli import plugins

    lease = SimpleNamespace(session_id="key-a", released=False, enabled=True, release=lambda: None)
    session["active_session_lease"] = lease
    session["agent"].session_id = "native-b"
    events = []
    manager.on_session_compacted = lambda **kwargs: events.append(kwargs)
    monkeypatch.setattr(plugins, "get_plugin_manager", lambda: manager)
    monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *_a, **_k: False)
    monkeypatch.setattr(server, "_restart_slash_worker", lambda *_a, **_k: None)

    server._sync_session_key_after_compress("ui-a", session)

    assert session["session_key"] == "key-a"
    assert lease.session_id == "key-a"
    assert events == []
    assert session.get("_route_transfer_failed") is True
    assert _deliver(manager, expected_session_id="native-b") is False

    session["attached_images"] = ["/tmp/human-draft.png"]
    response = server.dispatch({
        "jsonrpc": "2.0", "id": "human-after-failure", "method": "prompt.submit",
        "params": {"session_id": "ui-a", "text": "human message", "queued": True},
    }, transport=session["transport"])
    assert response["error"]["code"] == 4007
    assert session["attached_images"] == ["/tmp/human-draft.png"]
    assert session.get("queued_prompt") is None


def test_failed_route_blocks_direct_synthesized_turn_until_reanchored(runtime):
    _manager, session = runtime
    session.update(_route_transfer_failed=True, running=True,
                   attached_images=["/tmp/human-draft.png"])

    admitted = server._admit_prompt_turn("ui-a", session, "auto continuation", None, None, None, None)

    assert admitted is None
    assert session["running"] is False
    assert session["attached_images"] == ["/tmp/human-draft.png"]


def test_failed_compute_compression_transfer_keeps_old_route_and_drain_closed(runtime, monkeypatch):
    manager, session = runtime
    lease = SimpleNamespace(session_id="key-a", released=False, enabled=True, release=lambda: None)
    session.update(active_session_lease=lease, _compute_host_active=True,
                   queued_prompt={"text": "queued after child", "transport": session["transport"]},
                   running=False)
    monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *_a, **_k: False)
    monkeypatch.setattr(server, "_load_dashboard_process_isolation_config", lambda: {"turn_isolation": True})
    monkeypatch.setattr(server, "_submit_prompt_to_compute_host", lambda *_a, **_k: pytest.fail("must not drain"))

    with session["history_lock"]:
        server._compute_host_adopt_frame_meta(session, {
            "sid": "ui-a", "session_key": "native-b", "history_version": 9,
        })

    assert session["session_key"] == "key-a"
    assert lease.session_id == "key-a"
    assert session.get("_route_transfer_failed") is True
    assert server._drain_queued_prompt("after-end", "ui-a", session) is False
    assert session["queued_prompt"]["text"] == "queued after child"
    assert _deliver(manager, expected_session_id="native-b") is False


def test_compression_hook_observes_new_route_only_after_lease_reanchors(runtime, monkeypatch):
    manager, session = runtime
    from hermes_cli import plugins

    lease = SimpleNamespace(session_id="key-a", released=False, enabled=True, release=lambda: None)
    session["active_session_lease"] = lease
    session["agent"].session_id = "native-b"
    observed = []
    manager.on_session_compacted = lambda **kwargs: observed.append((lease.session_id, kwargs))
    monkeypatch.setattr(plugins, "get_plugin_manager", lambda: manager)
    monkeypatch.setattr(server, "_restart_slash_worker", lambda *_a, **_k: None)

    def transfer(*_args, **kwargs):
        assert session["session_key"] == "key-a"
        lease.session_id = kwargs["new_session_id"]
        return True

    monkeypatch.setattr(server, "_transfer_active_session_slot", transfer)

    server._sync_session_key_after_compress("ui-a", session)

    assert session["session_key"] == "native-b"
    assert len(observed) == 1
    assert observed[0][0] == "native-b"
    assert observed[0][1]["route_is_current"]() is True


def test_transfer_success_without_matching_lease_does_not_publish_route(runtime, monkeypatch):
    _manager, session = runtime
    lease = SimpleNamespace(session_id="key-a", released=False, enabled=True, release=lambda: None)
    session["active_session_lease"] = lease
    session["agent"].session_id = "native-b"
    monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *_a, **_k: True)

    server._sync_session_key_after_compress("ui-a", session)

    assert session["session_key"] == "key-a"
    assert session["_route_transfer_failed"] is True


def test_successful_retry_reopens_failed_route_only_after_lease_reanchors(runtime, monkeypatch):
    manager, session = runtime
    lease = SimpleNamespace(session_id="key-a", released=False, enabled=True, release=lambda: None)
    session["active_session_lease"] = lease
    session["agent"].session_id = "native-b"
    monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *_a, **_k: False)
    monkeypatch.setattr(server, "_restart_slash_worker", lambda *_a, **_k: None)

    server._sync_session_key_after_compress("ui-a", session)
    assert session["_route_transfer_failed"] is True

    def successful_transfer(*_args, **kwargs):
        lease.session_id = kwargs["new_session_id"]
        return True

    monkeypatch.setattr(server, "_transfer_active_session_slot", successful_transfer)
    server._sync_session_key_after_compress("ui-a", session)

    assert session["session_key"] == "native-b"
    assert "_route_transfer_failed" not in session
    assert _deliver(manager, session_key="native-b", expected_session_id="native-b") is True


def test_delayed_compaction_hook_after_new_cannot_rebind(runtime, monkeypatch):
    manager, old = runtime
    from hermes_cli import plugins

    pending = []
    manager.on_session_compacted = lambda **kwargs: pending.append(kwargs)
    monkeypatch.setattr(plugins, "get_plugin_manager", lambda: manager)
    monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *_a, **_k: True)
    monkeypatch.setattr(server, "_restart_slash_worker", lambda *_a, **_k: None)
    old["agent"].session_id = "native-b"
    server._sync_session_key_after_compress("ui-a", old)

    # /new may reuse a UI sid or replace its record while an observer is delayed.
    old["_queued_prompt_generation"] += 1
    old["session_key"] = "native-new"
    old["agent"] = SimpleNamespace(session_id="native-new")
    rebound = []
    delayed = pending.pop()
    if delayed["route_is_current"]():
        rebound.append(delayed["session_id"])
    assert rebound == []


def test_resume_emits_for_published_route_and_rejects_later_new(runtime, monkeypatch):
    manager, session = runtime
    from hermes_cli import plugins

    events = []
    manager.on_session_resumed = lambda **kwargs: events.append(kwargs)
    monkeypatch.setattr(plugins, "get_plugin_manager", lambda: manager)
    session["created_at"] = 1.0
    ctx = SimpleNamespace(rid="r1", target="key-a", omit_messages=False, messages=lambda _display: [])

    result = server._resume_with_plugin_notification(
        server._resume_response(ctx, "ui-a", session, info={}, messages=[]))

    assert result["result"]["session_id"] == "ui-a"
    assert len(events) == 1
    event = events[0]
    assert {key: event[key] for key in ("session_key", "session_id", "profile")} == {
        "session_key": "key-a", "session_id": "native-a", "profile": "default",
    }
    assert event["route_is_current"]() is True
    old = server._sessions.pop("ui-a")
    old["_closing"] = True
    assert event["route_is_current"]() is False


def test_resume_hook_absence_preserves_tui(runtime):
    _manager, session = runtime
    assert notify_tui_session_resumed("ui-a", session) is None


def test_resume_hook_exception_preserves_tui_response(runtime, monkeypatch):
    manager, session = runtime
    from hermes_cli import plugins

    def broken_hook(**_kwargs):
        raise RuntimeError("synthetic hook failure")

    manager.on_session_resumed = broken_hook
    monkeypatch.setattr(plugins, "get_plugin_manager", lambda: manager)
    response = server._resume_with_plugin_notification({
        "result": {"session_id": "ui-a", "session_key": "key-a"},
    })
    assert response["result"]["session_id"] == "ui-a"
    assert session.get("queued_prompt") is None


def test_resume_of_compacted_parent_rebinds_to_live_tip(runtime, monkeypatch):
    manager, session = runtime
    from hermes_cli import plugins

    events = []
    manager.on_session_resumed = lambda **kwargs: events.append(kwargs)
    monkeypatch.setattr(plugins, "get_plugin_manager", lambda: manager)
    session["session_key"] = "native-b"
    session["agent"].session_id = "native-b"

    class _DB:
        def get_session(self, key):
            return {"id": key, "message_count": 0} if key in {"key-a", "native-b"} else None

        def resolve_resume_session_id(self, key):
            return "native-b" if key == "key-a" else key

    monkeypatch.setattr(server, "_get_db", lambda: _DB())
    monkeypatch.setattr(server, "_cancel_ws_orphan_reap", lambda *_: None)
    monkeypatch.setattr(server, "_reattach_refusal", lambda *_: None)
    monkeypatch.setattr(server, "_live_session_payload", lambda sid, _session, **_kw: {
        "session_id": sid, "session_key": "native-b", "messages": [], "message_count": 0,
        "info": {},
    })

    response = server.handle_request({
        "id": "resume-old", "method": "session.resume",
        "params": {"session_id": "key-a", "source": "tui"},
    })

    assert response["result"]["resumed"] == "native-b"
    assert response["result"]["session_id"] == "ui-a"
    assert len(events) == 1
    assert events[0]["session_key"] == "native-b"
    assert events[0]["session_id"] == "native-b"
    assert events[0]["route_is_current"]() is True
