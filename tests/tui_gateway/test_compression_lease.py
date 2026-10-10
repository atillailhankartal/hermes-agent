"""Manual and isolated compression must keep the published route behind its live lease."""

from __future__ import annotations

import threading
from copy import copy
from types import SimpleNamespace

import pytest

from hermes_cli.active_sessions import ActiveSessionLease, active_session_registry_snapshot, try_acquire_active_session
from tui_gateway import server


def _session(key: str = "A") -> dict:
    return {
        "_sid": "ui", "session_key": key, "active_session_lease": None,
        "agent": SimpleNamespace(session_id=key), "history_lock": threading.Lock(),
        "history": [{"role": "user", "content": "earlier message"}],
        "history_version": 0, "running": False, "source": "tui",
    }


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = tmp_path / "hermes"
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    monkeypatch.setattr(server, "_emit_session_info_for_session", lambda *_a: None)
    monkeypatch.setattr(server, "_drain_queued_prompt", lambda *_a: None)
    return root


def _entries(home) -> list[dict]:
    return active_session_registry_snapshot(home)


def test_resumed_manual_compress_claims_before_mutation_then_reanchors(home):
    session = _session()
    assert session["active_session_lease"] is None
    assert _entries(home) == []  # resume itself keeps the normal lazy-claim contract

    with server._manual_compress_turn("ui", session):
        lease = session["active_session_lease"]
        assert lease is not None and lease.session_id == "A"
        assert [(row["session_id"], row["lease_id"]) for row in _entries(home)] == [("A", lease.lease_id)]
        session["agent"].session_id = "B"
        server._sync_session_key_after_compress("ui", session, restart_slash_worker=False)
        assert session["session_key"] == "B" and lease.session_id == "B"
        assert [(row["session_id"], row["lease_id"]) for row in _entries(home)] == [("B", lease.lease_id)]
    assert session["running"] is False
    lease.release()


def test_manual_compress_refuses_foreign_owner_before_mutation(home):
    foreign, refusal = try_acquire_active_session(
        session_id="A", surface="cli", config={}, metadata={"live_session_id": "other"},
        registry_home=home)
    assert foreign is not None and refusal is None
    session = _session()
    try:
        with pytest.raises(RuntimeError, match="open in another Hermes"):
            with server._manual_compress_turn("ui", session):
                session["history"].clear()
        assert session["history"] and session["session_key"] == "A"
        assert session["running"] is False
        assert [(row["session_id"], row["lease_id"]) for row in _entries(home)] == [("A", foreign.lease_id)]
    finally:
        foreign.release()


def test_stale_lease_object_cannot_mutate_after_foreign_owner_takes_a(home):
    owned, refusal = try_acquire_active_session(
        session_id="A", surface="tui", config={}, metadata={"live_session_id": "ui"},
        registry_home=home)
    assert owned is not None and refusal is None
    stale = copy(owned)
    owned.release()  # one handle removes the row; the copied handle still claims released=False
    assert stale.released is False and _entries(home) == []
    foreign, refusal = try_acquire_active_session(
        session_id="A", surface="cli", config={}, metadata={"live_session_id": "foreign"},
        registry_home=home)
    assert foreign is not None and refusal is None
    session = _session()
    session["active_session_lease"] = stale
    try:
        with pytest.raises(RuntimeError, match="could not safely reserve"):
            with server._manual_compress_turn("ui", session):
                session["history"].clear()
        assert session["history"] and session["session_key"] == "A"
        assert [row["lease_id"] for row in _entries(home)] == [foreign.lease_id]
    finally:
        foreign.release()


def test_lease_from_other_profile_cannot_prove_local_history(home, tmp_path):
    other_home = tmp_path / "other-profile"
    other, refusal = try_acquire_active_session(
        session_id="A", surface="tui", config={}, metadata={"live_session_id": "ui"},
        registry_home=other_home)
    assert other is not None and refusal is None
    session = _session()
    session["profile_home"] = home
    session["active_session_lease"] = other
    try:
        with pytest.raises(RuntimeError, match="could not safely reserve"):
            with server._manual_compress_turn("ui", session):
                session["history"].clear()
        assert session["history"] and _entries(home) == []
        assert [row["lease_id"] for row in _entries(other_home)] == [other.lease_id]
    finally:
        other.release()


def test_borrowed_token_alone_cannot_prove_parent_lease(home):
    session = _session()
    session["active_session_lease"] = ActiveSessionLease(
        lease_id="borrowed:missing-parent", session_id="A", surface="desktop", enabled=False)
    with pytest.raises(RuntimeError, match="could not safely reserve"):
        with server._manual_compress_turn("ui", session):
            session["history"].clear()
    assert session["history"] and _entries(home) == []


def test_borrowed_token_matches_real_parent_lease(home):
    parent, refusal = try_acquire_active_session(
        session_id="A", surface="desktop", config={}, metadata={"live_session_id": "ui"},
        registry_home=home, track_liveness=True)
    assert parent is not None and refusal is None
    session = _session()
    session["active_session_lease"] = ActiveSessionLease(
        lease_id=f"borrowed:{parent.lease_id}", session_id="A", surface="desktop", enabled=False)
    try:
        with server._manual_compress_turn("ui", session):
            assert [row["lease_id"] for row in _entries(home)] == [parent.lease_id]
    finally:
        parent.release()


def test_short_history_noop_compress_releases_new_slot_before_prompt_drain(home, monkeypatch):
    monkeypatch.setattr(server, "_load_cfg", lambda: {"max_concurrent_sessions": 1})
    session = _session()
    observed_at_drain = []
    monkeypatch.setattr(server, "_drain_queued_prompt", lambda *_a: observed_at_drain.extend(_entries(home)))
    with server._manual_compress_turn("ui", session):
        removed, _usage = server._compress_session_history(session)
        assert removed == 0
    assert observed_at_drain == [] and _entries(home) == []
    assert session.get("active_session_lease") is None
    next_owner, refusal = try_acquire_active_session(
        session_id="B", surface="cli", config={"max_concurrent_sessions": 1},
        metadata={"live_session_id": "next"}, registry_home=home)
    assert next_owner is not None and refusal is None
    next_owner.release()


def test_noop_release_fences_concurrent_compute_route_change(home, monkeypatch):
    session = _session()
    release_entered = threading.Event()
    frame_attempted = threading.Event()
    frame_done = threading.Event()
    frame_results = []
    observed_during_release = []
    real_release = server._release_active_session_slot

    def watched_release(record):
        release_entered.set()
        assert frame_attempted.wait(5)
        observed_during_release.append(frame_done.wait(2))
        return real_release(record)

    def adopt_frame():
        assert release_entered.wait(10)
        frame_attempted.set()
        with session["history_lock"]:
            frame_results.append(server._compute_host_adopt_frame_meta(
                session, {"sid": "ui", "session_key": "B", "history_version": 1}))
        frame_done.set()

    monkeypatch.setattr(server, "_release_active_session_slot", watched_release)
    worker = threading.Thread(target=adopt_frame, daemon=True)
    worker.start()
    try:
        with server._manual_compress_turn("ui", session):
            assert server._compress_session_history(session)[0] == 0
        assert frame_done.wait(5)
        assert observed_during_release == [False]
        assert frame_results == [False]
        assert session["session_key"] == "A" and _entries(home) == []
    finally:
        release_entered.set()
        worker.join(timeout=5)
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()


def test_real_compaction_keeps_lease_after_in_place_history_commit(home, monkeypatch):
    from agent import conversation_compression_manual as manual

    session = _session()
    session["history"] = [{"role": "user", "content": f"message {i}"} for i in range(4)]
    monkeypatch.setattr(server, "_session_cwd", lambda _session: str(home))

    def compress_now(_agent, before, _request, **_kw):
        assert [row["session_id"] for row in _entries(home)] == ["A"]
        return SimpleNamespace(status="compressed", after_messages=before[:2], removed=2)

    monkeypatch.setattr(manual, "compress_now", compress_now)
    with server._manual_compress_turn("ui", session):
        removed, _usage = server._compress_session_history(session)
        assert removed == 2
    lease = session["active_session_lease"]
    try:
        assert session["history_version"] == 1 and len(session["history"]) == 2
        assert [row["lease_id"] for row in _entries(home)] == [lease.lease_id]
    finally:
        lease.release()


def test_lease_loss_during_summary_cannot_commit_old_history(home, monkeypatch):
    from agent import conversation_compression_manual as manual

    session = _session()
    before = [{"role": "user", "content": f"message {i}"} for i in range(4)]
    session["history"] = before[:]
    monkeypatch.setattr(server, "_session_cwd", lambda _session: str(home))
    foreign = None

    def compress_now(_agent, messages, _request, **_kw):
        nonlocal foreign
        copy(session["active_session_lease"]).release()
        foreign, refusal = try_acquire_active_session(
            session_id="A", surface="cli", config={}, metadata={"live_session_id": "foreign"},
            registry_home=home)
        assert foreign is not None and refusal is None
        return SimpleNamespace(status="compressed", after_messages=messages[:2], removed=2)

    monkeypatch.setattr(manual, "compress_now", compress_now)
    try:
        with pytest.raises(RuntimeError, match="could not safely reserve"):
            with server._manual_compress_turn("ui", session):
                server._compress_session_history(session)
        assert session["history"] == before and session["history_version"] == 0
        assert [row["lease_id"] for row in _entries(home)] == [foreign.lease_id]
    finally:
        if foreign is not None:
            foreign.release()


def test_foreign_acquire_waits_until_short_history_commit_finishes(home, monkeypatch):
    from agent import conversation_compression_manual as manual

    write_reached = threading.Event()
    acquire_attempted = threading.Event()
    foreign_done = threading.Event()
    observed_while_paused = []
    foreign_holder = []

    class PausingSession(dict):
        def __setitem__(self, key, value):
            if key == "history" and len(value) == 2:
                write_reached.set()
                assert acquire_attempted.wait(5)
                observed_while_paused.append(foreign_done.wait(2))
            super().__setitem__(key, value)

    session = PausingSession(_session())
    session["history"] = [{"role": "user", "content": f"message {i}"} for i in range(4)]
    monkeypatch.setattr(server, "_session_cwd", lambda _session: str(home))
    monkeypatch.setattr(manual, "compress_now", lambda _agent, before, _request, **_kw: SimpleNamespace(
        status="compressed", after_messages=before[:2], removed=2))

    def compete():
        assert write_reached.wait(10)
        acquire_attempted.set()
        copy(session["active_session_lease"]).release()
        owner, refusal = try_acquire_active_session(
            session_id="A", surface="cli", config={}, metadata={"live_session_id": "foreign"},
            registry_home=home)
        foreign_holder.append((owner, refusal))
        foreign_done.set()

    worker = threading.Thread(target=compete, daemon=True)
    worker.start()
    try:
        with server._manual_compress_turn("ui", session):
            removed, _usage = server._compress_session_history(session)
            assert removed == 2
        assert observed_while_paused == [False]
        assert session["history_version"] == 1
        assert foreign_done.wait(5)
        owner, refusal = foreign_holder[0]
        assert owner is not None and refusal is None
    finally:
        write_reached.set()
        worker.join(timeout=5)
        if foreign_holder and foreign_holder[0][0] is not None:
            foreign_holder[0][0].release()


def test_failed_manual_transfer_keeps_old_route_and_no_new_notification(home, monkeypatch):
    session = _session()
    assert server._ensure_active_session_slot("ui", session) is None
    lease = session["active_session_lease"]
    session["agent"].session_id = "B"
    session["_queued_prompt_generation"] = 4
    monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *_a, **_kw: False)
    try:
        with pytest.raises(RuntimeError, match="could not safely reserve"):
            server._sync_session_key_after_compress("ui", session, restart_slash_worker=False)
        assert session["session_key"] == "A"
        assert session["_queued_prompt_generation"] == 4
        assert [(row["session_id"], row["lease_id"]) for row in _entries(home)] == [("A", lease.lease_id)]
    finally:
        lease.release()


@pytest.mark.parametrize("has_lease", [False, True])
def test_compute_frame_failed_proof_keeps_old_route_and_version(home, monkeypatch, has_lease):
    session = _session()
    lease = None
    if has_lease:
        assert server._ensure_active_session_slot("ui", session) is None
        lease = session["active_session_lease"]
        monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *_a, **_kw: False)
    try:
        with session["history_lock"]:
            server._compute_host_adopt_frame_meta(
                session, {"sid": "ui", "session_key": "B", "history_version": 9})
        assert session["session_key"] == "A" and session["history_version"] == 0
        assert [row["session_id"] for row in _entries(home)] == (["A"] if has_lease else [])
    finally:
        if lease is not None:
            lease.release()


def test_first_prompt_keeps_lazy_claim_after_resume(home):
    session = _session()
    assert _entries(home) == []
    assert server._ensure_active_session_slot("ui", session) is None
    lease = session["active_session_lease"]
    try:
        assert [(row["session_id"], row["lease_id"]) for row in _entries(home)] == [("A", lease.lease_id)]
    finally:
        lease.release()


def test_compute_compress_claims_parent_slot_before_host_control(home, monkeypatch):
    session = _session()
    server._sessions["ui"] = session
    observed = []

    class Host:
        def control(self, *args, **kwargs):
            observed.extend(_entries(home))
            return {"type": "control.ack"}

    monkeypatch.setattr(server, "_get_compute_host_supervisor", lambda: Host())
    try:
        server._send_compute_host_control("ui", route_name="slash.compress", command="/compress")
        assert [(row["session_id"], row["lease_id"]) for row in observed] == [
            ("A", session["active_session_lease"].lease_id)]
    finally:
        server._sessions.pop("ui", None)
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()


def test_compute_compress_foreign_owner_never_reaches_host(home, monkeypatch):
    foreign, refusal = try_acquire_active_session(
        session_id="A", surface="cli", config={}, metadata={"live_session_id": "other"},
        registry_home=home)
    assert foreign is not None and refusal is None
    session = _session()
    server._sessions["ui"] = session
    called = []
    monkeypatch.setattr(server, "_get_compute_host_supervisor", lambda: called.append(True))
    try:
        with pytest.raises(RuntimeError, match="open in another Hermes"):
            server._send_compute_host_control("ui", route_name="session.compress", command="/compress")
        assert called == [] and session["session_key"] == "A"
    finally:
        server._sessions.pop("ui", None)
        foreign.release()


def test_sync_compute_ack_failed_transfer_returns_error_without_new_route(home, monkeypatch):
    session = _session()
    server._sessions["ui"] = session
    assert server._ensure_active_session_slot("ui", session) is None
    lease = session["active_session_lease"]

    class Host:
        def control(self, *args, **kwargs):
            return {"type": "control.ack", "sid": "ui", "session_key": "B", "history_version": 9}

    monkeypatch.setattr(server, "_get_compute_host_supervisor", lambda: Host())
    monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *_a, **_kw: False)
    try:
        with pytest.raises(RuntimeError, match="could not safely reserve"):
            server._send_compute_host_control("ui", route_name="slash.compress", command="/compress")
        assert session["session_key"] == "A" and session["history_version"] == 0
        assert [(row["session_id"], row["lease_id"]) for row in _entries(home)] == [("A", lease.lease_id)]
    finally:
        server._sessions.pop("ui", None)
        lease.release()


def test_late_compute_ack_failed_proof_emits_error_without_compacted(home, monkeypatch):
    session = _session()
    server._sessions["ui"] = session
    emitted = []
    status = []
    monkeypatch.setattr(server, "_emit", lambda event, *_a: emitted.append(event))
    monkeypatch.setattr(server, "_status_update", lambda *_a: status.append(_a))
    try:
        server._adopt_late_compute_host_compress_ack(
            "ui", session,
            {"type": "control.ack", "sid": "ui", "session_key": "B", "history_version": 9,
             "message_count": 2, "session_info": {"model": "child"}},
            route_name="session.compress")
        assert emitted == ["error"]
        assert [args[1] for args in status] == ["ready"]
        assert session["session_key"] == "A" and session["history_version"] == 0
        assert "_metadata_mirror" not in session and "_metadata_message_count" not in session
    finally:
        server._sessions.pop("ui", None)
