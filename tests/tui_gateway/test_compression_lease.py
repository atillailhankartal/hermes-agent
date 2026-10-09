"""Manual and isolated compression must keep the published route behind its live lease."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from hermes_cli.active_sessions import active_session_registry_snapshot, try_acquire_active_session
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
