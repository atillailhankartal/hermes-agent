"""A TUI compression must still own its session at the first durable write."""

from __future__ import annotations

import threading
from copy import copy
from unittest.mock import MagicMock

import pytest

from agent.context_compressor import SUMMARY_PREFIX
from hermes_cli.active_sessions import active_session_registry_snapshot, try_acquire_active_session
from hermes_state import SessionDB
from run_agent import AIAgent
from tui_gateway import server


def _real_session(tmp_path, monkeypatch, *, in_place=True):
    home = tmp_path / "home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    db = SessionDB(db_path=tmp_path / "state.db")
    session_id = "durable-lease-loss"
    db.create_session(session_id, source="tui")
    for i in range(12):
        db.append_message(session_id, "user", f"question {i} " + "x" * 80)
        db.append_message(session_id, "assistant", f"answer {i} " + "y" * 80)
    before = db.get_messages_as_conversation(session_id)
    agent = AIAgent(
        api_key="fixture-only", base_url="http://127.0.0.1:9/v1", model="test/model", platform="tui",
        quiet_mode=True, session_db=db, session_id=session_id, skip_context_files=True,
        skip_memory=True, enabled_toolsets=[],
    )
    compressor = MagicMock()
    compressor.compression_count = 1
    compressor.last_prompt_tokens = compressor.last_completion_tokens = 0
    compressor._last_summary_error = None
    compressor._last_compress_aborted = compressor._last_summary_auth_failure = False
    compressor._last_aux_model_failure_model = compressor._last_aux_model_failure_error = None
    agent.context_compressor = compressor
    agent.compression_in_place = in_place
    agent._compression_feasibility_checked = True
    agent._build_system_prompt = lambda *_a, **_kw: "fixture prompt"
    hooks = []
    agent.event_callback = lambda name, *_a: hooks.append(name)
    session = {
        "_sid": "ui", "agent": agent, "history_lock": threading.Lock(), "history": list(before),
        "history_version": 0, "running": False, "session_key": session_id, "cwd": str(tmp_path),
        "profile_home": home, "source": "tui", "active_session_lease": None,
    }
    monkeypatch.setattr(server, "_load_cfg", lambda: {})
    monkeypatch.setattr(server, "_emit_session_info_for_session", lambda *_a: None)
    monkeypatch.setattr(server, "_drain_queued_prompt", lambda *_a: None)
    monkeypatch.setattr(server, "_session_cwd", lambda _session: str(tmp_path))
    return db, agent, session, before, home, compressor, hooks


@pytest.mark.parametrize("in_place", [True, False])
def test_lost_lease_during_real_summary_keeps_sqlite_and_live_history(tmp_path, monkeypatch, in_place):
    db, agent, session, before, home, compressor, hooks = _real_session(
        tmp_path, monkeypatch, in_place=in_place)
    session_id = session["session_key"]
    foreign = None

    def steal_then_summarize(messages, *_a, **_kw):
        nonlocal foreign
        copy(session["active_session_lease"]).release()
        foreign, refusal = try_acquire_active_session(
            session_id=session_id, surface="cli", config={},
            metadata={"live_session_id": "foreign"}, registry_home=home,
        )
        assert foreign is not None and refusal is None
        return [
            {"role": "user", "content": SUMMARY_PREFIX + " earlier turns"},
            before[-1].copy(),
        ]

    compressor.compress.side_effect = steal_then_summarize
    try:
        with pytest.raises(RuntimeError, match="could not safely reserve"):
            with server._manual_compress_turn("ui", session):
                server._compress_session_history(session)
        assert db.get_messages_as_conversation(session_id) == before
        assert session["history"] == before
        assert session["history_version"] == 0 and session["session_key"] == session_id
        assert "session:compress" not in hooks
        assert foreign is not None
        assert [row["lease_id"] for row in active_session_registry_snapshot(home)] == [foreign.lease_id]
    finally:
        if foreign is not None:
            foreign.release()
        agent.close()
        db.close()


@pytest.mark.parametrize("in_place", [True, False])
def test_valid_lease_commits_sqlite_and_live_route_together(tmp_path, monkeypatch, in_place):
    db, agent, session, before, home, compressor, hooks = _real_session(
        tmp_path, monkeypatch, in_place=in_place)
    parent = session["session_key"]
    compressor.compress.side_effect = lambda _messages, *_a, **_kw: [
        {"role": "user", "content": SUMMARY_PREFIX + " earlier turns"}, before[-1].copy()]
    memory_calls = []

    def commit_memory(_messages):
        registry_read_finished = threading.Event()
        reader = threading.Thread(
            target=lambda: (active_session_registry_snapshot(home), registry_read_finished.set()),
            daemon=True,
        )
        reader.start()
        assert registry_read_finished.wait(2), "external memory callback ran under the registry file lock"
        reader.join(timeout=2)
        assert not session["history_lock"].locked()
        memory_calls.append((agent.session_id, session["history_version"], session["session_key"]))

    agent.commit_memory_session = commit_memory
    try:
        with server._manual_compress_turn("ui", session):
            removed, _usage = server._compress_session_history(session)
            assert removed > 0
            server._sync_session_key_after_compress("ui", session, restart_slash_worker=False)
        child = session["session_key"]
        assert (child == parent) is in_place
        assert session["history_version"] == 1
        assert len(session["history"]) < len(before)
        assert agent.session_id == child
        assert memory_calls == [(parent, 1, child)]
        assert "session:compress" in hooks
        rows = active_session_registry_snapshot(home)
        assert [(row["session_id"], row["lease_id"]) for row in rows] == [
            (child, session["active_session_lease"].lease_id)]
        fresh = SessionDB(db_path=tmp_path / "state.db")
        try:
            assert fresh.get_messages_as_conversation(child) == db.get_messages_as_conversation(child)
            assert len(fresh.get_messages_as_conversation(child)) == len(session["history"])
        finally:
            fresh.close()
    finally:
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()
        agent.close()
        db.close()


def test_memory_callback_failure_follows_committed_rotated_boundary(tmp_path, monkeypatch):
    db, agent, session, before, home, compressor, hooks = _real_session(
        tmp_path, monkeypatch, in_place=False)
    parent = session["session_key"]
    compressor.compress.side_effect = lambda _messages, *_a, **_kw: [
        {"role": "user", "content": SUMMARY_PREFIX + " earlier turns"}, before[-1].copy()]
    memory_calls = []

    def failing_memory(_messages):
        memory_calls.append((agent.session_id, session["history_version"]))
        raise RuntimeError("memory service unavailable")

    agent.commit_memory_session = failing_memory
    try:
        with server._manual_compress_turn("ui", session):
            server._compress_session_history(session)
            server._sync_session_key_after_compress("ui", session, restart_slash_worker=False)
        child = session["session_key"]
        assert child != parent and memory_calls == [(parent, 1)]
        assert agent.session_id == child and "session:compress" in hooks
        assert len(db.get_messages_as_conversation(child)) == len(session["history"])
        assert [row["session_id"] for row in active_session_registry_snapshot(home)] == [child]
    finally:
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()
        agent.close()
        db.close()


def test_cancel_before_commit_leaves_real_db_and_memory_untouched(tmp_path, monkeypatch):
    db, agent, session, before, home, compressor, hooks = _real_session(tmp_path, monkeypatch)
    parent = session["session_key"]
    memory_calls = []
    agent.commit_memory_session = lambda *_a: memory_calls.append(True)

    def cancel_after_summary(_messages, *_a, **_kw):
        assert agent._active_compression_commit_fence.cancel_before_commit() is True
        return [{"role": "user", "content": SUMMARY_PREFIX + " earlier turns"}, before[-1].copy()]

    compressor.compress.side_effect = cancel_after_summary
    try:
        with server._manual_compress_turn("ui", session):
            removed, _usage = server._compress_session_history(session)
            assert removed == 0
        assert db.get_messages_as_conversation(parent) == before
        assert session["history"] == before and session["history_version"] == 0
        assert memory_calls == [] and "session:compress" not in hooks
        assert active_session_registry_snapshot(home) == []
    finally:
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()
        agent.close()
        db.close()
