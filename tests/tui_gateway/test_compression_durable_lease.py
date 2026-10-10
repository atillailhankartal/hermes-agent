"""A TUI compression must still own its session at the first durable write."""

from __future__ import annotations

import threading
import types
from copy import copy
from unittest.mock import MagicMock, patch

import pytest

from agent.context_compressor import SUMMARY_PREFIX
from agent import conversation_compression as core
from hermes_cli import active_sessions as active
from hermes_cli.active_sessions import active_session_registry_snapshot, try_acquire_active_session
from hermes_state import SessionDB
from run_agent import AIAgent
from tui_gateway import server
from tui_gateway import session_compression


def _resume_in_fresh_tui_record(monkeypatch, db, parent, expected):
    """Exercise the actual session.resume admission and tip binding after a simulated restart."""
    captured = {}

    def make_agent(_sid, _key, session_id=None, **_kwargs):
        captured["agent_session_id"] = session_id
        return types.SimpleNamespace(model="test", provider="test")

    monkeypatch.setattr(server, "_get_db", lambda: db)
    monkeypatch.setattr(server, "_enable_gateway_prompts", lambda: None)
    monkeypatch.setattr(server, "_make_agent", make_agent)
    monkeypatch.setattr(server, "_session_info", lambda *_a: {"model": "test", "tools": {}, "skills": {}})
    monkeypatch.setattr(server, "_init_session", lambda *_a, **_kw: None)
    response = server.handle_request(
        {"id": "resume-after-fault", "method": "session.resume",
         "params": {"session_id": parent, "eager_build": True}})
    assert response["result"]["session_key"] == expected
    assert captured["agent_session_id"] == expected


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


def test_rotated_registry_write_failure_rolls_back_child_and_can_restart(tmp_path, monkeypatch):
    db, agent, session, before, home, compressor, hooks = _real_session(
        tmp_path, monkeypatch, in_place=False)
    parent = session["session_key"]
    child = "child-transfer-write-fault"
    compressor.compress.side_effect = lambda _messages, *_a, **_kw: [
        {"role": "user", "content": SUMMARY_PREFIX + " earlier turns"}, before[-1].copy()]
    real_write = active._write_entries

    def reject_child(path, entries):
        if any(row.get("session_id") == child for row in entries):
            raise OSError("injected registry transfer write failure")
        return real_write(path, entries)

    try:
        with patch.object(core, "mint_session_id", return_value=child), patch.object(
                active, "_write_entries", side_effect=reject_child):
            with pytest.raises(RuntimeError, match="persistence failed"):
                with server._manual_compress_turn("ui", session):
                    server._compress_session_history(session)
        fresh = SessionDB(db_path=tmp_path / "state.db")
        try:
            assert fresh.get_session(parent)["ended_at"] is None
            assert fresh.get_session(child) is None
            assert fresh.get_messages_as_conversation(parent) == before
            assert fresh.resolve_resume_session_id(parent) == parent
            _resume_in_fresh_tui_record(monkeypatch, fresh, parent, parent)
        finally:
            fresh.close()
        assert agent.session_id == parent
        assert session["session_key"] == parent and session["history_version"] == 0
        assert session["history"] == before
        assert active_session_registry_snapshot(home) == []
        assert "session:compress" not in hooks
        with server._manual_compress_turn("ui", session):
            removed, _usage = server._compress_session_history(session)
            assert removed > 0
            server._sync_session_key_after_compress("ui", session, restart_slash_worker=False)
        retry_child = session["session_key"]
        assert retry_child != parent and agent.session_id == retry_child
        assert db.get_session(retry_child) is not None
        assert [row["session_id"] for row in active_session_registry_snapshot(home)] == [retry_child]
        assert hooks.count("session:compress") == 1
    finally:
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()
        agent.close()
        db.close()


def test_in_place_prompt_write_failure_rolls_back_archive_and_hook(tmp_path, monkeypatch):
    db, agent, session, before, home, compressor, hooks = _real_session(tmp_path, monkeypatch)
    parent = session["session_key"]
    compressor.compress.side_effect = lambda _messages, *_a, **_kw: [
        {"role": "user", "content": SUMMARY_PREFIX + " earlier turns"}, before[-1].copy()]
    try:
        with patch.object(db, "_store_system_prompt", side_effect=OSError("injected prompt write failure")), \
                patch.object(db, "update_system_prompt", side_effect=AssertionError("separate prompt write")):
            with server._manual_compress_turn("ui", session):
                with pytest.raises(RuntimeError, match="persistence failed"):
                    server._compress_session_history(session)
        fresh = SessionDB(db_path=tmp_path / "state.db")
        try:
            assert fresh.get_messages_as_conversation(parent) == before
            assert fresh.resolve_resume_session_id(parent) == parent
        finally:
            fresh.close()
        assert session["history"] == before and session["history_version"] == 0
        assert agent.session_id == session["session_key"] == parent
        assert active_session_registry_snapshot(home) == []
        assert "session:compress" not in hooks
    finally:
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()
        agent.close()
        db.close()


@pytest.mark.parametrize("sqlite_commit_happened", [False, True])
def test_registry_transfer_then_sqlite_commit_error_reconciles_from_readback(
        tmp_path, monkeypatch, sqlite_commit_happened):
    db, agent, session, before, home, compressor, hooks = _real_session(
        tmp_path, monkeypatch, in_place=False)
    parent = session["session_key"]
    child = "child-ambiguous-sqlite-commit"
    compressor.compress.side_effect = lambda _messages, *_a, **_kw: [
        {"role": "user", "content": SUMMARY_PREFIX + " earlier turns"}, before[-1].copy()]
    real_conn = db._conn
    route_staged = False
    fault_fired = False
    real_stage = session_compression._TuiCompressionCommit.stage_route_before_sqlite_commit

    def stage_route(commit, child_id):
        nonlocal route_staged
        real_stage(commit, child_id)
        route_staged = True

    class CommitFaultConnection:
        def __getattr__(self, name):
            return getattr(real_conn, name)

        def commit(self):
            nonlocal fault_fired
            if route_staged and not fault_fired:
                fault_fired = True
                if sqlite_commit_happened:
                    real_conn.commit()
                raise OSError("injected SQLite COMMIT result failure")
            return real_conn.commit()

    try:
        db._conn = CommitFaultConnection()
        with patch.object(core, "mint_session_id", return_value=child), patch.object(
                session_compression._TuiCompressionCommit, "stage_route_before_sqlite_commit", stage_route):
            if sqlite_commit_happened:
                with server._manual_compress_turn("ui", session):
                    removed, _usage = server._compress_session_history(session)
                    assert removed > 0
                    server._sync_session_key_after_compress("ui", session, restart_slash_worker=False)
            else:
                with pytest.raises(RuntimeError, match="persistence failed"):
                    with server._manual_compress_turn("ui", session):
                        server._compress_session_history(session)
        assert route_staged and fault_fired
        db._conn = real_conn
        fresh = SessionDB(db_path=tmp_path / "state.db")
        try:
            if sqlite_commit_happened:
                assert fresh.get_session(parent)["end_reason"] == "compression"
                assert fresh.get_session(child) is not None
                assert len(fresh.get_messages_as_conversation(child)) == len(session["history"]) < len(before)
                assert fresh.resolve_resume_session_id(parent) == child
                _resume_in_fresh_tui_record(monkeypatch, fresh, parent, child)
            else:
                assert fresh.get_session(parent)["ended_at"] is None
                assert fresh.get_session(child) is None
                assert fresh.get_messages_as_conversation(parent) == before
                assert fresh.resolve_resume_session_id(parent) == parent
                _resume_in_fresh_tui_record(monkeypatch, fresh, parent, parent)
        finally:
            fresh.close()
        expected = child if sqlite_commit_happened else parent
        assert agent.session_id == session["session_key"] == expected
        assert session["history_version"] == int(sqlite_commit_happened)
        assert hooks.count("session:compress") == int(sqlite_commit_happened)
        rows = active_session_registry_snapshot(home)
        assert [row["session_id"] for row in rows] == ([child] if sqlite_commit_happened else [])
        if sqlite_commit_happened:
            assert rows[0]["lease_id"] == session["active_session_lease"].lease_id
    finally:
        db._conn = real_conn
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()
        agent.close()
        db.close()


@pytest.mark.parametrize("settlement", ["committed", "rolled_back", "unreadable", "cancelled_after_commit"])
def test_in_place_sqlite_commit_error_reconciles_or_faults_before_prompt(
        tmp_path, monkeypatch, settlement):
    """The real DB can commit and still raise; the host must publish or reject the next turn."""
    db, agent, session, before, home, compressor, hooks = _real_session(
        tmp_path, monkeypatch, in_place=True)
    parent = session["session_key"]
    compressor.compress.side_effect = lambda _messages, *_a, **_kw: [
        {"role": "user", "content": SUMMARY_PREFIX + " earlier turns"}, before[-1].copy()]
    real_conn = db._conn
    real_archive = db.archive_and_compact
    real_get_messages = SessionDB.get_messages_as_conversation
    armed = fired = False

    def arm_archive(*args, **kwargs):
        nonlocal armed
        armed = True
        return real_archive(*args, **kwargs)

    class CommitFaultConnection:
        def __getattr__(self, name):
            return getattr(real_conn, name)

        def commit(self):
            nonlocal fired
            if armed and not fired:
                fired = True
                if settlement != "rolled_back":
                    real_conn.commit()
                if settlement == "cancelled_after_commit":
                    raise KeyboardInterrupt("injected cancellation after SQLite COMMIT")
                raise OSError("injected in-place COMMIT result failure")
            return real_conn.commit()

    def unreadable_after_commit(handle, *args, **kwargs):
        if settlement == "unreadable" and fired and handle.read_only:
            raise OSError("injected fresh SQLite readback failure")
        return real_get_messages(handle, *args, **kwargs)

    try:
        db._conn = CommitFaultConnection()
        db.archive_and_compact = arm_archive
        with patch.object(SessionDB, "get_messages_as_conversation", unreadable_after_commit):
            if settlement in {"committed", "cancelled_after_commit"}:
                with server._manual_compress_turn("ui", session):
                    removed, _usage = server._compress_session_history(session)
                    assert removed > 0
            else:
                with pytest.raises(RuntimeError, match="persistence failed"):
                    with server._manual_compress_turn("ui", session):
                        server._compress_session_history(session)
        assert armed and fired
        db._conn = real_conn
        db.archive_and_compact = real_archive
        fresh = SessionDB(db_path=tmp_path / "state.db")
        try:
            durable = fresh.get_messages_as_conversation(parent)
            if settlement in {"committed", "cancelled_after_commit"}:
                assert session["history"] == durable
                assert len(durable) < len(before)
                assert session["history_version"] == 1
                assert session.get("_compression_faulted") is not True
                assert hooks.count("session:compress") == 1
                assert server._ensure_active_session_slot("ui", session) is None
            elif settlement == "rolled_back":
                assert durable == before == session["history"]
                assert session["history_version"] == 0
                assert session.get("_compression_faulted") is not True
                assert "session:compress" not in hooks
                assert server._ensure_active_session_slot("ui", session) is None
                with server._manual_compress_turn("ui", session):
                    removed, _usage = server._compress_session_history(session)
                    assert removed > 0
                assert hooks.count("session:compress") == 1
                replayed = fresh.get_messages_as_conversation(parent)
                assert [(m["role"], m["content"]) for m in session["history"]] == [
                    (m["role"], m["content"]) for m in replayed
                ]
                assert len(replayed) < len(before)
                assert session["history_version"] == 1
            else:
                assert len(durable) < len(before)
                assert session["history_version"] == 0
                assert session["_compression_faulted"] is True
                assert "session:compress" not in hooks
                assert server._ensure_active_session_slot("ui", session) is not None
                previous = server._sessions.get("ui")
                server._sessions["ui"] = session
                try:
                    refused = server.handle_request(
                        {"id": "faulted-in-place-prompt", "method": "prompt.submit",
                         "params": {"session_id": "ui", "text": "continue"}})
                    assert refused["error"]["code"] == 4090
                finally:
                    if previous is None:
                        server._sessions.pop("ui", None)
                    else:
                        server._sessions["ui"] = previous
                with pytest.raises(RuntimeError, match="could not safely reserve"):
                    with server._manual_compress_turn("ui", session):
                        pass
                # A new process constructs its history from the committed SQLite rows.
                # Once the old runtime lease is gone, a fresh record can own that tip.
                resumed_history, _display, _prefix = server._load_resume_transcript(
                    fresh, parent, model_history_only=True)
                assert len(resumed_history) == len(durable)
                if session.get("active_session_lease") is not None:
                    session["active_session_lease"].release()
                restart_db = SessionDB(db_path=tmp_path / "state.db")
                resumed_agent = AIAgent(
                    api_key="fixture-only", base_url="http://127.0.0.1:9/v1", model="test/model",
                    platform="tui", quiet_mode=True, session_db=restart_db, session_id=parent,
                    skip_context_files=True, skip_memory=True, enabled_toolsets=[],
                )
                resumed = {
                    "agent": resumed_agent, "history_lock": threading.Lock(),
                    "history": resumed_history, "history_version": 0, "running": False,
                    "session_key": parent, "profile_home": home, "source": "tui",
                    "active_session_lease": None,
                }
                try:
                    assert server._ensure_active_session_slot("restarted", resumed) is None
                    assert server._prove_active_session_slot("restarted", resumed) is None
                    assert resumed.get("_compression_faulted") is None
                finally:
                    if resumed.get("active_session_lease") is not None:
                        resumed["active_session_lease"].release()
                    resumed_agent.close()
                    restart_db.close()
            _resume_in_fresh_tui_record(monkeypatch, fresh, parent, parent)
        finally:
            fresh.close()
    finally:
        db._conn = real_conn
        db.archive_and_compact = real_archive
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()
        agent.close()
        db.close()


@pytest.mark.parametrize("fault", ["unreadable_sqlite", "failed_registry_compensation"])
def test_unresolved_commit_fault_blocks_live_route_and_restart_resolves_from_db(
        tmp_path, monkeypatch, fault):
    db, agent, session, before, home, compressor, hooks = _real_session(
        tmp_path, monkeypatch, in_place=False)
    parent = session["session_key"]
    child = "child-unresolved-commit"
    compressor.compress.side_effect = lambda _messages, *_a, **_kw: [
        {"role": "user", "content": SUMMARY_PREFIX + " earlier turns"}, before[-1].copy()]
    real_conn = db._conn
    real_stage = session_compression._TuiCompressionCommit.stage_route_before_sqlite_commit
    real_get = db.get_session
    real_write = active._write_entries
    staged = False
    fired = False

    def stage_route(commit, child_id):
        nonlocal staged
        real_stage(commit, child_id)
        staged = True

    def get_with_fault(session_id):
        if fault == "unreadable_sqlite" and staged:
            raise OSError("injected readback failure")
        return real_get(session_id)

    def write_with_fault(path, entries):
        if (fault == "failed_registry_compensation" and staged
                and any(row.get("session_id") == parent for row in entries)):
            raise OSError("injected compensation write failure")
        return real_write(path, entries)

    class CommitFaultConnection:
        def __getattr__(self, name):
            return getattr(real_conn, name)

        def commit(self):
            nonlocal fired
            if staged and not fired:
                fired = True
                raise OSError("injected SQLite COMMIT failure")
            return real_conn.commit()

    try:
        db._conn = CommitFaultConnection()
        with patch.object(core, "mint_session_id", return_value=child), patch.object(
                session_compression._TuiCompressionCommit, "stage_route_before_sqlite_commit", stage_route), \
                patch.object(db, "get_session", side_effect=get_with_fault), \
                patch.object(active, "_write_entries", side_effect=write_with_fault):
            with pytest.raises(RuntimeError, match="persistence failed"):
                with server._manual_compress_turn("ui", session):
                    server._compress_session_history(session)
        db._conn = real_conn
        assert staged and fired and session["_compression_faulted"] is True
        assert server._ensure_active_session_slot("ui", session) is not None
        assert server._prove_active_session_slot("ui", session) is not None
        old_runtime = server._sessions.get("ui")
        server._sessions["ui"] = session
        try:
            refused = server.handle_request(
                {"id": "faulted-prompt", "method": "prompt.submit",
                 "params": {"session_id": "ui", "text": "continue"}})
            assert refused["error"]["code"] == 4090
        finally:
            if old_runtime is None:
                server._sessions.pop("ui", None)
            else:
                server._sessions["ui"] = old_runtime
        with pytest.raises(RuntimeError, match="could not safely reserve"):
            with server._manual_compress_turn("ui", session):
                pass
        assert session["history"] == before and session["history_version"] == 0
        assert "session:compress" not in hooks
        fresh = SessionDB(db_path=tmp_path / "state.db")
        try:
            assert fresh.get_session(parent)["ended_at"] is None
            assert fresh.get_session(child) is None
            assert fresh.resolve_resume_session_id(parent) == parent
            assert fresh.get_messages_as_conversation(parent) == before
            _resume_in_fresh_tui_record(monkeypatch, fresh, parent, parent)
        finally:
            fresh.close()
    finally:
        db._conn = real_conn
        if session.get("active_session_lease") is not None:
            session["active_session_lease"].release()
        agent.close()
        db.close()
