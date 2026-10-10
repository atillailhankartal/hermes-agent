"""CLI native delivery admission through production startup and real SQLite."""
from contextlib import ExitStack

import pytest


@pytest.fixture
def shell(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_DEFER_AGENT_STARTUP", "1")
    from hermes_cli.plugins import _reset_plugin_managers_for_tests
    _reset_plugin_managers_for_tests()
    import cli
    instance = cli.HermesCLI(compact=True, max_turns=1)
    instance._tui_init_run_state()
    yield instance
    host = getattr(instance, "_native_plugin_host", None)
    if host:
        host.close()
    instance._release_active_session()
    _reset_plugin_managers_for_tests()


def test_real_cli_startup_publishes_typed_host(shell):
    from hermes_cli.plugins import get_plugin_manager
    host = get_plugin_manager()._admission_hosts.get("cli")
    assert host is not None
    assert host[0] is shell._native_plugin_host


def test_idle_candidate_is_not_a_native_turn_receipt(shell):
    host, ctx = context(shell)
    claim = host.claim()
    assert not shell._agent_running
    assert not claim.is_current(native_session_id=shell.session_id)
    receipt = deliver(ctx, claim)
    assert receipt.state == "unknown" and receipt.candidate_id is None
    row = host.queue.lookup(host.profile, claim.route_epoch, "delivery")
    assert row["execution"] == "queued"
    assert host.query(route_claim=claim, delivery_id="delivery",
        expected_content="native prompt") == receipt
    host.close()
    assert not claim.is_route_current()
    assert deliver(ctx, claim, "after-close").state != "admitted"
    assert host.queue.lookup(host.profile, claim.route_epoch, "after-close") is None


def context(shell):
    from hermes_cli.plugins import PluginManifest, LoadedPlugin, PluginContext
    host = shell._native_plugin_host
    manifest = PluginManifest(name="bee", key="bee", source="user")
    host.manager._plugins["bee"] = LoadedPlugin(manifest, enabled=True)
    return host, PluginContext(manifest, host.manager)


def deliver(ctx, claim, delivery="delivery", content="native prompt"):
    return ctx.inject_message_admitted(content, surface="cli", route_claim=claim,
        expected_session_id=claim.native_session_id, delivery_id=delivery)


def test_busy_candidates_durable_distinct_and_restart_query(shell):
    from hermes_cli.cli_plugin_admission import install_cli_admission_host
    host, ctx = context(shell)
    claim = host.claim()
    shell._agent_running = True
    first = deliver(ctx, claim)
    assert first.state == "unknown" and first.candidate_id is None
    assert deliver(ctx, claim) == first
    assert deliver(ctx, claim, "second", "another prompt").state == "unknown"
    assert shell._interrupt_queue.empty() and shell._pending_input.empty()
    row = host.queue.lookup(host.profile, claim.route_epoch, "delivery")
    other = host.queue.lookup(host.profile, claim.route_epoch, "second")
    assert row["candidate"] != other["candidate"]
    assert row["owner"] == claim.host_owner_id
    restarted = install_cli_admission_host(shell)
    new_claim = restarted.claim()
    assert new_claim.host_owner_id != claim.host_owner_id
    assert restarted.query(route_claim=new_claim, route_epoch=claim.route_epoch,
        delivery_id="delivery", expected_content="native prompt") == first
    assert restarted.query(route_claim=new_claim, route_epoch=claim.route_epoch,
        delivery_id="delivery", expected_content="changed").state == "unknown"
    assert host.queue.lookup(host.profile, claim.route_epoch, "delivery")["candidate"] == row["candidate"]


def test_payload_conflict_and_owner_forgery_do_not_insert(shell):
    from dataclasses import replace
    host, ctx = context(shell)
    claim = host.claim()
    deliver(ctx, claim)
    conflict = deliver(ctx, claim, content="changed")
    assert conflict.state == "unknown" and conflict.reason == "native_delivery_conflict"
    assert deliver(ctx, replace(claim, host_owner_id="forged"), "forged").state == "rejected"
    assert host.queue.lookup(host.profile, claim.route_epoch, "forged") is None


def test_postcommit_exception_is_unknown_and_same_id_readback(shell, monkeypatch):
    host, ctx = context(shell)
    claim = host.claim()
    original = host.queue.admit
    def commit_then_fail(**kwargs):
        original(**kwargs)
        raise OSError("committed")
    monkeypatch.setattr(host.queue, "admit", commit_then_fail)
    first = deliver(ctx, claim)
    assert first.state == "unknown"
    row = host.queue.lookup(host.profile, claim.route_epoch, "delivery")
    assert deliver(ctx, claim) == first
    assert host.queue.lookup(host.profile, claim.route_epoch, "delivery")["candidate"] == row["candidate"]


def bind_real_agent_thread(shell, callback):
    """Stub only model execution; use the production CLI agent-thread body."""
    from types import SimpleNamespace
    import threading
    shell.agent = SimpleNamespace(session_id=shell.session_id, run_conversation=callback)
    shell.conversation_history = [{"role": "user", "content": "native prompt"}]
    def chat(message, images=None):
        turn = SimpleNamespace(voice_prefix="", stream_callback=None, result=None)
        from hermes_cli.cli_plugin_turn import current_candidate
        turn.native_plugin_candidate = current_candidate()
        thread = threading.Thread(target=shell._chat_run_agent, args=(turn, message))
        thread.start()
        thread.join(timeout=10)
        assert not thread.is_alive()
        shell._last_turn_result = turn.result
        return turn.result
    shell.chat = chat


def test_actual_agent_thread_settles_only_with_native_slot(shell):
    host, ctx = context(shell)
    claim = host.claim()
    seen = []
    def model(**kwargs):
        seen.append((kwargs["user_message"], host.query(route_claim=claim,
            delivery_id="delivery", expected_content="native prompt")))
        assert claim.is_current(native_session_id=shell.session_id)
        return {"messages": [], "final_response": "done", "completed": True}
    bind_real_agent_thread(shell, model)
    assert deliver(ctx, claim).state == "unknown"
    assert host.drain_one()
    assert len(seen) == 1 and seen[0][0] == "native prompt"
    assert seen[0][1].state == "admitted" and seen[0][1].candidate_id
    assert not claim.is_current(native_session_id=shell.session_id)
    assert deliver(ctx, claim) == seen[0][1]
    assert not host.drain_one()


def test_slot_failure_never_settles_or_requeues(shell, monkeypatch):
    host, ctx = context(shell)
    claim = host.claim()
    called = []
    bind_real_agent_thread(shell, lambda **kw: called.append(kw))
    monkeypatch.setattr(shell, "_claim_active_session", lambda *a, **kw: False)
    deliver(ctx, claim)
    host.drain_one()
    receipt = host.query(route_claim=claim, delivery_id="delivery", expected_content="native prompt")
    assert receipt.state == "unknown" and receipt.candidate_id is None
    assert not called
    assert deliver(ctx, claim) == receipt
    assert not host.drain_one()


def test_real_new_session_invalidates_old_epoch(shell):
    host, ctx = context(shell)
    claim = host.claim()
    deliver(ctx, claim)
    shell.new_session(silent=True)
    assert not claim.is_route_current()
    next_claim = host.claim()
    assert next_claim is not None and next_claim.route_epoch != claim.route_epoch
    assert next_claim.native_session_id == shell.session_id
    assert not host.drain_one()


def test_quiet_one_shot_drains_before_exit(shell, monkeypatch):
    from types import SimpleNamespace
    from hermes_cli.cli_single_query import _run_quiet_single_query
    host, ctx = context(shell)
    claim = host.claim()
    seen = []
    def model(**kwargs):
        seen.append(kwargs["user_message"])
        assert claim.is_current(native_session_id=shell.session_id)
        if len(seen) == 1:
            assert deliver(ctx, claim).state == "unknown"
        return {"messages": [], "final_response": "done", "completed": True}
    shell.agent = SimpleNamespace(session_id=shell.session_id, run_conversation=model)
    monkeypatch.setattr("hermes_cli.quiet_single_query.quiet_notify_linger_seconds", lambda: 0)
    with pytest.raises(SystemExit) as exited:
        _run_quiet_single_query(shell, "initial")
    assert exited.value.code == 0
    assert seen == ["initial", "native prompt"]
    receipt = host.query(route_claim=claim, delivery_id="delivery", expected_content="native prompt")
    assert receipt.state == "admitted"
    assert host.closed


def test_new_resume_aba_never_revives_old_claim(shell):
    host, ctx = context(shell)
    first = host.claim()
    shell._session_db.create_session(session_id=shell.session_id, source="cli", model=shell.model)
    shell._session_db.append_message(shell.session_id, "user", "keep original session")
    deliver(ctx, first)
    shell.new_session(silent=True)
    middle = host.claim()
    shell._handle_resume_command("/resume " + first.native_session_id)
    last = host.claim()
    assert last.native_session_id == first.native_session_id
    assert len({first.route_epoch, middle.route_epoch, last.route_epoch}) == 3
    assert not first.is_route_current() and not middle.is_route_current()
    assert not host.drain_one()


def test_stop_before_real_turn_invalidates_candidate(shell):
    from hermes_cli.cli_plugin_turn import interrupt_cli_turn
    host, ctx = context(shell)
    claim = host.claim()
    calls = []
    bind_real_agent_thread(shell, lambda **kw: calls.append(kw))
    deliver(ctx, claim)
    interrupt_cli_turn(shell)
    assert not claim.is_route_current()
    assert not host.drain_one()
    assert not calls
    assert host.query(route_claim=claim, delivery_id="delivery", expected_content="native prompt").state == "unknown"


def test_repl_loop_drains_real_thread_and_binds_private_tool_claim(shell, monkeypatch):
    import queue
    import model_tools
    host, ctx = context(shell)
    claim = host.claim()
    dispatched = []
    monkeypatch.setattr(model_tools.registry, "dispatch",
        lambda *a, **kw: dispatched.append(kw) or {"ok": True})
    def model(**kwargs):
        options = dict(user_task=None, enabled_tools=None, skip_tool_execution_middleware=True)
        model_tools._execute_tool("bee_test", {}, {},
            model_tools._CallIds(session_id=shell.session_id), **options)
        model_tools._execute_tool("bee_test", {}, {},
            model_tools._CallIds(session_id="detached-child"), **options)
        return {"messages": [], "final_response": "done", "completed": True}
    bind_real_agent_thread(shell, model)
    deliver(ctx, claim)
    def stop_loop(**kwargs):
        shell._should_exit = True
        raise queue.Empty
    monkeypatch.setattr(shell._pending_input, "get", stop_loop)
    monkeypatch.setattr(shell, "_tui_idle_tick", lambda: None)
    shell._tui_process_loop()
    assert len(dispatched) == 1
    proof = dispatched[0]["route_claim"]
    assert proof.host_owner_id == claim.host_owner_id and proof.route_epoch == claim.route_epoch
    assert host.query(route_claim=claim, delivery_id="delivery", expected_content="native prompt").state == "admitted"


@pytest.mark.parametrize("child_context", ("in_process", "inherited_marker"))
def test_cli_tool_claim_rejects_delegated_child_context(shell, monkeypatch, child_context):
    from agent.delegation_context import DELEGATED_CHILD_ENV_MARKER, delegated_child_context
    from hermes_cli.cli_plugin_turn import cli_native_turn, claim_for_cli_tool

    with cli_native_turn(shell, None):
        parent_claim = claim_for_cli_tool(shell.session_id)
        assert parent_claim is not None
        assert parent_claim.is_current(native_session_id=shell.session_id)

        with ExitStack() as stack:
            if child_context == "in_process":
                stack.enter_context(delegated_child_context(shell.session_id))
            else:
                stack.enter_context(monkeypatch.context()).setenv(DELEGATED_CHILD_ENV_MARKER, "1")
            assert claim_for_cli_tool(shell.session_id) is None
            assert not parent_claim.is_current(native_session_id=shell.session_id)

        assert claim_for_cli_tool(shell.session_id) is not None
        assert parent_claim.is_current(native_session_id=shell.session_id)


def test_admitted_readback_survives_process_reopen_without_replay(shell):
    import json
    import subprocess
    import sys
    from hermes_cli.cli_plugin_admission import install_cli_admission_host
    host, ctx = context(shell)
    claim = host.claim()
    bind_real_agent_thread(shell, lambda **kw: {"messages": [], "completed": True})
    deliver(ctx, claim)
    host.drain_one()
    script = ("import json,sys; from pathlib import Path; "
              "from hermes_cli.cli_plugin_ledger import CliPluginLedger; "
              "q=CliPluginLedger(Path(sys.argv[1])); r=q.lookup(*sys.argv[2:]); "
              "print(json.dumps([r['state'],r['candidate']]))")
    result = json.loads(subprocess.check_output([sys.executable, "-c", script,
        str(host.home / "cli-admission"), host.profile, claim.route_epoch, "delivery"], text=True))
    fresh = install_cli_admission_host(shell)
    receipt = fresh.query(route_claim=fresh.claim(), route_epoch=claim.route_epoch,
        delivery_id="delivery", expected_content="native prompt")
    assert result == ["admitted", receipt.candidate_id]
    assert not fresh.drain_one()


def test_cancellation_before_agent_entry_never_replays(shell, monkeypatch):
    host, ctx = context(shell)
    claim = host.claim()
    deliver(ctx, claim)
    def cancel(_):
        raise KeyboardInterrupt
    monkeypatch.setattr(shell, "chat", cancel)
    with pytest.raises(KeyboardInterrupt):
        host.drain_one()
    assert deliver(ctx, claim).state == "unknown"
    assert not host.drain_one()
    assert not shell._agent_running


def test_slot_boolean_without_real_lease_is_not_admission(shell, monkeypatch):
    host, ctx = context(shell)
    claim = host.claim()
    calls = []
    bind_real_agent_thread(shell, lambda **kw: calls.append(kw))
    monkeypatch.setattr(shell, "_claim_active_session", lambda *a, **kw: True)
    shell._active_session_lease = None
    deliver(ctx, claim)
    host.drain_one()
    assert not calls
    assert host.query(route_claim=claim, delivery_id="delivery", expected_content="native prompt").state == "unknown"


def test_settlement_postcommit_error_has_durable_receipt_and_no_second_turn(shell, monkeypatch):
    host, ctx = context(shell)
    claim = host.claim()
    calls = []
    bind_real_agent_thread(shell, lambda **kw: calls.append(kw))
    original = host.queue.settle
    def settle_then_fail(candidate):
        assert host.active_turn is not None
        assert original(candidate)
        raise OSError("after native turn commit")
    monkeypatch.setattr(host.queue, "settle", settle_then_fail)
    deliver(ctx, claim)
    host.drain_one()
    receipt = host.query(route_claim=claim, delivery_id="delivery", expected_content="native prompt")
    assert receipt.state == "admitted" and receipt.candidate_id
    assert not calls and host.active_turn is None
    assert deliver(ctx, claim) == receipt
    assert not host.drain_one()


def test_private_admit_never_replays_receipt_under_stale_epoch_or_new_owner(shell):
    from dataclasses import replace
    from hermes_cli.cli_plugin_admission import install_cli_admission_host
    host, ctx = context(shell)
    claim = host.claim()
    bind_real_agent_thread(shell, lambda **kw: {"messages": [], "completed": True})
    deliver(ctx, claim)
    host.drain_one()
    historical = host.query(route_claim=claim, delivery_id="delivery", expected_content="native prompt")
    host.invalidate()
    def private_admit(owner, proof):
        return owner.admit(content="native prompt", surface="cli", route_claim=proof,
            expected_session_id=proof.native_session_id, delivery_id="delivery", plugin_id="bee",
            manager=owner.manager)
    assert private_admit(host, claim).state == "unknown"
    fresh = install_cli_admission_host(shell)
    current = fresh.claim()
    assert private_admit(fresh, replace(current, route_epoch=claim.route_epoch)).state == "unknown"
    assert fresh.query(route_claim=current, route_epoch=claim.route_epoch, delivery_id="delivery",
        expected_content="native prompt") == historical


def test_nonquiet_one_shot_entry_drains_native_candidate(shell, monkeypatch):
    import cli
    from hermes_cli.cli_single_query import _run_single_query_mode
    _, ctx = context(shell)
    seen, proofs = [], []
    def model(**kwargs):
        host = shell._native_plugin_host
        claim = host.claim()
        seen.append(kwargs["user_message"])
        if len(seen) == 1:
            proofs.append(claim)
            assert deliver(ctx, claim).state == "unknown"
        return {"messages": [], "final_response": "done", "completed": True}
    bind_real_agent_thread(shell, model)
    monkeypatch.setattr(shell, "_show_security_advisories", lambda: None)
    monkeypatch.setattr(shell, "_print_exit_summary", lambda **kw: None)
    monkeypatch.setattr(cli, "_finalize_single_query", lambda instance: instance._release_active_session())
    with pytest.raises(SystemExit) as exited:
        _run_single_query_mode(shell, "initial", None, False, True)
    assert exited.value.code == 0 and seen == ["initial", "native prompt"]
    host = shell._native_plugin_host
    assert host.closed
    assert host.query(route_claim=proofs[0], delivery_id="delivery", expected_content="native prompt").state == "admitted"


@pytest.mark.parametrize("outcome", [{"interrupted": True}, {"failed": True}])
def test_unsuccessful_quiet_turn_does_not_start_native_followup(shell, monkeypatch, outcome):
    from types import SimpleNamespace
    from hermes_cli.cli_single_query import _run_quiet_single_query
    host, ctx = context(shell)
    claim = host.claim()
    seen = []
    def model(**kwargs):
        seen.append(kwargs["user_message"])
        if len(seen) == 1:
            assert deliver(ctx, claim).state == "unknown"
        return {"messages": [], "final_response": "", "completed": False, **outcome}
    shell.agent = SimpleNamespace(session_id=shell.session_id, run_conversation=model)
    monkeypatch.setattr("hermes_cli.quiet_single_query.quiet_notify_linger_seconds", lambda: 0)
    with pytest.raises(SystemExit) as exited:
        _run_quiet_single_query(shell, "initial")
    assert exited.value.code != 0
    assert seen == ["initial"]
    assert host.query(route_claim=claim, delivery_id="delivery", expected_content="native prompt").state == "unknown"


@pytest.mark.parametrize("rotation", ["invalidate", "restart"])
def test_stale_capacity_does_not_block_fresh_native_turn(shell, rotation):
    from hermes_cli.cli_plugin_admission import install_cli_admission_host
    host, ctx = context(shell)
    old = host.claim()
    for index in range(100):
        assert deliver(ctx, old, f"old-{index}").state == "unknown"
    assert deliver(ctx, old, "over-cap").reason == "native_queue_full"
    original = host.queue.lookup(host.profile, old.route_epoch, "old-0")
    if rotation == "restart":
        host = install_cli_admission_host(shell)
    else:
        host.invalidate()
    fresh = host.claim()
    assert fresh.route_epoch != old.route_epoch
    assert deliver(ctx, fresh, "fresh").state == "unknown"
    row = host.queue.next_candidate(host.profile, fresh.route_epoch, host.owner)
    assert row["delivery"] == "fresh"
    assert deliver(ctx, fresh, "fresh").state == "unknown"
    assert deliver(ctx, fresh, "fresh", "conflict").reason == "native_delivery_conflict"
    seen = []
    bind_real_agent_thread(shell, lambda **kwargs: seen.append(kwargs["user_message"]) or {"final_response": "ok"})
    assert host.drain_one()
    assert not host.drain_one()
    assert seen == ["native prompt"]
    assert host.query(route_claim=fresh, delivery_id="fresh", expected_content="native prompt").state == "admitted"
    assert host.query(route_claim=fresh, route_epoch=old.route_epoch,
        delivery_id="old-0", expected_content="native prompt").state == "unknown"
    assert host.queue.lookup(host.profile, old.route_epoch, "old-0") == original

    import json
    import subprocess
    import sys
    script = ("import json,sys; from pathlib import Path; "
              "from hermes_cli.cli_plugin_ledger import CliPluginLedger; "
              "q=CliPluginLedger(Path(sys.argv[1])); r=q.lookup(*sys.argv[2:]); "
              "print(json.dumps(r))")
    reopened = json.loads(subprocess.check_output([sys.executable, "-c", script,
        str(host.home / "cli-admission"), host.profile, old.route_epoch, "old-0"], text=True))
    assert reopened == original
    for index in range(100):
        assert deliver(ctx, fresh, f"current-{index}").state == "unknown"
    assert deliver(ctx, fresh, "current-over-cap").reason == "native_queue_full"
