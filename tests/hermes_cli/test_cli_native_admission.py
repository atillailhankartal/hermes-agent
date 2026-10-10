"""CLI native delivery admission through production startup and real SQLite."""
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
