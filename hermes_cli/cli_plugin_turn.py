"""CLI native turn ownership and route transitions, separate from prompt rendering."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import secrets

from agent.delegation_context import is_delegated_child_process_context
from hermes_cli.active_sessions import active_session_lease_guard

_BOUND_TURN = ContextVar("cli_native_turn", default=None)
_CANDIDATE = ContextVar("cli_native_candidate", default=None)


def current_candidate():
    return _CANDIDATE.get()


@contextmanager
def candidate_scope(candidate):
    token = _CANDIDATE.set(candidate)
    try:
        yield
    finally:
        _CANDIDATE.reset(token)


def cli_route_bound():
    return _BOUND_TURN.get() is not None


def interrupt_cli_turn(cli, interrupt=None):
    from agent.interrupt_compat import request_hard_interrupt
    host = getattr(cli, "_native_plugin_host", None)
    if host is not None:
        host.invalidate()
    return (interrupt or request_hard_interrupt)(cli.agent)


def claim_for_cli_tool(native_session_id):
    bound = _BOUND_TURN.get()
    if bound is None or is_delegated_child_process_context():
        return None
    host, _ = bound
    claim = host.claim()
    return claim if claim and claim.is_current(native_session_id=native_session_id) else None


def tool_claim_current(host, claim):
    with host.lock:
        return _tool_claim_current_locked(host, claim)


def _tool_claim_current_locked(host, claim):
    bound = _BOUND_TURN.get()
    active = host.active_turn
    if (is_delegated_child_process_context() or bound is None or active is None
            or bound[0] is not host or bound[1] is not active):
        return False
    if (not host.route_current(claim) or host.cli.agent is not active[1]
            or (claim.native_session_id, claim.route_epoch) != active[3:]):
        return False
    try:
        with active_session_lease_guard(active[2], session_id=claim.native_session_id,
                live_session_id=claim.native_session_id, registry_home=host.home):
            return True
    except (OSError, RuntimeError):
        return False


def cli_route_transition(method):
    @wraps(method)
    def guarded(cli, *args, **kwargs):
        host = getattr(cli, "_native_plugin_host", None)
        if host is None:
            return method(cli, *args, **kwargs)
        if cli_route_bound():
            raise RuntimeError("CLI route transition cannot run inside its active turn")
        with host.turn_lock, host.lock:
            host.blocked = True
            host.epoch = secrets.token_urlsafe(24)
            try:
                return method(cli, *args, **kwargs)
            finally:
                host.native = str(cli.session_id or "")
                host.blocked = False
    return guarded


def _claim_slot(host):
    cli = host.cli
    lease = getattr(cli, "_active_session_lease", None)
    if lease is not None and lease.session_id != host.native:
        cli._release_active_session()
    if not cli._claim_active_session("cli"):
        raise RuntimeError("CLI active session slot unavailable")
    return getattr(cli, "_active_session_lease", None)


def _settle_candidate(host, row):
    if row is None:
        return
    if (row is not host.candidate or row["epoch"] != host.epoch or row["native_id"] != host.native
            or row["profile"] != host.profile):
        raise RuntimeError("CLI native candidate route changed")
    from hermes_cli.cli_plugin_consumer import _eligible
    if not _eligible(host, row):
        raise RuntimeError("CLI native candidate owner unavailable")
    if not host.queue.transition(row["candidate"], "dispatching", "running"):
        raise RuntimeError("CLI native candidate already consumed")
    from hermes_cli.trusted_inbound_broker import NativeCandidateSnapshot, TrustedInboundBrokerClient
    running = host.queue.lookup(row["profile"], row["epoch"], row["delivery"])
    immutable_fields = ("sequence", "profile", "epoch", "delivery", "session_key", "native_id",
                        "owner", "plugin", "content", "payload_digest", "candidate", "reason")
    if running is None or any(running[field] != row[field] for field in immutable_fields):
        raise RuntimeError("CLI native candidate changed")
    claim = host.claim()
    active = host.active_turn
    if (claim is None or active is None or active[3:] != (host.native, host.epoch)
            or (running["profile"], running["session_key"], running["native_id"],
                running["epoch"], running["owner"]) !=
               (host.profile, claim.session_key, claim.native_session_id,
                claim.route_epoch, claim.host_owner_id)):
        raise RuntimeError("CLI native candidate route changed")
    try:
        snapshot = NativeCandidateSnapshot.from_running_row(running, surface="cli", content=row["content"])
    except ValueError as exc:
        raise RuntimeError("CLI native candidate changed") from exc
    if snapshot.candidate_id != row["candidate"] or snapshot.host_owner_id != host.owner:
        raise RuntimeError("CLI native candidate owner changed")
    TrustedInboundBrokerClient().observe_native_turn(snapshot)
    if not host.queue.settle(row):
        raise RuntimeError("CLI native candidate settlement unavailable")


@contextmanager
def cli_native_turn(cli, candidate):
    host = getattr(cli, "_native_plugin_host", None)
    if host is None or (not host.native and candidate is None):
        yield
        return
    # Thread ownership is private and exact; neither task scheduling nor a busy flag is proof.
    with host.turn_lock:
        with host.lock, host.manager._admission_host_lock:
            claim = host.claim()
            if claim is None:
                raise RuntimeError("CLI native route unavailable")
            lease = _claim_slot(host)
            with active_session_lease_guard(lease, session_id=host.native,
                    live_session_id=host.native, registry_home=host.home):
                if host.active_turn is not None:
                    raise RuntimeError("CLI native turn already active")
                active = (object(), cli.agent, lease, host.native, host.epoch)
                host.active_turn = active
                try:
                    _settle_candidate(host, candidate)
                except BaseException:  # health: allow BLE001 -- release private ownership after uncertain commit
                    host.active_turn = None
                    raise
        token = _BOUND_TURN.set((host, active))
        try:
            yield
        finally:
            _BOUND_TURN.reset(token)
            with host.lock:
                host.active_turn = None


def run_cli_conversation(cli, *, native_candidate=None, **kwargs):
    with cli_native_turn(cli, native_candidate or current_candidate()):
        return cli.agent.run_conversation(**kwargs)
