"""Ink TUI / desktop host for ``PluginContext.inject_message``.

Separate from ``PluginManager.set_gateway_message_injector``. A messaging gateway
and this process can both be live; they must not share one slot (last writer
would win). The callback is bound to the calling manager's profile and admits
only one exact native conversation into its prompt queue.

Bodies are rebound onto ``server.py`` globals at install time
(``method_ctx.bind_module``), so ``_sessions`` and the queue helpers are bare names.
"""

from __future__ import annotations

import atexit
from dataclasses import dataclass
from pathlib import Path
import threading
import time
from typing import Literal
import uuid

from .method_ctx import bind_module

# Identity for the process-owned host. A later owner can replace it; clear is
# identity-conditional so this process cannot drop that replacement.
_TUI_INJECT_OWNER = object()
_atexit_registered = False
_TUI_ADMISSION_SLOTS = threading.BoundedSemaphore(16)


@dataclass(frozen=True)
class TuiAdmissionReceipt:
    status: Literal["admitted", "rejected", "unknown"]
    reason: str
    candidate_id: str
    delivery_id: str


def _plugin_route_current(
    manager, sid: str, session: dict, *, session_key: str, expected_session_id: str,
    agent, transport, generation: int,
) -> bool:
    """Check the same in-process record and route generation at queue insertion."""
    if _sessions.get(sid) is not session:
        return False
    if session.get("source") not in {"tui", "desktop"}:
        return False
    if any(session.get(flag) for flag in (
        "_closing", "_finalized", "_route_transfer_failed", "pending_hidden", "room_plumbing", "lazy"
    )):
        return False
    if session.get("agent") is not agent or getattr(agent, "session_id", None) != expected_session_id:
        # A cold isolated child has no attested native ID in this parent process.
        return False
    if session.get("transport") is not transport or _transport_is_dead(transport):
        return False
    if session.get("session_key") != session_key:
        return False
    if int(session.get("_queued_prompt_generation", 0)) != generation:
        return False
    try:
        return Path(session.get("profile_home") or _hermes_home).resolve() == Path(manager.home_path).resolve()
    except (OSError, TypeError, ValueError):
        return False


def _remove_plugin_candidate(session: dict, candidate: dict) -> None:
    """Undo a queued candidate if the idle drain could not be scheduled."""
    entries = [entry for entry in (
        [session.get("queued_prompt"), *(session.get("queued_prompts") or [])]
    ) if entry is not None and entry is not candidate]
    _ac_set_queue(session, entries)


def _candidate_is_queued(session: dict, candidate: dict) -> bool:
    return any(item is candidate for item in
               [session.get("queued_prompt"), *(session.get("queued_prompts") or [])])


def _admit_tui_candidate(
    *, manager, session_key: str, expected_session_id: str, content: str,
    plugin_id: str, route_claim, candidate_id: str, delivery_id: str, publish,
) -> None:
    """Publish a receipt at the exact insertion point, before slow persistence.

    The current TUI record has no host-issued opaque epoch yet. Reject a supplied
    claim until that protocol exists; caller data cannot authorize a route. The
    real registry lease and the in-process record stay pinned through insertion.
    """
    from hermes_cli.active_sessions import ActiveSessionRegistryError, active_session_lease_guard
    from hermes_cli.input_sanitize import sanitize_user_prompt_text

    def finish(status: Literal["admitted", "rejected", "unknown"], reason: str) -> None:
        publish(TuiAdmissionReceipt(status, reason, candidate_id, delivery_id))

    if not all(isinstance(value, str) and value.strip()
               for value in (session_key, expected_session_id, content, plugin_id)):
        finish("rejected", "invalid_target")
        return
    if route_claim is not None:
        finish("rejected", "host_epoch_unavailable")
        return
    if not manager._tui_injection_allowed(plugin_id):
        finish("rejected", "tui_grant_denied")
        return
    with _sessions_lock:
        matches = [(sid, session) for sid, session in _sessions.items()
                   if isinstance(session, dict) and session.get("session_key") == session_key]
        if len(matches) != 1:
            finish("rejected", "route_not_unique")
            return
        sid, session = matches[0]
        agent, transport = session.get("agent"), session.get("transport")
        generation = int(session.get("_queued_prompt_generation", 0))
        if not _plugin_route_current(
            manager, sid, session, session_key=session_key, expected_session_id=expected_session_id,
            agent=agent, transport=transport, generation=generation,
        ):
            finish("rejected", "route_not_current")
            return
    # Session slot acquisition may wait on another process. It happens outside
    # the record/history locks; the route is checked again at the insertion point.
    held_lease = session.get("active_session_lease")
    if _ensure_active_session_slot(sid, session) is not None:
        finish("rejected", "lease_refused")
        return
    claimed_lease = session.get("active_session_lease")
    accepted = False
    candidate = None
    insertion_started = False
    try:
        text = sanitize_user_prompt_text(content)
        with session["history_lock"], _sessions_lock:
            if not _plugin_route_current(
                manager, sid, session, session_key=session_key, expected_session_id=expected_session_id,
                agent=agent, transport=transport, generation=generation,
            ) or not manager._tui_injection_allowed(plugin_id):
                finish("rejected", "route_changed_before_insert")
                return
            with active_session_lease_guard(
                claimed_lease, session_id=session_key, live_session_id=sid,
                registry_home=session.get("profile_home"),
            ):
                insertion_started = True
                candidate = _enqueue_prompt(
                    session, text, transport, image_paths=[], plugin_origin=plugin_id,
                    plugin_candidate_id=candidate_id, plugin_delivery_id=delivery_id,
                )
                if candidate is None or not _candidate_is_queued(session, candidate):
                    insertion_started = False
                    finish("rejected", "candidate_not_inserted")
                    return
                if not session.get("running"):
                    rid = f"inject-{uuid.uuid4().hex[:8]}"
                    try:
                        worker = _start_session_work(
                            lambda: _drain_queued_prompt(rid, sid, session),
                            name=f"tui-inject-{sid[:8]}", session=session,
                        )
                    except Exception:  # health: allow BLE001 -- a failed start may have begun; report uncertain admission
                        finish("unknown", "drain_start_uncertain")
                        return
                    if worker is None:
                        _remove_plugin_candidate(session, candidate)
                        candidate = None
                        insertion_started = False
                        finish("rejected", "drain_not_reserved")
                        return
                accepted = True
                session["last_active"] = time.time()
                finish("admitted", "candidate_inserted")
                try:
                    _persist_queued_user_row(session, candidate, None)
                except Exception:  # health: allow BLE001 -- an accepted candidate remains accepted if persistence fails
                    # The in-memory candidate has already been admitted and may
                    # be draining. A storage failure cannot turn that receipt
                    # into a truthful rejection.
                    logger.warning("TUI plugin candidate persistence failed for %s", plugin_id)
    except ActiveSessionRegistryError:
        finish("rejected", "lease_not_current")
    except Exception:  # health: allow BLE001 -- unknown mutation state must not become a false rejection
        # No prompt body or plugin exception detail in logs.
        logger.warning("TUI plugin admission failed for plugin %s", plugin_id)
        finish("unknown", "admission_exception")
    finally:
        if (held_lease is None and not accepted and not insertion_started
                and session.get("active_session_lease") is claimed_lease
                and not session.get("running")):
            _release_active_session_slot(session)


def admit_tui_session_message(
    *, manager, session_key: str, expected_session_id: str, content: str,
    plugin_id: str, route_claim=None, delivery_id: str | None = None,
    timeout_seconds: float = 5.0,
) -> TuiAdmissionReceipt:
    """Return admitted/rejected/unknown without treating a timeout as a rejection.

    The worker may finish after a timeout. Its candidate ID stays on the queue
    envelope so a future public receipt/settlement API can correlate that result.
    """
    candidate_id = uuid.uuid4().hex
    identity = delivery_id if delivery_id is not None else candidate_id
    if not isinstance(identity, str) or not identity.strip():
        return TuiAdmissionReceipt("rejected", "invalid_delivery_id", candidate_id, str(identity))
    try:
        wait = float(timeout_seconds)
    except (TypeError, ValueError):
        return TuiAdmissionReceipt("rejected", "invalid_timeout", candidate_id, identity)
    if not 0 <= wait <= 30:
        return TuiAdmissionReceipt("rejected", "invalid_timeout", candidate_id, identity)
    if not _TUI_ADMISSION_SLOTS.acquire(blocking=False):
        return TuiAdmissionReceipt("rejected", "admission_capacity", candidate_id, identity)

    done = threading.Event()
    result: dict[str, TuiAdmissionReceipt] = {}

    def publish(receipt: TuiAdmissionReceipt) -> None:
        if "receipt" not in result:
            result["receipt"] = receipt
            done.set()

    def work() -> None:
        try:
            _admit_tui_candidate(
                manager=manager, session_key=session_key, expected_session_id=expected_session_id,
                content=content, plugin_id=plugin_id, route_claim=route_claim,
                candidate_id=candidate_id, delivery_id=identity, publish=publish,
            )
        except Exception:  # health: allow BLE001 -- no worker failure may be mistaken for a definite denial
            logger.warning("TUI plugin admission worker failed for %s", plugin_id)
            publish(TuiAdmissionReceipt("unknown", "worker_exception", candidate_id, identity))
        finally:
            _TUI_ADMISSION_SLOTS.release()

    try:
        from agent.memory_provider import spawn_context_thread
        spawn_context_thread(work, name="tui-plugin-admission").start()
    except Exception:  # health: allow BLE001 -- thread.start may fail after scheduling; caller must get unknown
        _TUI_ADMISSION_SLOTS.release()
        return TuiAdmissionReceipt("unknown", "worker_start_uncertain", candidate_id, identity)
    if not done.wait(wait):
        return TuiAdmissionReceipt("unknown", "admission_timeout", candidate_id, identity)
    return result["receipt"]


def inject_tui_session_message(
    *, manager, session_key: str, expected_session_id: str, content: str,
    plugin_id: str, route_claim=None,
) -> bool:
    """Compatibility API: only an exact admitted candidate maps to literal True."""
    return admit_tui_session_message(
        manager=manager, session_key=session_key, expected_session_id=expected_session_id,
        content=content, plugin_id=plugin_id, route_claim=route_claim,
    ).status == "admitted"


# Only this host callback receives its calling manager. Third-party callbacks
# keep the legacy kwargs contract through TuiPluginHostMixin.
inject_tui_session_message._tui_manager_aware = True


def install_tui_message_injector(manager=None) -> None:
    """Publish this process's TUI host on *manager*, or the active profile's manager.

    Passing a manager (tests) does not publish process-wide. The no-arg form is
    the Ink TUI / desktop startup path: every profile manager in this process
    gets the host, and managers created later pick it up, without touching the
    messaging-gateway slot.
    """
    from hermes_cli.plugins import get_plugin_manager, publish_tui_message_host

    global _atexit_registered
    if manager is None:
        publish_tui_message_host(_TUI_INJECT_OWNER, inject_tui_session_message)
        manager = get_plugin_manager()
        if not _atexit_registered:
            atexit.register(clear_tui_message_injector)
            _atexit_registered = True
        return
    manager.set_tui_message_injector(_TUI_INJECT_OWNER, inject_tui_session_message)


def clear_tui_message_injector(manager=None) -> None:
    """Drop this process's host. A different owner is left in place."""
    from hermes_cli.plugins import clear_published_tui_message_host

    if manager is None:
        clear_published_tui_message_host(_TUI_INJECT_OWNER)
        return
    manager.clear_tui_message_injector(_TUI_INJECT_OWNER)


def register(server) -> None:
    """Publish this module's helpers onto ``server``, rebound to its globals."""
    bind_module(globals(), server, skip=("_",))
