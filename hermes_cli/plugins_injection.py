"""Host routing for ``PluginContext.inject_message``: classic CLI REPL, Ink TUI / desktop, messaging
gateway (existing ``session_key`` or a new session at ``origin``)."""
from __future__ import annotations

import logging
import asyncio
import threading
import weakref
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional

from hermes_cli.middleware import OBSERVER_SCHEMA_VERSION

logger = logging.getLogger("hermes_cli.plugins")

_ADMISSION_WAIT_SECONDS = 5.0  # Queue insertion only; never wait for the model turn.
_MAX_ADMISSION_WORKERS_PER_SURFACE = 4
_HOST_SURFACES = ("cli", "gateway", "tui")
_admission_workers_lock = threading.Lock()
_admission_workers: weakref.WeakKeyDictionary[Any, dict[str, int]] = weakref.WeakKeyDictionary()

# Separate process slots: legacy bool callbacks remain managed in plugins.py.
_published_admission_hosts: dict[str, tuple[object, Callable[..., AdmissionReceipt], str]] = {}
_published_admission_hosts_lock = threading.Lock()
_published_keyed_lifecycle_hosts: dict[str, tuple[object, str]] = {}
_published_keyed_lifecycle_hosts_lock = threading.Lock()


@dataclass(frozen=True)
class AdmissionReceipt:
    """Exact host result for one delivery, never a scheduler acknowledgement."""

    state: Literal["admitted", "rejected", "unknown"]
    reason: str
    delivery_id: str
    route_epoch: str | None
    admission_id: str | None = None

    @property
    def candidate_id(self) -> str | None:
        return self.admission_id

    def __bool__(self) -> bool:
        raise TypeError("Inspect AdmissionReceipt.state explicitly")


def _admission_receipt(state: Literal["rejected", "unknown"], reason: str,
                       delivery_id: str, route_epoch: str | None) -> AdmissionReceipt:
    return AdmissionReceipt(state, reason, delivery_id, route_epoch)


def _reserve_admission_worker(manager: Any, surface: str) -> bool:
    with _admission_workers_lock:
        counts = _admission_workers.setdefault(manager, {})
        if counts.get(surface, 0) >= _MAX_ADMISSION_WORKERS_PER_SURFACE:
            return False
        counts[surface] = counts.get(surface, 0) + 1
        return True


def _release_admission_worker(manager: Any, surface: str) -> None:
    with _admission_workers_lock:
        counts = _admission_workers.get(manager)
        if counts is None:
            return
        remaining = counts.get(surface, 0) - 1
        if remaining > 0:
            counts[surface] = remaining
        else:
            counts.pop(surface, None)
        if not counts:
            _admission_workers.pop(manager, None)


def _claim_matches(claim: Any, *, surface: str, profile_home_key: str,
                   expected_session_id: str) -> bool:
    """Accept only an in-process host claim with exact live route coordinates."""
    if claim is None or isinstance(claim, Mapping):
        return False
    try:
        fields = (claim.surface, claim.profile_home_key, claim.session_key,
                  claim.native_session_id, claim.route_epoch, claim.host_owner_id)
        return (all(isinstance(value, str) and value.strip() for value in fields)
                and claim.surface == surface and claim.profile_home_key == profile_home_key
                and claim.native_session_id == expected_session_id
                and callable(claim.is_route_current) and claim.is_route_current() is True)
    except Exception:  # health: allow BLE001 -- untrusted host validator must deny malformed proof
        return False


def _call_host_bounded(
    manager: Any, surface: str, registered: tuple[object, Callable, str],
    callback_kwargs: dict[str, Any], delivery_id: str, route_epoch: str,
) -> Any:
    """Return a callback result or an unknown receipt; late workers keep their slot."""
    if not _reserve_admission_worker(manager, surface):
        return _admission_receipt("unknown", "admission_workers_saturated", delivery_id, route_epoch)
    done = threading.Event()
    outcome: dict[str, Any] = {}

    def invoke_host() -> None:
        try:
            # The caller may be inside a different profile. Keep its other ContextVars,
            # but bind host work to the manager that authorized this delivery.
            from hermes_cli.plugins import _plugin_home_scope
            with _plugin_home_scope(manager.home_path):
                outcome["receipt"] = registered[1](**callback_kwargs)
        except BaseException:  # health: allow BLE001 -- worker must release capacity even on host failure
            outcome["failed"] = True
        finally:
            _release_admission_worker(manager, surface)
            done.set()

    worker = None
    try:
        from agent.memory_provider import spawn_context_thread
        worker = spawn_context_thread(invoke_host, name="plugin-admission")
        worker.start()
    except Exception:  # health: allow BLE001 -- scheduler may fail after dispatch was attempted
        # A scheduler can report failure after starting the thread. In that case
        # the late callback owns its capacity slot until it actually finishes.
        if worker is None or worker.ident is None:
            _release_admission_worker(manager, surface)
        return _admission_receipt("unknown", "host_worker_start_failed", delivery_id, route_epoch)
    if not done.wait(_ADMISSION_WAIT_SECONDS):
        return _admission_receipt("unknown", "admission_timeout", delivery_id, route_epoch)
    if outcome.get("failed"):
        logger.warning("plugin admission result unknown for %s", callback_kwargs["plugin_id"])
        return _admission_receipt("unknown", "host_callback_failed", delivery_id, route_epoch)
    return outcome.get("receipt")


def publish_admission_host(surface: Literal["cli", "gateway", "tui"], owner: object,
                           callback: Callable[..., AdmissionReceipt], host_owner_id: str) -> None:
    """Atomically publish the typed callback to existing and future profile managers."""
    from hermes_cli.plugins import _known_plugin_managers

    if (surface not in _HOST_SURFACES or owner is None or not callable(callback)
            or not isinstance(host_owner_id, str) or not host_owner_id.strip()):
        raise ValueError("invalid admission host")
    with _published_admission_hosts_lock:
        _published_admission_hosts[surface] = (owner, callback, host_owner_id)
        for manager in _known_plugin_managers():
            manager.set_admission_host(surface, owner, callback, host_owner_id)


def clear_published_admission_host(surface: str, owner: object) -> None:
    from hermes_cli.plugins import _known_plugin_managers

    with _published_admission_hosts_lock:
        if (surface in _published_admission_hosts
                and _published_admission_hosts[surface][0] is owner):
            _published_admission_hosts.pop(surface, None)
        for manager in _known_plugin_managers():
            manager.clear_admission_host(surface, owner)


def publish_keyed_lifecycle_host(surface: Literal["cli", "gateway", "tui"],
                                 owner: object, host_owner_id: str) -> None:
    """Publish an owner whose private route claims may dispatch keyed hooks."""
    from hermes_cli.plugins import _known_plugin_managers

    if (surface not in _HOST_SURFACES or owner is None
            or not isinstance(host_owner_id, str) or not host_owner_id.strip()):
        raise ValueError("invalid keyed lifecycle host")
    with _published_keyed_lifecycle_hosts_lock:
        _published_keyed_lifecycle_hosts[surface] = (owner, host_owner_id)
        for manager in _known_plugin_managers():
            manager.set_keyed_lifecycle_host(surface, owner, host_owner_id)


def clear_published_keyed_lifecycle_host(surface: str, owner: object) -> None:
    from hermes_cli.plugins import _known_plugin_managers

    with _published_keyed_lifecycle_hosts_lock:
        if (surface in _published_keyed_lifecycle_hosts
                and _published_keyed_lifecycle_hosts[surface][0] is owner):
            _published_keyed_lifecycle_hosts.pop(surface, None)
        for manager in _known_plugin_managers():
            manager.clear_keyed_lifecycle_host(surface, owner)


def attach_published_host_apis(manager: Any) -> None:
    """Attach published slots after manager registration, with publication lock ordering."""
    with _published_admission_hosts_lock:
        for surface, (owner, callback, host_owner_id) in _published_admission_hosts.items():
            with manager._admission_host_lock:
                present = surface in manager._admission_hosts
            if not present:
                manager.set_admission_host(surface, owner, callback, host_owner_id)
    with _published_keyed_lifecycle_hosts_lock:
        for surface, (owner, host_owner_id) in _published_keyed_lifecycle_hosts.items():
            with manager._keyed_lifecycle_lock:
                present = surface in manager._keyed_lifecycle_hosts
            if not present:
                manager.set_keyed_lifecycle_host(surface, owner, host_owner_id)


def reset_published_host_apis() -> None:
    """Test-only process publication reset (manager cache is cleared separately)."""
    with _published_admission_hosts_lock:
        _published_admission_hosts.clear()
    with _published_keyed_lifecycle_hosts_lock:
        _published_keyed_lifecycle_hosts.clear()


def inject_plugin_message_admitted(
    ctx: Any, content: str, *, surface: str, route_claim: Any,
    expected_session_id: str, delivery_id: str,
) -> AdmissionReceipt:
    """Run every route observation under the authorizing manager's profile."""
    from hermes_cli.plugins import _plugin_home_scope

    with _plugin_home_scope(ctx._manager.home_path):
        return _inject_plugin_message_admitted_scoped(
            ctx, content, surface=surface, route_claim=route_claim,
            expected_session_id=expected_session_id, delivery_id=delivery_id,
        )


def _inject_plugin_message_admitted_scoped(
    ctx: Any, content: str, *, surface: str, route_claim: Any,
    expected_session_id: str, delivery_id: str,
) -> AdmissionReceipt:
    """Ask a separately registered host for a definitive candidate insertion result.

    Legacy Gateway/TUI bool callbacks are never consulted. A timeout or exception after
    dispatch is ambiguous, so it is ``unknown`` rather than a retryable rejection.
    A route change after dispatch stays unknown until a same-delivery host status query
    proves whether the candidate was inserted; never retry blindly on that result.
    """
    manager = ctx._manager
    epoch = getattr(route_claim, "route_epoch", None)
    epoch = epoch if isinstance(epoch, str) and epoch else None
    if not isinstance(delivery_id, str) or not delivery_id.strip():
        return _admission_receipt("rejected", "invalid_delivery_id", delivery_id, epoch)
    if not all(isinstance(value, str) and value.strip()
               for value in (content, expected_session_id)) or surface not in _HOST_SURFACES:
        return _admission_receipt("rejected", "invalid_request", delivery_id, epoch)
    if not _claim_matches(route_claim, surface=surface, profile_home_key=manager.scope_key,
                          expected_session_id=expected_session_id):
        return _admission_receipt("rejected", "invalid_route_claim", delivery_id, epoch)
    if surface == "gateway":
        allowed = ctx._gateway_injection_allowed()
    elif surface == "tui":
        allowed = manager._tui_injection_allowed(ctx.plugin_id)
    else:
        allowed = True  # CLI admission still requires a separately published typed host.
    if not allowed:
        return _admission_receipt("rejected", "plugin_grant_denied", delivery_id, epoch)
    loaded = manager._plugins.get(ctx.plugin_id)
    if loaded is None or not loaded.enabled or loaded.error:
        return _admission_receipt("rejected", "plugin_unloaded", delivery_id, epoch)
    with manager._admission_host_lock:
        registered = manager._admission_hosts.get(surface)
    if registered is None:
        return _admission_receipt("rejected", "admission_host_unavailable", delivery_id, epoch)
    if route_claim.host_owner_id != registered[2]:
        return _admission_receipt("rejected", "host_owner_mismatch", delivery_id, epoch)
    # A synchronous callback on its own event-loop thread could deadlock waiting for
    # the same loop to insert a candidate. The async host seam is a separate slice.
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        return _admission_receipt("rejected", "sync_event_loop_unavailable", delivery_id, epoch)
    try:
        route_still_current = route_claim.is_route_current() is True
    except Exception:  # health: allow BLE001 -- route may revoke between validation and dispatch
        route_still_current = False
    if not route_still_current:
        return _admission_receipt("rejected", "route_changed_before_dispatch", delivery_id, epoch)
    with manager._admission_host_lock:
        if manager._admission_hosts.get(surface) is not registered:
            return _admission_receipt("rejected", "admission_host_replaced", delivery_id, epoch)
    result = _call_host_bounded(
        manager, surface, registered,
        dict(content=content, surface=surface, route_claim=route_claim,
             expected_session_id=expected_session_id, delivery_id=delivery_id,
             plugin_id=ctx.plugin_id, manager=manager),
        delivery_id, epoch,
    )
    with manager._admission_host_lock:
        if manager._admission_hosts.get(surface) is not registered:
            return _admission_receipt("unknown", "admission_host_replaced", delivery_id, epoch)
    if (not isinstance(result, AdmissionReceipt) or result.delivery_id != delivery_id
            or result.route_epoch != epoch or result.state not in ("admitted", "rejected", "unknown")
            or (result.state == "admitted" and not (
                isinstance(result.admission_id, str) and result.admission_id.strip()
            )) or (result.state != "admitted" and result.admission_id is not None)):
        return _admission_receipt("unknown", "invalid_host_receipt", delivery_id, epoch)
    try:
        still_current = route_claim.is_route_current() is True
    except Exception:  # health: allow BLE001 -- post-dispatch validator failure is ambiguous
        still_current = False
    if result.state == "admitted" and not still_current:
        return _admission_receipt("unknown", "route_changed_after_dispatch", delivery_id, epoch)
    return result


def inject_plugin_message(
    ctx: Any, content: str, role: str, *, session_key: Optional[str],
    origin: Optional[Mapping[str, Any]], expected_session_id: Optional[str] = None,
    surface: Literal["gateway", "tui"] | None = None,
    route_claim: Optional[Mapping[str, Any]] = None,
) -> bool:
    manager = ctx._manager
    msg = content if role == "user" else f"[{role}] {content}"
    if surface not in (None, "gateway", "tui"):
        return False
    if route_claim is not None and not isinstance(route_claim, Mapping):
        return False
    if expected_session_id is not None and (
        not isinstance(expected_session_id, str) or not expected_session_id.strip()
    ):
        return False
    if surface == "tui":
        if origin is not None:
            return False
        target = {
            "session_key": session_key,
            "expected_session_id": expected_session_id,
            "content": msg,
            "plugin_id": ctx.plugin_id,
        }
        if route_claim is not None:
            target["route_claim"] = dict(route_claim)
        return manager.inject_tui_message(**target)
    cli = manager._cli_ref
    # An origin names a messaging chat; the local REPL is never that chat.
    if cli is not None and origin is None and surface is None:
        # The REPL queue cannot prove a requested native route or host claim.
        if expected_session_id is not None or route_claim is not None:
            return False
        queue_ = cli._interrupt_queue if getattr(cli, "_agent_running", False) else cli._pending_input
        queue_.put(msg)
        return True
    if session_key and origin is not None:
        logger.warning("inject_message: pass session_key or origin, not both")
        return False
    if not session_key and origin is None:
        logger.warning("inject_message: gateway mode requires an existing session_key or an origin")
        return False
    if origin is not None and not isinstance(origin, Mapping):
        logger.warning("inject_message: origin must be a mapping in the SessionSource.to_dict() shape")
        return False
    if origin is not None and (expected_session_id is not None or route_claim is not None):
        return False
    if not ctx._gateway_injection_allowed():
        logger.warning("inject_message: gateway injection denied for plugin %s; set "
                       "plugins.entries.%s.allow_gateway_injection: true to allow it",
                       ctx.plugin_id, ctx.plugin_id)
        return False
    if not manager.has_gateway_message_injector:
        logger.warning("inject_message: no live gateway is available")
        return False
    if origin is None:
        target: dict[str, Any] = {"session_key": session_key}
    else:
        # The manager's immutable home is the plugin's profile: the gateway creates the session
        # there or nowhere (never the ambient HERMES_HOME of whatever thread called us).
        target = {"origin": dict(origin), "plugin_home": manager.home_path}
    if expected_session_id is not None:
        target["expected_session_id"] = expected_session_id
    if route_claim is not None:
        target["route_claim"] = dict(route_claim)
    try:
        return bool(manager.inject_gateway_message(**target, content=msg, plugin_id=ctx.plugin_id))
    except Exception:
        logger.warning("inject_message: gateway scheduling failed for plugin %s", ctx.plugin_id, exc_info=True)
        return False


class TuiPluginHostMixin:
    """Profile-scoped host ingress and bounded route observation for PluginManager."""

    @property
    def has_gateway_message_injector(self) -> bool:
        """Return whether a live gateway can accept plugin-triggered turns."""
        return self._gateway_message_injector is not None

    def set_gateway_message_injector(self, owner: object, injector: Callable[..., bool]) -> None:
        """Publish a live gateway injector and its lifecycle owner."""
        self._gateway_message_injector = (owner, injector)

    def clear_gateway_message_injector(self, owner: object) -> None:
        """Clear the injector only when it still belongs to ``owner``."""
        if self._gateway_message_injector is not None and self._gateway_message_injector[0] is owner:
            self._gateway_message_injector = None

    def inject_gateway_message(self, **kwargs: Any) -> bool:
        """Submit a plugin-triggered turn to the live gateway."""
        registered = self._gateway_message_injector
        return registered is not None and bool(registered[1](**kwargs))

    def set_admission_host(
        self, surface: str, owner: object, callback: Callable[..., AdmissionReceipt], host_owner_id: str,
    ) -> None:
        """Register a typed host callback separately from legacy scheduling callbacks."""
        if (surface not in _HOST_SURFACES or owner is None or not callable(callback)
                or not isinstance(host_owner_id, str) or not host_owner_id.strip()):
            raise ValueError("admission host requires a valid surface, owner and callback")
        with self._admission_host_lock:
            self._admission_hosts[surface] = (owner, callback, host_owner_id)

    def clear_admission_host(self, surface: str, owner: object) -> None:
        """An old host cannot clear a successor's typed admission callback."""
        with self._admission_host_lock:
            current = self._admission_hosts.get(surface)
            if current is not None and current[0] is owner:
                self._admission_hosts.pop(surface, None)

    def set_keyed_lifecycle_host(self, surface: str, owner: object, host_owner_id: str) -> None:
        """Authorize host-only keyed observations for one process owner and surface."""
        if (surface not in _HOST_SURFACES or owner is None
                or not isinstance(host_owner_id, str) or not host_owner_id.strip()):
            raise ValueError("keyed lifecycle host requires a valid owner and host owner id")
        with self._keyed_lifecycle_lock:
            self._keyed_lifecycle_hosts[surface] = (owner, host_owner_id)

    def clear_keyed_lifecycle_host(self, surface: str, owner: object) -> None:
        with self._keyed_lifecycle_lock:
            current = self._keyed_lifecycle_hosts.get(surface)
            if current is not None and current[0] is owner:
                self._keyed_lifecycle_hosts.pop(surface, None)

    def _keyed_lifecycle_owner(self, surface: str, owner: object) -> str | None:
        with self._keyed_lifecycle_lock:
            current = self._keyed_lifecycle_hosts.get(surface)
            return current[1] if current is not None and current[0] is owner else None

    def _notify_keyed_session_event(
        self, hook_name: str, surface: str, owner: object, *, session_key: str,
        session_id: str, route_epoch: str, old_session_id: str | None = None,
        old_route_epoch: str | None = None, route_claim: Any = None,
        route_is_current: Callable[[], bool] | None = None, **extra: Any,
    ) -> bool:
        """Dispatch exactly one named event with a fresh host route or old-revocation proof."""
        from hermes_cli.plugins import _plugin_home_scope

        host_owner_id = self._keyed_lifecycle_owner(surface, owner)
        if host_owner_id is None or not all(
            isinstance(value, str) and value.strip()
            for value in (session_key, session_id, route_epoch)
        ):
            return False
        if hook_name == "on_session_finalize":
            if extra.get("old_route_revoked") is not True or route_claim is not None:
                return False
            guard = None
        else:
            if (not all(isinstance(value, str) and value.strip()
                        for value in (old_session_id, old_route_epoch))
                    or not callable(route_is_current)
                    or not _claim_matches(route_claim, surface=surface,
                                          profile_home_key=self.scope_key,
                                          expected_session_id=session_id)
                    or route_claim.session_key != session_key
                    or route_claim.route_epoch != route_epoch
                    or route_claim.host_owner_id != host_owner_id):
                return False

            def guard() -> bool:
                if self._keyed_lifecycle_owner(surface, owner) != host_owner_id:
                    return False
                try:
                    return (route_is_current() is True
                            and _claim_matches(route_claim, surface=surface,
                                               profile_home_key=self.scope_key,
                                               expected_session_id=session_id)
                            and route_claim.session_key == session_key
                            and route_claim.route_epoch == route_epoch
                            and route_claim.host_owner_id == host_owner_id)
                except Exception:  # health: allow BLE001 -- host route guard may raise during transition
                    return False

            if not guard():
                return False

        payload = dict(
            session_key=session_key, session_id=session_id, route_epoch=route_epoch,
            profile_home_key=self.scope_key, surface=surface, host_owner_id=host_owner_id,
            **extra,
        )
        if guard is not None:
            payload.update(old_session_id=old_session_id, old_route_epoch=old_route_epoch,
                           route_claim=route_claim, route_is_current=guard)
        with _plugin_home_scope(self.home_path):
            if not self._discovered and not self.iter_hook_callbacks(hook_name):
                try:
                    self.discover_and_load()
                except Exception:  # health: allow BLE001 -- route observations fail closed
                    logger.warning("keyed plugin lifecycle discovery failed for %s", hook_name)
                    return False
            for callback in self.iter_hook_callbacks(hook_name):
                if self._keyed_lifecycle_owner(surface, owner) != host_owner_id:
                    return False
                if guard is not None and not guard():
                    return False
                try:
                    # Built-in shell/webhook bridges stringify unknown values before
                    # sending JSON externally. The private in-process claim and guard
                    # must never reach those bridges; scalar legacy fields still do.
                    callback_payload = payload
                    if getattr(callback, "__module__", "") in (
                        "agent.shell_hooks", "agent.outbound_webhooks",
                    ):
                        callback_payload = {
                            key: value for key, value in payload.items()
                            if key not in ("route_claim", "route_is_current")
                        }
                    self._invoke_hook_callback(callback, callback_payload)
                except (Exception, SystemExit) as exc:  # health: allow BLE001 -- isolate third-party lifecycle callbacks
                    self._report_hook_failure(hook_name, callback, payload, exc)
        return True

    def notify_keyed_session_finalize(
        self, surface: str, owner: object, *, session_key: str, session_id: str,
        route_epoch: str, reason: str, old_route_revoked: bool,
    ) -> bool:
        return self._notify_keyed_session_event(
            "on_session_finalize", surface, owner, session_key=session_key,
            session_id=session_id, route_epoch=route_epoch, reason=reason,
            old_route_revoked=old_route_revoked,
        )

    def notify_keyed_session_reset(
        self, surface: str, owner: object, *, session_key: str, old_session_id: str,
        session_id: str, old_route_epoch: str, route_epoch: str, route_claim: Any,
        route_is_current: Callable[[], bool],
    ) -> bool:
        return self._notify_keyed_session_event(
            "on_session_reset", surface, owner, session_key=session_key,
            old_session_id=old_session_id, session_id=session_id,
            old_route_epoch=old_route_epoch, route_epoch=route_epoch,
            route_claim=route_claim, route_is_current=route_is_current,
        )

    def notify_keyed_session_resumed(
        self, surface: str, owner: object, *, session_key: str, old_session_id: str,
        session_id: str, old_route_epoch: str, route_epoch: str, route_claim: Any,
        route_is_current: Callable[[], bool],
    ) -> bool:
        return self._notify_keyed_session_event(
            "on_session_resumed", surface, owner, session_key=session_key,
            old_session_id=old_session_id, session_id=session_id,
            old_route_epoch=old_route_epoch, route_epoch=route_epoch,
            route_claim=route_claim, route_is_current=route_is_current,
        )

    def notify_keyed_session_compacted(
        self, surface: str, owner: object, *, session_key: str, old_session_id: str,
        session_id: str, old_route_epoch: str, route_epoch: str, in_place: bool,
        route_claim: Any, route_is_current: Callable[[], bool],
    ) -> bool:
        return self._notify_keyed_session_event(
            "on_session_compacted", surface, owner, session_key=session_key,
            old_session_id=old_session_id, session_id=session_id,
            old_route_epoch=old_route_epoch, route_epoch=route_epoch, in_place=in_place,
            route_claim=route_claim, route_is_current=route_is_current,
        )

    def _prune_tui_hook_wrappers(self) -> None:
        """Remove wrappers for callbacks no longer registered to this manager."""
        live = {
            (hook_name, id(callback)): callback
            for hook_name in ("on_session_compacted", "on_session_resumed")
            for callback in self.iter_hook_callbacks(hook_name)
        }
        with self._tui_hook_wrapper_lock:
            for key, (callback, _, _) in tuple(self._tui_hook_wrappers.items()):
                if live.get(key) is not callback:
                    self._tui_hook_wrappers.pop(key, None)

    def _invalidate_tui_hook_wrapper(self, hook_name: str, callback: Callable) -> None:
        """Invalidate this registration generation before a deferred worker can run."""
        key = (hook_name, id(callback))
        with self._tui_hook_wrapper_lock:
            entry = self._tui_hook_wrappers.get(key)
            if entry is not None and entry[0] is callback:
                self._tui_hook_wrappers.pop(key, None)

    def unload(self, plugin: Any = None) -> bool:
        found = super().unload(plugin)
        self._prune_tui_hook_wrappers()
        return found

    @property
    def has_tui_message_injector(self) -> bool:
        """Return whether a live TUI/Desktop host callback is registered."""
        with self._tui_injector_lock:
            return self._tui_message_injector is not None

    def set_tui_message_injector(self, owner: object, injector: Callable[..., bool]) -> None:
        """Publish a host-owned TUI callback without touching the Gateway slot."""
        if owner is None or not callable(injector):
            raise ValueError("TUI injector requires an owner and callable")
        with self._tui_injector_lock:
            self._tui_message_injector = (owner, injector)

    def clear_tui_message_injector(self, owner: object) -> None:
        """Clear the TUI injector only when it still belongs to ``owner``."""
        with self._tui_injector_lock:
            if self._tui_message_injector is not None and self._tui_message_injector[0] is owner:
                self._tui_message_injector = None

    def _tui_injection_allowed(self, plugin_id: str) -> bool:
        """Read the separately granted TUI capability from this manager's profile."""
        from hermes_cli.plugins import _plugin_home_scope, _plugin_settings_entry, load_config_readonly

        loaded = self._plugins.get(plugin_id)
        if loaded is None or not loaded.enabled or loaded.error:
            return False
        try:
            with _plugin_home_scope(self.home_path):
                cfg = load_config_readonly() or {}
        except Exception:  # health: allow BLE001 -- config/read failures deny ingress without exposing profile data
            return False
        plugins = cfg.get("plugins") if isinstance(cfg, dict) else None
        if not isinstance(plugins, dict):
            return False
        enabled = plugins.get("enabled")
        disabled = plugins.get("disabled", [])
        return (isinstance(enabled, list) and plugin_id in enabled
                and (not isinstance(disabled, list) or plugin_id not in disabled)
                and (_plugin_settings_entry(cfg, plugin_id) or {}).get("allow_tui_injection") is True)

    def inject_tui_message(
        self, *, session_key: str | None, expected_session_id: str | None,
        content: str, plugin_id: str, route_claim: Mapping[str, Any] | None = None,
    ) -> bool:
        """Ask the pinned TUI host to admit one exact plugin route and require literal True."""
        if not all(isinstance(value, str) and value.strip()
                   for value in (session_key, expected_session_id, content, plugin_id)):
            return False
        if route_claim is not None and not isinstance(route_claim, Mapping):
            return False
        if not self._tui_injection_allowed(plugin_id):
            return False
        with self._tui_injector_lock:
            registered = self._tui_message_injector
        if registered is None:
            return False
        kwargs = {
            "session_key": session_key, "expected_session_id": expected_session_id,
            "content": content, "plugin_id": plugin_id,
        }
        if route_claim is not None:
            kwargs["route_claim"] = dict(route_claim)
        try:
            # The process-published TUI host is shared by all profile managers.
            # Only that host opts in to receiving the calling manager, so it can
            # prove the target record belongs to the profile that granted access.
            if getattr(registered[1], "_tui_manager_aware", False) is True:
                kwargs["manager"] = self
            return registered[1](**kwargs) is True
        except Exception:  # health: allow BLE001 -- third-party host failures deny ingress without logging message text
            # Host exceptions may contain prompt text; never copy their detail into logs.
            logger.warning("TUI plugin message admission failed for %s", plugin_id)
            return False

    def _guard_tui_session_callback(
        self, hook_name: str, callback: Callable, generation: object,
    ) -> Callable:
        """Recheck route and registration inside a delayed bounded observer worker."""
        def guarded(**worker_kwargs: Any) -> Any:
            if not worker_kwargs["route_is_current"]():
                return None
            if not any(current is callback for current in self.iter_hook_callbacks(hook_name)):
                return None
            with self._tui_hook_wrapper_lock:
                entry = self._tui_hook_wrappers.get((hook_name, id(callback)))
                if entry is None or entry[0] is not callback or entry[2] is not generation:
                    return None
            return self._invoke_hook_callback(
                callback, {key: value for key, value in worker_kwargs.items() if key != "turn_id"})

        return guarded

    def _notify_tui_session_hook(
        self, hook_name: str, *, route_is_current: Callable[[], bool], **payload: Any,
    ) -> None:
        """Deliver one TUI route observation through the existing bounded hook engine."""
        from hermes_cli.plugins import (
            _HOOK_CALLBACK_TIMEOUT_SECS, _MAX_HOOK_CALLBACK_TIMEOUT_SECS,
            _plugin_home_scope, _resolve_hook_callback_timeout,
        )

        if not callable(route_is_current):
            return
        with _plugin_home_scope(self.home_path):
            try:
                if not route_is_current():
                    return
                # Resume may happen before the first human turn and lazy discovery.
                self.discover_and_load()
            except Exception:
                logger.warning("TUI plugin %s discovery/route check failed", hook_name, exc_info=True)
                return
            kwargs = {
                **payload, "route_is_current": route_is_current,
                "telemetry_schema_version": OBSERVER_SCHEMA_VERSION,
            }
            callbacks = self.iter_hook_callbacks(hook_name)
            timeout = _resolve_hook_callback_timeout()
            # Disabling generic hook timeouts must not make route changes unbounded.
            if not 0 < timeout <= _MAX_HOOK_CALLBACK_TIMEOUT_SECS:
                timeout = _HOOK_CALLBACK_TIMEOUT_SECS
            self._prune_tui_hook_wrappers()
            bounded_kwargs = {
                **kwargs, "turn_id": repr((payload["session_key"], payload["session_id"])),
            }
            try:
                for callback in callbacks:
                    try:
                        if not route_is_current():
                            return
                        key = (hook_name, id(callback))
                        with self._tui_hook_wrapper_lock:
                            entry = self._tui_hook_wrappers.get(key)
                            if entry is None or entry[0] is not callback:
                                generation = object()
                                entry = (
                                    callback,
                                    self._guard_tui_session_callback(hook_name, callback, generation),
                                    generation,
                                )
                                self._tui_hook_wrappers[key] = entry
                        self._run_hook_callback_bounded(hook_name, entry[1], bounded_kwargs, timeout)
                    except (Exception, SystemExit) as exc:  # health: allow BLE001 -- isolate plugin observer failures per callback
                        self._report_hook_failure(hook_name, callback, kwargs, exc)
            finally:
                self._prune_tui_hook_wrappers()

    def on_session_compacted(
        self, *, session_key: str, old_session_id: str, session_id: str, profile: str,
        in_place: bool, route_is_current: Callable[[], bool],
    ) -> None:
        """Notify plugins after a TUI continuation route is published."""
        self._notify_tui_session_hook(
            "on_session_compacted", session_key=session_key, old_session_id=old_session_id,
            session_id=session_id, profile=profile, in_place=in_place,
            route_is_current=route_is_current,
        )

    def on_session_resumed(
        self, *, session_key: str, session_id: str, profile: str,
        route_is_current: Callable[[], bool],
    ) -> None:
        """Notify plugins after a live TUI/Desktop route is resumed."""
        self._notify_tui_session_hook(
            "on_session_resumed", session_key=session_key, session_id=session_id,
            profile=profile, route_is_current=route_is_current,
        )
