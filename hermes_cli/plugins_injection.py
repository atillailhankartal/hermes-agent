"""Host routing for ``PluginContext.inject_message``: classic CLI REPL, Ink TUI / desktop, messaging
gateway (existing ``session_key`` or a new session at ``origin``)."""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Callable, Literal, Optional

from hermes_cli.middleware import OBSERVER_SCHEMA_VERSION

logger = logging.getLogger("hermes_cli.plugins")


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
    """Profile-scoped TUI admission and bounded route observation for PluginManager."""

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
