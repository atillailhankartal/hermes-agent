"""Host-owned plugin ingress for the live TUI/Desktop prompt queue.

There is deliberately no JSON-RPC method: a plugin's capability grant is not a
credential a remote renderer may claim in a request body.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_OWNER = object()
logger = logging.getLogger(__name__)


def _route_lease_current(session: dict) -> bool:
    """A transfer-in-flight must never authorize the old published route."""
    lease = session.get("active_session_lease")
    return (not session.get("_route_transfer_failed")
            and (lease is None or (not getattr(lease, "released", False)
                                   and str(getattr(lease, "session_id", "")) == session.get("session_key"))))


@dataclass(frozen=True)
class _SessionRoute:
    """One TUI record generation; a delayed observer must check this again before rebinding."""

    sid: str
    session: dict
    session_key: str
    native_session_id: str
    agent: Any
    profile_home: Path
    generation: int

    def current(self) -> bool:
        from tui_gateway import server

        try:
            with server._sessions_lock:
                session = self.session
                live_agent = session.get("agent")
                if self.agent is None:
                    agent_current = (live_agent is None or
                                     getattr(live_agent, "session_id", None) == self.native_session_id)
                else:
                    agent_current = (live_agent is self.agent and
                                     getattr(live_agent, "session_id", None) == self.native_session_id)
                return (
                    server._sessions.get(self.sid) is session
                    and session.get("source") in {"tui", "desktop"}
                    and not any(session.get(flag) for flag in (
                        "_closing", "_finalized", "pending_hidden", "room_plumbing", "lazy"))
                    and _route_lease_current(session)
                    and not server._transport_is_dead(session.get("transport"))
                    and Path(session.get("profile_home") or server._hermes_home).resolve() == self.profile_home
                    and session.get("session_key") == self.session_key
                    and int(session.get("_queued_prompt_generation", 0)) == self.generation
                    and agent_current
                )
        except (OSError, TypeError, ValueError):
            return False


def _live_route(sid: str, session: dict) -> _SessionRoute | None:
    from tui_gateway import server

    try:
        with server._sessions_lock:
            if server._sessions.get(sid) is not session:
                return None
            key = session.get("session_key")
            agent = session.get("agent")
            native_id = getattr(agent, "session_id", None) if agent is not None else key
            if not isinstance(key, str) or not key or not isinstance(native_id, str) or not native_id:
                return None
            route = _SessionRoute(
                sid, session, key, native_id, agent,
                Path(session.get("profile_home") or server._hermes_home).resolve(),
                int(session.get("_queued_prompt_generation", 0)),
            )
            return route if route.current() else None
    except (OSError, TypeError, ValueError):
        return None


def _notify_tui_lifecycle(method_name: str, sid: str, session: dict, **payload: Any) -> None:
    """Use an optional, synchronous host manager hook; never expose the route proof on JSON-RPC."""
    from tui_gateway import server

    route = _live_route(sid, session)
    if route is None:
        return
    try:
        from hermes_cli.plugins import get_plugin_manager
        from hermes_constants import profile_name_for_home

        with server._session_profile_runtime_scope(session, hydrate_secrets=False):
            manager = get_plugin_manager()
            if Path(manager.home_path).resolve() != route.profile_home:
                return
            notify = getattr(manager, method_name, None)
            if callable(notify) and route.current():
                notify(
                    session_key=route.session_key,
                    session_id=route.native_session_id,
                    profile=profile_name_for_home(route.profile_home) or "default",
                    route_is_current=route.current,
                    **payload,
                )
    except Exception:
        logger.warning("TUI plugin %s notification failed", method_name, exc_info=True)


def notify_tui_session_compacted(sid: str, session: dict, old_session_id: str) -> None:
    """Emit after the continuation route is published, with a guard for delayed consumers."""
    _notify_tui_lifecycle(
        "on_session_compacted", sid, session,
        old_session_id=old_session_id, in_place=False,
    )


def notify_tui_session_resumed(sid: str, session: dict) -> None:
    """Emit for a published live resume route, including a deferred agent build."""
    _notify_tui_lifecycle("on_session_resumed", sid, session)


def _plugin_allowed(manager: Any, plugin_id: str) -> bool:
    from hermes_cli.config import load_config_readonly
    from hermes_cli.plugins_loader import _plugin_home_scope

    loaded = manager._plugins.get(plugin_id)
    if loaded is None or not loaded.enabled or loaded.error:
        return False
    try:
        with _plugin_home_scope(manager.home_path):
            config = load_config_readonly() or {}
    except (OSError, ValueError, TypeError):
        return False
    plugins = config.get("plugins") if isinstance(config, dict) else None
    if not isinstance(plugins, dict):
        return False
    enabled = plugins.get("enabled")
    disabled = plugins.get("disabled", [])
    entries = plugins.get("entries")
    entry = entries.get(plugin_id) if isinstance(entries, dict) else None
    return (isinstance(enabled, list) and plugin_id in enabled
            and (not isinstance(disabled, list) or plugin_id not in disabled)
            and isinstance(entry, dict) and entry.get("allow_tui_injection") is True)


@dataclass(frozen=True)
class PluginAdmission:
    """An in-process proof bound to one live record and one native conversation."""

    manager: Any
    session: dict
    session_key: str
    expected_session_id: str
    plugin_id: str
    agent: Any
    transport: Any
    generation: int

    def current(self, sid: str, session: dict) -> bool:
        from tui_gateway import server

        agent = session.get("agent")
        transport = session.get("transport")
        source = session.get("source")
        home = Path(session.get("profile_home") or server._hermes_home).resolve()
        return (
            session is self.session and server._sessions.get(sid) is session
            and home == Path(self.manager.home_path).resolve()
            and source in {"tui", "desktop"}
            and not any(session.get(flag) for flag in (
                "_closing", "_finalized", "pending_hidden", "room_plumbing", "lazy"))
            and _route_lease_current(session)
            and not server._transport_is_dead(transport)
            and agent is self.agent and transport is self.transport
            and int(session.get("_queued_prompt_generation", 0)) == self.generation
            and session.get("session_key") == self.session_key
            and getattr(agent, "session_id", None) == self.expected_session_id
            and _plugin_allowed(self.manager, self.plugin_id)
        )


def inject_plugin_message(
    *, manager: Any, session_key: str, expected_session_id: str, content: str, plugin_id: str,
) -> bool:
    """Return True only for a prompt.submit reply confirming turn or queue admission."""
    from tui_gateway import server
    from tui_gateway.transport import bind_transport, reset_transport

    if not all(isinstance(v, str) and v.strip()
               for v in (session_key, expected_session_id, content, plugin_id)):
        return False
    with server._sessions_lock:
        matches = [(sid, session) for sid, session in server._sessions.items()
                   if session.get("session_key") == session_key]
        if len(matches) != 1:
            return False
        sid, session = matches[0]
        proof = PluginAdmission(
            manager, session, session_key, expected_session_id, plugin_id,
            session.get("agent"), session.get("transport"),
            int(session.get("_queued_prompt_generation", 0)),
        )
        if not proof.current(sid, session):
            return False
        transport = session["transport"]
    token = bind_transport(transport)
    try:
        with server._session_profile_runtime_scope(session, hydrate_secrets=False):
            reply = server._methods["prompt.submit"](
                "plugin-injection", {"session_id": sid, "text": content, "queued": True,
                                     "_plugin_admission": proof})
    finally:
        reset_transport(token)
    return (isinstance(reply, dict) and reply.get("error") is None
            and (reply.get("result") or {}).get("status") in {"streaming", "queued"})


def register_tui_plugin_injector() -> None:
    """Publish the callback for the manager of the currently bound profile."""
    from hermes_cli.plugins import get_plugin_manager

    manager = get_plugin_manager()
    if hasattr(manager, "set_tui_message_injector"):
        manager.set_tui_message_injector(
            _OWNER, lambda **kwargs: inject_plugin_message(manager=manager, **kwargs))
