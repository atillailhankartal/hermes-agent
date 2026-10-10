"""Plugin-triggered gateway turns (``PluginContext.inject_message``): the process-wide injector this
runner publishes, the thread-safe scheduler, and the dispatch through the adapter message path.

Two targets: an existing session (``session_key``; route and session id pinned from the store) or a
messaging chat (``origin``) whose session is created — or continued — through the normal session path
in the calling plugin's OWN profile. The origin path never chooses a profile: the gateway's routing
for that chat through that profile's adapter must already land in the plugin's profile, so a human
follow-up in the same chat keys into the same session."""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import logging
import sqlite3
import weakref
from pathlib import Path
from typing import Any, Mapping, Optional

from gateway.platforms.event import MessageEvent, MessageType
from gateway.session import SessionSource

logger = logging.getLogger("gateway.run")


class GatewayPluginInjectionMixin:
    def _install_plugin_message_injector(self) -> None:
        """Publish this live gateway's plugin message scheduler process-wide."""
        from hermes_cli.plugins import publish_gateway_message_host

        publish_gateway_message_host(self, self._schedule_plugin_message_injection)
        self._native_plugin_admission_open = True
        from hermes_cli.plugins_injection import publish_admission_host, publish_keyed_lifecycle_host
        owner = getattr(self.session_store, "_route_owner_id", None)
        if owner:
            self._native_plugin_queue()
            publish_admission_host("gateway", self, self._admit_plugin_message, owner)
            publish_keyed_lifecycle_host("gateway", self, owner)
            loop = getattr(self, "_gateway_loop", None)
            if loop is not None and not loop.is_closed():
                self._native_plugin_drain_task = loop.create_task(self._drain_native_plugin_candidates())

    def _clear_plugin_message_injector(self) -> None:
        """Remove this runner's scheduler without clobbering a newer owner."""
        from hermes_cli.plugins import clear_published_gateway_message_host

        self._native_plugin_admission_open = False
        clear_published_gateway_message_host(self)
        from hermes_cli.plugins_injection import clear_published_admission_host, clear_published_keyed_lifecycle_host
        clear_published_admission_host("gateway", self)
        clear_published_keyed_lifecycle_host("gateway", self)
        task = getattr(self, "_native_plugin_drain_task", None)
        if task is not None:
            task.cancel()

    def _native_plugin_queue(self):
        from gateway.native_plugin_queue import NativePluginQueue
        queue = self.__dict__.get("_native_plugin_candidate_store")
        if queue is None:
            queue = NativePluginQueue(self.session_store.sessions_dir)
            self._native_plugin_candidate_store = queue
        return queue

    def _native_plugin_claim_owned(self, manager, claim) -> bool:
        """Authenticate the host object, even for status of a now-stale route."""
        from gateway.route_claim import RouteClaim
        from hermes_constants import hermes_home_key
        store = self.session_store
        return (type(claim) is RouteClaim and claim.surface == "gateway"
                and claim._proof is store._route_claim_proof
                and claim.host_owner_id == store._route_owner_id
                and claim.profile_home_key == manager.scope_key
                and hermes_home_key(manager.home_path) == manager.scope_key)

    def _query_native_plugin_admission(
        self, *, manager, route_claim, delivery_id, expected_content, route_epoch=None, expected_session_id=None,
    ):
        """Private same-ID readback; does not schedule, reinsert or require a current epoch.

        A fresh host claim after restart can read a retained same-epoch receipt.
        Historical claims from this owner can reconcile late completion after /new.
        After restart a fresh host claim for the same profile/key can select the
        retained epoch/native pair explicitly. Selectors are correlation, not authority.
        This reports the ORIGINAL owner's admission, never a new-owner insertion.
        Settlement requires expected_content and the original attempt's owner/route
        fingerprint. There is no status-only receipt path.
        Missing status is unknown, never permission to reinsert.
        """
        from hermes_cli.plugins_injection import AdmissionReceipt
        epoch = route_epoch if route_epoch is not None else getattr(route_claim, "route_epoch", None)
        native = expected_session_id if expected_session_id is not None else getattr(route_claim, "native_session_id", None)
        unknown = AdmissionReceipt("unknown", "native_status_unavailable", delivery_id, epoch)
        if not self._native_plugin_claim_owned(manager, route_claim):
            return unknown
        try:
            queue = self._native_plugin_queue()
            row = queue.lookup(manager.scope_key, epoch, delivery_id)
            if (row and row["session_key"] == route_claim.session_key
                    and row["native_id"] == native):
                if not isinstance(expected_content, str) or row["payload_digest"] != queue.payload_digest(expected_content):
                    return queue.receipt(queue.conflict(row))
                return queue.receipt(row)
        except (OSError, sqlite3.Error):
            logger.warning("Native plugin status read failed")
        return unknown

    def _admit_plugin_message(self, **request):
        """Typed worker callback. A timeout leaves the exact operation running for readback."""
        from hermes_cli.plugins_injection import AdmissionReceipt
        epoch = getattr(request.get("route_claim"), "route_epoch", None)
        unknown = AdmissionReceipt("unknown", "native_admission_pending", request["delivery_id"], epoch)
        loop = getattr(self, "_gateway_loop", None)
        if loop is None or loop.is_closed():
            return unknown
        try:
            if asyncio.get_running_loop() is loop:
                return unknown
        except RuntimeError:
            pass
        coro = self._admit_native_plugin_candidate(**request)
        try:
            future = asyncio.run_coroutine_threadsafe(coro, loop)
        except RuntimeError:
            coro.close()
            return unknown
        try:
            return future.result(timeout=4.0)
        except (concurrent.futures.TimeoutError, concurrent.futures.CancelledError):
            return unknown
        except Exception:  # health: allow BLE001 -- attempted dispatch may have committed
            logger.warning("Native plugin admission outcome unavailable")
            return unknown

    async def _admit_native_plugin_candidate(
        self, *, content, surface, route_claim, expected_session_id, delivery_id, plugin_id, manager,
    ):
        from hermes_cli.plugins_injection import AdmissionReceipt
        from hermes_constants import hermes_home_key
        epoch = getattr(route_claim, "route_epoch", None)
        queue = None

        def reject(reason):
            if queue is not None:
                row = queue.admit(profile=manager.scope_key, epoch=epoch, delivery=delivery_id,
                                  session_key=route_claim.session_key, native_id=expected_session_id,
                                  owner=self.session_store._route_owner_id, plugin=plugin_id,
                                  content=content, rejection_reason=reason)
                return queue.receipt(row)
            return AdmissionReceipt("rejected", reason, delivery_id, epoch)

        if (surface != "gateway" or not self._native_plugin_claim_owned(manager, route_claim)
                or expected_session_id != route_claim.native_session_id):
            return reject("invalid_host_route")
        if not all(isinstance(value, str) and value.strip() for value in (content, delivery_id, plugin_id)):
            return reject("invalid_request")
        async with self._session_route_gate(route_claim.session_key):
            try:
                queue = self._native_plugin_queue()
                existing = queue.lookup(manager.scope_key, epoch, delivery_id)
                if existing:
                    if (existing["session_key"] != route_claim.session_key
                            or existing["native_id"] != expected_session_id or existing["plugin"] != plugin_id
                            or existing["payload_digest"] != queue.payload_digest(content)):
                        return AdmissionReceipt("unknown", "native_delivery_conflict", delivery_id, epoch)
                    return queue.receipt(existing)
                if not route_claim.is_route_current():
                    return reject("route_not_current")
                store = self.session_store
                # The store lock also fences synchronous reset/repoint writers.
                with manager._admission_host_lock, store._lock:
                    registered = manager._admission_hosts.get("gateway")
                    if (registered is None or registered[0] is not self
                            or registered[2] != route_claim.host_owner_id
                            or not getattr(self, "_native_plugin_admission_open", True)):
                        return reject("admission_host_replaced")
                    entry = store._entry_locked(route_claim.session_key)
                    if (not self._plugin_injection_accepting() or store._route_owner_retired
                            or entry is None or entry.origin is None or entry.route_claim_blocked
                            or entry.session_id != expected_session_id or entry.route_epoch != epoch):
                        return reject("route_not_current")
                    source = self._restored_source(entry)
                    if hermes_home_key(self._resolve_profile_home_for_source(source)) != manager.scope_key:
                        return reject("profile_mismatch")
                    from hermes_cli.plugins import PluginContext
                    loaded = manager._plugins.get(plugin_id)
                    if (loaded is None or not loaded.enabled or loaded.error
                            or not PluginContext(loaded.manifest, manager)._gateway_injection_allowed()):
                        return reject("plugin_grant_denied")
                    if (not self._plugin_injection_authorized(source, plugin_id=plugin_id, target="native")
                            or self._delivery_adapter_for(source) is None):
                        return reject("route_unavailable")
                    row = queue.admit(profile=manager.scope_key, epoch=epoch, delivery=delivery_id,
                                      session_key=route_claim.session_key, native_id=expected_session_id,
                                      owner=store._route_owner_id, plugin=plugin_id, content=content)
                return queue.receipt(row)
            except (OSError, sqlite3.Error):
                # Includes failures reported after COMMIT: exact readback can recover the receipt.
                logger.warning("Native plugin candidate commit outcome unavailable")
                return self._query_native_plugin_admission(
                    manager=manager, route_claim=route_claim, delivery_id=delivery_id, expected_content=content)

    @staticmethod
    def _strict_plugin_session_matches(entry, native_id, metadata):
        if entry is None or not native_id or entry.session_id != native_id:
            return False
        epoch = metadata.get("gateway_route_epoch")
        return not epoch or (entry.route_epoch == epoch and not entry.route_claim_blocked)

    async def _hmwa_acquire_native_turn_lease(self, event, key, generation, entry, env_tokens):
        await self._hmwa_acquire_turn_lease(key, generation, entry, env_tokens)
        if not (getattr(event, "metadata", None) or {}).get("hermes_native_candidate_id"):
            return
        try:
            async with self._session_route_gate(key):
                if self._settle_native_plugin_turn(event, key, generation, entry):
                    return
        except (OSError, sqlite3.Error):
            logger.warning("Native turn settlement unavailable")
        self._clear_session_env(env_tokens)
        from gateway.turn_lease import TurnLeaseTimeoutError
        raise TurnLeaseTimeoutError(entry.session_id, owner_key=key, generation=generation, wait_seconds=0)

    def _settle_native_plugin_turn(self, event, key, generation, entry):
        from hermes_cli.active_sessions import active_session_lease_guard, ActiveSessionRegistryError
        from hermes_constants import hermes_home_key
        state = self._peek_session_state(key)
        held = self._held_turn_lease(key, generation)
        if state is None or held is None or state.turn.event is not event:
            return False
        if state.persistent.run_generation != generation:
            return False
        token = held[1][generation]
        if (token.released or token.lease.holder is not token or token.session_id != entry.session_id
                or token.owner_key != key or token.generation != generation):
            return False
        metadata = event.metadata
        profile_home = self._resolve_profile_home_for_source(event.source)
        queue = self._native_plugin_queue()
        with self.session_store._lock:
            live = self.session_store._entry_locked(key)
            if not self._strict_plugin_session_matches(live, entry.session_id, metadata):
                return False
            row = queue.lookup(hermes_home_key(profile_home), live.route_epoch, metadata["hermes_delivery_id"])
            if (not row or row["candidate"] != metadata["hermes_native_candidate_id"]
                    or row["session_key"] != key or row["native_id"] != live.session_id
                    or row["content"] != event.text
                    or getattr(event, "_native_plugin_proof", None) is not self.session_store._route_claim_proof):
                return False
            try:
                with active_session_lease_guard(state.turn.lease, session_id=key,
                                               live_session_id=key, registry_home=profile_home):
                    return queue.settle(row["candidate"])
            except ActiveSessionRegistryError:
                return False

    async def _handle_native_plugin_candidate(self, event):
        """One native dequeue can enter the ordinary Gateway handler at most once."""
        from hermes_constants import hermes_home_key
        metadata = event.metadata or {}
        key = metadata.get("gateway_session_key")
        queue = self._native_plugin_queue()
        async with self._session_route_gate(key):
            if (getattr(event, "_native_plugin_proof", None) is not self.session_store._route_claim_proof
                    or not event.internal or event.allow_gateway_control):
                return None
            with self.session_store._lock:
                entry = self.session_store._entry_locked(key)
                if (entry is None or entry.route_claim_blocked
                        or entry.session_id != metadata.get("gateway_session_id")
                        or entry.route_epoch != metadata.get("gateway_route_epoch")):
                    queue.transition(metadata["hermes_native_candidate_id"], "dispatching", "stale_route")
                    return None
                profile = hermes_home_key(self._resolve_profile_home_for_source(event.source))
                row = queue.lookup(profile, entry.route_epoch, metadata.get("hermes_delivery_id"))
                if (not row or row["candidate"] != metadata["hermes_native_candidate_id"]
                        or row["session_key"] != key or row["native_id"] != entry.session_id
                        or row["content"] != event.text
                        or not queue.transition(row["candidate"], "dispatching", "running")):
                    return None
        try:
            result = await self._handle_message_admitted(event)
        except BaseException:
            queue.transition(row["candidate"], "running", "execution_unknown")
            raise
        queue.transition(row["candidate"], "running", "handler_returned")
        return result

    async def _drain_native_plugin_candidates(self):
        """Restart recovery and wake loop; the database is the queue, this task is only a signal."""
        while getattr(self, "_running", False):
            try:
                await self._drain_native_plugin_candidates_once()
            except Exception:  # health: allow BLE001 -- durable queue remains authoritative after a wake failure
                logger.warning("Native plugin queue wake failed")
            await asyncio.sleep(0.25)

    async def _drain_native_plugin_candidates_once(self):
        from hermes_constants import hermes_home_key
        if not self._plugin_injection_accepting():
            return
        queue = self._native_plugin_queue()
        for row in queue.next_queued_page():
            key = row["session_key"]
            async with self._session_route_gate(key):
                entry = self.session_store.lookup_by_session_key(key)
                if (entry is None or entry.route_epoch != row["epoch"]
                        or entry.session_id != row["native_id"] or entry.route_claim_blocked
                        or entry.origin is None):
                    queue.transition(row["candidate"], "queued", "stale_route")
                    continue
                source = self._restored_source(entry)
                if hermes_home_key(self._resolve_profile_home_for_source(source)) != row["profile"]:
                    queue.transition(row["candidate"], "queued", "stale_profile")
                    continue
                adapter = self._delivery_adapter_for(source)
                if (adapter is None or self._is_session_running(key)
                        or key in adapter._active_sessions or key in adapter._pending_messages):
                    continue
                if not self._plugin_injection_authorized(source, plugin_id=row["plugin"], target="native"):
                    queue.transition(row["candidate"], "queued", "authorization_revoked")
                    continue
                event = MessageEvent(text=row["content"], message_type=MessageType.TEXT, source=source,
                                     internal=True, allow_gateway_control=False, metadata={
                    "hermes_plugin_id": row["plugin"], "hermes_plugin_injection": True,
                    "hermes_native_candidate_id": row["candidate"], "hermes_delivery_id": row["delivery"],
                    "gateway_session_key": key, "gateway_session_id": row["native_id"],
                    "gateway_route_epoch": row["epoch"], "gateway_session_strict": True,
                })
                event._native_plugin_proof = self.session_store._route_claim_proof
                # Persist before crossing the scheduler boundary. If the process dies after this
                # CAS, automatic replay could execute twice. Preserve the status but never retry.
                if not queue.transition(row["candidate"], "queued", "dispatching"):
                    continue
                try:
                    async with self._plugin_injection_scope(source):
                        started = adapter._start_session_processing(event, key)
                    if not started:
                        queue.transition(row["candidate"], "dispatching", "execution_unknown")
                except Exception:  # health: allow BLE001 -- adapter may have started before raising
                    queue.transition(row["candidate"], "dispatching", "execution_unknown")
                    logger.warning("Native plugin candidate execution outcome unavailable")

    def _schedule_plugin_message_injection(
        self, *, content: str, plugin_id: str, session_key: Optional[str] = None,
        origin: Optional[Mapping[str, Any]] = None, plugin_home: Optional[Path] = None,
    ) -> bool:
        """Schedule a plugin-triggered turn on the live gateway loop (thread-safe).

        With ``origin`` the profile, origin and adapter checks run here, synchronously, so the plugin
        gets ``False`` for a chat it may not start; authorization is rechecked at dispatch."""
        from gateway.run import safe_schedule_threadsafe
        loop = getattr(self, "_gateway_loop", None)
        if not getattr(self, "_running", False) or loop is None or loop.is_closed():
            return False

        if origin is not None:
            source = self._plugin_origin_source(origin, plugin_home=plugin_home, plugin_id=plugin_id)
            if source is None:
                return False
            target = f"origin={source.platform.value}/{source.chat_id}"
            coro = self._dispatch_plugin_origin_injection(source=source, content=content, plugin_id=plugin_id)
        else:
            target = f"session={session_key}"
            coro = self._dispatch_plugin_message_injection(
                session_key=session_key, content=content, plugin_id=plugin_id,
            )
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if current_loop is loop:
            try:
                future = loop.create_task(coro)
            except Exception:
                coro.close()
                logger.warning("Plugin message injection scheduling failed", exc_info=True)
                return False
            self._background_tasks.add(future)
            future.add_done_callback(self._background_tasks.discard)
        else:
            future = safe_schedule_threadsafe(
                coro, loop, logger=logger, log_message="Plugin message injection scheduling failed",
                log_level=logging.WARNING,
            )
            if future is None:
                return False

        def _log_result(completed) -> None:
            try:
                if completed.result():
                    return
            except (asyncio.CancelledError, concurrent.futures.CancelledError):
                return
            except Exception:  # dispatch boundary: the plugin already got True; log, never raise
                logger.warning("Plugin message injection failed: plugin=%s %s", plugin_id, target, exc_info=True)
                return
            logger.warning("Plugin message injection was not routed: plugin=%s %s", plugin_id, target)

        future.add_done_callback(_log_result)
        return True

    def _plugin_injection_accepting(self) -> bool:
        return getattr(self, "_running", False) and not getattr(self, "_draining", False)

    def _plugin_injection_scope(self, source: SessionSource):
        """Multiplex: enter the source's profile runtime scope around ``handle_message`` so the
        background task it spawns — the turn AND the reply send after the handler returns — inherits
        that profile's home and secrets (this coroutine runs from the default loop context, not from
        the profile adapter's own intake task)."""
        if getattr(getattr(self, "config", None), "multiplex_profiles", False) is not True:
            return contextlib.nullcontext()
        from gateway.run import _async_profile_runtime_scope
        return _async_profile_runtime_scope(self._resolve_profile_home_for_source(source))

    def _plugin_injection_authorized(self, source: SessionSource, *, plugin_id: str, target: str) -> bool:
        """Current gateway authorization for the route the injected turn will run as. Host-side
        plugin code is trusted to ask, never to widen access: a stored or supplied route must pass
        today's allowlists / pairing / allow-all, and adapter-time grants (Discord roles) do not count."""
        try:
            authorized = self._is_user_authorized_for_source(source, allow_adapter_delegation=False)
        except Exception:
            logger.warning("Plugin message injection authorization check failed: plugin=%s %s",
                           plugin_id, target, exc_info=True)
            return False
        if not authorized:
            logger.warning("Plugin message injection denied by current gateway authorization: plugin=%s %s",
                           plugin_id, target)
        return authorized

    async def _dispatch_plugin_message_injection(
        self, *, session_key: str, content: str, plugin_id: str
    ) -> bool:
        """Route a plugin-triggered turn through the session's live adapter."""
        if not self._plugin_injection_accepting():
            return False
        entry = await self.async_session_store.lookup_by_session_key(session_key)
        if entry is None or entry.origin is None or not self._plugin_injection_accepting():
            return False

        from gateway.session_identity import replace_source
        source = replace_source(self._restored_source(entry))
        if not self._plugin_injection_authorized(source, plugin_id=plugin_id, target=f"session={session_key}"):
            return False

        adapter = self._delivery_adapter_for(source)
        if adapter is None:
            return False

        async with self._plugin_injection_scope(source):
            await adapter.handle_message(MessageEvent(
                text=content, message_type=MessageType.TEXT, source=source, internal=True,
                allow_gateway_control=False,
                metadata={
                    "hermes_plugin_id": plugin_id, "hermes_plugin_injection": True,
                    "gateway_session_key": session_key, "gateway_session_id": entry.session_id,
                    "gateway_session_strict": True,
                },
            ))
        logger.info(
            "Plugin message injection dispatched: plugin=%s session=%s session_id=%s",
            plugin_id, session_key, entry.session_id,
        )
        return True

    def _served_profile_for_home(self, home: Optional[Path]) -> Optional[str]:
        """Name of the profile this gateway serves at *home* (a plugin manager's immutable home), or
        ``None`` when this gateway does not serve it."""
        if home is None:
            return None
        from hermes_constants import get_routing_process_hermes_home, hermes_home_key
        key = hermes_home_key(home)
        if getattr(getattr(self, "config", None), "multiplex_profiles", False):
            from gateway.run import _multiplex_profile_homes
            try:
                served = _multiplex_profile_homes(self.config)
            except Exception:
                logger.warning("Plugin message injection: served-profile set unavailable", exc_info=True)
                return None
            return next((name for name, served_home in served if hermes_home_key(served_home) == key), None)
        if hermes_home_key(get_routing_process_hermes_home()) != key:
            return None
        return getattr(self, "_primary_profile_name", None) or self._active_profile_name()

    def _plugin_origin_source(
        self, origin: Mapping[str, Any], *, plugin_home: Optional[Path], plugin_id: str,
    ) -> Optional[SessionSource]:
        """The canonicalized source for a plugin-supplied *origin*, or ``None`` (logged) when the
        plugin may not start a turn there: its profile is not served, the origin is malformed or
        names another profile, that profile has no live adapter for the platform, or the gateway's
        own routing for the chat lands in a different profile."""
        def _refuse(reason: str, *args: Any) -> None:
            logger.warning("Plugin message injection refused: plugin=%s " + reason, plugin_id, *args)

        profile = self._served_profile_for_home(plugin_home)
        if profile is None:
            return _refuse("its profile home %s is not served by this gateway", plugin_home)
        fields = dict(origin)
        requested = fields.pop("profile", None)
        if requested and requested != profile:
            return _refuse("origin names profile %r; plugins may only start sessions in their own profile (%s)",
                           requested, profile)
        try:
            source = SessionSource.from_dict(fields)
        except (KeyError, TypeError, ValueError) as exc:
            return _refuse("invalid origin (%s)", exc)
        where = f"{source.platform.value}/{source.chat_id}"
        adapter = self._adapters_for_profile(profile).get(source.platform)
        if adapter is None:
            return _refuse("no connected %s adapter for profile %s", source.platform.value, profile)
        # Same provenance build_source() stamps on a live inbound event from this adapter, so the
        # identity (receiving bot, runtime profile, authorization home) resolves exactly as it would
        # for a human message in this chat.
        source._transport_adapter_ref = weakref.ref(adapter)
        identity = self._canonicalize(source)
        if identity is None:
            return _refuse("origin %s does not resolve to a served profile", where)
        if identity.runtime_profile != profile:
            return _refuse("origin %s routes to profile %s, not the plugin's profile %s",
                           where, identity.runtime_profile, profile)
        return source

    async def _dispatch_plugin_origin_injection(
        self, *, source: SessionSource, content: str, plugin_id: str
    ) -> bool:
        """Start (or continue) the session at a plugin-supplied origin through the adapter's normal
        message path: ``get_or_create_session`` creates it, the reply goes back to that chat."""
        target = f"origin={source.platform.value}/{source.chat_id}"
        if not self._plugin_injection_accepting():
            return False
        adapter = self._delivery_adapter_for(source)
        if adapter is None:
            logger.warning("Plugin message injection: adapter for %s went away before dispatch", target)
            return False
        if not self._plugin_injection_authorized(source, plugin_id=plugin_id, target=target):
            return False
        session_key = self._session_key_for_source(source)
        async with self._plugin_injection_scope(source):
            await adapter.handle_message(MessageEvent(
                text=content, message_type=MessageType.TEXT, source=source, internal=True,
                allow_gateway_control=False,
                # Non-strict: the key is pinned against topic recovery, the session may not exist yet.
                metadata={
                    "hermes_plugin_id": plugin_id, "hermes_plugin_injection": True,
                    "gateway_session_key": session_key,
                },
            ))
        logger.info("Plugin message injection dispatched: plugin=%s %s session=%s", plugin_id, target, session_key)
        return True
