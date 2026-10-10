"""Private CLI host authority and durable native plugin candidates.

A durable candidate alone is unknown. Only the actual CLI turn consumer may
settle it after taking the native slot and turn ownership.
"""
from __future__ import annotations

import atexit
import logging
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field

from gateway.native_plugin_queue import NativePluginQueue
from hermes_cli.plugins_injection import AdmissionReceipt
from hermes_constants import get_hermes_home, hermes_home_key

logger = logging.getLogger(__name__)


@dataclass(frozen=True, eq=False)
class CliRouteClaim:
    surface: str
    profile_home_key: str
    session_key: str
    native_session_id: str
    route_epoch: str
    host_owner_id: str
    _host: object = field(repr=False)
    _proof: object = field(repr=False)

    def is_route_current(self):
        return self._host.route_current(self)

    def is_current(self, *, native_session_id=None, **coordinates):
        return (native_session_id in (None, self.native_session_id)
                and all(getattr(self, key, None) == value for key, value in coordinates.items())
                and self._host.tool_claim_current(self))


class CliAdmissionHost:
    def __init__(self, cli, manager):
        self.cli, self.manager = cli, manager
        self.home = get_hermes_home().resolve()
        self.profile = hermes_home_key(self.home)
        self.owner = secrets.token_urlsafe(24)
        self.proof = object()
        self.lock = threading.RLock()
        self.turn_lock = threading.Lock()
        self.epoch = secrets.token_urlsafe(24)
        self.native = str(getattr(cli, "session_id", "") or "")
        self.closed = False
        self.blocked = False
        self.active_turn = None
        self.candidate = None
        self.queue = NativePluginQueue(self.home / "cli-admission")

    def _matches(self, claim):
        return (type(claim) is CliRouteClaim and claim._host is self and claim._proof is self.proof
                and claim.surface == "cli" and claim.profile_home_key == self.profile
                and claim.host_owner_id == self.owner and claim.session_key == claim.native_session_id)

    def _live_native(self):
        native = str(getattr(self.cli, "session_id", "") or "")
        agent = getattr(self.cli, "agent", None)
        return native if agent is None or getattr(agent, "session_id", None) == native else ""

    def route_current(self, claim):
        with self.lock:
            return (self._matches(claim) and not self.closed and not self.blocked
                    and not getattr(self.cli, "_should_exit", False)
                    and claim.route_epoch == self.epoch and claim.native_session_id == self.native
                    and self._live_native() == self.native
                    and hermes_home_key(get_hermes_home()) == self.profile)

    def claim(self):
        with self.lock:
            if not self.native or self._live_native() != self.native:
                return None
            claim = CliRouteClaim("cli", self.profile, self.native, self.native,
                                  self.epoch, self.owner, self, self.proof)
            return claim if self.route_current(claim) else None

    def tool_claim_current(self, claim):
        # Observation-only until the consumer binds exact native turn ownership.
        return False

    def query(self, *, route_claim, delivery_id, expected_content, route_epoch=None):
        epoch = route_epoch or getattr(route_claim, "route_epoch", None)
        unknown = AdmissionReceipt("unknown", "cli_status_unavailable", delivery_id, epoch)
        if not self._matches(route_claim) or not isinstance(expected_content, str):
            return unknown
        try:
            row = self.queue.lookup(self.profile, epoch, delivery_id)
            if row and row["native_id"] == route_claim.native_session_id:
                if row["payload_digest"] != self.queue.payload_digest(expected_content):
                    return self.queue.receipt(self.queue.conflict(row))
                return self.queue.receipt(row)
        except (OSError, sqlite3.Error):
            logger.warning("CLI native status unavailable")
        return unknown

    def admit(self, *, content, surface, route_claim, expected_session_id, delivery_id, plugin_id, manager):
        epoch = getattr(route_claim, "route_epoch", None)
        if (surface != "cli" or manager is not self.manager or not self._matches(route_claim)
                or expected_session_id != route_claim.native_session_id
                or not all(isinstance(v, str) and v.strip() for v in (content, delivery_id, plugin_id))):
            return AdmissionReceipt("rejected", "invalid_cli_route", delivery_id, epoch)
        with self.lock, manager._admission_host_lock:
            try:
                existing = self.queue.lookup(self.profile, epoch, delivery_id)
                if existing:
                    if existing["plugin"] != plugin_id or existing["native_id"] != expected_session_id:
                        return self.queue.receipt(self.queue.conflict(existing))
                    return self.query(route_claim=route_claim, delivery_id=delivery_id, expected_content=content)
                loaded = manager._plugins.get(plugin_id)
                registered = manager._admission_hosts.get("cli")
                allowed = (registered is not None and registered[0] is self and loaded is not None
                           and loaded.enabled and not loaded.error and self.route_current(route_claim))
                row = self.queue.admit(profile=self.profile, epoch=epoch, delivery=delivery_id,
                    session_key=route_claim.session_key, native_id=expected_session_id, owner=self.owner,
                    plugin=plugin_id, content=content, rejection_reason=None if allowed else "cli_route_unavailable")
                return self.queue.receipt(row)
            except (OSError, sqlite3.Error):
                logger.warning("CLI native admission outcome unavailable")
                return self.query(route_claim=route_claim, delivery_id=delivery_id, expected_content=content)

    def close(self):
        from hermes_cli.plugins_injection import clear_published_admission_host
        with self.lock:
            self.closed = True
            clear_published_admission_host("cli", self)
            self.manager.clear_admission_host("cli", self)


def install_cli_admission_host(cli):
    from hermes_cli.plugins import get_plugin_manager
    from hermes_cli.plugins_injection import publish_admission_host
    previous = getattr(cli, "_native_plugin_host", None)
    if previous is not None:
        previous.close()
    manager = get_plugin_manager()
    manager._cli_ref = cli
    host = CliAdmissionHost(cli, manager)
    cli._native_plugin_host = host
    publish_admission_host("cli", host, host.admit, host.owner)
    atexit.register(host.close)
    return host
