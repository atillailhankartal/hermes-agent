"""Protected ENROLL owner. Never loaded into a model worker for authority.

The source adapter must independently validate upstream delivery and route state.
No production source adapter or service startup is enabled by this module.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, fields
from typing import Protocol

from hermes_cli.trusted_inbound_broker import PreModelBrokerGrant
from hermes_cli.trusted_inbound_wire import decode_request, encode_request


def current_uid():
    return os.getuid() if hasattr(os, "getuid") else -1


@dataclass(frozen=True)
class DeliveryBinding:
    enrollment_attempt_id: str
    delivery_id: str
    surface: str
    profile_home_key: str
    session_key: str
    native_session_id: str
    host_owner_id: str
    route_epoch: str
    route_fingerprint: str
    host_boot_epoch: str
    origin_epoch: str
    payload_sha256: str
    holder_uid: int
    holder_pid: int

    def valid(self):
        strings = (getattr(self, field.name) for field in fields(self)
                   if field.name not in ('holder_uid', 'holder_pid'))
        return (all(type(v) is str and v.strip() and len(v.encode('utf-8')) <= 16384
                    for v in strings)
                and self.surface in ('cli', 'gateway')
                and len(self.payload_sha256) == 64
                and all(c in '0123456789abcdef' for c in self.payload_sha256)
                and type(self.holder_uid) is int and self.holder_uid >= 0
                and type(self.holder_pid) is int and self.holder_pid > 0)


class ProtectedDeliverySource(Protocol):
    """Implemented only by an independently provisioned protected upstream reader.

    claim atomically and durably consumes the delivery's pre-model issuance right,
    across issuer restarts. It validates the actual upstream delivery, payload,
    enrollment attempt/epoch and active route/owner/host boot and holder process;
    host-supplied correlation is NEVER evidence. is_current rechecks revocation
    and the exact authoritative tuple after ENROLL. Errors must fail closed.
    """

    def claim(self, delivery_id: str) -> DeliveryBinding | None: ...

    def is_current(self, binding: DeliveryBinding) -> bool: ...


class ProtectedInboundSupervisor:
    """Only this distinct OS principal owns the ENROLL transport."""

    def __init__(self, *, source: ProtectedDeliverySource, issuer_uid: int,
                 host_uid: int, host_pid: int, transport):
        if (type(issuer_uid) is not int or type(host_uid) is not int
                or issuer_uid < 0 or host_uid < 0 or issuer_uid == host_uid
                or type(host_pid) is not int or host_pid <= 0):
            raise ValueError('distinct issuer and host principals required')
        self.source = source
        self.issuer_uid, self.host_uid, self.host_pid = issuer_uid, host_uid, host_pid
        self.issuer_pid = os.getpid()
        self.transport = transport
        self._used = set()
        self._lock = threading.Lock()

    def issue(self, expected: DeliveryBinding) -> PreModelBrokerGrant | None:
        if (current_uid() != self.issuer_uid or os.getpid() != self.issuer_pid
                or type(expected) is not DeliveryBinding or not expected.valid()
                or (expected.holder_uid, expected.holder_pid) != (self.host_uid, self.host_pid)):
            return None
        with self._lock:
            key = (expected.delivery_id, expected.host_boot_epoch)
            if key in self._used:
                return None
            self._used.add(key)  # Ambiguous failure burns the right; never auto-retry ENROLL.
            actual = self.source.claim(expected.delivery_id)
            if type(actual) is not DeliveryBinding or actual != expected:
                return None
            request = encode_request(
                1, actual.enrollment_attempt_id, actual.delivery_id, actual.surface,
                actual.profile_home_key, actual.session_key, actual.native_session_id,
                actual.host_owner_id, actual.route_epoch, actual.route_fingerprint,
                actual.host_boot_epoch, actual.origin_epoch)
            response = self.transport.exchange(request)
            if (response is None or response.kind != 0x81 or response.status != 1
                    or response.request_id != decode_request(request).request_id
                    or not all((response.enrollment_id, response.reserved_candidate_id,
                                response.capability))
                    or response.expires_at_unix_ms <= int(time.time() * 1000)
                    or not self.source.is_current(actual)):
                return None
            return PreModelBrokerGrant(
                actual.delivery_id, actual.surface, actual.profile_home_key, actual.session_key,
                actual.native_session_id, actual.host_owner_id, actual.route_epoch,
                actual.payload_sha256, response.enrollment_id, response.reserved_candidate_id,
                response.capability, response.expires_at_unix_ms)
