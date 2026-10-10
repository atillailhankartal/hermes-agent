"""Dormant, fail-closed seam for a future isolated Bee inbound broker.

The Hermes SQLite row is only a local candidate. Its route fingerprint is a
correlation value, never proof that the broker saw a native insertion. Bee
space, recipient, generation, message and enrollment are unavailable from
this host callback. No transport, credential, signer or admitted proof exists.
"""
from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass

from hermes_cli.plugins_injection import AdmissionReceipt


@dataclass(frozen=True)
class PreModelBrokerGrant:
    """Broker reservation carried into the host before model tools can run.

    This object only aligns the local candidate ID. A Python object or SQLite
    row is never authority for a signed Bee admission decision.
    """

    delivery_id: str
    surface: str
    profile_home_key: str
    session_key: str
    native_session_id: str
    host_owner_id: str
    route_epoch: str
    payload_sha256: str
    enrollment_id: str
    reserved_candidate_id: str
    capability: str
    expires_at_unix_ms: int

    def matches(self, *, delivery, surface, profile, session_key, native_id, owner, epoch, digest):
        return (self.delivery_id == delivery and self.surface == surface
                and self.profile_home_key == profile and self.session_key == session_key
                and self.native_session_id == native_id and self.host_owner_id == owner
                and self.route_epoch == epoch and self.payload_sha256 == digest)


@dataclass(frozen=True)
class NativeCandidateSnapshot:
    surface: str
    profile_home_key: str
    session_key: str
    native_session_id: str
    route_epoch: str
    host_owner_id: str
    delivery_id: str
    candidate_id: str
    local_event_id: str
    payload_sha256: str
    route_fingerprint: str
    enrollment_id: str | None = None
    native_event_id: str | None = None

    @classmethod
    def from_running_row(cls, row: dict, *, surface: str, content: str):
        """Bind the local candidate's exact immutable correlation tuple."""
        if surface not in ("cli", "gateway") or not isinstance(content, str):
            raise ValueError("invalid native candidate")
        names = ("profile", "session_key", "native_id", "epoch", "owner", "delivery", "candidate")
        if (row.get("state") not in ("unknown", "admitted") or row.get("execution") != "running"
                or any(not isinstance(row.get(name), str) or not row[name].strip() for name in names)
                or row.get("content") != content):
            raise ValueError("native candidate changed")
        if (row["state"] == "admitted" and not row.get("native_event_id")) or (
                row["state"] == "unknown" and row.get("native_event_id")):
            raise ValueError("native event must follow settlement")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if row.get("payload_digest") != digest:
            raise ValueError("native candidate digest changed")
        route = (row["profile"], row["session_key"], row["epoch"], row["owner"], row["native_id"])
        hasher = hashlib.sha256()
        for value in route:
            encoded = value.encode("utf-8")
            hasher.update(struct.pack(">i", len(encoded)))
            hasher.update(encoded)
        # This same-UID ID is only for future protected IPC readback, never authority.
        event_hasher = hashlib.sha256(b"hermes-local-native-event-v1\0")
        for value in (surface, *route, row["delivery"], row["candidate"], digest):
            encoded = value.encode("utf-8")
            event_hasher.update(struct.pack(">i", len(encoded)))
            event_hasher.update(encoded)
        return cls(surface, row["profile"], row["session_key"], row["native_id"],
                   row["epoch"], row["owner"], row["delivery"], row["candidate"],
                   event_hasher.hexdigest().upper(), digest, hasher.hexdigest().upper(),
                   row.get("enrollment_id"), row.get("native_event_id"))


class TrustedInboundBrokerClient:
    """Fail-closed BHI1 observer; local correlation never authorizes acceptance.

    The default host has no protected issuer, pinned proof key or isolated broker
    configuration. A configured transport can notify/query a broker, but an
    unverified response cannot be promoted to an admitted receipt.
    """

    def __init__(self, *, socket_path=None, issuer_socket_path=None,
                 expected_broker_uid=None, timeout=0.5):
        self.transport = None
        self.issuer_transport = None
        if socket_path is not None and expected_broker_uid is not None:
            from hermes_cli.trusted_inbound_wire import BHI1UnixClient
            self.transport = BHI1UnixClient(socket_path, expected_broker_uid=expected_broker_uid,
                                            timeout=timeout)
            if issuer_socket_path is not None:
                self.issuer_transport = BHI1UnixClient(
                    issuer_socket_path, expected_broker_uid=expected_broker_uid, timeout=timeout)

    @staticmethod
    def _unknown(snapshot, reason):
        return AdmissionReceipt("unknown", reason, snapshot.delivery_id, snapshot.route_epoch)

    def enroll_pre_model(self, *, queue, enrollment_attempt_id, delivery_id, surface,
                         profile_home_key, session_key, native_session_id, host_owner_id,
                         route_epoch, route_fingerprint, host_boot_epoch, origin_epoch,
                         payload_sha256):
        """Pre-model issuer path: reserve and queue before local candidate creation.

        The caller must be the isolated supervisor. The default process has no
        issuer socket or broker principal; without both responses there is no
        grant to install. Bee independently rechecks the exact body and route.
        """
        if self.issuer_transport is None or self.transport is None:
            return None
        from hermes_cli.trusted_inbound_wire import decode_request, encode_request
        try:
            digest = bytes.fromhex(payload_sha256)
            if len(digest) != 32 or digest.hex() != payload_sha256:
                return None
            request = encode_request(1, enrollment_attempt_id, delivery_id, surface,
                                     profile_home_key, session_key, native_session_id,
                                     host_owner_id, route_epoch, route_fingerprint,
                                     host_boot_epoch, origin_epoch)
            enrollment = self.issuer_transport.exchange(request)
            if (enrollment is None or enrollment.status != 1 or enrollment.kind != 0x81
                    or enrollment.request_id != decode_request(request).request_id
                    or not all((enrollment.enrollment_id, enrollment.reserved_candidate_id,
                                enrollment.capability))
                    or enrollment.expires_at_unix_ms <= int(time.time() * 1000)):
                return None
            queued_request = encode_request(2, delivery_id, enrollment.enrollment_id,
                                            enrollment.capability, digest)
            queued = self.transport.exchange(queued_request)
            if (queued is None or queued.status != 1 or queued.kind != 0x82
                    or queued.request_id != decode_request(queued_request).request_id
                    or queued.candidate_id != enrollment.reserved_candidate_id):
                return None
            grant = PreModelBrokerGrant(
                delivery_id, surface, profile_home_key, session_key, native_session_id,
                host_owner_id, route_epoch, payload_sha256, enrollment.enrollment_id,
                enrollment.reserved_candidate_id, enrollment.capability,
                enrollment.expires_at_unix_ms,
            )
            return grant if queue.install_pre_model_grant(grant) else None
        except (TypeError, ValueError):
            return None

    def query_native_event(self, snapshot: NativeCandidateSnapshot) -> AdmissionReceipt:
        """Read only the retained event ID; never insert a second host candidate."""
        if self.transport is None or not snapshot.enrollment_id or not snapshot.native_event_id:
            return self._unknown(snapshot, "trusted_broker_unavailable")
        from hermes_cli.trusted_inbound_wire import encode_query_request
        request = encode_query_request(snapshot.delivery_id, snapshot.enrollment_id,
                                       snapshot.native_event_id, True)
        response = self.transport.exchange(request)
        if response is None:
            return self._unknown(snapshot, "broker_query_unknown")
        # The broker response is not a Bee majority/proof verification performed
        # by this host. No pinned issuer/tuple is provisioned in this slice.
        return self._unknown(snapshot, "broker_proof_unverified" if response.status == 2
                             else response.reason)

    def observe_native_turn(self, snapshot: NativeCandidateSnapshot) -> AdmissionReceipt:
        if self.transport is None or not snapshot.enrollment_id or not snapshot.native_event_id:
            return self._unknown(snapshot, "trusted_broker_unavailable")
        from hermes_cli.trusted_inbound_wire import encode_request
        request = encode_request(3, snapshot.delivery_id, snapshot.enrollment_id,
                                 snapshot.candidate_id, snapshot.native_event_id)
        # The CAS and durable ID already exist. Even if this write is ambiguous,
        # the only retry is a read-only QUERY with the same event ID.
        self.transport.exchange(request)
        return self.query_native_event(snapshot)
