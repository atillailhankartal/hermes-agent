"""Dormant, fail-closed seam for a future isolated Bee inbound broker.

The Hermes SQLite row is only a local candidate. Its route fingerprint is a
correlation value, never proof that the broker saw a native insertion. Bee
space, recipient, generation, message and enrollment are unavailable from
this host callback. No transport, credential, signer or admitted proof exists.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from hermes_cli.plugins_injection import AdmissionReceipt


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
    payload_sha256: str
    route_fingerprint: str

    @classmethod
    def from_running_row(cls, row: dict, *, surface: str, content: str):
        """Bind the local candidate's exact immutable correlation tuple."""
        if surface not in ("cli", "gateway") or not isinstance(content, str):
            raise ValueError("invalid native candidate")
        names = ("profile", "session_key", "native_id", "epoch", "owner", "delivery", "candidate")
        if (row.get("state") != "unknown" or row.get("execution") != "running"
                or any(not isinstance(row.get(name), str) or not row[name].strip() for name in names)
                or row.get("content") != content):
            raise ValueError("native candidate changed")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if row.get("payload_digest") != digest:
            raise ValueError("native candidate digest changed")
        route = (row["profile"], row["session_key"], row["epoch"], row["owner"], row["native_id"])
        hasher = hashlib.sha256()
        for value in route:
            encoded = value.encode("utf-8")
            hasher.update(struct.pack(">i", len(encoded)))
            hasher.update(encoded)
        return cls(surface, row["profile"], row["session_key"], row["native_id"],
                   row["epoch"], row["owner"], row["delivery"], row["candidate"],
                   digest, hasher.hexdigest().upper())


class TrustedInboundBrokerClient:
    """Explicitly unavailable until a protected broker and native event source exist."""

    def observe_native_turn(self, snapshot: NativeCandidateSnapshot) -> AdmissionReceipt:
        # Same-UID callback, SQLite and in-process lease checks cannot authorize
        # a broker decision. A future client must use a protected endpoint and
        # broker-owned enrollment/event verification before any positive result.
        return AdmissionReceipt("unknown", "trusted_broker_unavailable",
                                snapshot.delivery_id, snapshot.route_epoch)
