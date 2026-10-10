"""BHI1 framing and fail-closed host transport contracts."""
import hashlib
import os
import socket
import struct
import threading
import time

import pytest

from hermes_cli.trusted_inbound_wire import (
    BHI1ProtocolError, BHI1Response, BHI1UnixClient, decode_request, decode_response,
    encode_query_request, encode_request,
)
from hermes_cli.trusted_inbound_broker import NativeCandidateSnapshot, TrustedInboundBrokerClient


QUERY_HEX = ("424849310000003700010400011748aed488b5e1a1a1f2d39dfe37765837d777"
             "9a4bebe29bab6e8be12bcbf1000000026431000000026531000000026e3101")
UNKNOWN_HEX = ("424849310000006200018400011748aed488b5e1a1a1f2d39dfe37765837d777"
               "9a4bebe29bab6e8be12bcbf1000000000d70726f6f665f756e6b6e6f776e"
               "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
               "ffffffff00000000")


def _wire_string(value):
    if value is None:
        return struct.pack(">i", -1)
    encoded = value.encode("utf-8")
    return struct.pack(">i", len(encoded)) + encoded


def _response_frame(request, status, *, optionals=None, expiry=-1, proof=b""):
    optionals = (None,) * 8 if optionals is None else optionals
    body = (struct.pack(">HBB", 1, request[10] | 0x80, 0) + request[12:44]
            + bytes((status,)) + _wire_string("reason")
            + b"".join(_wire_string(value) for value in optionals)
            + struct.pack(">qI", expiry, len(proof)) + proof)
    return b"BHI1" + struct.pack(">I", len(body)) + body


REQUESTS = {
    1: ("enrollment", "delivery", "cli", "profile", "session", "native",
        "owner", "route", "boot", "origin", "digest"),
    2: ("delivery", "enrollment", "capability", b"x" * 32),
    3: ("delivery", "enrollment", "candidate", "native-event"),
    4: ("delivery", "enrollment", "native-event", True),
}
ADMITTED_FIELDS = (None, None, None, "candidate", "proof", "issuer", "epoch", "signature")


@pytest.mark.parametrize("kind", (1, 2, 3, 4))
@pytest.mark.parametrize("status", (0, 1, 2, 3, 4))
def test_response_status_kind_matrix_matches_bee_shape(kind, status):
    request = encode_request(kind, *REQUESTS[kind])
    optionals = ADMITTED_FIELDS if status == 2 else (None,) * 8
    proof = b"canonical" if status == 2 else b""
    frame = _response_frame(request, status, optionals=optionals, proof=proof)
    valid = status in (0, 3, 4) or (status == 2 and kind in (3, 4))
    if valid:
        assert decode_response(frame, request).status == status
    else:
        with pytest.raises(BHI1ProtocolError):
            decode_response(frame, request)


@pytest.mark.parametrize(("kind", "optionals", "expiry"), [
    (1, ("enrollment", "reserved", "capability", None, None, None, None, None), 1),
    (2, (None, None, None, "candidate", None, None, None, None), -1),
])
def test_queued_shapes_required_by_bee_are_accepted(kind, optionals, expiry):
    request = encode_request(kind, *REQUESTS[kind])
    frame = _response_frame(request, 1, optionals=optionals, expiry=expiry)
    assert decode_response(frame, request).status == 1


@pytest.mark.parametrize(("kind", "status", "optionals", "expiry", "proof"), [
    (4, 0, (None, None, None, "candidate", None, None, None, None), -1, b""),
    (4, 3, (None,) * 8, 0, b""),
    (4, 4, (None, None, None, "candidate", None, None, None, None), -1, b""),
    (1, 1, ("enrollment", "reserved", "capability", None, None, None, None, None), -1, b""),
    (1, 1, ("enrollment", "reserved", "capability", "candidate", None, None, None, None), 1, b""),
    (2, 1, (None, None, None, "candidate", None, None, None, None), 0, b""),
    (2, 1, (None, None, None, "candidate", "proof", None, None, None), -1, b""),
    (4, 2, ("enrollment", None, None, "candidate", "proof", "issuer", "epoch", "signature"), -1, b"canonical"),
    (4, 2, ADMITTED_FIELDS, -1, b""),
    (4, 2, (None, None, None, "candidate", None, "issuer", "epoch", "signature"), -1, b"canonical"),
])
def test_malformed_response_shapes_rejected(kind, status, optionals, expiry, proof):
    request = encode_request(kind, *REQUESTS[kind])
    frame = _response_frame(request, status, optionals=optionals, expiry=expiry, proof=proof)
    with pytest.raises(BHI1ProtocolError):
        decode_response(frame, request)


@pytest.mark.parametrize(("kind", "index"), [
    (kind, index) for kind, count in ((1, 11), (2, 3), (3, 4), (4, 3))
    for index in range(count)
])
def test_encode_request_rejects_every_empty_required_string(kind, index):
    fields = list(REQUESTS[kind])
    fields[index] = ""
    with pytest.raises(BHI1ProtocolError):
        encode_request(kind, *fields)


@pytest.mark.parametrize(("kind", "index"), [
    (kind, index) for kind, count in ((1, 11), (2, 3), (3, 4), (4, 3))
    for index in range(count)
])
def test_decode_request_rejects_every_empty_string_with_valid_request_id(kind, index):
    fields = list(REQUESTS[kind])
    fields[index] = ""
    delivery = fields[1] if kind == 1 else fields[0]
    enrollment = fields[0] if kind == 1 else fields[1]
    native_event = fields[3] if kind == 3 else fields[2] if kind == 4 else ""
    want_proof = bool(fields[3]) if kind == 4 else False
    id_material = (b"bee-hermes-ipc-v1\0" + bytes((kind,)) + _wire_string(delivery)
                   + _wire_string(enrollment) + _wire_string(native_event)
                   + bytes((want_proof,)))
    request_id = hashlib.sha256(id_material).digest()
    string_fields = fields[:3] if kind in (2, 4) else fields
    suffix = fields[3] if kind == 2 else bytes((want_proof,)) if kind == 4 else b""
    body = (struct.pack(">HBB", 1, kind, 0) + request_id
            + b"".join(_wire_string(value) for value in string_fields) + suffix)
    frame = b"BHI1" + struct.pack(">I", len(body)) + body
    with pytest.raises(BHI1ProtocolError):
        decode_request(frame)


def test_query_matches_shared_exact_byte_vector():
    request = encode_query_request("d1", "e1", "n1", True)
    assert request.hex() == QUERY_HEX
    parsed = decode_request(request)
    assert parsed.kind == 4 and parsed.request_id.hex() == (
        "011748aed488b5e1a1a1f2d39dfe37765837d7779a4bebe29bab6e8be12bcbf1")
    response = decode_response(bytes.fromhex(UNKNOWN_HEX), request)
    assert response.status == 0 and response.reason == "proof_unknown"


def test_shared_utf8_body_and_route_digest_vector():
    content = "Hi 🌍"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert digest == "b30714628d2f78e5efbc24dff04688aa8d2325a81996010a8d3601be286594b7"
    row = {"profile": "profile1", "session_key": "session1", "epoch": "epoch1",
           "owner": "owner1", "native_id": "native1", "delivery": "d1", "candidate": "c1",
           "state": "unknown", "execution": "running", "content": content, "payload_digest": digest}
    snapshot = NativeCandidateSnapshot.from_running_row(row, surface="gateway", content=content)
    assert snapshot.route_fingerprint == (
        "CD0CDB2E9BB3E1A51D6F24433CE8572625137A3445F95116C35630658CDE557D")


@pytest.mark.parametrize("raw", [
    bytes.fromhex("42414431" + QUERY_HEX[8:]),
    bytes.fromhex(QUERY_HEX)[:-1],
    bytes.fromhex(QUERY_HEX[:20] + "7f" + QUERY_HEX[22:]),
    bytes.fromhex(QUERY_HEX) + b"x",
    bytes.fromhex(QUERY_HEX[:8] + "00010000" + QUERY_HEX[16:]),
])
def test_malformed_request_rejected_before_side_effect(raw):
    with pytest.raises(BHI1ProtocolError):
        decode_request(raw)


def test_unknown_response_rejects_wrong_request_id_or_extra_data():
    request = encode_query_request("d1", "e1", "n1", True)
    response = bytes.fromhex(UNKNOWN_HEX)
    with pytest.raises(BHI1ProtocolError):
        decode_response(response, encode_query_request("d2", "e1", "n1", True))
    with pytest.raises(BHI1ProtocolError):
        decode_response(response + b"x", request)


def test_ambiguous_insert_uses_same_durable_event_for_read_only_query():
    snapshot = NativeCandidateSnapshot(
        "cli", "profile", "session", "native", "epoch", "owner", "delivery", "candidate",
        "local", "a" * 64, "route", "enrollment", "durable-event",
    )
    sent = []

    class AmbiguousTransport:
        def exchange(self, request):
            sent.append(decode_request(request))
            return None

    client = TrustedInboundBrokerClient()
    client.transport = AmbiguousTransport()
    assert client.observe_native_turn(snapshot).state == "unknown"
    assert [(request.kind, request.fields) for request in sent] == [
        (3, ("delivery", "enrollment", "candidate", "durable-event")),
        (4, ("delivery", "enrollment", "durable-event", True)),
    ]
    restarted = TrustedInboundBrokerClient()
    restarted.transport = AmbiguousTransport()
    assert restarted.query_native_event(snapshot).state == "unknown"
    assert [request.kind for request in sent] == [3, 4, 4]


def test_unconfigured_observer_never_promotes_local_running_row():
    snapshot = NativeCandidateSnapshot(
        "gateway", "profile", "session", "native", "epoch", "owner", "delivery", "candidate",
        "local", "a" * 64, "route", None, "durable-event",
    )
    assert TrustedInboundBrokerClient().observe_native_turn(snapshot).state == "unknown"


def test_pre_cas_row_cannot_claim_a_native_event_id():
    content = "payload"
    row = {"profile": "profile", "session_key": "session", "native_id": "native",
           "epoch": "epoch", "owner": "owner", "delivery": "delivery",
           "candidate": "candidate", "state": "unknown", "execution": "running",
           "content": content, "payload_digest": hashlib.sha256(content.encode()).hexdigest(),
           "native_event_id": "forged-pre-cas"}
    with pytest.raises(ValueError, match="event must follow settlement"):
        NativeCandidateSnapshot.from_running_row(row, surface="cli", content=content)


def test_unverified_positive_broker_reply_cannot_promote_host_receipt():
    snapshot = NativeCandidateSnapshot(
        "cli", "profile", "session", "native", "epoch", "owner", "delivery", "candidate",
        "local", "a" * 64, "route", "enrollment", "durable-event",
    )

    class UnverifiedTransport:
        def exchange(self, request):
            parsed = decode_request(request)
            return BHI1Response(0x84, parsed.request_id, 2, "admitted", None, None, None,
                                "candidate", "proof", "issuer", "epoch", "forged-signature",
                                int(time.time() * 1000) + 60_000, b"forged canonical")

    client = TrustedInboundBrokerClient()
    client.transport = UnverifiedTransport()
    receipt = client.query_native_event(snapshot)
    assert receipt.state == "unknown" and receipt.candidate_id is None


def test_pre_model_host_queues_reserved_id_without_enrolling(tmp_path):
    from gateway.native_plugin_queue import NativePluginQueue
    from hermes_cli.trusted_inbound_broker import PreModelBrokerGrant

    queue = NativePluginQueue(tmp_path)
    seen = []

    class Broker:
        def exchange(self, request):
            parsed = decode_request(request)
            seen.append(parsed.kind)
            assert parsed.kind == 2
            return BHI1Response(0x82, parsed.request_id, 1, "queued", None, None, None,
                                "bee-reserved", None, None, None, None, -1, b"")

    client = TrustedInboundBrokerClient()
    client.transport = Broker()
    grant = PreModelBrokerGrant(
        "delivery", "gateway", "profile", "key", "native", "owner", "epoch",
        queue.payload_digest("payload"), "enrollment", "bee-reserved", "test-capability",
        int(time.time() * 1000) + 60_000)
    assert client.queue_pre_model(queue=queue, grant=grant, still_current=lambda: True) == grant
    row = queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                      native_id="native", owner="owner", plugin="bee", content="payload")
    assert row["candidate"] == "bee-reserved" and row["state"] == "unknown"
    assert seen == [2]


@pytest.mark.platforms("linux")
def test_linux_client_checks_connected_peer_uid(tmp_path):
    path = tmp_path / "broker.sock"
    ready = threading.Event()
    received = []

    def serve():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(2)
            ready.set()
            for _ in range(2):
                conn, _ = listener.accept()
                with conn:
                    request = bytearray()
                    while part := conn.recv(4096):
                        request.extend(part)
                    received.append(bytes(request))
                    if request:
                        conn.sendall(bytes.fromhex(UNKNOWN_HEX))

    thread = threading.Thread(target=serve)
    thread.start()
    assert ready.wait(3)
    request = encode_query_request("d1", "e1", "n1", True)
    try:
        assert BHI1UnixClient(path, expected_broker_uid=os.getuid() + 1,
                              timeout=1).exchange(request) is None
        response = BHI1UnixClient(path, expected_broker_uid=os.getuid(), timeout=1).exchange(request)
        assert response is not None and response.status == 0 and response.reason == "proof_unknown"
    finally:
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert received == [b"", request]
