"""BHI1 framing and fail-closed host transport contracts."""
import hashlib
import os
import socket
import threading
import time

import pytest

from hermes_cli.trusted_inbound_wire import (
    BHI1ProtocolError, BHI1Response, BHI1UnixClient, decode_request, decode_response,
    encode_query_request,
)
from hermes_cli.trusted_inbound_broker import NativeCandidateSnapshot, TrustedInboundBrokerClient


QUERY_HEX = ("424849310000003700010400011748aed488b5e1a1a1f2d39dfe37765837d777"
             "9a4bebe29bab6e8be12bcbf1000000026431000000026531000000026e3101")
UNKNOWN_HEX = ("424849310000006200018400011748aed488b5e1a1a1f2d39dfe37765837d777"
               "9a4bebe29bab6e8be12bcbf1000000000d70726f6f665f756e6b6e6f776e"
               "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
               "ffffffff00000000")


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


def test_pre_model_enroll_and_queue_pass_exact_reserved_id_into_sqlite(tmp_path):
    from gateway.native_plugin_queue import NativePluginQueue

    queue = NativePluginQueue(tmp_path)
    expires = int(time.time() * 1000) + 60_000
    seen = []

    class Issuer:
        def exchange(self, request):
            parsed = decode_request(request)
            seen.append(parsed)
            assert parsed.kind == 1 and parsed.fields[1:3] == ("delivery", "gateway")
            return BHI1Response(0x81, parsed.request_id, 1, "enrolled", "enrollment",
                                "bee-reserved", "capability", None, None, None, None, None,
                                expires, b"")

    class Broker:
        def exchange(self, request):
            parsed = decode_request(request)
            seen.append(parsed)
            assert parsed.kind == 2 and parsed.fields[:3] == (
                "delivery", "enrollment", "capability")
            return BHI1Response(0x82, parsed.request_id, 1, "queued", None, None, None,
                                "bee-reserved", None, None, None, None, -1, b"")

    client = TrustedInboundBrokerClient()
    client.issuer_transport = Issuer()
    client.transport = Broker()
    digest = queue.payload_digest("payload")
    grant = client.enroll_pre_model(
        queue=queue, enrollment_attempt_id="attempt", delivery_id="delivery", surface="gateway",
        profile_home_key="profile", session_key="key", native_session_id="native",
        host_owner_id="owner", route_epoch="epoch", route_fingerprint="fingerprint",
        host_boot_epoch="boot", origin_epoch="origin", payload_sha256=digest,
    )
    assert grant and grant.reserved_candidate_id == "bee-reserved"
    row = queue.admit(profile="profile", epoch="epoch", delivery="delivery", session_key="key",
                      native_id="native", owner="owner", plugin="bee", content="payload")
    assert row["candidate"] == "bee-reserved" and row["state"] == "unknown"
    assert [request.kind for request in seen] == [1, 2]


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
