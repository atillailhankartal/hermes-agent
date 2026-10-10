"""Pure BHDF1 transcript/proof primitives; no transport or admission authority.

B and S are opaque, caller-supplied bytes. This module cannot validate their
native/source schemas, enrollment, currentness, channel binding or provenance.
Only public synthetic B/S vectors have been exercised. Positive Darwin admission
remains unavailable pending bootstrap, canonical B/S and transactional fencing.
Trusted callers must obtain local allowlists and bindings independently of input.
Proof verification establishes byte agreement only, not freshness or one-time use.
"""
from hashlib import sha256
import hmac

from hermes_cli.trusted_inbound_darwin_codec import (
    MAX_FRAME_BYTES, CodecError, _decode, _encode, _integer, _raw32,
)


def _bounded(value: bytes, *, nonempty: bool = False) -> bytes:
    if type(value) is not bytes or len(value) > MAX_FRAME_BYTES or (nonempty and not value):
        raise CodecError()
    return value


def _ascii(value: str) -> bytes:
    if (type(value) is not str or not value or len(value) > MAX_FRAME_BYTES
            or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise CodecError()
    return value.encode('ascii')


def _allowed(value: str, allowed: frozenset[str]) -> bytes:
    raw = _ascii(value)
    if type(allowed) is not frozenset or not allowed:
        raise CodecError()
    for item in allowed:
        _ascii(item)
    if value not in allowed:
        raise CodecError()
    return raw


def encode_transcript(
    *, registry_binding: bytes, source_binding: bytes, request_id: bytes,
    client_nonce: bytes, server_nonce: bytes, connection_id: bytes,
    operation: str, request: bytes, allowed_operations: frozenset[str],
    channel: str | None = None, allowed_channels: frozenset[str] | None = None,
) -> bytes:
    """Build T using trusted local policy; optional channel check does not parse B.

    The caller must retain this exact T as its expected context for verification.
    A peer-supplied T or peer-supplied allowlist cannot establish expected context.
    """
    if channel is not None or allowed_channels is not None:
        _allowed(channel, allowed_channels)
    return _encode(b'BHDF1/transcript', _bounded(registry_binding, nonempty=True),
                   _bounded(source_binding, nonempty=True), _raw32(request_id),
                   _raw32(client_nonce), _raw32(server_nonce), _raw32(connection_id),
                   _allowed(operation, allowed_operations), sha256(_bounded(request)).digest())


def _transcript(transcript: bytes) -> list[bytes]:
    fields = _decode(transcript, b'BHDF1/transcript', 8)
    _bounded(fields[0], nonempty=True)
    _bounded(fields[1], nonempty=True)
    for field in (*fields[2:6], fields[7]):
        _raw32(field)
    # Inspect raw ASCII before decoding; errors never embed rejected input.
    if not fields[6] or any(c < 33 or c > 126 for c in fields[6]):
        raise CodecError()
    return fields


def challenge_proof(key_sc: bytes, transcript: bytes) -> bytes:
    """Mc: server-to-client proof of the exact canonical T supplied by caller."""
    _raw32(key_sc)
    _transcript(transcript)
    return hmac.digest(key_sc, _encode(b'BHDF1/challenge', transcript), 'sha256')


def request_proof(key_cs: bytes, transcript: bytes, challenge: bytes, request: bytes) -> bytes:
    """Mr: bind T, Mc and R; caller must have independently verified Mc first."""
    _raw32(key_cs)
    fields = _transcript(transcript)
    _raw32(challenge)
    if not hmac.compare_digest(fields[7], sha256(_bounded(request)).digest()):
        raise CodecError()
    return hmac.digest(key_cs, _encode(b'BHDF1/request', transcript, challenge, request), 'sha256')


def response_proof(
    key_sc: bytes, transcript: bytes, request_mac: bytes, status: int, response: bytes,
) -> bytes:
    """Mp: bind T, Mr, uint64BE status and exact response bytes."""
    _raw32(key_sc)
    _transcript(transcript)
    _raw32(request_mac)
    status_bytes = _integer(status, 0, 2**64 - 1).to_bytes(8, 'big')
    return hmac.digest(key_sc, _encode(b'BHDF1/response', transcript, request_mac,
                                     status_bytes, _bounded(response)), 'sha256')


def _verify(expected: bytes, supplied: bytes) -> None:
    if not hmac.compare_digest(expected, _raw32(supplied)):
        raise CodecError()


def verify_challenge(key_sc: bytes, expected_transcript: bytes, supplied: bytes) -> None:
    """Verify against the retained locally expected T, never an incoming T."""
    _raw32(supplied)
    _verify(challenge_proof(key_sc, expected_transcript), supplied)


def verify_request(
    key_cs: bytes, expected_transcript: bytes, challenge: bytes, request: bytes, supplied: bytes,
) -> None:
    """Verify Mr against the retained T/Mc; no pending-state consumption occurs."""
    _raw32(supplied)
    _verify(request_proof(key_cs, expected_transcript, challenge, request), supplied)


def verify_response(
    key_sc: bytes, expected_transcript: bytes, request_mac: bytes,
    status: int, response: bytes, supplied: bytes,
) -> None:
    """Verify Mp for retained T/Mr and supplied status/body; no admission result."""
    _raw32(supplied)
    _verify(response_proof(key_sc, expected_transcript, request_mac, status, response), supplied)
