"""Bounded BHSC2 host-safe codecs, with no I/O or admission authority.

Only D/W/S/R are implemented. The caller must supply an explicitly synthetic
32-byte H(B); this module does not encode native B, private C/P/E, BHDF proofs,
or establish currentness. Safe bytes still belong only on protected channels,
never in diagnostics. Claim K and source-v2 use different codecs.
"""
from hashlib import sha256
import re
from typing import Any

MAX_FRAME_BYTES = 65536
_DELIVERY_FIELDS = (
    'version', 'claim_id', 'tuple_digest', 'enrollment_attempt_id', 'delivery_id',
    'surface', 'profile_home_key', 'session_key', 'native_session_id',
    'host_owner_id', 'route_epoch', 'route_fingerprint', 'host_boot_epoch',
    'origin_epoch', 'payload_sha256', 'holder_uid', 'holder_pid',
    'holder_start_ticks', 'holder_machine_boot_id', 'expires_at_unix_ms',
)
_NUMERIC_RANGES = {
    'version': (2, 2), 'holder_uid': (0, 4294967295),
    'holder_pid': (1, 2147483647), 'holder_start_ticks': (1, 9223372036854775807),
    'expires_at_unix_ms': (0, 253402300799999),
}
_LOWER_HEX = frozenset(('claim_id', 'tuple_digest', 'payload_sha256'))
_PHASES = ('enroll', 'admit_native')


class CodecError(ValueError):
    """Fixed public error; never include rejected bytes or private values."""

    def __init__(self):
        super().__init__('invalid_request')


def _integer(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise CodecError()
    return value


def _raw32(value: Any) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise CodecError()
    return value


def _text(value: Any) -> bytes:
    if type(value) is not str or not value or len(value) > 1024:
        raise CodecError()
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise CodecError()
    raw = value.encode('utf-8')
    if len(raw) > 1024:
        raise CodecError()
    return raw


def _utf8(raw: bytes) -> str:
    # Raise outside the handler so exception chaining cannot retain raw input.
    try:
        return raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        pass
    raise CodecError()


def _u64(value: int) -> bytes:
    return value.to_bytes(8, 'big')


def _read_u64(raw: bytes) -> int:
    if len(raw) != 8:
        raise CodecError()
    return int.from_bytes(raw, 'big')


def _encode(domain: bytes, *fields: bytes) -> bytes:
    parts = (domain, *fields)
    if sum(4 + len(part) for part in parts) > MAX_FRAME_BYTES:
        raise CodecError()
    return b''.join(len(part).to_bytes(4, 'big') + part for part in parts)


def _decode(frame: bytes, domain: bytes, count: int) -> list[bytes]:
    if type(frame) is not bytes or len(frame) > MAX_FRAME_BYTES:
        raise CodecError()
    offset = 0
    fields = []
    for _ in range(count + 1):
        if offset + 4 > len(frame):
            raise CodecError()
        size = int.from_bytes(frame[offset:offset + 4], 'big')
        offset += 4
        if size > len(frame) - offset:
            raise CodecError()
        fields.append(frame[offset:offset + size])
        offset += size
    if offset != len(frame) or fields[0] != domain:
        raise CodecError()
    return fields[1:]


def encode_delivery(delivery: dict[str, Any]) -> bytes:
    """Encode exactly the 20 DeliveryBinding v2 fields, never a claim projection."""
    if type(delivery) is not dict or delivery.keys() != set(_DELIVERY_FIELDS):
        raise CodecError()
    fields = []
    for name in _DELIVERY_FIELDS:
        value = delivery[name]
        if name in _NUMERIC_RANGES:
            fields.append(_u64(_integer(value, *_NUMERIC_RANGES[name])))
        else:
            raw = _text(value)
            if name in _LOWER_HEX and not re.fullmatch('[0-9a-f]{64}', value):
                raise CodecError()
            if name == 'route_fingerprint' and not re.fullmatch('[0-9A-F]{64}', value):
                raise CodecError()
            fields.append(raw)
    if delivery['surface'] not in ('cli', 'gateway'):
        raise CodecError()
    if delivery['enrollment_attempt_id'] != 'hermes-enroll-v1:' + delivery['claim_id']:
        raise CodecError()
    return _encode(b'BHSC2/delivery', *fields)


def decode_delivery(frame: bytes) -> dict[str, Any]:
    fields = _decode(frame, b'BHSC2/delivery', 20)
    delivery = {name: _read_u64(raw) if name in _NUMERIC_RANGES else _utf8(raw)
                for name, raw in zip(_DELIVERY_FIELDS, fields)}
    encode_delivery(delivery)
    return delivery


def encode_public_binding(
    delivery: dict[str, Any], *, reference: bytes, phase: str,
    action_id: bytes, synthetic_pair_hash: bytes, reference_expires_at_unix_ms: int,
) -> bytes:
    """Build W with synthetic H(B), not a registered/native pair assertion."""
    encoded_delivery = encode_delivery(delivery)
    if type(phase) is not str or phase not in _PHASES:
        raise CodecError()
    expiry = _integer(reference_expires_at_unix_ms, 0, delivery['expires_at_unix_ms'])
    return _encode(b'BHSC2/public-bind', _u64(2), _raw32(reference),
                   encoded_delivery, phase.encode('ascii'), _raw32(action_id),
                   _raw32(synthetic_pair_hash), _u64(expiry))


def decode_public_binding(frame: bytes) -> dict[str, Any]:
    version, reference, delivery, phase, action, pair_hash, expiry = _decode(
        frame, b'BHSC2/public-bind', 7)
    if _read_u64(version) != 2:
        raise CodecError()
    result = dict(delivery=decode_delivery(delivery), reference=reference,
                  phase=_utf8(phase), action_id=action, synthetic_pair_hash=pair_hash,
                  reference_expires_at_unix_ms=_read_u64(expiry))
    encode_public_binding(**result)
    return result


def encode_host(public_binding: bytes) -> bytes:
    """Wrap validated W in S and bind its exact bytes with H(W)."""
    decode_public_binding(public_binding)
    return _encode(b'BHSC2/host', _u64(2), public_binding, sha256(public_binding).digest())


def decode_host(frame: bytes) -> bytes:
    version, public_binding, digest = _decode(frame, b'BHSC2/host', 3)
    if _read_u64(version) != 2 or _raw32(digest) != sha256(public_binding).digest():
        raise CodecError()
    decode_public_binding(public_binding)
    return public_binding


def encode_request(public_binding: bytes) -> bytes:
    """Construct exact R from validated W; no payload or extension fields."""
    binding = decode_public_binding(public_binding)
    return _encode(b'BHSC2/request', _u64(2), binding['reference'],
                   sha256(public_binding).digest(), binding['phase'].encode('ascii'),
                   binding['action_id'])


def validate_request(request: bytes, host: bytes) -> None:
    """Require byte-exact R/S agreement. Success does not authorize admission."""
    _decode(request, b'BHSC2/request', 5)
    if request != encode_request(decode_host(host)):
        raise CodecError()
