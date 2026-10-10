"""Host-safe BHSC2 vectors; synthetic pair hashes do not attest native peers."""
import hashlib
import struct

import pytest

from hermes_cli import trusted_inbound_darwin_codec as codec

FIELDS = (
    'version claim_id tuple_digest enrollment_attempt_id delivery_id surface '
    'profile_home_key session_key native_session_id host_owner_id route_epoch '
    'route_fingerprint host_boot_epoch origin_epoch payload_sha256 holder_uid '
    'holder_pid holder_start_ticks holder_machine_boot_id expires_at_unix_ms'
).split()
NUMERIC = {'version', 'holder_uid', 'holder_pid', 'holder_start_ticks', 'expires_at_unix_ms'}


def binding():
    values = [2, 'a' * 64, 'b' * 64, 'hermes-enroll-v1:' + 'a' * 64,
              'delivery-β', 'cli', 'profile', 'session', 'native', 'owner',
              'route', 'C' * 64, 'boot', 'origin', 'd' * 64, 501, 201, 555,
              'machine', 1700000030000]
    return dict(zip(FIELDS, values))


def pack(*fields):
    return b''.join(struct.pack('>I', len(f)) + f for f in fields)


def vectors():
    d = binding()
    delivery = pack(b'BHSC2/delivery', *(struct.pack('>Q', d[k]) if k in NUMERIC
                                      else d[k].encode('utf-8') for k in FIELDS))
    w = pack(b'BHSC2/public-bind', struct.pack('>Q', 2), b'r' * 32, delivery,
             b'admit_native', b'a' * 32, b'b' * 32, struct.pack('>Q', 1700000020000))
    digest = hashlib.sha256(w).digest()
    s = pack(b'BHSC2/host', struct.pack('>Q', 2), w, digest)
    r = pack(b'BHSC2/request', struct.pack('>Q', 2), b'r' * 32, digest,
             b'admit_native', b'a' * 32)
    return delivery, w, s, r


def test_exact_bytes_and_roundtrip_with_synthetic_pair_hash():
    d, w, s, r = vectors()
    assert codec.encode_delivery(binding()) == d
    assert codec.decode_delivery(d) == binding()
    assert codec.encode_public_binding(binding(), reference=b'r' * 32,
        phase='admit_native', action_id=b'a' * 32, synthetic_pair_hash=b'b' * 32,
        reference_expires_at_unix_ms=1700000020000) == w
    assert codec.encode_host(w) == s
    assert codec.decode_host(s) == w
    assert codec.encode_request(w) == r
    assert codec.validate_request(r, s) is None
    assert codec.decode_public_binding(w)['delivery'] == binding()


@pytest.mark.parametrize('field', FIELDS)
def test_every_delivery_field_is_bound_by_public_digest(field):
    d = binding()
    if field == 'version':
        d[field] = 1
        with pytest.raises(codec.CodecError):
            codec.encode_delivery(d)
        return
    if field == 'claim_id':
        d[field] = 'e' * 64
        d['enrollment_attempt_id'] = 'hermes-enroll-v1:' + d[field]
    elif field == 'enrollment_attempt_id':
        d[field] = 'wrong'
        with pytest.raises(codec.CodecError):
            codec.encode_delivery(d)
        return
    elif field in NUMERIC:
        d[field] += 1
    elif field == 'surface':
        d[field] = 'gateway'
    elif field in {'tuple_digest', 'payload_sha256'}:
        d[field] = 'e' * 64
    elif field == 'route_fingerprint':
        d[field] = 'E' * 64
    else:
        d[field] += '-changed'
    w = codec.encode_public_binding(d, reference=b'r' * 32, phase='admit_native',
        action_id=b'a' * 32, synthetic_pair_hash=b'b' * 32,
        reference_expires_at_unix_ms=1700000020000)
    with pytest.raises(codec.CodecError):
        codec.validate_request(vectors()[3], codec.encode_host(w))


@pytest.mark.parametrize('field,value', [
    ('version', True), ('version', 1), ('holder_uid', -1), ('holder_uid', 2**32),
    ('holder_pid', 0), ('holder_pid', 2**31), ('holder_start_ticks', 0),
    ('holder_start_ticks', 2**63), ('expires_at_unix_ms', 253402300800000),
    ('holder_pid', 2.0), ('delivery_id', ''), ('delivery_id', '\ud800'),
    ('delivery_id', 'x\x00y'), ('delivery_id', 'x' * 1025),
    ('route_fingerprint', 'c' * 64), ('payload_sha256', 'D' * 64),
    ('surface', 'tui'), ('session_key', None), ('enrollment_attempt_id', 'wrong'),
])
def test_delivery_rejects_invalid_types_ranges_and_text(field, value):
    d = binding()
    d[field] = value
    with pytest.raises(codec.CodecError, match='^invalid_request$'):
        codec.encode_delivery(d)


@pytest.mark.parametrize('decode,index', [('decode_delivery', 0),
    ('decode_public_binding', 1), ('decode_host', 2)])
def test_frames_deny_all_truncations_trailing_null_and_wrong_endian(decode, index):
    frame = vectors()[index]
    fn = getattr(codec, decode)
    for cut in range(len(frame)):
        with pytest.raises(codec.CodecError):
            fn(frame[:cut])
    for bad in [frame + b'\x00', frame + pack(b'extra'), b'\xff' * 4,
                frame[:4][::-1] + frame[4:], b'x' * 65537,
                frame.replace(b'BHSC2', b'BHSC1', 1)]:
        with pytest.raises(codec.CodecError, match='^invalid_request$'):
            fn(bad)


def test_private_extras_never_escape_in_errors_or_logs(caplog, capsys):
    for key in ['C', 'P', 'E', 'issuer_uid', 'source_digest', 'capability']:
        d = binding()
        d[key] = 'PRIVATE-SENTINEL-' + key
        with pytest.raises(codec.CodecError) as exc:
            codec.encode_delivery(d)
        assert str(exc.value) == 'invalid_request'
        assert exc.value.__cause__ is None
    assert not caplog.records
    assert capsys.readouterr() == ('', '')
    assert b'PRIVATE-SENTINEL' not in b''.join(vectors())


def test_digest_request_fields_and_duplicate_delivery_are_checked():
    d, w, s, r = vectors()
    for index in range(len(r)):
        changed = r[:index] + bytes([r[index] ^ 1]) + r[index + 1:]
        with pytest.raises(codec.CodecError):
            codec.validate_request(changed, s)
    with pytest.raises(codec.CodecError):
        codec.decode_host(s[:-1] + bytes([s[-1] ^ 1]))
    with pytest.raises(codec.CodecError):
        codec.decode_delivery(d + pack(b'PRIVATE-SENTINEL'))
    with pytest.raises(codec.CodecError):
        codec.encode_delivery(dict(list(binding().items())[:-1]))


@pytest.mark.parametrize('changes', [
    {'reference': b'x' * 31}, {'action_id': b'x' * 33},
    {'synthetic_pair_hash': b'private-pair'}, {'phase': 'ENROLL'},
    {'reference_expires_at_unix_ms': 1700000030001},
    {'reference_expires_at_unix_ms': True},
])
def test_public_binding_input_restrictions(changes):
    args = dict(reference=b'r' * 32, phase='admit_native', action_id=b'a' * 32,
                synthetic_pair_hash=b'b' * 32, reference_expires_at_unix_ms=1700000020000)
    args.update(changes)
    with pytest.raises(codec.CodecError):
        codec.encode_public_binding(binding(), **args)


def test_binary_utf8_numeric_width_and_domain_counterexamples():
    d, w, s, r = vectors()
    for bad in [d.replace('delivery-β'.encode(), b'delivery-\xff\xff'),
                d.replace(struct.pack('>Q', 501), struct.pack('<Q', 501)),
                d.replace(b'BHSC2/delivery', b'BHSC2/privates'),
                b'\xff\xff\xff\xff' + d[4:]]:
        with pytest.raises(codec.CodecError):
            codec.decode_delivery(bad)
    for frame, decode in [(w, codec.decode_public_binding), (s, codec.decode_host)]:
        with pytest.raises(codec.CodecError):
            decode(frame.replace(struct.pack('>Q', 2), struct.pack('>Q', 1), 1))
    with pytest.raises(codec.CodecError):
        codec.validate_request(r + pack(b'PRIVATE-SENTINEL'), s)


def test_unicode_is_not_normalized_and_valid_numeric_boundaries_roundtrip():
    d = binding()
    d.update(holder_uid=0, holder_pid=2147483647,
             holder_start_ticks=9223372036854775807, expires_at_unix_ms=253402300799999)
    d['delivery_id'] = 'é'
    composed = codec.encode_delivery(d)
    d['delivery_id'] = 'e\u0301'
    decomposed = codec.encode_delivery(d)
    assert composed != decomposed
    assert codec.decode_delivery(decomposed) == d
    for phase in ['enroll', 'admit_native']:
        w = codec.encode_public_binding(d, reference=bytes(32), phase=phase,
            action_id=bytes(32), synthetic_pair_hash=bytes(32),
            reference_expires_at_unix_ms=0)
        assert codec.validate_request(codec.encode_request(w), codec.encode_host(w)) is None
