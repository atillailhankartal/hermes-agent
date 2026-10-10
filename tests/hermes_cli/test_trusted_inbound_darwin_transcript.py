"""BHDF1 pure byte/proof contracts; public synthetic B/S are not native bindings."""
import hashlib
import hmac
import struct

import pytest

from hermes_cli.trusted_inbound_darwin_codec import CodecError

STATUS = 0x0102030405060708
PUBLIC_KCS = bytes(range(32))
PUBLIC_KSC = bytes(range(32, 64))


def pack(*fields):
    return b''.join(struct.pack('>I', len(f)) + f for f in fields)


def inputs():
    return dict(registry_binding=b'PUBLIC synthetic B; no native schema',
                source_binding=b'PUBLIC synthetic S; no source authority',
                request_id=b'r' * 32, client_nonce=b'c' * 32,
                server_nonce=b's' * 32, connection_id=b'i' * 32,
                operation='admit_native', request=b'PUBLIC exact request',
                allowed_operations=frozenset({'admit_native'}))


def vector():
    a = inputs()
    t = pack(b'BHDF1/transcript', a['registry_binding'], a['source_binding'],
             a['request_id'], a['client_nonce'], a['server_nonce'],
             a['connection_id'], b'admit_native', hashlib.sha256(a['request']).digest())
    mc = hmac.digest(PUBLIC_KSC, pack(b'BHDF1/challenge', t), 'sha256')
    mr = hmac.digest(PUBLIC_KCS, pack(b'BHDF1/request', t, mc, a['request']), 'sha256')
    mp = hmac.digest(PUBLIC_KSC, pack(b'BHDF1/response', t, mr,
                                   struct.pack('>Q', STATUS), b'PUBLIC response'), 'sha256')
    return t, mc, mr, mp


def test_exact_transcript_and_directional_proofs_bind_every_field():
    from hermes_cli import trusted_inbound_darwin_transcript as codec
    a = inputs()
    t, mc, mr, mp = vector()
    assert codec.encode_transcript(**a) == t
    assert codec.challenge_proof(PUBLIC_KSC, t) == mc
    assert codec.request_proof(PUBLIC_KCS, t, mc, a['request']) == mr
    assert codec.response_proof(PUBLIC_KSC, t, mr, STATUS, b'PUBLIC response') == mp
    assert codec.verify_challenge(PUBLIC_KSC, t, mc) is None
    assert codec.verify_request(PUBLIC_KCS, t, mc, a['request'], mr) is None
    assert codec.verify_response(PUBLIC_KSC, t, mr, STATUS, b'PUBLIC response', mp) is None
    for status in [0, 2**64 - 1]:
        expected = hmac.digest(PUBLIC_KSC, pack(b'BHDF1/response', t, mr,
            struct.pack('>Q', status), b''), 'sha256')
        assert codec.response_proof(PUBLIC_KSC, t, mr, status, b'') == expected
    for name in a.keys() - {'allowed_operations'}:
        b = a.copy()
        b[name] = 'other' if name == 'operation' else bytes([b[name][0] ^ 1]) + b[name][1:]
        if name == 'operation':
            b['allowed_operations'] = frozenset({'other'})
        changed = codec.encode_transcript(**b)
        with pytest.raises(CodecError):
            codec.verify_challenge(PUBLIC_KSC, changed, mc)
    for bad in [PUBLIC_KCS, bytes(32)]:
        with pytest.raises(CodecError):
            codec.verify_challenge(bad, t, mc)
    for wrong in [mr, mp, bytes(32)]:
        with pytest.raises(CodecError):
            codec.verify_challenge(PUBLIC_KSC, t, wrong)
    for request in [a['request'] + b'x', b'', a['request'][::-1]]:
        with pytest.raises(CodecError):
            codec.request_proof(PUBLIC_KCS, t, mc, request)
    for proof in [bytes(32), mc]:
        with pytest.raises(CodecError):
            codec.verify_request(PUBLIC_KCS, t, mc, a['request'], proof)
        with pytest.raises(CodecError):
            codec.verify_response(PUBLIC_KSC, t, mr, STATUS, b'PUBLIC response', proof)
    with pytest.raises(CodecError):
        codec.verify_request(PUBLIC_KCS, t, bytes(32), a['request'], mr)
    with pytest.raises(CodecError):
        codec.verify_response(PUBLIC_KSC, t, bytes(32), STATUS, b'PUBLIC response', mp)
    for status, response in [(0, b'PUBLIC response'), (STATUS, b'changed')]:
        with pytest.raises(CodecError):
            codec.verify_response(PUBLIC_KSC, t, mr, status, response, mp)


def test_untrusted_bytes_are_bounded_canonical_and_never_authority(monkeypatch, caplog, capsys):
    from hermes_cli import trusted_inbound_darwin_transcript as codec
    a = inputs()
    t, mc, mr, mp = vector()
    for name in ['request_id', 'client_nonce', 'server_nonce', 'connection_id']:
        for bad in [b'x' * 31, b'x' * 33, 'ab' * 32, bytearray(32), None]:
            with pytest.raises(CodecError):
                codec.encode_transcript(**(a | {name: bad}))
    for name in ['registry_binding', 'source_binding']:
        for bad in [b'', b'x' * 65537, None, 'PRIVATE-SENTINEL']:
            with pytest.raises(CodecError):
                codec.encode_transcript(**(a | {name: bad}))
    for op in ['', 'ADMIT_NATIVE', 'admit_native\x00', 'é', '\ud800', 'x' * 65537]:
        with pytest.raises(CodecError):
            codec.encode_transcript(**(a | {'operation': op}))
    for allowed in [frozenset(), {'admit_native'}, 'admit_native', None,
                    frozenset({'admit_native', 1})]:
        with pytest.raises(CodecError):
            codec.encode_transcript(**(a | {'allowed_operations': allowed}))
    assert codec.encode_transcript(**a, channel='public-channel',
        allowed_channels=frozenset({'public-channel'})) == t
    for kwargs in [dict(channel='unknown', allowed_channels=frozenset({'public-channel'})),
                   dict(channel='public-channel'), dict(allowed_channels=frozenset({'public-channel'}))]:
        with pytest.raises(CodecError):
            codec.encode_transcript(**a, **kwargs)
    # B/S are opaque: success is bytes only, never an enrolled/native object.
    assert type(codec.encode_transcript(**(a | {'registry_binding': b'unknown'}))) is bytes
    for bad in [t[:i] for i in range(len(t))] + [t + b'\0', t + pack(b'extra'),
            t.replace(b'BHDF1/transcript', b'BHDF1/TRANSCRIPT'), b'\xff' * 4 + t[4:],
            t[:4][::-1] + t[4:], b'x' * 65537, bytearray(t), None]:
        with pytest.raises(CodecError, match='^invalid_request$'):
            codec.challenge_proof(PUBLIC_KSC, bad)
    # Same-width swapped fields are syntactically valid but cannot keep the MAC.
    swapped = t.replace(b'c' * 32, b'!' * 32).replace(b's' * 32, b'c' * 32).replace(b'!' * 32, b's' * 32)
    with pytest.raises(CodecError):
        codec.verify_challenge(PUBLIC_KSC, swapped, mc)
    for bad in [-1, 2**64, True, 1.0, None]:
        with pytest.raises(CodecError):
            codec.response_proof(PUBLIC_KSC, t, mr, bad, b'')
    for bad in [b'', b'x' * 31, b'x' * 33, bytearray(32), None]:
        with pytest.raises(CodecError):
            codec.challenge_proof(bad, t)
        with pytest.raises(CodecError):
            codec.verify_challenge(PUBLIC_KSC, t, bad)
        with pytest.raises(CodecError):
            codec.request_proof(PUBLIC_KCS, t, bad, a['request'])
        with pytest.raises(CodecError):
            codec.response_proof(PUBLIC_KSC, t, bad, 0, b'')
    for payload in [b'x' * 65537, bytearray(b'x'), None]:
        with pytest.raises(CodecError):
            codec.encode_transcript(**(a | {'request': payload}))
        with pytest.raises(CodecError):
            codec.response_proof(PUBLIC_KSC, t, mr, 0, payload)
    codec.encode_transcript(**(a | {'request': b''}))
    with pytest.raises(CodecError):
        codec.encode_transcript(**(a | {'registry_binding': b'x' * 32768,
                                       'source_binding': b'y' * 32768}))
    large_request = b'x' * 65536
    large_t = codec.encode_transcript(**(a | {'request': large_request}))
    with pytest.raises(CodecError):
        codec.request_proof(PUBLIC_KCS, large_t, mc, large_request)
    # Aggregate cap includes all LP headers, domain, transcript and proof.
    overhead = len(pack(b'BHDF1/response', t, mr, struct.pack('>Q', 0), b''))
    codec.response_proof(PUBLIC_KSC, t, mr, 0, b'x' * (65536 - overhead))
    with pytest.raises(CodecError):
        codec.response_proof(PUBLIC_KSC, t, mr, 0, b'x' * (65537 - overhead))
    real_compare = hmac.compare_digest
    calls = []
    monkeypatch.setattr(hmac, 'compare_digest', lambda x, y: calls.append((x, y)) or real_compare(x, y))
    codec.verify_challenge(PUBLIC_KSC, t, mc)
    codec.verify_request(PUBLIC_KCS, t, mc, a['request'], mr)
    codec.verify_response(PUBLIC_KSC, t, mr, STATUS, b'PUBLIC response', mp)
    assert (mc, mc) in calls and (mr, mr) in calls and (mp, mp) in calls
    assert not caplog.records
    assert capsys.readouterr() == ('', '')
