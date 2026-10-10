"""Supplemental StartBytes wire contract; no native identity or admission claim."""
import struct

import pytest

from hermes_cli.trusted_inbound_darwin_codec import CodecError
from hermes_cli.trusted_inbound_darwin_start import encode_start_bytes


@pytest.mark.parametrize('sec,usec', [(1, 0), (1, 999999), (2**64 - 1, 999999),
                                     (0x0102030405060708, 256)])
def test_canonical_start_bytes(sec, usec):
    encoded = encode_start_bytes(sec, usec)
    expected = struct.pack('>I21sIQIQ', 21, b'BHDF1/darwin-start/v1', 8, sec, 8, usec)
    assert type(encoded) is bytes
    assert len(encoded) == 49
    assert encoded == expected == encode_start_bytes(sec, usec)
    if (sec, usec) == (1, 999999):
        assert encoded.hex() == (
            '0000001542484446312f64617277696e2d73746172742f7631'
            '0000000800000000000000010000000800000000000f423f'
        )


class IntSubclass(int):
    pass


@pytest.mark.parametrize('value', [True, False, None, 1.0, '1', b'1', [], {},
                                  IntSubclass(1), -1, 2**64, 2**100])
@pytest.mark.parametrize('field', ['sec', 'usec'])
def test_reject_noncanonical_values(value, field):
    pair = {'sec': 1, 'usec': 0}
    pair[field] = value
    with pytest.raises(CodecError, match='^invalid_request$'):
        encode_start_bytes(**pair)


@pytest.mark.parametrize('sec,usec', [(0, 0), (1, 1000000), (1, 2**64 - 1)])
def test_reject_outside_start_time_domain(sec, usec):
    with pytest.raises(CodecError, match='^invalid_request$'):
        encode_start_bytes(sec, usec)
