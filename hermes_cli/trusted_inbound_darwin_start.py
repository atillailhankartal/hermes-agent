"""Pure supplemental Darwin StartBytes encoding, without process inspection.

A start tuple is neither unique incarnation evidence nor approved-executable
attestation: exec can preserve it. Encoding does not grant native admission.
"""
from hermes_cli.trusted_inbound_darwin_codec import _encode, _integer, _u64


def encode_start_bytes(sec: int, usec: int) -> bytes:
    """Encode caller-supplied UInt64 seconds and microseconds as 49 bytes.

    Seconds must be positive and microseconds in 0..999999. This checks the
    numeric domain only, not calendar plausibility, provenance or freshness.
    """
    seconds = _integer(sec, 1, 2**64 - 1)
    microseconds = _integer(usec, 0, 999999)
    return _encode(b'BHDF1/darwin-start/v1', _u64(seconds), _u64(microseconds))
