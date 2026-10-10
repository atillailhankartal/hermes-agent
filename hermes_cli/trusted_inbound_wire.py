"""BHI1 fixed-field framing for the isolated Bee/Hermes Unix broker.

The wire codec carries correlation data only. A parsed response is not an
admission decision; the host must independently verify its signed proof.
"""
from __future__ import annotations

import hashlib
import os
import socket
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"BHI1"
MAX_BODY = 65536
MAX_STRING = 16384
REQUEST_FIELDS = {1: ("s",) * 11, 2: ("s", "s", "s", "h"),
                  3: ("s", "s", "s", "s"), 4: ("s", "s", "s", "b")}
RESPONSE_STRINGS = 9


class BHI1ProtocolError(ValueError):
    """Malformed or mismatched BHI1 message."""


@dataclass(frozen=True)
class BHI1Request:
    kind: int
    request_id: bytes
    fields: tuple


@dataclass(frozen=True)
class BHI1Response:
    kind: int
    request_id: bytes
    status: int
    reason: str
    enrollment_id: str | None
    reserved_candidate_id: str | None
    capability: str | None
    candidate_id: str | None
    proof_id: str | None
    issuer_key_id: str | None
    issuer_epoch: str | None
    proof_signature_base64: str | None
    expires_at_unix_ms: int
    proof_canonical: bytes


def _string(value: str | None, *, nullable: bool = False) -> bytes:
    if value is None:
        if nullable:
            return struct.pack(">i", -1)
        raise BHI1ProtocolError("null required string")
    if not isinstance(value, str):
        raise BHI1ProtocolError("non-string field")
    try:
        data = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise BHI1ProtocolError("invalid UTF-8") from exc
    if len(data) > MAX_STRING:
        raise BHI1ProtocolError("oversized string")
    return struct.pack(">i", len(data)) + data


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise BHI1ProtocolError("truncated field")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def integer(self, fmt: str) -> int:
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def string(self, *, nullable: bool = False) -> str | None:
        size = self.integer(">i")
        if size == -1 and nullable:
            return None
        if size < 0 or size > MAX_STRING:
            raise BHI1ProtocolError("invalid string length")
        try:
            return self.take(size).decode("utf-8", "strict")
        except UnicodeError as exc:
            raise BHI1ProtocolError("invalid UTF-8") from exc

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise BHI1ProtocolError("trailing bytes")


def _frame(kind: int, request_id: bytes, fields: bytes) -> bytes:
    if len(request_id) != 32:
        raise BHI1ProtocolError("invalid request ID")
    body = struct.pack(">HBB", 1, kind, 0) + request_id + fields
    if not 36 <= len(body) <= MAX_BODY:
        raise BHI1ProtocolError("invalid body length")
    return MAGIC + struct.pack(">I", len(body)) + body


def _unframe(frame: bytes) -> tuple[int, bytes, _Reader]:
    if len(frame) < 8 or frame[:4] != MAGIC:
        raise BHI1ProtocolError("invalid magic")
    size = struct.unpack(">I", frame[4:8])[0]
    if not 36 <= size <= MAX_BODY or len(frame) != size + 8:
        raise BHI1ProtocolError("invalid frame length")
    reader = _Reader(frame[8:])
    if reader.integer(">H") != 1:
        raise BHI1ProtocolError("unknown version")
    kind = reader.integer(">B")
    if reader.integer(">B") != 0 or (kind & 0x7F) not in REQUEST_FIELDS:
        raise BHI1ProtocolError("unknown kind or flags")
    return kind, reader.take(32), reader


def _request_id(kind: int, fields: tuple) -> bytes:
    if kind == 1:
        delivery, enrollment, native, want = fields[1], fields[0], "", False
    else:
        delivery, enrollment = fields[:2]
        native = fields[3] if kind == 3 else fields[2] if kind == 4 else ""
        want = fields[3] if kind == 4 else False
    material = (b"bee-hermes-ipc-v1\0" + bytes((kind,)) + _string(delivery)
                + _string(enrollment) + _string(native) + bytes((int(want),)))
    return hashlib.sha256(material).digest()


def encode_request(kind: int, *fields) -> bytes:
    schema = REQUEST_FIELDS.get(kind)
    if schema is None or len(fields) != len(schema):
        raise BHI1ProtocolError("invalid request fields")
    encoded = bytearray()
    for field_type, field in zip(schema, fields):
        if field_type == "s":
            encoded.extend(_string(field))
        elif field_type == "h":
            if not isinstance(field, bytes) or len(field) != 32:
                raise BHI1ProtocolError("invalid digest")
            encoded.extend(field)
        elif field_type == "b":
            if type(field) is not bool:
                raise BHI1ProtocolError("invalid bool")
            encoded.append(int(field))
    request_id = _request_id(kind, fields)
    return _frame(kind, request_id, bytes(encoded))


def encode_query_request(delivery_id: str, enrollment_id: str,
                         native_event_id: str, want_proof: bool = True) -> bytes:
    return encode_request(4, delivery_id, enrollment_id, native_event_id, want_proof)


def decode_request(frame: bytes) -> BHI1Request:
    kind, request_id, reader = _unframe(frame)
    if kind & 0x80:
        raise BHI1ProtocolError("response on request channel")
    fields = []
    for field_type in REQUEST_FIELDS[kind]:
        if field_type == "s":
            fields.append(reader.string())
        elif field_type == "h":
            fields.append(reader.take(32))
        else:
            value = reader.integer(">B")
            if value not in (0, 1):
                raise BHI1ProtocolError("invalid bool")
            fields.append(bool(value))
    reader.finish()
    if _request_id(kind, tuple(fields)) != request_id:
        raise BHI1ProtocolError("request ID mismatch")
    return BHI1Request(kind, request_id, tuple(fields))


def decode_response(frame: bytes, request: bytes) -> BHI1Response:
    expected = decode_request(request)
    kind, request_id, reader = _unframe(frame)
    if kind != expected.kind | 0x80 or request_id != expected.request_id:
        raise BHI1ProtocolError("response request mismatch")
    status = reader.integer(">B")
    if status not in range(5):
        raise BHI1ProtocolError("invalid status")
    reason = reader.string()
    if not reason:
        raise BHI1ProtocolError("missing reason")
    optionals = tuple(reader.string(nullable=True) for _ in range(RESPONSE_STRINGS - 1))
    if any(value == "" for value in optionals if value is not None):
        raise BHI1ProtocolError("empty optional field")
    expires_at = reader.integer(">q")
    proof_size = reader.integer(">I")
    if proof_size > MAX_BODY or (proof_size and status != 2):
        raise BHI1ProtocolError("invalid proof length")
    proof = reader.take(proof_size)
    reader.finish()
    if status == 2 and (not proof or any(value is None for value in optionals[3:])):
        raise BHI1ProtocolError("incomplete admitted response")
    if expected.kind != 1 and optionals[2] is not None:
        raise BHI1ProtocolError("capability on data channel")
    return BHI1Response(kind, request_id, status, reason, *optionals, expires_at, proof)


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = conn.recv(size - len(chunks))
        if not chunk:
            raise BHI1ProtocolError("early EOF")
        chunks.extend(chunk)
    return bytes(chunks)


class BHI1UnixClient:
    """One request per Linux AF_UNIX connection, with connected peer UID pinning."""

    def __init__(self, path: str | Path, *, expected_broker_uid: int, timeout: float = 2.0):
        self.path = Path(path)
        self.expected_broker_uid = expected_broker_uid
        self.timeout = timeout

    def exchange(self, request: bytes) -> BHI1Response | None:
        try:
            decode_request(request)
            if sys.platform != "linux" or type(self.expected_broker_uid) is not int:
                return None
            if not stat.S_ISSOCK(os.lstat(self.path).st_mode):
                return None
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(self.timeout)
                conn.connect(str(self.path))
                peer = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                _, uid, _ = struct.unpack("3i", peer)
                if uid != self.expected_broker_uid:
                    return None
                conn.sendall(request)
                conn.shutdown(socket.SHUT_WR)
                header = _recv_exact(conn, 8)
                if header[:4] != MAGIC:
                    return None
                size = struct.unpack(">I", header[4:])[0]
                if not 36 <= size <= MAX_BODY:
                    return None
                response = header + _recv_exact(conn, size)
                if conn.recv(1):
                    return None
                return decode_response(response, request)
        except (OSError, TimeoutError, BHI1ProtocolError):
            return None
