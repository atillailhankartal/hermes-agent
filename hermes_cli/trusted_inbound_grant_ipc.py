"""Linux-only pre-model grant handoff, authenticated in both directions.

SO_PEERCRED pins the connected issuer UID and the exact host UID/PID. No signer
or broad enrollment credential is placed in the host. The deployment must keep
model/tool execution outside this trusted host process and close the receiver
before starting it. This module does not make same-process Python a sandbox.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import struct
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path

from hermes_cli.trusted_inbound_broker import PreModelBrokerGrant
from hermes_cli.trusted_inbound_supervisor import DeliveryBinding, current_uid

_MAX_FRAME = 65536
_MAX_JSON_DEPTH = 8


def _peer(conn):
    if sys.platform != 'linux':
        raise ValueError('Linux peer credentials required')
    pid, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return uid, pid


def _exact(conn, size):
    result = bytearray()
    while len(result) < size:
        part = conn.recv(size - len(result))
        if not part:
            raise ValueError('truncated grant frame')
        result.extend(part)
    return bytes(result)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate grant field')
        result[key] = value
    return result


def _bounded_json(body):
    # Match json.loads' byte decoding so UTF-16/32 cannot bypass the depth limit.
    text = body.decode(json.detect_encoding(body), 'surrogatepass')
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise ValueError('grant JSON nesting limit exceeded')
        elif char in ']}':
            depth -= 1
    return json.loads(text, object_pairs_hook=_unique)


def _receive(conn):
    size = struct.unpack('>I', _exact(conn, 4))[0]
    if not 1 <= size <= _MAX_FRAME:
        raise ValueError('invalid grant frame size')
    value = _bounded_json(_exact(conn, size))
    if conn.recv(1):
        raise ValueError('trailing grant data')
    return value


def _send(conn, value):
    body = json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    if len(body) > _MAX_FRAME:
        raise ValueError('oversized grant')
    conn.sendall(struct.pack('>I', len(body)) + body)
    conn.shutdown(socket.SHUT_WR)


class PreModelGrantServer:
    """Bounded single-request connections; caller owns the service accept loop."""

    def __init__(self, path, *, supervisor, timeout=2.0):
        self.path = Path(path)
        self.supervisor = supervisor
        self.timeout = timeout
        self.listener = None

    def __enter__(self):
        parent = self.path.parent.lstat()
        if (sys.platform != 'linux' or current_uid() != self.supervisor.issuer_uid
                or os.getpid() != self.supervisor.issuer_pid
                or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != self.supervisor.issuer_uid or parent.st_mode & 0o022):
            raise ValueError('protected issuer socket directory required')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))  # Never replace an existing endpoint.
            self._inode = self.path.lstat().st_ino
            self.listener = listener
            self.path.chmod(0o666)  # UID/PID auth, not group membership, grants access.
            listener.listen(8)
            listener.settimeout(self.timeout)
        except BaseException:
            listener.close()
            raise
        return self

    def serve_once(self):
        if self.listener is None:
            raise ValueError('server not started')
        conn, _ = self.listener.accept()
        with conn:
            conn.settimeout(self.timeout)
            try:
                service = self.supervisor
                if _peer(conn) != (service.host_uid, service.host_pid):
                    return False
                request = _receive(conn)
                if type(request) is not dict:
                    return False
                expected = DeliveryBinding(**request)
                grant = service.issue(expected)
                if grant is None:
                    return False
                _send(conn, {'binding': asdict(expected), 'grant': asdict(grant)})
                return True
            except (OSError, ValueError, TypeError):
                return False

    def __exit__(self, *_):
        if self.listener is not None:
            self.listener.close()
            self.listener = None
            try:
                if self.path.lstat().st_ino == self._inode:
                    self.path.unlink()
            except FileNotFoundError:
                pass


class PreModelGrantReceiver:
    """Host lifecycle object. Create before model startup; close irreversibly."""

    def __init__(self, path, *, issuer_uid, host_uid, host_pid, broker, queue, current_binding, timeout=2.0):
        if (type(issuer_uid) is not int or type(host_uid) is not int
                or issuer_uid < 0 or host_uid < 0 or issuer_uid == host_uid
                or type(host_pid) is not int or host_pid <= 0):
            raise ValueError('distinct issuer and host principals required')
        self.path = Path(path)
        self.issuer_uid, self.host_uid, self.host_pid = issuer_uid, host_uid, host_pid
        self.broker, self.queue, self.timeout = broker, queue, timeout
        self.current_binding = current_binding
        self._closed = False
        self._used = set()
        self._lock = threading.Lock()

    def close_before_model(self):
        with self._lock:
            self._closed = True

    def receive(self, expected: DeliveryBinding):
        with self._lock:
            if (self._closed or sys.platform != 'linux'
                    or (current_uid(), os.getpid()) != (self.host_uid, self.host_pid)
                    or type(expected) is not DeliveryBinding or not expected.valid()
                    or (expected.holder_uid, expected.holder_pid) != (self.host_uid, self.host_pid)
                    or self.current_binding() != expected):
                return None
            key = (expected.delivery_id, expected.host_boot_epoch)
            if key in self._used:
                return None
            self._used.add(key)
            try:
                grant = self._exchange(expected)
                if grant is None:
                    return None
                return self.broker.queue_pre_model(
                    queue=self.queue, grant=grant, still_current=lambda: self.current_binding() == expected)
            except (OSError, ValueError, TypeError):
                return None

    def _exchange(self, expected):
        if not stat.S_ISSOCK(self.path.lstat().st_mode):
            return None
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout)
            conn.connect(str(self.path))
            if _peer(conn)[0] != self.issuer_uid:
                return None
            _send(conn, asdict(expected))
            response = _receive(conn)
        if (type(response) is not dict or set(response) != {'binding', 'grant'}
                or response['binding'] != asdict(expected) or type(response['grant']) is not dict):
            return None
        grant = PreModelBrokerGrant(**response['grant'])
        if (type(grant.expires_at_unix_ms) is not int
                or grant.expires_at_unix_ms <= int(time.time() * 1000)
                or not grant.matches(delivery=expected.delivery_id, surface=expected.surface,
                                     profile=expected.profile_home_key, session_key=expected.session_key,
                                     native_id=expected.native_session_id, owner=expected.host_owner_id,
                                     epoch=expected.route_epoch, digest=expected.payload_sha256)):
            return None
        return grant
