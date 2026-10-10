"""Protected issuer contract; Linux tests exercise kernel peer credentials."""
import os
import time
from dataclasses import replace

import pytest

from hermes_cli.trusted_inbound_broker import TrustedInboundBrokerClient
from hermes_cli.trusted_inbound_supervisor import DeliveryBinding, ProtectedInboundSupervisor
from hermes_cli.trusted_inbound_wire import BHI1Response, decode_request


def binding(**changes):
    value = DeliveryBinding('attempt', 'delivery', 'gateway', 'profile', 'session',
                            'native', 'owner', 'route', 'fingerprint', 'boot', 'origin',
                            'a' * 64, os.getuid() + 1, os.getpid())
    return replace(value, **changes)


class Source:
    def __init__(self, value):
        self.value = value
        self.claimed = False
        self.current = True

    def claim(self, delivery_id):
        if self.claimed or delivery_id != self.value.delivery_id:
            return None
        self.claimed = True
        return self.value

    def is_current(self, value):
        return self.current and value == self.value


class IssuerTransport:
    def __init__(self):
        self.requests = []
        self.expiry = int(time.time() * 1000) + 60_000
        self.after = lambda: None

    def exchange(self, frame):
        request = decode_request(frame)
        self.requests.append(request)
        assert request.kind == 1
        self.after()
        return BHI1Response(0x81, request.request_id, 1, 'enrolled', 'enrollment',
                            'candidate', 'test-capability', None, None, None, None, None,
                            self.expiry, b'')


def supervisor(value):
    source, transport = Source(value), IssuerTransport()
    service = ProtectedInboundSupervisor(source=source, issuer_uid=os.getuid(),
                                         host_uid=value.holder_uid, host_pid=value.holder_pid,
                                         transport=transport)
    return service, source, transport


@pytest.mark.platforms('posix')
def test_issuer_claims_once_and_only_sends_enroll():
    value = binding()
    service, _, transport = supervisor(value)
    grant = service.issue(value)
    assert grant.delivery_id == value.delivery_id
    assert grant.enrollment_id == 'enrollment'
    assert service.issue(value) is None
    assert [r.kind for r in transport.requests] == [1]
    assert transport.requests[0].fields == (
        value.enrollment_attempt_id, value.delivery_id, value.surface, value.profile_home_key,
        value.session_key, value.native_session_id, value.host_owner_id, value.route_epoch,
        value.route_fingerprint, value.host_boot_epoch, value.origin_epoch)


@pytest.mark.parametrize('field', ['delivery_id', 'surface', 'profile_home_key', 'session_key',
                                 'native_session_id', 'host_owner_id', 'route_epoch',
                                 'route_fingerprint', 'host_boot_epoch', 'origin_epoch',
                                 'payload_sha256', 'enrollment_attempt_id'])
@pytest.mark.platforms('posix')
def test_changed_binding_cannot_issue(field):
    value = binding()
    service, _, transport = supervisor(value)
    replacement = 'b' * 64 if field == 'payload_sha256' else 'changed'
    assert service.issue(replace(value, **{field: replacement})) is None
    assert transport.requests == []


@pytest.mark.platforms('posix')
def test_expired_or_revoked_during_enroll_is_not_delivered():
    value = binding()
    service, source, transport = supervisor(value)
    transport.after = lambda: setattr(source, 'current', False)
    assert service.issue(value) is None
    service, _, transport = supervisor(value)
    transport.expiry = 1
    assert service.issue(value) is None


@pytest.mark.platforms('posix')
def test_same_uid_configuration_is_rejected():
    value = binding(holder_uid=os.getuid())
    with pytest.raises(ValueError):
        supervisor(value)


def test_legacy_host_cannot_enroll():
    client = TrustedInboundBrokerClient()
    transport = IssuerTransport()
    client.issuer_transport = transport
    assert client.enroll_pre_model(queue=None) is None
    assert transport.requests == []


@pytest.mark.platforms('linux')
@pytest.mark.skipif(getattr(os, "getuid", lambda: -1)() != 0, reason='isolated root container required to drop to three UIDs')
def test_real_linux_issuer_host_model_uid_boundary():
    import subprocess
    import sys

    command = "import runpy; runpy.run_path('tests/hermes_cli/test_trusted_inbound_supervisor.py')['_linux_uid_fixture']()"
    result = subprocess.run([sys.executable, '-c', command], capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'LINUX-UID-EVIDENCE' in result.stdout
    print(result.stdout)


def _linux_uid_fixture():
    import json
    import socket
    from pathlib import Path

    from gateway.native_plugin_queue import NativePluginQueue
    from hermes_cli.trusted_inbound_grant_ipc import PreModelGrantReceiver, PreModelGrantServer

    # pytest's parent directory is private; use an independent temporary test root.
    import tempfile
    import shutil
    root = Path(tempfile.mkdtemp(prefix='hermes-uid-fixture-', dir='/dev/shm'))
    root.chmod(0o755)
    issuer_dir, host_dir = root / 'issuer', root / 'host'
    issuer_dir.mkdir(mode=0o755)
    host_dir.mkdir(mode=0o700)
    os.chown(issuer_dir, 10001, 10001)
    os.chown(host_dir, 10002, 10002)
    path = issuer_dir / 'grant.sock'
    start_read, start_write = os.pipe()
    result_read, result_write = os.pipe()
    ready_read, ready_write = os.pipe()
    children = []

    def drop(uid):
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    def denied_connection(expected_pid):
        import hashlib
        from dataclasses import asdict
        from hermes_cli.trusted_inbound_grant_ipc import _send

        expected = binding(holder_uid=10002, holder_pid=expected_pid,
                           payload_sha256=hashlib.sha256(b'payload').hexdigest())
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(3)
            conn.connect(str(path))
            try:
                _send(conn, asdict(expected))
                return conn.recv(1) == b''
            except (ConnectionResetError, BrokenPipeError):
                return True

    host_pid = os.fork()
    if host_pid == 0:
        try:
            drop(10002)
            assert os.read(start_read, 1) == b'1'
            # Model subprocess under the SAME UID still cannot receive a grant.
            model_pid = os.fork()
            if model_pid == 0:
                os._exit(0 if denied_connection(os.getppid()) else 2)
            assert os.waitpid(model_pid, 0)[1] == 0
            value = binding(holder_uid=10002, holder_pid=os.getpid())
            queue = NativePluginQueue(host_dir)
            value = replace(value, payload_sha256=queue.payload_digest('payload'))

            class HostTransport:
                def exchange(self, frame):
                    assert os.getuid() == 10002
                    request = decode_request(frame)
                    if request.kind == 4:
                        return None
                    assert request.kind == 2
                    return BHI1Response(0x82, request.request_id, 1, 'queued', None, None,
                                        None, 'candidate', None, None, None, None, -1, b'')

            broker = TrustedInboundBrokerClient()
            broker.transport = HostTransport()
            receiver = PreModelGrantReceiver(path, issuer_uid=10001, host_uid=10002,
                                            host_pid=os.getpid(), broker=broker, queue=queue,
                                            current_binding=lambda: value)
            forged = PreModelGrantReceiver(path, issuer_uid=10004, host_uid=10002,
                                            host_pid=os.getpid(), broker=broker, queue=queue,
                                            current_binding=lambda: value)
            assert forged.receive(value) is None
            assert receiver.receive(value) is not None
            assert receiver.receive(value) is None
            receiver.close_before_model()
            assert receiver.receive(replace(value, delivery_id='second')) is None
            row = queue.admit(profile='profile', epoch='route', delivery='delivery',
                              session_key='session', native_id='native', owner='owner',
                              plugin='bee', content='payload')
            assert row['candidate'] == 'candidate' and row['enrollment_id'] == 'enrollment'
            assert row['state'] == 'unknown'
            assert queue.transition('candidate', 'queued', 'running')
            row = queue.lookup('profile', 'route', 'delivery')
            event = queue.settle(row)
            assert event and queue.settle(row) is None
            assert broker.query_native_event(__import__(
                'hermes_cli.trusted_inbound_broker', fromlist=['NativeCandidateSnapshot']
            ).NativeCandidateSnapshot.from_running_row(
                queue.lookup('profile', 'route', 'delivery'), surface='gateway', content='payload'
            )).state == 'unknown'
            os.write(result_write, json.dumps({'host_uid': os.getuid(), 'host_pid': os.getpid(),
                                              'model_pid': model_pid, 'replay': 'denied',
                                              'closed_receiver': 'denied', 'cas': 'one event'}).encode())
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    children.append(host_pid)
    issuer_pid = os.fork()
    if issuer_pid == 0:
        try:
            drop(10001)
            value = binding(holder_uid=10002, holder_pid=host_pid)
            import hashlib
            value = replace(value, payload_sha256=hashlib.sha256(b'payload').hexdigest())
            service, _, transport = supervisor(value)
            with PreModelGrantServer(path, supervisor=service, timeout=10) as server:
                os.write(ready_write, b'1')
                assert server.serve_once() is False  # model UID
                assert server.serve_once() is False  # same UID, wrong PID
                assert server.serve_once() is False  # host rejects unpinned issuer
                assert server.serve_once() is True   # exact host
            assert [r.kind for r in transport.requests] == [1]
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    children.append(issuer_pid)
    try:
        import select
        assert select.select([ready_read], [], [], 10)[0]
        assert os.read(ready_read, 1) == b'1'
        attacker_pid = os.fork()
        if attacker_pid == 0:
            drop(10003)
            os._exit(0 if denied_connection(host_pid) else 2)
        assert os.waitpid(attacker_pid, 0)[1] == 0
        os.write(start_write, b'1')
        assert select.select([result_read], [], [], 15)[0]
        result = json.loads(os.read(result_read, 4096))
        assert result['host_uid'] == 10002 and result['host_pid'] == host_pid
        print('LINUX-UID-EVIDENCE', json.dumps(result), 'issuer_uid=10001 model_uid=10003')
        for pid in children:
            assert os.waitpid(pid, 0)[1] == 0
        children.clear()
    finally:
        for pid in children:
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass
        for fd in (start_read, start_write, result_read, result_write, ready_read, ready_write):
            os.close(fd)
        shutil.rmtree(root)


def test_route_revoked_while_queueing_never_installs(tmp_path):
    from gateway.native_plugin_queue import NativePluginQueue
    from hermes_cli.trusted_inbound_broker import PreModelBrokerGrant

    current = True
    queue = NativePluginQueue(tmp_path)
    grant = PreModelBrokerGrant('delivery', 'gateway', 'profile', 'session', 'native',
                                'owner', 'route', 'a' * 64, 'enrollment', 'candidate',
                                'test-capability', int(time.time() * 1000) + 60_000)

    class RevokingBroker:
        def exchange(self, frame):
            nonlocal current
            current = False
            request = decode_request(frame)
            return BHI1Response(0x82, request.request_id, 1, 'queued', None, None, None,
                                'candidate', None, None, None, None, -1, b'')

    client = TrustedInboundBrokerClient()
    client.transport = RevokingBroker()
    assert client.queue_pre_model(queue=queue, grant=grant, still_current=lambda: current) is None
    row = queue.admit(profile='profile', epoch='route', delivery='delivery', session_key='session',
                      native_id='native', owner='owner', plugin='bee', content='payload')
    assert row['enrollment_id'] is None and row['candidate'] != 'candidate'


@pytest.mark.parametrize('body', [b'{"grant":1,"grant":2}', b'null extra', b'{}x'])
def test_grant_frames_reject_ambiguous_payload(body):
    import socket
    import struct
    from hermes_cli.trusted_inbound_grant_ipc import _receive

    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack('>I', len(body)) + body)
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(ValueError):
            _receive(right)
