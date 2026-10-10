"""Real Darwin sockets and exact no-policy F image; no simulated successful syscall."""
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import signal
import socket
import struct
import tempfile
import time


def spawn_final(image, directory):
    bootstrap, child3 = socket.socketpair()
    transport, child4 = socket.socketpair()
    root = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    root.bind(str(Path(directory) / "direct.sock"))
    sources = [fcntl.fcntl(item.fileno(), fcntl.F_DUPFD_CLOEXEC, 64) for item in (child3, child4, root)]
    opened = []
    for name in os.listdir("/dev/fd"):
        descriptor = int(name)
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError:
            continue
        if descriptor > 2 and descriptor not in sources:
            opened.append(descriptor)
    actions = [(os.POSIX_SPAWN_CLOSE, fd) for fd in opened]
    actions += [(os.POSIX_SPAWN_DUP2, source, destination) for source, destination in zip(sources, (3, 4, 6))]
    actions += [(os.POSIX_SPAWN_CLOSE, fd) for fd in sources]
    signals = set(signal.valid_signals()) - {signal.SIGKILL, signal.SIGSTOP}
    pid = os.posix_spawn(str(image), [str(image)], {}, file_actions=actions, setsigmask=signals, setsigdef=signals)
    for fd in sources:
        os.close(fd)
    child3.close()
    child4.close()
    root.close()
    bootstrap.settimeout(3)
    transport.settimeout(3)
    print("DIRECT_F_SETUP", pid, "fds=0,1,2,3,4,6 mask=all_blockable defaults=all_resettable bound=AF_UNIX", flush=True)
    assert transport.recv(1) == b"F", "F entry proof missing: not provider denial"
    return pid, bootstrap, transport


def reap(pid):
    until = time.monotonic() + 3
    while time.monotonic() < until:
        result, status = os.waitpid(pid, os.WNOHANG)
        if result == pid:
            assert os.WIFEXITED(status), status
            return os.WEXITSTATUS(status)
        time.sleep(0.005)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    raise AssertionError("direct F exceeded deadline")


def read_all(channel):
    output = b""
    while True:
        part = channel.recv(4096)
        if not part:
            return output
        output += part


def frame(nonce, incarnation, key, mutation=None):
    wire = struct.pack(">IIQ", 1, 1, 1) + nonce + incarnation + struct.pack(">Q", 7) + hashlib.sha256(b"inventory fixture").digest()
    if mutation is not None:
        offset, replacement = mutation
        wire = wire[:offset] + replacement + wire[offset + len(replacement):]
    return wire + hmac.new(key, wire, hashlib.sha256).digest()


def final_cases(image, nonce, incarnation, key, unavailable=False):
    cases = {"unavailable": None} if unavailable else {
        "complete": None, "early_eof": None, "partial": None, "extra": None, "timeout": None,
        "mac": None, "version": (0, b"\x00\x00\x00\x02"),
        "type": (4, b"\x00\x00\x00\x02"), "sequence": (8, b"\x00" * 8),
        "nonce": (16, b"\x00" * 32), "incarnation": (48, b"\x00" * 32),
        "generation": (80, b"\x00" * 8), "inventory": (88, b"\x00" * 32),
    }
    for name, mutation in cases.items():
        with tempfile.TemporaryDirectory(prefix="a2c3-f-", dir="/private/tmp") as directory:
            pid, bootstrap, transport = spawn_final(image, directory)
            try:
                wire = frame(nonce, incarnation, key, mutation)
                payload = wire
                if name == "mac":
                    payload = wire[:-1] + bytes([wire[-1] ^ 1])
                if name == "partial":
                    payload = wire[:31]
                if name == "early_eof":
                    payload = b""
                if name == "extra":
                    payload = wire + b"!"
                if name not in ("timeout", "unavailable"):
                    bootstrap.sendall(payload)
                    bootstrap.shutdown(socket.SHUT_WR)
                receipt = read_all(transport)
                if name == "complete":
                    assert receipt == b"R" + hashlib.sha256(wire).digest(), receipt
                    transport.sendall(b"X")
                    expected = 0
                else:
                    assert receipt == b"", receipt
                    expected = 54 if unavailable else 55
                status = reap(pid)
                pid = None
                assert status == expected, (name, status)
                print("DIRECT_F_CASE", name, "ENTRY_F=1 RECEIPT", receipt.hex(), "EXIT", status, flush=True)
            finally:
                bootstrap.close()
                transport.close()
                if pid is not None:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
