#!/usr/bin/env python3
"""Source mechanics only: frozen-image native process and independent wire oracles."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

import test_a2c_phase2 as phase2
from test_a2c_phase3_red import assert_phase3_observations, compile_image

ROOT, NATIVE, TESTS = phase2.ROOT, phase2.NATIVE, phase2.TESTS
COMMON = [NATIVE / name for name in ("a2c_policy.c", "launch_authority.c", "fd_inventory.c",
                                   "release_manifest.c", "stage0.c")]
CONTROL = NATIVE / "launch_control.c"
POLICY = NATIVE / "a2c_phase3_policy.c"
JOURNAL = NATIVE / "a2c_phase3_journal.c"
IO = NATIVE / "a2c_phase3_io.c"
FIXTURE = TESTS / "test_a2c_phase3_audit.c"
BUNDLE = b"bee.phase3.disposable.source"
NONCE, INCARNATION = hashlib.sha256(b"phase3 nonce").digest(), hashlib.sha256(b"phase3 incarnation").digest()
# Nonsecret MAC exercise material, never an installed credential; do not print bytes.
EXERCISE_KEY = hashlib.sha256(b"phase3 nonsecret fixture exercise").digest()


def field(value):
    return struct.pack(">I", len(value)) + value


def initializer(value):
    return "{" + ",".join(str(byte) for byte in value) + "}"


def freeze(path):
    value = hashlib.sha256(path.read_bytes()).hexdigest()
    print("ARTIFACT_SHA256", str(path), value, flush=True)
    return bytes.fromhex(value)


def build_fixture(build, receipt_fault=None):
    core = build / "core.c"
    core.write_text('#include "a2c_phase3_policy.h"\n'
                    'static const struct bh_a2c_phase3_core core = {'
                    '.version=2,.epoch=0x41324331U,.generation=7,'
                    f'.nonce={initializer(NONCE)},.incarnation={initializer(INCARNATION)},'
                    f'.exercise_key={initializer(EXERCISE_KEY)},.bundle="{BUNDLE.decode()}"' + '};\n'
                    'const struct bh_a2c_phase3_core *bh_a2c_phase3_core(void) { return &core; }\n')
    freeze(core)
    probe, final, stage = (build / name for name in ("probe", "final", "stage0"))
    compile_image([TESTS / "test_a2c_phase3_probe.c", "-o", probe])
    if receipt_fault is None:
        compile_image(["-I", NATIVE, "-DBH_A2C_PHASE3_FINAL",
                       TESTS / "test_a2c_phase3_final_observer.c", POLICY, core, *COMMON, "-o", final])
    else:
        control_object = build / "control.o"
        compile_image(["-c", CONTROL, "-o", control_object])
        compile_image(["-I", NATIVE, "-DBH_A2C_PHASE3", f"-DBH_A2C_RECEIPT_FAULT={receipt_fault}",
                       TESTS / "test_a2c_phase3_final_fault.c", POLICY, IO, control_object, core,
                       *COMMON, "-o", final])
    final_digest = freeze(final)
    compile_image(["-DBH_A2C_TEST_DROP", f'-DBH_A2C_FINAL_IMAGE="{final}"',
                   NATIVE / "stage0_entry.c", FIXTURE, CONTROL, *COMMON, "-o", stage])
    stage_digest = freeze(stage)
    release = hashlib.sha256(field(b"bee.a2c.phase3.release.v1") + field(str(stage).encode()) + stage_digest
                             + field(str(final).encode()) + final_digest + field(BUNDLE)).digest()
    manifest = build / "manifest.c"
    manifest.write_text('#include "a2c_phase3_policy.h"\n'
                        'static const struct bh_a2c_phase3_manifest manifest = {'
                        f'.leaf="broker.sock",.stage={json.dumps(str(stage))},.final={json.dumps(str(final))},'
                        f'.release={initializer(release)},.stage_digest={initializer(stage_digest)},'
                        f'.final_digest={initializer(final_digest)}' + '};\n'
                        'const struct bh_a2c_phase3_manifest *bh_a2c_phase3_manifest(void) { return &manifest; }\n')
    freeze(manifest)
    curator = build / "curator"
    compile_image(["-I", NATIVE, TESTS / "test_a2c_phase3_curator.c", core, manifest,
                   JOURNAL, POLICY, *COMMON, "-o", curator])
    return dict(build=build, core=core, manifest=manifest, probe=probe, final=final, stage=stage,
                curator=curator, release=release, stage_digest=stage_digest, final_digest=final_digest)


def build_attempt(fixture, suffix, flags=(), parent_flags=()):
    attempt, parent = (fixture["build"] / (name + suffix) for name in ("attempt-", "parent-"))
    extra = ["-I", NATIVE, fixture["core"], fixture["manifest"], JOURNAL, POLICY]
    compile_image(["-DBH_A2C_PHASE3", "-DBH_A2C_TEST_AUDIT", "-DBH_A2C_TEST_SEND_CHUNK=17", *flags,
                   f'-DBH_A2C_STAGE0_IMAGE="{fixture["stage"]}"', NATIVE / "attempt_entry.c",
                   FIXTURE, CONTROL, IO, *extra, *COMMON, NATIVE / "socket_lineage.c",
                   ROOT / "native/trusted_inbound/darwin/socket_observer.c", "-o", attempt])
    compile_image([*parent_flags, f'-DBH_A2C_ATTEMPT_IMAGE="{attempt}"',
                   TESTS / "test_a2c_phase3_parent.c", CONTROL, *extra, *COMMON, "-o", parent])
    freeze(attempt)
    freeze(parent)
    return attempt, parent


def journal_bytes(fixture, directory, state):
    info = os.stat(directory)
    payload = (struct.pack(">IBIQ", 2, state, 0x41324331, 7) + NONCE + INCARNATION
               + hashlib.sha256(EXERCISE_KEY).digest() + struct.pack(">QQ", info.st_dev, info.st_ino)
               + field(b"broker.sock") + fixture["release"] + field(str(fixture["stage"]).encode())
               + fixture["stage_digest"] + field(str(fixture["final"]).encode()) + fixture["final_digest"]
               + field(BUNDLE))
    return payload + hashlib.sha256(field(b"bee.a2c.phase3.journal.v2") + payload).digest()


def seed(fixture, directory):
    result = subprocess.run([str(fixture["curator"]), directory], capture_output=True, timeout=2, check=False)
    assert result.returncode == 0, result
    actual = (Path(directory) / "attempt.journal").read_bytes()
    assert actual == journal_bytes(fixture, directory, 0), "independent canonical FRESH mismatch"
    print("FRESH", actual.hex(), "SHA256", hashlib.sha256(actual).hexdigest(), flush=True)


def main():
    if sys.platform != "darwin" or shutil.disk_usage(ROOT).free < 20 * 1024**3 + 64 * 1024**2:
        raise RuntimeError("UNAVAILABLE runtime/disk gate")
    with tempfile.TemporaryDirectory(prefix="bee-a2c3-") as temporary:
        fixture = build_fixture(Path(temporary).resolve())
        _, parent = build_attempt(fixture, "normal")
        run_case(fixture, parent)
        from test_a2c_phase3_sockets import final_cases
        final_cases(fixture["final"], NONCE, INCARNATION, EXERCISE_KEY)
        journal_cases(fixture, parent)
        for name, flags in [("receipt_inert", ["-DBH_A2C_TEST_PARK_RECEIPT"]),
                            ("sim_eagain", ["-DBH_A2C_TEST_ERRNO=EAGAIN"]),
                            ("sim_eintr", ["-DBH_A2C_TEST_ERRNO=EINTR"]),
                            ("loss_preframe", ["-DBH_A2C_TEST_PARK_PREFRAME"]),
                            ("loss_152", ["-DBH_A2C_TEST_PARK_WRITE=152"]),
                            ("report_loss3", []), ("full_audit", []), ("closed_audit", []), ("a_death", []),
                            ("loss_halfclose", ["-DBH_A2C_TEST_PARK_HALF_CLOSE"]),
                            ("journal_replaced", ["-DBH_A2C_TEST_PARK_PREFRAME"]),
                            ("unknown_fd", ["-DBH_A2C_TEST_LEAK_PARENT"]),
                            ("reserved_management", ["-DBH_A2C_TEST_BAD_SOURCE"]),
                            ("collision", ["-DBH_A2C_TEST_COLLISION"]),
                            ("child_stop", []), ("uncertain_reap", ["-DBH_A2C_TEST_AUTO_REAP"])]:
            _, selected = build_attempt(fixture, name, flags)
            run_case(fixture, selected, name, reject=name in ("report_loss3", "a_death", "journal_replaced", "unknown_fd", "reserved_management", "collision", "child_stop", "uncertain_reap"))
        for boundary in range(17, 152, 17):
            name = f"loss_{boundary}"
            _, selected = build_attempt(fixture, name, [f"-DBH_A2C_TEST_PARK_WRITE={boundary}"])
            run_case(fixture, selected, name)
        _, failed_readback = build_attempt(fixture, "readback", parent_flags=["-DBH_A2C_TEST_READBACK_FAIL"])
        journal_readback_case(fixture, failed_readback)
        if "--cmake-dir" in sys.argv:
            cmake_dir = Path(sys.argv[sys.argv.index("--cmake-dir") + 1]).resolve()
            no_policy_cases(fixture, cmake_dir)
        for fault in range(1, 9):
            fault_dir = fixture["build"] / f"receipt-{fault}"
            fault_dir.mkdir()
            adversary = build_fixture(fault_dir, fault)
            _, selected = build_attempt(adversary, f"receipt-{fault}")
            run_case(adversary, selected, f"receipt-{fault}", reject=fault != 7)
            if fault == 7:
                run_case(adversary, selected, "loss_receipt")
    print("PHASE3 source_mechanics_only PASS cleanup_disposable_build_removed", flush=True)

def wait_park(observer, attempt):
    until = time.monotonic() + 0.5
    while time.monotonic() < until:
        info = phase2.probe(observer, attempt)
        if info and info["status"] == 4:
            return
        time.sleep(0.005)
    raise AssertionError("A did not reach requested park")


def handle_phase3_line(line, process, stage, final, observer, mode, reject, parked,
                       attempt, child, parent_killed, records, snapshots, failures, journal, directory):
    if line.startswith("AUDIT RECEIPT_PARK "):
        wait_park(observer, attempt)
        final_info = phase2.probe(observer, child)
        assert final_info and final_info["fds"] == [0, 1, 2, 3, 4, 6] and final_info["listening"] == 0
        records.append("HARNESS F_AFTER_RECEIPT_INERT " + json.dumps(final_info))
        os.kill(attempt, signal.SIGCONT)
    if line.startswith("AUDIT PREFRAME ") and mode == "journal_replaced":
        wait_park(observer, attempt)
        old_inode = journal.stat().st_ino
        replacement = Path(directory) / "replacement"
        replacement.write_bytes(journal.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(journal)
        assert journal.stat().st_ino != old_inode
        records.append("HARNESS JOURNAL_REPLACED SAME_BYTES NEW_INODE")
        os.kill(attempt, signal.SIGCONT)
    elif line.startswith(("AUDIT PREFRAME ", "AUDIT WRITE_PARK ", "AUDIT HALF_CLOSE_PARK ")):
        phase2.kill_parked_parent(process, observer, attempt, records, failures)
        parent_killed = True
    if mode == "loss_receipt" and line.startswith("AUDIT WAIT_EOF "):
        process.kill()
        process.wait(timeout=1)
        records.append("HARNESS P_KILLED_REAPED WAITING_RECEIPT_EOF")
        parent_killed = True
    if mode == "collision" and line.startswith("BARRIER 4 "):
        records.append(line)
        process.stdin.write(b"G")
        process.stdin.flush()
        return attempt, child, parent_killed
    return phase2.handle_line(
        line, process, stage, final, observer, "report_loss" if mode == "report_loss3" else mode, reject, parked, attempt, child,
        parent_killed, records, snapshots, failures)


def verify_phase3_loss(mode, parent_killed, child, records):
    assert parent_killed, "P loss barrier not observed"
    assert f"AUDIT RESULT {child} 0" in records, records
    assert not any(line == f"AUDIT FORWARD {child} 88" for line in records)
    assert any(line.startswith((f"AUDIT REAP {child} ", f"AUDIT REAP_KILLED {child} ")) for line in records)
    positive = [int(line.split()[3]) for line in records if line.startswith("AUDIT WRITE_RETURN ") and int(line.split()[3]) > 0]
    expected_bytes = int(mode.removeprefix("loss_")) if mode.removeprefix("loss_").isdigit() else (152 if mode in ("loss_halfclose", "loss_receipt") else 0)
    assert sum(positive) == expected_bytes, (positive, expected_bytes)
    assert not any(line.startswith("AUDIT RECEIPT_EOF ") for line in records)
    observed = [line for line in records if line.startswith("OBS_F ")]
    if observed:
        fields = dict(item.split("=", 1) for item in observed[0].split()[1:])
        assert int(fields["bytes"]) == expected_bytes
        if expected_bytes < 152:
            assert fields["receipt"] == "46", fields


def verify_positive(mode, snapshots, records, failures):
    assert snapshots[4]["listening"] == 0
    if mode.startswith("sim_"):
        assert any(line.startswith("AUDIT SIMULATED_ERRNO ") for line in records)
    failures.extend(assert_phase3_observations(records))
    writes = [int(line.split()[3]) for line in records if line.startswith("AUDIT WRITE_RETURN ")]
    assert len([n for n in writes if n > 0]) >= 2 and sum(n for n in writes if n > 0) == 152
    for index, line in enumerate(records):
        if line.startswith("AUDIT WRITE_RETURN ") and int(line.split()[3]) > 0:
            assert records[index - 1].startswith("AUDIT WRITE_GUARD ")
            assert records[index + 1].startswith("AUDIT WRITE_CHECKED ")


def audit_pipe(mode):
    reader, writer = os.pipe()
    os.set_blocking(writer, False)
    os.set_blocking(reader, False)
    if mode == "full_audit":
        try:
            while True:
                os.write(writer, b"z" * 4096)
        except BlockingIOError:
            pass
    if mode == "closed_audit":
        os.close(reader)
    return reader, writer


def run_case(fixture, parent, mode="normal", reject=False):
    stage, final, observer = (fixture[name] for name in ("stage", "final", "probe"))
    parked = mode in ("parked", "prespawn")
    phase3_loss = mode.startswith("loss_")
    audit_lost = mode in ("full_audit", "closed_audit")
    with tempfile.TemporaryDirectory(prefix="bee-a2c2-", dir="/private/tmp") as directory:
        journal = Path(directory) / "attempt.journal"
        seed(fixture, directory)
        reader, writer = audit_pipe(mode)
        frozen = phase2.freeze_artifacts(stage, final, mode)
        process = subprocess.Popen([str(parent), directory], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=writer, start_new_session=True)
        os.close(writer)
        selector = selectors.DefaultSelector()
        if not audit_lost:
            selector.register(reader, selectors.EVENT_READ, "audit")
        selector.register(process.stdout, selectors.EVENT_READ, "parent")
        buffers = {"audit": b"", "parent": b""}
        records, snapshots, failures = [], {0: frozen}, []
        attempt = child = None
        parent_killed = False
        rescue = False
        started = time.monotonic()
        try:
            while selector.get_map() and time.monotonic() - started < 5:
                for key, _ in selector.select(0.02):
                    data = os.read(key.fd, 4096)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    tag = key.data
                    buffers[tag] += data
                    while b"\n" in buffers[tag]:
                        line, buffers[tag] = buffers[tag].split(b"\n", 1)
                        line = line.decode()
                        attempt, child, parent_killed = handle_phase3_line(
                            line, process, stage, final, observer, mode, reject, parked,
                            attempt, child, parent_killed, records, snapshots, failures, journal, directory)
            if selector.get_map():
                rescue = True
                failures.append("owned process group exceeded fixed deadline")
                print("FAILURE_BEFORE_CLEANUP", json.dumps(records), flush=True)
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)
            if phase3_loss:
                verify_phase3_loss(mode, parent_killed, child, records)
            elif mode in ("prefinal", "post_x"):
                phase2.verify_late_loss(mode, parent_killed, child, records, failures)
            else:
                phase2.verify_progress(parked, parent_killed, reject, mode, process, child, observer, records,
                                snapshots, audit_lost, failures)
            phase2.verify_digest_negative(mode, records, failures)
            phase2.verify_fault_status(mode, child, attempt, observer, records, audit_lost, failures)
            if journal.read_bytes() != journal_bytes(fixture, directory, 1):
                failures.append("pending latch changed")
            if not (Path(directory) / "broker.sock").exists():
                failures.append("bound leaf was removed")
            retry = subprocess.run([str(parent), directory], capture_output=True, text=True, timeout=2, check=False)
            if retry.returncode != 30:
                failures.append("pending namespace relaunched")
            print("CASE", mode, "P_EXIT", process.returncode,
                  "RESCUE", rescue, "FAILURES", json.dumps(failures), flush=True)
            print("RECORDS", json.dumps(records), "LIVE", json.dumps(snapshots), flush=True)
            if not reject and mode in ("normal", "sim_eagain", "sim_eintr", "receipt_inert"):
                verify_positive(mode, snapshots, records, failures)
            assert not failures, failures
            return records
        except BaseException:
            print("FAILURE_BEFORE_CLEANUP", json.dumps(records), flush=True)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1)
            raise
        finally:
            saved = final.with_suffix(".saved")
            if saved.exists():
                saved.replace(final)
            selector.close()
            if mode != "closed_audit":
                os.close(reader)
            process.stdin.close()
            process.stdout.close()


def symlink_journal(journal):
    target = journal.with_name("other")
    journal.rename(target)
    journal.symlink_to(target)


def mutate_journal(name, journal):
    metadata = {"absent": lambda: journal.unlink(), "symlink": lambda: symlink_journal(journal),
                "mode": lambda: journal.chmod(0o644), "hardlink": lambda: os.link(journal, journal.with_name("other"))}
    if name in metadata:
        metadata[name]()
        return
    value = bytearray(journal.read_bytes())
    transforms = {"short": lambda data: data[:40], "extra": lambda data: data + b"!"}
    if name in transforms:
        journal.write_bytes(transforms[name](value))
        return
    offset = {"corrupt": 0, "fingerprint": len(value) - 1, "namespace": 113, "release": 144, "image": 180}[name]
    value[offset] ^= 1
    if name in ("namespace", "release", "image"):
        value[-32:] = hashlib.sha256(field(b"bee.a2c.phase3.journal.v2") + value[:-32]).digest()
    journal.write_bytes(value)


def journal_cases(fixture, parent):
    cases = ("absent", "short", "corrupt", "fingerprint", "namespace", "release", "image", "extra", "symlink", "mode", "hardlink", "locked")
    for name in cases:
        with tempfile.TemporaryDirectory(prefix="a2c3-j-", dir="/private/tmp") as directory:
            seed(fixture, directory)
            journal = Path(directory) / "attempt.journal"
            locked = None
            if name == "locked":
                locked = journal.open("rb")
                fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                mutate_journal(name, journal)
            result = subprocess.run([str(parent), directory], capture_output=True, text=True, timeout=3, check=False)
            if locked is not None:
                locked.close()
            assert result.returncode == 30 and result.stdout == "DENIED\n", (name, result)
            assert not (Path(directory) / "broker.sock").exists()
            print("JOURNAL_NEGATIVE", name, "EXIT", result.returncode, "NO_ATTEMPT=1 NO_LEAF=1", flush=True)


def journal_readback_case(fixture, parent):
    with tempfile.TemporaryDirectory(prefix="a2c3-readback-", dir="/private/tmp") as directory:
        seed(fixture, directory)
        result = subprocess.run([str(parent), directory], capture_output=True, text=True, timeout=3, check=False)
        assert result.returncode == 30 and result.stdout == "DENIED\n"
        assert (Path(directory) / "attempt.journal").read_bytes() == journal_bytes(fixture, directory, 1)
        assert not (Path(directory) / "broker.sock").exists()
        print("JOURNAL_SIMULATED_READBACK_FAILURE EXIT=30 PENDING=1 NO_ATTEMPT=1", flush=True)


def no_policy_cases(fixture, cmake_dir):
    from test_a2c_phase3_sockets import final_cases
    final = cmake_dir / "bee_hermes_a2c_phase3_final"
    attempt = cmake_dir / "bee_hermes_a2c_phase3_attempt"
    freeze(final)
    freeze(attempt)
    final_cases(final, NONCE, INCARNATION, EXERCISE_KEY, unavailable=True)
    parent = fixture["build"] / "parent-unavailable"
    compile_image(["-I", NATIVE, f'-DBH_A2C_ATTEMPT_IMAGE="{attempt}"',
                   TESTS / "test_a2c_phase3_parent.c", CONTROL, fixture["core"], fixture["manifest"],
                   JOURNAL, POLICY, *COMMON, "-o", parent])
    with tempfile.TemporaryDirectory(prefix="a2c3-nopolicy-", dir="/private/tmp") as directory:
        seed(fixture, directory)
        result = subprocess.run([str(parent), directory], capture_output=True, text=True, timeout=3, check=False)
        assert result.returncode == 20 and "TERMINAL reason=106 bound=0 fd6=0 parent=0" in result.stdout, result
        assert "BARRIER" not in result.stdout and not (Path(directory) / "broker.sock").exists()
        assert (Path(directory) / "attempt.journal").read_bytes() == journal_bytes(fixture, directory, 1)
        print("CMAKE_NO_POLICY_A", repr(result.stdout), "EXIT", result.returncode, flush=True)


if __name__ == "__main__":
    main()
