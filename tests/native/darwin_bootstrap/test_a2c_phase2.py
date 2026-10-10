#!/usr/bin/env python3
"""Actual P→A→S→exec(F), source only; external live libproc and reap oracles."""
from pathlib import Path
import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / "native/darwin_bootstrap"
TESTS = Path(__file__).resolve().parent
CC = ["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]


def compile_image(arguments):
    result = subprocess.run(CC + list(map(str, arguments)), capture_output=True, text=True, timeout=30, check=False)
    print("COMPILE", " ".join(map(str, arguments)), "EXIT", result.returncode, flush=True)
    if result.returncode or result.stderr:
        raise RuntimeError(result.stdout + result.stderr)


def probe(binary, pid):
    result = subprocess.run([str(binary), str(pid)], capture_output=True, text=True, timeout=1, check=False)
    return json.loads(result.stdout) if result.returncode == 0 else None


def kill_parked_parent(process, observer, attempt, records, failures):
    until = time.monotonic() + 0.5
    info = None
    while time.monotonic() < until:
        info = probe(observer, attempt)
        if info and info["status"] == 4:
            break
        time.sleep(0.005)
    if not info or info["status"] != 4:
        failures.append("A was not parked after exact ownership")
    process.kill()
    process.wait(timeout=1)
    records.append("HARNESS P_KILLED_REAPED BEFORE_A_RELEASE")
    os.kill(attempt, signal.SIGCONT)


def observe_barrier(parts, process, stage, final, observer, mode, reject, attempt, records, snapshots, failures):
    checkpoint, observed_child = map(int, parts[1:])
    child = observed_child
    info = probe(observer, observed_child)
    snapshots[checkpoint] = info
    expected = stage if checkpoint == 3 else final
    if reject and checkpoint == 3:
        pass  # Negative child may already have rejected its entry.
    elif not info or Path(info["path"]) != expected or info["pid"] != observed_child:
        failures.append(f"live executable mismatch checkpoint={checkpoint}: {info}")
    else:
        expected_fds = list(range(7)) if checkpoint == 3 else [0, 1, 2, 3, 4, 6]
        if sorted(info["fds"]) != expected_fds:
            failures.append(f"live descriptor mismatch: {info}")
        info["artifact_sha256"] = hashlib.sha256(expected.read_bytes()).hexdigest()
    if mode == "a_death" and checkpoint == 4:
        os.kill(attempt, signal.SIGKILL)
        records.append("HARNESS A_KILLED_AT_LIVE_F")
    if mode == "child_stop" and checkpoint == 3:
        os.kill(child, signal.SIGSTOP)
        records.append("HARNESS OWNED_CHILD_STOPPED")
    process.stdin.write(b"C" if mode == "report_loss" and checkpoint == 4 else b"G")
    process.stdin.flush()
    return child


def verify_progress(parked, parent_killed, reject, mode, process, child, observer, records, snapshots, audit_lost, failures):
    if parked:
        if not parent_killed:
            failures.append("P death barrier not reached")
        if any(line.startswith("AUDIT FORWARD") for line in records):
            failures.append("child forward occurred after post-spawn P death barrier")
        if mode == "parked" and not any(line.startswith(f"AUDIT REAP {child} ") for line in records):
            failures.append("missing exact A-owned child reap")
        if mode == "prespawn" and child is not None:
            failures.append("child created after pre-spawn loss")
    elif reject:
        if process.returncode != 20:
            failures.append("fault did not terminally reject")
        if child is not None and mode not in ("a_death", "uncertain_reap") and not any(
            line.startswith((f"AUDIT REAP {child} ", f"AUDIT REAP_KILLED {child} ")) for line in records
        ):
            failures.append("fault lacks exact child reap")
        if mode == "a_death" and probe(observer, child) is not None:
            failures.append("F survivor after own A loss")
    else:
        if process.returncode != 0 or 3 not in snapshots or 4 not in snapshots:
            failures.append("two-image mechanics did not complete")
        elif not snapshots[3] or not snapshots[4] or any(
            snapshots[3][field] != snapshots[4][field] for field in ("pid", "start_sec", "start_usec")
        ):
            failures.append("external PID/start identity changed across exec")
        if not audit_lost and not any(line == f"AUDIT REAP {child} 0" for line in records):
            failures.append("child was not reaped with exit0")


def verify_fault_status(mode, child, attempt, observer, records, audit_lost, failures):
    if mode == "uncertain_reap" and not any(
        line.startswith(f"AUDIT UNCERTAIN {child} ") for line in records
    ):
        failures.append("real waitpid uncertainty not latched")
    expected_status = {"missing_mask": 41 << 8, "missing_default": 41 << 8,
                       "omitted_close": 41 << 8, "exec_fail": 45 << 8,
                       "full_status": 45 << 8, "report_loss": 53 << 8}
    if mode in expected_status and f"AUDIT REAP {child} {expected_status[mode]}" not in records:
        failures.append("wrong production child rejection status")
    if mode == "child_stop" and f"AUDIT REAP_KILLED {child} 9" not in records:
        failures.append("stopped child was not killed/reaped by owning A")
    if mode == "reserved_management" and child is not None:
        failures.append("reserved management source permitted a child")
    if audit_lost and (not any(line.startswith(f"ATTEMPT_REAP {attempt} 0") for line in records)
                       or probe(observer, child) is not None):
        failures.append("lost audit blocked terminal exit or left live child")


def handle_line(line, process, stage, final, observer, mode, reject, parked, attempt, child, parent_killed, records, snapshots, failures):
    records.append(line)
    parts = line.split()
    if parts[:1] == ["ATTEMPT"]:
        attempt = int(parts[1])
    if parts[:2] in (["AUDIT", "OWN"], ["AUDIT", "PRESPAWN"]):
        if parts[1] == "OWN":
            child = int(parts[2])
        if parked:
            kill_parked_parent(process, observer, attempt, records, failures)
            parent_killed = True
    if parts[:1] == ["BARRIER"]:
        child = observe_barrier(parts, process, stage, final, observer, mode, reject,
                                attempt, records, snapshots, failures)
    return attempt, child, parent_killed


def run_case(parent, stage, final, observer, mode="normal", reject=False):
    parked = mode in ("parked", "prespawn")
    audit_lost = mode in ("full_audit", "closed_audit")
    with tempfile.TemporaryDirectory(prefix="bee-a2c2-", dir="/private/tmp") as directory:
        journal = Path(directory) / "attempt.journal"
        journal.write_bytes(b"SOURCE_FIXTURE_FRESH\n")
        journal.chmod(0o600)
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
        process = subprocess.Popen([str(parent), directory], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=writer, start_new_session=True)
        os.close(writer)
        selector = selectors.DefaultSelector()
        if not audit_lost:
            selector.register(reader, selectors.EVENT_READ, "audit")
        selector.register(process.stdout, selectors.EVENT_READ, "parent")
        buffers = {"audit": b"", "parent": b""}
        records, snapshots, failures = [], {}, []
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
                        attempt, child, parent_killed = handle_line(
                            line, process, stage, final, observer, mode, reject, parked, attempt, child,
                            parent_killed, records, snapshots, failures)
            if selector.get_map():
                rescue = True
                failures.append("owned process group exceeded fixed deadline")
                print("FAILURE_BEFORE_CLEANUP", json.dumps(records), flush=True)
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)
            verify_progress(parked, parent_killed, reject, mode, process, child, observer, records,
                            snapshots, audit_lost, failures)
            verify_fault_status(mode, child, attempt, observer, records, audit_lost, failures)
            if journal.read_bytes() != b"ATTEMPT_PENDING_SOURCE_ONLY\n":
                failures.append("pending latch changed")
            if not (Path(directory) / "broker.sock").exists():
                failures.append("bound leaf was removed")
            retry = subprocess.run([str(parent), directory], capture_output=True, text=True, timeout=2, check=False)
            if retry.returncode != 30:
                failures.append("pending namespace relaunched")
            print("CASE", mode, "P_EXIT", process.returncode,
                  "RESCUE", rescue, "FAILURES", json.dumps(failures), flush=True)
            print("RECORDS", json.dumps(records), "LIVE", json.dumps(snapshots), flush=True)
            return not failures
        except BaseException:
            print("FAILURE_BEFORE_CLEANUP", json.dumps(records), flush=True)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1)
            raise
        finally:
            selector.close()
            if mode != "closed_audit":
                os.close(reader)
            process.stdin.close()
            process.stdout.close()


def main():
    if sys.platform != "darwin" or shutil.disk_usage(ROOT).free < 20 * 1024**3 + 64 * 1024**2:
        raise SystemExit("UNAVAILABLE: runtime/disk gate")
    with tempfile.TemporaryDirectory(prefix="bee-a2c2-build-") as temporary:
        build = Path(temporary).resolve()
        common = [NATIVE / name for name in ("a2c_policy.c", "launch_control.c", "launch_authority.c",
                                            "fd_inventory.c", "release_manifest.c", "stage0.c")]
        fixture = TESTS / "test_a2c_phase2_fixture.c"
        observer = build / "probe"
        compile_image([TESTS / "test_a2c_phase2_probe.c", "-o", observer])
        final, stage = build / "final", build / "stage0"
        compile_image([NATIVE / "final_entry.c", *common, "-o", final])
        compile_image(["-DBH_A2C_TEST_DROP", f'-DBH_A2C_FINAL_IMAGE="{final}"',
                       NATIVE / "stage0_entry.c", fixture, *common, "-o", stage])
        failed_stage = build / "stage-exec-fail"
        compile_image(["-DBH_A2C_TEST_DROP", f'-DBH_A2C_FINAL_IMAGE="{build / "absent-final"}"',
                       NATIVE / "stage0_entry.c", fixture, *common, "-o", failed_stage])
        passed = []
        cases = [
            ("normal", [], False),
            ("parked", ["PARK_AFTER_SPAWN"], False),
            ("prespawn", ["PARK_BEFORE_SPAWN"], False),
            ("collision", ["COLLISION"], False),
            ("dirty_signals", ["DIRTY_SIGNALS"], False),
            ("missing_mask", ["DIRTY_SIGNALS", "NO_SIGMASK"], True),
            ("missing_default", ["DIRTY_SIGNALS", "NO_SIGDEF"], True),
            ("omitted_close", ["LEAK_CHILD"], True),
            ("reserved_management", ["BAD_SOURCE"], True),
            ("exec_fail", [], True),
            ("full_status", ["FULL_STATUS"], True),
            ("full_audit", [], False),
            ("closed_audit", [], False),
            ("a_death", [], True),
            ("child_stop", [], True),
            ("report_loss", [], True),
            ("uncertain_reap", ["AUTO_REAP"], True),
        ]
        for suffix, faults, reject in cases:
            selected_stage = failed_stage if suffix in ("exec_fail", "full_status") else stage
            attempt, parent = build / ("attempt-" + suffix), build / ("parent-" + suffix)
            flags = ["-DBH_A2C_PHASE2", "-DBH_A2C_TEST_AUDIT", "-DBH_A2C_TEST_LEAK_PARENT", f'-DBH_A2C_STAGE0_IMAGE="{selected_stage}"']
            flags += ["-DBH_A2C_TEST_" + fault for fault in faults]
            compile_image([*flags, NATIVE / "attempt_entry.c", fixture, *common,
                           NATIVE / "socket_lineage.c", ROOT / "native/trusted_inbound/darwin/socket_observer.c",
                           "-o", attempt])
            compile_image([f'-DBH_A2C_ATTEMPT_IMAGE="{attempt}"', TESTS / "test_a2c_phase2_parent.c",
                           *common, "-o", parent])
            passed.append(run_case(parent, selected_stage, final, observer, suffix, reject))
        for source in ("launch_control.c", "attempt_entry.c", "stage0_entry.c", "final_entry.c"):
            compile_image(["--analyze", "-Xanalyzer", "-analyzer-output=text", "-DBH_A2C_PHASE2",
                           NATIVE / source, "-o", build / (source + ".plist")])
        size = sum(path.stat().st_size for path in build.iterdir())
        assert size < 64 * 1024**2
        print(f"PHASE2 cases={len(passed)} failures={passed.count(False)} build_bytes={size}", flush=True)
        assert all(passed), "actual two-image / post-spawn parent-loss source oracle failed"
    print("CLEANUP owned_groups_exited=1 disposable_artifacts_removed=1")


if __name__ == "__main__":
    main()
