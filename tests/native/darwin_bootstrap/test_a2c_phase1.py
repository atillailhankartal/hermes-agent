#!/usr/bin/env python3
"""Real native P→A phase-1 source mechanics. No installed qualification."""
from pathlib import Path
import os
import signal
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / "native/darwin_bootstrap"
TESTS = Path(__file__).resolve().parent
CC = ["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
PENDING = b"ATTEMPT_PENDING_SOURCE_ONLY\n"


def command(args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=30, check=False)
    print("COMMAND", " ".join(str(arg) for arg in args), "EXIT", result.returncode, flush=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode or result.stderr:
        raise RuntimeError("native command failed")
    return result


def stdout_cases(parents):
    failures = []
    cases = [("full_entry_loss", False, True), ("full_after_loss", False, False),
             ("full_entry", True, True), ("full_after", True, False),
             ("full_after", False, False), ("full_status", False, True)]
    for mode, fault, prefill in cases:
        with tempfile.TemporaryDirectory(prefix="bee-a2c1-stdout-", dir="/private/tmp") as directory:
            folder = Path(directory)
            journal = folder / "attempt.journal"
            journal.write_bytes(b"SOURCE_FIXTURE_FRESH\n")
            journal.chmod(0o600)
            reader, writer = os.pipe()
            child = None
            result = None
            rescue = False
            try:
                if prefill:
                    os.set_blocking(writer, False)
                    try:
                        while True:
                            os.write(writer, b"x" * 4096)
                    except BlockingIOError:
                        pass
                    os.set_blocking(writer, True)
                parent = parents["fault" if fault else "normal"]
                started = time.monotonic()
                result = subprocess.run([str(parent), directory, mode, str(writer)],
                                        pass_fds=(writer,), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                        timeout=8, check=False)
                child = int(re.search(r"P_SPAWN child=(\d+)", result.stdout).group(1))
                # External read endpoint remains OPEN and UNDRAINED until A exits.
                deadline = started + 3.0
                alive = True
                while True:
                    try:
                        os.kill(child, 0)
                    except ProcessLookupError:
                        alive = False
                        break
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.01)
                elapsed = time.monotonic() - started
                expected_bound = not mode.endswith("loss") and mode != "full_status"
                expected_code = 20 if fault or mode == "full_status" else 0
                okay = (not alive and elapsed < 3.0 and not result.stderr and
                        result.returncode == (31 if mode.endswith("loss") else 0) and
                        journal.read_bytes() == PENDING and
                        (folder / "broker.sock").exists() == expected_bound)
                if not mode.endswith("loss"):
                    okay = okay and f"P_REAP exited=1 code={expected_code}" in result.stdout
                if alive:
                    os.kill(child, signal.SIGKILL)  # Failure cleanup, NEVER a passing oracle.
                    rescue = True
                    for _ in range(200):
                        try:
                            os.kill(child, 0)
                        except ProcessLookupError:
                            break
                        time.sleep(0.01)
                print(f"STDOUT_CASE {mode} fault={fault} prefill={prefill} "
                      f"parent_exit={result.returncode} elapsed={elapsed:.3f} "
                      f"rescue={rescue} PASS={okay}\n{result.stdout}", flush=True)
                retry = subprocess.run([str(parent), directory, "baseline"],
                                       capture_output=True, text=True, timeout=3, check=False)
                okay = okay and retry.returncode == 30 and "P_SPAWN" not in retry.stdout
                if not okay:
                    failures.append((mode, fault))
            finally:
                os.close(writer)
                os.close(reader)
    assert not failures, f"undrained stdout prevented A own bounded exit: {failures}"
    return len(cases)


def main():
    if sys.platform != "darwin":
        raise SystemExit("UNAVAILABLE: Darwin only")
    if shutil.disk_usage(ROOT).free < 20 * 1024**3 + 64 * 1024**2:
        raise SystemExit("UNAVAILABLE: disk reserve")
    with tempfile.TemporaryDirectory(prefix="bee-a2c1-build-") as temp:
        build = Path(temp)
        common = [NATIVE / name for name in ("a2c_policy.c", "launch_control.c", "launch_authority.c",
                                            "fd_inventory.c", "release_manifest.c")]
        observer = ROOT / "native/trusted_inbound/darwin/socket_observer.c"
        parents = {}
        for fault in (False, True):
            name = "fault" if fault else "normal"
            attempt = build / ("attempt-" + name)
            parent = build / ("parent-" + name)
            bind = TESTS / "test_a2c_phase1_bind_fault.c" if fault else NATIVE / "socket_lineage.c"
            command(CC + [str(NATIVE / "attempt_entry.c"), *map(str, common), str(bind), str(observer), "-o", str(attempt)])
            command(CC + [f'-DBH_A2C_ATTEMPT_IMAGE="{attempt}"', str(TESTS / "test_a2c_phase1_parent.c"),
                          *map(str, common), "-o", str(parent)])
            parents[name] = parent
        size = sum(path.stat().st_size for path in build.iterdir())
        assert size < 64 * 1024**2, "build cap"
        cases = [("loss_prebind", False), ("baseline", False), ("loss_postbind", False),
                 ("cancel", False), ("stale", False), ("shutdown", False), ("queued_cancel", False),
                 ("timeout", False), ("partial", False),
                 ("baseline", True)]
        if "--red" in sys.argv:
            cases = cases[:1]
        if "--stdout-red" in sys.argv:
            stdout_cases(parents)
            return
        for mode, fault in cases:
            with tempfile.TemporaryDirectory(prefix="bee-a2c1-", dir="/private/tmp") as directory:
                folder = Path(directory)
                journal = folder / "attempt.journal"
                journal.write_bytes(b"SOURCE_FIXTURE_FRESH\n")
                journal.chmod(0o600)
                parent = parents["fault" if fault else "normal"]
                started = time.monotonic()
                result = subprocess.run([str(parent), directory, mode], capture_output=True, text=True, timeout=8, check=False)
                print(f"CASE {mode} fault={fault} exit={result.returncode}\n{result.stdout}", flush=True)
                assert not result.stderr, result.stderr
                assert time.monotonic() - started < 8
                assert result.returncode == (31 if mode.startswith("loss_") else 0)
                assert "P_CHECKPOINT checkpoint=1" in result.stdout
                assert journal.read_bytes() == PENDING
                leaf = folder / "broker.sock"
                expected_bound = fault or mode in ("baseline", "loss_postbind")
                assert leaf.exists() == expected_bound, f"{mode}: unexpected bind after parent loss/cancel"
                assert ("BOUND_OBSERVED_SOURCE_ONLY" in result.stdout) == (mode == "baseline" and not fault)
                if (mode != "baseline" or fault) and mode not in ("loss_prebind", "loss_postbind", "shutdown"):
                    assert "P_OBSERVED_A_TERMINAL" in result.stdout
                if fault:
                    assert "cancelled=1 bound=1 fd6=1 parent=1 node_known=0" in result.stdout
                if not mode.startswith("loss_"):
                    expected_exit = 0 if mode == "baseline" and not fault else 20
                    assert f"P_REAP exited=1 code={expected_exit}" in result.stdout
                child = int(re.search(r"P_SPAWN child=(\d+)", result.stdout).group(1))
                # Pipe EOF proves child closed inherited output; verify PID no longer lives.
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise AssertionError("attempt still exists after terminal output EOF")
                retry = subprocess.run([str(parent), directory, "baseline"], capture_output=True, text=True, timeout=3, check=False)
                assert retry.returncode == 30 and "P_SPAWN" not in retry.stdout
                for contents in (None, b"corrupt\n"):
                    if contents is None:
                        journal.unlink()
                    else:
                        journal.write_bytes(contents)
                        journal.chmod(0o600)
                    retry = subprocess.run([str(parent), directory, "baseline"], capture_output=True, text=True, timeout=3, check=False)
                    assert retry.returncode == 30 and "P_SPAWN" not in retry.stdout
                print(f"PASS {mode} fault={fault} pending/missing/corrupt_restart=DENIED", flush=True)
        if "--red" not in sys.argv:
            stdout_count = stdout_cases(parents)
            print(f"A2c full_stdout_cases={stdout_count} failures=0")
            for source in ("a2c_policy.c", "launch_control.c", "attempt_entry.c"):
                command(CC + ["--analyze", "-Xanalyzer", "-analyzer-output=text", str(NATIVE / source),
                              "-o", str(build / (source + ".plist"))])
        print(f"A2c phase1 cases={len(cases)} failures=0 build_bytes={size} outcome=SOURCE_MECHANICS_ONLY")
    print("A2c disposable_build_cleanup=complete fixture_namespace_cleanup=complete")


if __name__ == "__main__":
    main()
