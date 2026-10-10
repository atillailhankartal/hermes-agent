#!/usr/bin/env python3
"""Real native P→A phase-1 source mechanics. No installed qualification."""
from pathlib import Path
import os
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
                assert "A_ENTRY exact_fds=0,1,2,3 signal_policy=checked" in result.stdout
                assert journal.read_bytes() == PENDING
                leaf = folder / "broker.sock"
                expected_bound = fault or mode in ("baseline", "loss_postbind")
                assert leaf.exists() == expected_bound, f"{mode}: unexpected bind after parent loss/cancel"
                assert ("BOUND_OBSERVED_SOURCE_ONLY" in result.stdout) == (mode == "baseline" and not fault)
                if mode != "baseline" or fault:
                    assert "A_TERMINAL" in result.stdout
                if fault:
                    assert "cancelled=1 bound=1 fd6=1 parent=1 node_known=0" in result.stdout
                if not mode.startswith("loss_"):
                    assert "P_REAP exited=1" in result.stdout
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
            for source in ("a2c_policy.c", "launch_control.c", "attempt_entry.c"):
                command(CC + ["--analyze", "-Xanalyzer", "-analyzer-output=text", str(NATIVE / source),
                              "-o", str(build / (source + ".plist"))])
        print(f"A2c phase1 cases={len(cases)} failures=0 build_bytes={size} outcome=SOURCE_MECHANICS_ONLY")
    print("A2c disposable_build_cleanup=complete fixture_namespace_cleanup=complete")


if __name__ == "__main__":
    main()
