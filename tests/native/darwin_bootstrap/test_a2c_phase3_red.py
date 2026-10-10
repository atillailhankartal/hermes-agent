#!/usr/bin/env python3
"""Reusable Phase3 behavior oracle; old Phase2 build is intentionally RED.

No Phase3 symbol is required. Setup failures return 2, observed missing behavior 1.
The runner preserves Phase2's real process, entry, image, pending and reap checks.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import test_a2c_phase2 as phase2


def assert_phase3_observations(records):
    """Same runtime predicates for later Phase3 fixture/v2 build qualification."""
    final = [line for line in records if line.startswith("OBS_F ")]
    attempt = [line for line in records if line.startswith("OBS_A ")]
    if len(final) != 1 or len(attempt) != 1:
        raise RuntimeError("observation setup incomplete: expected exact A and F records")
    f = dict(item.split("=", 1) for item in final[0].split()[1:])
    a = dict(item.split("=", 1) for item in attempt[0].split()[1:])
    if f["status"] != "0" or a["management3"] != "1" or int(a["bound_aliases"]) < 0:
        raise RuntimeError("entry/terminal/descriptor observation invalid")
    frame = bytes.fromhex(f["frame"])
    receipt = bytes.fromhex(f["receipt"])
    failures = []
    if a["root6"] != "0" or a["bound_aliases"] != "0":
        failures.append("A retained original/temp bound-root aliases when forwarding X")
    if len(frame) != 152 or f["bytes"] != "152" or f["eof"] != "1":
        failures.append("F did not receive exactly 152 child3 bytes followed by EOF")
    if receipt != b"F" + b"R" + hashlib.sha256(frame).digest():
        failures.append("F did not send distinct R plus exact frame digest after F_ENTERED")
    return failures


def compile_image(arguments):
    command = phase2.CC + list(map(str, arguments))
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    print("COMPILE_COMMAND", json.dumps(command), flush=True)
    print("COMPILE_EXIT", result.returncode, "STDOUT", repr(result.stdout), "STDERR", repr(result.stderr), flush=True)
    if result.returncode or result.stderr:
        raise RuntimeError("compile failed; not behavioral RED")


def main():
    if sys.platform != "darwin" or shutil.disk_usage(phase2.ROOT).free < 20 * 1024**3 + 64 * 1024**2:
        raise RuntimeError("runtime/disk gate unavailable")
    records = []
    original = phase2.handle_line

    def record(*args):
        records.append(args[0])
        return original(*args)

    phase2.handle_line = record
    with tempfile.TemporaryDirectory(prefix="bee-a2c3-red-build-") as temporary:
        build = Path(temporary).resolve()
        common = [phase2.NATIVE / name for name in (
            "a2c_policy.c", "launch_authority.c", "fd_inventory.c", "release_manifest.c", "stage0.c")]
        control = phase2.NATIVE / "launch_control.c"
        fixture = phase2.TESTS / "test_a2c_phase3_audit.c"
        observer, final, stage, attempt, parent = [build / name for name in ("probe", "final", "stage0", "attempt", "parent")]
        compile_image([phase2.TESTS / "test_a2c_phase2_probe.c", "-o", observer])
        compile_image([phase2.TESTS / "test_a2c_phase3_final_observer.c", *common, "-o", final])
        compile_image(["-DBH_A2C_TEST_DROP", f'-DBH_A2C_FINAL_IMAGE="{final}"',
                       phase2.NATIVE / "stage0_entry.c", fixture, control, *common, "-o", stage])
        compile_image(["-DBH_A2C_PHASE2", "-DBH_A2C_TEST_AUDIT", "-DBH_A2C_TEST_LEAK_PARENT",
                       f'-DBH_A2C_STAGE0_IMAGE="{stage}"', phase2.NATIVE / "attempt_entry.c",
                       fixture, control, *common, phase2.NATIVE / "socket_lineage.c",
                       phase2.ROOT / "native/trusted_inbound/darwin/socket_observer.c", "-o", attempt])
        compile_image([f'-DBH_A2C_ATTEMPT_IMAGE="{attempt}"', phase2.TESTS / "test_a2c_phase2_parent.c",
                       control, *common, "-o", parent])
        print("MILESTONE COMPILE_ALL_EXIT_0", flush=True)
        if not phase2.run_case(parent, stage, final, observer):
            raise RuntimeError("Phase2 mechanics/setup oracle failed; not behavioral RED")
        print("PRECONDITION PASS real_P_A_S_F live_F_entry exact_reap pending_retry_denied", flush=True)
        failures = assert_phase3_observations(records)
        print("PHASE3_BEHAVIOR_FAILURES", json.dumps(failures), flush=True)
    print("CLEANUP disposable_build_removed owned_processes_reaped", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
        print("UNVERIFIED_SETUP", str(error), file=sys.stderr)
        sys.exit(2)
