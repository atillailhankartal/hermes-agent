#!/usr/bin/env python3
"""A caller-supplied fake CLI must never make install preflight green."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


HARNESS = Path(__file__).with_name("test_install_preflight.py")
FAKE_OUTPUT = "READY installed_authority=true synthetic=true UNAVAILABLE reason=approved\n"


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
    print("COMMAND", " ".join(map(str, command)), flush=True)
    print("EXIT", result.returncode, flush=True)
    print("STDOUT_BEGIN\n" + result.stdout + "STDOUT_END", flush=True)
    print("STDERR_BEGIN\n" + result.stderr + "STDERR_END", flush=True)
    return result


def main():
    if not HARNESS.is_file():
        print("SETUP_FAIL missing harness", flush=True)
        return 70
    print("HARNESS_SHA256", hashlib.sha256(HARNESS.read_bytes()).hexdigest(), flush=True)

    # A working normal run separates an oracle failure from a build/setup failure.
    control = run([sys.executable, str(HARNESS)])
    if control.returncode != 0 or "SUMMARY failed 0" not in control.stdout or \
            "mode SOURCE_GREEN" not in control.stdout:
        print("SETUP_FAIL normal harness did not pass", flush=True)
        return 70

    with tempfile.TemporaryDirectory(prefix="hermes-ip-fake-cli-") as directory:
        fake = Path(directory) / "fake-positive-cli"
        fake.write_text("#!/bin/sh\nprintf '%s\\n' '" + FAKE_OUTPUT.rstrip("\n") + "'\nexit 69\n")
        os.chmod(fake, 0o700)
        print("FAKE_SHA256", hashlib.sha256(fake.read_bytes()).hexdigest(), flush=True)
        attack = run([sys.executable, str(HARNESS), "--cli", str(fake)])
        if attack.returncode != 0 and "SOURCE_GREEN" not in attack.stdout:
            print("PASS CallerSuppliedPositiveCli_IsRejected", flush=True)
            return 0
        print("FAIL CallerSuppliedPositiveCli_WasAccepted", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
