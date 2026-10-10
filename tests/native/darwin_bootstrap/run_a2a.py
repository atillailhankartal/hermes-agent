#!/usr/bin/env python3
"""Build and run dormant A2a source tests; no installation or admission."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / "native/darwin_bootstrap"
TESTS = Path(__file__).resolve().parent
OBSERVER = ROOT / "native/trusted_inbound/darwin/socket_observer.c"
CC = ["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]


def run(arguments, timeout=30):
    completed = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
    if completed.returncode:
        sys.stderr.write(completed.stdout + completed.stderr)
        raise SystemExit(completed.returncode)
    if completed.stderr:
        raise SystemExit(completed.stderr)
    return completed.stdout


def main():
    if sys.platform != "darwin":
        raise SystemExit("UNAVAILABLE: A2a requires Darwin; no skip-as-pass")
    if shutil.disk_usage(ROOT).free <= 20 * 1024**3 + 64 * 1024**2:
        raise SystemExit("UNAVAILABLE: below 20 GiB reserve plus 64 MiB build cap")
    with tempfile.TemporaryDirectory(prefix="bee-a2a-native-") as temporary:
        target = Path(temporary)
        child = target / "a2a-child"
        suite = target / "a2a-suite"
        run(CC + [str(TESTS / "a2a_child_fixture.c"), str(NATIVE / "stage0.c"),
                  str(NATIVE / "fd_inventory.c"), "-o", str(child)])
        run(CC + [str(TESTS / "test_a2a_root.c"),
                  *[str(NATIVE / name) for name in (
                      "launch_authority.c", "stage0.c", "release_manifest.c",
                      "fd_inventory.c", "socket_lineage.c")],
                  str(OBSERVER), "-o", str(suite)])
        if sum(path.stat().st_size for path in target.iterdir()) >= 64 * 1024**2:
            raise SystemExit("UNAVAILABLE: A2a build exceeded 64 MiB")
        output = run([str(suite), str(child)], timeout=20)
        if "cases=12 failures=0" not in output:
            raise SystemExit("A2a suite did not report twelve passing cases")
        print(output, end="")


if __name__ == "__main__":
    main()
