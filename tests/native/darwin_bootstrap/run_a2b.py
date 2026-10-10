#!/usr/bin/env python3
"""Build dormant FD7 observation tests on Darwin; retain no build artifacts."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / "native/darwin_bootstrap"
TESTS = Path(__file__).resolve().parent
CC = ["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]


def run(arguments, timeout=30):
    completed = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
    if completed.returncode or completed.stderr:
        sys.stderr.write(completed.stdout + completed.stderr)
        raise SystemExit(completed.returncode or 1)
    return completed.stdout


def main():
    if sys.platform != "darwin":
        raise SystemExit("UNAVAILABLE: A2b requires Darwin; no skip-as-pass")
    if shutil.disk_usage(ROOT).free <= 20 * 1024**3 + 64 * 1024**2:
        raise SystemExit("UNAVAILABLE: below 20 GiB reserve plus 64 MiB build cap")
    with tempfile.TemporaryDirectory(prefix="bee-a2b-native-") as temporary:
        target = Path(temporary)
        source = str(NATIVE / "broker_entry.c")
        tests = str(TESTS / "test_a2b_fd7.c")
        suite = target / "suite"
        faults = target / "faults"
        run(CC + [tests, source, "-o", str(suite)])
        run(CC + ["-DBH_A2B_FAULTS", tests, "-o", str(faults)])
        run(CC + ["--analyze", "-Xanalyzer", "-analyzer-output=text", source, "-o", str(target / "analysis.plist")])
        size = sum(path.stat().st_size for path in target.iterdir())
        if size >= 64 * 1024**2:
            raise SystemExit("UNAVAILABLE: A2b build exceeded 64 MiB")
        for binary, count in ((suite, 34), (faults, 18)):
            output = run([str(binary)], timeout=20)
            if f"cases={count} failures=0" not in output:
                raise SystemExit("A2b suite did not report expected passing cases")
            print(output, end="")
        print(f"A2b warning_as_error=PASS analyzer=PASS build_bytes={size} disposable_cleanup=on_exit")


if __name__ == "__main__":
    main()
