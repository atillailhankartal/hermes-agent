#!/usr/bin/env python3
"""Run acquisition-only C tests with raw evidence; RED remains nonzero."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("red", "green"), default="green")
    parser.add_argument("--sanitizers", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    tests = root / "tests/native/darwin_bootstrap"
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = output / ("transaction-" + args.phase)
    source = args.source or (tests / "signed_preflight_v2_transaction_red_stub.c" if args.phase == "red" else root / "native/darwin_bootstrap/signed_preflight_v2_transaction.c")
    command = [
        "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
        "-I" + str(root / "native/darwin_bootstrap"), "-I" + str(tests), str(tests / "test_signed_preflight_v2_transaction.c"),
        str(source), "-o", str(binary),
    ]
    if args.sanitizers:
        command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g"]
    build = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
    (output / "build.log").write_text(build.stdout + build.stderr)
    record = {"compile_command": shlex.join(command), "compile_exit": build.returncode,
              "source_path": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    if build.returncode:
        (output / "run.json").write_text(json.dumps(record, indent=2) + "\n")
        print(build.stdout + build.stderr)
        return build.returncode
    run = subprocess.run([str(binary)], cwd=root, capture_output=True, text=True, check=False)
    (output / "stdout.log").write_text(run.stdout)
    (output / "stderr.log").write_text(run.stderr)
    record.update({
        "test_command": shlex.join([str(binary)]), "test_exit": run.returncode,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "semantic_assertion_count": run.stderr.count("ASSERT "),
        "summary": [line for line in run.stdout.splitlines() if line.startswith("SUMMARY ")],
        "interpretation": "Acquisition-only native test; no installed acceptance",
    })
    (output / "run.json").write_text(json.dumps(record, indent=2) + "\n")
    print(run.stdout, end="")
    print(f"compile_exit={build.returncode} test_exit={run.returncode} assertions={record['semantic_assertion_count']}")
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
