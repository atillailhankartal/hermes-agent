#!/usr/bin/env python3
"""Compile and run dormant signed-v2 structure tests on pinned public fixtures."""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / "native/darwin_bootstrap"
TESTS = Path(__file__).resolve().parent
FIXTURES = TESTS / "fixtures/signed_preflight_v2"
VECTOR_SHA256 = "edb9c7ae441d85e21e0c908c6e9ed3690aa2c82e62d040cd4972ed1db8dea859"
CC = ("/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic")
RESERVE = 20 * 1024**3 + 256 * 1024**2
EXPECTED_CASES = 67


RED_HEADER = """#ifndef BH_SIGNED_PREFLIGHT_V2_H
#define BH_SIGNED_PREFLIGHT_V2_H
#include <stddef.h>
#include <stdint.h>
enum bh_v2_structure_status {
    BH_V2_STRUCTURE_ONLY = 0,
    BH_V2_DENY_ARGUMENT,
    BH_V2_DENY_POLICY_WIRE,
    BH_V2_DENY_POLICY_TLV,
    BH_V2_DENY_MANIFEST_WIRE,
    BH_V2_DENY_MANIFEST_TLV,
    BH_V2_DENY_MANIFEST_DIGEST,
    BH_V2_DENY_ENTRY_TABLE,
    BH_V2_DENY_MODE_MASK,
    BH_V2_DENY_HOST_MODE_MISSING,
    BH_V2_DENY_HOST_TABLE,
    BH_V2_DENY_HOST_ENTRY,
    BH_V2_DENY_MODEL_GRAPH
};
enum bh_v2_structure_status bh_v2_validate_structure(
    const uint8_t *policy, size_t policy_len,
    const uint8_t *manifest, size_t manifest_len);
#endif
"""

RED_STUB = """#include \"signed_preflight_v2.h\"
enum bh_v2_structure_status bh_v2_validate_structure(
    const uint8_t *policy, size_t policy_len,
    const uint8_t *manifest, size_t manifest_len) {
    (void)policy;
    (void)policy_len;
    (void)manifest;
    (void)manifest_len;
    return BH_V2_STRUCTURE_ONLY;
}
"""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_fixtures() -> None:
    vector = FIXTURES / "S2-vector.json"
    if sha256(vector) != VECTOR_SHA256:
        raise ValueError("pinned S2-vector.json hash mismatch")
    metadata = json.loads(vector.read_text(encoding="utf-8"))
    if metadata.get("test_only") is not True or metadata.get("private_key_serialized_by_script") is not False:
        raise ValueError("fixture provenance metadata changed")
    expected_names = set(metadata["files"]) | {"S2-vector.json"}
    actual_names = {path.name for path in FIXTURES.iterdir() if path.is_file()}
    if actual_names != expected_names:
        raise ValueError("fixture inventory differs from pinned vector")
    for name, expected in metadata["files"].items():
        path = FIXTURES / name
        if path.stat().st_size != expected["size"] or sha256(path) != expected["sha256"]:
            raise ValueError(f"fixture hash/size mismatch: {name}")
    print(f"fixture_count={len(metadata['files'])} fixture_vector_sha256={VECTOR_SHA256}")


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    print("command=" + shlex.join(command), flush=True)
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", flush=True)
    if result.stderr:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n", file=sys.stderr, flush=True)
    print(f"exit={result.returncode}", flush=True)
    return result


def green_result_is_complete(result: subprocess.CompletedProcess[str]) -> bool:
    expected = f"signed_preflight_v2 cases={EXPECTED_CASES} failures=0\n"
    return result.returncode == 0 and result.stdout == expected and result.stderr == ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("red", "green"), required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        print("UNAVAILABLE: signed-v2 C test requires Darwin; no skip-as-pass", file=sys.stderr)
        return 2
    free = shutil.disk_usage(ROOT).free
    print(f"disk_free_bytes={free} reserve_bytes={RESERVE}")
    if free <= RESERVE:
        print("UNAVAILABLE: disk below reserve", file=sys.stderr)
        return 2
    try:
        verify_fixtures()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"FIXTURE_ERROR {error}", file=sys.stderr)
        return 2
    test_source = TESTS / "test_signed_preflight_v2.c"
    print(f"test_source_sha256={sha256(test_source)}")
    with tempfile.TemporaryDirectory(prefix="bee-signed-v2-test-") as temporary:
        build = Path(temporary)
        binary = build / "signed-v2-suite"
        if args.phase == "red":
            header = build / "signed_preflight_v2.h"
            stub = build / "signed_preflight_v2_stub.c"
            header.write_text(RED_HEADER, encoding="utf-8")
            stub.write_text(RED_STUB, encoding="utf-8")
            print(f"red_stub_header_sha256={sha256(header)} red_stub_source_sha256={sha256(stub)}")
            include = build
            source = stub
        else:
            header = NATIVE / "signed_preflight_v2.h"
            source = NATIVE / "signed_preflight_v2.c"
            if not header.is_file() or not source.is_file():
                print("UNAVAILABLE: production parser source/header absent", file=sys.stderr)
                return 2
            print(f"parser_header_sha256={sha256(header)} parser_source_sha256={sha256(source)}")
            include = NATIVE
        compile_command = [*CC, "-I", str(include), str(test_source), str(source), "-o", str(binary)]
        try:
            compiled = run(compile_command, timeout=30)
            if compiled.returncode != 0:
                return compiled.returncode
            if binary.stat().st_size >= 64 * 1024**2:
                print("UNAVAILABLE: test binary exceeded 64 MiB", file=sys.stderr)
                return 2
            tested = run([str(binary), str(FIXTURES)], timeout=20)
        except subprocess.TimeoutExpired as error:
            print(f"TIMEOUT command={shlex.join(error.cmd)}", file=sys.stderr)
            return 124
        if args.phase == "red":
            if tested.returncode != 1 or "ASSERT ValidateStructure_WhenGatewayHostMissing_DeniesHostModeMissing" not in tested.stderr:
                print("RED_INVALID: expected semantic assertion failure was not observed", file=sys.stderr)
                return 3
            print("RED_VALID: compiled test failed on Gateway missing-host semantic assertion")
            return 1
        if not green_result_is_complete(tested):
            print(f"GREEN_INVALID: expected exactly {EXPECTED_CASES} cases and zero failures", file=sys.stderr)
            return tested.returncode or 3
        print("GREEN_VALID: pinned fixture suite passed against production parser")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
