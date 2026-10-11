#!/usr/bin/env python3
"""Run the opt-in signed-v2 crypto C suite on frozen public fixtures."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / "native/darwin_bootstrap"
TEST = Path(__file__).with_name("test_signed_preflight_v2_crypto.c")
FIXTURES = TEST.parent / "fixtures/signed_preflight_v2"
VECTOR_SHA = "edb9c7ae441d85e21e0c908c6e9ed3690aa2c82e62d040cd4972ed1db8dea859"
BASE_SHA = "abb303945a422547b8f0cbed9b7e2b3185ca808a"
RESERVE = 20 * 1024**3 + 256 * 1024**2
EXPECTED = (
    "S2FrozenPair_ReturnsCryptoValidOnly",
    "SignedGatewayHostMissing_DeniesHostModeMissing",
    "SignedGatewayHostSubstituted_DeniesHostEntry",
    "ResultZeroInitialized_RemainsDenial",
    "PolicyBodyByteTampered_DeniesSignature",
    "RawRByteTampered_DeniesSignature",
    "RawSByteTampered_DeniesSignature",
    "S2PolicyWithMissingHostSignature_DeniesSignature",
    "SubstitutedHostPolicyWithS2Signature_DeniesSignature",
    "WrongValidPublicKey_DeniesKey",
    "WrongKeyIdReboundButS2Signature_DeniesSignature",
    "OffCurveKeyWithMatchingHeaderId_DeniesKey",
    "PublicKeyPrefixWrong_DeniesKey",
    "PublicKeyLength64_DeniesKey",
    "PublicKeyLength66_DeniesKey",
    "MissingHostManifestSwapped_DeniesManifestDigest",
    "SubstitutedHostManifestSwapped_DeniesManifestDigest",
    "ManifestValueByteTampered_DeniesManifestDigest",
    "V1ManifestMagic_DeniesManifestWire",
    "ManifestHeaderOnly_DeniesManifestWire",
    "ManifestSuffix_DeniesManifestWire",
    "V1PolicyMagic_DeniesPolicyWire",
    "PolicyBodyLengthMismatch_DeniesPolicyWire",
    "PolicySuffix_DeniesPolicyWire",
    "PolicyHeaderOnly_DeniesPolicyWire",
    "PolicyTruncated_DeniesPolicyWire",
    "PolicyNull_DeniesArgument",
    "ManifestNull_DeniesArgument",
    "SignatureNull_DeniesArgument",
    "PublicKeyNull_DeniesArgument",
    "PolicyLength47_DeniesArgument",
    "PolicyLength65585_DeniesArgument",
    "ManifestLength15_DeniesArgument",
    "ManifestLength65553_DeniesArgument",
    "SignatureLength0_DeniesSignatureFormat",
    "SignatureLength63_DeniesSignatureFormat",
    "SignatureLength65_DeniesSignatureFormat",
    "S2DerSignature_DeniesSignatureFormat",
    "MissingHostDerSignature_DeniesSignatureFormat",
    "RawRZero_DeniesSignatureFormat",
    "RawROrder_DeniesSignatureFormat",
    "RawSZero_DeniesSignatureFormat",
    "RawSOrder_DeniesSignatureFormat",
    "RawSAboveHalfOrder_DeniesSignatureFormat",
    "RawHighSMalleation_DeniesSignatureFormat",
    "RawRMaxCanonicalButWrong_DeniesSignature",
    "RawSOneCanonicalButWrong_DeniesSignature",
)
NAMES = tuple("CheckSignedPair_When" + suffix for suffix in EXPECTED)
STUB = r'''#include "signed_preflight_v2_crypto.h"
#include <string.h>
struct bh_v2_crypto_result bh_v2_check_signed_pair(
    const uint8_t *p, size_t pl, const uint8_t *m, size_t ml,
    const uint8_t *s, size_t sl, const uint8_t *k, size_t kl) {
    struct bh_v2_crypto_result r = {BH_V2_CRYPTO_DENY, BH_V2_DENY_ARGUMENT};
    if (!p || !m || !s || !k || pl < 48 || pl > 65584 || ml < 16 || ml > 65552) {
        r.status = BH_V2_CRYPTO_DENY_ARGUMENT; return r;
    }
    if (sl != 64) {r.status = BH_V2_CRYPTO_DENY_SIGNATURE_FORMAT; return r;}
    if (kl != 65 || k[0] != 4) {r.status = BH_V2_CRYPTO_DENY_KEY; return r;}
    if (memcmp(p, "BHPOL2\0\0", 8) != 0 || p[8] != 0 || p[9] != 2 ||
        p[10] != 0 || p[11] != 48 ||
        (((size_t)p[12] << 24) | ((size_t)p[13] << 16) |
         ((size_t)p[14] << 8) | p[15]) != pl - 48) {
        r.status = BH_V2_CRYPTO_DENY_POLICY_WIRE; return r;
    }
    r.structure_reason = bh_v2_validate_structure(p, pl, m, ml);
    r.status = r.structure_reason == BH_V2_STRUCTURE_ONLY ?
        BH_V2_CRYPTO_VALID_ONLY : BH_V2_CRYPTO_DENY_STRUCTURE;
    return r;
}
'''


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv: list[str], seconds: int) -> subprocess.CompletedProcess[str]:
    print("command=" + json.dumps(argv), flush=True)
    result = subprocess.run(argv, capture_output=True, text=True, timeout=seconds, check=False)
    print(result.stdout, end="", flush=True)
    print(result.stderr, end="", file=sys.stderr, flush=True)
    print(f"exit={result.returncode}", flush=True)
    return result


def verify_fixtures() -> None:
    vector_path = FIXTURES / "S2-vector.json"
    if digest(vector_path) != VECTOR_SHA:
        raise ValueError("vector hash")
    vector = json.loads(vector_path.read_text())
    if vector.get("test_only") is not True or vector.get("private_key_serialized_by_script") is not False:
        raise ValueError("provenance")
    files = vector["files"]
    if len(files) != 17 or set(files) | {"S2-vector.json"} != {p.name for p in FIXTURES.iterdir() if p.is_file()}:
        raise ValueError("fixture inventory")
    for name, meta in files.items():
        path = FIXTURES / name
        if not path.is_file() or path.stat().st_size != meta["size"] or digest(path) != meta["sha256"]:
            raise ValueError(f"fixture {name}")
    print(f"fixture_count=17 vector_sha256={VECTOR_SHA}")


def verify_cases(source: str, result: subprocess.CompletedProcess[str], phase: str) -> bool:
    inventory = tuple(re.findall(r'"(CheckSignedPair_When[^"\n]+)"', source))
    if inventory != NAMES or len(NAMES) != 47 or len(set(NAMES)) != 47:
        raise ValueError("source case inventory differs from pinned 47 names")
    lines = result.stdout.splitlines()
    case_lines = lines[:-1]
    if len(case_lines) != 47 or tuple(line.split(" ", 1)[1] for line in case_lines) != NAMES:
        raise ValueError("runtime case inventory differs from pinned 47 names")
    if any(not line.startswith(("PASS ", "FAIL ")) for line in case_lines):
        raise ValueError("runtime case status")
    fails = sum(line.startswith("FAIL ") for line in case_lines)
    if lines[-1] != f"signed_preflight_v2_crypto cases=47 failures={fails}":
        raise ValueError("runtime summary disagrees with cases")
    if phase == "red":
        required = (
            "RawSByteTampered_DeniesSignature",
            "RawHighSMalleation_DeniesSignatureFormat",
        )
        for suffix in required:
            name = "CheckSignedPair_When" + suffix
            if f"FAIL {name}" not in case_lines or not re.search(
                rf"ASSERT {name} expected=\d+ actual=1\b", result.stderr
            ):
                raise ValueError(f"missing semantic RED {name}")
        return result.returncode == 1 and fails >= 2 and "FIXTURE_ERROR" not in result.stderr
    return result.returncode == 0 and fails == 0 and result.stderr == ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("red", "green"), required=True)
    parser.add_argument("--sanitizers", action="store_true")
    args = parser.parse_args()
    if sys.platform != "darwin":
        print("UNAVAILABLE: Darwin required", file=sys.stderr)
        return 2
    free = shutil.disk_usage(ROOT).free
    print(f"disk_free_bytes={free} reserve_bytes={RESERVE}")
    if free <= RESERVE:
        print("UNAVAILABLE: disk reserve", file=sys.stderr)
        return 2
    current = command(["git", "-C", str(ROOT), "rev-parse", "HEAD"], 10)
    if current.returncode != 0:
        return 2
    head = current.stdout.strip()
    ancestor = command(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", BASE_SHA, head], 10)
    if ancestor.returncode != 0:
        print("UNAVAILABLE: unexpected product base", file=sys.stderr)
        return 2
    print(f"base_sha={BASE_SHA} head_sha={head}")
    try:
        verify_fixtures()
        source = TEST.read_text()
        inventory = tuple(re.findall(r'"(CheckSignedPair_When[^"\n]+)"', source))
        if inventory != NAMES:
            raise ValueError("source case inventory")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"FIXTURE_ERROR {exc}", file=sys.stderr)
        return 2
    for path in (TEST, NATIVE / "signed_preflight_v2.h", NATIVE / "signed_preflight_v2.c",
                 NATIVE / "signed_preflight_v2_crypto.h"):
        print(f"source_sha256 {path.relative_to(ROOT)} {digest(path)}")
    with tempfile.TemporaryDirectory(prefix="bee-signed-v2-crypto-") as directory:
        build = Path(directory)
        binary = build / "suite"
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
        if args.sanitizers:
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        if args.phase == "red":
            stub = build / "missing_crypto_stub.c"
            stub.write_text(STUB)
            print(f"stub_sha256={digest(stub)}")
            crypto = stub
        else:
            crypto = NATIVE / "signed_preflight_v2_crypto.c"
            if not crypto.is_file():
                print("UNAVAILABLE: crypto source absent", file=sys.stderr)
                return 2
            print(f"source_sha256 {crypto.relative_to(ROOT)} {digest(crypto)}")
        compile_argv = ["/usr/bin/xcrun", "clang", *flags, "-I", str(NATIVE),
                        str(TEST), str(crypto), str(NATIVE / "signed_preflight_v2.c"),
                        "-framework", "Security", "-framework", "CoreFoundation",
                        "-o", str(binary)]
        try:
            compiled = command(compile_argv, 60)
            if compiled.returncode != 0:
                return 2
            if not binary.is_file() or binary.stat().st_size > 64 * 1024**2:
                return 2
            result = command([str(binary), str(FIXTURES)], 30)
            if not verify_cases(source, result, args.phase):
                print("INVALID: exact case/oracle check failed", file=sys.stderr)
                return 3
        except (subprocess.TimeoutExpired, ValueError, IndexError) as exc:
            print(f"INVALID {exc}", file=sys.stderr)
            return 3
    print(f"{args.phase.upper()}_VALID cases=47")
    return 0 if args.phase == "green" else 1


if __name__ == "__main__":
    raise SystemExit(main())
