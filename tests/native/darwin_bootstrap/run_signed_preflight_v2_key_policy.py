#!/usr/bin/env python3
"""Explicit dormant native consistency tests; never installs or provisions keys."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / "native/darwin_bootstrap"
TEST = Path(__file__).with_name("test_signed_preflight_v2_key_policy.c")
FIXTURES = TEST.parent / "fixtures/signed_preflight_v2"
EXPECTED_CASES = 52
# Pinned contract list independent of the executable's C case array.
EXPECTED = (
    "CheckKeyPolicy_WhenOldEpochBelowT_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenOldEpochAtTWithNewDigest_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenNewEpochTPlusOne_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenNewEpochUint64Max_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenTOneAndOldEpochOne_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenTMaxMinusOneAndNewMax_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenMinimumEqualsEpoch_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenOldValidSignatureAtTPlusOne_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenOldEpochUint64Max_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenNewEpochAtOrBelowT_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenTransitionEpochInvalid_DeniesConfig",
    "CheckKeyPolicy_WhenEntryCountNotTwo_DeniesConfig",
    "CheckKeyPolicy_WhenConfiguredIdMissing_DeniesConfig",
    "CheckKeyPolicy_WhenConfiguredIdsDuplicate_DeniesConfig",
    "CheckKeyPolicy_WhenEqualIdsHaveDifferentKeys_DeniesConfig",
    "CheckKeyPolicy_WhenConfiguredKeyDigestWrong_DeniesConfig",
    "CheckKeyPolicy_WhenConfiguredKeyShapeInvalid_DeniesConfig",
    "CheckKeyPolicy_WhenHeaderIdUnknown_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenHeaderIdMissing_DeniesWire",
    "CheckKeyPolicy_WhenEpochOrMinimumZero_DeniesTlv",
    "CheckKeyPolicy_WhenMinimumGreaterThanEpoch_DeniesTlv",
    "CheckKeyPolicy_WhenInstallationMismatch_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenConfiguredInstallationZero_DeniesConfig",
    "CheckKeyPolicy_WhenPolicyInstallationZero_DeniesTlv",
    "CheckKeyPolicy_WhenTransitionDigestZeroAtT_DeniesTransition",
    "CheckKeyPolicy_WhenTransitionDigestWrongAtT_DeniesTransition",
    "CheckKeyPolicy_WhenOldOrdinaryPolicyRepeatsTransitionDigest_DeniesTransition",
    "CheckKeyPolicy_WhenNewPolicyCarriesTransitionDigest_DeniesTransition",
    "CheckKeyPolicy_WhenArgumentsNull_DeniesWithoutReading",
    "CheckKeyPolicy_WhenSpanLengthInvalid_DeniesWithoutReading",
    "CheckKeyPolicy_WhenVersionOrHeaderWrong_DeniesWire",
    "CheckKeyPolicy_WhenBodyBoundInvalid_DeniesWire",
    "CheckKeyPolicy_WhenTlvHeaderTruncated_DeniesTlv",
    "CheckKeyPolicy_WhenTlvValueTruncated_DeniesTlv",
    "CheckKeyPolicy_WhenTlvLengthWrong_DeniesTlv",
    "CheckKeyPolicy_WhenTagsMissingDuplicateUnknownOrReordered_DeniesTlv",
    "CheckKeyPolicy_WhenManifestMismatch_DeniesStructureBeforeCrypto",
    "CheckKeyPolicy_WhenSignedHostModeMissing_DeniesStructureBeforeCrypto",
    "CheckKeyPolicy_WhenValidInputsReachSpy_PassesExactOwnedSelectedBytes",
    "CheckKeyPolicy_WhenMultipleFaultsExist_PreservesPrecheckOrdering",
    "CheckKeyPolicy_WhenCallbackRejects_DeniesCrypto",
    "CheckKeyPolicy_WhenCallbackUnavailable_ReturnsUnavailable",
    "CheckKeyPolicy_WhenSignatureTampered_DeniesCrypto",
    "CheckKeyPolicy_WhenSelectedKeyOffCurve_DeniesCrypto",
    "CheckKeyPolicy_WhenOriginalInputsMutateInsideCallback_UsesOwnedSnapshot",
    "CheckKeyPolicy_WhenInputsShareBackingStorage_RemainsBounded",
    "CheckKeyPolicy_WhenAllocationFails_ReturnsUnavailableWithoutCrypto",
    "CheckKeyPolicy_WhenResultZeroInitialized_RemainsDenial",
    "CheckKeyPolicy_WhenCallsRepeat_HasNoImplicitFloorOrCache",
    "CheckKeyPolicy_WhenDifferentOldPoliciesAtT_AreLocallyConsistentOnly",
    "CheckKeyPolicy_WhenInputsAreUnaligned_DecodesBytesSafely",
    "CheckKeyPolicy_WhenLengthsAtMaximum_RemainsBounded",
)

# Parameter cardinalities from the approved matrix, including 2 allocation and
# 2 SHA failure ordinals in case 47. Independent from C variants().
PARAMETERS = (1,1,1,1,1,1,1,1,1,3,2,4,2,1,1,2,10,1,2,2,2,1,1,1,1,2,
              1,2,5,12,6,6,39,26,12,42,1,1,2,4,8,1,1,1,1,2,4,1,3,2,1,1)


def command(argv):
    print("COMMAND", " ".join(map(str, argv)), flush=True)
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90,
                            env={**os.environ, "UBSAN_OPTIONS": "halt_on_error=1"})
    print(result.stdout, end="")
    print(result.stderr, end="")
    print("EXIT", result.returncode, flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["green", "red-deny", "red-crypto", "red-first"], default="green")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    assert len(EXPECTED) == EXPECTED_CASES == len(set(EXPECTED)) == len(PARAMETERS)
    if shutil.disk_usage(ROOT).free < 20 * 1024**3 + 256 * 1024**2:
        raise RuntimeError("native build disk reserve")
    build = Path(tempfile.mkdtemp(prefix="bh-key-policy-"))
    try:
        gate = NATIVE / "signed_preflight_v2_key_policy.c"
        if args.phase != "green":
            gate = build / "mutant.c"
            body = "(void)v;(void)x;return BH_KEY_POLICY_DENY;"
            if args.phase != "red-deny":
                body = """
                if (!c || !p || !m || !s || !v || pn<49 || pn>65584 || mn<17 || mn>65552 || sn!=64)
                    return BH_KEY_POLICY_DENY_ARGUMENT;
                unsigned i = memcmp(p+16,c->entries[1].id,32)==0 ? 1 : 0;
                struct bh_v2_crypto_result r=v(x,p,pn,m,mn,s,sn,c->entries[i].public_key,65);
                """
                body += ("(void)r;return BH_KEY_POLICY_DENY_EPOCH;" if args.phase == "red-first" else
                         "return r.status==BH_V2_CRYPTO_VALID_ONLY?BH_KEY_POLICY_CONSISTENT_ONLY:BH_KEY_POLICY_DENY_CRYPTO;")
            gate.write_text("""#include "signed_preflight_v2_key_policy.h"
#include <string.h>
enum bh_key_policy_status bh_v2_check_key_policy_for_test(
const struct bh_key_policy_test_config *c,const uint8_t *p,size_t pn,
const uint8_t *m,size_t mn,const uint8_t *s,size_t sn,bh_key_policy_test_verify_fn v,void *x) {
(void)c;(void)p;(void)pn;(void)m;(void)mn;(void)s;(void)sn;
""" + body + "\n}\n")
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-g"]
        if args.phase == "green":
            flags += ["-DBH_KEY_POLICY_TESTING"]
        if args.sanitize:
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        binary = build / "test"
        compiled = command(["xcrun", "clang", *flags, "-I", str(NATIVE), str(TEST), str(gate),
                            str(NATIVE / "signed_preflight_v2.c"), str(NATIVE / "signed_preflight_v2_crypto.c"),
                            "-framework", "Security", "-framework", "CoreFoundation", "-o", str(binary)])
        if compiled.returncode:
            return 2
        result = command([str(binary), str(FIXTURES)])
        observed = re.findall(r"^(?:PASS|FAIL) (CheckKeyPolicy_\w+)$", result.stdout, re.M)
        if len(observed) != EXPECTED_CASES or set(observed) != set(EXPECTED):
            print("INVALID exact case set")
            return 3
        params = re.findall(r"^PARAM (CheckKeyPolicy_\w+) variant=(\d+) .* (PASS|FAIL)$", result.stdout, re.M)
        expected_params = {(name, str(v)) for name, count in zip(EXPECTED, PARAMETERS) for v in range(count)}
        if len(params) != 232 or {(name, v) for name, v, _ in params} != expected_params:
            print("INVALID parameter set")
            return 3
        target = "CheckKeyPolicy_WhenOldValidSignatureAtTPlusOne_DeniesBeforeCrypto"
        target_line = next(line for line in result.stdout.splitlines() if line.startswith("PARAM " + target + " "))
        if args.phase == "green":
            valid = result.returncode == 0 and "failures=0" in result.stdout and "parameter_failures=0 skips=0" in result.stdout
        else:
            valid = result.returncode == 1 and "FAIL " in result.stdout
            if args.phase in {"red-crypto", "red-first"}:
                valid = valid and "calls=1 expected_calls=0" in target_line and target_line.endswith("FAIL")
                valid = valid and "CONTROL " + target + " actual=1 expected=1" in result.stdout
        print("SOURCE_SHA256", hashlib.sha256(gate.read_bytes()).hexdigest())
        print(args.phase.upper() + ("_VALID" if valid else "_INVALID"), "cases=52")
        return (0 if args.phase == "green" else 1) if valid else 3
    finally:
        # All subprocess.run calls have returned (or killed/waited on timeout).
        # Delete only our own private, unmounted temporary build; preserve sources/evidence.
        if build.is_symlink() or build.stat().st_uid != os.getuid() or os.path.ismount(build):
            raise RuntimeError("unsafe temporary build cleanup")
        shutil.rmtree(build)
        print("CLEANUP owned inactive temporary build removed")


if __name__ == "__main__":
    raise SystemExit(main())
