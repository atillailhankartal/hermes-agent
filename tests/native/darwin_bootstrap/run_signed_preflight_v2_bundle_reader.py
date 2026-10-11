#!/usr/bin/env python3
"""Pinned, nonempty 65-case native observer suite; RED is intentionally nonzero."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
TEST = ROOT / "tests/native/darwin_bootstrap"
NATIVE = ROOT / "native/darwin_bootstrap"
NAME_HASH = "b01f3538ef45da28150f1e17886a14e80611a90e08c42efdb3e58eb396f4ba81"
VECTOR_HASH = "edb9c7ae441d85e21e0c908c6e9ed3690aa2c82e62d040cd4972ed1db8dea859"
BASE = "5c7a544091dbc8416737f5cb45e559a721614991"
RED_STUB = '/* Intentionally incomplete test-local semantic RED, NEVER a product object. */\n#include "signed_preflight_v2_bundle_reader.h"\n#include "bundle_reader_os.h"\n#include <fcntl.h>\n#include <string.h>\nvoid bh_v2_bundle_result_dispose(struct bh_v2_bundle_result *o) {\n    if (!o) return;\n    bh_br_free(o->policy); bh_br_free(o->signature); bh_br_free(o->manifest);\n    memset(o, 0, sizeof(*o));\n}\nenum bh_v2_bundle_status bh_v2_bundle_observe(int d,\n    const struct bh_v2_bundle_expectation *e, struct bh_v2_bundle_result *o) {\n    if (!o || !e || d < 0) return BH_V2_BUNDLE_REJECTED;\n    /* Kept here only to allow the ownership abuse tests to execute safely. */\n    if ((const void *)o == (const void *)e) return BH_V2_BUNDLE_REJECTED;\n    /* Deliberately wrong reuse semantics: preserve existing bytes/ownership,\n     * but report a positive result instead of rejecting the attempted reuse. */\n    if (o->policy || o->signature || o->manifest)\n        return BH_V2_BUNDLE_OBSERVED_UNTRUSTED;\n    int dir = bh_br_dup(d), fds[3] = {-1,-1,-1};\n    const char *names[3] = {"policy.v2.bin","policy.v2.sig","release.v2.bin"};\n    size_t min[3] = {49,64,17}, max[3] = {65584,64,65552};\n    uint8_t **ptr[3] = {&o->policy,&o->signature,&o->manifest};\n    size_t *len[3] = {&o->policy_len,&o->signature_len,&o->manifest_len};\n    enum bh_v2_bundle_status r = BH_V2_BUNDLE_UNAVAILABLE;\n    if (dir < 0) return r;\n    for (int i = 0; i < 3; ++i) {\n        struct stat s;\n        if (bh_br_atstat(dir, names[i], &s, AT_SYMLINK_NOFOLLOW)) goto end;\n        if (!S_ISREG(s.st_mode) || s.st_size < (off_t)min[i] || s.st_size > (off_t)max[i]) {r = BH_V2_BUNDLE_REJECTED; goto end;}\n        fds[i] = bh_br_open(dir,names[i],O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);\n        if (fds[i] < 0 || bh_br_stat(fds[i],&s)) goto end;\n        if (!S_ISREG(s.st_mode) || s.st_size < (off_t)min[i] || s.st_size > (off_t)max[i]) {r = BH_V2_BUNDLE_REJECTED; goto end;}\n        *len[i]=(size_t)s.st_size; *ptr[i]=bh_br_alloc(*len[i]);\n        if (!*ptr[i] || bh_br_pread(fds[i],*ptr[i],*len[i],0)!=(ssize_t)*len[i]) goto end;\n    }\n    r=BH_V2_BUNDLE_OBSERVED_UNTRUSTED;\nend:\n    for(int i=0;i<3;++i) if(fds[i]>=0) (void)bh_br_close(fds[i]);\n    (void)bh_br_close(dir);\n    if(r!=BH_V2_BUNDLE_OBSERVED_UNTRUSTED) bh_v2_bundle_result_dispose(o);\n    o->status=r; return r;\n}\n'

def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(argv):
    print("ARGV " + shlex.join(map(str, argv)), flush=True)
    p = subprocess.run(argv, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    print(p.stdout, end="", flush=True)
    print(f"RAW_EXIT {p.returncode}", flush=True)
    return p


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("red", "green"), default="green")
    parser.add_argument("--sanitizers", action="store_true")
    args = parser.parse_args()
    source = TEST / "test_signed_preflight_v2_bundle_reader.c"
    names = re.findall(r'"(ObserveBundle_When\w+)"', source.read_text())
    assert len(names) == len(set(names)) == 65
    assert digest("\n".join(names).encode()) == NAME_HASH
    assert run(["git", "merge-base", "--is-ancestor", BASE, "HEAD"]).returncode == 0
    fixtures = TEST / "fixtures/signed_preflight_v2"
    vector = (fixtures / "S2-vector.json").read_bytes()
    assert digest(vector) == VECTOR_HASH
    for name, expected in json.loads(vector)["files"].items():
        data = (fixtures / name).read_bytes()
        assert len(data) == expected["size"] and digest(data) == expected["sha256"], name
        print(f"FIXTURE {name} size={len(data)} sha256={digest(data)}")
    run(["df", "-k", str(ROOT)])
    print("BUILD_BUDGET peak_incremental_bytes=67108864 reserve_bytes=1073741824")
    with tempfile.TemporaryDirectory(prefix="bh-bundle-run-") as temp:
        build = Path(temp)
        flags = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", str(NATIVE), "-I", str(TEST)]
        if args.sanitizers:
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g"]
        preflight = build / "preflight"
        assert run(flags + [str(NATIVE / n) for n in ("install_preflight_main.c", "install_preflight.c", "install_preflight_unavailable.c")] + ["-o", str(preflight)]).returncode == 0
        implementation = NATIVE / "signed_preflight_v2_bundle_reader.c"
        if args.phase == "red":
            implementation = build / "red_stub.c"
            implementation.write_text(RED_STUB)
        sources = [source, TEST / "bundle_reader_os_test.c", implementation, NATIVE / "signed_preflight_v2.c", NATIVE / "signed_preflight_v2_crypto.c"]
        if args.phase == "green":
            assert run(flags + ["-c", str(NATIVE / "bundle_reader_os_darwin.c"), "-o", str(build / "darwin.o")]).returncode == 0
        for p in sources + [NATIVE / "signed_preflight_v2_bundle_reader.h", NATIVE / "bundle_reader_os.h", NATIVE / "bundle_reader_darwin_name.h", NATIVE / "bundle_reader_os_darwin.c", TEST / "bundle_reader_os_test.h", Path(__file__)]:
            print(f"SOURCE {p} sha256={digest(p.read_bytes())}")
        binary = build / "bundle_test"
        command = flags + [f'-DBH_BUNDLE_FIXTURES="{fixtures}"', f'-DBH_BUNDLE_PREFLIGHT="{preflight}"'] + list(map(str, sources)) + ["-framework", "Security", "-framework", "CoreFoundation", "-o", str(binary)]
        assert run(command).returncode == 0, "compile failure is not semantic RED"
        result = run([str(binary)])
        lines = re.findall(r"^(PASS|FAIL) (ObserveBundle_When\w+)$", result.stdout, re.M)
        assert [n for _, n in lines] == names, "runtime order/count/name/duplicate/skip mismatch"
        assert "0 skipped" in result.stdout
        if args.phase == "red":
            assert lines[0][0] == "PASS", "RED stable positive must pass"
            for case in (28, 39, 42, 55):
                assert lines[case - 1][0] == "FAIL", f"missing semantic RED case {case}"
            assert result.returncode != 0
            print("SEMANTIC_RED_PROVEN required named failures=28,39,42,55; compile=0; stable-positive=PASS")
            return 1
        assert result.returncode == 0 and all(s == "PASS" for s, _ in lines)
        assert all(lines[i][0] == "PASS" for i in range(3))
        print("GREEN 65/65; 0 skipped; pinned source/runtime inventory and full fixture inventory verified")
    print("CLEANUP owned TemporaryDirectory removed; logs remain with caller")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
