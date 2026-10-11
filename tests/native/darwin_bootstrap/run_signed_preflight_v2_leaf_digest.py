#!/usr/bin/env python3
"""Source-bound native retained-leaf digest RED/diagnostic runner."""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


BASELINE = "818adb64da84f31f218ae490686be053f4e2e9b1"
PRODUCT = (
    "signed_preflight_v2_transaction.c",
    "signed_preflight_v2_transaction.h",
    "signed_preflight_v2_transaction_os.h",
    "signed_preflight_v2_journal_codec.c",
    "signed_preflight_v2_journal_codec.h",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("red", "green"), default="red")
    parser.add_argument("--link", choices=("real", "spy"), default="real")
    parser.add_argument("--sanitizers", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    tests = root / "tests/native/darwin_bootstrap"
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    baseline = output / "immutable-baseline"
    baseline.mkdir(exist_ok=True)
    if args.phase == "red":
        for name in PRODUCT:
            source = subprocess.run(["git", "show", f"{BASELINE}:native/darwin_bootstrap/{name}"],
                                    cwd=root, capture_output=True, check=True).stdout
            target = baseline / name
            if target.exists() and target.read_bytes() != source:
                raise RuntimeError(f"baseline copy changed: {target}")
            target.write_bytes(source)
        product_dir = baseline
    else:
        product_dir = root / "native/darwin_bootstrap"
    generation = ["python3.11", str(tests / "fixtures/signed_preflight_v2_journal/run.py"),
                  "--emit-header", str(output / "journal_vectors.h")]
    leaf_generation = ["python3.11", str(tests / "fixtures/signed_preflight_v2_leaf_digest/generate.py"),
                       "--emit-header", str(output / "leaf_vectors.h")]
    commands = []

    def run(label: str, argv: list[str]) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(argv,cwd=root,capture_output=True,text=True,check=False)
        (output / f"{label}.stdout.log").write_text(result.stdout)
        (output / f"{label}.stderr.log").write_text(result.stderr)
        commands.append({"label":label,"argv":argv,"shell":shlex.join(argv),"exit":result.returncode,
                         "stdout_sha256":digest(output / f"{label}.stdout.log"),
                         "stderr_sha256":digest(output / f"{label}.stderr.log")})
        return result

    if run("journal-header",generation).returncode or run("leaf-header",leaf_generation).returncode:
        raise RuntimeError("fixture header generation failed")
    flags = ["cc","-std=c11","-Wall","-Wextra","-Werror","-pedantic"]
    if args.sanitizers:
        flags += ["-fsanitize=address,undefined","-fno-omit-frame-pointer","-g"]
    includes = ["-I"+str(product_dir),"-I"+str(tests),"-I"+str(output)]
    definitions = ["-DBH_TX_LEAF_DIGEST_TEST"]
    if args.phase == "red":
        definitions.append("-DBH_TX_LEAF_RED_STUB")
    if args.link == "spy":
        definitions.append("-DBH_TX_CODEC_SPY")
    test_obj = output / "leaf-test.o"
    tx_obj = output / "leaf-tx.o"
    binary = output / "leaf-digest"
    builds = [
        ("test-compile",flags+includes+definitions+["-c",str(tests / "test_signed_preflight_v2_leaf_digest.c"),"-o",str(test_obj)]),
        ("transaction-compile",flags+includes+["-DCC_SHA256=bh_test_tx_sha256","-c",str(product_dir / "signed_preflight_v2_transaction.c"),"-o",str(tx_obj)]),
    ]
    codec_obj = output / "leaf-codec.o"
    if args.link == "real":
        builds.append(("codec-compile",flags+includes+["-Dbh_journal_observe=bh_test_real_journal_observe",
                       "-c",str(product_dir / "signed_preflight_v2_journal_codec.c"),"-o",str(codec_obj)]))
    for label,argv in builds:
        if run(label,argv).returncode:
            print((output / f"{label}.stderr.log").read_text())
            return 2
    link = flags+[str(test_obj),str(tx_obj)]
    if args.link == "real": link.append(str(codec_obj))
    link += ["-o",str(binary)]
    if run("link",link).returncode:
        print((output / "link.stderr.log").read_text())
        return 2
    executed = run("test",[str(binary)])
    record = {"phase":args.phase,"link":args.link,"sanitizers":args.sanitizers,
              "baseline":BASELINE,"commands":commands,"product_hashes":{p:digest(product_dir/p) for p in PRODUCT},
              "test_hashes":{p.name:digest(p) for p in (tests/"test_signed_preflight_v2_leaf_digest.c",
                            tests/"test_signed_preflight_v2_transaction.c",
                            tests/"fixtures/signed_preflight_v2_leaf_digest/generate.py",
                            tests/"fixtures/signed_preflight_v2_leaf_digest/leaf-fixtures.json",
                            tests/"fixtures/signed_preflight_v2_leaf_digest/leaf-fixture-expansions.json",
                            tests/"fixtures/signed_preflight_v2_leaf_digest/leaf-registry.json")},
              "header_hashes":{p:digest(output/p) for p in ("journal_vectors.h","leaf_vectors.h")},
              "binary_sha256":digest(binary)}
    (output / "run.json").write_text(json.dumps(record,indent=2)+"\n")
    print(executed.stdout,end="")
    print(executed.stderr,end="")
    print(f"compile=0 link=0 runtime={executed.returncode}")
    if args.phase == "red":
        expected = "ASSERT LeafDigest_WhenActiveTupleMatches_RemainsUntrusted variant=0: expected PREPARED_UNTRUSTED actual=1"
        return 0 if (executed.returncode == 1 and "stub_hits=1" in executed.stdout
                     and expected in executed.stderr) else 1
    return executed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
