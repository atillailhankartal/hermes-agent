#!/usr/bin/env python3
"""Public-contract tests; --stub records behavioral RED before implementation."""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
TESTS = Path(__file__).resolve().parent
NATIVE = ROOT / "native" / "darwin_bootstrap"
EXPECTED_CLI_OUTPUT = b"UNAVAILABLE reason=no_policy synthetic=false installed_authority=false\n"
CASES = (
    "SyntheticValid_RemainsUntrusted",
    "MissingPolicy_ReturnsRejected",
    "ModelBrokerUidCollision_ReturnsRejected",
    "ModelClientUidCollision_ReturnsRejected",
    "BrokerClientUidCollision_ReturnsRejected",
    "ModelBrokerGidCollision_ReturnsRejected",
    "ModelClientGidCollision_ReturnsRejected",
    "BrokerClientGidCollision_ReturnsRejected",
    "ZeroUid_ReturnsRejected",
    "RelativePath_ReturnsRejected",
    "EmptyPath_ReturnsRejected",
    "DotComponent_ReturnsRejected",
    "DotDotComponent_ReturnsRejected",
    "EmptyComponent_ReturnsRejected",
    "TrailingSlash_ReturnsRejected",
    "PathWithoutNul_ReturnsRejected",
    "PathWithTrailingBytes_ReturnsRejected",
    "DuplicateRoots_ReturnsRejected",
    "LongestCanonicalPath_RemainsUntrusted",
    "ZeroDigest_ReturnsRejected",
    "ZeroEpoch_ReturnsRejected",
    "ZeroCount_ReturnsRejected",
    "ExcessiveCount_ReturnsRejected",
    "OverflowCount_ReturnsRejected",
    "UnknownProvider_ReturnsUnavailable",
    "MissingProvider_ReturnsUnavailable",
    "NoPolicy_StopsBeforeObservation",
    "MissingObservation_ReturnsUnavailable",
    "ProbeError_ReturnsUnavailable",
    "EpochMismatch_ReturnsRejected",
    "CountMismatch_ReturnsRejected",
    "ReleaseDigestMismatch_ReturnsRejected",
    "BrokerDigestMismatch_ReturnsRejected",
    "UnknownReason_MapsToNonsecretUnknown",
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_image(compiler, sources, output, flags=()):
    command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
               "-I", str(NATIVE), *flags, *map(str, sources), "-o", str(output)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    print("COMPILE", output.name, "exit", result.returncode, flush=True)
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", flush=True)
    if result.returncode != 0:
        return False
    print("BINARY_SHA256", output.name, sha256(output), flush=True)
    return True


def run_cli_mutations(compiler, directory, main_source):
    mutation_core = TESTS / "test_install_preflight_mutation_core.c"
    unavailable = NATIVE / "install_preflight_unavailable.c"
    for path in (main_source, mutation_core, unavailable):
        print("SOURCE_SHA256", path.relative_to(ROOT), sha256(path), flush=True)
    failures = 0
    for kind, name in ((1, "UntrustedCore_TriggersInternalError"),
                       (2, "AuthorityBit_TriggersInternalError")):
        binary = directory / ("mutation_cli_" + str(kind))
        if not compile_image(compiler, [main_source, mutation_core, unavailable], binary,
                             flags=[f"-DBH_IP_MUTATION_KIND={kind}"]):
            return None
        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                timeout=5, check=False)
        print("RUN", name, "exit", result.returncode,
              "stdout", result.stdout.strip(), "stderr", result.stderr.strip(), flush=True)
        if result.returncode != 70 or "UNAVAILABLE reason=internal_error" not in result.stdout:
            print("FAIL", name, flush=True)
            failures += 1
        else:
            print("PASS", name, flush=True)
    return failures


def accepts_no_policy_cli(result):
    return (result.returncode == 69 and result.stdout == EXPECTED_CLI_OUTPUT and
            result.stderr == b"")


def run_cli_oracle_negatives():
    wrong = (
        ("FakeReadyOutput_IsRejected", 69,
         b"READY installed_authority=true synthetic=true UNAVAILABLE reason=approved\n", b""),
        ("WrongExit_IsRejected", 0, EXPECTED_CLI_OUTPUT, b""),
        ("Stderr_IsRejected", 69, EXPECTED_CLI_OUTPUT, b"unexpected diagnostic\n"),
        ("CrLfOutput_IsRejected", 69, EXPECTED_CLI_OUTPUT[:-1] + b"\r\n", b""),
    )
    failures = 0
    for name, code, stdout, stderr in wrong:
        rejected = not accepts_no_policy_cli(
            subprocess.CompletedProcess([], code, stdout, stderr))
        print("PASS" if rejected else "FAIL", name, flush=True)
        failures += not rejected
    return failures


def run_cmake(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=90,
                            check=False)
    print("CMAKE_COMMAND", " ".join(map(str, command)), "exit", result.returncode,
          flush=True)
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)
    return result.returncode == 0


def audit_macho(cli, otool, nm):
    # Closed baseline for the pinned Darwin toolchain, not a side-effect denylist.
    outputs = {}
    for option, tool in (("-L", otool), ("-l", otool), ("-u", nm)):
        result = subprocess.run([tool, option, str(cli)], capture_output=True,
                                text=True, timeout=10, check=False)
        print("MACHO_AUDIT", tool, option, "exit", result.returncode, flush=True)
        print(result.stdout, end="", flush=True)
        if result.returncode != 0 or result.stderr:
            print("SETUP_FAIL Mach-O inspection", result.stderr.strip(), flush=True)
            return False
        outputs[option] = result.stdout
    dependency_lines = outputs["-L"].splitlines()
    if len(dependency_lines) != 2 or dependency_lines[0] != f"{cli}:" or not re.fullmatch(
            r"\s+/usr/lib/libSystem\.B\.dylib \(compatibility version [0-9.]+, "
            r"current version [0-9.]+\)", dependency_lines[1]):
        print("SETUP_FAIL Mach-O dynamic dependencies mismatch", flush=True)
        return False
    # Account for every load-command block, rejecting unknown commands as well as
    # rpath, weak, reexport, lazy and upward dylib loads and dyld environment entries.
    blocks = re.split(r"^Load command ", outputs["-l"], flags=re.MULTILINE)
    expected_commands = ["LC_SEGMENT_64"] * 4 + [
        "LC_DYLD_CHAINED_FIXUPS", "LC_DYLD_EXPORTS_TRIE", "LC_SYMTAB",
        "LC_DYSYMTAB", "LC_LOAD_DYLINKER", "LC_UUID", "LC_BUILD_VERSION",
        "LC_SOURCE_VERSION", "LC_MAIN", "LC_LOAD_DYLIB", "LC_FUNCTION_STARTS",
        "LC_DATA_IN_CODE", "LC_CODE_SIGNATURE"]
    commands = []
    if blocks[0] != f"{cli}:\n":
        print("SETUP_FAIL Mach-O load command header", flush=True)
        return False
    for index, block in enumerate(blocks[1:]):
        lines = block.splitlines()
        command = re.findall(r"^\s+cmd (LC_\w+)$", block, re.MULTILINE)
        if not lines or lines[0] != str(index) or len(command) != 1:
            print("SETUP_FAIL unrecognized Mach-O load command", flush=True)
            return False
        commands.extend(command)
        if command[0] in ("LC_LOAD_DYLIB", "LC_LOAD_DYLINKER"):
            names = re.findall(r"^\s+name (.+) \(offset \d+\)$", block, re.MULTILINE)
            expected_name = ("/usr/lib/libSystem.B.dylib" if command[0] == "LC_LOAD_DYLIB"
                             else "/usr/lib/dyld")
            if names != [expected_name]:
                print("SETUP_FAIL Mach-O load path mismatch", flush=True)
                return False
    if sorted(commands) != sorted(expected_commands):
        print("SETUP_FAIL Mach-O load commands mismatch", commands, flush=True)
        return False
    imports = outputs["-u"].splitlines()
    expected_imports = {"___stack_chk_fail", "___stack_chk_guard", "_memcmp",
                        "_memset", "_printf", "_puts", "_strcmp"}
    if len(imports) != len(expected_imports) or set(imports) != expected_imports:
        print("SETUP_FAIL exact CLI undefined imports mismatch", imports, flush=True)
        return False
    return True


def build_exact_cli(directory):
    cmake = shutil.which("cmake")
    nm = shutil.which("nm")
    otool = shutil.which("otool")
    if cmake is None or nm is None or otool is None:
        print("SETUP_FAIL cmake, nm or otool unavailable", flush=True)
        return None
    if shutil.disk_usage(ROOT).free <= 20 * 1024**3 + 64 * 1024**2:
        print("SETUP_FAIL below 20 GiB reserve plus 64 MiB build cap", flush=True)
        return None
    build = directory / "cmake-build"
    if not run_cmake([cmake, "-S", str(NATIVE), "-B", str(build),
                      "-G", "Unix Makefiles", "-DCMAKE_BUILD_TYPE=Debug"]):
        return None
    if not run_cmake([cmake, "--build", str(build), "--target",
                      "hermes_bee_install_preflight", "--parallel", "2"]):
        return None
    cli = build / "hermes_bee_install_preflight"
    link_map = build / "hermes_bee_install_preflight.map"
    cache = build / "CMakeCache.txt"
    if not cli.is_file() or not link_map.is_file() or not cache.is_file():
        print("SETUP_FAIL exact CMake CLI, map or cache absent", flush=True)
        return None
    if f"CMAKE_HOME_DIRECTORY:INTERNAL={NATIVE.resolve()}" not in cache.read_text():
        print("SETUP_FAIL CMake source root mismatch", flush=True)
        return None
    contents = link_map.read_text()
    object_section = contents.split("# Object files:\n", 1)
    if len(object_section) != 2:
        print("SETUP_FAIL link map object section absent", flush=True)
        return None
    sections = object_section[1].split("# Sections:\n")
    if len(sections) != 2:
        print("SETUP_FAIL link map sections boundary absent or repeated", flush=True)
        return None
    objects = []
    # Parse every row: filtering for .o silently omitted archives and dylibs.
    for index, line in enumerate(sections[0].splitlines()):
        row = re.fullmatch(r"\[\s*(\d+)\] (.+)", line)
        if row is None or int(row[1]) != index:
            print("SETUP_FAIL unrecognized link map object row", repr(line), flush=True)
            return None
        objects.append(row[2])
    expected = {
        f"CMakeFiles/hermes_bee_install_preflight.dir/{name}.c.o"
        for name in ("install_preflight_main", "install_preflight",
                     "install_preflight_unavailable")
    }
    # Exact SDK stub identities observed in the pinned Xcode link map. No SDK
    # glob, basename match or arbitrary system library is accepted.
    sdk = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
    expected_rows = expected | {"linker synthesized", f"{sdk}/usr/lib/libSystem.tbd",
                                f"{sdk}/usr/lib/system/libsystem_c.tbd"}
    print("LINK_OBJECTS", objects, flush=True)
    if len(objects) != len(expected_rows) or set(objects) != expected_rows:
        print("SETUP_FAIL exact CLI link object graph mismatch", flush=True)
        return None
    for obj in sorted(expected):
        object_path = build / obj
        if not object_path.is_file():
            print("SETUP_FAIL linked object absent", obj, flush=True)
            return None
        print("OBJECT_SHA256", obj, sha256(object_path), flush=True)
    symbols = subprocess.run([nm, "-g", str(cli)], capture_output=True, text=True,
                             timeout=10, check=False)
    if symbols.returncode != 0:
        print("SETUP_FAIL nm", symbols.stderr.strip(), flush=True)
        return None
    required = {"_main", "_bh_install_preflight",
                "_bh_install_preflight_unavailable_provider"}
    entries = [line.split() for line in symbols.stdout.splitlines() if line.split()]
    defined = {parts[-1] for parts in entries if len(parts) >= 3 and parts[-2] == "T"}
    actual = {parts[-1] for parts in entries}
    print("LINK_DEFINED_SYMBOLS", sorted(defined), flush=True)
    if not required.issubset(defined) or "_bh_ip_test_synthetic_provider" in actual:
        print("SETUP_FAIL exact CLI symbols mismatch", flush=True)
        return None
    if not audit_macho(cli, otool, nm):
        return None
    print("LINK_AUDIT PASS", flush=True)
    print("CMAKE_CLI_SHA256", sha256(cli), flush=True)
    return cli


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stub", action="store_true", help="compile deliberate wrong behavior")
    parser.add_argument("--mutation-oracle", action="store_true",
                        help="prove hardcoded UNAVAILABLE/69 main fails the mutation assertions")
    args = parser.parse_args()
    compiler = shutil.which("clang")
    if compiler is None:
        print("SETUP_FAIL compiler unavailable", flush=True)
        return 70
    if args.mutation_oracle:
        main_source = TESTS / "test_install_preflight_mutation_hardcoded_main.c"
        with tempfile.TemporaryDirectory(prefix="hermes-ip-mutation-") as directory:
            failures = run_cli_mutations(compiler, Path(directory), main_source)
            if failures is None:
                return 73
            print("SUMMARY", "failed", failures, "total", 2,
                  "mode", "MUTATION_ORACLE_RED", flush=True)
            return 1 if failures else 0
    header = NATIVE / "install_preflight.h"
    test_sources = [TESTS / "test_install_preflight.c", TESTS / "test_install_preflight_adapter.c"]
    core = (TESTS / "test_install_preflight_stub.c") if args.stub else (NATIVE / "install_preflight.c")
    test_link_sources = ([core] if args.stub else
                         [core, NATIVE / "install_preflight_unavailable.c"])
    cli_sources = ([TESTS / "test_install_preflight_stub_cli.c"] if args.stub else
                   [NATIVE / "install_preflight_main.c", NATIVE / "install_preflight.c",
                    NATIVE / "install_preflight_unavailable.c"])
    for path in dict.fromkeys([header, *test_sources, *test_link_sources, *cli_sources]):
        if not path.is_file():
            print("SETUP_FAIL missing", path, flush=True)
            return 70
        print("SOURCE_SHA256", path.relative_to(ROOT), sha256(path), flush=True)
    with tempfile.TemporaryDirectory(prefix="hermes-ip-test-") as directory:
        directory = Path(directory)
        binary = directory / "test_install_preflight"
        if not compile_image(compiler, [*test_sources, *test_link_sources], binary):
            return 71
        if args.stub:
            cli = directory / "hermes_bee_install_preflight_stub"
            if not compile_image(compiler, cli_sources, cli):
                return 72
        else:
            cli = build_exact_cli(directory)
            if cli is None:
                return 72
        failures = 0
        for case in CASES:
            result = subprocess.run([str(binary), case], capture_output=True, text=True,
                                    timeout=5, check=False)
            print("RUN", case, "exit", result.returncode, result.stdout.strip(), flush=True)
            if result.stderr:
                print("STDERR", case, result.stderr.strip(), flush=True)
            if result.returncode != 0:
                failures += 1
        result = subprocess.run([str(cli)], capture_output=True,
                                timeout=5, check=False)
        print("RUN NoPolicyCli_RejectsBeforeObservation exit", result.returncode,
              "stdout", repr(result.stdout), "stderr", repr(result.stderr), flush=True)
        if not accepts_no_policy_cli(result):
            print("FAIL NoPolicyCli_RejectsBeforeObservation", flush=True)
            failures += 1
        else:
            print("PASS NoPolicyCli_RejectsBeforeObservation", flush=True)
        if not args.stub:
            failures += run_cli_oracle_negatives()
            mutation_failures = run_cli_mutations(compiler, directory,
                                                  NATIVE / "install_preflight_main.c")
            if mutation_failures is None:
                return 73
            failures += mutation_failures
        print("SUMMARY", "failed", failures, "total", len(CASES) + 1 + (0 if args.stub else 6),
              "mode", "RED_STUB" if args.stub else "SOURCE_GREEN", flush=True)
        return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
