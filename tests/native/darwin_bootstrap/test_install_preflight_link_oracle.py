#!/usr/bin/env python3
"""An extra linked dylib must be rejected before the preflight CLI runs."""

import argparse
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "native" / "darwin_bootstrap"
HARNESS = Path(__file__).with_name("test_install_preflight.py")
SOURCE_NAMES = ("install_preflight_main.c", "install_preflight.c",
                "install_preflight_unavailable.c", "install_preflight.h")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90, check=False)
    print("COMMAND", " ".join(map(str, argv)), "exit", result.returncode, flush=True)
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--simulate-unrelated-failure", action="store_true",
                        help="prove an unrelated builder failure cannot satisfy this oracle")
    args = parser.parse_args()
    cmake = shutil.which("cmake")
    otool = shutil.which("otool")
    if cmake is None or otool is None or not HARNESS.is_file():
        print("SETUP_FAIL cmake, otool or harness absent", flush=True)
        return 70
    if shutil.disk_usage(ROOT).free <= 20 * 1024**3 + 64 * 1024**2:
        print("SETUP_FAIL disk reserve", flush=True)
        return 70
    print("HARNESS_SHA256", sha256(HARNESS), flush=True)
    for name in SOURCE_NAMES:
        print("SOURCE_SHA256", name, sha256(SOURCE / name), flush=True)
    with tempfile.TemporaryDirectory(prefix="hermes-ip-link-oracle-") as temporary:
        root = Path(temporary)
        source = root / "source"
        source.mkdir()
        for name in SOURCE_NAMES:
            shutil.copy2(SOURCE / name, source / name)
        extra = source / "extra.c"
        extra.write_text("int extra_dependency_marker(void) { return 7; }\n")
        cmakelists = source / "CMakeLists.txt"
        cmakelists.write_text(
            "cmake_minimum_required(VERSION 3.20)\n"
            "project(bee_hermes_darwin_bootstrap C)\n"
            "add_library(extra SHARED extra.c)\n"
            "add_executable(hermes_bee_install_preflight "
            "install_preflight_main.c install_preflight.c install_preflight_unavailable.c)\n"
            "target_link_libraries(hermes_bee_install_preflight PRIVATE extra)\n"
            "target_link_options(hermes_bee_install_preflight PRIVATE "
            "\"LINKER:-map,${CMAKE_CURRENT_BINARY_DIR}/hermes_bee_install_preflight.map\")\n")
        print("EXTRA_SOURCE_SHA256", sha256(extra), flush=True)
        print("CMAKELISTS_SHA256", sha256(cmakelists), flush=True)
        build = root / "independent-build"
        if command([cmake, "-S", str(source), "-B", str(build),
                    "-G", "Unix Makefiles", "-DCMAKE_BUILD_TYPE=Debug"]).returncode != 0:
            print("SETUP_FAIL independent configure", flush=True)
            return 70
        if command([cmake, "--build", str(build), "--target",
                    "hermes_bee_install_preflight", "--parallel", "2"]).returncode != 0:
            print("SETUP_FAIL independent build", flush=True)
            return 70
        cli = build / "hermes_bee_install_preflight"
        link_map = build / "hermes_bee_install_preflight.map"
        dylib = build / "libextra.dylib"
        if not cli.is_file() or not link_map.is_file() or not dylib.is_file():
            print("SETUP_FAIL binary, map or extra dylib absent", flush=True)
            return 70
        link_text = link_map.read_text()
        object_section = link_text.split("# Object files:\n", 1)
        if len(object_section) != 2 or "libextra.dylib" not in object_section[1].split("# Sections:", 1)[0]:
            print("SETUP_FAIL extra dylib absent from link object section", flush=True)
            return 70
        linked = command([otool, "-L", str(cli)])
        if linked.returncode != 0 or "libextra.dylib" not in linked.stdout:
            print("SETUP_FAIL extra dylib absent from Mach-O dependencies", flush=True)
            return 70
        print("PHYSICAL_EXTRA_LIBRARY_PRESENT map=true otool=true", flush=True)
        print("EXTRA_DYLIB_SHA256", sha256(dylib), flush=True)
        print("INDEPENDENT_CLI_SHA256", sha256(cli), flush=True)

        spec = importlib.util.spec_from_file_location("preflight_harness", HARNESS)
        if spec is None or spec.loader is None:
            print("SETUP_FAIL harness import spec", flush=True)
            return 70
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        harness.NATIVE = source.resolve()
        if args.simulate_unrelated_failure:
            def unrelated_failure(_directory):
                print("SETUP_FAIL unrelated tool failure", flush=True)
                return None
            harness.build_exact_cli = unrelated_failure
        executions = []
        original_run = subprocess.run

        class GuardedSubprocess:
            def __getattr__(self, name):
                return getattr(subprocess, name)

            def run(self, argv, *args, **kwargs):
                if isinstance(argv, (list, tuple)) and argv and \
                        Path(str(argv[0])).name == "hermes_bee_install_preflight":
                    executions.append(str(argv[0]))
                    raise RuntimeError("CLI execution before dependency rejection")
                return original_run(argv, *args, **kwargs)

        harness.subprocess = GuardedSubprocess()
        owned_build = root / "harness-build"
        owned_build.mkdir()
        audit_output = io.StringIO()
        try:
            with redirect_stdout(audit_output):
                audited_cli = harness.build_exact_cli(owned_build)
        except RuntimeError as error:
            print("FAIL CLI executed before rejection", str(error), flush=True)
            return 1
        diagnostic = "SETUP_FAIL exact CLI link object graph mismatch"
        output = audit_output.getvalue()
        print(output, end="", flush=True)
        print("AUDITOR_RETURN", audited_cli, flush=True)
        print("CLI_EXECUTIONS", len(executions), flush=True)
        print("EXPECTED_GRAPH_REFUSAL_COUNT", output.splitlines().count(diagnostic), flush=True)
        if audited_cli is not None or executions or output.splitlines().count(diagnostic) != 1:
            print("FAIL ExtraDylib_NotSpecificallyRejected", flush=True)
            return 1
        print("PASS ExtraDylib_IsRejectedBeforeExecution", flush=True)
        return 0


if __name__ == "__main__":
    sys.exit(main())
