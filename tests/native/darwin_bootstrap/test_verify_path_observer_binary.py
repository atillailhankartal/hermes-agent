"""Test-first parser/refusal fixtures for the dormant observer binary gate.

These synthetic bytes are never executable product images.  Product acceptance
requires a separately reviewed profile measured from actual build artifacts.
"""

from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from verify_path_observer_binary import (
    GateRefusal,
    ImagePermit,
    RawProfile,
    REAL,
    INJECTED,
    PROTECTED,
    _capture,
    _profile_from_json,
    _qualified_tool,
    _observer_map_closure,
    _observer_symbol_closure,
    _depfile_closure,
    _sdk_link_inputs,
    _source_hashes,
    _toolchain_bytes,
    check_compile_rows,
    parse_depfile,
    parse_link_map,
    parse_macho_bytes,
    require,
    validate_otool_capture,
)


def _padded_command(command, payload):
    size = (8 + len(payload) + 7) & ~7
    return struct.pack("<II", command, size) + payload.ljust(size - 8, b"\0")


def _dylib_command(name):
    return _padded_command(0xC, struct.pack("<IIII", 24, 0, 0, 0) + name + b"\0")


def _dyld_command(name):
    return _padded_command(0xE, struct.pack("<I", 12) + name + b"\0")


def _synthetic_macho():
    version = (27037 << 16) | (1 << 8)
    commands = [
        _padded_command(0x19, b"\0" * 64),
        _padded_command(0x2, b"\0" * 16),
        _padded_command(0xB, b"\0" * 72),
        _dylib_command(b"/usr/lib/libSystem.B.dylib"),
        _dyld_command(b"/usr/lib/dyld"),
        _padded_command(0x32, struct.pack("<IIIIII", 1, 27 << 16, 27 << 16, 1, 3, version)),
        _padded_command(0x80000028, struct.pack("<QQ", 32, 0)),
        _padded_command(0x1B, b"\0" * 16),
        _padded_command(0x2A, b"\0" * 8),
    ]
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2,
                         len(commands), sum(map(len, commands)), 0, 0)
    return header + b"".join(commands)


SYNTHETIC_PROFILE = RawProfile(
    command_counts=Counter({0x19: 1, 0x2: 1, 0xB: 1, 0xC: 1, 0xE: 1,
                            0x32: 1, 0x80000028: 1, 0x1B: 1, 0x2A: 1}),
    build_version=(1, 27 << 16, 27 << 16, ((3, (27037 << 16) | (1 << 8)),)),
    dylibs=("/usr/lib/libSystem.B.dylib",),
    dyld="/usr/lib/dyld",
)


class TestRawMachO(unittest.TestCase):
    def test_explicit_profile_accepts_synthetic_fixture(self):
        result = parse_macho_bytes(_synthetic_macho(), SYNTHETIC_PROFILE)
        self.assertEqual(result.dylibs, ("/usr/lib/libSystem.B.dylib",))
        self.assertEqual(result.commands[0].numeric_type, 0x19)

    def test_rpath_refuses_even_if_dylib_list_is_unchanged(self):
        value = bytearray(_synthetic_macho())
        struct.pack_into("<I", value, 32, 0x8000001C)
        with self.assertRaisesRegex(GateRefusal, "RAW_LC_RPATH"):
            parse_macho_bytes(bytes(value), SYNTHETIC_PROFILE)

    def test_minos_26_refuses_against_reviewed_27_profile(self):
        value = bytearray(_synthetic_macho())
        cursor = 32
        while cursor < len(value):
            cmd, size = struct.unpack_from("<II", value, cursor)
            if cmd == 0x32:
                struct.pack_into("<I", value, cursor + 12, 26 << 16)
                break
            cursor += size
        with self.assertRaisesRegex(GateRefusal, "RAW_BUILD_VERSION_PROFILE"):
            parse_macho_bytes(bytes(value), SYNTHETIC_PROFILE)

    def test_unknown_numeric_type_refuses(self):
        value = bytearray(_synthetic_macho())
        struct.pack_into("<I", value, 32, 0xDEADBEEF)
        with self.assertRaisesRegex(GateRefusal, "RAW_COMMAND_PROFILE"):
            parse_macho_bytes(bytes(value), SYNTHETIC_PROFILE)

    def test_truncated_command_refuses(self):
        value = bytearray(_synthetic_macho())
        struct.pack_into("<I", value, 36, 7)
        with self.assertRaisesRegex(GateRefusal, "RAW_STRUCTURE"):
            parse_macho_bytes(bytes(value), SYNTHETIC_PROFILE)


class TestCompositeComponents(unittest.TestCase):
    def test_same_path_qualified_tool_byte_change_refuses(self):
        with tempfile.TemporaryDirectory(prefix="po-gate-tool-unit-") as directory:
            root = Path(directory).resolve()
            paths = {}
            for name in ("xcrun", "clang", "ld", "otool", "nm", "ar"):
                path = root / name
                path.write_bytes((name + " original\n").encode())
                paths[name] = path
            pinned = _toolchain_bytes(paths)
            paths["clang"].write_bytes(b"clang changed\n")
            with self.assertRaisesRegex(GateRefusal, "TOOLCHAIN_BYTES"):
                require(_toolchain_bytes(paths) == pinned, "TOOLCHAIN_BYTES")

    def test_same_path_link_stub_byte_change_refuses(self):
        with tempfile.TemporaryDirectory(prefix="po-gate-tbd-unit-") as directory:
            root = Path(directory).resolve()
            xcode = root / "Xcode.app"
            sdk = xcode / "Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
            stub = sdk / "usr/lib/libSystem.B.tbd"
            stub.parent.mkdir(parents=True)
            stub.write_bytes(b"tbd original\n")
            (stub.parent / "libSystem.tbd").symlink_to(stub.name)
            (sdk / "SDKSettings.json").write_bytes(b"{}\n")
            (xcode / "Contents/version.plist").write_bytes(b"version\n")
            (xcode / "Contents/Info.plist").write_bytes(b"info\n")
            targets = {target: {"dependencies": ["/usr/lib/libSystem.B.dylib"],
                                "map_rows": ["${SDK}/usr/lib/libSystem.tbd"]}
                       for target in (REAL, INJECTED, *PROTECTED)}
            pinned = _sdk_link_inputs(sdk, root, root / "build", targets)
            stub.write_bytes(b"tbd changed\n")
            with self.assertRaisesRegex(GateRefusal, "SDK_INPUT_BYTES"):
                require(_sdk_link_inputs(sdk, root, root / "build", targets) == pinned,
                        "SDK_INPUT_BYTES")

    def test_same_path_map_stub_byte_change_refuses(self):
        with tempfile.TemporaryDirectory(prefix="po-gate-map-tbd-unit-") as directory:
            root = Path(directory).resolve()
            xcode = root / "Xcode.app"
            sdk = xcode / "Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
            libdir = sdk / "usr/lib"
            system = libdir / "system/libsystem_c.tbd"
            system.parent.mkdir(parents=True)
            system.write_bytes(b"system tbd original\n")
            (libdir / "libSystem.B.tbd").write_bytes(b"system aggregate\n")
            (libdir / "libSystem.tbd").symlink_to("libSystem.B.tbd")
            (sdk / "SDKSettings.json").write_bytes(b"{}\n")
            (xcode / "Contents/version.plist").write_bytes(b"version\n")
            (xcode / "Contents/Info.plist").write_bytes(b"info\n")
            targets = {target: {"dependencies": ["/usr/lib/libSystem.B.dylib"],
                                "map_rows": ["${SDK}/usr/lib/libSystem.tbd",
                                             "${SDK}/usr/lib/system/libsystem_c.tbd"]}
                       for target in (REAL, INJECTED, *PROTECTED)}
            before = _sdk_link_inputs(sdk, root, root / "build", targets)
            system.write_bytes(b"system tbd changed\n")
            after = _sdk_link_inputs(sdk, root, root / "build", targets)
            with self.assertRaisesRegex(GateRefusal, "SDK_INPUT_BYTES"):
                require(after == before, "SDK_INPUT_BYTES")

    def test_same_path_sdk_byte_change_changes_reviewed_dependency_closure(self):
        with tempfile.TemporaryDirectory(prefix="po-gate-sdk-unit-") as directory:
            root = Path(directory).resolve()
            source, build, sdk = (root / name for name in ("source", "build", "sdk"))
            source.mkdir()
            build.mkdir()
            used = sdk / "usr/include/used.h"
            used.parent.mkdir(parents=True)
            used.write_bytes(b"original SDK header\n")
            unit = source / "core.c"
            unit.write_bytes(b"#include <used.h>\n")
            output = "CMakeFiles/core.dir/core.c.o"
            depfile = build / (output + ".d")
            depfile.parent.mkdir(parents=True)
            depfile.write_text(f"{output}: {unit} {used}\n")
            row = {"file": str(unit), "output": output}
            before = _depfile_closure([row], build, source, sdk)
            used.write_bytes(b"changed SDK header\n")
            after = _depfile_closure([row], build, source, sdk)
            self.assertNotEqual(before, after)
            with self.assertRaisesRegex(GateRefusal, "SDK_INPUT_BYTES"):
                require(after["external_sha256"] == before["external_sha256"],
                        "SDK_INPUT_BYTES")

    def test_actual_abi_header_byte_change_refuses_source_profile(self):
        repository = Path(__file__).resolve().parents[3]
        relative = "native/darwin_bootstrap/abi_v1.h"
        original = (repository / relative).read_bytes()
        with tempfile.TemporaryDirectory(prefix="po-gate-header-unit-") as directory:
            source = Path(directory).resolve()
            copied = source / relative
            copied.parent.mkdir(parents=True)
            copied.write_bytes(original)
            pinned = _source_hashes(source, (relative,))
            self.assertEqual(pinned[relative], hashlib.sha256(original).hexdigest())
            copied.write_bytes(original + b"\n/* test-only byte change */\n")
            with self.assertRaisesRegex(GateRefusal, "SOURCE_BYTES"):
                require(_source_hashes(source, (relative,)) == pinned, "SOURCE_BYTES")

    def test_compiler_depfiles_require_exact_set_and_local_closure(self):
        with tempfile.TemporaryDirectory(prefix="po-gate-dep-unit-") as directory:
            root = Path(directory)
            source, build = root / "source", root / "build"
            source.mkdir()
            build.mkdir()
            unit = source / "core.c"
            header = source / "abi_v1.h"
            added = source / "added.h"
            for path in (unit, header, added):
                path.write_text("fixture\n")
            output = "CMakeFiles/core.dir/core.c.o"
            depfile = build / (output + ".d")
            depfile.parent.mkdir(parents=True)
            depfile.write_text(f"{output}: \\\n  {unit} \\\n  {header}\n")
            row = {"file": str(unit), "output": output}
            parsed = parse_depfile(depfile.read_text(), output)
            self.assertEqual(parsed, (str(unit), str(header)))
            expected = _depfile_closure([row], build, source, root / "sdk")
            self.assertEqual(expected["workspace_paths"], ["abi_v1.h", "core.c"])

            depfile.write_text(f"{output}: \\\n  {unit}\n")
            self.assertNotEqual(_depfile_closure([row], build, source, root / "sdk"), expected)
            depfile.write_text(f"{output}: \\\n  {unit} \\\n  {header} \\\n  {added}\n")
            self.assertNotEqual(_depfile_closure([row], build, source, root / "sdk"), expected)

            depfile.write_text(f"{output}: \\\n  {unit} \\\n  /etc/passwd\n")
            with self.assertRaisesRegex(GateRefusal, "DEPFILE_PATH"):
                _depfile_closure([row], build, source, root / "sdk")
            depfile.unlink()
            with self.assertRaisesRegex(GateRefusal, "DEPFILE_SET"):
                _depfile_closure([row], build, source, root / "sdk")
            depfile.write_text(f"{output}: {unit}\n")
            extra = build / "CMakeFiles/extra.dir/extra.c.o.d"
            extra.parent.mkdir(parents=True)
            extra.write_text("fixture")
            with self.assertRaisesRegex(GateRefusal, "DEPFILE_SET"):
                _depfile_closure([row], build, source, root / "sdk")

    def test_depfile_parser_rejects_wrong_target_and_malformed_continuation(self):
        with self.assertRaisesRegex(GateRefusal, "DEPFILE_TARGET"):
            parse_depfile("other.o: /source/core.c\n", "core.o")
        with self.assertRaisesRegex(GateRefusal, "DEPFILE_STRUCTURE"):
            parse_depfile("core.o: /source/core.c\\\n", "core.o")

    def test_map_requires_indexed_object_table(self):
        text = "# Object files:\n[  0] linker synthesized\n[  1] main.o\n# Sections:\n"
        self.assertEqual(parse_link_map(text), ("linker synthesized", "main.o"))
        corrupt = text.replace("[  1] main.o", "[  2] main.o")
        with self.assertRaisesRegex(GateRefusal, "MAP_STRUCTURE"):
            parse_link_map(corrupt)
        with self.assertRaisesRegex(GateRefusal, "MAP_STRUCTURE"):
            parse_link_map("header mentions main.o but has no indexed table")

    def test_wrong_adapter_and_omitted_call_refuse_before_launch(self):
        wrong_rows = ("linker synthesized", "test_path_observer_real.c.o",
                      "CMakeFiles/bee_hermes_path_observer_v1_core.dir/path_observer_core_v1.c.o",
                      "path_observer_os_test_v1.c.o")
        with self.assertRaisesRegex(GateRefusal, "MAP_OBJECT_CLOSURE"):
            _observer_map_closure(REAL, wrong_rows)
        with self.assertRaisesRegex(GateRefusal, "NM_OBSERVER_CLOSURE"):
            _observer_symbol_closure(REAL, ("_main",), ())
        with self.assertRaisesRegex(GateRefusal, "PROTECTED_OBSERVER_EDGE"):
            _observer_map_closure("bee_hermes_a2c_phase3_stage0",
                                  ("linker synthesized", "path_observer_core_v1.c.o"))

    def test_duplicate_core_compile_row_refuses_before_execution(self):
        rows = [
            {"file": "/src/core.c", "output": "core.o", "directory": "/build"},
            {"file": "/src/real.c", "output": "real.o", "directory": "/build"},
        ]
        expected = (("/src/core.c", "core.o"), ("/src/real.c", "real.o"))
        self.assertEqual(check_compile_rows(rows, expected, "/src/core.c"), 1)
        with self.assertRaisesRegex(GateRefusal, "COMPILE_MANIFEST_MULTISET"):
            check_compile_rows([*rows, rows[0]], expected, "/src/core.c")

    def test_otool_capture_rejects_stderr_and_incomplete_capture(self):
        stdout = "/build/real:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1354.0.0)\n"
        capture = {"argv": ("/qualified/otool", "-L", "/build/real"),
                   "executable": "/qualified/otool", "executable_sha256": "a" * 64,
                   "qualified_sha256": "a" * 64, "exit": 0, "stdout": stdout,
                   "stderr": "", "complete": True, "timed_out": False, "pid": 123}
        deps = validate_otool_capture(capture, capture["argv"], "a" * 64, "/build/real")
        self.assertEqual(deps, ("/usr/lib/libSystem.B.dylib",))
        with self.assertRaisesRegex(GateRefusal, "OTOOL_L_STDERR"):
            validate_otool_capture({**capture, "stderr": "warning\n"}, capture["argv"],
                                   "a" * 64, "/build/real")
        with self.assertRaisesRegex(GateRefusal, "OTOOL_L_INCOMPLETE"):
            validate_otool_capture({**capture, "complete": False}, capture["argv"],
                                   "a" * 64, "/build/real")
        with self.assertRaisesRegex(GateRefusal, "OTOOL_L_STDOUT"):
            validate_otool_capture({**capture, "stdout": stdout[:-1]}, capture["argv"],
                                   "a" * 64, "/build/real")

    def test_one_use_sha_permit_cannot_start_refused_or_changed_image(self):
        content = b"test-owned image bytes only"
        digest = hashlib.sha256(content).hexdigest()
        launches = []

        def launcher(path, argv):
            launches.append((path, argv))
            return 77

        with tempfile.TemporaryDirectory(prefix="po-gate-unit-") as directory:
            image = Path(directory) / "real"
            image.write_bytes(content)
            permit = ImagePermit("real", image, digest)
            with self.assertRaisesRegex(GateRefusal, "IMAGE_SHA_CHANGED"):
                permit.launch(image, b"changed", ("case",), launcher)
            self.assertEqual(launches, [])
            self.assertEqual(permit.image_pids, ())
            self.assertEqual(permit.launch(image, content, ("case",), launcher), 77)
            self.assertEqual(permit.image_pids, (77,))
            with self.assertRaisesRegex(GateRefusal, "PERMIT_CONSUMED"):
                permit.launch(image, content, ("case",), launcher)

            failed_permit = ImagePermit("real", image, digest)

            def started_then_failed(path, argv):
                failed_permit.image_pids += (88,)
                raise OSError("synthetic post-start communication failure")

            with self.assertRaisesRegex(OSError, "post-start"):
                failed_permit.launch(image, content, ("case",), started_then_failed)
            self.assertEqual(failed_permit.image_pids, (88,))
            self.assertTrue(failed_permit.consumed)


def physical_candidate_negatives(build: Path, candidate: Path) -> dict[str, object]:
    """Use final product bytes in memory; never execute any candidate image."""
    profile = json.loads(candidate.read_text(encoding="utf-8"))
    real = build / REAL
    injected = build / INJECTED
    real_bytes = real.read_bytes()
    injected_bytes = injected.read_bytes()
    real_profile = _profile_from_json(profile["targets"][REAL]["raw"])
    injected_profile = _profile_from_json(profile["targets"][INJECTED]["raw"])
    assert parse_macho_bytes(real_bytes, real_profile).sha256 == profile["targets"][REAL]["image_sha256"]
    assert parse_macho_bytes(injected_bytes, injected_profile).sha256 == profile["targets"][INJECTED]["image_sha256"]
    source_root = Path(__file__).resolve().parents[3]
    initial_sources = {path: hashlib.sha256((source_root / path).read_bytes()).hexdigest()
                       for path in profile["source_hashes"]}
    results: list[dict[str, object]] = []

    def refusal(label, expected, callable_):
        try:
            callable_()
        except GateRefusal as exc:
            actual = str(exc)
            results.append({"case": label, "expected": expected, "actual": actual,
                            "passed": actual == expected, "new_image_pids": []})
        else:
            results.append({"case": label, "expected": expected, "actual": "ACCEPTED",
                            "passed": False, "new_image_pids": []})

    rpath = bytearray(real_bytes)
    struct.pack_into("<I", rpath, 32, 0x8000001C)
    refusal("actual_real_bytes_numeric_rpath", "RAW_LC_RPATH",
            lambda: parse_macho_bytes(bytes(rpath), real_profile))
    minos = bytearray(real_bytes)
    cursor = 32
    for _ in range(struct.unpack_from("<I", minos, 16)[0]):
        cmd, size = struct.unpack_from("<II", minos, cursor)
        if cmd == 0x32:
            struct.pack_into("<I", minos, cursor + 12, 26 << 16)
            break
        cursor += size
    refusal("actual_real_bytes_minos26", "RAW_BUILD_VERSION_PROFILE",
            lambda: parse_macho_bytes(bytes(minos), real_profile))
    unknown = bytearray(real_bytes)
    struct.pack_into("<I", unknown, 32, 0xDEADBEEF)
    refusal("actual_real_bytes_unknown_command", "RAW_COMMAND_PROFILE",
            lambda: parse_macho_bytes(bytes(unknown), real_profile))
    size7 = bytearray(real_bytes)
    struct.pack_into("<I", size7, 36, 7)
    refusal("actual_real_bytes_cmdsize7", "RAW_STRUCTURE",
            lambda: parse_macho_bytes(bytes(size7), real_profile))
    refusal("actual_real_bytes_truncated_commands", "RAW_STRUCTURE",
            lambda: parse_macho_bytes(real_bytes[:40], real_profile))

    otool = _qualified_tool("otool")
    argv = (str(otool), "-L", str(real))
    capture = _capture(argv)
    dependencies = validate_otool_capture(capture, argv,
                                           hashlib.sha256(otool.read_bytes()).hexdigest(),
                                           str(real))
    assert dependencies == tuple(profile["targets"][REAL]["dependencies"])
    refusal("actual_otool_capture_stderr", "OTOOL_L_STDERR",
            lambda: validate_otool_capture({**capture, "stderr": "warning\n"}, argv,
                                           capture["qualified_sha256"], str(real)))
    refusal("actual_otool_capture_incomplete", "OTOOL_L_INCOMPLETE",
            lambda: validate_otool_capture({**capture, "complete": False}, argv,
                                           capture["qualified_sha256"], str(real)))
    refusal("actual_otool_capture_truncated", "OTOOL_L_STDOUT",
            lambda: validate_otool_capture({**capture, "stdout": capture["stdout"][:-1]},
                                           argv, capture["qualified_sha256"], str(real)))
    manifest = json.loads((build / "compile_commands.json").read_text(encoding="utf-8"))
    expected_rows = tuple((row["file"], row["output"]) for row in manifest)
    core_file = str(source_root / "native/darwin_bootstrap/path_observer_core_v1.c")
    core_row = next(row for row in manifest if row["file"] == core_file)
    refusal("actual_manifest_duplicate_core_row", "COMPILE_MANIFEST_MULTISET",
            lambda: check_compile_rows([*manifest, core_row], expected_rows, core_file))
    real_map = (build / (REAL + ".map")).read_text(encoding="utf-8")
    corrupt = real_map.replace("[  1]", "[ 99]", 1)
    refusal("actual_map_corrupt_index", "MAP_STRUCTURE", lambda: parse_link_map(corrupt))
    real_rows = parse_link_map(real_map)
    wrong_adapter = tuple(row.replace("path_observer_os_darwin_v1.c.o",
                                      "path_observer_os_test_v1.c.o") for row in real_rows)
    refusal("actual_map_wrong_adapter_row", "MAP_OBJECT_CLOSURE",
            lambda: _observer_map_closure(REAL, wrong_adapter))
    protected_rows = parse_link_map((build / (PROTECTED[1] + ".map")).read_text(encoding="utf-8"))
    refusal("actual_stage0_map_observer_edge", "PROTECTED_OBSERVER_EDGE",
            lambda: _observer_map_closure(PROTECTED[1],
                                          (*protected_rows, "path_observer_core_v1.c.o")))
    defined = tuple(profile["targets"][INJECTED]["defined"])
    refusal("actual_injected_nm_omitted_call_inventory", "NM_OBSERVER_CLOSURE",
            lambda: _observer_symbol_closure(INJECTED,
                                              tuple(x for x in defined if x != "_bh_po_observe_v1"),
                                              profile["targets"][INJECTED]["imports"]))
    after_sources = {path: hashlib.sha256((source_root / path).read_bytes()).hexdigest()
                     for path in profile["source_hashes"]}
    return {"schema": 1, "candidate_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
            "source_hashes_unchanged": initial_sources == after_sources == profile["source_hashes"],
            "real_image_sha256": hashlib.sha256(real_bytes).hexdigest(),
            "injected_image_sha256": hashlib.sha256(injected_bytes).hexdigest(),
            "cases": results, "case_count": len(results), "all_refused": all(x["passed"] for x in results),
            "image_pids": [], "installed_authority": False, "ready": False,
            "scope": "component faults over final product bytes; no composite admission or image execution"}


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--physical-candidate":
        report = physical_candidate_negatives(Path(sys.argv[2]), Path(sys.argv[3]))
        print(json.dumps(report, sort_keys=True, indent=2))
        raise SystemExit(0 if report["all_refused"] and report["source_hashes_unchanged"] else 1)
    unittest.main()
