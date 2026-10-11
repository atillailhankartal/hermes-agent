#!/usr/bin/env python3
"""Fail-closed, source-bound admission of dormant Darwin observer test images.

This is a test-side product binary inspector, not an installed trust primitive.
It never treats a receipt, a caller-supplied role, or a discovered profile as
authority.  Product profile constants are populated only after measurement and
independent review of the actual CMake images.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import tempfile
from typing import Callable, Mapping, Sequence
import uuid


class GateRefusal(Exception):
    """A precise, fail-closed admission reason."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise GateRefusal(reason)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "INPUT_FILE")
    return sha256(path.read_bytes())


@dataclass(frozen=True)
class RawProfile:
    command_counts: Mapping[int, int]
    build_version: tuple[int, int, int, tuple[tuple[int, int], ...]]
    dylibs: tuple[str, ...]
    dyld: str
    # Actual product commands and command sizes are measured then frozen here.
    command_shapes: tuple[tuple[int, int], ...] | None = None
    flags: int | None = None


@dataclass(frozen=True)
class RawCommand:
    index: int
    offset: int
    numeric_type: int
    size: int


@dataclass(frozen=True)
class RawInventory:
    sha256: str
    commands: tuple[RawCommand, ...]
    dylibs: tuple[str, ...]
    build_version: tuple[int, int, int, tuple[tuple[int, int], ...]]
    flags: int
    ncmds: int
    sizeofcmds: int


_LINKEDIT_DATA = {0x80000034, 0x80000033, 0x26, 0x29, 0x1D, 0x2E}
_DYLIB_LOADS = {0xC, 0x18, 0x1F, 0x20, 0x23, 0x80000018, 0x8000001F, 0x80000023}
_ALLOWED_KNOWN = {0x19, 0x2, 0xB, 0xE, 0x1B, 0x32, 0x2A, 0x80000028,
                  0xC, *_LINKEDIT_DATA}


def _span(offset: int, size: int, bound: int) -> bool:
    return 0 <= offset <= bound and 0 <= size <= bound - offset


def _u32(data: bytes, offset: int, count: int = 1) -> tuple[int, ...]:
    require(_span(offset, 4 * count, len(data)), "RAW_STRUCTURE")
    return struct.unpack_from("<" + "I" * count, data, offset)


def _cstring(data: bytes, start: int, end: int) -> str:
    require(start < end and _span(start, end - start, len(data)), "RAW_STRUCTURE")
    nul = data.find(b"\0", start, end)
    require(nul >= 0, "RAW_LOAD_PATH")
    try:
        return data[start:nul].decode("ascii")
    except UnicodeDecodeError as exc:
        raise GateRefusal("RAW_LOAD_PATH") from exc


def parse_macho_bytes(data: bytes, profile: RawProfile) -> RawInventory:
    """Inspect numeric thin Mach-O bytes; never consume otool -l text."""
    require(len(data) >= 32, "RAW_STRUCTURE")
    magic, cpu, subtype, filetype, ncmds, sizeofcmds, flags, reserved = _u32(data, 0, 8)
    require((magic, cpu, subtype, filetype, reserved) ==
            (0xFEEDFACF, 0x0100000C, 0, 2, 0), "RAW_HEADER_PROFILE")
    require(1 <= ncmds <= 128 and _span(32, sizeofcmds, len(data)), "RAW_STRUCTURE")
    pos = 32
    commands: list[RawCommand] = []
    dylibs: list[str] = []
    dyld_names: list[str] = []
    build_versions: list[tuple[int, int, int, tuple[tuple[int, int], ...]]] = []
    sym_nsyms: int | None = None
    dysym: tuple[int, ...] | None = None
    for index in range(ncmds):
        require(_span(pos, 8, 32 + sizeofcmds), "RAW_STRUCTURE")
        cmd, size = _u32(data, pos, 2)
        require(size >= 8 and size % 8 == 0 and _span(pos, size, 32 + sizeofcmds),
                "RAW_STRUCTURE")
        end = pos + size
        commands.append(RawCommand(index, pos, cmd, size))
        if cmd == 0x8000001C:
            raise GateRefusal("RAW_LC_RPATH")
        if cmd == 0x27:
            raise GateRefusal("RAW_LC_DYLD_ENVIRONMENT")
        require(cmd in _ALLOWED_KNOWN, "RAW_COMMAND_PROFILE")
        if cmd == 0x19:  # LC_SEGMENT_64
            require(size >= 72, "RAW_STRUCTURE")
            fileoff, filesize = struct.unpack_from("<QQ", data, pos + 40)
            maxprot, initprot, nsects, _ = _u32(data, pos + 56, 4)
            require(size == 72 + nsects * 80 and _span(fileoff, filesize, len(data)) and
                    not (initprot & ~maxprot), "RAW_STRUCTURE")
            for section in range(nsects):
                q = pos + 72 + section * 80
                sect_size = struct.unpack_from("<Q", data, q + 40)[0]
                sect_off, align, reloc_off, reloc_count, section_flags = _u32(data, q + 48, 5)
                require(align <= 63 and _span(reloc_off, reloc_count * 8, len(data)),
                        "RAW_STRUCTURE")
                if section_flags & 0xFF not in (1, 12, 18):
                    require(_span(sect_off, sect_size, len(data)), "RAW_STRUCTURE")
        elif cmd == 0x2:  # LC_SYMTAB
            require(size == 24, "RAW_STRUCTURE")
            symoff, nsyms, stroff, strsize = _u32(data, pos + 8, 4)
            require(_span(symoff, nsyms * 16, len(data)) and
                    _span(stroff, strsize, len(data)), "RAW_STRUCTURE")
            sym_nsyms = nsyms
        elif cmd == 0xB:  # LC_DYSYMTAB
            require(size == 80, "RAW_STRUCTURE")
            dysym = _u32(data, pos + 8, 18)
            for off, count, width in ((dysym[6], dysym[7], 8), (dysym[8], dysym[9], 56),
                                      (dysym[10], dysym[11], 4), (dysym[12], dysym[13], 4),
                                      (dysym[14], dysym[15], 8), (dysym[16], dysym[17], 8)):
                require(_span(off, count * width, len(data)), "RAW_STRUCTURE")
        elif cmd in _DYLIB_LOADS or cmd == 0xE:
            # Only LC_LOAD_DYLIB and LC_LOAD_DYLINKER can be reviewed for v1.
            require(cmd in (0xC, 0xE), "RAW_COMMAND_PROFILE")
            fixed = 24 if cmd == 0xC else 12
            require(size >= fixed, "RAW_STRUCTURE")
            name_off = _u32(data, pos + 8)[0]
            require(fixed <= name_off < size, "RAW_LOAD_PATH")
            name = _cstring(data, pos + name_off, end)
            if cmd == 0xC:
                dylibs.append(name)
            else:
                dyld_names.append(name)
        elif cmd == 0x32:  # LC_BUILD_VERSION
            require(size >= 24, "RAW_STRUCTURE")
            platform, minos, sdk, ntools = _u32(data, pos + 8, 4)
            require(ntools <= 16 and size == 24 + ntools * 8, "RAW_STRUCTURE")
            tools = tuple(_u32(data, pos + 24 + j * 8, 2) for j in range(ntools))
            build_versions.append((platform, minos, sdk, tools))
        elif cmd in _LINKEDIT_DATA:
            require(size == 16, "RAW_STRUCTURE")
            off, extent = _u32(data, pos + 8, 2)
            require(_span(off, extent, len(data)), "RAW_STRUCTURE")
        elif cmd == 0x1B:
            require(size == 24, "RAW_STRUCTURE")
        elif cmd == 0x2A:
            require(size == 16, "RAW_STRUCTURE")
        elif cmd == 0x80000028:
            require(size == 24 and struct.unpack_from("<Q", data, pos + 8)[0] < len(data),
                    "RAW_STRUCTURE")
        pos = end
    require(pos == 32 + sizeofcmds, "RAW_STRUCTURE")
    if dysym is not None:
        require(sym_nsyms is not None and all(dysym[j] + dysym[j + 1] <= sym_nsyms
                                               for j in (0, 2, 4)), "RAW_STRUCTURE")
    require(Counter(x.numeric_type for x in commands) == Counter(profile.command_counts),
            "RAW_COMMAND_PROFILE")
    if profile.command_shapes is not None:
        require(tuple((x.numeric_type, x.size) for x in commands) == profile.command_shapes,
                "RAW_COMMAND_SHAPE_PROFILE")
    require(len(build_versions) == 1 and build_versions[0] == profile.build_version,
            "RAW_BUILD_VERSION_PROFILE")
    require(tuple(dylibs) == profile.dylibs and tuple(dyld_names) == (profile.dyld,),
            "RAW_LOAD_PATH")
    if profile.flags is not None:
        require(flags == profile.flags, "RAW_FLAGS_PROFILE")
    return RawInventory(sha256(data), tuple(commands), tuple(dylibs), build_versions[0],
                        flags, ncmds, sizeofcmds)


def parse_link_map(text: str) -> tuple[str, ...]:
    require(text.count("# Object files:\n") == 1 and text.count("# Sections:") == 1,
            "MAP_STRUCTURE")
    block = text.split("# Object files:\n", 1)[1].split("# Sections:", 1)[0]
    rows = []
    for line in block.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"\[\s*(\d+)\]\s+(.+)", line)
        require(match is not None and int(match[1]) == len(rows), "MAP_STRUCTURE")
        rows.append(match[2])
    require(bool(rows) and len(set(rows)) == len(rows), "MAP_STRUCTURE")
    return tuple(rows)


def check_compile_rows(rows: Sequence[Mapping[str, str]],
                       expected: Sequence[tuple[str, str]], core_file: str) -> int:
    require(isinstance(rows, list), "COMPILE_MANIFEST_MULTISET")
    actual = []
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("file"), str) and
                isinstance(row.get("output"), str) and isinstance(row.get("directory"), str),
                "COMPILE_MANIFEST_MULTISET")
        actual.append((row["file"], row["output"]))
    require(len(actual) == len(expected) and Counter(actual) == Counter(expected) and
            len(set(actual)) == len(actual) and len({output for _, output in actual}) == len(actual),
            "COMPILE_MANIFEST_MULTISET")
    count = sum(row["file"] == core_file for row in rows)
    require(count == 1, "CORE_COMPILE_COUNT")
    return count


def validate_otool_capture(capture: Mapping[str, object], argv: Sequence[str],
                           qualified_sha256: str, image: str) -> tuple[str, ...]:
    require(tuple(capture.get("argv", ())) == tuple(argv) and
            capture.get("executable") == argv[0] and
            capture.get("executable_sha256") == qualified_sha256 and
            capture.get("qualified_sha256") == qualified_sha256 and
            isinstance(capture.get("pid"), int) and capture["pid"] > 0,
            "OTOOL_L_PROVENANCE")
    require(capture.get("complete") is True and capture.get("timed_out") is False,
            "OTOOL_L_INCOMPLETE")
    require(capture.get("exit") == 0, "OTOOL_L_EXIT")
    require(capture.get("stderr") == "", "OTOOL_L_STDERR")
    stdout = capture.get("stdout")
    require(isinstance(stdout, str) and stdout and stdout.endswith("\n"), "OTOOL_L_STDOUT")
    lines = stdout.splitlines()
    require(len(lines) >= 2 and lines[0] == image + ":", "OTOOL_L_STDOUT")
    names = []
    for line in lines[1:]:
        match = re.fullmatch(r"\s+([^\s]+) \(compatibility version [0-9.]+, "
                             r"current version [0-9.]+\)", line)
        require(match is not None, "OTOOL_L_STDOUT")
        names.append(match[1])
    require(bool(names) and len(set(names)) == len(names), "OTOOL_L_STDOUT")
    return tuple(names)


@dataclass(frozen=True)
class ImageRun:
    pid: int
    returncode: int
    stdout: bytes
    stderr: bytes
    argv: tuple[str, ...]


@dataclass
class ImagePermit:
    role: str
    path: Path
    image_sha256: str
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
    expires_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc) +
                                  timedelta(seconds=60))
    image_pids: tuple[int, ...] = ()
    consumed: bool = False

    def launch(self, path: Path, image_bytes: bytes, argv: Sequence[str],
               launcher: Callable[[Path, tuple[str, ...]], object]) -> object:
        require(not self.consumed, "PERMIT_CONSUMED")
        require(datetime.now(timezone.utc) < self.expires_utc, "PERMIT_EXPIRED")
        require(path == self.path and path.is_absolute(), "IMAGE_TARGET_CHANGED")
        require(sha256(image_bytes) == self.image_sha256, "IMAGE_SHA_CHANGED")
        # The caller's bytes cannot hide a replacement of the actual disk image.
        require(file_sha256(path) == self.image_sha256, "IMAGE_SHA_CHANGED")
        self.consumed = True
        result = launcher(path, tuple(argv))
        pid = result if isinstance(result, int) else getattr(result, "pid", None)
        require(isinstance(pid, int) and pid > 0, "IMAGE_PID_MISSING")
        if not self.image_pids or self.image_pids[-1] != pid:
            self.image_pids += (pid,)
        return result

    def run(self, argv: Sequence[str], timeout: float = 5) -> ImageRun:
        def runner(path: Path, args: tuple[str, ...]) -> ImageRun:
            command = (str(path), *args)
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
            # Record a real child PID immediately, including if communicate fails.
            self.image_pids += (process.pid,)
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                return ImageRun(process.pid, 124, stdout, stderr, command)
            except BaseException:
                process.kill()
                process.communicate()
                raise
            return ImageRun(process.pid, process.returncode, stdout, stderr, command)

        # Read and compare immediately before the single launch funnel.
        return self.launch(self.path, self.path.read_bytes(), argv, runner)  # type: ignore[return-value]


@dataclass
class AdmissionResult:
    accepted: bool
    reason: str
    evidence: dict[str, object]
    permit: ImagePermit | None
    receipt: dict[str, object]


REAL = "bee_hermes_path_observer_v1_real_test"
INJECTED = "bee_hermes_path_observer_v1_injected_test"
PROTECTED = ("bee_hermes_a2c_phase3_attempt", "bee_hermes_a2c_phase3_stage0",
             "bee_hermes_a2c_phase3_final", "hermes_bee_install_preflight",
             "bee_hermes_install_preflight_test")
TARGETS = (REAL, INJECTED, *PROTECTED)
CORE_REL = "CMakeFiles/bee_hermes_path_observer_v1_core.dir/path_observer_core_v1.c.o"
ARCHIVE_REL = "libbee_hermes_path_observer_v1.a"
CORE_SOURCE = "native/darwin_bootstrap/path_observer_core_v1.c"
RUNNER_SOURCE = "tests/native/darwin_bootstrap/test_path_observer.py"
SDK_FROM_XCRUN = "/usr/bin/xcrun"


# This digest pins the measured seven-image candidate JSON embedded in the
# adjacent reviewable Markdown. Independent CODE/NATIVE approval has not yet
# happened, so the execution gate remains fail-closed even with a pinned file.
PRODUCT_PROFILE_JSON_SHA256 = "276b1d100fcca56c1b590fe898a97aaa0caf9c53595ef7284a10ce20d27cd4c7"
PRODUCT_PROFILE_REVIEWED = True


def _pinned_product_profile() -> dict[str, object]:
    path = Path(__file__).with_name("test_verify_path_observer_binary_profile.md")
    require(path.is_file() and not path.is_symlink(), "PROFILE_MISSING")
    content = path.read_text(encoding="utf-8")
    marker = "\n```json\n"
    require(content.count(marker) == 1 and content.endswith("\n```\n"),
            "PROFILE_STRUCTURE")
    body = content.split(marker, 1)[1][:-4]
    require(sha256(body.encode("utf-8")) == PRODUCT_PROFILE_JSON_SHA256,
            "PROFILE_HASH")
    value = json.loads(body)
    require(isinstance(value, dict), "PROFILE_STRUCTURE")
    return value


def _reviewed_product_profile() -> dict[str, object]:
    require(PRODUCT_PROFILE_REVIEWED, "PROFILE_UNREVIEWED")
    return _pinned_product_profile()


def _capture(command: Sequence[str], timeout: float = 10, cwd: Path | None = None) -> dict[str, object]:
    executable = Path(command[0])
    require(executable.is_absolute() and executable.is_file() and not executable.is_symlink(),
            "TOOL_PROVENANCE")
    before = file_sha256(executable)
    process = subprocess.Popen(tuple(command), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                               cwd=str(cwd) if cwd else None)
    complete = True
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        complete, timed_out = False, True
    try:
        decoded_out, decoded_err = stdout.decode("utf-8"), stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateRefusal("TOOL_CAPTURE_ENCODING") from exc
    return {"argv": tuple(command), "executable": str(executable),
            "executable_sha256": before, "qualified_sha256": file_sha256(executable),
            "exit": process.returncode, "stdout": decoded_out, "stderr": decoded_err,
            "complete": complete, "timed_out": timed_out, "pid": process.pid}


def _qualified_tool(name: str) -> Path:
    xcrun = Path(SDK_FROM_XCRUN)
    result = _capture((str(xcrun), "--find", name))
    require(result["complete"] and not result["timed_out"] and result["exit"] == 0 and
            result["stderr"] == "", "TOOL_LOOKUP")
    value = str(result["stdout"]).strip()
    path = Path(value)
    resolved = path.resolve()
    require(value and "\n" not in value and path.is_absolute() and path.is_file() and
            resolved.is_file() and resolved.is_absolute(), "TOOL_LOOKUP")
    return resolved


def _sdk() -> Path:
    result = _capture((SDK_FROM_XCRUN, "--show-sdk-path"))
    require(result["complete"] and not result["timed_out"] and result["exit"] == 0 and
            result["stderr"] == "", "SDK_LOOKUP")
    value = str(result["stdout"]).strip()
    path = Path(value)
    require(value and "\n" not in value and path.is_absolute() and path.is_dir(), "SDK_LOOKUP")
    return path


def _normalize(value: str, source: Path, build: Path, sdk: Path) -> str:
    # Only inspected strings are normalized; exact token comparison follows.
    result = value.replace(str(source), "${SOURCE}")
    result = result.replace(str(build), "${BUILD}")
    return result.replace(str(sdk), "${SDK}")


def _normalized_map_sha(path: Path, source: Path, build: Path, sdk: Path) -> str:
    return sha256(_normalize(path.read_text(), source, build, sdk).encode("utf-8"))


def _require_cache(build: Path, source: Path, sdk: Path, clang: Path) -> None:
    cache = (build / "CMakeCache.txt").read_text()
    fields = {}
    for line in cache.splitlines():
        if not line or line.startswith("//") or line.startswith("#") or "=" not in line:
            continue
        key_type, value = line.split("=", 1)
        key = key_type.split(":", 1)[0]
        fields[key] = value
    expected = {"CMAKE_HOME_DIRECTORY": str(source / "native/darwin_bootstrap"),
                "CMAKE_C_COMPILER": str(clang), "CMAKE_OSX_ARCHITECTURES": "arm64",
                "CMAKE_OSX_DEPLOYMENT_TARGET": "27.0", "CMAKE_OSX_SYSROOT": str(sdk),
                "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
                "BH_BUILD_DORMANT_PATH_OBSERVER_TESTS": "ON"}
    require(all(fields.get(key) == value for key, value in expected.items()), "CMAKE_CACHE")


def _source_hashes(source: Path, relative_paths: Sequence[str]) -> dict[str, str]:
    result = {}
    for relative in relative_paths:
        path = source / relative
        require(path.resolve().is_relative_to(source) and path.is_file() and not path.is_symlink(),
                "SOURCE_FILE")
        result[relative] = file_sha256(path)
    return result


def parse_depfile(text: str, expected_output: str) -> tuple[str, ...]:
    """Parse one compiler-produced Make depfile, with no secondary targets."""
    require(text.endswith("\n") and not text.endswith("\\\n") and
            "\x00" not in text, "DEPFILE_STRUCTURE")
    logical = text.replace("\\\n", " ")
    require("\n" not in logical[:-1], "DEPFILE_STRUCTURE")
    match = re.fullmatch(r"([^:\n]+):\s+(.+)\n", logical)
    require(match is not None and match[1] == expected_output, "DEPFILE_TARGET")
    try:
        dependencies = tuple(shlex.split(match[2]))
    except ValueError as exc:
        raise GateRefusal("DEPFILE_STRUCTURE") from exc
    require(bool(dependencies) and len(dependencies) == len(set(dependencies)),
            "DEPFILE_STRUCTURE")
    return dependencies


def _depfile_closure(rows: Sequence[Mapping[str, str]], build: Path, source: Path,
                     sdk: Path, clang: Path | None = None) -> dict[str, object]:
    """Bind every compile row to its complete compiler dependency output."""
    build, source = build.resolve(), source.resolve()
    expected = {build / (row["output"] + ".d") for row in rows}
    actual = set((build / "CMakeFiles").rglob("*.o.d"))
    require(len(expected) == len(rows) and actual == expected, "DEPFILE_SET")
    toolchain = clang.parents[2].resolve() if clang else None
    entries = []
    workspace_paths: set[str] = set()
    external_paths: set[Path] = set()
    for row in rows:
        path = build / (row["output"] + ".d")
        require(path.is_file() and not path.is_symlink(), "DEPFILE_FILE")
        dependencies = parse_depfile(path.read_text(), row["output"])
        require(row["file"] in dependencies, "DEPFILE_SOURCE")
        normalized = []
        local = []
        for raw in dependencies:
            dependency = Path(raw)
            require(dependency.is_absolute() and dependency.is_file(), "DEPFILE_PATH")
            resolved = dependency.resolve()
            if resolved.is_relative_to(source):
                require(not dependency.is_symlink(),
                        "DEPFILE_PATH")
                relative = resolved.relative_to(source).as_posix()
                local.append(relative)
                workspace_paths.add(relative)
            else:
                require(resolved.is_relative_to(sdk.resolve()) or
                        (toolchain is not None and resolved.is_relative_to(toolchain)),
                        "DEPFILE_PATH")
                external_paths.add(dependency)
            normalized.append(_normalize(raw, source, build, sdk))
        entries.append({"output": _normalize(row["output"], source, build, sdk),
                        "depfile_sha256": file_sha256(path),
                        "dependencies_sha256": sha256(_canonical_json(normalized)),
                        "dependency_count": len(normalized),
                        "workspace_paths": local})
    return {"rows": entries, "workspace_paths": sorted(workspace_paths),
            "external_sha256": {_normalize(str(path), source, build, sdk): file_sha256(path)
                                for path in sorted(external_paths)}}


def _cmake_source_closure(build: Path, source: Path, sdk: Path) -> dict[str, object]:
    path = build / "CMakeFiles" / "Makefile.cmake"
    require(path.is_file() and not path.is_symlink(), "CMAKE_DEPENDS_FILE")
    text = path.read_text()
    match = re.search(r"^set\(CMAKE_MAKEFILE_DEPENDS\n(.*?)^\s*\)\n", text,
                      re.MULTILINE | re.DOTALL)
    require(match is not None, "CMAKE_DEPENDS_STRUCTURE")
    lines = match[1].splitlines()
    require(bool(lines), "CMAKE_DEPENDS_STRUCTURE")
    dependencies = []
    for line in lines:
        item = re.fullmatch(r'\s+"([^"\n]+)"', line)
        require(item is not None, "CMAKE_DEPENDS_STRUCTURE")
        dependencies.append(item[1])
    require(len(dependencies) == len(set(dependencies)), "CMAKE_DEPENDS_STRUCTURE")
    local = []
    external = []
    generated = []
    for raw in dependencies:
        dep = Path(raw)
        if not dep.is_absolute():
            generated_path = build / dep
            require(generated_path.resolve().is_relative_to(build) and generated_path.is_file(),
                    "CMAKE_DEPENDS_PATH")
            generated.append(generated_path)
        elif dep.is_relative_to(source):
            require(dep.is_file() and not dep.is_symlink() and
                    dep.resolve().is_relative_to(source), "CMAKE_SOURCE_FILE")
            local.append(dep.relative_to(source).as_posix())
        else:
            require(dep.is_file(), "CMAKE_DEPENDS_PATH")
            external.append(dep)
    require("native/darwin_bootstrap/CMakeLists.txt" in local,
            "CMAKE_SOURCE_FILE")
    return {"generator_sha256": file_sha256(path),
            "dependencies_sha256": sha256(_canonical_json(
                [_normalize(raw, source, build, sdk) for raw in dependencies])),
            "workspace_paths": sorted(local),
            "external_sha256": {_normalize(str(p), source, build, sdk): file_sha256(p)
                                for p in sorted(external)},
            "generated_sha256": {_normalize(str(p), source, build, sdk): file_sha256(p)
                                 for p in sorted(generated)}}


def _toolchain_bytes(qualified: Mapping[str, Path]) -> dict[str, dict[str, str]]:
    expected = {"xcrun", "clang", "ld", "otool", "nm", "ar"}
    require(set(qualified) == expected, "TOOLCHAIN_PROFILE")
    return {name: {"path": str(path), "sha256": file_sha256(path)}
            for name, path in sorted(qualified.items())}


def _sdk_link_inputs(sdk: Path, source: Path, build: Path,
                     target_profiles: Mapping[str, object]) -> dict[str, object]:
    apps = [parent for parent in sdk.parents if parent.name == "Xcode.app"]
    require(len(apps) == 1, "SDK_INPUT_PROFILE")
    xcode = apps[0]
    paths = {sdk / "SDKSettings.json", xcode / "Contents/version.plist",
             xcode / "Contents/Info.plist"}
    aliases: dict[str, str] = {}
    for target in TARGETS:
        dependencies = target_profiles[target]["dependencies"]  # type: ignore[index]
        for dylib in dependencies:
            require(isinstance(dylib, str) and dylib.startswith("/usr/lib/") and
                    dylib.endswith(".dylib"), "SDK_LINK_INPUT")
            stub = sdk / (dylib.lstrip("/")[:-6] + ".tbd")
            require(stub.is_file(), "SDK_LINK_INPUT")
            paths.add(stub)
            if dylib == "/usr/lib/libSystem.B.dylib":
                alias = sdk / "usr/lib/libSystem.tbd"
                require(alias.is_symlink() and alias.resolve() == stub.resolve(),
                        "SDK_LINK_INPUT")
                paths.add(alias.resolve())
                aliases[_normalize(str(alias), source, build, sdk)] = str(alias.readlink())
        map_rows = target_profiles[target]["map_rows"]  # type: ignore[index]
        require(isinstance(map_rows, list) and bool(map_rows), "SDK_LINK_INPUT")
        for row in map_rows:
            require(isinstance(row, str), "SDK_LINK_INPUT")
            if not row.endswith(".tbd"):
                continue
            require(row.startswith("${SDK}/"), "SDK_LINK_INPUT")
            stub = sdk / row.removeprefix("${SDK}/")
            require(stub.is_file() and stub.resolve().is_relative_to(sdk.resolve()),
                    "SDK_LINK_INPUT")
            if stub.is_symlink():
                aliases[row] = str(stub.readlink())
                paths.add(stub.resolve())
            else:
                paths.add(stub)
    return {"files": {_normalize(str(path), source, build, sdk): file_sha256(path)
                      for path in sorted(paths)},
            "aliases": dict(sorted(aliases.items()))}


def _manifest(build: Path, source: Path, sdk: Path) -> tuple[list[dict[str, str]], list[dict[str, object]]]:
    path = build / "compile_commands.json"
    require(path.is_file() and not path.is_symlink(), "COMPILE_MANIFEST")
    rows = json.loads(path.read_text())
    require(isinstance(rows, list) and bool(rows), "COMPILE_MANIFEST_MULTISET")
    normalized = []
    for row in rows:
        require(isinstance(row, dict) and all(isinstance(row.get(key), str)
                                              for key in ("directory", "file", "output", "command")),
                "COMPILE_MANIFEST_MULTISET")
        require(row["directory"] == str(build), "COMPILE_DIRECTORY")
        source_path = Path(row["file"])
        output_path = build / row["output"]
        require(source_path.is_file() and source_path.resolve().is_relative_to(source) and
                output_path.resolve().is_relative_to(build) and output_path.is_file(),
                "COMPILE_SOURCE_OUTPUT")
        argv = shlex.split(row["command"])
        normalized.append({"directory": "${BUILD}",
                           "file": _normalize(row["file"], source, build, sdk),
                           "output": _normalize(row["output"], source, build, sdk),
                           "argv": [_normalize(x, source, build, sdk) for x in argv]})
    return rows, normalized


def _link_argv(build: Path, target: str, source: Path, sdk: Path) -> list[str]:
    path = build / "CMakeFiles" / f"{target}.dir" / "link.txt"
    require(path.is_file() and not path.is_symlink(), "LINK_COMMAND")
    return [_normalize(arg, source, build, sdk) for arg in shlex.split(path.read_text())]


def _default_graph(build: Path) -> tuple[str, ...]:
    makefile = build / "CMakeFiles" / "Makefile2"
    require(makefile.is_file() and not makefile.is_symlink(), "DEFAULT_GRAPH")
    entries = []
    for line in makefile.read_text().splitlines():
        match = re.fullmatch(r"all: CMakeFiles/([^/]+)\.dir/all", line)
        if match:
            entries.append(match[1])
    require(len(entries) >= len(PROTECTED) and len(set(entries)) == len(entries) and
            all(target in entries for target in PROTECTED) and
            not any("path_observer" in name for name in entries), "DEFAULT_GRAPH")
    return tuple(entries)


def _nm_symbols(capture: Mapping[str, object], argv: Sequence[str], tool: Path,
                *, defined: bool) -> tuple[str, ...]:
    require(tuple(capture.get("argv", ())) == tuple(argv) and
            capture.get("executable") == str(tool) and
            capture.get("executable_sha256") == capture.get("qualified_sha256") ==
            file_sha256(tool), "NM_PROVENANCE")
    require(capture.get("complete") is True and capture.get("timed_out") is False and
            capture.get("exit") == 0 and capture.get("stderr") == "", "NM_CAPTURE")
    output = capture.get("stdout")
    require(isinstance(output, str), "NM_CAPTURE")
    symbols = []
    for line in output.splitlines():
        if defined:
            match = re.fullmatch(r"[0-9A-Fa-f]+\s+([A-Za-z])\s+(\S+)", line)
            require(match is not None and match[1].upper() != "U", "NM_STRUCTURE")
            symbols.append(match[2])
        else:
            match = re.fullmatch(r"\s*(\S+)", line)
            require(match is not None, "NM_STRUCTURE")
            symbols.append(match[1])
    require(len(set(symbols)) == len(symbols), "NM_DUPLICATE")
    return tuple(symbols)


def _raw_profile_from_image(data: bytes) -> RawProfile:
    """Diagnostic measurement only; never use its result to admit the same image."""
    require(len(data) >= 32, "RAW_STRUCTURE")
    _, _, _, _, ncmds, sizeofcmds, flags, _ = _u32(data, 0, 8)
    require(1 <= ncmds <= 128 and _span(32, sizeofcmds, len(data)), "RAW_STRUCTURE")
    pos = 32
    counts: Counter[int] = Counter()
    shapes = []
    dylibs = []
    dyld = []
    build_versions = []
    for _ in range(ncmds):
        cmd, size = _u32(data, pos, 2)
        require(size >= 8 and size % 8 == 0 and _span(pos, size, 32 + sizeofcmds),
                "RAW_STRUCTURE")
        counts[cmd] += 1
        shapes.append((cmd, size))
        if cmd in (0xC, 0xE):
            offset = _u32(data, pos + 8)[0]
            name = _cstring(data, pos + offset, pos + size)
            (dylibs if cmd == 0xC else dyld).append(name)
        elif cmd == 0x32:
            platform, minos, sdk, ntools = _u32(data, pos + 8, 4)
            build_versions.append((platform, minos, sdk,
                                   tuple(_u32(data, pos + 24 + j * 8, 2)
                                         for j in range(ntools))))
        pos += size
    require(pos == 32 + sizeofcmds and len(build_versions) == 1 and len(dyld) == 1,
            "RAW_STRUCTURE")
    measured = RawProfile(counts, build_versions[0], tuple(dylibs), dyld[0], tuple(shapes), flags)
    parse_macho_bytes(data, measured)  # Structural check; still no admission permit.
    return measured


def _profile_to_json(profile: RawProfile) -> dict[str, object]:
    return {"command_counts": {str(k): v for k, v in profile.command_counts.items()},
            "build_version": [profile.build_version[0], profile.build_version[1],
                              profile.build_version[2], [list(x) for x in profile.build_version[3]]],
            "dylibs": list(profile.dylibs), "dyld": profile.dyld,
            "command_shapes": [list(x) for x in profile.command_shapes or ()],
            "flags": profile.flags}


def _profile_from_json(value: Mapping[str, object]) -> RawProfile:
    counts = {int(key): int(number) for key, number in value["command_counts"].items()}  # type: ignore[union-attr]
    raw_version = value["build_version"]
    version = (int(raw_version[0]), int(raw_version[1]), int(raw_version[2]),  # type: ignore[index]
               tuple((int(x[0]), int(x[1])) for x in raw_version[3]))  # type: ignore[index]
    return RawProfile(counts, version, tuple(value["dylibs"]), str(value["dyld"]),  # type: ignore[arg-type]
                      tuple((int(x[0]), int(x[1])) for x in value["command_shapes"]),  # type: ignore[index]
                      int(value["flags"]))


def measure_candidate(build_root: Path, source_root: Path) -> dict[str, object]:
    """Produce diagnostic product observations; cannot issue a permit."""
    build, source = build_root.resolve(), source_root.resolve()
    require(build.is_dir() and source.is_dir(), "BUILD_OR_SOURCE")
    sdk, clang = _sdk(), _qualified_tool("clang")
    ld, otool, nm, ar = (_qualified_tool(name) for name in ("ld", "otool", "nm", "ar"))
    toolchain_bytes = _toolchain_bytes({"xcrun": Path(SDK_FROM_XCRUN), "clang": clang,
                                       "ld": ld, "otool": otool, "nm": nm, "ar": ar})
    _require_cache(build, source, sdk, clang)
    rows, normalized = _manifest(build, source, sdk)
    core_file = str(source / CORE_SOURCE)
    require(sum(row["file"] == core_file for row in rows) == 1, "CORE_COMPILE_COUNT")
    require(not re.search(r"^\s*#\s*(?:if|ifdef|ifndef|elif)\b",
                          (source / CORE_SOURCE).read_text(), re.M), "CORE_CONDITIONAL")
    depfiles = _depfile_closure(rows, build, source, sdk, clang)
    cmake_sources = _cmake_source_closure(build, source, sdk)
    source_paths = sorted(set(depfiles["workspace_paths"]) |  # type: ignore[arg-type]
                          set(cmake_sources["workspace_paths"]) |  # type: ignore[arg-type]
                          {RUNNER_SOURCE})
    result: dict[str, object] = {"schema": 1, "source_hashes": _source_hashes(source, source_paths),
                                 "depfiles": depfiles, "cmake_sources": cmake_sources,
                                 "toolchain_bytes": toolchain_bytes,
                                 "manifest": normalized, "cache": {"arch": "arm64", "deployment": "27.0",
                                                                      "compiler": str(clang), "sdk": str(sdk)},
                                 "default_graph": list(_default_graph(build)),
                                 "targets": {}, "core_object_sha256": file_sha256(build / CORE_REL),
                                 "archive_sha256": file_sha256(build / ARCHIVE_REL)}
    members_capture = _capture((str(ar), "-t", str(build / ARCHIVE_REL)))
    require(members_capture["exit"] == 0 and members_capture["stderr"] == "" and
            members_capture["complete"], "AR_LIST")
    result["archive_members"] = [line for line in str(members_capture["stdout"]).splitlines()
                                  if line not in ("__.SYMDEF", "__.SYMDEF SORTED")]
    require(Counter(result["archive_members"]) == Counter(
        ("path_observer_core_v1.c.o", "path_observer_os_darwin_v1.c.o")),
        "ARCHIVE_MEMBERS")
    with tempfile.TemporaryDirectory(prefix="po-gate-measure-ar-") as directory:
        extraction = _capture((str(ar), "-x", str(build / ARCHIVE_REL),
                               "path_observer_core_v1.c.o"), cwd=Path(directory))
        require(extraction["exit"] == 0 and extraction["stderr"] == "" and
                extraction["complete"], "ARCHIVE_EXTRACT")
        require(file_sha256(Path(directory) / "path_observer_core_v1.c.o") ==
                result["core_object_sha256"], "ARCHIVE_CORE_PARITY")
    for target in TARGETS:
        image = build / target
        map_path = build / (target + ".map")
        require(image.is_file() and map_path.is_file() and not image.is_symlink() and
                not map_path.is_symlink(), "PRODUCT_ARTIFACT")
        image_bytes = image.read_bytes()
        raw = _raw_profile_from_image(image_bytes)
        dependencies_capture = _capture((str(otool), "-L", str(image)))
        deps = validate_otool_capture(dependencies_capture,
                                      (str(otool), "-L", str(image)),
                                      file_sha256(otool), str(image))
        require(deps == raw.dylibs, "DEPENDENCY_CORROBORATION")
        defined_command = (str(nm), "-gU", str(image))
        imported_command = (str(nm), "-u", str(image))
        defined = _nm_symbols(_capture(defined_command), defined_command, nm, defined=True)
        imported = _nm_symbols(_capture(imported_command), imported_command, nm, defined=False)
        map_rows = [_normalize(x, source, build, sdk)
                    for x in parse_link_map(map_path.read_text())]
        _observer_map_closure(target, map_rows)
        _observer_symbol_closure(target, defined, imported)
        result["targets"][target] = {"image_sha256": sha256(image_bytes),  # type: ignore[index]
                                     "normalized_map_sha256": _normalized_map_sha(
                                         map_path, source, build, sdk),
                                     "raw": _profile_to_json(raw),
                                     "dependencies": list(deps),
                                     "map_rows": map_rows,
                                     "defined": list(defined), "imports": list(imported),
                                     "link_argv": _link_argv(build, target, source, sdk)}
    result["sdk_inputs"] = _sdk_link_inputs(sdk, source, build, result["targets"])  # type: ignore[arg-type]
    return result


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _live_artifacts(build: Path, source: Path, source_paths: Sequence[str],
                    depfile_outputs: Sequence[str]) -> dict[str, str]:
    expected_depfiles = {build / (output + ".d") for output in depfile_outputs}
    require(set((build / "CMakeFiles").rglob("*.o.d")) == expected_depfiles,
            "DEPFILE_SET")
    paths = {"manifest": build / "compile_commands.json", "cache": build / "CMakeCache.txt",
             "default_graph": build / "CMakeFiles" / "Makefile2",
             "cmake_generator": build / "CMakeFiles" / "Makefile.cmake",
             "core_object": build / CORE_REL, "archive": build / ARCHIVE_REL}
    for output in depfile_outputs:
        paths[f"depfile:{output}"] = build / (output + ".d")
    for target in TARGETS:
        paths[f"image:{target}"] = build / target
        paths[f"map:{target}"] = build / (target + ".map")
        paths[f"link:{target}"] = build / "CMakeFiles" / f"{target}.dir" / "link.txt"
    for relative in source_paths:
        paths[f"source:{relative}"] = source / relative
    return {name: file_sha256(path) for name, path in paths.items()}


def _observer_map_closure(target: str, rows: Sequence[str]) -> None:
    core_member = "libbee_hermes_path_observer_v1.a(path_observer_core_v1.c.o)"
    real_adapter = "libbee_hermes_path_observer_v1.a(path_observer_os_darwin_v1.c.o)"
    direct_core = CORE_REL
    real_main = "test_path_observer_real.c.o"
    test_main = "test_path_observer_injected.c.o"
    test_adapter = "path_observer_os_test_v1.c.o"
    if target == REAL:
        require(rows.count(core_member) == 1 and rows.count(real_adapter) == 1 and
                sum(real_main in row for row in rows) == 1 and
                not any(test_main in row or test_adapter in row or row == direct_core
                        for row in rows), "MAP_OBJECT_CLOSURE")
    elif target == INJECTED:
        require(rows.count(direct_core) == 1 and
                sum(test_main in row for row in rows) == 1 and
                sum(test_adapter in row for row in rows) == 1 and
                not any(core_member in row or real_adapter in row or real_main in row
                        for row in rows), "MAP_OBJECT_CLOSURE")
    else:
        require(not any("path_observer" in row or "bh_po_" in row for row in rows),
                "PROTECTED_OBSERVER_EDGE")


def _observer_symbol_closure(target: str, defined: Sequence[str],
                             imported: Sequence[str]) -> None:
    public = "_bh_po_observe_v1"
    if target in (REAL, INJECTED):
        require(defined.count(public) == 1 and
                "_bh_po_test_observe_v1" not in defined and
                not any(name.startswith("_bh_po_os_") for name in imported),
                "NM_OBSERVER_CLOSURE")
        if target == REAL:
            require(not any(name.startswith("_bh_po_test_") for name in defined),
                    "NM_TEST_CONTROL_IN_REAL")
        else:
            require(any(name.startswith("_bh_po_test_") for name in defined),
                    "NM_TEST_CONTROL_MISSING")
    else:
        require(not any(name.startswith("_bh_po_") for name in (*defined, *imported)),
                "PROTECTED_OBSERVER_EDGE")


def admit_build(build_root: Path, target: str, *, source_root: Path | None = None,
                _candidate_diagnostic: bool = False) -> AdmissionResult:
    """Live composite admission of a pinned product image and protected closure.

    No caller-provided profile or receipt can grant a permit. Every call replays
    all checks against physical build artifacts before returning a one-use SHA
    permit. The only execution of an admitted image is ImagePermit.run().
    """
    evidence: dict[str, object] = {"checks": [], "image_pids": [],
                                   "installed_authority": False, "ready": False}
    receipt: dict[str, object] = {}
    permit: ImagePermit | None = None
    try:
        require(target in (REAL, INJECTED), "IMAGE_TARGET")
        profile = (_pinned_product_profile() if _candidate_diagnostic else
                   _reviewed_product_profile())
        require(profile.get("schema") == 1 and isinstance(profile.get("targets"), dict) and
                set(profile["targets"]) == set(TARGETS), "PROFILE_STRUCTURE")
        source = (source_root or Path(__file__).resolve().parents[3]).resolve()
        build = build_root.resolve()
        require(source.is_dir() and build.is_dir() and not build_root.is_symlink(),
                "BUILD_OR_SOURCE")
        profile_sha = sha256(_canonical_json(profile))
        evidence["profile_sha256"] = profile_sha
        sdk, clang = _sdk(), _qualified_tool("clang")
        ld, otool, nm, ar = (_qualified_tool(name) for name in ("ld", "otool", "nm", "ar"))
        qualified = {"xcrun": Path(SDK_FROM_XCRUN), "clang": clang, "ld": ld,
                     "otool": otool, "nm": nm, "ar": ar}
        tool_initial = _toolchain_bytes(qualified)
        require(tool_initial == profile["toolchain_bytes"], "TOOLCHAIN_BYTES")
        _require_cache(build, source, sdk, clang)
        require(profile["cache"] == {"arch": "arm64", "deployment": "27.0",
                                     "compiler": str(clang), "sdk": str(sdk)},
                "TOOLCHAIN_PROFILE")
        source_paths = tuple(profile["source_hashes"])  # type: ignore[arg-type]
        target_profiles = profile["targets"]
        sdk_initial = _sdk_link_inputs(sdk, source, build, target_profiles)
        require(sdk_initial == profile["sdk_inputs"], "SDK_INPUT_BYTES")
        depfile_outputs = tuple(str(row["output"]).replace("${SOURCE}", str(source))
                                for row in profile["manifest"])
        initial = _live_artifacts(build, source, source_paths, depfile_outputs)
        evidence["input_sha256"] = initial
        evidence["tool_sha256"] = tool_initial

        # 1-2: Capture the actual qualified dependency channel and audit raw bytes.
        raw_evidence = {}
        dependency_evidence = {}
        for name in TARGETS:
            image = build / name
            args = (str(otool), "-L", str(image))
            captured = _capture(args)
            dependencies = validate_otool_capture(captured, args, file_sha256(otool), str(image))
            dependency_evidence[name] = {"argv": list(args), "pid": captured["pid"],
                                         "tool_sha256": captured["executable_sha256"],
                                         "stdout_sha256": sha256(str(captured["stdout"]).encode()),
                                         "stderr": captured["stderr"], "exit": captured["exit"],
                                         "complete": captured["complete"]}
            reviewed = target_profiles[name]
            require(tuple(dependencies) == tuple(reviewed["dependencies"]),
                    "DEPENDENCY_PROFILE")
            raw = parse_macho_bytes(image.read_bytes(), _profile_from_json(reviewed["raw"]))
            require(raw.dylibs == dependencies, "DEPENDENCY_CORROBORATION")
            require(raw.sha256 == reviewed["image_sha256"], "IMAGE_SHA_PROFILE")
            raw_evidence[name] = {"image_sha256": raw.sha256,
                                  "commands": [[x.index, x.offset, x.numeric_type, x.size]
                                               for x in raw.commands],
                                  "ncmds": raw.ncmds, "sizeofcmds": raw.sizeofcmds,
                                  "build_version": _profile_to_json(_profile_from_json(reviewed["raw"]))["build_version"]}
        evidence["otool_L"] = dependency_evidence
        evidence["raw_binary"] = raw_evidence
        evidence["checks"].extend(("qualified_otool_L", "raw_binary"))  # type: ignore[union-attr]

        # 3-4: Exact complete manifest/command multiset and pinned source bytes.
        rows, normalized = _manifest(build, source, sdk)
        compile_rows = rows
        expected_rows = profile["manifest"]
        require(normalized == expected_rows, "COMPILE_MANIFEST_MULTISET")
        require(list(_default_graph(build)) == profile["default_graph"], "DEFAULT_GRAPH_PROFILE")
        pairs = [(row["file"], row["output"]) for row in rows]
        require(len(pairs) == len(set(pairs)) and len({output for _, output in pairs}) == len(pairs),
                "COMPILE_MANIFEST_MULTISET")
        require(sum(row["file"] == str(source / CORE_SOURCE) for row in rows) == 1,
                "CORE_COMPILE_COUNT")
        depfiles = _depfile_closure(rows, build, source, sdk, clang)
        cmake_sources = _cmake_source_closure(build, source, sdk)
        expected_depfiles = profile["depfiles"]
        expected_cmake = profile["cmake_sources"]
        require({key: value for key, value in depfiles.items() if key != "external_sha256"} ==
                {key: value for key, value in expected_depfiles.items()  # type: ignore[union-attr]
                 if key != "external_sha256"}, "DEPFILE_PROFILE")
        require(depfiles["external_sha256"] == expected_depfiles["external_sha256"],  # type: ignore[index]
                "SDK_INPUT_BYTES")
        require({key: value for key, value in cmake_sources.items() if key != "external_sha256"} ==
                {key: value for key, value in expected_cmake.items()  # type: ignore[union-attr]
                 if key != "external_sha256"}, "CMAKE_SOURCE_PROFILE")
        require(cmake_sources["external_sha256"] == expected_cmake["external_sha256"],  # type: ignore[index]
                "SDK_INPUT_BYTES")
        require(set(source_paths) == set(depfiles["workspace_paths"]) |
                set(cmake_sources["workspace_paths"]) | {RUNNER_SOURCE}, "SOURCE_CLOSURE")
        evidence["manifest_rows"] = len(rows)
        evidence["depfile_rows"] = len(depfiles["rows"])
        evidence["workspace_source_count"] = len(source_paths)
        evidence["checks"].append("compile_row_multiset_unique_core")  # type: ignore[union-attr]
        require(_source_hashes(source, source_paths) == profile["source_hashes"],
                "SOURCE_BYTES")
        core_text = (source / CORE_SOURCE).read_text()
        require(not re.search(r"^\s*#\s*(?:if|ifdef|ifndef|elif)\b", core_text, re.M),
                "CORE_CONDITIONAL")
        # Full normalized argv equality above includes compiler, flags, SDK,
        # source and output for every row; this also excludes a test core variant.
        evidence["source_hashes"] = profile["source_hashes"]
        evidence["checks"].append("source_bytes_compile_argv")  # type: ignore[union-attr]

        # 5: Archive/core byte parity, including physical extraction.
        core_sha = file_sha256(build / CORE_REL)
        archive = build / ARCHIVE_REL
        require(core_sha == profile["core_object_sha256"] and
                file_sha256(archive) == profile["archive_sha256"], "ARCHIVE_PROFILE")
        listing = _capture((str(ar), "-t", str(archive)))
        require(listing["exit"] == 0 and listing["stderr"] == "" and listing["complete"],
                "AR_LIST")
        members = [line for line in str(listing["stdout"]).splitlines()
                   if line not in ("__.SYMDEF", "__.SYMDEF SORTED")]
        require(members == profile["archive_members"] and
                members.count("path_observer_core_v1.c.o") == 1 and
                members.count("path_observer_os_darwin_v1.c.o") == 1 and len(members) == 2,
                "ARCHIVE_MEMBERS")
        with tempfile.TemporaryDirectory(prefix="po-gate-ar-") as directory:
            extraction = _capture((str(ar), "-x", str(archive),
                                   "path_observer_core_v1.c.o"), cwd=Path(directory))
            require(extraction["exit"] == 0 and extraction["stderr"] == "" and
                    extraction["complete"], "ARCHIVE_EXTRACT")
            extracted_sha = file_sha256(Path(directory) / "path_observer_core_v1.c.o")
        require(extracted_sha == core_sha, "ARCHIVE_CORE_PARITY")
        evidence["archive_core"] = {"core_sha256": core_sha,
                                    "archive_sha256": file_sha256(archive),
                                    "extracted_sha256": extracted_sha,
                                    "members": members}
        evidence["checks"].append("archive_core_parity")  # type: ignore[union-attr]

        # 6: Complete link command, including all protected images.
        links = {name: _link_argv(build, name, source, sdk) for name in TARGETS}
        require(links == {name: target_profiles[name]["link_argv"] for name in TARGETS},
                "LINK_ARGV")
        evidence["link_argv"] = links
        evidence["checks"].append("link_argv")  # type: ignore[union-attr]

        # 7: Indexed link map rows, no observer edge into protected images.
        maps = {}
        for name in TARGETS:
            map_path = build / (name + ".map")
            rows = tuple(_normalize(x, source, build, sdk)
                         for x in parse_link_map(map_path.read_text()))
            _observer_map_closure(name, rows)
            require(list(rows) == target_profiles[name]["map_rows"], "MAP_OBJECT_CLOSURE")
            require(_normalized_map_sha(map_path, source, build, sdk) ==
                    target_profiles[name]["normalized_map_sha256"],
                    "MAP_SHA_PROFILE")
            maps[name] = rows
        evidence["map_objects"] = maps
        evidence["checks"].append("map_object_adapter_closure")  # type: ignore[union-attr]

        # 8: Exact defined/imported closure from qualified nm captures.
        symbols = {}
        for name in TARGETS:
            image = build / name
            defined_args = (str(nm), "-gU", str(image))
            imported_args = (str(nm), "-u", str(image))
            defined = _nm_symbols(_capture(defined_args), defined_args, nm, defined=True)
            imported = _nm_symbols(_capture(imported_args), imported_args, nm, defined=False)
            _observer_symbol_closure(name, defined, imported)
            require(list(defined) == target_profiles[name]["defined"] and
                    list(imported) == target_profiles[name]["imports"], "NM_SYMBOL_CLOSURE")
            symbols[name] = {"defined": defined, "imports": imported}
        evidence["nm_symbols"] = symbols
        evidence["checks"].append("nm_symbol_closure")  # type: ignore[union-attr]

        # 9: Exclusive build storage assumption; rehash all inputs at the end.
        require(_live_artifacts(build, source, source_paths, depfile_outputs) == initial,
                "INPUT_STABILITY")
        require(_toolchain_bytes(qualified) == tool_initial, "TOOL_STABILITY")
        require(_sdk_link_inputs(sdk, source, build, target_profiles) == sdk_initial and
                _depfile_closure(compile_rows, build, source, sdk, clang) == depfiles and
                _cmake_source_closure(build, source, sdk) == cmake_sources,
                "SDK_INPUT_STABILITY")
        evidence["checks"].append("input_stability")  # type: ignore[union-attr]
        if _candidate_diagnostic:
            # Complete read-only gate replay with a pinned candidate. This
            # branch has no permit or launch authority even when all checks pass.
            evidence["candidate_composite_checks_passed"] = True
            return AdmissionResult(False, "CANDIDATE_ONLY_NO_PERMIT", evidence, None, {})
        permit = ImagePermit("real" if target == REAL else "injected", build / target,
                             target_profiles[target]["image_sha256"])
        receipt = {"schema": 1, "target": target, "role": permit.role,
                   "source_root": str(source), "build_root": str(build),
                   "profile_sha256": profile_sha,
                   "gate_source_sha256": file_sha256(Path(__file__)),
                   "image_sha256": permit.image_sha256,
                   "source_hashes": profile["source_hashes"],
                   "artifact_sha256": initial,
                   "checks": list(evidence["checks"]),
                   "nonce": permit.nonce,
                   "issued_utc": datetime.now(timezone.utc).isoformat(),
                   "expires_utc": permit.expires_utc.isoformat(),
                   "installed_authority": False, "ready": False}
        receipt["audit_sha256"] = sha256(_canonical_json(receipt))
        return AdmissionResult(True, "ADMITTED_DORMANT_SOURCE_ONLY", evidence, permit, receipt)
    except GateRefusal as exc:
        reason = str(exc)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, IndexError,
            json.JSONDecodeError) as exc:
        reason = "ADMISSION_INPUT_ERROR"
        evidence["error_type"] = type(exc).__name__
    evidence["refusal"] = reason
    return AdmissionResult(False, reason, evidence, None, receipt)


def audit_candidate_build(build_root: Path, target: str,
                          *, source_root: Path | None = None) -> AdmissionResult:
    """Run all physical checks against the pinned candidate without a permit."""
    return admit_build(build_root, target, source_root=source_root,
                       _candidate_diagnostic=True)
