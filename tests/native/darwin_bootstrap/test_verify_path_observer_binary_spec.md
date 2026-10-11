# Dormant path observer binary admission contract

Source: frozen `DESIGN-v6.md` SHA256 `4272921bc5540469715f0d33161ef4c4b7b9593e9c9558a559b35dc2401742cd`, sections `CMake and regression isolation`, `Raw Mach-O binary gate`, and `Composite admission phase`. Product scope is `SCOPE.md` SHA256 `ba2a86184b81987ee5ae4bbfff5fff98d031e094fa28f2dc7e87489205b6e23b`. The design's toy `17/18` command counts and segment counts are not product profiles. The gate is a source and test-image inspector; it never grants installed authority.

## Interface and trust boundary

`verify_path_observer_binary.py` has one admission call that takes an exclusively owned CMake build directory and a **reviewed, code-pinned product profile**. Its role is derived from the exact CMake target, source/output manifest and link-map graph, not caller-provided descriptive text. A separate one-use launcher may execute only a matching image SHA after the entire composite admission succeeds. The returned record always sets `installed_authority=0` and `ready=0`. Raw `otool -l` output has no admission input.

The profile is measured from the two actual product test images plus current A/S/F/preflight images, written down for review, and embedded/pinned before any accepted launch. Discovery/measurement mode is diagnostic only and cannot create a permit or execute an image. No profile is learned from an image while admitting that same image. Different Xcode/SDK/deployment or source bytes require an updated review, not an automatic fallback.

The reviewed build-input closure pins the SHA256 of the exact qualified `xcrun`, `clang`, `ld`, `otool`, `nm` and `ar` executables, Xcode/SDK version metadata, every external SDK/toolchain file named by the 39 compiler depfiles, CMake generator external module inputs and **every SDK `.tbd` object row in the seven indexed link maps**, including the implicit `libSystem.tbd` alias and its resolved target. It checks these bytes against the reviewed candidate before admission and rechecks at the end. The contract covers the observed build-input closure; it does not claim a digest of every unrelated file in the Xcode tree. A same-path byte change in any pinned input refuses before a permit.

## Composite checks, all before image execution

1. Qualified absolute `xcrun --find otool` `-L` capture: record tool/argv/PID/exit/complete/stdout/stderr and tool SHA before/after. Require exit 0, empty stderr, nonempty newline-terminated complete stdout; parse exact dependencies and compare to raw Mach-O dylib names.
2. Parse thin ARM64 little-endian `MH_EXECUTE` bytes: checked 32-byte header, command count/size/bounds, numeric command multiplicities, per-command payload extents, exact loader strings, no RPATH/dyld environment/unreviewed command, reviewed product role profile, platform/minOS/SDK/tool tuple. Reject fat, arm64e, truncated, overlapping/out-of-bounds or unknown loader payloads. UUID bytes may vary but command type/shape must match the reviewed profile.
3. Parse the complete `compile_commands.json` multiset with unique source/output; require exactly one core compile, exact pinned source hashes, qualified compiler/SDK/flags/working directory/output and no decision macro/test variant. For every compile row, require exactly one real compiler `.o.d` depfile and no extras. Parse its one target, complete dependency list and source entry; bind each depfile byte SHA and normalized full dependency list digest to the reviewed profile. All 39 compiled translation units' transitive workspace headers, the generated CMake source dependency set and the Python case runner are individually SHA-pinned and rehashed live. Missing/extra/poisoned depfiles or added/omitted local dependencies refuse. Duplicate/missing/extra compile row refuses.
4. Inspect exact normal static archive member list and compare extracted core member SHA256 to the single physical core `.o` directly linked in injected image. No duplicate core or unreviewed member.
5. Parse and compare actual complete normal/injected link argv against role-specific reviewed templates, including archive/object operand, map, image, compiler, SDK, arch and deployment. No free token allowance.
6. Parse each link map's indexed `# Object files:` table until `# Sections:` with contiguous indices, no duplicate rows and exact reviewed role set. Normal image requires archive core+Darwin adapter; injected requires direct identical core+test adapter. Wrong adapter or omitted call refuses. A/S/F/preflight maps, including Phase3 S, must have explicit nonempty observer-free object closure.
7. Capture qualified `nm -gU` and `nm -u` with successful complete empty-stderr results. Exactly one public `bh_po_observe_v1` definition in each test image; exact expected shim/control definitions and imports; no observer/control symbol in protected A/S/F/preflight images.
8. Rehash all image/core/archive/map/manifest/source inputs just before issuing a one-use SHA-bound permit. Changed input refuses; there is no atomic launch-lifetime claim.

The launcher has a single funnel and append-only in-memory PID ledger. A child PID is recorded immediately after process creation, including when later output collection fails. Refused images have zero new image PIDs. Build, `otool`, `nm`, `ar` and diagnostic processes are separately recorded and do not count as image launches. Permit consumption checks target identity and current image SHA and cannot be reused.

## Test-first matrix

| Fixture | Expected refusal | New image PIDs |
|---|---|---:|
| Raw numeric RPATH command, deployment 26, command type swap, `cmdsize=7`, truncated body, bad payload extent | `RAW_*` | 0 |
| `otool -L` stderr, nonzero, empty or unterminated stdout, incomplete capture | `OTOOL_L_*` | 0 |
| Duplicate core compile row, second output, altered source/flag/compiler/SDK, conditional core macro | `COMPILE_*` or `SOURCE_*` | 0 |
| Missing/extra compiler depfile, poisoned path, added/omitted local header dependency, changed CMake source input | `DEPFILE_*` or `CMAKE_SOURCE_*` | 0 |
| Actual `abi_v1.h` bytes copied into test-owned source root, then altered after SHA pin | `SOURCE_BYTES` | 0 |
| Test-owned SDK header, `.tbd`, CMake module or qualified tool copied under same stable path, then altered after SHA pin | `SDK_INPUT_BYTES` or `TOOLCHAIN_BYTES` | 0 |
| Test-owned `libsystem_c.tbd` copied at the same SDK map path, then altered while the map row and image stay unchanged | `SDK_INPUT_BYTES` | 0 |
| Corrupt indexed Object files row, missing S map, normal/test adapter swap, duplicate core/member, archive SHA mismatch | `MAP_*` or `ARCHIVE_*` | 0 |
| Omitted public call or unexpected observer edge in A/S/F/preflight; extra import/definition | `NM_*` or `MAP_*` | 0 |
| Changed source, image, manifest or map after earlier check | `INPUT_STABILITY` | 0 |

The first fixture set uses test-owned synthetic Mach-O/map/manifest data and a fake launcher that increments only if called. It proves parser/refusal ordering but cannot establish product acceptance. A later physical run uses actual built product images, reviewed frozen profile, raw tool captures, source/command evidence and a coordinator replay. Negative variants are built or altered in an owned temporary build and restored; unchanged source hashes and ledger are retained. Assertions check exact reason and zero new image PIDs, not only nonzero exit. Behavioral image tests start only after this gate passes. Default `OFF` and `ON` default build remain observer-free.

## Evidence and cleanup

Retain profile measurement input hashes, reviewed profile hash, source SHA, exact tool identity/argv/capture status, parsed raw command inventory, manifest rows, map tables, nm inventories, admission/refusal order, image PID ledger and test output under the task evidence root. Limit build growth to the checked 256 MiB planning cap with at least 20 GiB free. Remove only this task's inactive reproducible temp builds after evidence is copied; keep the active worktree and source diff. No OS account, DB, Docker, GitHub, install or publication mutation is part of this gate.
