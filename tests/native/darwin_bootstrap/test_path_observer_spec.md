# Dormant Darwin path observer test contract

Design source: `DESIGN-v6.md` SHA256 `4272921bc5540469715f0d33161ef4c4b7b9593e9c9558a559b35dc2401742cd`, especially lines 11–113 and 192–223. Source baseline: Hermes `3b22eadc95dd86c9a90c9dbadd7142ccfaffa45a`. This is a TDD specification; the C product header/core are absent at initial RED. Each executable accepts exactly one named case and returns 0 only after direct assertions. `test_path_observer.py --plan` is the pinned, nonempty 28-invocation inventory. A plan is not an execution claim.

| Case | Real image | Injected image | Required observation |
|---|---:|---:|---|
| `args` | yes | yes | NULL result/request and malformed ABI, size, count, byte lengths, total, names, kind, reserved, boolean; no OS calls for invalid input |
| `alias` | yes | yes | fixed-size snapshot survives same-start and both aligned partial overlaps; defined fields equal nonoverlap; false flags |
| `fd` | yes | yes | negative/AT_FDCWD/closed/non-directory borrowed FD typed refusal; caller FD unchanged |
| `raw-metadata` | yes, root | yes, root and leaf | captured dev/inode/type/uid/gid/mode/nlink matches actual fstat despite real ACL early stop |
| `ordinary-acl-enoent` | yes | no | actual plain local directory ACL NULL/ENOENT yields UNAVAILABLE/ACL_UNKNOWN and explicit ACL state |
| `empty-contract` | no | yes | owned `acl_init(0)` objects validate empty; full chain OBSERVED_UNTRUSTED, never installed authority |
| `acl-present` | no | yes | present ACL entry rejected without allow/deny interpretation |
| `acl-errors` | no | yes | NULL errno variants, acl_valid and first-entry failures unavailable; no empty promotion |
| `symlink-intermediate` | no | yes | real symlink rejected before open of target descendants |
| `symlink-leaf` | no | yes | real file/dangling links rejected; race renames original to `saved`, then inserts a valid `leaf -> saved` symlink; O_NOFOLLOW maps REPLACED with ELOOP/ENOTDIR, zero successful leaf opens, one root ACL fetch, retained inode/mode/owner/size and sentinel content unchanged |
| `type` | no | yes | actual FIFO/socket and intermediate/leaf type mismatches rejected before wrong open; type replacement detected |
| `owner-group` | yes | yes | wrong expected UID and GID reject based on actual stat, no chown/root |
| `writable` | no | yes | root/intermediate/leaf group/other write, owner-write forbid, special mode reject; owner-write permitted only when flag 0 |
| `links` | no | yes | actual hard-link regular leaf rejects; directory nlink>=1 allowed; injected zero link count rejects |
| `replace-before-open` | no | yes | actual rename plus replacement before real open detects dev/inode/type mismatch; baseline REPLACED and next ACL call count 0 |
| `replace-after-open` | no | yes | hook replaces namespace immediately before opened leaf's first post-check `fstatat`, after two opened-FD stats and root+leaf ACL fetches; REPLACED on new binding, one successful leaf open, retained original inode/mode/owner/size and sentinel content unchanged |
| `metadata-change` | no | yes | actual mode mutation after first opened-FD stat detected as CHANGED, no retry |
| `root-change` | no | yes | actual root mode mutation between ACL and readback detected as CHANGED |
| `final-sweep` | no | yes | earlier ancestor replacement after leaf observation detected in reverse sweep |
| `cleanup-failures` | no | yes | per-op injected errors clean known resources; synthetic release-then-error returns CLEANUP and no leak; non-release error reports UNKNOWN/no retry, no leak-free claim |
| `descriptor-budget` | no | yes | actual 16-component chain reaches 17 owned FDs maximum; count 17 rejected before OS |
| `no-authority` | yes | yes | every result has installed_authority=ready=0 and no FD/credential/service capability |

Every executable prints `case=<name> status=PASS|FAIL cleanup=PASS|FAIL` followed by diagnostic fields, with empty stderr on a passing case. The Python driver independently pins every case's final outcome/reason pair, the real ENOENT errno, the 17-FD peak, ACL-get counts, the symlink race's zero successful leaf opens, and the pre-open replacement's zero next-call count. It records exact argv, PID, exit, stdout, stderr, image hashes, exact case count and zero skips. For every case it calls the live composite verifier afresh, matches its nine checks, audit hash, role/target/source/image hash and one-use nonce to the permit, then launches only through `ImagePermit.run`. `--admission-file` is a new diagnostic output manifest, never input approval. It must refuse execution until the coordinator's source-bound map/nm/raw Mach-O profile is reviewed and installed; this test runner alone cannot grant image execution permission. Real cases use actual Darwin syscalls only. Injected cases use the same core object through the separate link-time test adapter and perform real filesystem mutations wherever the row says actual.

## Prepared O_NOFOLLOW mutation (execution deferred)

After an independently accepted composite profile for each owned image, create an owned source copy and replace exactly one line in its core: `int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;` with `int flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;`. Assert old-line occurrence count 1, the line-only diff, and mutant compile exit 0. Obtain separate composite admission for the mutant image; a baseline receipt/profile cannot authorize changed source or image bytes. Run only the unchanged injected `symlink-leaf` test via the gate permit. The valid `leaf -> saved` target permits the mutant to open the retained original (`open_success_count=1`, root+leaf ACL fetch count 2); the unchanged baseline oracle requires `open_success_count=0`, ACL fetch count 1, ELOOP/ENOTDIR and `status=PASS`. Mutant test exit must be nonzero with raw stdout/stderr/PID, then restore baseline bytes, re-admit and show GREEN. This mutation has **not** yet been built or executed; no behavioral RED is claimed here.

## Explicit design erratum awaiting owner decision

The frozen v6 `:64–66` orders ACL retrieval immediately after the pre-open/open fstat identity guard. Literal `:221` asks the next syscall after that fstat to fail EIO yet expects `UNAVAILABLE/SYSCALL`. The next syscall is ACL retrieval, whose frozen `:86–91` mapping is `UNAVAILABLE/ACL_UNKNOWN`. The test adapter arms ACL EIO only after physical replacement; baseline must reject REPLACED before that call (`next_call_count=0`), while a guard mutant reaches ACL (`next_call_count=1`, ACL_UNKNOWN/EIO) and fails the unchanged REPLACED assertion. The semantic mismatch is recorded, not silently recast as SYSCALL. No mutation RED or acceptance is claimed until source exists and the owner resolves the erratum.

## Required source and binary admission outside this runner

Before either image launches, the coordinator must establish exactly one physical core compile, identical core object bytes in real archive and injected image, expected adapter only, exact `bh_po_observe_v1` definition once, strict map object table and `nm` closure, raw Mach-O profile and qualified nonempty `otool -L` corroboration. The toy model command counts are not a product profile. A/S/F/preflight closure includes the newly required Phase3 S map. Existing preflight no-policy exit69 and native regressions remain separate gates. `--plan` and the compile-absence RED are no substitute for these checks or behavioral tests.
