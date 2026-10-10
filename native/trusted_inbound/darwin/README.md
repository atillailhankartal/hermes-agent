# Dormant Darwin FD6 observer

`bh_darwin_observe_fd6` is linked only into disposable native tests. Its enum
results are **unqualified local observations**, never admission, launch attestation,
READY, or a grant. No Python/FFI/config/installer consumer exists.

The caller exclusively retains descriptor 6 and a directory descriptor throughout
one bounded call. A basename, exact pathname bytes and expected node stat are
consistency inputs, not a trusted manifest. The observer reads OS identity itself,
then brackets each of two self-PID `proc_pidfdinfo` calls with direct FD/type/name,
no-peer, retained-directory and no-follow pathname checks. It never changes flags,
opens/closes a descriptor, listens, accepts, connects, retries or deletes a path.
The result contains only state/reason enums; records, handles and path bytes stay
private. Snapshot equality cannot exclude ABA replacement by a concurrent writer.

## Pins and failure behavior

Build requires the SDK-native 792-byte `socket_fdinfo` layout, explicitly asserted
offsets and `SO_ACCEPTCONN=0x0002`; wrong ABI is a compile failure. Runtime requires
Darwin 27.0.0, macOS 27.0.1 build 26A434 and arm64, read via uname/sysctl. A mismatch
is UNKNOWN. These pins do not qualify the private API, libproc runtime image,
signature, entitlements, protected namespace or cross-UID behavior. OS/SDK updates
require review and new qualification; no permissive fallback exists.

`psi.soi_stat` is deliberately not equated with `fstat(6)`. Pinned Apple XNU
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`, `bsd/kern/proc_info.c` `pid_socketinfo`,
zeros the record; `bsd/kern/socket_info.c` populates socket fields without filling
`soi_stat`. On the local target its dev/inode/mode were measured as zero. That
source observation does not prove shipped-kernel equivalence. Direct descriptor
stat is checked for socket type and stable device/inode/type across all four
snapshots. Filesystem socket stat remains a separate identity, with exact expected
device/inode/mode/owner/group. Libproc agrees with direct family/type and bounded
address, and nonzero opaque handles remain equal between exact-sized reads.
Queue/counter fields and address padding are not identity.

## Verification

From the repository root, with Xcode and an existing system Python:

```sh
python3 tests/native/darwin_bootstrap/verify_fixture.py
python3.12 scripts/check --base HEAD~1
```

The native test includes the C translation unit to exercise its private pure
validator on fully initialized records and adversarial scalar lengths. The product
has no syscall override, injection flag or exported validation backdoor. The
lifecycle fixture separately compiles/links the source, and the Fix4 probe remains
an independent implementation. The verifier checks a 20GiB reserve plus a 64MiB
build allowance before each compile and removes owned temporary binaries.

Signed protected-leaf root-bind/final-UID-listen, Q01/F01/F02, root closure,
exclusive FD lifecycle, immutable launch provenance, source/generation admission
and installed product end-to-end remain separate **BEKLET** gates. This component
cannot authorize activation or weaken those requirements.
