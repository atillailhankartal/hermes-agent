# A2b dormant FD7 observation

Run `python3 tests/native/darwin_bootstrap/run_a2b.py` on Darwin with the Xcode
compiler. The runner enforces warning-as-error compilation, runs 34 real native
cases and 10 deterministic syscall fault cases, runs the clang analyzer, bounds
build output to 64 MiB with a 20 GiB free-space reserve, and removes its own builds.
CMake is an independent static-library definition; CMake execution is unavailable
on the current validation host.

`bh_a2b_observe_fd7` accepts a **candidate**, unauthenticated absolute path, exact
parent metadata (device, inode, UID, GID, complete mode including file type), and
candidate observations of inherited sockets 3, 4, 6. Socket observations include
kernel socket identity from public `proc_pidfdinfo(pid, fd,
PROC_PIDFDSOCKETINFO, ...)`, descriptor flags and status flags. The helper checks
a bounded, complete sorted inventory of exactly 0–4,6, socket types AF_UNIX /
SOCK_STREAM and existing CLOEXEC on all three inherited sockets **before** opening
anything. This helper requires CLOEXEC already restored by a future native entry;
it does not modify FD6 flags. It does not verify bound/listening state or lineage.

The caller must own a single-threaded, serialized descriptor interval, including
no signal handlers that mutate descriptors. The helper does not establish this
precondition or authenticate the calling process. Within that interval it opens
`/` and each component read-only, directory-only, no-follow, CLOEXEC. Exact
F_GETPATH comparison rejects aliases; no normalization is performed. Observed
ancestor path, device/inode, UID/GID and mode are recorded. No ACL or ancestor
writer policy verifier exists; `acl_policy_verified` is always zero.

The last opened directory is retained at 7 or duplicated with F_DUPFD_CLOEXEC
(minimum 7) without overwriting an occupied descriptor. Only owned traversal FDs
are retired. A final failure retires owned FD7 after recorded vnode identity
readback; mismatched/unreadable identities are retained with an observable
`RETAINED_UNKNOWN` decision. A fresh open whose first metadata read fails remains
owned by the successful open within the serialized interval and is closed once.
A failed close is recorded and never retried. All cleanup decisions and initial /
final inventories are observable, including partial inventories on failure.
A failure may retain an ambiguous descriptor; PAUSED requires safe cancellation.
No pathname is unlinked. FD6 is never duplicated, closed, replaced or transferred.

Vnode metadata and kernel socket identities are observations, **not** proof
against same-object close/reopen ABA. A malicious same-UID process, unsealed
signal handler or competing FD writer violates the caller precondition. The
replacement test substitutes a different object and proves conservative cleanup
only; it is not a proof of OS isolation or continuous lifetime. A caller must not
promote this observation to source authority.

Successful output is only `BH_A2B_FD7_OBSERVED_UNTRUSTED`; the caller owns FD7.
There is no install target or runtime call site, key material, provision channel,
listen, accept, source grant, control frame, READY or guarded action. No installed
entrypoint, Python/model runtime, DB or OS account is changed. Same-UID native
success is synthetic. Fault wrappers live exclusively in the test translation
unit; the ordinary suite links the unmodified production source.

Coverage includes source=7, owned temporary=5, initial extras=5/7/200, missing or
wrong-type inherited slots, CLOEXEC failure, replaced or aliased inherited socket, malformed
and aliased paths, exact parent fields, open/fstat/F_GETPATH failure, replaced FD7
and unrelated-descriptor preservation. FD6 kernel identity and flags are compared
before/after all cases retaining a socket there. A1 four-snapshot, signed root /
final images, separate broker UID, protected ACL/writer policy, root close
barrier and source/pair ACK remain separate unavailable gates. A2a's first
post-bind fstatat failure still needs A2c reconciliation and terminal parent-FD
lifecycle. Full integration and publication remain blocked.
