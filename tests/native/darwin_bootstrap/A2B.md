# A2b dormant FD7 observation

Run `python3 tests/native/darwin_bootstrap/run_a2b.py` on Darwin with the Xcode
compiler. The runner enforces warning-as-error compilation, runs 34 real native
cases and 18 deterministic syscall fault cases, runs the clang analyzer, bounds
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
(minimum 7) without overwriting an occupied descriptor. Successful traversal
retires owned intermediates only under the caller's sealed-entry precondition;
vnode readback rejects a detected mismatch but cannot prove open-file-description
identity. This success-path dependency remains an unresolved A2c physical gate.

Once any observation fails, every outstanding cleanup candidate is recorded as
`RETAINED_UNKNOWN` and left open. This includes same-vnode independently reopened
FD7, an FD whose very first fstat failed, both sides of a failed traversal step,
and a duplicate allocated above 7 when the desired slot became occupied. No
fstat/F_GETPATH equality is used to authorize error-path close. PAUSED is terminal:
process termination or operator reconciliation must follow; do not retry the
acquisition in this process. A failed success-path close records `CLOSE_FAILED`
and is never retried; it may have closed the descriptor already. The final
inventory records the actual physical table, rather than assuming close failure
means the slot is present. No pathname is unlinked and FD6 is never duplicated,
closed, replaced or transferred. `fd7_installed` records a historical event only.

Vnode metadata and kernel socket identities are observations, **not** proof
against same-object close/reopen ABA. The maintained same-vnode FD7 and first-fstat
FD5 substitution tests violate the declared sealed interval deliberately and
prove conservative error cleanup. They do not prove OS isolation or continuous
lifetime. Success-path retirement still cannot exclude same-vnode substitution
without a proven sealed interval; installed acceptance remains BEKLET. No caller
may promote this observation to source authority.

Successful output is only `BH_A2B_FD7_OBSERVED_UNTRUSTED`; the caller owns FD7.
There is no install target or runtime call site, key material, provision channel,
listen, accept, source grant, control frame, READY or guarded action. No installed
entrypoint, Python/model runtime, DB or OS account is changed. Same-UID native
success is synthetic. Fault wrappers live exclusively in the test translation
unit; the ordinary suite links the unmodified production source.

Coverage includes source=7, owned temporary=5, initial extras=5/7/200, missing or
wrong-type inherited slots, CLOEXEC failure, replaced or aliased inherited socket, malformed
and aliased paths, exact parent fields, open/fstat/F_GETPATH failure, replaced FD7
and unrelated-descriptor preservation. Failure tests independently compare every
final inventory entry and all retained decisions to physical descriptors; close
faults cover no close, completed close, and completed close followed by foreign
slot reuse, with a one-attempt oracle. FD6 kernel identity and flags are compared
before/after all cases retaining a socket there. A1 four-snapshot, signed root /
final images, separate broker UID, protected ACL/writer policy, root close
barrier and source/pair ACK remain separate unavailable gates. A2a's first
post-bind fstatat failure still needs A2c reconciliation and terminal parent-FD
lifecycle. Full integration and publication remain blocked.
