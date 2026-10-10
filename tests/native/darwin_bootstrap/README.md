# Darwin FD 6 feasibility fixture

Disposable native experiment; never run as root. No product broker, launchd,
accounts, installed profile, DB, keys, Docker or service changes are made.

Run with the existing system Python and Xcode toolchain:

```sh
python3 tests/native/darwin_bootstrap/verify_fixture.py
```

The runner compiles two tiny native executables with `-Wall -Wextra -Werror
-pedantic`, uses real spawn/exec/socket calls, checks bounded JSON, and removes its
own build directory. Each fixture creates a unique `/tmp/hermes-fd6-*` directory,
checks recorded pathname device/inode/type before unlink and reaps its child.
Unknown child lifetime or replacement leaves the entry intact. The replacement
negative control records and separately removes only its own replacement inode.
No recursive cleanup is used by the native fixture.

## Two deliberately separate modes

`fixture <3|4|5|6|17|129> <fault> strict` exercises the original socket option
contract. On macOS 27.0.1 build 26A434 / Darwin 27.0.0, AF_UNIX
`getsockopt(SOL_SOCKET, SO_ACCEPTCONN)` returns `ENOPROTOOPT` (42), before and after
listen. The original positive path is **UNAVAILABLE**; this fixture rejects it
before READY. A passing rejection test does not make that positive path pass.

`fixture <slot> <fault> libproc-observational` is an explicitly selected candidate
experiment. It requires exactly `sizeof(struct socket_fdinfo)` bytes from public
`proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, ...)`, checks AF_UNIX,
SOCK_STREAM and SOCKINFO_UN, then reads `psi.soi_options & SO_ACCEPTCONN`.
`socket_state_probe.c` independently measures bound=0/empty-listener=1/queued-listener=1
on actual FD **6**, requiring exact **792** bytes on the pinned target ABI. Each
state also calls the deliberately swapped public arguments and requires that
result to remain unknown/rejected, with no `F_GETFL` change. FD6 must differ from
socket-info flavor3: accidentally using FD3 would hide the argument-order bug.
The public libproc API takes `(pid, fd, flavor, buffer, size)`; the kernel-internal
helper's argument order is not its public signature. The probe creates no grant
and never accepts the queued client. Both native and Python checks gate the A/B
results, and the runner verifies removal of the probe's owned directory.
This mode does
not amend or approve the protected bootstrap contract. Every result carries
`candidate_only: true`. READY here only describes this disposable socket test;
there are no source grants, pair provisioning, code-signing or incarnation checks.

Faults: `none`, `spawn` (ENOENT), `exec` (ENOENT), `early-exit` (exec succeeded but
no READY), `bad-close` (slot 6 closed after install), `leak` (unexpected FD 200),
`prelisten` (same-UID premature listener), `replace` (inode cleanup refusal).
All intended original sources are saved at distinct CLOEXEC high FDs before
close/dup/close actions, including source=destination=6. Stdio is inherited from
the test runner; child slots 3/4/5/6 are disposable bootstrap/control/status/socket.
The original parent reference closes before stage0 is allowed to exec the final
image. Stage0 and final entry report open/CLOEXEC bitmaps; final exec closes 5.
The parent also independently inspects its remaining socket FDs and reads client
peer UID. Path and descriptor stat evidence are separate; inode equality is not
assumed. Directory mode 0500 proves an ordinary bind denial in this test, **not**
resistance to a malicious same-UID owner capable of chmod.

## Evidence and open gates

The six unittest methods include collision and failure subcases. The original
strict-path RED is retained separately. Source-bound Bee QA may run this runner;
Bee C# analysis does not cover C. The Hermes pytest runner is unavailable with the
existing system Python 3.9 (`tomllib` missing); no packages are installed here.

Cross-UID root-bind/final-UID-listen and root-listen cached-credential negative
controls are **UNAVAILABLE**, never inferred from same-UID tests. No privileged
mode exists in this fixture. An authorized administrator needs a separately
reviewed cross-UID extension after the libproc observation contract is reviewed.
Full F01–F08, original N01–N16, protected-host isolation and product acceptance
remain open, including allocation/identity failures, ancillary input, revoke,
restart and source-fenced admission. Do not promote this experiment to a service.

Primary source: Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`,
[`socket_info.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/socket_info.c)
and [`uipc_usrreq.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_usrreq.c).
The pinned source is supporting provenance; the observed host is a newer kernel.
