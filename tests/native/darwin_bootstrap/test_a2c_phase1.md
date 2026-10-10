# A2c phase 1: SOURCE_MECHANICS_ONLY

Run `python3.11 tests/native/darwin_bootstrap/test_a2c_phase1.py` on the A1-pinned
Darwin runtime. C11 warning-as-error builds and clang analyzer run directly;
CMake wiring is separate and must be validated where CMake is available.

This is an uninstalled native P→A fixture, not a launcher exposed to Hermes,
Gateway or a model. The runner pins each native A path at P compile time and
initializes a private disposable journal to SOURCE_FIXTURE_FRESH. P never
creates/reinitializes it: it exclusively locks, replaces with ATTEMPT_PENDING,
fsyncs and reads back before spawning. Pending/missing/corrupt state rejects
restart. Same-UID fixture storage is not signed policy, tamper-resistant state
or power-loss qualification. Protocol epoch is a fixed source-test marker;
private inherited endpoint custody is not an installed authentication claim.

The spawn helper snapshots the full parent FD table within its single-threaded
no-FD-writer caller precondition, closes unrelated child descriptors before
mapping management3, and applies explicit signal defaults/mask. A checks exact
0–3 and signal policy, sets nonblocking/CLOEXEC3, receives bounded fixture config,
and waits for checkpoint-bound proceed. EOF/HUP/error/cancel/invalid or partial
commands are terminal and mirror root.cancelled. Queued input after proceed is
rejected, not interpreted as another permission. A checks channel state again
immediately before actual bind and guards again after successful readback. A
post-check parent death can race the next syscall; the guarantee is no progress
after observed loss, not atomicity with death. Polling has a fixed two-second
monotonic deadline; stopped processes/kernel stalls are external uncertainty.

Real bh_a2a_root_bind_observe executes on a same-UID private path. Only the fault
binary substitutes fstatat at its first post-bind readback; bind/FDs/A1 are real.
No root predicate or stage0-drop substitute exists in this phase. On uncertainty
A retains6/parentFD, attempts one optional nonsecret status on management3,
and uses _exit: no root_cancel, unlink, retry or callbacks in that terminal path.
Successful bind exits0 after its guarded checkpoints; P reports only
BOUND_OBSERVED_SOURCE_ONLY after actual waitpid(exit0) and both checkpoints. A spawns
no children, never retires aliases for a final broker, and never listens.

The test checks actual exit/reap (or observed disappearance after actual P death),
leaf presence before fixture teardown, exact journal bytes, and restart denial.
Ten cases cover baseline, pre/post-bind P death, cancel, stale epoch, management
shutdown, queued cancel, timeout, partial command and first-readback failure.
A performs no stdout/stderr/stdio writes at entry, failure or success. Its optional
terminal status uses one `send(MSG_DONTWAIT | MSG_NOSIGNAL)` on existing FD3, with
no retry, poll, ACK or success dependency before `_exit`. Closed/full/invalid3
can lose status; P cannot treat a missing/partial status as permission. P prints
received status only as supplemental evidence, while real waitpid/exit, journal
and socket-leaf assertions are the oracles. This is not an installed service or
logging interface. The harness removes its own private namespace
only after assertions, as disposable test teardown; no runtime cleanup authority
for an unknown leaf is implied. A failed test does not clear runtime pending.

`--red` selects the prebind-loss regression. The preserved pre-fix evidence has
compile0/run1: loss handling incorrectly continued and actually bound a leaf.
The maintained test now passes through the corrected production guard.

A1/A2a/A2b remain unchanged. The same-vnode foreign FD5 counterexample remains
valid outside A2b's no-writer precondition; no OFD or physical-seal proof is made.
S/F, two-image exec, root drop, after-spawn/pre-frame guards, immutable signed
release/ACL/debug/loader closure, durable installed latch, source/pair ACK and
final-only listen/READY are absent. Full A2c and INSTALLED_QUALIFIED remain BEKLET.

## Fix1: unread output cannot hold exit

Six extra subprocess cases retain an OPEN, UNDRAINED pipe reader outside P,
so P death cannot unblock A's old write with EPIPE. Only A inherits this stdout;
P restores its own captured stdout immediately after spawn. Cases cover full
stdout at A entry and after checkpoint1, prebind P death, first-post-bind fstatat
failure, successful source-only exit, and a saturated FD3 status queue with full
stdout. A must exit itself within the three-second external bound; P timeout
kill or harness rescue is failure. Original ten scenarios remain unchanged in
meaning. Terminal status under parent death is intentionally unavailable; actual
process disappearance and retained/absent leaf and pending restart denial are
checked instead. P's successful waitpid report includes the actual exit code.

`--stdout-red` selects these adversarial cases. The preserved pre-fix source
compiled0/run1: A hung with full FD1, parent timed out/killed it or the failure
harness cleaned it up. GREEN requires no rescue; optional status drops when3
is full and A still exits20. No A stdio write exists in the corrected path.
