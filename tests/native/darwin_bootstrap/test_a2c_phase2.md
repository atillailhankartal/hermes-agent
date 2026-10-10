# A2c phase 2: SOURCE_MECHANICS_ONLY

Run `python3.11 tests/native/darwin_bootstrap/test_a2c_phase2.py` on Darwin.
The disposable same-UID native P→A→S→execve(F) path uses production bind,
FD inventory/map, spawn, signal, exec and wait functions. Only the root-only
stage0 drop is replaced by a separately linked fixture. Default non-fixture
stage0 has no installed identity policy and denies its drop; these targets
have no install rules.

S and F are separate fixed executable paths selected at build time. External
libproc probes at deterministic barriers record live PID, start timestamp,
executable path and FD table; the expected live artifact is hashed there.
This proves source mechanics, not signature trust or cross-UID qualification.
S/F internal entry gates check signal policy and FD types; S verifies FD5
CLOEXEC, F verifies exact table before restoring and reading back CLOEXEC on
3/4/6. Extra descriptors are rejected, never silently closed by entry gates.

The suite checks baseline, FD source collision, low/high descriptor exclusion,
both signal attributes (including ignored disposition), omitted close action,
reserved management source rejection, exec failure, full status pipe, full and
closed diagnostic FD2, pre/post-spawn P death, A death, stopped child, report
loss and real ECHILD uncertainty. The last negative uses test-only SIGCHLD
ignore so the kernel auto-reaps; waitpid is not stubbed and uncertainty returns
terminal failure. Every case retains pending journal and bound leaf and denies
restart. Test hooks are compile-time only and absent from normal targets.

Post-spawn loss parks A after exact child ownership, kills/reaps P, then resumes
A and requires zero child-forward audit plus A's exact waitpid result. P also
holds an extra copy of its peer: complete A entry inventory must exclude it.
The nonblocking test-only audit cannot authorize progression or delay exit.
Full/closed audit cases use P's separate exact A reap and external child absence
for terminal proof; they do not claim missing audit is an exact child-wait log.
P's stdout remains drained in these cases.

Expected faults have exact child status checks. A owns and reaps its spawn PID;
it does not search for a new PID after ECHILD. Stopped children receive SIGKILL
only while still unreaped/owned. Lost ownership or bounded reap uncertainty
leaves pending admission blocked. Unexpected harness timeout records evidence
before killing only the fixture's own process group. A-death coverage observes
F's control-loss exit; a dead A cannot provide a child wait receipt.

No instantaneous P-death atomicity is claimed: death can occur between a guard
and the following syscall. A checks again while waiting for child input and
before forward progress; all waits have deadlines. A retains its FD6 aliases
until process exit. There is no root-close barrier, root-close frame, listen,
READY, credential/key/source admission or A2b retirement in this phase. The
outside-interval same-vnode foreign-FD5 counterexample remains expected RED.
Physical signed root→distinct UID and the remaining integration gates are
BEKLET. CMake configuration is unverified when CMake is absent; direct clang
warning-as-error builds and static analyzer are the native gate.
