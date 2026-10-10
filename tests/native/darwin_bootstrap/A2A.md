# Dormant Darwin A2a native source fixture

Run `python3 tests/native/darwin_bootstrap/run_a2a.py` on Darwin. The runner
requires more than 20 GiB free plus a 64 MiB allowance, compiles with
`-Wall -Wextra -Werror -pedantic`, and removes its own temporary binaries.

The 13 source-only cases exercise fresh root FD6 from source slots 3, 4, 5,
6 and 64; a preoccupied sentinel FD6; zero-context cancel preserving stdio;
unexpected inherited FDs; exact
parent/no-follow leaf and A1 bound observation; owned and replacement inode
cleanup; fixed child temp slots and action order; HMAC frame rejection; and
actual `posix_spawn` child FD mapping, synchronous ENOENT, root alias retirement,
then a bounded authenticated close frame. A second real child test cancels on an
invalid child PID, then tries the valid PID and requires FD6 retention, no frame,
and control EOF for the child. Two link-time observer fault cases compile the
same production bind path with a failing A1 observer and require cancellation,
no later close frame, exact-node cleanup, and replacement-node preservation.
The child fixture has a disposable
fixed key for the test. The key is not a product credential.

Local `BH_A2A_OK` means a native primitive advanced. No signed release,
protected root launch, separate broker UID, final FD7 acquisition, pair key,
source ACTIVE, listen, action or product integration is provided by A2a. The
root/child fixture uses a disposable `/private/tmp` leaf and does not qualify
Q01/F01/F02 or installed policy. A2b, protected packaging, source contracts and
cross-UID physical tests remain separate gates.
