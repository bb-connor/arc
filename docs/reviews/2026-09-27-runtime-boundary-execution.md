# Runtime boundary execution

Packet 2 continues the integrated signed simulation implementation. This batch
uses one implementer and focused owning targets. Native x86_64 qualification is
separate from implementation and portable verification.

## Production changes

- Cage allowlists and argument constraints use a closed `Syscall` enum. Public
  construction and deserialization validate the same rules used again at launch:
  constraint membership, duplicate syscalls/arguments, argument bounds, forbidden
  process/network authority and self-only `prlimit64`. Invalid plans cannot be
  constructed through public struct fields. Valid syscall spellings and canonical
  ordering remain unchanged; no compatibility decoder or alias is added.
- Public keyring seed recovery now requires the receipt store before loading the
  rotation. Previously an activated selector with an unfinished seed handoff
  called receipt confirmation before a sink could be attached, making that
  restart path fail. Trust-service and process-host initialization now supply
  the durable sink up front. Startup resumes only a persisted seed handoff and
  never invents a new rotation.
- Readiness rechecks the current durable head, receipt completion and fresh
  signed observations from the independent services. It refuses incomplete
  rotations and a missing receipt sink. Genesis is the sole witnessed-only
  ready state. Changed heads or overlapping durable storage identities reject.
- Discovery carries one deadline through cage launch and the complete MCP
  exchange. The explicitly unconfined demo path is named for its actual mode;
  privileged discovery still requires cage enforcement.

## Owning regressions

- The public keyring fixture runs three witness and two auditor executables. It
  interrupts active-receipt forwarding, kills an auditor, checks that failures
  preserve the original seed and pending handoff, then reopens through the public
  loader and requires the exact original activated epoch and checkpoint.
- Simulation uses the existing real kernel/planner/SQLite fixture in an owned
  subprocess. A socket barrier identifies the precise point before SIGKILL.
  Recovery opens the existing stores and observes the durable retry schedule.
- Credential disable/delete races pause after materialization and inside the
  actual dispatch commitment closure. The tests assert both mutation-first
  refusal and commit-first exclusion under the production mutation fence.
- The new native discovery target launches the real privileged CLI, observes
  UID/GID/supplementary groups through `/proc`, then releases its peer. It requires
  Landlock denial of a world-readable ungranted host file, seccomp denial of
  process creation, the shared deadline and eventual process reaping.
- x32 and foreign i386 syscall probes use otherwise allowed low syscall numbers
  and require SIGSYS. Both probes and the typed-plan cases enter the mandatory
  cage inventory: 78 all-target tests, including 29 real enforcement tests.

| Process cut point | Last durable state | Recovery contract |
| --- | --- | --- |
| Before report append | Plan/artifact binding and next retry time | Revalidate authority and create one advisory report when retry is due |
| After report append | Exact signed report; incomplete planning outbox | Read back that report and finish `Simulated`, without fresh live authority |
| During report recovery | Same committed report; incomplete planning outbox | Resume the same evidence after the persisted retry time |

All simulation cases require zero live effects, dispatch identities, approval
reservations and budget captures. The original process-recovery failure is
retained: its frozen clock had not reached the persisted retry time. The fixture
now advances to that recorded time, without changing production retry behavior.

The existing SQLite lock/deadline, archive authentication/replacement,
SQLITE_FULL, ledger-write failure and emergency-stop replay regressions remain
owning coverage. No duplicate SQL model or disconnected Loom implementation was
introduced.

| Existing broker cut point | Durable commitment and observed effect | Permitted recovery |
| --- | --- | --- |
| After registration | No quota capture; no provider connection | Refuse a second delivery without creating a capture |
| After capture | Original composite capture; no provider connection | Preserve capture and refuse replay |
| After provider effect, before acknowledgement | Original capture; exactly one authenticated provider connection | Preserve that commitment, refuse redispatch and retain the unresolved outcome |

The public keyring interruption has a different commit: the selector already
names epoch 1, but its active receipt has not reached the normal receipt store.
The old seed and exact pending handoff remain until auditors and durable receipt
readback permit installation. Reopening must retain the same head, epoch and
receipt count.

## Verification status

Focused verification completed on unprivileged Linux aarch64 with locked
dependencies, `umask 022`, `CARGO_INCREMENTAL=0`, one Cargo owner and
`RUST_TEST_THREADS=1`. The external target used `CHIO_CHECKOUT_ROOT`.

| Owning target | Terminal result |
| --- | --- |
| Cage typed-plan and launch validation | 5 passed; the new native compiler-boundary case typechecked and is explicitly ignored on aarch64 |
| Control-plane simulation, real process death, native admission races and ledger-write faults | 13 passed; the subprocess entry point is ignored by the top-level harness and explicitly invoked by its parent |
| Broker credential races, three process-death points and public keyring restart | All 6 selected cases passed across the original run and the focused keyring rerun |
| SQLite final-deadline, archive replacement and full-write cases | 29 passed |
| CLI absolute-deadline transport | 2 passed |

These are 55 selected passing cases, not a workspace qualification. The original
combined run retained one keyring fixture failure: it attempted a second reopen
while still holding the recovered runtime's exclusive selector owner. Dropping
that owner before the simulated restart repaired the fixture; production
single-writer enforcement was preserved. The focused rerun passed in 4.46 seconds.

Evidence remains in `/tmp/chio-packet2-focused-final.log`,
`/tmp/chio-packet2-keyring-final.log` and `/tmp/chio-packet2-cli-tests.log`.
The earlier clock, anchor-permission, assertion and compile failures remain in
`/tmp/chio-packet2-runtime-tests.log`, `/tmp/chio-packet2-broker-tests.log`,
`/tmp/chio-packet2-broker-tests-umask.log` and the two
`/tmp/chio-packet2-runtime-build*.log` files.

The native integration target compiled with Cargo. Its final fixture assertions
also passed a direct Rust metadata/type check against those dependency artifacts,
recorded in `/tmp/chio-packet2-discovery-typecheck.log`; this avoided rebuilding
the unchanged CLI binary. Clang compiled the discovery, x32 and foreign-ABI C
probes for x86_64. None of these compile checks executed native enforcement.

The 78-case source inventory and enforcement-stack gate passed. Cage inventory,
cage gate and enforcement-stack checker self-tests passed. Rust file hygiene,
negative-assertion checks, touched-file formatting, shell syntax and diff checks
passed. No size limit or assertion exception was added; four old weak-assertion
exceptions were removed. Source-check logs are
`/tmp/chio-packet2-hygiene-final.log` and `/tmp/chio-packet2-assertions-final.log`.

Privileged x86_64 cage/discovery execution remains required. No full workspace
sweep, independent review, hosted acceptance, M5 closure or operator rollout is
claimed by this batch. The source base is `f25cd61f49`; the implementation branch
is `packet/2-runtime-boundaries`.
