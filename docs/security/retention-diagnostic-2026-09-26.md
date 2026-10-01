# Receipt retention diagnostic

This diagnostic observes the public SQLite receipt store under controlled sync
delay and two deterministic durability gates. It does not identify the cause of
the historical retention hang tracked as #1045.

The harness is the integration target `receipt_retention_liveness`. A wrapper
around SQLite's process-default Unix VFS records sync calls, file locks, WAL
locks and calling threads. A held sync captures its own Rust backtrace; a stall
snapshot includes the lock ledger and Linux thread wait channels. The wrapper
preserves the parent VFS's failed-open cleanup callback. A regression verifies
that an unsuccessful open with an installed method table still reaches `xClose`.

The generated workload retains 24 cases, operation vectors of length 1 through
39, tool and child appends, nonmonotonic aged timestamps, a probe append after
every operation, a checkpoint batch of two, and a rotation cutoff above every
timestamp. It checks successful appends, health after rotations and at the end,
reopen health, and exact disjoint live/archive receipt-ID partitioning. Unlike
the original library property, it uses a fixed seed and runs individual public
calls on observed worker threads. It is a separate diagnostic, not a replacement
for that property.

The two gates hold an append's WAL sync before a queued rotation, and an
archive sync before a queued append. They check queue ownership and recover
the expected receipt partition after release. Completion joins, post-release
flushes and health checks use the step watchdog. An injected non-completing
caller tests that a timeout names the stalled step and emits lock/thread
diagnostics. The injection is explicitly released after the observation so the
regression itself leaves no permanently blocked worker.

WAL write-lock syncs during the workload must belong to the supervised receipt
writer. Bootstrap, caller-side passive checkpoints and connection cleanup are
accounted separately. In particular, `flush_receipt_writes()` can checkpoint
on its caller; observing that sync does not establish an unsupervised receipt
commit. Every sync still counts toward the workload's I/O totals.

## Local evidence

Source base: `414aaea0b1`. Evidence is under
`/tmp/chio-resume-20260926/` on the development machine.

- `j-retention-saved-diagnostic.log` preserves the original three failures.
  Two fixtures assumed receipt labels survived signing as IDs. The workload
  incorrectly classified maintenance syncs as receipt commits.
- `j-retention-lock-classification.log` records all three corrected diagnostics
  passing at zero injected delay: 24 cases, 375 operations, 133 rotations and
  4,135 syncs.
- `j-shim-failed-open-red.log` reproduces the lost close callback.
- `j-retention-delayed.log` records four passing tests with 3 ms added per
  `xSync`: the same 375 operations, 133 rotations and 4,135 syncs. The generated
  loop took 68.266 seconds; the complete target took 71.77 seconds.
- `j-completion-timeout-behavior-red.log` reproduces the unbounded completion
  wait found in independent review. `j-retention-reviewed.log` records all five
  tests passing after repair, in 73.62 seconds with the 3 ms delay. The strict
  Clippy check passed in `j-retention-reviewed-clippy.log`.

Run the diagnostic with:

```sh
CHIO_RETENTION_SYNC_DELAY_MS=3 cargo test --locked -p chio-store-sqlite \
  --test receipt_retention_liveness -- --nocapture
```

The original library property also ran successfully, without an ignore override,
in the 373-test receipt subset on `1e791271dc`. Its present source already uses a
direct 24-case runner; older roadmap language calling it quarantined is stale.
The unchanged original property then passed in 254.69 seconds with a 25 ms delay
interposed on real `fsync`/`fdatasync` calls. The interposer observed 6,837 `fsync`
calls and no `fdatasync` calls during that run. The property used RNG seed
`20260926`. `d-original-retention-slow-sync.json` records the source, copied test
binary hash, interposer hash, command and terminal exit; its adjacent log retains
the test result and syscall counts. `slow-sync-helper-check.log` verifies that
the interposer invokes both real syscalls and adds the configured delay.

These positive results do not account for the historical failure condition or
qualify either million-receipt campaign. Keep the historical issue and those
campaigns as separate acceptance work.
