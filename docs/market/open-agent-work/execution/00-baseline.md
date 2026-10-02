# Funded-work baseline

Recorded 2026-09-14. This is the executed first slice of
**Chio: A Peer-to-Peer Economy of Verifiable Work**.
Start with [escrow fit](01-escrow-fit.md), [contract draft](02-contract-draft.md),
[comparison draft](03-preregistration.md) and the machine-readable
[results and log hashes](04-results.json).

## Candidate source and included changes

Original source: `/home/connor/backbay/arc`, branch `paper/roadmap-phase-0-1`,
HEAD `2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`. The initial checkout had
78 modified tracked files and 3,610 untracked files, represented by 123 short
status entries. A worktree at HEAD alone would omit the research implementation.

Execution uses `/home/connor/backbay/arc-funded-work`, branch
`research/funded-work-baseline`. Its source-input checkpoint is
`ec9189e79c545eb30b783cafaa1e1bc67aa6bfeb`; the exact two-fixture dependency
repair is `905583e951b66db2a3223afffad9dc5de5b0ef5f`. The new model and escrow
characterization are separate from those baseline commits.

The [source ledger](00-source-inputs.json) records all 3,688 original dirty
paths, SHA-256 hashes, selection and exclusion reasons. It selects 494 source
inputs: the research native dependency changes; federated, composed and outcome
examples; the program and paper-home documentation; review reports; report-35
public evidence; and two report-30 public fixtures used by the Python suite.
It excludes unrelated adapter/Hermes edits, the separate technical-paper edits,
formal Lean edits and large unrelated evidence campaigns. No private run-state
directory is copied into the repository.

The [candidate inventory](00-candidate-inventory.json) freshly hashes all
163 workspace-member manifests, 142 functional crates, three standalone research
manifests and the 82 previously reviewed source files. All match that source
inventory. It records declared features/test targets and this run's selection;
manifest coverage is not a security audit of every crate. Root Cargo tests do
not select the three standalone workspaces. This run explicitly selects
`examples/federated-work`; the composed/outcome examples are retained but not
freshly executed or qualified for the new funding semantics.

The active security source is still `8738bdfd7be8c43a0543ca0ce468541529c47add`
on draft [PR #1117](https://github.com/bb-connor/arc/pull/1117), refreshed as open
and blocked. Its working `m4-local-acceptance.md` explicitly says final
qualification is in progress and M4 cannot close on current evidence.
Optional process [PR #1131](https://github.com/bb-connor/arc/pull/1131) remains
open/draft at `75d664822abf5f6e8da6e6f858cab5a6d81dc3bd`, with merge state dirty.
The exact refresh records are retained with the results. Neither is a selected
qualified M4 checkpoint yet. Both active worktrees remain untouched by this work.

Native integration must start from the eventual committed, reviewed Security
M4 checkpoint in another isolated candidate and forward-port the checkpointed
paper behavior. Preserve the [existing synchronization map](../09-security-roadmap-sync-review.md):

- The research runtime's version 10 is not security's historical version 10;
  security's current lineage reaches 34. Check schema ownership and predecessors,
  preserve original rows/unknown effects and reject unsupported migrations.
- Replace research unsigned manifest construction through the verified A2A
  constructor, with explicit profile and session restoration. No bypass imports.
- Preserve committed caller start before effect, retained signed reports and
  late-report finalization without re-admission. Financial successors cannot
  rewrite terminal execution uncertainty or fabricate historical custody.
- Port unknown-payment and checked-output-release behavior with their native
  tests; preserve the original hold and negotiated delivery contract.
- Reconcile optional process hosting only after choosing it; current conflict
  and ordinary-host evidence do not qualify enforced flow. Preserve the
  executor's 64-operation custody limit until sustained retention is implemented.

The earlier review records nine dirty semantic conflicts in the paper/security
route, 13 for the process/security comparison and 153 in legacy #1029. Those
are timestamped review inputs, not a fresh merge rehearsal in this execution.
Do not merge #1029 as a shortcut. Actual combined-source reconciliation and
qualification remain P40/P53/P55 gates before native funded admission.

## Historical evidence used

[Report 35](../../../papers/review-2026-09/35-bounded-intercompany-subcontracts.md)
and its public evidence are preserved. Its manifest SHA-256 is
`87de3a065fe13af801997b60d8983672d41175112b26c4b873cfe5af59554b8b`.
Historical counts are not substituted for fresh test results. The two retained
report-30 files are `paid-normal-public.json` and `paid-corrupt-report-public.json`;
the independent Python tests use them directly. Their bytes were copied from
the original checkout without regeneration.

The current review/inventory and security snapshot retain provenance for source
and integration decisions. New execution results supplement them and do not
rewrite their historical manifests or expand their qualification claims.

## Current environment and reproduction commands

Host: Linux `6.17.0-1020-oracle`, aarch64. Rust `1.94.1`; standalone model
Python `3.13.13`; locked buyer environment Python `3.12.3`; Node `24.16.0`.
Contracts use their unchanged lockfile: ethers `6.16.0`, Ganache `7.9.2`, solc
`0.8.30`. The shared pnpm launcher had an incomplete cache, so execution used
Corepack `0.35.0` with task-private pnpm `12.4.1`. No shared cache or lockfile
was repaired or changed.

These are the invocations used from the isolated repository root. All generated
state is under `/tmp/chio-funding-execution-mfkbfx6y`; use a fresh private
directory on a later run and retain the equivalent command record.

```sh
umask 022
uv venv --python /usr/bin/python3 /tmp/chio-funding-execution-mfkbfx6y/python-env
uv pip sync --python /tmp/chio-funding-execution-mfkbfx6y/python-env/bin/python --require-hashes --index-url https://pypi.org/simple examples/federated-work/python_buyer/requirements.txt
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=target cargo build --locked --offline --manifest-path examples/federated-work/Cargo.toml
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=target cargo test --locked --offline --manifest-path examples/federated-work/Cargo.toml
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=target cargo clippy --locked --offline --manifest-path examples/federated-work/Cargo.toml --all-targets -- -D warnings
python3 -B examples/federated-work/paid_smoke.py --binary target/debug/chio-federated-work --output /tmp/chio-funding-execution-mfkbfx6y/paid-run
python3 -B examples/federated-work/smoke.py --binary target/debug/chio-federated-work --output /tmp/chio-funding-execution-mfkbfx6y/negotiation-run
/tmp/chio-funding-execution-mfkbfx6y/python-env/bin/python -B examples/federated-work/subcontract_smoke.py --binary target/debug/chio-federated-work --python-env /tmp/chio-funding-execution-mfkbfx6y/python-env --output /tmp/chio-funding-execution-mfkbfx6y/subcontract-run
/tmp/chio-funding-execution-mfkbfx6y/python-env/bin/python -B -m unittest discover -s examples/federated-work/python_buyer -v
python3 -B -m unittest discover -s examples/funded-work-model -p 'test_*.py' -v
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=target cargo test --locked -p chio-store-sqlite --test finding_pool_ledger -- --list
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=target cargo test --locked -p chio-store-sqlite --test finding_pool_ledger -- --test-threads=1
COREPACK_HOME=/tmp/chio-funding-execution-mfkbfx6y/corepack corepack pnpm@12.4.1 --dir contracts install --frozen-lockfile
node --test contracts/scripts/funded-work-fit.test.mjs
CHIO_F1_REQUIRE_TIMELY_CLAIM=1 node --test --test-name-pattern='pre-expiry' contracts/scripts/funded-work-fit.test.mjs
```

The final command is an intentional negative calibration and must exit 1 on
the existing contract. All other final test commands above exit 0. The pool
fixture requires an independent device: this host has `/tmp` device 2049 and
`/dev/shm` device 31. These prerequisites were satisfied, not skipped.

## Fresh reproduction results and skipped prerequisites

| Surface | Fresh result | Boundary |
| --- | --- | --- |
| Standalone federated build | Exit 0 | Separate target directory and locked dependencies |
| Standalone Rust tests | 11 passed, 0 failed/ignored | Selected research binary |
| Standalone Clippy | Exit 0 with `-D warnings` | All targets of this example |
| Paid-work smoke | 11 result groups, exit 0 | Local credit and local process namespaces |
| Negotiation smoke | 3 result groups, exit 0 | Negotiation/recovery, no external settlement |
| Subcontract smoke | 10 scenario groups, exit 0 | Includes parent/child crash recovery, hostile worker and disclosure denials |
| Python buyer/verifier | 30 passed | Same project author/host; does not prove company independence |
| Funding model | 6 passed after retained import-failure red run | Serial explanatory authority, not a monetary implementation |
| Existing pool ledger | 38 listed, 38 passed, 0 ignored | Qualified local store/anchor fixture assumptions |
| Existing escrow characterization | 6 passed, 0 skipped | Real bytecode on mock-token dev chain; no work checker or native funding integration |
| Stronger timely-claim promise | Expected failure: paid 0 versus required 100 | Reproducible reason to change the proposed F1 design |

Initial failures are retained: the shared pnpm launcher lacked its distribution;
the buyer suite lacked its two historical fixtures; and default `umask 002`
made temporary store parents group writable, triggering deliberate fail-closed
denials in 30 pool tests. Task-local tool installation, exact fixture retention
and `umask 022` resolved these prerequisites without weakening guards. Ganache's
optional native accelerators were absent; its supported JavaScript fallback ran
the entire selected contract suite.

No selected final test was skipped. Full workspace/security CI, real finality
and reorg qualification, independent hosts, hosted/KVM profiles, stronger
dishonest-administrator attacks, useful W1 scoring and sustained retention were
outside this first-slice run. Nothing here qualifies that unexecuted surface.

## Uncommitted or externally unqualified boundaries

The original dirty checkout and historical evidence are preserved. This branch
contains a reviewable local source checkpoint and new research artifacts; it
has no new PR, remote CI or merge qualification. The escrow source and production
dependency locks are unchanged by the new characterization tests. No new
fund-moving implementation, real funds, external deployment or partner contact
occurred.

The first-slice deliverables are concrete. P01's stronger native adversary,
P40's qualified security integration and the executable parts of P45/P47/P53
remain open. M0/M1/G1 are not automatically complete. Proceed with the
[claim-escrow vertical slice plan](../../../superpowers/plans/2026-09-14-funded-work-claim-escrow.md),
using its native integration gate before touching the funded runtime.
