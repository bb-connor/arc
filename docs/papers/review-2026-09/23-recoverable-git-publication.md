# Recoverable publication of checked source

2026-09-13. Continuing the breakthrough objective after
[receiver-owned checking](22-receiver-owned-outcome-checking.md). A replacement
worker can now finish publishing the verified repair, or recover evidence that
it was published, after a crash around the Git reference update. This is a
domain-specific improvement. The independent ledger obtains the same behavior,
and no breakthrough is established.

## What changed

The previous publication sink appended to a log and copied files. A crash after
claiming its logical slot could leave an unknown external effect, so the gate
correctly refused another dispatch. The production runtime still behaves that
way. This experiment adds a separate
[Git adapter](../../../examples/outcome-ledger-comparison/src/graph/repair_git.rs)
with an effect the receiver can inspect and conditionally perform.

The receiver runs the same seven behavioral checks on the real two-file
Git-hook repair from report 21. Candidate Python remains isolated from the
check repositories, publication repositories and receiver keys. Successful
checking precedes trusted provisioning. Each gate checks once; only those exact
source bytes are reused across the crash scenarios. There is no upstream
signing service or live LLM discovering the repair in this experiment.

For each scenario, the receiver prepares a SHA-256 Git commit in a new owned
review repository. Creating objects does not publish a branch. The fixed
publication reference is still absent. A canonical, immutable owner record
binds the checked source artifact, prepared commit, reference and absent
expected value. The receiver signs that complete intent for the existing gate.
Temporary-file persistence, file synchronization and parent synchronization
protect the owner record; Git commands request `core.fsync=all` and the `fsync`
method. These settings are not themselves a power-loss qualification.

Every publication worker is a fresh process with a kernel, receipt store and
fresh capability. Its tool validates the complete intent and the prepared
commit's exact two regular-file paths and source bytes. Initial dispatch claims
the existing gate. It then uses `git update-ref --no-deref` with the pinned
commit and an all-zero expected old value. An existing different commit is a
conflict, and a symbolic reference is rejected. The input cannot choose another
reference, target or source after the owner record is installed. The experiment
never applies the repair to the operator's source checkout or pushes a remote.

## Recovery does not recreate a generic permit

On restart, the Git adapter compares the persisted claim with the exact
authorization for its immutable intent. The ledger gained a read-only view of
the evidence and effect consumed by a job; Chio already exposes claim identity
in its status type. Neither view constructs a dispatch permit, resets a slot
or marks it complete.

If the reference already names the intended commit, the adapter verifies the
tree and returns a fresh signed observation. If it is absent, the adapter
attempts the same conditional creation. Concurrent workers can converge on
that one reference transition. They cannot append to an ordinary sink using
this recovery route. A changed reference or unavailable target object produces
denial. The adapter checks live Git state even when an earlier observation
file exists.

The distinction between the two results is deliberate:

| State | Meaning |
| --- | --- |
| Gate `completed` | The worker retained its original permit and recorded its result normally |
| Gate `claimed`, Git observation present | The permit was lost; a replacement independently observed the fixed Git publication |
| Gate `claimed`, no Git observation | Publication remains unobserved or conflicted |
| Gate `waiting`, revoked | No new claim or Git publication is allowed |

The separate `git-observation.json` and signed kernel reply contain the intent
hash, source artifact hash, reference and observed commit. They do not pretend
the generic gate completed, and are not automatically exported through the
previous graph's completed-slot API. A downstream consumer would need to
explicitly support and verify this domain observation.

A claim accepts this specific conditional operation. Revocation before claim
prevents it. Revocation after claim prevents fresh claims but cannot cancel
the already accepted operation, which may already have happened. Both cases
are exercised. This is an explicit adapter contract, not a new cancellation
guarantee for the runtime.

## Retained observations

The [comparison](evidence/23-recoverable-git-publication/git-repair-comparison.json)
contains twelve scenarios for each gate. Each pair has identical observations.

| Scenario | Git publications after recovery | Final gate state |
| --- | --- | --- |
| SIGKILL before claim | 1 | `completed` |
| SIGKILL after claim, before reference update | 1 | `claimed` |
| SIGKILL after reference update, before result | 1 | `claimed` |
| SIGKILL after completion | 1 | `completed` |
| Eight recovery workers after claim | 1 | `claimed` |
| Revocation after claim | 1 | `claimed` |
| Changed source or changed target | 0 | `claimed` |
| Conflicting direct or symbolic reference | 0 | `claimed` |
| Missing prepared commit object | 0 | `claimed` |
| Revocation before claim | 0 | `waiting` |

The run injects 22 actual SIGKILLs at observed checkpoints and checks the exit
signal. Four boundaries are tested independently per gate; additional attack
and race cases also kill a worker after claim. Sixteen recovery contenders
race across the two backends. Repeated fresh workers preserve each case's
outcome and gate state. For denials, the complete reference inventory is
compared before and after invocation so a symbolic reference cannot redirect
a write into an unrelated branch unnoticed.

The two receiver checks execute fourteen real Git commit cases, all passing
without hook markers. The twelve successful scenario/backend pairs each have
one publication entry in the retained reflog. Reflogs are instrumentation under
the trusted-owner model, not tamper-proof proof of execution. Every successful
result also requires a fresh reference read and exact source comparison.
Changed argument and signed-evidence identities fail the persisted-claim
comparison. No candidate execution is repeated during publication recovery.

## What this assumes, and what it does not establish

The owned reference must not be deleted, reset or independently repurposed.
An absent reference after external deletion can look like an operation that
never ran, so this adapter does not establish protection against that history
or ABA transitions. Store rollback, cloned receiver authority and malicious
operators are likewise outside the model. Compare-and-swap does not solve
those problems by itself.

Crashes occur at observed boundaries around completed Git commands. This run
does not kill Git inside its reference transaction, test stale lock recovery,
crash the host or simulate power loss. It does not establish atomicity between
SQLite, Git and the observation file. It instead verifies whether this fixed
effect happened using Git state. Ordinary non-deduplicating append effects
remain uncertain after permit loss in the unchanged earlier regression.

Candidate execution still has the finite-contract and aggregate-resource
limits described in reports 20 through 22. Receiver code, checker, gate store,
Git implementation, host kernel and operator remain trusted. There is no
independently administered receiver, remote Git transport, production service,
market settlement, publication activation or integration-cost measurement.
The private receiver workers run on the host; the candidate and Git subprocess
mount boundaries reuse the earlier sandbox. This is not a new qualification of
all receiver roles under mutually hostile administration.

## Prior art and judgment

Git documents conditional reference updates against an expected old object
identifier, including creation only when the reference is absent. It also
documents separate creation of a commit from a tree. This experiment composes
those existing operations; it does not invent conditional publication.
[Git update-ref](https://git-scm.com/docs/git-update-ref),
[Git commit-tree](https://git-scm.com/docs/git-commit-tree).

Git's configuration documentation distinguishes hardened repository components
and warns that unsynchronized data can be lost on unclean shutdown. Explicit
fsync settings narrow a configuration assumption; they do not substitute for
crash testing the actual filesystem and storage stack.
[Git configuration](https://git-scm.com/docs/git-config).

RIFL, published at SOSP 2015, requires operation effects and completion records
to become durable atomically for its general exactly-once RPC mechanism. It
also shows why retrying an idempotent write can violate linearizability when
another writer intervenes. We read the primary paper but have not reproduced its
implementation or timing results. Our separate SQLite and Git stores do not
provide RIFL's atomic completion mechanism; the exclusive-reference assumption
is material. [RIFL](https://web.stanford.edu/~ouster/cgi-bin/papers/rifl.pdf).

The useful result is that a verified repair can reach an observable Git
publication despite the tested worker crashes and handoffs. The strongest
objection to a breakthrough claim remains decisive: the same established Git
primitive supplies the same benefit to the ordinary ledger under the same
assumptions. No uniquely enabled capability or reduction in trusted operators
has emerged here. A stronger result needs a workload and measured operational
advantage that survive an equally capable alternative, or a mechanism that
removes a trust assumption the alternative retains.

## Reproduction and validation

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair-git-recovery examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .
CARGO_TARGET_DIR=target cargo test --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml
CARGO_TARGET_DIR=target cargo clippy --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml \
  --all-targets -- -D warnings
```

An optional final argument selects a new output directory. Linux, bubblewrap,
Git with SHA-256 repository support and the prior Python checker prerequisites
are described in the [experiment README](../../../examples/outcome-ledger-comparison/README.md).
The local Git version is 2.43.0. Offline Cargo needs cached dependencies.

Final validation results and source/artifact hashes are recorded in the
[evidence manifest](evidence/23-recoverable-git-publication/manifest.json).
All six integration tests passed in 86.71 seconds. The whitepaper builds at
12 pages and 4,960 body words. All-target Clippy, Rust formatting and diff checks
pass. The suite retains all five earlier comparisons. No
production runtime implementation, Python repair source, dependency manifest
or lockfile changed in this continuation. The work remains local and
uncommitted on `paper/roadmap-phase-0-1`, based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`, without exact-commit CI or release
qualification.
