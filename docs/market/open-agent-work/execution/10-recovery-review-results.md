# Review and durable recovery of funded work

Date: 2026-09-14. Branch: `research/funded-work-baseline`, isolated at
`/home/connor/backbay/arc-funded-work`. Implementation commits:

- `59f1dec0fb4180757ef52c6613ddd7865e5c94b4`: reserve pending custody decisions.
- `db4023876d5a4d113a4b138e79317b1c1c3f5d12`: load pinned verifier source bytes.
- `ceae06b09795883b1b4b8e5c45a42d39d4f4129b`: durable signed-transaction recovery.

The independent funded W0 experiment now survives loss of its payment worker.
An actual SIGKILL at each of four boundaries recovers the original transaction,
hash and nonce, with exactly one included payment. The child case still pays
60 after the parent refunds 100. Review also reproduced and repaired two
existing custody/verifier defects and two new recovery edge cases.

The [manifest](11-recovery-results.json) binds source hashes, commands, actual
outcomes and public evidence. This closes the independent
[recovery plan](../../../superpowers/plans/2026-09-14-funded-work-recovery.md).
It does not complete native funded admission or the independent-company trial.

## Review findings and disposition

| Finding | Consequence before repair | Implemented disposition and evidence |
| --- | --- | --- |
| High: custody quota could consume pending decision space | Later evidence could strand a valid bound claim without a durable acceptance/rejection | Reserve 4096 bytes atomically per pending claim; consume only with decision commit. Reproduced with real custody writes, not a mocked quota |
| High: file hashing did not bind the imported checker | An earlier same-named `review` module certified incorrect output while the genuine file's hash still matched | Load and execute the exact pinned checker/parser bytes; load local dependencies by explicit path. False-acceptance reproduction and subprocess shadow-import tests retained |
| Missing durable payment correlation | A lost broadcast response left no retained authority for deciding what to resend | Persist immutable intent, exact signed bytes, hash and occupied nonce before any broadcast. The worker has no signing key and can send only those bytes |
| Medium: future nonce dispatch | An operation could enter the node's future-nonce queue before its predecessor resolved | Require the live nonce to equal the retained nonce before broadcast; otherwise remain unknown/pending. Failing regression retained |
| Medium: nonce index disagreed with retained record | A corrupt index could conceal an occupied nonce and permit another preparation | Read checks all indexed bindings; new preparation audits all retained records before nonce assignment. Failing read and allocation regressions retained |
| Integration still unqualified | Native source selection would combine different local/PR candidates without a completed M4 gate | Read-only refresh; keep native Tasks 3-4 pending and isolate these independent changes |

The exact known custody v1 layout migrates transactionally to v2 while retaining
objects, claims and decisions. Unknown layouts deny. A full old store that cannot
reserve its pending decisions fails without modifying its original database.
A copy of the earlier real child custody migrated and verified its original
signatures; the original retained v1 database was unchanged. No security or
native runtime store was migrated.

## Recovery mechanism and observed results

The [recovery profile](../../../../examples/funded-work/RECOVERY.md) defines
scope and wire fields. An owner-local SQLite outbox retains one signed type-2
transaction per allocation/action, together with its original nonce. The worker
validates signature, signer, deployment/code, chain/genesis, value, fees, gas and
exact calldata. It checks the original receipt, transaction, canonical block
position and resulting contract state before retaining an inclusion observation.

Observation failure retains uncertainty and occupied authority. A missing old
inclusion never authorizes replacement. Reopening can re-observe or resend only
the original bytes; it cannot request a new nonce or erase the old record.

Every row below used actual Rust W0 output, Python recomputation, signed work
artifacts, reopened custody and real contract bytecode on private Ganache.
Each case includes an actual killed worker, a recovery process and a further
idempotence restart. All four single-payment cases finish with A=900, B=1100.

| Worker interruption and evidence | Durable state after loss | Recovery state | Broadcasts / included transactions | Paid |
| --- | --- | --- | ---: | ---: |
| [Before broadcast](recovery-evidence/before_broadcast.json) | Unknown | Included | 1 / 1 | 100 |
| [After broadcast, before response](recovery-evidence/after_broadcast.json) | Unknown | Included | 1 / 1 | 100 |
| [After observation, before commit](recovery-evidence/after_observation.json) | Unknown | Included | 1 / 1 | 100 |
| [After durable observation](recovery-evidence/after_recorded.json) | Included | Included | 1 / 1 | 100 |
| [Child, after parent refund and broadcast](recovery-evidence/child.json) | Unknown | Included | 1 / 1 | 60 |

The child receives 60 from B's separately deposited funds. Parent refund returns
100 to A. Actual event/state accounting observes 160 deposited, 60 paid, 100
refunded and zero remaining. Final A/B/C balances are 1000/940/60. The parent
never submits work; only the rail worker is killed, not a native parent process.

A separate [standalone child run](recovery-evidence/standalone-child.json) also
exited zero with those exact balances and one payment. Its transaction hash is
`0xd657f223708142abbe3c0f63f9a0fa03328755d059a0da75335873c850a25fa1`.
Private state remains at `/tmp/chio-recovery-execution/retained-child-final`.
A later process reopened its custody and outbox, checked exact retained bytes
and verified signatures. Generated fixture keys are absent from public evidence.
Ganache ended with the run; reopening this database does not re-establish live
chain inclusion.

## Verification and its scope

| Check | Observed result |
| --- | --- |
| Python artifact, custody, journal, verifier and Rust-command boundary suite | 38 passed, zero skips |
| Selected Node contract, legacy escrow, W0 and recovery suites | 37 passed, zero skips |
| Affected W0/recovery suites after the final verifier loader change | 9 passed, zero skips; these are included in the 37, not additional unique tests |
| Standalone child recovery command | Exit 0, real SIGKILL and one included payment |
| Reopen standalone custody/outbox after all worker processes exit | Exact artifacts, signatures, prepared transaction and retained observation match |
| Copied real v1 custody migration | Original signatures retained; original database unchanged |
| Intentionally removed canonical-block hash check in an isolated source copy | Expected exit 1, `Missing expected rejection: block` |
| Syntax and whitespace checks | Python AST, Node syntax and `git diff --check` passed |
| Original checkout preservation | 3,688 snapshotted files/modes, HEAD, branch and status unchanged |

The selected Node total comprises 18 claim-contract, 6 legacy-escrow, 4 existing
W0, 4 recovery-core and 5 W0 crash/child tests. The 37-check run preceded the last
Python loader change; all nine affected cases and all 38 Python tests passed
again on the final implementation. The untouched 118 model-trace replays and
old Rust/buyer suites have their historical evidence in prior reports; they
were not rerun for this Python/Node slice. No native Rust or Solidity source
changed. Core rail tests use synthetic financial certificates to isolate chain
faults; the five crash/child tests use actual W0 artifacts and verification.

Unavailable RPC, chain/genesis/code substitution, mismatched receipts and
transactions, altered canonical block/position, actual snapshot/revert loss of
inclusion, actual reverted transactions, future nonces, byte replacement,
nonce/index conflict and retention exhaustion have focused checks. Intermediate
expected failures and final results are retained. The first standalone retry
used a nonexistent directory and failed before work; creating the required
fresh mode-0700 directory made the documented command succeed.

## What this establishes and what remains

This is a durable local financial outbox for an artifact-only experiment. It
retains authority across actual worker loss, including after a successful send
whose response never reaches the worker. It has 64 permanent operation slots,
logical per-slot byte bounds and no eviction or nonce reuse. It does not reserve
physical disk blocks or supply sustained trial capacity.

The host, interpreter, filesystem, verifier and single private RPC remain
trusted. All roles and synthetic keys share one administrator. Included means
observed private-chain inclusion, not a receipt Merkle proof, public finality or
independent observer agreement. Keyless worker construction is not a native
confinement proof. Reorged observations stay unknown; changed-block reinclusion,
fee replacement and retries after a mined revert require a future explicitly
authorized successor. Cloned databases and malicious owner rollback remain
outside this profile.

## How execution proceeds

1. Select the security agent's committed, qualified M4 checkpoint with its exact
   source and required checks. At the 13:13 UTC refresh, local security HEAD was
   `f1b88451527b2dec7314114b3b1e91cf101312cf`, with a modified acceptance
   report; draft PR #1117 remained at `6bb648b613b44ff5aaf1853768f2747bff166077`.
   The report still said M4 could not close. No merge or integration base was selected.
2. Create a separate integration candidate from that checkpoint. Reconcile the
   divergent schema predecessors, verified manifests/session handling and
   original caller start/report custody in bounded slices. Legacy #1029 remains
   a requirements reference, not the merge base.
3. Bind finalized backing to one actual native admission and original financial
   hold. Carry this outbox's exact-transaction rules into the existing stronger
   settlement proof/finality boundary. Qualify success, rejection, uncertainty,
   authorized financial successors and actual parent tool-process loss without
   a second admission or payment. Map the required Finding/custody facets.
4. Then qualify W1 source repair, independently authored implementation/operators
   and the matched economic trial. The current result supplies useful recovery
   evidence; it does not yet establish a Bitcoin-level contribution or public
   deployment readiness.

The [integration gate](06-native-integration.md) and
[vertical-slice plan](../../../superpowers/plans/2026-09-14-funded-work-claim-escrow.md)
carry those remaining requirements. Original source, historical evidence and
the active security worktree were preserved.
