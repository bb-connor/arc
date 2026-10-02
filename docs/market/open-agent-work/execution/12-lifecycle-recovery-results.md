# Complete post-funding lifecycle recovery

Date: 2026-09-14. Implementation:
`331bd1bf8cd347c3b2cc70aaee459894bc5218df` on
`research/funded-work-baseline`, isolated in `/home/connor/backbay/arc-funded-work`.
The [manifest](13-lifecycle-results.json) records source/evidence hashes,
commands, exact outcomes and the current integration rehearsal.

The W0 experiment now recovers claim submission, verifier decision, earned
payment and refund through the same durable outbox. Sixteen runs cover four
scenarios at four actual worker interruption points, totaling 48 SIGKILLs.
Each operation retains its original signed transaction, hash and nonce, with
one broadcast and one included transaction. One hundred later re-observations
return the same evidence with zero broadcasts after contract states advance.

This closes the independent [lifecycle plan](../../../superpowers/plans/2026-09-14-funded-work-lifecycle-recovery.md).
It does not close native Tasks 3-4, public finality or the independent-company
trial. Funding/setup and the orchestration parent still remain alive outside
the worker crash boundary.

## Review and implementation

The prior worker supported several ABI actions, but the real W0 flow routed
only payout through durable recovery. Submission, decision and refunds still
used direct calls. A failing real-W0 regression demonstrated that gap before
implementation. The new `railAction` hook routes those stages through the
existing worker; it preserves the original direct and payment-only modes.

The [generalized harness](../../../../contracts/scripts/work-claim-recovery-harness.mjs)
keeps one private journal per transaction actor. Consecutive seller or relay
actions share the same occupied nonce history. Existing configuration must
match the reconstructed actor, deployment and local paths; the runner cannot
overwrite it to accept a changed scope. A relay may submit the verifier's
already signed decision or request a refund; the contract still fixes who
receives the tokens.

The [lifecycle runner](../../../../contracts/scripts/work-claim-lifecycle.mjs)
recovers each action and then opens additional keyless workers to re-observe
all previous operations against the still-running chain. This checks an
important sequence property: a submission or decision must remain observable
after the allocation becomes Paid or Refunded. Recovery does not require the
old intermediate state to remain current or send the operation again.

No new Solidity, Python journal, native kernel/store or checker semantics were
needed. Existing exact-transaction checks already support the additional
actions. The new [action checks](../../../../contracts/scripts/work-claim-recovery-actions.test.mjs)
exercise their agreement, calldata, commitment, verdict and refund-effect
bindings against actual bytecode and altered RPC observations.

## Actual crash matrix

Every row runs at `before_broadcast`, `after_broadcast`, `after_observation` and
`after_recorded`. These mean, respectively: after durable preparation; after
actual chain broadcast but before response; after observation but before its
commit; and after durable observation but before completion. Only the owned
worker is killed. Recovery and a further idempotence restart use fresh processes.

| Scenario | Durable actions per run | Killed workers across four points | Deposited / paid / refunded | Final A / B / C |
| --- | --- | ---: | --- | --- |
| Accepted W0 | submit, decision, pay | 12 | 100 / 100 / 0 | 900 / 1100 / 0 |
| Rejected W0 | submit, decision, refund | 12 | 100 / 0 / 100 | 1000 / 1000 / 0 |
| Custody unavailable | submit, refund | 8 | 100 / 0 / 100 | 1000 / 1000 / 0 |
| Earned child | submit, decision, parent refund, child pay | 16 | 160 / 60 / 100 | 1000 / 940 / 60 |

Each run uses actual Rust W0 output, Python recomputation, signed agreement,
submission and custody evidence. Rejection retains a signed negative decision.
The unavailable case retains no certificate and refunds through timeout.
The child is still unpaid and Payable when its parent refunds, and its payment
comes from B's separately deposited funds. Every case ends with zero locked
balance; event deltas, contract state and token balances agree.

The [standalone child](lifecycle-evidence/standalone-child.json) separately
executes all four actions with `after_broadcast` loss, then records the same
160/60/100 accounting. Its private state remains at
`/tmp/chio-lifecycle-execution/retained-child`. A later process reopened all
four original signed transaction records across two actor journals, retrieved
actual work bytes and verified artifact signatures without reading private keys.
The ended private chain was not re-observed by that offline readback.

## Validation

| Check | Fresh result |
| --- | --- |
| Existing artifact/custody/journal/CLI Python suite | 38 passed, zero skips; Python source unchanged afterward |
| Lifecycle matrix plus existing W0/recovery/core/claim/legacy suites | 53 Node checks passed, zero skips |
| Added non-payment action substitution suite | 3 passed, zero skips |
| Total selected Node checks | 56 passed |
| Lifecycle-only crash evidence | 16 runs, 48 killed workers, 48 original included transactions, 100 later zero-send re-observations |
| Standalone child lifecycle and later custody/outbox reopen | Both commands exited zero |
| Isolated removal of decision-verdict guard | Expected exit 1: `Missing expected rejection: verdict` |
| Isolated removal of refund-amount guard | Expected exit 1: `Missing expected rejection: amount` |
| Node syntax, Python AST and whitespace | Passed |
| Original source checkout | All 3,688 snapshotted files/modes, HEAD, branch and status unchanged |

The non-payment core tests use synthetic financial certificates to isolate
chain observations. All sixteen lifecycle cases use real W0 verification.
The 53-check suite includes the earlier five payment-only crash tests; their
kills are separate from the 48 lifecycle kills. The standalone four are also
separate. Counts are not added together to inflate lifecycle coverage.
The untouched native Rust workspace, model trace suite and prior buyer suite
were not rerun or requalified by these Node changes.

Logs and public reports are retained under `lifecycle-evidence/`. Trailing blank
log whitespace is normalized only where required by repository checks, with
original hashes retained in the manifest. Generated fixture private keys are
absent from public evidence. Run instructions are in the
[recovery profile](../../../../examples/funded-work/RECOVERY.md#complete-post-funding-lifecycle).

## Integration review and next executable work

Security M4 has advanced: its 14:36 UTC acceptance report says all required
local gates, final documentation review and source-graph refresh passed. This
report was inspected, not independently rerun. Five closeout documentation files
remain modified. Local HEAD is `f1b88451527b2dec7314114b3b1e91cf101312cf`;
draft PR #1117 remains open/blocked at
`6bb648b613b44ff5aaf1853768f2747bff166077`. The acceptance report still lists
hosted MSRV qualification as running and its previous failure unresolved.
No committed M4 closeout or exact-head hosted/review qualification was selected.

A fresh read-only merge-tree compares committed security `f1b8845152` with
research `331bd1bf8c`, using common ancestor
`f5566d9a765c21cb36652a99c79de64968a656bf`. History is not shallow. It reports
nine code conflicts plus generated `docs/formal/COVERAGE.md`; the exact list is
in [the rehearsal record](lifecycle-evidence/integration-rehearsal.json).
The code overlaps cover native terminal handling/tests, runtime SQLite and
admission tests, the admission store/schema, anchored commit-chain handling
and A2A tests. No combined candidate was resolved, built or merged.

The concrete integration order is:

1. Finish and pin the committed M4 closeout and required qualification. Refresh
   both inputs if either advances; do not use dirty documentation as a frozen
   acceptance checkpoint or legacy #1029 as the integration base.
2. Create a separate integration candidate. Resolve original caller custody,
   terminal unknown execution and its separately authorized financial successor
   together. Research admission version 10 and security version 34 have different
   predecessors, including conflicting historical meanings for version 10.
   Use fresh native stores first; require fingerprinted populated fixtures before
   any supported migration and preserve original anchored history.
3. Migrate the paper provider from unsigned `chio.manifest.v1` vector construction
   to security's verified manifest registry and negotiated profile. This remains
   necessary even though Git does not report a conflict in the provider file.
4. Connect finalized backing to one native admission and original hold. Carry
   exact transaction recovery into the existing stronger settlement proof/finality
   boundary, then test native process loss, unknown-payment successors and earned
   children without a second admission or debit. Qualify required Finding facets
   and the affected caller/native/consumer/flow and standalone inventories.

These changes keep the current experiment useful while that integration is
prepared. A trusted single host, local journals, one private RPC, synthetic keys
and mock tokens remain the experiment's boundary. Included is not public
finality; keyless construction is not native confinement. Funding recovery,
full orchestration/parent tool-process loss, fee replacement, mined-revert
successors, malicious-owner rollback and sustained retention remain separate
requirements. Original source, prior evidence and the active security worktree
were preserved.
