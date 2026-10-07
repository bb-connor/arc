# Native contractual resolution and earned child survival

The original funded native operation now supports explicitly authorized financial
resolution after a verified refund without deleting work or replenishing consumed
budget. A separately funded child also earns an unpaid claim through its own
native kernel, survives actual parent process death, and collects after the
parent allocation refunds.

This delivery starts at `5257f963d869d89c7a54384ea88628cf727c32c8` on
`feat/funded-native-admission`. The [evidence manifest](22-native-successor-evidence.json)
binds selected local checks to source objects, hashes, the executable and public
scenario reports. The [prior milestone](19-native-finding-claim-settlement.md)
and its evidence retain their historical scope.

## Original authority, distinct financial successor

Before funding, the buyer and provider separately sign bounded native waiver
terms. They commit the capability, request ID, contract context and receiver-pinned
observer policy. The original request retains the signed terms digest, and the
funded agreement commits that complete request. Contract context commits domain
and immutable work terms without introducing a circular agreement digest.

A refund alone cannot authorize a waiver. The receiver freshly verifies the exact
successful refund transaction, immutable allocation, events, token movement and
private-chain inclusion. Its separately pinned observer signs those facts together
with the original operation, positive capture journal and raw outcome digest.
Native qualification checks both parties' original consent and the observer's
exact source bindings. A legacy agreement cannot acquire waiver authority after
execution. Changed terms, source identities, refund evidence or observation keys
deny before native resolution mutation.

The SQLite store accepts the successor under its current exclusive owner and
trusted clock. Any recovery claim from the current owner blocks new acceptance,
even after lease expiry: expiry cannot prove an in-flight capture callback has
stopped. A new resolution-only owner skips ordinary capture recovery, accepts
the waiver, and completes it before ordinary finalization resumes. The signed
terms must still be valid at initial acceptance using the store's current trusted
time. An exact replay uses retained acceptance, rather than renewing consent.

Acceptance and completion append separate immutable records with global commit
coverage. Ordinary payment mutations cannot mint `Resolving` or `Resolved`.
Reads revalidate original operation binding, retained request, outcome, journal,
positive budget event and successor history. Supported migration validates the
exact v35 schema before adding the empty v36 successor table. Exact replay adds
no successor, budget event, global commit or anchor write.

| Case | Native result | Original work and money history |
| --- | --- | --- |
| Accepted work is paid | `Completed`, `Settled` capture | Positive recorded cost and actual payment retained |
| Known positive-cost work refunds and receives its authorized waiver | `Completed`, effective `Resolved` capture | Original `Settling` capture and positive consumed budget remain unchanged; zero paid |
| Dispatch outcome is unknown and allocation refunds | `OutcomeUnknownAfterDispatch`, `Authorized` | No invented outcome or capture; original budget exposure remains open |
| Authorization was lost before dispatch and allocation refunds | Existing pre-dispatch compensation | Original authorized release can reverse its unused hold; zero executions |

The waiver's signed terminal financial receipt reports `cost_charged = 0` and
`settlement_status = failed`, while retaining positive
`cost_breakdown.payment.recorded_units` and the complete
`contractual_resolution` binding. Kernel replay and SQLite participant validation
check that whole authority, including kind, operation/version, refund reference
and evidence digest. Consumed work budget is independent of money paid. The
original tool outcome and capture disposition are not rewritten as zero-cost work.

## Child earns before parent dies

One owned chain receives two separately backed 100-unit allocations. Buyer A
funds provider B; B separately funds specialist C from B's own balance. Each
has its own original agreement, request, capability, native authority and hold.
B signs a dependency over both agreements and requests, both authority UUIDs,
and the exact shared input. Altered dependency signatures, identities and input
deny before opening or invoking the child kernel.

The parent tool calls the child's kernel on a scoped thread and joins it. The
child executes W0 once, retains its native outcome and custody, produces a signed
Finding, passes the pinned independent Python checker, and records an observed
accepted claim. The child is still unpaid and `Payable` when actual SIGKILL kills
the parent process after the parent tool invocation but before native outcome
recording. The parent invocation measures orchestration; W0 checking runs in C.

The surviving controller observes and refunds A's original allocation. The parent
remains outcome-unknown with one invocation and no replay. It does not acquire a
capture waiver. Parent financial signing and new child verifier decisions are
then disabled in the fixture, and attempted-signing negative controls confirm
that restriction. A separate collector receives only the child state and its
fixed observer socket. It uses retained claim/decision artifacts and C's existing
beneficiary authority to collect, without a new parent signature or decision.

All four child scenarios end with the same balances:

| Holder | Initial | Final |
| --- | ---: | ---: |
| Buyer A | 1,000 | 1,000 |
| Intermediary B | 1,000 | 900 |
| Specialist C | 0 | 100 |
| Escrow | 0 | 0 |
| Total supply | 2,000 | 2,000 |

B absorbs the 100-unit loss. The child collector also survives SIGKILL after
payment preparation, broadcast and observation. Recovery uses the same signed
transaction bytes and original native identifiers. Independent block/receipt
inventory counts actual transactions, including idempotent transactions that
could otherwise hide behind empty event logs. No database edit creates a recovered
state, and neither worker loss nor refund authorizes another execution.

## Review and security synchronization

Independent reviews covered the shared native authority and the funded adapters.
They prompted use of current store time for expiry, full financial-authority
comparison, and a direct waiver-validation assertion to prevent a funding mismatch
from making an authority test pass for the wrong reason. Runtime qualification
exposed nested blocking executor reentrancy; the scoped child thread fixes that
boundary without leaving detached child work. New modules keep the existing Rust
file-size gate intact.

A read-only security audit was refreshed through clean committed head
`1f2c8c3e9d8c074d4e50181201ce4e788bc47d0d`. The selected prerequisite from
`9d398d0186f19bf0724085b6aa82c47c27bde7f5` refreshes trusted recovery time under
the mutation lock. The new waiver API also preserves exact no-op behavior. No
whole security commit or broad process stack was merged. The newer WAL-backed
relocation fix applies to export/import; this witness reopens original owners in
place, so it remains part of a later relocation integration. See the
[selection record](native-successor-evidence/security-sync.json).

## Qualification boundary

Selected qualification is recorded in the evidence manifest:

- 43 owned-process scenarios, with 36 actual SIGKILL events: seven waiver cases,
  four earned-child cases, 27 lifecycle regressions and five admission cases.
- 1,445 kernel unit tests, 22 native durable SQLite tests and 48 selected store
  schema/payment/global-commit tests. The strengthened waiver test also exercises
  synchronized conflicting requests and exact no-op anchor preservation.
- 37 standalone Rust tests, including three explicitly selected private-chain
  tests. Five altered refund observations and a replaced observer key leave
  native waiver/global-commit counts unchanged; the valid control resolves.
- 68 Python regressions and 19 contract/inventory checks.
- Workspace and standalone strict Clippy, workspace all-target checking,
  all fuzz binaries type-checked, format, schema registry, Rust file hygiene,
  generated proof coverage, formal mirror references and patch whitespace.

These are selected local tests, not a full workspace test run, new fuzz campaign,
hosted CI, public-chain qualification or release authorization.

The formal mirror and coverage updates record reviewed source movement and the
new schema version. The live drop-guard model explicitly excludes capture-waiver
financial rules and the separately funded child protocol. Updated source hashes
are not new formal proofs. Native tests check owner-claim exclusion, already
paid refusal and two synchronized conflicting waiver requests with exactly one
accepted successor. They do not constitute a synchronized concurrent rail-capture race
or exhaustive mutation of every original SQLite column.

All roles, keys, custody, signer restrictions and chain operation belong to one
local fixture. The child relationship is explicitly separately funded orchestration,
not capability attenuation or host isolation. Two descendant blocks on owned
Ganache are the existing local confirmation profile, not public-chain finality.
The Finding remains asserted-class with a specific independent W0 decision;
general Finding receipt, lineage, status, bond and runtime-assurance facets remain
unqualified.

The original paper checkout retains its branch, HEAD, dirty status and all 3,688
snapshotted file hashes/modes. Research and security worktrees remain untouched.
Public evidence excludes private keys, full capabilities and authority databases.
No push, PR, merge, deployment, external-chain operation or release qualification
is part of this delivery.

## Next delivery

Register the bounded work, dependency and decision formats and connect their
acceptance requirements to the existing Finding verifier facets, with explicit
unsupported and unavailable outcomes. Preserve these completed funding, waiver
and child-survival witnesses as conformance cases. Then qualify disclosure and
signer substitution, sustained retention, and an independently implemented operator.
The full Task 4 and paper claims remain open where they exceed this local profile.

[Reproduction commands and trust limits](../../../../examples/federated-work/FUNDED.md)
and the [bounded implementation plan](../../../superpowers/plans/2026-09-14-native-resolution-earned-child.md)
record the executable surface separately from later program gates.
