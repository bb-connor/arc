# Connected native profile and its remaining boundary

This continuation adds a single connected trajectory, rather than inferring
composition from three unrelated kernels. It uses actual `ChioKernel` governed
approval, output-digest delivery, durable-admission, receipt-store and payment
interfaces. There is no production implementation change.

## Contract and owners

Buyer B, provider P and specialist C have distinct fixture signing keys, kernel
instances, SQLite authority stores and durable receipt logs. One administrator
controls the host and all fixtures. These are test keys, not deployment keys.

B's kernel materializes the fixed input. Its exact-output grant commits the
bytes, source version and authorized recipient set {P,C}. P receives and checks
the signed source receipt. B then approves P's materialized request, including
the digest of the original child request. P's tool invokes C's own kernel with
that request; P's approval binds the exact arguments, recipient and source
receipt. C's exact-output grant commits a bounded decision, evidence index and
authorized recipients {P,B}. P verifies that artifact before returning its own
result. The fixed recipient sets are explicit owner-authorized disclosure in
this fixture. No signature is treated as proof of continued host confinement.

The native governed-intent checker verifies signatures and argument binding;
the small profile guard also pins the approval role, source receipt, audience
and version. Native output-digest enforcement checks returned bytes before
release and gives a mismatched output zero charge. This guard and the signed
artifact schema are part of the experiment's trusted adapter and must be
counted as integration code, not free kernel functionality.

The test rail uses a separate SQLite database with immediate transactions and
durable integer balances. B starts with 1,000 units, P with 100 and C with zero.
B's materialization has a one-unit reversible ceiling and actual charge zero;
the parent ceiling is 100 and the child charge is 30. Each rail authorization
retains its complete original request, role and amount. Settlement is idempotent
and bound to its original reference. The rail is a declared qualified fixture,
not a bank, public blockchain, separately operated service or new settlement
protocol. Its conservation and available-backing rules are also tested directly.

## Acceptance and observed outcomes

The driver runs two no-fault companions and six actual SIGKILL schedules inside
parent finalization. The child has already earned its native payment when the
parent returns. The rejecting parent emits a canary outside its approved output
commitment; the canary is retained privately in native return custody and never
released through the tested response path.

| Parent cut | Recovery response | Monetary result |
| --- | --- | --- |
| No fault, correct output | Original Allow receipt and exact approved output replay | B 900, P 170, C 30 |
| No fault, mismatched output | Original Deny receipt; no output | B 1000, P 70, C 30 |
| ToolReturnRecorded | Original release owner unavailable; output withheld | B 1000, P 70, C 30 |
| PostReturnEvaluationBegun | Same refusal | B 1000, P 70, C 30 |
| PostReturnResolved | Same refusal | B 1000, P 70, C 30 |
| SecurityReleaseAcknowledged | Lost acknowledgement is not a durable release checkpoint | B 1000, P 70, C 30 |
| SecurityReleaseCheckpointed | Durable Deny receipt, no output | B 1000, P 70, C 30 |
| TerminalProjected | Durable Deny receipt, no output | B 1000, P 70, C 30 |

Every row asserts one invocation per owner, identical original operation/hold/
authorization identities across recovery, zero remaining escrow, conserved total
1,100 and byte-equivalent child artifact/receipt replay. The early recovery rows
also assert that a new callback never replaces the original release owner.
Blocked security release is not reported as successful full-process recovery.

Nine rejection controls cover absent approval, changed arguments, recipient,
source version, operation ID, approval signature, changed source bytes, changed
source receipt and substitution of a receiver capability by an approval authority.
The source mutations carry a fresh genuine approval to reach the source-evidence
check. Each produces no child dispatch; the authorized trajectory is its positive
companion. A separate rail control rejects underbacking, authorization changes,
cross-owner release, release of an earned claim and changed settlement reference.

The target contains four substantive tests plus one subprocess helper. Run it
with `--features admission-test-support`; the feature gates actual fault hooks.
`verify.py --record` records the final owning-target tests, focused clippy and
format check with the native source digest and all eight JSON trajectories.
Initial missing implementation, compile errors and successful exploratory runs
are retained. `native-owner-red` is a historical filename for a control that
passed immediately: native code already rejected that substitution. It is not
claimed as a discovered vulnerability or a red-to-green production fix.

## Crosswalk: closed here and still open

| Obligation | This continuation | Remaining gate |
| --- | --- | --- |
| Cross-owner input and result bindings | Actual signed approvals, receipt verification and output commitments in one connected profile | General multi-artifact/version semantics and formal refinement |
| Original-operation custody | Actual durable operation and hold identities survive all six finalization cuts | Other dispatch/family/concurrency cuts retain their prior bounded evidence |
| Earned child after parent failure | Actual native settlement calls into separately backed local test-rail accounts | Independent payment service and complete economic evaluation |
| Current release authority | Native code refuses a fresh substitute for the lost owner | Native recovery-owned mediator must establish authorized continuation |
| Complete PR #1172 mediation | Specification remains assumed shipped for the design, per user direction | This fixture does not implement all source, error, log, payment, timing and lifecycle channels |
| Independent operators and malicious host behavior | Not exercised | External trial and qualified deployment implementation |

The local profile is qualified by its recorded tests. The full native
composition gate remains open. A sensible engineer can reproduce this experiment;
a sensible researcher cannot infer universal confinement, arbitrary exactly-once
effects, distributed money correctness or a scientific advance from it.
