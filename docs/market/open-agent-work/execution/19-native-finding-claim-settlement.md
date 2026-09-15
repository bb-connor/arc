# Native Finding, observed claim and original settlement

The funded W0 lifecycle now carries the original native request, operation,
budget hold and rail authorization through Finding submission, independently
checked output, an observed escrow claim and an actual mock ERC20 payout or
refund. Successful payout completes the original native capture and operation.
Refund leaves recorded work cost or unknown execution intact unless the native
operation already has authority to release an undispatched hold.

This slice starts at `6162bccf5aa2ac0337b61604e5a935d571d41fb7` on
`feat/funded-native-admission`. Its [evidence manifest](20-native-claim-evidence.json)
binds the selected local checks to source objects, source hashes, executable and
public scenario reports. It extends the [funding admission milestone](17-native-funding-admission.md).
Earlier evidence is retained as historical evidence, not relabeled as these results.

## Evidence and decision authority

The native adapter reads the retained outcome through the qualified store API,
checks its operation link and raw content digest, and exports the exact input
and output to bounded SHA256 custody. The provider signs a canonical native
`chio.finding.v1` artifact and an experimental submission. The submission binds
allocation, agreement, authority UUID, request digest, operation, hold,
authorization, outcome and custody references. Strict raw-first decoding rejects
duplicate keys, noncanonical bytes, unknown fields and typed representation drift.

A separate policy-pinned Ed25519 verifier checks those bindings, retrieves custody
and reruns the pinned independent Python W0 checker over the original input.
The verifier can sign a decision only for the observed original claim in its
resolution window. The decision retains the claim transaction and block,
submission commitment, Finding ID, checker digest and original native identities.
The owned EVM signer checks that decision before signing the contract's EIP-712
authorization. A provider-signed incorrect result receives rejection; missing
custody or unavailable verifier authority cannot manufacture a decision.

The Finding deliberately uses **asserted** evidence and guarantee classes. The
completed native payment receipt does not exist at this prepayment boundary.
The independent W0 decision adds specific custody, native-outcome and semantic
checks; it is not the general 13-facet `chio-finding-verifier` report. Receipt
facets, status liveness, bond backing, lineage and runtime assurance remain
unqualified. The example-local submission and decision schemas are not registered
general work artifacts.

## Observed settlement and recovery

Claim, decision, payout and refund each retain exact signed transaction bytes
before broadcast. Rust checks the retained intent and ABI; the ethers reconciler
independently decodes actor, nonce, fees, domain and calldata. Restart uses the
same bytes and hash. Observation checks successful inclusion, two descendant
blocks, a separate head read, immutable terms, commitment and decision, exact
escrow events and exact ERC20 transfer. An already retained inclusion cannot
silently move to another block.

The lifecycle uses the existing `chio.experimental.local-confirmed-funding.v1`
profile: one owned Ganache chain, chain ID 31337, a mock token, amount 100 and
zero verifier/dispute fees. The fixture advances chain time for deadline tests.
Admission retains wall-clock freshness checks; lifecycle observation retains the
30-second receiver read limit and verifies the current chain snapshot. This is
not public-chain finality or independent witness evidence.

| Observed financial result | Original native state | Original payment and budget |
| --- | --- | --- |
| Accepted work, provider receives 100 | `Completed` | `Settled` capture; recorded work cost retained |
| Rejected or timed-out work, payer receives 100 back | `Finalizing` | Original positive capture remains `Settling`; consumed work cost retained |
| Outcome lost after dispatch, payer receives 100 back | `OutcomeUnknownAfterDispatch` | `Authorized`, no invented settle action; original hold remains open |
| Bound authorization lost before dispatch, payer receives 100 back | `CompensatedBeforeDispatch` | `Settled` release; original hold reversed; zero executions |

Financial refund cannot count as capture. Resolving an externally rejected or
timed-out positive native capture needs an explicit native authority that this
slice does not introduce. Unknown execution likewise cannot be replayed or
erased by the money outcome.

The parent retains the owned chain while a native worker receives actual
SIGKILL. A second worker resumes using the same observer socket and original
SQLite authorities. No database is edited to create a recovered state. The
controller independently reads native operation, hold and payment identities,
checks the actual W0 execution counter, and compares retained transaction hashes
with mined blocks and receipts. Payer, escrow and beneficiary balances are read
from the token independently of native bookkeeping.

## Review-driven corrections

Retained local artifacts do not prove an on-chain successor. A submission that
was never broadcast or a decision that was never recorded can miss its deadline;
recovery observes current escrow state and refunds without discarding the
original artifacts or replacing a transaction. Recorded acceptance remains
payable. A separate public `expire()` call followed by refund is also supported.

An absent receipt is a valid negative observer response. It must not poison the
owned Node transport or kill the surviving socket service. Framing, broken
transport and unverified observations still fail closed. Recovery after preparing
a payout or refund now exercises this distinction in a restarted worker.

Event counts alone cannot establish transaction uniqueness because idempotent
replays can emit no events. The evidence now enumerates all mined transactions
for the allocation and compares them with retained intents. A separate negative
control actually submits duplicate claim and decision transactions, then shows
that the independent inventory detects both despite empty replay event logs.

## Local qualification

The evidence manifest records individual commands, timestamps, exit status,
source hashes and public logs. The selected gate includes:

- 31 default standalone Rust tests and two explicitly selected private-chain
  Rust tests, including 25 altered settlement transcripts and two receiver-clock
  failures, original adapter identity checks, Finding/custody failures and bounds.
- 27 lifecycle scenarios: five ordinary success/refund paths, 15 claim/decision/
  money crash paths, five deadline-loss crash paths and two native execution-loss
  paths. These include 22 actual SIGKILL runs.
- The five original funding-admission scenarios, including four actual SIGKILL
  runs, plus 20 native SQLite recovery tests.
- 68 existing Python buyer/funded-work regressions, 18 escrow contract tests and
  the new mined-transaction inventory negative control.
- Standalone strict all-target Clippy, standalone and workspace formatting,
  Rust file hygiene and patch whitespace checks.

These are selected local checks, not a full workspace test run, hosted CI,
new fuzz campaign or release qualification. Shared kernel sources, public wire
schemas, Cargo manifests and lockfiles are unchanged by this slice. The broader
kernel, workspace, fuzz-build and formal checks at the admission milestone remain
historical checks on their recorded sources.

The original paper checkout retains its branch, HEAD, dirty status and all 3,688
snapshotted file hashes/modes. The research and active security worktrees are not
modified or merged by this slice. Public evidence excludes generated private keys, capability
material and authority databases. No push, PR, merge, deployment or external
chain operation is part of this qualification.

## Next boundary

Complete explicit native authority for contractual rejection/timeout of recorded
positive captures, then exercise the separately funded earned child surviving
native parent loss. Registered general work artifacts and Finding facet
integration, broader disclosure/key/manifest adversaries, independent operators
and sustained capacity remain Task 4 and later gates. The one-host mock-token
witness does not close the paper's independent-company or cross-border claims.

Reproduction commands and trust limits are in
[FUNDED.md](../../../../examples/federated-work/FUNDED.md). The bounded
[implementation plan](../../../superpowers/plans/2026-09-14-funded-native-claim-settlement.md)
tracks this slice separately from the full funded-work plan.
