# Verified funding bound to native work

The native admission slice of Task 4 connects a verified private-chain deposit
to one signed original request, one durable native operation and one native
budget hold. The kernel executes the existing W0 OpenAPI checker. Restart and
replay retain those identities. The allocation remains Funded; this milestone
does not establish a claim or transfer tokens to the provider.

The candidate starts from locally qualified integration
`412866ccbd4c6ad2654b648570161fd0d51f3559` on
`feat/funded-native-admission`. This report and its
[source-specific evidence](18-native-funding-evidence.json) describe local
qualification only. The earlier Task 3 evidence remains unchanged.

## What is enforced

Buyer and provider sign an example-local agreement over the complete original
native request digest, request ID, native authority UUID, receiver policy,
deployment/code pins, identities, amount and deadlines. The ABI-derived allocation
ID matches the independently retained Solidity golden vector. A changed request,
copied key in a fresh native authority, widened capability or re-signed agreement
cannot inherit the original deposit.

The receiver owns the observer and its transport. A payer cannot provide a
trusted snapshot or finality flag. Rust verifies the successful funding receipt,
exact Funded and token-transfer events, immutable ABI state, unclaimed allocation,
token backing, runtime-code hashes, chain/genesis identity, contiguous ancestry,
two descendant blocks, a separate head read and observation age. The capability
must remain valid and expire no later than the funding submission deadline.

The agreement and original request are committed before kernel admission. The
kernel's opt-in request-retention setting preserves exact direct-call custody
without a nonce-preflight hold. The funding rail reads that fenced request and
the actual native payment journal, verifies funding again, then atomically binds
the original operation and hold in its journal. Allocation, request, operation
and hold identities cannot be reassigned. Capacity is bounded to 63 allocations,
with one native retention slot reserved for recovery administration.

## Recovery findings and fixes

Review found that generic native compensation could cancel an unacknowledged
payment even when the rail had durably committed authorization. Recovery now
queries the original rail and checks its name and payment mode. An authoritative
negative permits cancellation; a held authorization is recovered into the same
native payment journal. Unavailable, panicking, malformed or incompatible replies
preserve exposure. `NoAuthorization` must exclude a still-outstanding authorization
that can complete later. Eventually consistent absence is insufficient.

A failed release previously left a durable release intent that later compensation
skipped. Recovery now resumes that exact intent with its existing release authority,
authorization and hold. It cannot substitute a capture or invent new release
authority. The SQLite regression reopens the actual authority to demonstrate
successful retry after an unavailable release. A live recovery lease intentionally
excludes immediate repeat sweeps until it becomes eligible again.

Reports also distinguish an unbound operation from a conflicting binding. An
operation that exists before funding authorization remains inspectable with no
invented authorization, including admission that stops before a payment participant
is created. Failure of the second observation is a definite refusal because that
verification phase has no rail side effects. A journal commit error remains
uncertain. Existing-operation retries never dispatch the tool again.

| Actual process-loss boundary | Executions after recovery | Native payment | Native budget hold |
| --- | --- | --- | --- |
| Funding journal committed, native admission not started | 1 | Settling capture, pending | Reconciled work cost |
| Native hold created, funding binding not committed | 0 | Closed without authorization | Original hold reversed |
| Funding binding committed, native acknowledgement absent | 0 | Original authorization recovered; release pending | Original hold open |
| W0 executed, native outcome not recorded | 1 | Original authorization held | Original hold open |

The last case remains `OutcomeUnknownAfterDispatch`. Successful W0 execution
records consumed native work cost even though financial settlement is pending.
Neither local budget reconciliation nor a pending native capture proves ERC20
payment. Every chain scenario independently observes payer balance 900, escrow
balance 100, beneficiary balance zero, paid zero and refunded zero after funding
100 of the payer's initial 1,000 mock units.

## Qualification and boundaries

Selected local gates passed: 27 standalone Rust tests, 20 native SQLite tests,
1,445 kernel unit tests, 30 Python regressions and 18 contract tests. The final
smoke passes five private-chain scenarios, including four actual SIGKILL runs.
Workspace and standalone strict Clippy pass; all 29 fuzz targets compile.
Formatting, file hygiene, 225 formal source mirrors and generated proof coverage
pass. This is not a full workspace test run or a fuzz campaign.

The evidence manifest records commands, exit status, test counts, source objects
and hashes of selected public logs and scenario reports. Negative controls cover
22 malformed observation variants, exact identity/signature/scope binding,
expiry, observer loss, concurrent retries, capacity, fresh authority rejection
and native payment recovery. The executable smoke uses real worker SIGKILL and
actual Ganache/Solidity/token state; it does not edit databases to manufacture
recovery. Fixture state containing private keys and capabilities is excluded.

The reviewed formal anchor changed because direct admission can retain its
original request. The live drop-guard model does not prove funding eligibility,
authorization acknowledgement recovery or public-chain finality. Its documentation
states that boundary; the existing source-mirror and generated-coverage gates
remain separate from executable recovery evidence.

The profile is `chio.experimental.local-confirmed-funding.v1`: one owned private
chain on chain ID 31337, a mock token, price 100 and zero verifier/dispute fees.
It does not qualify public-chain finality, hostile receiver hosts, independent
witnesses or companies, cross-border operation, public deployment or the optional
process stack. Existing public wire schemas and legacy funding semantics are
unchanged. Adapters without an authoritative settlement query now retain unresolved
pre-dispatch holds rather than cancelling them on an unproved assumption.

## Next execution slice

Connect the original operation to registered submission/decision artifacts and
Finding facets, then verify custodian retrieval and authorize the claim. Observe
the exact on-chain claim, decision, withdrawal or refund before completing the
original native payment. Keep unknown execution separate from financial closure.
Finish the separately funded earned-child trial with parent process loss, then
qualify disclosure, manifest/key substitution, independent implementations and
sustained capacity. These remain open Task 4 and later qualification gates.

Reproduction commands and detailed trust limits are in
[FUNDED.md](../../../../examples/federated-work/FUNDED.md). The original dirty
paper checkout and clean research checkpoint are preserved; no source is imported
from the other agent's active process/security worktree in this slice.
