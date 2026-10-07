# Executed work, checked delivery and local-credit settlement

The implementation now completes a bounded security-review purchase across the
production A2A connection. The buyer signs and retains an exact agreement. The
provider's kernel admits one review of the agreed input, validates the output,
records a 100-unit local-credit capture and signs the result receipt. The buyer
recomputes the review and verifies the finding, receipt and Merkle inclusion
proof before recording its expense.

This closes an executed-work gap in report 28. It does not demonstrate cash
payment between companies, independent administration or a breakthrough. The
selected credit ledger is explicitly trusted, and an unresolved output-denial
path remains visible in the failure evidence.

## Contract and authority

`examples/federated-work` retains the negotiation-only v1 agreement and adds
`chio.example.security-review-agreement.v2`. The new version explicitly selects
`provider-local-credit-after-check-v1`. It authorizes the exact input disclosure,
named checker and provider-local capture after the provider's output check.
The buyer's later independent verification is not an escrow release condition.

The work capability is the actual token in the signed market offer. It requires
the buyer's Chio proof of possession, permits one `review` invocation and caps
the charge at 100 TST. The existing A2A adapter carries the action-bound proof in
a sensitive header; the example host supplies it to the kernel. A configured
nonce cache and durable invocation/budget state enforce the tested boundary.
The separate negotiation capability cannot execute the review.

The native review guard checks the full retained acceptance, exact capability,
raw input digest, supported profile and live deadline. It runs again immediately
before dispatch. Output validation independently recomputes the expected report
before the result is released or captured. The kernel's policy identifier hashes
the example's agreement, market and review source. This is a local configuration
identifier, not remote attestation of that source's execution.

The buyer enforces its own 1,000-unit example budget. The provider caps retained
accepted jobs at ten, bounding its configured accepted credit exposure to 1,000
units. The participants trust their respective local journals. Neither a buyer
reservation signature nor a provider ledger receipt proves external solvency.

## Actual deliverable

The checker accepts a bounded, self-contained OpenAPI 3.1.0 JSON input and
inventories declared authentication for each operation. It handles inheritance,
operation overrides and anonymous alternatives according to the
[OpenAPI security definitions](https://spec.openapis.org/oas/v3.1.0.html#security-requirement-object),
inspected on 2026-09-13. Unsupported security references, callbacks, webhooks,
unknown scheme names and duplicate JSON keys reject. It performs no network
fetch or execution of supplied code.

The input fixture has four operations. The report identifies two that require
authentication, a refund operation that removes the inherited requirement, and
an explicitly anonymous health operation. These are findings about API
declarations, not proof of deployed vulnerabilities or a comprehensive review.

The provider emits a signed report inside the production finding reveal
envelope. The kernel's `content_hash` therefore binds the same canonical envelope
as `Finding.payload_sha256`. After a completed paid receipt is retained, the
provider creates a production `chio.finding.v1` artifact, a signed kernel
checkpoint and an inclusion proof. The finding references the exact agreement,
receipt, checkpoint and deterministic checker/input recipe.

The buyer verifies all of those bindings and re-executes the checker. The
profile rejects additional assurance claims: its finding is explicitly unbacked,
has no runtime-attestation tier, and names a local job rather than claiming an
authenticated market status feed. This is not publication admission into the
full finding market or collateral-backed assurance.

Provider and buyer retain separate SQLite journals. The provider reuses
`SqliteFindingOperatorPaymentAdapter`, `SqliteAuthorityStore`,
`SqliteReceiptStore` and `DurableAdmissionMode::All`. Recovery is configured only
after installing the same guards, tool server and payment adapter. Delivery
retrieval resolves retained signed receipts and results, never another review.
The buyer converts its reservation into one expense only after verification.

## Process and adversarial evidence

The harness uses separate Linux mount namespaces and public-only verifier
inputs. One trusted launcher, operating system and Rust implementation still
control the experiment. The provider's native tool and kernel share a trusted
process and signing authority. The controlled corrupt-report injection is not
an arbitrary untrusted-tool isolation experiment.

| Scenario | Review executions | Captures | Buyer expenses | Observed result |
| --- | ---: | ---: | ---: | --- |
| Normal completion and repeated retrieval | 1 | 1 | 1 | Verified report, finding, receipt and inclusion proof |
| Provider SIGKILL after rail capture but before its acknowledgement reaches the kernel | 1 | 1 | 1 | Native durable recovery completes without repeating the review or creating another charge |
| Provider SIGKILL after terminal settlement but before replying | 1 | 1 | 1 | Buyer obtains the retained deliverable after restart |
| Buyer SIGKILL after verification but before recording expense | 1 | 1 | 1 | Buyer verifies the retained result again and records one expense |
| Provider SIGKILL after writing the review, before recording its kernel return | 1 | 0 | 0 | Hold and uncertain outcome retained; no automatic replay |
| Provider-signed incorrect report | 1 | 0 | 0 | Output guard rejects; hold remains pending |
| Missing sender proof and changed input | 0 | 0 | 0 | Both requests denied before review execution |
| Two distinct jobs through the same buyer/provider journals | 2 | 2 | 2 | Correct job selection; 800 available, 200 spent, none reserved |

The completed single-job scenarios end with 900 available, zero reserved and
100 spent in the buyer's test accounting. Another paid invocation with the
same token is denied and leaves all counts unchanged. The public-only verifier
rejects five substitutions per completed scenario: changed input, report,
finding payload digest, receipt content digest and inclusion coordinates.
Those mutations are separate from the valid-provider-signature output fault.

All four injected SIGKILL scenarios terminate their targeted process and the
launcher reports 137. They measure process failure, not power-loss durability,
filesystem rollback resistance, hostile network behavior or separate host
administration. No external currency is transferred.

## A remaining defect, not a completed failure path

The corrupt-report case returns a kernel bridge error at output validation,
without a completed paid receipt or an exposed signed terminal denial for that
invocation. The payment remains held and the buyer records no expense. Retrying
the workflow does not execute the review or capture payment.

That is fail-closed on release and capture, but it does not close the job.
The next kernel task is to retain a verifiable terminal result for this known
output rejection and resolve its hold under the agreed payment rule. A generic
unknown execution must continue to preserve its uncertain effects. These two
cases cannot be collapsed into a timeout-driven refund or blind retry. This
observed gap also prevents a broad claim that this example produces a usable
signed receipt for every rejection and always resolves its economic obligations.

## Production payment API repair

`SqliteFindingOperatorPaymentAdapter` now implements the existing
`PaymentAdapter::settlement_state` method. Previously it inherited the default
unsupported response. The new query reads the durable reference without
authorizing, capturing, releasing or refunding. It returns absent, held,
captured, released or refunded state and rejects a supplied authorization id
that does not belong to that reference. It works when the caller lost the
authorization id before journaling it.

The new test queries before authorization, while held and after reopening a
captured payment, checks mismatched references, and verifies release/refund
states and unchanged capture count. The process tests separately exercise the
existing native idempotent rail and admission recovery; they do not establish
that this newly implemented query is the sole cause of successful recovery.

## Qualification and remaining objective

The complete `chio-store-sqlite` library suite passes 1,106 tests with three
pre-existing ignores: a retention property test documented as wedging CI, a
million-receipt scale proof, and a child-process helper. Its payment-adapter
subset passes all 12 tests. The example's three unit tests cover signed-offer
substitution, authentication inheritance and unsupported/ambiguous semantics.
All eight paid-work scenarios and the earlier three negotiation scenarios pass.
Clippy uses warnings denied. Formatting and whitespace checks pass. The paper
build passes at 12 pages and 4,999 body words.

Public transcripts, logs, the production payment diff and source hashes are
indexed in [the evidence manifest](evidence/29-checked-work-and-local-settlement/manifest.json).
The source remains uncommitted on the checkout based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`; this is not remote CI or release
qualification. The paper now distinguishes checked work/local credit settlement
from cross-company payment and novelty.

After closing the known output-rejection terminal, the substantive next tests
are a separately implemented participant, two independent administrative
domains, selected settlement authority beyond the provider's own ledger,
revocation and delegation failures, and a useful non-fixture customer job.
The breakthrough judgment remains unproven. Its strongest objection is still
that these are known mechanisms connected by application-specific code. Actual
independent adoption and a measured reduction in partner-specific security and
recovery work would be evidence against that objection.
