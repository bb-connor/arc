# Recoverable rejection under an explicit work contract

The known failure in report 29 now has a completed path in the new v3 example
agreement. A provider-signed incorrect review returns a signed kernel denial,
releases its local-credit hold, and leaves the buyer with zero expense. The buyer
checks the denial and receipt inclusion before restoring its reservation once.
Provider or buyer process death at the tested release boundaries does not repeat
the review, capture payment or restore the reservation twice.

This is a bounded improvement to interorganization work. It does not establish
independent company operation, cash settlement, adoption or a breakthrough.

## The economic rule is explicit

An arbitrary security rejection cannot establish that execution had no effects
or authorize a refund. The kernel therefore adds an opt-in trusted guard method,
`Guard::output_rejection_is_zero_charge`. The default is false. A host choosing
this contract must bind the work agreement and checker through its configured
policy. Monetary requests require a reversible hold and durable coverage before
dispatch. The initial profile rejects combinations with output-digest, Finding
purchase or Finding recovery contracts before admission.

The example now selects `chio.example.security-review-agreement.v3` and
`provider-local-credit-checked-or-zero-v1`. Successful checked work costs 100 TST;
a rejected check earns zero and requires release. The buyer's later verification
does not arbitrate an external escrow. The configured provider ledger remains
the selected settlement authority. No external funds move.

The new executable rejects old v2 work agreements. Report 29 preserves that
version's evidence and source. The harness creates fresh private state; there is
no migration or retroactive release of old agreements and their pending holds.
The v1 negotiation-only profile remains supported.

## Kernel and storage changes

The kernel records an authenticated raw tool return before evaluating output
guards. Recording it permits recovery without another dispatch; it does not
authorize release of the output or capture of payment. Guards still check the
raw and final transformed values at their applicable boundaries.

For an opted-in checker rejection, including a caught checker panic, the kernel
retains the output evaluation and zero-charge settlement decision before asking
the rail to release. It then projects a signed `DeniedAfterDelivery` terminal
with the new `output_guard_rejected` reason and native payment evidence.
SQLite's strict terminal-shape validator accepts this additional reason.

The public denial withholds the rejected output and replaces its content digest
with a fixed, domain-separated redaction binding. The privileged outcome store
retains the actual returned bytes and their digest. Receipt action parameters
still contain the disclosed review input; output redaction is not input privacy.

Recovery compares the retained output-guard decision digest and preserves an
already resolved rejection even if the checker later allows the result. It does
not change a release into a capture. Completed replay verifies the original
receipt and returns no rejected payload. Remote terminal verification binds the
typed reason to the signed decision, redaction digest and absence of conflicting
delivery overlays. Validly signed but inconsistent variants reject.

Ordinary output guard failures do not acquire zero-charge authority. Their raw
return can remain in `Finalizing` with the hold retained and an error returned.
An unrecorded post-dispatch outcome remains uncertain and is never automatically
replayed or released. A general dispute or authorized resolution protocol for
those cases is still required.

## Buyer and provider recovery

The provider's existing `delivery` method can return either the verified Finding
delivery or a checked-review rejection artifact. Both include a native signed
receipt, provider checkpoint and receipt inclusion proof. Rejection retrieval
uses the retained request and exact acceptance; it never executes the review.

The buyer verifies the provider pin, agreement and acceptance digests, request
parameters, capability, signed denial reason, redaction digest, terminal admission
state, zero-charge financial receipt and inclusion proof. Its transaction stores
the rejection and one `released_reservations` entry while restoring 100 test
units. Retained reservations remain available for audit but no longer count as
outstanding. Repeated retrieval validates the cached artifact without changing
the account again. The completed rejection contains no Finding or review report.
The transaction also fixes one terminal outcome per job. A conflicting verified
terminal or receipt id reused by another job rejects before either accounting
branch mutates. A storage-level regression exercises both acceptance-then-denial
and denial-then-acceptance conflicts. Four simultaneous buyer recovery processes
exercise reservation restoration after the buyer's injected crash.

These signatures establish what the configured provider attested. They do not
independently prove an honest external ledger, actual collateral or non-equivocation
by a malicious provider with control of its signing authority and database.

## Executed scenarios

All eleven process scenarios pass using separate Linux mount namespaces on one
host. The new rejection scenarios are:

| Scenario | Reviews | Captures | Released holds | Restored buyer reservations |
| --- | ---: | ---: | ---: | ---: |
| Provider-signed incorrect report | 1 | 0 | 1 | 1 |
| Provider SIGKILL after rail release, before acknowledgement | 1 | 0 | 1 | 1 |
| Provider SIGKILL after terminal denial, before reply | 1 | 0 | 1 | 1 |
| Buyer SIGKILL after rejection verification, before recording restoration | 1 | 0 | 1 | 1 |

Each ends with 1,000 available, zero reserved and zero spent. The three new kill
scenarios assert termination with SIGKILL or launcher exit 137. The public-only
verifier checks every rejection and rejects changed agreement, input, financial
receipt and inclusion coordinates. Another work invocation under the same
capability fails and leaves counts unchanged.

The seven other scenarios retain their prior boundaries: normal completion,
provider death after capture, provider death after completed settlement, buyer
death before recording an expense, uncertain execution after the review write,
missing proof or changed input, and two distinct paid jobs in the same journals.
The uncertain case still has one held payment and no capture or buyer expense.

This measures process crashes. It does not qualify power-loss behavior, storage
rollback, an adversarial network or independent administrative domains. The
provider tool and kernel share a trusted process. Both parties and the verifier
use the same Rust implementation.

## Qualification and next evidence

The kernel library passes 1,103 tests, including the finding-market feature
configuration. The real SQLite restart suite passes all 12 tests, and the SQLite
admission-store suite passes 84 tests. The example has four passing unit tests;
the earlier three negotiation scenarios also pass. Kernel, store and example
Clippy runs deny warnings. Formatting and whitespace checks pass. The paper
build remains at 12 pages and 4,999 body words.

The test logs, process transcripts and source hashes are retained in
[the evidence manifest](evidence/30-recoverable-checked-output-rejections/manifest.json).
The SQLite recovery fixtures now create their temporary directories with
explicit private permissions, so their ownership checks do not depend on the
launcher's umask. Production directory permission checks were not relaxed.

All work remains local and uncommitted on the checkout based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`. This is not exact-commit remote CI,
a release, or public market activation.

The next experiment should replace one participant with a separately implemented
client that follows the public contract, then run under independent operator
control with an agreed settlement authority and a useful non-fixture job. The
strongest objection remains that Chio connects established mechanisms through
application-specific code. Evidence of independent adoption with less bespoke
authorization and recovery work would matter more than another local test count.
