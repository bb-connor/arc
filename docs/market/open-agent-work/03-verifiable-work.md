# Useful work, inexpensive verification and bounded autonomy

Status: workload and research plan. No new task family is qualified by this
document. Program entry: [README](README.md).

## 1. Choose work with an objective acceptance contract

The initial commercial wedge is a checked software artifact: a repair,
transformation or analysis result bound to a particular input snapshot. The
buyer buys the artifact and its declared acceptance properties. The provider
may use any model or internal process allowed by its own policy.

Use two task families to test whether the protocol generalizes:

| Family | Purpose | Acceptance boundary | Principal weakness |
| --- | --- | --- | --- |
| W0: bounded OpenAPI authentication analysis | Preserve a small deterministic interoperability and failure fixture | Exact supported syntax, selected paths and declared authentication checks | Often cheaper to recompute than buy; not evidence of a valuable cognition market |
| W1: source repair against a frozen repository | Primary useful-work experiment | Base commit, allowed patch scope, reproducing failure, independent regression checks and bounded build/test environment | Passing selected checks does not establish general program correctness |
| W2: certificate-bearing bounded transformation | Research test of much cheaper verification and F2 settlement | A chosen mathematical relation with an independently executable certificate checker | A tractable certificate may cover only a commercially uninteresting property |

W1 builds on the repository's existing checked-repair experiments and finding
artifacts. Select public or explicitly shareable repositories with bounded
build environments. Initial examples should fix concrete behavioral failures,
such as a reproducible authorization bug or a parser regression, with a test
that fails on the original snapshot. Avoid tasks whose only success criterion
is a seller-written narrative.

P45 first maps this workload onto existing verified-fix submission/payload,
Finding verifier and challenge classes. Preserve `asserted`, `unavailable`,
`failed` and `verified` outcomes per facet. A required facet must actually pass;
a correct signature or receipt hash cannot make a missing checker result pass.
Reuse the class-specific standing and retained-authority checks when a result
is contested. F1's custody and payable-claim semantics are additional decisions.

For W2, spend a bounded research spike on candidates such as a proof of a
finite configuration property, a certificate for a bounded optimization
instance, or a proof-producing source transformation. Select one only after
measuring producer and checker costs and identifying a real user of the result.
Do not create a general proof language or zk execution stack before that choice.

## 2. Define the acceptance contract before procurement

Each task profile must include:

1. Exact input identity: source commit or canonical input digest, dependency
   lock, relevant environment and permitted external observations.
2. Output grammar: patch/artifact type, maximum size, permitted files, path
   normalization and extraction rules. Reject traversal and executable payloads
   outside the explicitly selected environment.
3. Acceptance predicate: the properties being bought, checker version and
   artifact digest, all deterministic tests and any explicitly accepted
   probabilistic checks.
4. Checker execution policy: hardware/resource limits, network permissions,
   dependency provenance, timeout behavior and deterministic error semantics.
5. Submission and appeal policy: who may submit, how many attempts are paid,
   what counts as infrastructure failure, and the exact evidentiary deadlines.
6. Data disclosure and result rights: approved input projection, allowed
   recipients, retention, intended output access and any reuse restrictions
   agreed by the participants.
7. Funding terms: service price, separately bounded verification/retry/rail
   fees, successful-child obligations and the owner of unsuccessful production.

The buyer chooses the acceptance profile before seeing a candidate result.
The supplier cannot select a weaker checker after producing output. A checker
upgrade creates newly negotiated terms; it cannot retroactively change a
funded obligation.

For held-out checks, commit the test bundle and evaluation policy before the
seller submits. Keep the plaintext with an agreed independent evaluator and
declare that trust dependency. A commitment proves that a bundle was fixed;
it does not prove the hidden tests are useful or fairly administered. After
scoring, reveal permitted tests or produce auditable evaluator evidence under
the trial's disclosure policy.

## 3. Keep artifact validity separate from business value

Track these independently:

| Observation | What it establishes |
| --- | --- |
| Signed, hash-valid output | Attribution and byte integrity |
| Checker accepts | The selected predicate accepted this input/output pair |
| Independent regression evaluation accepts | Success on the held-out evaluation procedure |
| Buyer uses the output | Evidence of practical utility for that buyer |
| Buyer returns and pays again | Evidence of recurring demand |

A cheap predicate can be satisfied by a useless artifact. A passing regression
suite can miss a vulnerability. A seller can generate many valid variants
without doing much new work. Charge for agreed useful results and exclusivity
where required; do not treat distinct hashes or signed compute receipts as
proof that a scarce new intellectual contribution occurred.

## 4. Measure verification economics

For each task record:

```text
producer_cost = model + tools + compute + paid inputs + failed production attempts
verification_cost = all checkers + held-out evaluation + disputes + failed checks
coordination_cost = protocol compute + storage + bandwidth + recovery operations
capital_cost = recorded funding cost for amount and duration actually locked
```

Keep end-to-end buyer price, total system resource cost and individual seller
profit as separate measures. Internal payments are revenue to one participant
and expense to another; eliminate them when computing total system resource
cost. Do not eliminate them when measuring a participant's solvency or profit.

The initial H2 decision target is a median verification-to-production cost
ratio at most 0.10 and a 90th percentile at most 0.25 on accepted W1 tasks,
with the same ratio reported for the full attempted workload including failed
production and checking. These are chosen research gates, not achieved numbers
or universal constants. Also report latency ratios, cache hits, corpus size
and confidence intervals. If production is nearly free, report absolute costs
instead of presenting an unstable ratio as meaningful.

Compare against a buyer using the same models and compute directly. A supplier
may legitimately amortize a reusable result across buyers, but disclose that
reuse and evaluate the buyer's actual marginal benefit. Do not manufacture
verification asymmetry by wasting producer compute.

## 5. Verification research ladder

Advance only when the preceding level has a measured shortcoming:

1. **Independent deterministic replay.** Pin checkers and environments; retain
   inputs and outputs for offline checking. This is the initial implementation.
2. **Smaller certificates.** Ask suppliers to produce a bounded witness that
   a smaller trusted checker validates. Measure the certificate-generation cost
   and expand the threat model to malicious certificates.
3. **Independent verifier choice.** Run interchangeable verifier implementations
   and compare disagreements, costs and availability. Two wrappers around the
   same core library do not establish independent implementation.
4. **Challenge-based acceptance.** Investigate only where cheap contradiction,
   data availability and an economically credible challenger exist. Model
   collusion, silent challengers, griefing and challenge funding.
5. **Proof-authorized settlement.** Attempt F2 for the selected W2 property
   only when proof production, verification and availability outperform or
   materially reduce trust relative to F1.

No level proves the agent followed a particular internal reasoning process.
No level converts a probabilistic or subjective predicate into certain truth.

## 6. Make agent choice real

The first live-agent workflow gives B a funded objective and several eligible
specialists with different offers. B may ask for quotes, compare methods and
prices, choose whether to subcontract, compose results and submit a final
artifact. Capture those decisions and the alternatives actually available.

The agent receives bounded tools for discovery, quotation, proposing a child
contract, checking status, retrieving delivery and requesting verification.
The trusted host constructs or validates consequential terms, reserves exposure
and obtains funding before issuing a procurement permit. The model does not
possess a root signing key, unrestricted wallet key or unmetered provider API
credential.

Use `chio-tool-call-fabric` and the selected provider adapter for the real
model/tool loop. In particular, reserve costs before the call: the current
workflow authority accounts for a step's reported cost after execution, and
the metering hierarchy evaluates a supplied snapshot without atomically
reserving it. P42 must connect these useful interfaces to the qualified local
budget authority and reconcile unknown provider charges.

A denied purchase returns a precise machine-readable reason so the model can
adapt within its mandate. Repeated retries consume a bounded attempt budget.
No amount of replanning turns a denied scope, exhausted allocation or missing
funding proof into an authorized action.

Compare live choice against a fixed specialist chain and a single-agent buyer
using equal model budgets. A live model in a predetermined workflow is not
evidence of dynamic team formation. Measure whether supplier changes reflect
price, availability and task fit, and whether those choices improve utility.

## 7. Work isolation and privacy

Keep repair work in an isolated checkout bound to a clean input commit. Export
a reviewable patch and evidence bundle; applying it to a buyer's repository is
a separate buyer-authorized operation. Do not auto-publish or merge artifacts
as a side effect of payment.

Treat fetched repositories, build scripts, checker inputs, archive contents
and model-generated commands as hostile. Production and verification run in
separate sandboxes with bounded CPU, memory, storage, processes and network.
Vendor the required dependencies or pin permitted network material. A verifier
must not execute seller code with the operator's credentials.

Use exact disclosure projections and secret canaries to test what leaves each
boundary. The current OpenAPI projection is a specific profile; it does not
solve arbitrary source-code declassification. For W1, initially select whole
public repositories or explicitly approved subsets whose build dependencies
are known. Reject work that needs undisclosed files instead of silently
expanding disclosure.

Include model providers, F1 verifier/custodians, artifact storage and diagnostic
exports in the recipient/disclosure map. A provider-approved subcontract is
not approval to upload all source to any model endpoint. Use the existing
egress contract for every new fetch and the guard-registry distribution rules
where a checker is packaged as a guard. Test at actual network dispatch,
including DNS/redirect changes, credential forwarding and response limits.

Record every checker fetch and invocation needed to reproduce acceptance.
Preserve private data in access-controlled evidence, with public commitments
where appropriate. A public proof package should not accidentally reveal
source code, private prompts, credentials or a company's entire supplier list.

Correlate authoritative payments and work receipts with the existing telemetry
and lineage surfaces. Trace-observation receipts and drop-prone queues do not
establish service payment or a complete experiment denominator. P54 records
which measurements came from authoritative records and which from observations.

## 8. Workload exit gates

W0 remains in every compatibility and failure run. W1 graduates only after
held-out evaluation establishes both useful outputs and the H2 cost result,
or records a narrower justified commercial threshold before a new trial.
W2 graduates only with a specified relation, independent checker, measured
economics and at least one concrete use case.

If W1 fails, spend the next bounded iteration improving task selection or
acceptance design. Do not respond by scaling the marketplace infrastructure.
If no useful cheap-to-verify work survives two preregistered workload
iterations, retire H2 for this program and reconsider the central thesis.
