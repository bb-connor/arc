# Verifiable-work comparison, preregistration draft 0.1

Recorded 2026-09-14, before any scored work. This version adopts the hypotheses,
baseline freedoms and provisional decision thresholds from
[thesis](../01-thesis.md) and [independent trial](../06-independent-trial.md).
The current six-case model and six escrow tests are mechanism development,
not observations in the scored trial. No partners, held-out sample or compute
budget have been committed. A final dated freeze after the pilot is required.

## Hypotheses and controls

| ID | Hypothesis | Required evidence |
| --- | --- | --- |
| H1 | Payable work agreements compose across dishonest counterparties while each honest participant's authorized financial exposure stays bounded | Authority-backed model, actual allocation, native fork/concurrency attacks and complete losses |
| H2 | Buyers can verify useful outputs materially more cheaply than producing them | Held-out useful tasks, independently selected checks, all costs and latency |
| H3 | One public contract substantially reduces repeated partner integration | Independent provider implementation, newcomer and matched alternative |
| H4 | Agents can choose and compose specialist purchases with bounded loss and useful economics | Live decisions, alternatives, matched budgets, subsidies and failures included |
| H5 | A compact general rule explains the gains beyond one application | Two task families, removal experiments, independent critique and explicit mechanism |

H1 is conditional on honest local enforcement and the specified funding and
acceptance authorities. H2 concerns the selected predicate, not arbitrary
truth. H3 separates technical integration from business onboarding. H4 is
empirical. The original falsification conditions remain unchanged.

| Arm | Allowed construction and purpose |
| --- | --- |
| C0 | Direct buyer agent: same models, task information, checker and total allowance |
| C1 | Composed cross-company baseline: receiver-owned authentication, signed application contracts, durable workflow/ledger, identical escrow/verifier and ordinary protocol extensions |
| C2 | Chio with live supplier selection under the same economic, model, network and evaluation conditions |
| C3 | Chio with fixed eligible supplier workflow; same mechanisms, models and budget |

C1 gets an unscored engineering review and time to repair obvious deficiencies.
It may use every underlying mechanism Chio uses. Record its engineering budget
and any guarantee it cannot match; do not present a budget-limited construction
as a theoretical impossibility. The original composed examples are retained
as inputs, not certified as an already matched implementation of this new F1.

## Sampling and freeze procedure

1. Build a task registry before selection. Each candidate records a public or
   explicitly shareable repository/base commit, reproducible original failure,
   allowed patch scope, build/checker digest, resource ceiling, defect category
   and buyer-use criterion. Exclude unbuildable or unlicensed/unshareable tasks
   before allocation, recording reasons. Do not select by a production model's
   success. W0 remains the compatibility fixture; W1 is the useful-work arm.
2. Use at least three defect categories, initially authorization behavior,
   parsing/validation and state/recovery behavior. Separate development and
   held-out repositories or related defect clusters to prevent leakage. Within
   each category order eligible IDs by SHA-256 of UTF-8
   `chio-work-trial-v0.1|split|task_id`, with the full task ID as a tie breaker.
   Publish the candidate manifest and selection program before viewing results.
3. Select **30 unscored W1 pilot tasks**, balanced over the declared categories
   where feasible. Estimate variance, realistic all-attempt cost and checker
   failure rates. Freeze exact category counts, exclusions, sample size and
   budget in version 0.2 before scoring. Revision reasons and pilot evidence
   remain public; no threshold changes after examining held-out outcomes.
4. Initial scored design: **150 held-out W1 task instances, three stochastic
   repetitions per applicable arm**, up to **1,800 attempts** for four arms.
   Pilot power analysis may change this before the freeze. The final freeze
   must set model versions, order randomization seed, repetitions, stopping
   rule and uncertainty method. Paired tasks and counterbalanced arm order
   are required; cluster analysis by task/repository, not individual retries.
5. Pin hidden checker bundles and evaluator custody before submissions. Give
   every arm the same information and resource allowances. Publish cold/warm
   cache results separately. Record provider changes, outages and all attempted
   runs. Safety violations stop the affected claim; budget/outage stops are
   reported as incomplete, never success-selected omissions.
6. Require three independent core operators plus a newcomer, two independently
   authored providers and an independent F1 verifier. At least six paired
   onboarding exercises are planned for quantitative H3, with small-sample
   uncertainty. One newcomer alone supports only a demonstration. Cross-border
   operation requires actual companies in two jurisdictions and their scoped
   participation decisions. No such trial has run in this slice.

W2 selection and H5 removal experiments need a separate pre-scoring amendment
after a bounded certificate-checker spike. W0's cheap recomputation cannot
stand in for H2. Production Python/TypeScript SDKs calling the Rust CLI count
as compatibility, not independent verifier implementations.

## Adopted provisional thresholds

| Measure | Threshold and denominator |
| --- | --- |
| Monetary safety | Zero observed Q2-Q5 violations in the published corpus; any counterexample blocks the corresponding claim |
| Verification cost | Median at most 0.10 and p90 at most 0.25 of production cost on accepted W1; also publish all-attempt ratios, absolute cost and latency |
| Useful output | Lower 95% interval for C2 minus C1 success rate at least -5 percentage points, with held-out acceptance and buyer-use criteria |
| Repeated integration | Median hands-on technical time at most half C1; no new per-pair protocol code under the frozen profile |
| Newcomer | At most one working day after generic infrastructure/business prerequisites; report all assistance |
| Buyer economics | C2 median price plus buyer verification, coordination and recovery cost per useful accepted result no higher than C1 at the quality boundary |
| Autonomous choice | At least one preregistered meaningful C2-over-C3 improvement, uncertainty reported, no safety regression |
| Recovery | At least 95% of scheduled recoverable incidents need no database edits or bespoke repair after dependencies return |
| Capital | All exposure within declared reserves; report locked-balance-time integral, maximum frozen amount and failed-parent losses |

The meaningful effect and primary metric for autonomous choice remain to be
set from pilot economics before version 0.2. They are not retroactively chosen
from the best outcome. Inconclusive intervals remain inconclusive; any added
sample requires another independent preregistration, never extension of only
the favorable arm.

## Cost and evidence record

Retain task/arm/repetition, exact source/profile/model versions, operator and
implementation identities, quotes and procurement decisions, authority-observed
allocations and monetary terminals, production/checking durations, raw resource
usage, fee destinations, parent/child outcomes, fault schedule, recoveries and
all human intervention. Retain the hashed authoritative sources behind a
reported success; telemetry or a harness summary alone cannot establish payment.

Reconcile buyer cash flows, each seller's cash flows, funding-authority balances
and total resource consumption. Include failed production, specialists,
verification/disputes, storage, recovery, gas, capital and operator assistance.
Eliminate internal transfers only when calculating total resource cost. Publish
gross and subsidy-adjusted margins; a zero verifier fee in a mock-token fixture
does not mean verification is free. Report technical and commercial onboarding
both separately and together, with elapsed and hands-on time.

## Property-to-experiment ledger

| Property | Current evidence | Required next obligation |
| --- | --- | --- |
| Q1 local authority | Existing native regression inputs and reproduced local smokes | On integrated source, reject foreign allocation/issuer before dispatch; preserve committed start |
| Q2 exclusive backing | Serial model fragment; 38 real local-ledger cases; one-deposit dev-chain denial | Two funding sources, concurrent native admissions, dishonest administrator/anchor threat and independent final balance reconstruction |
| Q3 exclusive terminals | Existing escrow duplicate-payment denial | New claim contract exhaustive transitions, conflicting accept/reject/refund ordering and actual concurrent calls |
| Q4 child claim survives | Already-paid child retains 60 when parent expires; native local-credit child crash cases | Still-unpaid accepted child withdraws after parent death/refund, without parent cooperation |
| Q5 uncertainty preserved | Native local-credit recovery reproduced | Crash during rail dispatch; authoritative reconciliation resolves money while original execution remains unknown |
| Q6 exact acceptance | Python public-evidence denials and native artifact tests | New agreement/claim/checker/custodian/recipient binding and cross-chain substitution corpus |
| Q7 disclosure and budgets | Existing subcontract disclosure and hostile-worker scenarios | Actual selected sandbox/egress, concurrent budget limits and capacity exhaustion on integrated source |
| Q8 interoperability | Python buyer suite; shared project and administration disclosed | Independent provider and decision implementation, every pairing, malformed/downgrade vectors |
| Q9 conditional progress | Local process recovery and escrow deadline counterexample | Partition, verifier outage, pending-claim timing, key change and restart tests under declared assumptions |
| Q10 honest claims | Source ledger, command logs, negative calibration and explicit limits | Independent offline reconstruction, privacy audit, exact-source CI and full trial omissions |

No Q property is fully discharged by this first slice. No H hypothesis is
declared supported by these development observations. Changes from this version
must carry a date, reason and pre-scoring status; the full adoption and paper
gates continue to apply.
