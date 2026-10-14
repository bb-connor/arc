# Frozen analysis contract

This is a prospective analysis worksheet. It contains no observed trial values.
It carries forward Section 5 of the [approved design](../../../market/open-agent-work/06-independent-trial.md).
Any pre-score change must be versioned with a rationale. Once scoring starts,
report deviations and both the original and revised analyses where meaningful.

## Arms and matching

| Arm | Question |
| --- | --- |
| C0 direct buyer | Does buying work beat producing it internally? |
| C1 ordinary composition | Does Chio reduce integration or operating cost at the same guarantees? |
| C2 Chio live selection | Does the complete proposed system work? |
| C3 Chio fixed suppliers | Does autonomous supplier choice add value? |

Give C1 the same external escrow, checker, models, task information, budgets,
ordinary signed fields, persistence and receiver-owned authority. ERC-8183 is
an available construction, not an intentionally weakened opponent. Allow an
unscored competent review of every arm. Record initial implementation work
separately from subsequent partner onboarding. Pair tasks and counterbalance
order; account for learning, caches and service-version changes.

## Prespecified measurements

| Outcome | Measurement and original target |
| --- | --- |
| Monetary safety | Zero observed Q2-Q5 violations in the specified corpus; any counterexample blocks that safety claim |
| Verification cost | Full verification/dispute cost divided by production cost: median at most 0.10, p90 at most 0.25 for accepted W1 results; all-attempt costs also reported |
| Useful output | Held-out acceptance plus buyer-use judgment; lower 95% interval for C2 minus C1 success at least -5 percentage points |
| Partner integration | Median hands-on time at most half C1; no new pair-specific protocol code under the frozen profile |
| Newcomer | One working day after declared prerequisites; at least six paired onboarding exercises for a quantitative generalization |
| Buyer cost | Price plus verification, coordination and recovery per useful accepted result; C2 median no higher than C1 at the quality boundary |
| Autonomous choice | At least one predeclared meaningful C2 versus C3 improvement without a safety regression |
| Recovery | At least 95% of scheduled recoverable incidents require no database edits or bespoke repair after dependencies return |
| Capital | Report locked-balance time integral, peak balance and failed-parent loss; exposure stays within reserves |

Before Stage C, select the exact C2/C3 primary endpoint, minimum meaningful
effect, task categories, sample size, cluster method, interval calculation,
exclusion rules and multiplicity treatment. These choices need pilot variance
and operator budget; none is inferred from the paper's deterministic tests.
Analyze task/repository clusters so three attempts at one task are not three
independent problems. Publish all prespecified endpoints and arm comparisons.
Do not continue only a favorable arm after observing the result.

Use all assigned attempts as the primary success denominator, including
timeouts, invalid outputs, crashes and cancellations. Show accepted-only cost
ratios alongside total spending divided by useful accepted results. A zero
production-cost denominator is undefined, not a favorable zero ratio; report
it separately and apply the frozen rule. No accepted result means cost per
success is undefined with total cost and zero successes disclosed.

Reconcile buyer and seller cash flows, authoritative escrow balances and total
resource consumption. Seller margin includes compute, subcontractors,
verification, custody, rail fees, failures and declared capital cost. Report
subsidies separately. Test tokens permit accounting exercises, not claims of
commercial profit. Capital duration is the sum of balance times elapsed time
over observed balance changes, with unresolved reserves right-censored and
reported rather than silently set to zero.

## Readout

For H1-H5 and Q1-Q10, state supported, contradicted or inconclusive, with the
exact scope, evidence and strongest counterexample. Distinguish implementation
independence, administrative independence and protocol compatibility. Explain
any benefit using observed mechanisms and cost, not the number of passing tests.
If the ordinary composition matches at comparable cost, that is evidence
against the broad integration-advantage claim.
