# Conditional backing: useful optimization, no surviving exclusive advance

This experiment tests the falsifier preregistered in the continuation plan.
It does not reopen the rejected exclusive-safe-progress claim. The question is
whether a work kernel can commit less capital than an equally provisioned B1
while guaranteeing unconditional parent refunds and independently earned child
claims, including after loss of the parent.

## Model and derived bound

Let R be a fully refundable parent allocation. There are nonnegative integer
child claims c_i. No borrowing, insurance subsidy, expected future revenue,
cross-currency conversion, negative balance or creditor haircut is allowed.
All backing is available at a single qualified allocator, with durable atomic
selection and a non-equivocating ledger. Separate physical escrows can require
more capital. A separate institution or rights-transfer message is not free.

Each claim is earned, unknown, fenced absent, or ready. Earned claims must be
paid; each unknown claim may already be earned. Fenced absence is authoritative
and prevents that original operation from later earning. Ready claims have not
dispatched; they may have a group in which a durable selector can authorize at
most one member to earn. A label supplied by the parent is not this selector.
Old group labels on earned or unknown work carry no exclusivity assumption.
Ready groups are disjoint. Overlapping constraints, probabilistic liabilities,
deadline scheduling and observation costs are outside this small model.

For the set W of payment vectors consistent with that knowledge, the necessary
backing is max(w in W) [R + sum of claims payable in w]. The refund may coexist
with every allowed child payment. In this model that maximum equals:

    R + sum(earned, unknown and ungrouped ready amounts)
      + sum(maximum ready amount in each exclusive group).

Necessity: choose the allowed world where every independent liability earns and
the largest member of each ready group earns. The unconditional refund remains
due. Any smaller balance cannot discharge all claims in that world.
Sufficiency: in every allowed world independent liabilities are bounded by their
sum and each ready group contributes at most its largest amount. A durable
allocator that never spends reserved backing for unrelated work can therefore
pay them all. This is a short argument about this declared cash-flow model,
not a machine-checked distributed protocol theorem or an implementation proof.

With no authoritative resolution, treating unknown as absent violates necessity.
Likewise, a parent choosing its favorite result after two specialists have
earned cannot retroactively make their obligations exclusive. Retaining all
earned claims is part of the promise, not an implementation inconvenience.

## Executable comparison

`capital.py` computes the structural candidate bound; B1 separately enumerates
binary payment vectors and removes vectors inconsistent with the declared
states and selection groups. Both receive exactly the same information and
allocator. No benchmark timing or integration-effort claim is inferred.

The finite experiment enumerates 4,095 profiles: zero through five claims,
all four states, three disjoint grouping patterns and deterministic varying
amounts. All candidate and B1 bounds match. Five tests include positive
companions, rejected malformed inputs and two explicit underbacking controls.
The initially unimplemented reserve failed four tests before implementation;
raw failed and successful outputs are retained in `results/`.

| Profile with refundable parent 100 | Candidate | B1 | Consequence |
| --- | ---: | ---: | --- |
| Two earned children of 30 each | 160 | 160 | Parent failure cannot cancel either claim |
| Three ready alternatives of 50, enforced selection before dispatch | 150 | 150 | Saves 100 against reserving every alternative |
| Three unknown children of 50 | 250 | 250 | A selection label cannot erase uncertainty |
| One authoritatively fenced absent child | 100 | 100 | No surviving child exposure |

The finite enumeration supports the implementation of this model; the argument
above explains the general disjoint-group expression. It does not establish
that the set of possible worlds is complete for a real deployment. That is the
most consequential assumption to audit in an implementation.

## Primary-source check

O'Neil's [The Escrow Transactional Method (1986)](https://ics.uci.edu/~cs223/papers/p405-o_neil.pdf)
already addresses recoverable intermediate updates, uncertainty ranges and
long-lived transactions. Our treatment of reserved exposure is closely related;
renaming a reservation as an obligation cannot establish a new method.

Balegas et al.'s [Extending Eventually Consistent Cloud Databases for Enforcing
Numeric Invariants (2015)](https://perso.lip6.fr/Marc.Shapiro/papers/2015/numeric-invariants-SRDS-2015.pdf)
partitions rights so replicas can preserve bounds locally and transfer rights
when necessary. That is a strong baseline for claims about low-coordination
budget allocation, with its own crash/replication assumptions.

Bailis et al.'s [Coordination Avoidance in Database Systems (2014)](https://www.vldb.org/pvldb/vol8/p185-bailis.pdf)
analyzes when independent operations can preserve invariants. A shared selector
that prevents two branches from earning is an additional coordination or
preallocated-rights condition, not evidence that Chio escaped that issue.

These sources were inspected on 2026-10-02. This is a targeted prior-art check
for conditional backing, not a literature-wide novelty verdict.

## Decision

The candidate has a real saving against an unnecessarily conservative sum of
mutually exclusive future work. It has **zero advantage over B1 in this model**.
Both can implement the same allocator. The preregistered Chio-exclusive capital
hypothesis is rejected. This candidate does not supply the missing breakthrough.

The actionable design rule is narrower: expose the distinction between earned,
unknown, fenced absent and exclusively selectable future obligations in a
reviewable contract. Native evidence must show where each classification and
selection right comes from. A foundational claim still requires a different
result; empirical integration value remains a separate, unmeasured hypothesis.
