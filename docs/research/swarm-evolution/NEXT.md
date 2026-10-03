# Next result: one evolving, funded execution

The next implementation should connect the existing D1, S1 and F1 paths into one
execution. It should make the current composition claim observable at their
handoffs, using the existing capability, treaty, custody and settlement owners.

## Question

Can a running program discover and fund a new collaborator, execute through
that receiver's own authority, and preserve every earlier operation and earned
claim when the planner or intermediary fails?

## Existing owners to connect

| Resource | Existing owner | Required binding |
| --- | --- | --- |
| Delegated declared capacity | `chio-workflow::delegation::DelegationStore` | Allocator/root/slot digest and sealed native request |
| Swarm membership and declared allocations | S1 protected runtime graph head | Exact graph version, task, allocation and stable continuation ID |
| Permission and execution identity | Native receiver capability, treaty gate and operation custody | Same receiver, subject, capability, arguments, request and physical claim |
| Deposited backing and earned payment | Existing funded-work agreement and F1 escrow | Settlement domain, original funding allocation, exact accepted output and beneficiary |

The key design decision is which existing record owns each binding. Copying a
number between D1 and S1 does not create a financial reserve. A graph extension
does not mint a native capability, and a funded agreement does not activate an
issuer at a receiver.

## Bounded execution plan

1. Trace one concrete request through the existing native funded-work path and
   identify its canonical agreement, allocation, operation and output digests.
   Define the smallest adapter that carries those same identities in D1 and S1.
   Document who may authorize each transition and what a crash between stores
   leaves committed. Preserve uncertainty where no atomic handoff exists.
2. Implement the adapter at those existing boundaries. Form the initial graph,
   run a first task, discover a second receiver at runtime, reserve its backing,
   install checked graph growth, and admit its exact sealed invocation under
   that receiver's capability and treaty conditions.
3. Kill the intermediary after a child becomes earned and before parent
   completion. Reopen the existing stores and collect the child's original
   claim. Attempt reuse of its allocation, substitution of another receiver,
   and refresh of its continuation through another graph version. Each attempt
   must fail at the owning boundary without extra effects or payment.
4. Publish the exact interface and trajectory as the implementation target for
   an independently written receiver. Give the conventional comparator the
   same escrow, authority, signatures, persistence and checker. Measure the
   changes required to add that receiver, alongside held-out work quality and
   full failed-attempt costs.

## Acceptance and falsification

The local result is complete when one trajectory carries the same resource
identities through all three profiles, demonstrates actual native effects and
escrow balances, and preserves old work after growth and failure. The paper may
then claim a unified evaluated execution under its declared operators and rail.

The broader hypothesis still fails if useful work requires bespoke pairwise
code comparable to the strongest conventional construction, or if the apparent
gain disappears when failures, checker cost and locked capital are counted.
An outside implementation and trial can establish that distinction; another
local success count cannot.

This brief records the next task. It is not evidence that the handoff or trial
has already been implemented.
