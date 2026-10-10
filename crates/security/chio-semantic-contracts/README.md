# chio-semantic-contracts

Portable, pure validation for bounded symbolic dependency graphs and explicit effect
contracts. The crate defaults to `no_std + alloc` with an additive `std` feature.
Provider facts, authority authentication, materialization and execution belong to
owning deployment and kernel components.

Dependency validation uses at most 16 steps and 16 dependencies per step. Ordering is
deterministic by dependency readiness then opaque step ID. One shared, irreversible
work meter charges repeated references, search passes and bounded sorting before
allocation. Missing dependencies, duplicate identities, cycles, unsafe cost arithmetic
and work exhaustion refuse. A validated DAG is not a reviewed action or a permit.

The effect contract permits one submission under the original native operation,
requires disabled automatic retries and makes no provider deduplication assumption.
Provider lookup finality and maximum effect cardinality are explicit metadata that
requires operator verification. Semantic packages describe prerequisites, transformations,
destinations and withholding; fresh native authority checks govern their execution.
