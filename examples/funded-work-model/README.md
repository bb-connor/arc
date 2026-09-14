# Forked funding claims and exclusive allocation

This executable model isolates one question: can two receivers rely on the
same payer-local balance? It is an explanatory artifact for
[Open Agent Work](../../docs/market/open-agent-work/README.md).

Run from the repository root with Python 3.10 or newer:

```sh
python3 -B -m unittest discover -s examples/funded-work-model -p 'test_*.py' -v
```

Six tests pass. The four planned cases cover forked promises, exclusive
allocation, exact replay and all 24 serial permutations of four bounded
claims. Two additional cases reject invalid monetary values without mutation.
The retained red run failed to import the absent implementation before it was
written; see the [execution results](../../docs/market/open-agent-work/execution/04-results.json).

## Interface and trace

`Claim(source, job, recipient, units)` is immutable.
`AllocationAuthority(source, deposited)` owns one trusted balance and exposes
`reserve(claim) -> bool`, `available` and a `claims` dictionary keyed by job.
An identical replay succeeds without consuming more balance. A conflicting
job claim, foreign source or invalid amount fails. Callers are trusted model
code; they must not mutate the authority's public inspection fields. These
objects are not a parser, signed wire format or remote service.

| Step | Payer-local view C | Payer-local view D | Real source | Decision |
| --- | --- | --- | --- | --- |
| Copy state | 100 | 100 | 100 | Neither copy allocates real funds |
| Promise C 100 | Approves 100 | 100 | 100 | Local check passes |
| Promise D 100 | Already promised | Approves 100 | 100 | Promises total 200 against 100 |
| Reset; authority reserves C 100 | Irrelevant | Irrelevant | Available 0; reserved 100 | Accept C |
| Authority receives D 100 | Irrelevant | Irrelevant | Available 0; reserved 100 | Deny D |

Signing both local promises can authenticate the payer and expose its
equivocation. It does not add another 100 units of backing. The accepted
model enforces `sum(reserved) + available = deposited` in serial transitions.

## Comparison with the existing ledger

The production pool already has signed allocation, concrete store binding,
domain exclusion, durable reservations and an independent rollback anchor:

- [Kernel pool](../../crates/kernel/chio-kernel/src/finding_pool.rs).
- [Swarm pool authority](../../crates/kernel/chio-swarm-authority/src/finding_pool.rs).
- [SQLite pool ledger](../../crates/platform/chio-store-sqlite/src/finding_pool_ledger.rs).
- [Existing regression suite](../../crates/platform/chio-store-sqlite/tests/finding_pool_ledger.rs).

On the isolated Linux candidate, all 38 existing pool tests pass, including
`cognition_market_sqlite_clone_cannot_reuse_the_store_binding`,
`cognition_market_allocation_binds_one_concrete_store_across_deployments` and
`cognition_market_authenticated_pool_restart_never_exceeds_signed_amount`.
Run them with a parent directory that is not group/world writable and an
available separate-device anchor fixture at `/dev/shm`:

```sh
umask 022
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=target cargo test --locked -p chio-store-sqlite --test finding_pool_ledger -- --list
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=target cargo test --locked -p chio-store-sqlite --test finding_pool_ledger -- --test-threads=1
```

There are three distinct results:

1. **Unsafe model:** copied local balances can authorize incompatible promises.
2. **Qualified ledger fixture:** the existing clone/rollback defenses pass with
   trusted local enforcement, custody, store identity and separate anchor.
3. **Dishonest remote administrator:** an operator controlling enforcement,
   signing and anchor state remains a stronger research adversary. This model
   does not execute that native attack or complete P01/Q2.

The model has one trusted in-memory authority, serial transitions, no monetary
terminals, no signatures, no real funding and no implementation-level
concurrency proof. The [escrow characterization](../../docs/market/open-agent-work/execution/01-escrow-fit.md)
tests real contract bytecode separately; it does not convert this model into
a settlement protocol.
