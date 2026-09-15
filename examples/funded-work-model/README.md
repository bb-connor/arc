# Forked funding claims and exclusive allocation

This executable model isolates one question: can two receivers rely on the
same payer-local balance? It is an explanatory artifact for
[Open Agent Work](../../docs/market/open-agent-work/README.md).

The directory now also contains the [claim state model](claim_model.py) and
[bounded explorer](claim_explorer.py). The original six allocation tests remain
unchanged; the full command below now runs 18 tests across both stages.

Run from the repository root with Python 3.10 or newer:

```sh
python3 -B -m unittest discover -s examples/funded-work-model -p 'test_*.py' -v
```

The six original allocation tests pass. The four planned cases cover forked promises, exclusive
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

## Funded claim state exploration

The second model records real model cash movements independently of its state
enum: Funded, Submitted, Payable, Paid, Rejected, TimedOut and Refunded. Its
source deposits are fixed; returned cash is reported as refunded rather than
implicitly redeposited. Original execution uncertainty survives financial
resolution. Failed transfers model atomic transaction reverts.

`Terms` fixes source, recipient, verifier, amount and four deadlines.
`ClaimLedger` supports fund, submit, decide, expire, pay and refund. All
arguments are trusted model inputs, not parsed or signed wire data. It has no
chain fork/finality, crash-persistent custody, arbitrary verifier faults or
proof that a checker is useful.

```sh
python3 -B examples/funded-work-model/claim_explorer.py --output /tmp/claim-traces.json
cmp examples/funded-work-model/claim-traces.json /tmp/claim-traces.json
python3 -B examples/funded-work-model/claim_explorer.py --broken-expiry --output /tmp/claim-counterexample.json
```

The ordinary exploration exhausts the reachable finite graph for two already
funded jobs (3 and 2 units), a fixed actor/commitment/decision alphabet and nine
monotonic timestamps. It visits 5,508 states and 132,192 transitions, checking
source conservation, nonnegative balances, terminal/transfer agreement,
no refund of accepted work, immutable uncertainty and no mutation on denial.
The funding and transfer-failure boundaries are separately exercised by unit
tests; they are not all transitions in this finite graph.

The broken-expiry driver exits 1 with the short financial trace `submit ->
accept -> timeout refund`. It changes the explorer's copied state only; no
production contract or normal model switch weakens the real implementation.

The retained [trace corpus](claim-traces.json) selects 118 financial-edge
representatives with their shortest discovered prefixes. The
[bytecode replay suite](../../contracts/scripts/work-claim-model.test.mjs)
checks each against an independent Solidity implementation and actual token
balances. It does not run all 132,192 model transitions against the contract.
Regenerate and compare the corpus whenever the model or explorer changes.

The [claim-escrow report](../../docs/market/open-agent-work/execution/05-claim-escrow-results.md)
records the new result and the remaining native integration requirements.
