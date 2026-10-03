# One evolving funded execution

The composed experiment connects existing D1 delegation, S1 swarm evolution,
receiver-owned bilateral treaty admission and F1 escrow. The program runs a
scout, uses its result to allocate an enrolled specialist, grows the graph and
executes the specialist through native admission. Actual intermediary SIGKILL
does not remove the specialist's already earned payment claim.

The implementation follows the [approved design](../../superpowers/specs/2026-10-02-evolving-funded-work-design.md)
and [plan](../../superpowers/plans/2026-10-02-evolving-funded-work.md), starting
from `28e1ac92e7`. It extends the existing machinery. There is no new capability
framework, treaty verifier, replay store or settlement contract.
The implementation and qualification tools are committed as `d46524ee8c`.

## Programmable sovereignty at the admission boundary

Each receiver pins its own deployment policy, treaty peer, allocator, witness
and custody authority. A transported graph cannot install these authorities.
Funding cannot grant tool access. The same protected configuration is installed
before recovery, and removing it or its runtime store fails closed.

| Resource | Preserved owner and binding |
| --- | --- |
| Delegated capacity | Existing allocator namespace, immutable root/slot digest and sealed selection |
| Evolving plan | Existing signed graph and protected compare-and-swap head; exact historical versions |
| Tool access | Receiver-issued capability, original subject and tool arguments, bilateral treaty and exact receiver route |
| Native effect | Original operation, request, budget hold and physical treaty/swarm continuation claims |
| Deposited backing | Existing agreement signs the complete final request; existing escrow allocation binds those terms |
| Earned payment | Original acceptance decision and child allocation, independent of the parent's later refund |

The D1 slot and native request share the S1 task name. The S1 allocation names
the D1 allocation digest. F1 retains its own ABI-derived allocation identifier,
transitively committing to the exact request through its signed agreement.
Copying a ceiling between records does not create backing.

## Observed trajectory

The original graph has three nodes: a planning root, scout and intermediary.
After the scout's review identifies an operation without required authentication,
the program creates the specialist's task, capability, selection, agreement and
deposit. The extended graph has four nodes. All possible readers were enrolled
before discovery; the result does not authorize arbitrary unknown peers.

The child reaches `Payable` with zero paid before the parent is killed by signal
9. The parent remains `OutcomeUnknownAfterDispatch` after its financial refund.
Parent and verifier rail signing are then disabled. The child's own collector
withdraws the original claim, and repeated collection preserves the same
transaction and execution identities.

Each receiver records one tool invocation and one native claim episode with two
physical resources: its treaty continuation and swarm continuation. Original
operation, allocation, hold, authorization and physical claim history agree
before and after recovery. The scout's execution evidence is unchanged through
growth and reopen. The final balances are:

| Account | Mock XTS |
| --- | ---: |
| Buyer | 900 |
| Intermediary, including scout proceeds | 1,000 |
| Specialist | 100 |
| Escrow | 0 |
| Conserved supply | 2,000 |

The scout and child receive 100 each; the parent's 100 is refunded. The S1
declared pool is 300. Declared capacity and observed funds remain separate facts.

## Execution evidence is not final bilateral delivery

The native pre-settlement exporter now supports qualified frozen federation
provenance. It reuses the existing decoder to check original participants,
request, treaty signatures and admission time against the content-addressed
outcome. It emits a receiver-local execution statement. It does not perform a
new tool call, obtain new remote consent or transfer funds.

The first child collection report retains a startup error: the local operation
completed, but the remote co-signer was unavailable. A later open has no
unfinished local operation to reconcile. Both reports remain in the evidence;
the identity comparison excludes only this startup observation. Payment and
local completion are established. Final bilateral receipt delivery is not.

## Reproduction and review

Current source hashes, exact commands, terminal statuses and public artifacts
live in [qualification.json](../dynamic-delegation/evidence/qualification.json).
The [artifact instructions](../../papers/verifiable-work/ARTIFACT.md) describe
the locked dependencies and the source-bound campaign. Its semantic validator
requires the actual kill, unchanged original identities, physical resource
history, one effect per receiver and conserved balances.

[Review](REVIEW.md) records the defects and repairs. Development logs in
`evidence/` preserve initial compilation, environment and integration failures;
they are distinct from qualified current-source outputs. The final qualification
record is the authority for pass counts and command completion.

All 21 commands completed with exit zero against 36,556 unchanged source inputs
and 48 hashed outputs. The recorded Rust results are:

| Boundary | Passed | Recorded skips |
| --- | ---: | --- |
| Workflow crate | 54 | One pre-existing ignored doctest |
| Native D1 admission | 10 | None; count includes the subprocess worker |
| Existing three-owner composition | 5 | None |
| Swarm authority and runtime core | 453 | None |
| Native execution export | 11 | None |
| Durable SQLite admission | 25 | None |
| Standalone funded executable, default suite | 91 | Six opt-in chain tests |
| Standalone funded executable, explicit opt-in run | 6 | The other 91 tests filtered out |

The supplementary six-test run has the same canonical source-inventory digest,
`865a331ba3a022f8ee11554a878c0f07727a754190dda36624bdc4e7cf3d24bd`,
and records unchanged source before and after execution. Its independent
[command record](evidence/chain-regressions.json) preserves the default suite's
skips rather than relabeling that first run.

The campaign also passes three Node wire/pin tests, thirteen artifact tests,
the composed trajectory and the existing child recovery test with four crash
subcases. Four strict Clippy commands, three format commands, the D1 example
and the funded binary build pass. These are bounded local checks, not full
workspace, hosted CI or production release qualification.

## What this establishes

The local composed execution is a concrete implementation of editable plans
with preserved commitments. Its assumptions remain one protected graph writer,
one custody domain per receiver, honest local enforcement, the agreed checker
and the observed private settlement domain. All roles share one administrator;
fresh co-signers are in-process fixture handles. Mock tokens have no value.

The next decisive task is the [outside receiver exercise](RECEIVER-TRIAL.md):
implement the published boundary independently, operate separate keys/stores,
and compare integration work against a competent construction with the same
authority, backing, checker and durability. Held-out useful work must then
justify its checker cost, failures and locked capital. This local result does
not establish those advantages or close the foundational publication gate.
